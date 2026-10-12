package com.rawtcp.burp.ui;

import com.rawtcp.burp.ipc.ControlPlane;
import com.rawtcp.burp.ipc.proto.BurpTcp;
import com.rawtcp.burp.util.Display;
import com.rawtcp.burp.util.HexText;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JSplitPane;
import javax.swing.JTable;
import javax.swing.JTextField;
import javax.swing.JCheckBox;
import javax.swing.JPopupMenu;
import javax.swing.JMenuItem;
import javax.swing.RowFilter;
import javax.swing.table.TableRowSorter;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.ListSelectionModel;
import javax.swing.SwingUtilities;
import javax.swing.table.AbstractTableModel;
import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.function.BiConsumer;
import java.awt.event.KeyEvent;
import java.awt.Toolkit;
import java.awt.datatransfer.StringSelection;

/**
 * TCP history tab: every captured chunk across all connections, newest last.
 *
 * <p>Unlike the queue in Intercept (one held unit at a time), this is a
 * passive log: it shows the exact bytes the engine already forwarded, for
 * every connection, without selecting anything first. A connection dropdown
 * only <em>filters</em> the view and defaults to all connections, so new
 * traffic appears on its own while Live is on.
 *
 * <p>Fetching is cheap by construction: each refresh re-reads a
 * connection's chunks only when its byte counters moved since the last
 * read. Unchanged connections cost no snapshot RPC.
 */
public final class HistoryPanel extends JPanel {

    /** Bound outstanding history RPCs, not the number of visible connections. */
    static final int MAX_IN_FLIGHT = 2;
    static final long MAX_CACHE_BYTES = 16 * 1024 * 1024;
    static final int MAX_CACHE_CHUNKS = 8192;
    /**
     * Newest chunks requested per connection per direction. Bounds every
     * snapshot so one bulk transfer cannot wedge the control plane; the
     * engine reports the retained total alongside.
     */
    static final int HISTORY_MAX_CHUNKS = 300;

    private final ControlPlane client;
    private final Model model = new Model();
    private final JTable table = new JTable(model) {
        @Override public String getToolTipText(java.awt.event.MouseEvent event) {
            int row = rowAtPoint(event.getPoint());
            if (row < 0) return null;
            Row item = model.get(convertRowIndexToModel(row));
            return "Chunk " + item.chunk().getChunkId() + " · Sequence " + item.chunk().getSeq()
                    + " · Offset " + item.chunk().getOffset();
        }
    };
    private final JComboBox<String> direction =
            new JComboBox<>(new String[] {"All traffic", "To server", "To client"});
    private final JComboBox<String> connectionFilter = new JComboBox<>();
    private final List<String> filterIds = new ArrayList<>();
    private final ByteViewPanel detail = new ByteViewPanel(true);
    private final JLabel status = new JLabel("Waiting for traffic. Enable Live or press Refresh.");
    private final JTextField search = new JTextField(20);
    private final JCheckBox live = new JCheckBox("Live", true);
    private final TableRowSorter<Model> sorter = new TableRowSorter<>(model);
    private BiConsumer<String, byte[]> repeater = (id, bytes) -> {};
    private java.util.function.Consumer<byte[]> decoder = bytes -> {};
    private java.util.function.Function<String, String> destination = Display::shortId;
    private boolean applying;
    private String detailChunkId;
    /** Per-connection chunk cache plus the counters observed at the last fetch. */
    private final Map<String, ConnCache> caches = new LinkedHashMap<>();
    private List<BurpTcp.ConnectionInfo> latestConns = List.of();
    /** Null means no filter: show every connection. */
    private String filterConnId;
    private boolean syncingFilter;
    /** Only a session reset invalidates responses; polling never does. */
    private long cycleSeq;
    private int cyclePending;
    private final java.util.Set<String> queued = new java.util.LinkedHashSet<>();
    private String lastFetchError = "";

    private record Row(String connId, BurpTcp.TrafficChunkInfo chunk) {}
    private static final class ConnCache {
        BurpTcp.ConnectionInfo info;
        long fetchedC2s = -1;
        long fetchedS2c = -1;
        List<BurpTcp.TrafficChunkInfo> chunks = List.of();
        long totalChunks;
        boolean loading;
        boolean fetchedClosed;
        long fetchedAtNanos;
    }

    public HistoryPanel(ControlPlane client) {
        super(new BorderLayout(4, 4));
        this.client = client;
        setBorder(BorderFactory.createEmptyBorder(4, 4, 4, 4));

        connectionFilter.addActionListener(event -> {
            if (syncingFilter) return;
            int index = connectionFilter.getSelectedIndex();
            filterConnId = index <= 0 ? null : filterIds.get(index);
            refilter();
            refresh();
        });

        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        table.setRowSorter(sorter);
        table.setFillsViewportHeight(true);
        table.getColumnModel().getColumn(0).setCellRenderer(new javax.swing.table.DefaultTableCellRenderer() {
            @Override protected void setValue(Object value) { setText(Display.time((Long) value)); }
        });
        table.getSelectionModel().addListSelectionListener(event -> {
            if (!event.getValueIsAdjusting() && !applying) {
                showSelected();
            }
        });

        JPopupMenu menu = new JPopupMenu();
        JMenuItem send = new JMenuItem("Send to Repeater");
        send.addActionListener(event -> sendSelectedToRepeater());
        menu.add(send);
        JMenuItem decode = new JMenuItem("Send to Decoder");
        decode.addActionListener(event -> {
            Row row = selectedRow();
            if (row != null) decoder.accept(row.chunk().getBytes().toByteArray());
        });
        menu.add(decode);
        JMenuItem copy = new JMenuItem("Copy bytes as hex");
        copy.addActionListener(event -> {
            Row row = selectedRow();
            if (row != null) Toolkit.getDefaultToolkit().getSystemClipboard()
                    .setContents(new StringSelection(HexText.toHex(row.chunk().getBytes().toByteArray())), null);
        });
        menu.add(copy);
        TrafficActions.popup(table, menu);
        TrafficActions.shortcut(this, KeyEvent.VK_R, "Send to Repeater", this::sendSelectedToRepeater);
        search.setToolTipText("Filter all traffic by text or hex bytes (spaces optional)");
        search.getDocument().addDocumentListener(new DocumentListener() {
            @Override public void insertUpdate(DocumentEvent e) { refilter(); }
            @Override public void removeUpdate(DocumentEvent e) { refilter(); }
            @Override public void changedUpdate(DocumentEvent e) { refilter(); }
        });

        JButton refresh = new JButton("Refresh");
        refresh.addActionListener(event -> refresh());
        direction.addActionListener(event -> refilter());
        JButton showAll = new JButton("Show all");
        showAll.setToolTipText("Clear the connection filter");
        showAll.addActionListener(event -> setConnection(null));

        JPanel top = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
        top.add(new JLabel("Connection:"));
        top.add(connectionFilter);
        top.add(showAll);
        top.add(new JLabel("Traffic:"));
        top.add(direction);
        top.add(refresh);
        top.add(live);

        JPanel filters = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
        filters.add(new JLabel("Find text / hex:"));
        filters.add(search);
        JButton sendButton = new JButton("Send to Repeater");
        sendButton.addActionListener(event -> sendSelectedToRepeater());
        filters.add(sendButton);
        JPanel toolbar = new JPanel(new BorderLayout(4, 4));
        toolbar.add(top, BorderLayout.NORTH);
        toolbar.add(filters, BorderLayout.SOUTH);

        JSplitPane split = new JSplitPane(
                JSplitPane.VERTICAL_SPLIT,
                TrafficActions.scroll(table),
                detail);
        split.setResizeWeight(0.55);

        add(toolbar, BorderLayout.NORTH);
        add(split, BorderLayout.CENTER);
        add(status, BorderLayout.SOUTH);
        rebuildFilter();
    }

    /**
     * Filter the view to one connection, or {@code null} for all connections.
     * Called when a Connections row is picked; never hides traffic by itself.
     */
    public void setConnection(String connId) {
        filterConnId = (connId == null || connId.isEmpty()) ? null : connId;
        syncingFilter = true;
        try {
            if (filterConnId == null) {
                connectionFilter.setSelectedIndex(0);
            } else {
                int index = filterIds.indexOf(filterConnId);
                if (index >= 0) connectionFilter.setSelectedIndex(index);
                else rebuildFilter();
            }
        } finally {
            syncingFilter = false;
        }
        refilter();
        refresh();
    }

    /** Latest connection snapshot; drives fetching and the filter dropdown. */
    void setConnections(List<BurpTcp.ConnectionInfo> rows) {
        latestConns = List.copyOf(rows);
        for (BurpTcp.ConnectionInfo info : rows) {
            caches.computeIfAbsent(info.getConnId(), id -> new ConnCache()).info = info;
        }
        boolean hadFilter = filterConnId != null && caches.containsKey(filterConnId);
        caches.keySet().retainAll(rows.stream().map(BurpTcp.ConnectionInfo::getConnId).toList());
        if (filterConnId != null && hadFilter && !caches.containsKey(filterConnId)) {
            filterConnId = null; // Follow live traffic instead of a vanished connection.
        }
        if (!connectionFilter.isPopupVisible()) rebuildFilter();
        queued.retainAll(caches.keySet());
        applyMerged();
        if (live.isSelected()) refresh();
    }

    /** Drop cached chunks and invalidate in-flight fetches (e.g. on disconnect). */
    public void clear() {
        cycleSeq++;
        cyclePending = 0;
        queued.clear();
        lastFetchError = "";
        caches.clear();
        latestConns = List.of();
        filterConnId = null;
        rebuildFilter();
        model.set(List.of());
        detail.setBytes(new byte[0]);
        detailChunkId = null;
        status.setText("Waiting for traffic. Enable Live or press Refresh.");
    }

    /** Fetch changed connections, then merge every cached chunk into one view. */
    public void refresh() {
        // Keep FIFO work across refreshes. A busy early connection cannot
        // continually jump ahead of a later or short-lived connection.
        for (var entry : caches.entrySet()) {
            ConnCache cache = entry.getValue();
            if (!cache.loading && stale(cache)) queued.add(entry.getKey());
        }
        drainFetches();
    }

    private boolean stale(ConnCache cache) {
        return cache.fetchedC2s != cache.info.getBytesClientToServer()
                || cache.fetchedS2c != cache.info.getBytesServerToClient()
                || cache.fetchedClosed != cache.info.getClosed()
                // Recording follows the transport counter increment. Revisit
                // live sessions to catch a snapshot taken in that tiny gap.
                || (!cache.info.getClosed() && System.nanoTime() - cache.fetchedAtNanos
                        >= java.util.concurrent.TimeUnit.SECONDS.toNanos(5));
    }

    private void drainFetches() {
        long cycle = cycleSeq;
        while (cyclePending < MAX_IN_FLIGHT && !queued.isEmpty()) {
            String id = queued.iterator().next();
            queued.remove(id);
            ConnCache cache = caches.get(id);
            if (cache == null || cache.loading || !stale(cache)) continue;
            BurpTcp.ConnectionInfo info = cache.info;
            long c2s = info.getBytesClientToServer();
            long s2c = info.getBytesServerToClient();
            cache.loading = true;
            cyclePending++;
            client.historySnapshot(id, BurpTcp.Direction.DIRECTION_UNSPECIFIED, HISTORY_MAX_CHUNKS)
                    .whenComplete((data, error) -> SwingUtilities.invokeLater(() -> {
                        if (cycle != cycleSeq) return;
                        cyclePending--;
                        cache.loading = false;
                        if (caches.get(id) == cache && error == null) {
                            cache.chunks = List.copyOf(data.getChunksList());
                            cache.totalChunks = data.getTotalChunks();
                            cache.fetchedC2s = c2s;
                            cache.fetchedS2c = s2c;
                            cache.fetchedClosed = info.getClosed();
                            cache.fetchedAtNanos = System.nanoTime();
                            trimCache();
                        } else if (error != null) {
                            lastFetchError = error.getMessage();
                        }
                        applyMerged();
                        drainFetches();
                    }));
        }
    }

    /** Enqueue new work without superseding or duplicating pending RPCs. */
    void refreshLive() {
        if (live.isSelected()) refresh();
    }

    public void setRepeaterListener(BiConsumer<String, byte[]> listener) {
        repeater = listener;
    }

    public void setDecoderListener(java.util.function.Consumer<byte[]> listener) { decoder = listener; }
    public void setDestinationResolver(java.util.function.Function<String, String> resolver) { destination = resolver; }

    void sendSelectedToRepeater() {
        Row row = selectedRow();
        if (row != null) repeater.accept(row.connId(), row.chunk().getBytes().toByteArray());
    }

    /** Bound payload and row retention even when many connections are active. */
    private void trimCache() {
        List<BurpTcp.TrafficChunkInfo> all = new ArrayList<>();
        caches.values().forEach(cache -> all.addAll(cache.chunks));
        all.sort(Comparator.comparingLong(BurpTcp.TrafficChunkInfo::getRecordedUnixMs).reversed());
        var keep = new java.util.HashSet<String>();
        long bytes = 0;
        for (var chunk : all) {
            if (keep.size() >= MAX_CACHE_CHUNKS || bytes + chunk.getBytes().size() > MAX_CACHE_BYTES) continue;
            keep.add(chunk.getChunkId());
            bytes += chunk.getBytes().size();
        }
        for (ConnCache cache : caches.values()) {
            cache.chunks = cache.chunks.stream().filter(chunk -> keep.contains(chunk.getChunkId())).toList();
        }
    }

    private void applyMerged() {
        List<Row> merged = new ArrayList<>();
        for (Map.Entry<String, ConnCache> entry : caches.entrySet()) {
            if (filterConnId != null && !entry.getKey().equals(filterConnId)) continue;
            for (BurpTcp.TrafficChunkInfo chunk : entry.getValue().chunks) {
                merged.add(new Row(entry.getKey(), chunk));
            }
        }
        merged.sort(Comparator.comparingLong((Row row) -> row.chunk().getRecordedUnixMs())
                .thenComparing(Row::connId)
                .thenComparing(row -> row.chunk().getDirectionValue())
                .thenComparingLong(row -> row.chunk().getSeq()));
        Row selected = selectedRow();
        String selectedId = selected == null ? null : selected.chunk().getChunkId();
        applying = true;
        try {
            model.set(merged);
            boolean restored = false;
            if (selectedId != null) {
                for (int i = 0; i < merged.size(); i++) {
                    if (merged.get(i).chunk().getChunkId().equals(selectedId)) {
                        int view = table.convertRowIndexToView(i);
                        if (view >= 0) table.setRowSelectionInterval(view, view);
                        restored = true;
                        break;
                    }
                }
            }
            if (!restored && table.getSelectedRow() < 0 && table.getRowCount() > 0 && live.isSelected()) {
                table.setRowSelectionInterval(table.getRowCount() - 1, table.getRowCount() - 1);
            }
        } finally {
            applying = false;
        }
        refilter();
        showSelected();
        int conns = filterConnId != null ? 1 : caches.size();
        long total = 0;
        for (Map.Entry<String, ConnCache> entry : caches.entrySet()) {
            if (filterConnId != null && !entry.getKey().equals(filterConnId)) continue;
            total += Math.max(entry.getValue().totalChunks, entry.getValue().chunks.size());
        }
        status.setText(table.getRowCount() + " / " + model.getRowCount()
                + " chunks across " + conns + " connection(s)"
                + (total > model.getRowCount() ? " · newest " + model.getRowCount() + " of " + total : "")
                + " · exact forwarded bytes"
                + (lastFetchError.isEmpty() ? "" : " · last fetch error: " + lastFetchError));
    }

    private void refilter() {
        String query = search.getText().toLowerCase(Locale.ROOT).trim();
        String hex = query.replaceAll("\\s+", "");
        BurpTcp.Direction wanted = selectedDirection();
        sorter.setRowFilter(new RowFilter<>() {
            @Override public boolean include(Entry<? extends Model, ? extends Integer> entry) {
                Row row = model.get(entry.getIdentifier());
                if (wanted != BurpTcp.Direction.DIRECTION_UNSPECIFIED
                         && row.chunk().getDirection() != wanted) return false;
                if (query.isEmpty()) return true;
                byte[] bytes = row.chunk().getBytes().toByteArray();
                return HexText.toPrintableText(bytes).toLowerCase(Locale.ROOT).contains(query)
                        || HexText.toHex(bytes).contains(hex);
            }
        });
        showSelected();
    }

    private void rebuildFilter() {
        syncingFilter = true;
        try {
            connectionFilter.removeAllItems();
            filterIds.clear();
            filterIds.add(null);
            connectionFilter.addItem("All connections");
            for (BurpTcp.ConnectionInfo info : latestConns) {
                if (info.getRequestedHost().isEmpty() || info.getRequestedPort() == 0) continue;
                filterIds.add(info.getConnId());
                connectionFilter.addItem(info.getRequestedHost() + ":" + info.getRequestedPort()
                        + " · " + Display.connectionState(info));
            }
            int index = filterConnId == null ? 0 : filterIds.indexOf(filterConnId);
            if (filterConnId != null && index < 0) {
                // A filter set before its snapshot arrived (or for retained
                // history): show it truthfully instead of pretending "All".
                filterIds.add(filterConnId);
                connectionFilter.addItem("Connection " + Display.shortId(filterConnId));
                index = filterIds.size() - 1;
            }
            connectionFilter.setSelectedIndex(Math.max(0, index));
        } finally {
            syncingFilter = false;
        }
    }

    void selectRow(int row) { table.setRowSelectionInterval(row, row); }
    void setSearch(String text) { search.setText(text); }
    JTable trafficTable() { return table; }
    /** Status line text, for tests. */
    String statusText() { return status.getText(); }
    /** Pick the traffic-direction filter by index, for tests. */
    void selectDirection(int index) { direction.setSelectedIndex(index); }
    /** Connection filter entries shown, for tests. */
    java.util.List<String> filterEntries() {
        java.util.List<String> entries = new ArrayList<>();
        for (int i = 0; i < connectionFilter.getItemCount(); i++) entries.add(connectionFilter.getItemAt(i));
        return entries;
    }

    /** Filter target, or {@code null} for all connections. For tests. */
    String connectionId() {
        return filterConnId;
    }

    /** Chunks currently shown, for tests. */
    java.util.List<BurpTcp.TrafficChunkInfo> displayedChunks() {
        List<BurpTcp.TrafficChunkInfo> chunks = new ArrayList<>();
        for (int i = 0; i < model.getRowCount(); i++) chunks.add(model.get(i).chunk());
        return chunks;
    }

    private BurpTcp.Direction selectedDirection() {
        return switch (direction.getSelectedIndex()) {
            case 1 -> BurpTcp.Direction.CLIENT_TO_SERVER;
            case 2 -> BurpTcp.Direction.SERVER_TO_CLIENT;
            default -> BurpTcp.Direction.DIRECTION_UNSPECIFIED;
        };
    }

    private void showSelected() {
        Row row = selectedRow();
        String id = row == null ? null : row.chunk().getChunkId();
        if (java.util.Objects.equals(id, detailChunkId)) return;
        detailChunkId = id;
        detail.setBytes(row == null ? new byte[0] : row.chunk().getBytes().toByteArray());
    }

    private Row selectedRow() {
        int viewRow = table.getSelectedRow();
        if (viewRow < 0) {
            return null;
        }
        return model.get(table.convertRowIndexToModel(viewRow));
    }

    private final class Model extends AbstractTableModel {

        private static final String[] COLUMNS =
                {"Time", "Destination", "Traffic", "Size (bytes)", "Preview"};

        private List<Row> rows = new ArrayList<>();

        void set(List<Row> newRows) {
            this.rows = new ArrayList<>(newRows);
            fireTableDataChanged();
        }

        Row get(int row) {
            return rows.get(row);
        }

        List<Row> rows() {
            return List.copyOf(rows);
        }

        @Override
        public int getRowCount() {
            return rows.size();
        }

        @Override
        public int getColumnCount() {
            return COLUMNS.length;
        }

        @Override
        public String getColumnName(int column) {
            return COLUMNS[column];
        }

        @Override public Class<?> getColumnClass(int column) {
            return column == 0 || column == 3 ? Long.class : String.class;
        }

        @Override
        public Object getValueAt(int row, int column) {
            Row item = rows.get(row);
            BurpTcp.TrafficChunkInfo chunk = item.chunk();
            return switch (column) {
                case 0 -> chunk.getRecordedUnixMs();
                case 1 -> destination.apply(item.connId());
                case 2 -> Display.direction(chunk.getDirection());
                case 3 -> (long) chunk.getBytes().size();
                default -> Display.preview(chunk.getBytes().toByteArray());
            };
        }
    }
}
