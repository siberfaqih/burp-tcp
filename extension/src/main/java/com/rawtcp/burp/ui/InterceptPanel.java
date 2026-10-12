package com.rawtcp.burp.ui;

import com.rawtcp.burp.ipc.ControlPlane;
import com.rawtcp.burp.ipc.proto.BurpTcp;
import com.rawtcp.burp.util.Display;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTable;
import javax.swing.JSplitPane;
import javax.swing.JPopupMenu;
import javax.swing.JMenuItem;
import javax.swing.ListSelectionModel;
import javax.swing.SwingUtilities;
import javax.swing.table.AbstractTableModel;
import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.awt.event.KeyEvent;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.HashMap;
import java.util.Set;
import java.util.HashSet;
import java.util.Arrays;
import java.util.function.BiConsumer;
import java.util.function.Function;

/**
 * Intercept tab: directional enable toggles and the pending-unit queue.
 *
 * <p>The checkboxes show the engine's <em>authoritative</em> interception
 * policy (from {@code Stats.c2s_enabled}/{@code s2c_enabled}), not local
 * optimistic state, so a fail-open or an externally applied policy is
 * reflected. While disconnected the controls are disabled.
 *
 * <p>Edits follow the unit ID and revision across refreshes and selections.
 * Forward commits a replacement only when the inline bytes changed.
 */
public final class InterceptPanel extends JPanel {

    private final ControlPlane client;
    private final Model model = new Model();
    private final JTable table = new JTable(model) {
        @Override public String getToolTipText(java.awt.event.MouseEvent event) {
            int row = rowAtPoint(event.getPoint());
            if (row < 0) return null;
            BurpTcp.PendingUnitInfo unit = model.get(convertRowIndexToModel(row));
            return "Unit " + unit.getUnitId() + " · Connection " + unit.getConnId()
                    + " · Sequence " + unit.getSeq() + " · Offset " + unit.getOffset()
                    + " · Revision " + unit.getRevision();
        }
    };
    private final JCheckBox c2s = new JCheckBox("Intercept to server");
    private final JCheckBox s2c = new JCheckBox("Intercept to client");
    private final JLabel stats = new JLabel(" ");
    private final JButton forward = new JButton("Forward");
    private final JButton forwardAll = new JButton("Forward all");
    private final JButton suppress = new JButton("Drop bytes");
    private final JButton close = new JButton("Close connection");
    private final JButton restore = new JButton("Restore original");
    private final BinaryEditorPanel editor = new BinaryEditorPanel();
    private final JLabel selection = new JLabel("No traffic held. Enable a direction to intercept.");
    private final JLabel notice = new JLabel(" ");
    private BurpTcp.PendingUnitInfo editing;
    private boolean applying;
    private boolean pendingLoading;
    private final Map<String, Draft> drafts = new HashMap<>();
    private final Set<String> decisionsInFlight = new HashSet<>();
    private final Set<String> committed = new HashSet<>();
    private long connectionEpoch;
    private BiConsumer<String, byte[]> repeater = (id, bytes) -> {};
    private java.util.function.Consumer<byte[]> decoder = bytes -> {};
    private Function<String, String> destination = Display::shortId;
    private java.util.function.IntConsumer queueListener = count -> {};

    private record Draft(long revision, BinaryEditorPanel.Draft content) {}

    /** Guards against programmatic checkbox updates re-triggering SetEnabled. */
    private boolean syncing;
    /** Last authoritative enable state reported by the engine. */
    private boolean authoritativeC2s;
    private boolean authoritativeS2c;
    /** Count of SetEnabled round trips in flight (suppresses polling). */
    private int togglesInFlight;
    private boolean controlsEnabled;
    private long pendingSeq;
    private long statsSeq;
    private boolean statsLoading;
    private java.util.function.Consumer<String> notifier = notice::setText;

    public InterceptPanel(ControlPlane client) {
        super(new BorderLayout(4, 4));
        this.client = client;
        setBorder(BorderFactory.createEmptyBorder(4, 4, 4, 4));

        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        table.setAutoCreateRowSorter(true);
        table.setFillsViewportHeight(true);
        table.getSelectionModel().addListSelectionListener(event -> {
            if (!event.getValueIsAdjusting() && !applying) showSelected();
        });

        c2s.addActionListener(
                event -> applyEnabled(BurpTcp.Direction.CLIENT_TO_SERVER, c2s.isSelected()));
        s2c.addActionListener(
                event -> applyEnabled(BurpTcp.Direction.SERVER_TO_CLIENT, s2c.isSelected()));

        JButton refresh = new JButton("Refresh");
        refresh.addActionListener(event -> refreshAll());
        forward.addActionListener(event -> forwardEdited());
        forwardAll.addActionListener(event -> forwardAll());
        suppress.addActionListener(event -> decide(selectedUnit(), BurpTcp.InterceptActionKind.SUPPRESS, null));
        close.addActionListener(event -> decide(selectedUnit(), BurpTcp.InterceptActionKind.CLOSE, null));
        restore.addActionListener(event -> {
            if (editing != null) editor.loadBytes(editing.getBytes().toByteArray());
        });
        forward.setToolTipText("Forward current bytes; edits are sent as a replacement (Ctrl/Cmd+Enter)");
        forwardAll.setToolTipText("Forward every held unit unchanged, oldest first; keeps intercept enabled");
        suppress.setToolTipText("Discard only this slice; the connection stays open but the stream loses these bytes");
        close.setToolTipText("Terminate this TCP connection in both directions; the app sees a broken connection");
        TrafficActions.shortcut(this, KeyEvent.VK_ENTER, "Forward", this::forwardEdited);
        TrafficActions.shortcut(this, KeyEvent.VK_R, "Send to Repeater", this::sendSelectedToRepeater);
        JPopupMenu menu = new JPopupMenu();
        JMenuItem send = new JMenuItem("Send edited bytes to Repeater");
        send.addActionListener(event -> sendSelectedToRepeater());
        menu.add(send);
        JMenuItem decode = new JMenuItem("Send to Decoder");
        decode.addActionListener(event -> {
            if (editing == null) return;
            try { decoder.accept(editor.getBytes()); }
            catch (IllegalArgumentException invalid) { notifier.accept(invalid.getMessage()); }
        });
        menu.add(decode);
        TrafficActions.popup(table, menu);

        JPanel top = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
        top.add(c2s);
        top.add(s2c);
        top.add(refresh);

        JPanel actions = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
        actions.add(forward);
        actions.add(forwardAll);
        actions.add(suppress);
        actions.add(close);
        actions.add(restore);
        JButton sendButton = new JButton("Send to Repeater");
        sendButton.addActionListener(event -> sendSelectedToRepeater());
        actions.add(sendButton);

        JPanel editingPanel = new JPanel(new BorderLayout(4, 4));
        editingPanel.add(selection, BorderLayout.NORTH);
        editingPanel.add(editor, BorderLayout.CENTER);
        JPanel toolbar = new JPanel(new BorderLayout(4, 4));
        toolbar.add(top, BorderLayout.NORTH);
        toolbar.add(actions, BorderLayout.SOUTH);
        JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT, TrafficActions.scroll(table), editingPanel);
        split.setResizeWeight(0.28);
        JPanel footer = new JPanel(new BorderLayout());
        footer.add(notice, BorderLayout.NORTH);
        footer.add(stats, BorderLayout.SOUTH);

        add(toolbar, BorderLayout.NORTH);
        add(split, BorderLayout.CENTER);
        add(footer, BorderLayout.SOUTH);

        setConnected(false);
    }

    /** Override the error/notification sink (tests supply a collector). */
    void setNotifier(java.util.function.Consumer<String> notifier) {
        this.notifier = notifier;
    }

    /** Enable/disable controls and reset derived state on connection change. */
    public void setConnected(boolean connected) {
        connectionEpoch++;
        togglesInFlight = 0;
        this.controlsEnabled = connected;
        c2s.setEnabled(connected);
        s2c.setEnabled(connected);
        if (!connected) {
            pendingSeq++;
            statsSeq++;
            statsLoading = false;
            pendingLoading = false;
            drafts.clear();
            decisionsInFlight.clear();
            committed.clear();
            editing = null;
            applyPending(List.of());
            applyEnabledState(false, false);
            stats.setText(" ");
        }
        updateActions();
    }

    /** Refresh the pending queue and authoritative policy/stats. */
    public void refreshAll() {
        if (!controlsEnabled) {
            return;
        }
        long pSeq = ++pendingSeq;
        pendingLoading = true;
        client.pendingUnits().whenComplete((list, error) -> SwingUtilities.invokeLater(() -> {
            if (pSeq == pendingSeq) {
                pendingLoading = false;
                if (error == null) {
                    Set<String> ids = new HashSet<>();
                    list.getUnitsList().forEach(unit -> ids.add(unit.getUnitId()));
                    committed.retainAll(ids);
                    applyPending(list.getUnitsList().stream()
                            .filter(unit -> !committed.contains(unit.getUnitId())).toList());
                } else {
                    notice.setText("Queue refresh failed: " + error.getMessage());
                }
            }
        }));
        refreshPolicy();
    }

    void refreshLive() {
        updateSelectionLabel();
        if (!pendingLoading) refreshAll();
    }

    public void setRepeaterListener(BiConsumer<String, byte[]> listener) { repeater = listener; }
    public void setDecoderListener(java.util.function.Consumer<byte[]> listener) { decoder = listener; }
    public void setDestinationResolver(Function<String, String> resolver) { destination = resolver; }
    public void setQueueListener(java.util.function.IntConsumer listener) { queueListener = listener; }

    private void saveDraft() {
        if (editing != null) drafts.put(editing.getUnitId(),
                new Draft(editing.getRevision(), editor.captureDraft()));
    }

    private void applyPending(List<BurpTcp.PendingUnitInfo> units) {
        if (model.rows().equals(units)) {
            updateActions();
            return;
        }
        String selectedId = editing == null ? null : editing.getUnitId();
        Set<String> ids = new HashSet<>();
        units.forEach(unit -> ids.add(unit.getUnitId()));
        drafts.keySet().retainAll(ids);
        if (editing != null && !ids.contains(selectedId) && !committed.contains(selectedId)) {
            notice.setText("Previous unit released or expired; its edit was not sent.");
        }
        applying = true;
        try {
            model.set(units);
            for (int i = 0; i < units.size(); i++) {
                if (units.get(i).getUnitId().equals(selectedId)) {
                    int view = table.convertRowIndexToView(i);
                    table.setRowSelectionInterval(view, view);
                    break;
                }
            }
            if (table.getSelectedRow() < 0 && table.getRowCount() > 0) table.setRowSelectionInterval(0, 0);
        } finally {
            applying = false;
        }
        showSelected();
        // showSelected saves the previous editor; prune again after switching.
        drafts.keySet().retainAll(ids);
        queueListener.accept(units.size());
    }

    private void showSelected() {
        BurpTcp.PendingUnitInfo next = selectedUnit();
        if (editing != null && next != null && editing.getUnitId().equals(next.getUnitId())
                && editing.getRevision() == next.getRevision()) {
            editing = next;
            updateActions();
            return; // Preserve caret, selection, undo history and partially typed hex.
        }
        saveDraft();
        editing = next;
        editor.loadBytes(next == null ? new byte[0] : next.getBytes().toByteArray());
        if (next != null) {
            Draft draft = drafts.get(next.getUnitId());
            if (draft != null && draft.revision() == next.getRevision()) {
                editor.restoreDraft(draft.content());
            }
        }
        updateActions();
    }

    private void updateActions() {
        boolean enabled = controlsEnabled && editing != null
                && !decisionsInFlight.contains(editing.getUnitId());
        forward.setEnabled(enabled);
        forwardAll.setEnabled(controlsEnabled && !model.rows().isEmpty());
        suppress.setEnabled(enabled);
        close.setEnabled(enabled);
        restore.setEnabled(enabled);
        editor.setEditable(enabled);
        updateSelectionLabel();
    }

    private void updateSelectionLabel() {
        if (editing == null) {
            selection.setText("No traffic held. Enable a direction to intercept.");
        } else {
            long seconds = Math.max(0, (editing.getExpiresUnixMs() - System.currentTimeMillis() + 999) / 1000);
            String text = destination.apply(editing.getConnId()) + " · "
                    + Display.direction(editing.getDirection()) + " · " + editing.getBytes().size()
                    + " bytes · auto-release in " + seconds + "s";
            if (editing.getSeq() > 0) {
                text += " · stream slice #" + (editing.getSeq() + 1)
                        + ": Drop/Replace here alters a running transfer, Close breaks it";
            }
            selection.setText(text);
        }
    }

    /** Selection description line, for tests. */
    String selectionText() {
        return selection.getText();
    }

    void forwardEdited() {
        if (!forward.isEnabled()) return;
        try {
            byte[] bytes = editor.getBytes();
            byte[] original = editing.getBytes().toByteArray();
            boolean changed = !Arrays.equals(bytes, original);
            // Text-mode Content-Length maintenance already happened inside
            // getBytes; Hex mode sends exact bytes by contract.
            decide(editing, changed ? BurpTcp.InterceptActionKind.REPLACE
                    : BurpTcp.InterceptActionKind.FORWARD, changed ? bytes : null);
        } catch (IllegalArgumentException invalid) {
            notifier.accept("Invalid bytes: " + invalid.getMessage());
        }
    }

    /**
     * Forward every held unit unchanged, oldest first, without disabling
     * interception. Unblocks multi-packet handshakes (each round trip is
     * otherwise held until its lease expires) while keeping the policy on
     * for later connections. Units already decided or in flight are skipped
     * by {@link #decide}.
     */
    void forwardAll() {
        if (!forwardAll.isEnabled()) return;
        for (BurpTcp.PendingUnitInfo unit : model.rows()) {
            decide(unit, BurpTcp.InterceptActionKind.FORWARD, null);
        }
    }

    void sendSelectedToRepeater() {
        if (editing == null) return;
        try {
            repeater.accept(editing.getConnId(), editor.getBytes());
        } catch (IllegalArgumentException invalid) {
            notifier.accept("Invalid bytes: " + invalid.getMessage());
        }
    }

    BinaryEditorPanel editor() { return editor; }

    /**
     * Re-read only the authoritative enable policy and stats. Called by the
     * periodic status refresh so a policy changed by another controller (or a
     * fail-open) is reflected even when no count-bearing event fires. Skipped
     * while a local toggle is in flight so it cannot fight the user.
     */
    void refreshPolicy() {
        if (!controlsEnabled || togglesInFlight > 0 || statsLoading) {
            return;
        }
        long sSeq = ++statsSeq;
        statsLoading = true;
        client.stats().whenComplete((value, error) -> SwingUtilities.invokeLater(() -> {
            if (sSeq == statsSeq) {
                statsLoading = false;
                if (togglesInFlight == 0 && error == null) applyStats(value);
            }
        }));
    }

    private void applyStats(BurpTcp.Stats value) {
        applyEnabledState(value.getC2SEnabled(), value.getS2CEnabled());
        stats.setText(String.format(
                "Held total: %d · Decisions: %d · Bypassed (queue full): %d · Expired: %d · Released on disable: %d · Abandoned: %d · Event drops: %d",
                value.getOffers(), value.getCommits(), value.getOverflowForwards(),
                value.getLeaseReleases(),
                value.getDisableReleases(), value.getAbandoned(),
                value.getIpcDroppedEvents()));
    }

    /** Stats line text, for tests. */
    String statsText() {
        return stats.getText();
    }

    private void applyEnabledState(boolean c2sEnabled, boolean s2cEnabled) {
        authoritativeC2s = c2sEnabled;
        authoritativeS2c = s2cEnabled;
        syncing = true;
        try {
            c2s.setSelected(c2sEnabled);
            s2c.setSelected(s2cEnabled);
        } finally {
            syncing = false;
        }
    }

    private void applyEnabled(BurpTcp.Direction direction, boolean enabled) {
        if (syncing) {
            return;
        }
        togglesInFlight++;
        long epoch = connectionEpoch;
        // Invalidate any Stats response already in flight: it predates this
        // toggle and must not overwrite the user's intent when it lands.
        statsSeq++;
        statsLoading = false;
        client.setEnabled(direction, enabled).whenComplete((result, error) -> SwingUtilities.invokeLater(() -> {
            if (epoch != connectionEpoch) return;
            togglesInFlight--;
            if (error != null) {
                // Restore the last authoritative state before notifying: the
                // default notifier blocks until the dialog is dismissed, so an
                // optimistic toggle the engine rejected must not remain
                // visible. Recovery does not depend on a further Stats call.
                applyEnabledState(authoritativeC2s, authoritativeS2c);
                notifier.accept("SetEnabled failed: " + error.getMessage());
                return;
            }
            // Success: adopt this direction authoritatively now, so a later
            // failure of a *different*, still-pending toggle restores the
            // confirmed value instead of a stale one. A follow-up Stats refines
            // the full policy.
            if (direction == BurpTcp.Direction.CLIENT_TO_SERVER) {
                authoritativeC2s = enabled;
            } else {
                authoritativeS2c = enabled;
            }
            refreshAll();
        }));
    }

    /** The unit currently selected in the table, or {@code null}. */
    BurpTcp.PendingUnitInfo selectedUnit() {
        int viewRow = table.getSelectedRow();
        if (viewRow < 0) {
            return null;
        }
        return model.get(table.convertRowIndexToModel(viewRow));
    }

    /**
     * Commit a decision against an explicitly captured unit.
     *
     * <p>Takes the unit rather than reading the table, so a later snapshot
     * cannot retarget an in-flight decision.
     */
    void decide(BurpTcp.PendingUnitInfo unit, BurpTcp.InterceptActionKind action, byte[] replaceBytes) {
        if (unit == null) {
            notifier.accept("Select a pending unit first.");
            return;
        }
        if (!controlsEnabled || committed.contains(unit.getUnitId())
                || !decisionsInFlight.add(unit.getUnitId())) return;
        long epoch = connectionEpoch;
        updateActions();
        client.decide(unit.getUnitId(), unit.getRevision(), action, replaceBytes)
                .whenComplete((result, error) -> SwingUtilities.invokeLater(() -> {
                    if (epoch != connectionEpoch) return;
                    decisionsInFlight.remove(unit.getUnitId());
                    updateActions();
                    if (error != null) {
                        notifier.accept("Decide failed: " + error.getMessage());
                        refreshAll();
                        return;
                    }
                    if (!result.getCommitted()) {
                        notifier.accept("Decision not committed: " + result.getErrorKind()
                                + (result.getExpectedRevision() > 0
                                        ? " (expected revision " + result.getExpectedRevision() + ")" : ""));
                    } else {
                        committed.add(unit.getUnitId());
                        String applied = "Decision applied · " + Display.shortId(unit.getUnitId());
                        if (action == BurpTcp.InterceptActionKind.REPLACE && replaceBytes != null
                                && replaceBytes.length != unit.getBytes().size()) {
                            applied += " · size " + unit.getBytes().size() + " → " + replaceBytes.length
                                    + " bytes; length-framed protocols may reject this";
                        }
                        notice.setText(applied);
                        applyPending(model.rows().stream()
                                .filter(row -> !row.getUnitId().equals(unit.getUnitId())).toList());
                    }
                    refreshAll();
                }));
    }

    /**
     * Capture the current replacement target independently of later selection.
     */
    BurpTcp.PendingUnitInfo captureReplaceTarget() {
        return selectedUnit();
    }

    /** Commit a replacement against an explicitly captured unit. */
    void commitReplace(BurpTcp.PendingUnitInfo unit, byte[] bytes) {
        decide(unit, BurpTcp.InterceptActionKind.REPLACE, bytes);
    }

    /** Pending units currently shown, for tests. */
    List<BurpTcp.PendingUnitInfo> displayedUnits() {
        return model.rows();
    }

    /** Select a table row by view index, for tests. */
    void selectRow(int viewRow) {
        table.setRowSelectionInterval(viewRow, viewRow);
    }

    /** Click the Client→Server toggle as a user would, for tests. */
    void clickClientToServerToggle() {
        c2s.doClick();
    }

    /** Click Forward all as a user would, for tests. */
    void clickForwardAll() {
        forwardAll.doClick();
    }

    /** Whether Forward all is currently clickable, for tests. */
    boolean isForwardAllEnabled() {
        return forwardAll.isEnabled();
    }

    /** Click the Server→Client toggle as a user would, for tests. */
    void clickServerToClientToggle() {
        s2c.doClick();
    }

    /** Authoritative enable state as displayed, for tests. */
    boolean[] displayedEnabledState() {
        return new boolean[] {c2s.isSelected(), s2c.isSelected()};
    }

    boolean controlsEnabled() {
        return controlsEnabled;
    }

    private final class Model extends AbstractTableModel {

        private static final String[] COLUMNS =
                {"#", "Destination", "Traffic", "Size (bytes)", "Auto-release at", "Preview"};

        private List<BurpTcp.PendingUnitInfo> rows = new ArrayList<>();

        void set(List<BurpTcp.PendingUnitInfo> newRows) {
            this.rows = new ArrayList<>(newRows);
            fireTableDataChanged();
        }

        BurpTcp.PendingUnitInfo get(int row) {
            return rows.get(row);
        }

        List<BurpTcp.PendingUnitInfo> rows() {
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
            return column == 0 ? Integer.class : column == 3 ? Long.class : String.class;
        }

        @Override
        public Object getValueAt(int row, int column) {
            BurpTcp.PendingUnitInfo unit = rows.get(row);
            return switch (column) {
                case 0 -> row + 1;
                case 1 -> destination.apply(unit.getConnId());
                case 2 -> Display.direction(unit.getDirection());
                case 3 -> (long) unit.getBytes().size();
                case 4 -> Display.time(unit.getExpiresUnixMs());
                default -> Display.preview(unit.getBytes().toByteArray());
            };
        }
    }
}
