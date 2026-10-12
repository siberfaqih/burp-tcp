package com.rawtcp.burp.ui;

import com.rawtcp.burp.ipc.ControlPlane;
import com.rawtcp.burp.ipc.proto.BurpTcp;
import com.rawtcp.burp.util.Display;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JPanel;
import javax.swing.JTable;
import javax.swing.ListSelectionModel;
import javax.swing.SwingUtilities;
import javax.swing.table.AbstractTableModel;
import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

/** Connections tab: the live session list from {@code ListConnections}. */
public final class ConnectionsPanel extends JPanel {

    private final ControlPlane client;
    private final Model model = new Model();
    private final JTable table = new JTable(model) {
        @Override public String getToolTipText(java.awt.event.MouseEvent event) {
            int row = rowAtPoint(event.getPoint());
            if (row < 0) return null;
            BurpTcp.ConnectionInfo info = model.get(convertRowIndexToModel(row));
            String tip = "Connection " + info.getConnId();
            if (!info.getCloseReason().isEmpty()) tip += " · ended: " + info.getCloseReason();
            return tip;
        }
    };
    private Consumer<String> selectionListener = connId -> {};
    private long requestSeq;
    private boolean applying;
    private boolean loading;
    private Consumer<List<BurpTcp.ConnectionInfo>> snapshotListener = rows -> {};

    public ConnectionsPanel(ControlPlane client) {
        super(new BorderLayout(4, 4));
        this.client = client;
        setBorder(BorderFactory.createEmptyBorder(4, 4, 4, 4));

        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        table.setAutoCreateRowSorter(true);
        table.setFillsViewportHeight(true);
        table.getSelectionModel().addListSelectionListener(event -> {
            if (event.getValueIsAdjusting() || applying) {
                return;
            }
            int viewRow = table.getSelectedRow();
            if (viewRow < 0) {
                return;
            }
            selectionListener.accept(model.get(table.convertRowIndexToModel(viewRow)).getConnId());
        });

        JButton refresh = new JButton("Refresh");
        refresh.addActionListener(event -> refresh());
        JPanel top = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
        top.add(refresh);

        add(top, BorderLayout.NORTH);
        add(TrafficActions.scroll(table), BorderLayout.CENTER);
    }

    public void setSelectionListener(Consumer<String> listener) {
        this.selectionListener = listener;
    }

    public void setSnapshotListener(Consumer<List<BurpTcp.ConnectionInfo>> listener) {
        snapshotListener = listener;
    }

    public BurpTcp.ConnectionInfo connection(String id) {
        return model.rows.stream().filter(row -> row.getConnId().equals(id)).findFirst().orElse(null);
    }

    void refreshLive() { if (!loading) refresh(); }

    /** Request a fresh snapshot; safe to call from any thread. */
    public void refresh() {
        long seq = ++requestSeq;
        loading = true;
        client.listConnections().whenComplete((list, error) -> SwingUtilities.invokeLater(() -> {
            if (seq != requestSeq) {
                return;
            }
            loading = false;
            if (error == null) {
                String selected = table.getSelectedRow() < 0 ? null
                        : model.get(table.convertRowIndexToModel(table.getSelectedRow())).getConnId();
                applying = true;
                try {
                    model.set(list.getConnectionsList());
                    for (int i = 0; i < model.getRowCount(); i++) {
                        if (model.get(i).getConnId().equals(selected)) {
                            int view = table.convertRowIndexToView(i);
                            table.setRowSelectionInterval(view, view);
                            break;
                        }
                    }
                } finally {
                    applying = false;
                }
                snapshotListener.accept(List.copyOf(model.rows));
            }
        }));
    }

    /** Drop all rows and invalidate in-flight snapshots (e.g. on disconnect). */
    public void clear() {
        requestSeq++;
        loading = false;
        model.set(List.of());
        snapshotListener.accept(List.of());
    }

    /** Number of rows currently shown, for tests. */
    int rowCount() {
        return model.getRowCount();
    }

    /** Cell value at a view position, for tests. */
    Object cellValue(int viewRow, int column) {
        return model.getValueAt(table.convertRowIndexToModel(viewRow), column);
    }

    private static final class Model extends AbstractTableModel {

        private static final String[] COLUMNS =
                {"#", "Host", "Port", "Status", "Sent (bytes)", "Received (bytes)", "Ended"};

        private List<BurpTcp.ConnectionInfo> rows = new ArrayList<>();

        void set(List<BurpTcp.ConnectionInfo> newRows) {
            this.rows = new ArrayList<>(newRows);
            fireTableDataChanged();
        }

        BurpTcp.ConnectionInfo get(int row) {
            return rows.get(row);
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
            return column == 0 || column == 2 ? Integer.class : column >= 4 && column <= 5 ? Long.class : String.class;
        }

        @Override
        public Object getValueAt(int row, int column) {
            BurpTcp.ConnectionInfo info = rows.get(row);
            return switch (column) {
                case 0 -> row + 1;
                case 1 -> info.getRequestedHost();
                case 2 -> info.getRequestedPort();
                case 3 -> Display.connectionState(info);
                case 4 -> info.getBytesClientToServer();
                case 5 -> info.getBytesServerToClient();
                default -> info.getCloseReason();
            };
        }
    }
}
