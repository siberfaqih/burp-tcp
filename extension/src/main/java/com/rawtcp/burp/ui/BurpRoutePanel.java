package com.rawtcp.burp.ui;

import com.rawtcp.burp.ipc.ControlPlane;
import com.rawtcp.burp.ipc.proto.BurpTcp;
import com.rawtcp.burp.util.BurpRoutes;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JPanel;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.ListSelectionModel;
import javax.swing.SwingUtilities;
import javax.swing.table.AbstractTableModel;
import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.util.ArrayList;
import java.util.List;

/**
 * Burp Route tab: destinations the engine hands to a local Burp Proxy
 * listener instead of dialling directly.
 *
 * <p>A matching SOCKS session is relayed byte-for-byte to the configured
 * Burp listener, so native Proxy history, Intercept, Repeater, Intruder,
 * and Scanner can be used. Routed sessions bypass engine interception
 * (Burp owns the hold queue there) and are marked "via Burp" in
 * Connections. Point a Burp Proxy listener at the Burp address with
 * invisible proxying and a redirect to the real target.
 */
public final class BurpRoutePanel extends JPanel {

    private final ControlPlane client;
    private final Model model = new Model();
    private final JTable table = new JTable(model);
    private final JTextField ruleField = new JTextField(32);
    private final JButton addButton = new JButton("Add");
    private final JButton removeButton = new JButton("Remove selected");
    private final JButton applyButton = new JButton("Apply");
    private final JButton refreshButton = new JButton("Refresh");
    private final JButton clearButton = new JButton("Clear");
    private final javax.swing.JLabel status = new javax.swing.JLabel(" ");
    private long requestSeq;
    private boolean connected;

    public BurpRoutePanel(ControlPlane client) {
        super(new BorderLayout(4, 4));
        this.client = client;
        setBorder(BorderFactory.createEmptyBorder(4, 4, 4, 4));

        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        table.setFillsViewportHeight(true);

        ruleField.setToolTipText("HOST[:PORT]=>127.0.0.1:PORT, e.g. 10.0.0.5:7007=>127.0.0.1:8081");
        addButton.addActionListener(event -> addFromField());
        ruleField.addActionListener(event -> addFromField());
        removeButton.addActionListener(event -> removeSelected());
        applyButton.addActionListener(event -> apply());
        refreshButton.addActionListener(event -> refresh());
        clearButton.addActionListener(event -> {
            model.set(List.of());
            setStatus("Cleared locally — press Apply to push to the engine.");
        });

        JPanel top = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
        top.add(ruleField);
        top.add(addButton);
        top.add(removeButton);
        top.add(applyButton);
        top.add(refreshButton);
        top.add(clearButton);

        JTextArea help = new JTextArea(
                "Route matching SOCKS destinations to Burp, e.g. 10.0.0.5:7007=>127.0.0.1:8081 "
                + "(* matches any host, no :PORT matches any port). First match wins.\n"
                + "Burp setup: Proxy > Proxy settings > add listener on the Burp address, "
                + "enable invisible proxying, redirect to the real target. "
                + "Routed traffic bypasses Raw TCP intercept — use Burp Proxy intercept instead.");
        help.setEditable(false);
        help.setLineWrap(true);
        help.setWrapStyleWord(true);
        help.setBackground(getBackground());
        help.setBorder(BorderFactory.createEmptyBorder(4, 4, 4, 4));

        JPanel north = new JPanel(new BorderLayout());
        north.add(top, BorderLayout.NORTH);
        north.add(status, BorderLayout.SOUTH);

        add(north, BorderLayout.NORTH);
        add(TrafficActions.scroll(table), BorderLayout.CENTER);
        add(help, BorderLayout.SOUTH);
        setConnected(false);
    }

    /** Enable controls when the IPC session is live. Safe to call from any thread. */
    public void setConnected(boolean connected) {
        SwingUtilities.invokeLater(() -> {
            this.connected = connected;
            boolean on = connected;
            ruleField.setEnabled(on);
            addButton.setEnabled(on);
            removeButton.setEnabled(on);
            applyButton.setEnabled(on);
            refreshButton.setEnabled(on);
            clearButton.setEnabled(on);
            if (!on) {
                setStatus("Not connected.");
            }
        });
    }

    /** Whether the controls are currently enabled, for tests. */
    boolean controlsEnabled() {
        return applyButton.isEnabled();
    }

    /** Request the engine table; safe to call from any thread. */
    public void refresh() {
        long seq = ++requestSeq;
        client.listBurpRoutes().whenComplete((list, error) -> SwingUtilities.invokeLater(() -> {
            if (seq != requestSeq || !connected) {
                return;
            }
            if (error == null) {
                model.set(list.getRoutesList());
                setStatus(list.getRoutesCount() == 0
                        ? "No routes — traffic is dialled directly."
                        : list.getRoutesCount() + " route(s) active.");
            } else {
                setStatus("Refresh failed: " + message(error));
            }
        }));
    }

    void addFromField() {
        String raw = ruleField.getText().trim();
        if (raw.isEmpty()) {
            setStatus("Type a rule first, e.g. 10.0.0.5:7007=>127.0.0.1:8081.");
            return;
        }
        BurpTcp.BurpRoute route;
        try {
            route = BurpRoutes.parse(raw);
        } catch (IllegalArgumentException invalid) {
            setStatus("Invalid rule: " + invalid.getMessage());
            return;
        }
        model.add(route);
        ruleField.setText("");
        setStatus("Added locally — press Apply to push to the engine.");
    }

    void removeSelected() {
        int viewRow = table.getSelectedRow();
        if (viewRow < 0) {
            setStatus("Select a row to remove.");
            return;
        }
        model.remove(table.convertRowIndexToModel(viewRow));
        setStatus("Removed locally — press Apply to push to the engine.");
    }

    void apply() {
        long seq = ++requestSeq;
        List<BurpTcp.BurpRoute> routes = List.copyOf(model.rows);
        client.setBurpRoutes(routes).whenComplete((list, error) ->
                SwingUtilities.invokeLater(() -> {
                    if (seq != requestSeq || !connected) {
                        return;
                    }
                    if (error == null) {
                        model.set(list.getRoutesList());
                        setStatus(list.getRoutesCount() == 0
                                ? "Applied: routing cleared."
                                : "Applied: " + list.getRoutesCount() + " route(s) active.");
                    } else {
                        setStatus("Apply failed: " + message(error));
                    }
                }));
    }

    private void setStatus(String text) {
        status.setText(text);
    }

    /** Status line text, for tests. */
    String statusText() {
        return status.getText();
    }

    /** Rows currently shown, for tests. */
    int rowCount() {
        return model.getRowCount();
    }

    /** Rule input text, for tests. */
    void setRuleInput(String text) {
        ruleField.setText(text);
    }

    private static String message(Throwable error) {
        String message = error.getMessage();
        if (error instanceof java.util.concurrent.CompletionException && error.getCause() != null) {
            message = error.getCause().getMessage();
        }
        return message == null ? error.toString() : message;
    }

    private static final class Model extends AbstractTableModel {

        private static final String[] COLUMNS = {"Rule", "Host", "Port", "Burp listener"};

        private List<BurpTcp.BurpRoute> rows = new ArrayList<>();

        void set(List<BurpTcp.BurpRoute> newRows) {
            this.rows = new ArrayList<>(newRows);
            fireTableDataChanged();
        }

        void add(BurpTcp.BurpRoute route) {
            rows.add(route);
            fireTableDataChanged();
        }

        void remove(int row) {
            rows.remove(row);
            fireTableDataChanged();
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

        @Override
        public Object getValueAt(int row, int column) {
            BurpTcp.BurpRoute route = rows.get(row);
            return switch (column) {
                case 1 -> route.getHostPattern();
                case 2 -> route.getPort() == 0 ? "*" : Integer.toString(route.getPort());
                case 3 -> route.getBurpAddr();
                default -> BurpRoutes.format(route);
            };
        }
    }
}
