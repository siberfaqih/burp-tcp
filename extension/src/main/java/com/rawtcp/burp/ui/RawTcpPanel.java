package com.rawtcp.burp.ui;

import com.rawtcp.burp.SettingsStore;
import com.rawtcp.burp.ipc.IpcListener;
import com.rawtcp.burp.ipc.IpcSession;
import com.rawtcp.burp.ipc.proto.BurpTcp;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JTabbedPane;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;
import javax.swing.Timer;
import java.awt.BorderLayout;
import java.awt.FlowLayout;

/**
 * Top-level Raw TCP suite tab: connection bar plus the Connections,
 * History, Intercept, and Repeater sub-tabs.
 *
 * <p>Implements {@link IpcListener} to drive UI refreshes from engine
 * events, always marshalling onto the event dispatch thread. The panel
 * never performs network I/O on the EDT, and {@link #dispose()} releases
 * the status timer and detaches the listener so unload leaves nothing
 * running.
 */
public final class RawTcpPanel extends JPanel implements IpcListener {

    private static final String KEY_PORT = "rawtcp.ipc.port";
    private static final String KEY_TOKEN = "rawtcp.ipc.token";
    private final IpcSession client;
    private final SettingsStore settings;

    private final JTextField portField = new JTextField(6);
    private final JTextField tokenField = new JTextField(40);
    private final JButton connectButton = new JButton("Connect");
    private final JLabel status = new JLabel(" ");
    private final JLabel events = new JLabel(" ");

    private final ConnectionsPanel connections;
    private final HistoryPanel history;
    private final InterceptPanel intercept;
    private final RepeaterWorkspace repeater;
    private final JTabbedPane tabs = new JTabbedPane();
    private final UrlToolsPanel decoder = new UrlToolsPanel();
    private boolean connected;

    private final Timer statusTimer;

    private boolean started;
    private String lastEpoch;
    private long lastConnectionCount = -1;
    private long lastPendingCount = -1;
    private long lastEventSeq;
    private int statusTicks;
    /**
     * Bumped on every connect/disconnect/dispose. Listener callbacks capture
     * it when they queue an EDT action and drop the action if the session has
     * since changed, so a callback queued before a disconnect can never
     * re-enable controls after it.
     */
    private volatile long sessionEpoch;
    /** Terminal once {@link #dispose()} has run; no callback may act afterwards. */
    private volatile boolean disposed;

    public RawTcpPanel(IpcSession client, SettingsStore settings) {
        super(new BorderLayout(4, 4));
        this.client = client;
        this.settings = settings;

        this.connections = new ConnectionsPanel(client);
        this.history = new HistoryPanel(client);
        this.intercept = new InterceptPanel(client);
        this.repeater = new RepeaterWorkspace(client);

        connections.setSelectionListener(history::setConnection);
        connections.setSnapshotListener(history::setConnections);
        history.setRepeaterListener(this::sendToRepeater);
        intercept.setRepeaterListener(this::sendToRepeater);
        history.setDecoderListener(this::sendToDecoder);
        intercept.setDecoderListener(this::sendToDecoder);
        java.util.function.Function<String, String> destination = id -> {
            BurpTcp.ConnectionInfo info = connections.connection(id);
            return info == null ? com.rawtcp.burp.util.Display.shortId(id)
                    : info.getRequestedHost() + ":" + info.getRequestedPort();
        };
        intercept.setDestinationResolver(destination);
        history.setDestinationResolver(destination);
        intercept.setQueueListener(count -> {
            int index = tabs.indexOfComponent(intercept);
            if (index >= 0) tabs.setTitleAt(index, count == 0 ? "Intercept" : "Intercept (" + count + ")");
        });

        portField.setText(settings.get(KEY_PORT, "8080"));
        tokenField.setText(settings.get(KEY_TOKEN, ""));
        tokenField.setToolTipText("Per-launch capability token printed by the engine at startup");

        connectButton.addActionListener(event -> toggleConnection());

        JPanel bar = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
        bar.add(new JLabel("Engine IPC 127.0.0.1:"));
        bar.add(portField);
        bar.add(new JLabel("Token:"));
        bar.add(tokenField);
        bar.add(connectButton);

        tabs.addTab("Intercept", intercept);
        tabs.addTab("TCP history", history);
        tabs.addTab("Repeater", repeater);
        tabs.addTab("Decoder", decoder);
        tabs.addTab("Connections", connections);

        JPanel north = new JPanel(new BorderLayout());
        JPanel statusRow = new JPanel(new BorderLayout());
        statusRow.add(status, BorderLayout.WEST);
        statusRow.add(events, BorderLayout.EAST);
        north.add(bar, BorderLayout.NORTH);
        north.add(statusRow, BorderLayout.SOUTH);

        add(north, BorderLayout.NORTH);
        add(tabs, BorderLayout.CENTER);

        client.addListener(this);

        statusTimer = new Timer(500, event -> {
            status.setText(client.status());
            // Periodically reconcile the authoritative interception policy so
            // a change made by another controller (or a fail-open) is shown
            // even when no count-bearing event fires.
            if (connected) {
                intercept.refreshLive();
                if (++statusTicks % 2 == 0) {
                    connections.refreshLive();
                    if (tabs.getSelectedComponent() == history) history.refreshLive();
                }
            }
        });
        statusTimer.setInitialDelay(0);
        statusTimer.start();
    }

    private void sendToRepeater(String connId, byte[] bytes) {
        BurpTcp.ConnectionInfo info = connections.connection(connId);
        String host = info == null ? "" : info.getRequestedHost();
        int port = info == null ? 0 : info.getRequestedPort();
        repeater.open(host, port, bytes, "From connection " + com.rawtcp.burp.util.Display.shortId(connId));
        tabs.setSelectedComponent(repeater);
    }

    private void sendToDecoder(byte[] bytes) {
        decoder.load(bytes);
        tabs.setSelectedComponent(decoder);
    }

    public void setTheme(java.util.function.Consumer<java.awt.Component> theme) {
        repeater.setTheme(theme);
        theme.accept(this);
    }

    /**
     * Release UI resources: stop the status timer and detach the listener.
     * Called from the extension's unloading handler.
     */
    public void dispose() {
        disposed = true;
        sessionEpoch++;
        connected = false;
        connections.clear();
        history.clear();
        intercept.setConnected(false);
        repeater.setConnected(false);
        statusTimer.stop();
        client.removeListener(this);
    }

    /** Connect using the fields, or disconnect when already started. */
    public void toggleConnection() {
        if (disposed) {
            return;
        }
        if (started) {
            // Invalidate any callback already queued for this session before
            // clearing state, so a stale onConnected cannot re-enable it.
            sessionEpoch++;
            client.stop();
            started = false;
            connectButton.setText("Connect");
            status.setText("disconnected");
            onDisconnectedInternal();
            return;
        }

        String rawPort = portField.getText().trim();
        int port;
        try {
            port = Integer.parseInt(rawPort);
        } catch (NumberFormatException invalid) {
            JOptionPane.showMessageDialog(this, "IPC port must be a number.",
                    "Raw TCP", JOptionPane.ERROR_MESSAGE);
            return;
        }
        if (port < 1 || port > 65535) {
            JOptionPane.showMessageDialog(this, "IPC port must be 1..65535.",
                    "Raw TCP", JOptionPane.ERROR_MESSAGE);
            return;
        }
        String token = tokenField.getText().trim();
        if (token.isEmpty()) {
            JOptionPane.showMessageDialog(this,
                    "Paste the capability token printed by the engine at startup.",
                    "Raw TCP", JOptionPane.ERROR_MESSAGE);
            return;
        }

        settings.put(KEY_PORT, Integer.toString(port));
        settings.put(KEY_TOKEN, token);
        // Start a fresh session epoch: callbacks from any earlier session are
        // now stale.
        sessionEpoch++;
        started = true;
        connectButton.setText("Disconnect");
        client.start("127.0.0.1", port, token);
    }

    // --- IpcListener (background threads) ------------------------------

    /**
     * Queue an EDT action that is dropped if the session changed (disconnect,
     * reconnect, or dispose) between queueing and execution.
     */
    private void onEdtIfCurrent(Runnable action) {
        long epoch = sessionEpoch;
        SwingUtilities.invokeLater(() -> {
            if (!disposed && epoch == sessionEpoch) {
                action.run();
            }
        });
    }

    @Override
    public void onConnected(BurpTcp.HelloAck ack) {
        onEdtIfCurrent(() -> {
            connected = true;
            connectButton.setText("Disconnect");
            // A daemon restart invalidates all previously observed state.
            if (lastEpoch != null && !lastEpoch.equals(ack.getDaemonEpoch())) {
                history.clear();
                lastEventSeq = 0;
                events.setText(" ");
            }
            lastEpoch = ack.getDaemonEpoch();
            intercept.setConnected(true);
            repeater.setConnected(true);
            connections.refresh();
            intercept.refreshAll();
        });
    }

    @Override
    public void onDisconnected(String reason) {
        onEdtIfCurrent(() -> {
            status.setText("disconnected: " + reason);
            onDisconnectedInternal();
        });
    }

    private void onDisconnectedInternal() {
        connected = false;
        lastConnectionCount = -1;
        lastPendingCount = -1;
        lastEventSeq = 0;
        events.setText(" ");
        connections.clear();
        history.clear();
        intercept.setConnected(false);
        repeater.setConnected(false);
    }

    @Override
    public void onEvent(BurpTcp.Event event) {
        if (!event.hasStateChanged()) {
            return;
        }
        long conns = event.getStateChanged().getConnectionCount();
        long pending = event.getStateChanged().getPendingCount();
        long seq = event.getSeq();
        onEdtIfCurrent(() -> {
            // Surface the per-server event sequence as a diagnostic. A gap
            // does not by itself mean dropped events: the sequence is shared
            // across clients.
            lastEventSeq = seq;
            events.setText("last event seq " + seq);
            if (conns != lastConnectionCount) {
                lastConnectionCount = conns;
                connections.refreshLive();
            }
            if (pending != lastPendingCount) {
                lastPendingCount = pending;
                intercept.refreshLive();
            }
        });
    }

    /** True while the connect/reconnect loop is running. */
    public boolean isStarted() {
        return started;
    }

    /** Status timer running state, for tests. */
    boolean isStatusTimerRunning() {
        return statusTimer.isRunning();
    }

    /** Last observed per-server event sequence, for tests. */
    long lastEventSeq() {
        return lastEventSeq;
    }

    /** Event-sequence label text, for tests. */
    String eventsLabel() {
        return events.getText();
    }

    ConnectionsPanel connectionsPanel() {
        return connections;
    }

    HistoryPanel historyPanel() {
        return history;
    }

    InterceptPanel interceptPanel() {
        return intercept;
    }

    RepeaterPanel repeaterPanel() {
        return repeater.selected();
    }
}
