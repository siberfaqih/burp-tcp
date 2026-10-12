package com.rawtcp.burp.ui;

import com.rawtcp.burp.ipc.ControlPlane;
import com.rawtcp.burp.ipc.proto.BurpTcp;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JSplitPane;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;
import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;

/**
 * Repeater tab: one explicitly approved manual TCP send per click.
 *
 * <p>Each send opens a fresh engine-side TCP session, writes the payload
 * exactly once, captures a bounded response, and then closes. The panel
 * never retries a send: status polling only reads the operation already
 * accepted by the engine. While a send is active, the Send button is
 * disabled and Stop requests cancellation of that operation only.
 */
public final class RepeaterPanel extends JPanel {

    private static final int MAX_HOST_BYTES = 255;
    private static final int MAX_PAYLOAD_BYTES = 65_536;
    private static final int MAX_RESPONSE_BYTES = 262_144;
    private static final long MAX_TIMEOUT_MS = 30_000L;
    private static final long MAX_IDLE_TIMEOUT_MS = 10_000L;
    private static final long STATUS_POLL_DELAY_MS = 100L;

    private final ControlPlane client;
    private final JTextField hostField = new JTextField("127.0.0.1", 18);
    private final JTextField portField = new JTextField("7", 6);
    private final JComboBox<String> completion = new JComboBox<>(new String[] {
            "Read until close",
            "Read exact response size",
            "Read until idle",
    });
    private final JTextField responseLimitField = new JTextField("4096", 7);
    private final JTextField timeoutField = new JTextField("5000", 7);
    private final JTextField idleTimeoutField = new JTextField("0", 7);
    private final BinaryEditorPanel payload = new BinaryEditorPanel();
    private final ByteViewPanel responseView = new ByteViewPanel();
    private final JButton send = new JButton("Send");
    private final JButton stop = new JButton("Stop");
    private final JLabel status = new JLabel("disconnected");
    private final JLabel source = new JLabel("Manual TCP send · fresh connection per send");
    private boolean workspaceBusy;
    private Consumer<Boolean> activityListener = busy -> {};
    private Consumer<String> notifier = message ->
            JOptionPane.showMessageDialog(this, message, "Raw TCP", JOptionPane.WARNING_MESSAGE);

    private boolean controlsEnabled;
    private boolean sendInFlight;
    private String activeSendId;
    /** Invalidates queued status callbacks on disconnect or completion. */
    private long opSeq;

    public RepeaterPanel(ControlPlane client) {
        super(new BorderLayout(4, 4));
        this.client = client;
        setBorder(BorderFactory.createEmptyBorder(4, 4, 4, 4));

        send.addActionListener(event -> startSend());
        stop.addActionListener(event -> stopSend());

        JPanel form = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
        form.add(new JLabel("Host:"));
        form.add(hostField);
        form.add(new JLabel("Port:"));
        form.add(portField);
        form.add(send);
        form.add(stop);
        JPanel options = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
        options.add(new JLabel("Completion:"));
        options.add(completion);
        options.add(new JLabel("Response limit:"));
        options.add(responseLimitField);
        options.add(new JLabel("Timeout ms:"));
        options.add(timeoutField);
        options.add(new JLabel("Idle ms:"));
        options.add(idleTimeoutField);
        JPanel toolbar = new JPanel(new java.awt.GridLayout(0, 1, 0, 4));
        toolbar.add(form);
        toolbar.add(options);
        toolbar.add(source);
        TrafficActions.shortcut(this, java.awt.event.KeyEvent.VK_ENTER, "Send", this::startSend);

        JPanel requestPanel = new JPanel(new BorderLayout());
        requestPanel.setBorder(BorderFactory.createTitledBorder("Request"));
        requestPanel.add(payload, BorderLayout.CENTER);
        JPanel responsePanel = new JPanel(new BorderLayout());
        responsePanel.setBorder(BorderFactory.createTitledBorder("Response"));
        responsePanel.add(responseView, BorderLayout.CENTER);
        requestPanel.setPreferredSize(new java.awt.Dimension(500, 300));
        responsePanel.setPreferredSize(new java.awt.Dimension(500, 300));
        requestPanel.setMinimumSize(new java.awt.Dimension(150, 100));
        responsePanel.setMinimumSize(new java.awt.Dimension(150, 100));
        JSplitPane split = new JSplitPane(
                JSplitPane.VERTICAL_SPLIT,
                requestPanel,
                responsePanel);
        split.setResizeWeight(0.65);

        JPanel actions = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
        actions.add(status);

        add(toolbar, BorderLayout.NORTH);
        add(split, BorderLayout.CENTER);
        add(actions, BorderLayout.SOUTH);

        setConnected(false);
    }

    /** Override the error/notification sink (tests supply a collector). */
    void setNotifier(Consumer<String> notifier) {
        this.notifier = notifier;
    }

    /** Enable/disable controls and invalidate in-flight operations. */
    public void setConnected(boolean connected) {
        this.controlsEnabled = connected;
        hostField.setEnabled(connected);
        portField.setEnabled(connected);
        completion.setEnabled(connected);
        responseLimitField.setEnabled(connected);
        timeoutField.setEnabled(connected);
        idleTimeoutField.setEnabled(connected);
        if (!connected) {
            finishIdle("disconnected");
            responseView.setBytes(new byte[0]);
        }
        updateButtons();
    }

    private void updateButtons() {
        send.setEnabled(controlsEnabled && !sendInFlight && !workspaceBusy);
        stop.setEnabled(controlsEnabled && activeSendId != null);
    }

    private void startSend() {
        if (!controlsEnabled || sendInFlight || workspaceBusy) {
            return;
        }
        ParsedSend parsed;
        try {
            parsed = readForm();
        } catch (IllegalArgumentException invalid) {
            notifier.accept("Invalid repeater request: " + invalid.getMessage());
            return;
        }

        sendInFlight = true;
        activityListener.accept(true);
        activeSendId = null;
        long seq = ++opSeq;
        // A new send supersedes any previously displayed response: clear it
        // now so a stale response can never sit beside the new outcome.
        responseView.setBytes(new byte[0]);
        updateButtons();
        status.setText("sending to " + parsed.host + ":" + parsed.port + "…");
        client.repeaterSend(parsed.host, parsed.port, parsed.payload, parsed.responseLimit,
                parsed.timeoutMs, parsed.completion, parsed.idleTimeoutMs)
                .whenComplete((started, error) -> SwingUtilities.invokeLater(() -> {
                    if (seq != opSeq) {
                        return;
                    }
                    if (error != null || started == null) {
                        finishIdle("send failed: "
                                + (error == null ? "missing start result" : error.getMessage()));
                        return;
                    }
                    activeSendId = started.getSendId();
                    status.setText("sent; waiting for response…");
                    updateButtons();
                    pollStatus(activeSendId, seq);
                }));
    }

    private void stopSend() {
        if (!sendInFlight || activeSendId == null) {
            return;
        }
        long seq = opSeq;
        String sendId = activeSendId;
        // Disable Stop synchronously: stopping the same operation twice could
        // otherwise issue a second stop for one manual send.
        stop.setEnabled(false);
        status.setText("stopping " + sendId + "…");
        client.repeaterStop(sendId)
                .whenComplete((stopped, error) -> SwingUtilities.invokeLater(() -> {
                    if (seq != opSeq || !sendId.equals(activeSendId)) {
                        return;
                    }
                    if (error != null || stopped == null) {
                        finishIdle("stop failed: "
                                + (error == null ? "missing stop result" : error.getMessage()));
                        return;
                    }
                    pollStatus(sendId, seq);
                }));
    }

    private void pollStatus(String sendId, long seq) {
        client.repeaterStatus(sendId)
                .whenComplete((state, error) -> SwingUtilities.invokeLater(() -> {
                    if (seq != opSeq || !sendId.equals(activeSendId)) {
                        return;
                    }
                    if (error != null || state == null) {
                        finishIdle("status failed: "
                                + (error == null ? "missing status result" : error.getMessage()));
                        return;
                    }
                    if (!state.getFinished() || !state.hasResult()) {
                        CompletableFuture.delayedExecutor(STATUS_POLL_DELAY_MS, TimeUnit.MILLISECONDS)
                                .execute(() -> SwingUtilities.invokeLater(() -> {
                                    // Re-check on the EDT before issuing
                                    // another status RPC: a delayed poll that
                                    // survived disconnect or dispose must not
                                    // query an obsolete send ID, even
                                    // read-only, against a new session.
                                    if (seq == opSeq && sendId.equals(activeSendId)) {
                                        pollStatus(sendId, seq);
                                    }
                                }));
                        return;
                    }
                    renderResult(state.getResult(), seq);
                }));
    }

    private void renderResult(BurpTcp.RepeaterResult result, long seq) {
        if (seq != opSeq) {
            return;
        }
        opSeq++;
        sendInFlight = false;
        activityListener.accept(false);
        activeSendId = null;
        responseView.setBytes(result.getResponse().toByteArray());
        status.setText(describeResult(result));
        updateButtons();
    }

    private void finishIdle(String message) {
        opSeq++;
        boolean wasActive = sendInFlight;
        sendInFlight = false;
        if (wasActive) activityListener.accept(false);
        activeSendId = null;
        status.setText(message);
        updateButtons();
    }

    /** Populate a fresh draft only. Importing never initiates network traffic. */
    void loadDraft(String host, int port, byte[] bytes, String origin) {
        hostField.setText(host);
        portField.setText(port > 0 ? Integer.toString(port) : "");
        payload.setBytes(bytes, true);
        source.setText(origin + " · " + bytes.length + " bytes · fresh connection on Send");
        status.setText("Draft ready — edit, then Send");
    }

    void setActivityListener(Consumer<Boolean> listener) { activityListener = listener; }
    void setWorkspaceBusy(boolean busy) { workspaceBusy = busy; updateButtons(); }
    boolean isActive() { return sendInFlight; }

    private String describeResult(BurpTcp.RepeaterResult result) {
        String outcome = switch (result.getOutcome()) {
            case COMPLETED_CLOSED -> "completed on close";
            case COMPLETED_BYTE_COUNT -> "completed on exact byte count";
            case COMPLETED_IDLE_TIMEOUT -> "completed on idle timeout";
            case STOPPED -> "stopped";
            case TIMED_OUT -> "timed out";
            case TRUNCATED -> "truncated at response limit";
            case FAILED -> "failed";
            default -> "unknown outcome";
        };
        StringBuilder text = new StringBuilder(outcome)
                .append(" (sent ")
                .append(result.getBytesSent())
                .append(" B, received ")
                .append(result.getResponse().size())
                .append(" B in ")
                .append(result.getElapsedMs())
                .append(" ms)");
        if (result.getResponseTruncated()) {
            text.append("; response truncated");
        }
        if (!result.getErrorKind().isEmpty()) {
            text.append("; ").append(result.getErrorKind());
        }
        return text.toString();
    }

    private ParsedSend readForm() {
        String host = requireHost(hostField.getText());
        int port = parseInt(portField.getText(), "port");
        if (port < 1 || port > 65535) {
            throw new IllegalArgumentException("port must be 1..65535");
        }
        int responseLimit = parseInt(responseLimitField.getText(), "response limit");
        if (responseLimit < 1 || responseLimit > MAX_RESPONSE_BYTES) {
            throw new IllegalArgumentException("response limit must be 1..262144");
        }
        long timeoutMs = parseLong(timeoutField.getText(), "timeout");
        if (timeoutMs < 1 || timeoutMs > MAX_TIMEOUT_MS) {
            throw new IllegalArgumentException("timeout must be 1..30000 ms");
        }
        long idleTimeoutMs = parseLong(idleTimeoutField.getText(), "idle timeout");
        BurpTcp.RepeaterCompletion policy = switch (completion.getSelectedIndex()) {
            case 0 -> BurpTcp.RepeaterCompletion.READ_UNTIL_CLOSE;
            case 1 -> BurpTcp.RepeaterCompletion.READ_EXACT_BYTES;
            case 2 -> BurpTcp.RepeaterCompletion.READ_UNTIL_IDLE;
            default -> throw new IllegalArgumentException("select a response completion policy");
        };
        if (policy == BurpTcp.RepeaterCompletion.READ_UNTIL_IDLE) {
            if (idleTimeoutMs < 1 || idleTimeoutMs > MAX_IDLE_TIMEOUT_MS) {
                throw new IllegalArgumentException("idle timeout must be 1..10000 ms");
            }
        } else if (idleTimeoutMs != 0) {
            throw new IllegalArgumentException("idle timeout applies only to read-until-idle");
        }
        byte[] payload;
        try {
            payload = this.payload.getBytes();
        } catch (IllegalArgumentException invalid) {
            throw new IllegalArgumentException("payload: " + invalid.getMessage());
        }
        if (payload.length > MAX_PAYLOAD_BYTES) {
            throw new IllegalArgumentException("payload must be at most 65536 bytes");
        }
        return new ParsedSend(host, port, payload, responseLimit, timeoutMs, policy, idleTimeoutMs);
    }

    /**
     * Mirror the engine's destination rules (IPv4 literal or DNS name, no
     * IPv6) so a request the engine must reject never leaves the UI.
     */
    private static String requireHost(String raw) {
        String host = raw.trim();
        if (host.isEmpty()) {
            throw new IllegalArgumentException("destination host is required");
        }
        if (host.length() > MAX_HOST_BYTES) {
            throw new IllegalArgumentException("destination host exceeds 255 bytes");
        }
        for (int i = 0; i < host.length(); i++) {
            char c = host.charAt(i);
            if (c < 0x21 || c > 0x7E) {
                throw new IllegalArgumentException(
                        "destination host must be printable ASCII without whitespace");
            }
        }
        if (isIpv4Literal(host)) {
            return host;
        }
        if (host.contains(":")) {
            throw new IllegalArgumentException("IPv6 destinations are not supported");
        }
        String name = host.endsWith(".") ? host.substring(0, host.length() - 1) : host;
        if (name.length() > 253) {
            throw new IllegalArgumentException("domain name exceeds 253 bytes");
        }
        for (String label : name.split("\\.", -1)) {
            if (label.isEmpty() || label.length() > 63) {
                throw new IllegalArgumentException(
                        "domain name has an empty or oversized label");
            }
            for (int i = 0; i < label.length(); i++) {
                char c = label.charAt(i);
                boolean valid = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
                        || (c >= '0' && c <= '9') || c == '-';
                if (!valid) {
                    throw new IllegalArgumentException(
                            "domain name contains an invalid character");
                }
            }
            if (label.startsWith("-") || label.endsWith("-")) {
                throw new IllegalArgumentException(
                        "domain label must not start or end with '-'");
            }
        }
        return host;
    }

    private static boolean isIpv4Literal(String host) {
        String[] parts = host.split("\\.", -1);
        if (parts.length != 4) {
            return false;
        }
        for (String part : parts) {
            if (part.isEmpty() || part.length() > 3) {
                return false;
            }
            for (int i = 0; i < part.length(); i++) {
                if (!Character.isDigit(part.charAt(i))) {
                    return false;
                }
            }
            if (Integer.parseInt(part) > 255) {
                return false;
            }
        }
        return true;
    }

    private static int parseInt(String text, String what) {
        try {
            return Integer.parseInt(text.trim());
        } catch (NumberFormatException invalid) {
            throw new IllegalArgumentException(what + " must be a number");
        }
    }

    private static long parseLong(String text, String what) {
        try {
            return Long.parseLong(text.trim());
        } catch (NumberFormatException invalid) {
            throw new IllegalArgumentException(what + " must be a number");
        }
    }

    private record ParsedSend(
            String host,
            int port,
            byte[] payload,
            int responseLimit,
            long timeoutMs,
            BurpTcp.RepeaterCompletion completion,
            long idleTimeoutMs) {
    }

    void setHost(String host) {
        hostField.setText(host);
    }

    void setPort(String port) {
        portField.setText(port);
    }

    void setResponseLimit(String limit) {
        responseLimitField.setText(limit);
    }

    void setTimeoutMs(String timeoutMs) {
        timeoutField.setText(timeoutMs);
    }

    void setIdleTimeoutMs(String idleTimeoutMs) {
        idleTimeoutField.setText(idleTimeoutMs);
    }

    void selectCompletion(int index) {
        completion.setSelectedIndex(index);
    }

    void setPayload(byte[] payload) {
        this.payload.setBytes(payload, true);
    }

    void clickSend() {
        send.doClick();
    }

    void clickStop() {
        stop.doClick();
    }

    boolean isSendEnabled() {
        return send.isEnabled();
    }

    boolean isStopEnabled() {
        return stop.isEnabled();
    }

    boolean controlsEnabled() {
        return controlsEnabled;
    }

    String statusText() {
        return status.getText();
    }

    String responseDump() {
        return responseView.hexDump();
    }
}
