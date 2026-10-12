package com.rawtcp.burp.ipc;

import com.rawtcp.burp.ipc.proto.BurpTcp;

/**
 * Callbacks from {@link IpcClient}. Every callback is invoked on a
 * background thread (the WebSocket listener or the reconnect thread),
 * never on the Swing event dispatch thread, so implementations that touch
 * the UI must marshal with {@code SwingUtilities.invokeLater}.
 */
public interface IpcListener {

    /** Authenticated: the engine acknowledged our {@code Hello}. */
    void onConnected(BurpTcp.HelloAck ack);

    /** Lost the connection (or never established it). {@code reason} is human-readable. */
    void onDisconnected(String reason);

    /** An asynchronous server event (currently {@code StateChanged}). */
    void onEvent(BurpTcp.Event event);
}
