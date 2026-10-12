package com.rawtcp.burp.ipc;

/**
 * A {@link ControlPlane} whose connection lifecycle the UI drives.
 *
 * <p>Kept separate from {@link ControlPlane} so panels that only read state
 * (Connections, History, Intercept) cannot start or stop the transport.
 */
public interface IpcSession extends ControlPlane {

    /** Begin (or restart) the connect/reconnect loop. Returns immediately. */
    void start(String host, int port, String token);

    /** Stop the loop and close any live connection. Idempotent. */
    void stop();

    /** Stop and release background resources. */
    void close();
}
