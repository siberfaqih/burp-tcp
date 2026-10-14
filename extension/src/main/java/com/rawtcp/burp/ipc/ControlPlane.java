package com.rawtcp.burp.ipc;

import com.rawtcp.burp.ipc.proto.BurpTcp;

import java.util.concurrent.CompletableFuture;

/**
 * The control-plane operations the workspace UI needs from the engine.
 *
 * <p>Extracted so panels depend on an interface rather than the concrete
 * WebSocket client; tests supply a fake. Every method returns immediately
 * with a {@link CompletableFuture} and never blocks the caller.
 */
public interface ControlPlane {

    CompletableFuture<BurpTcp.ConnectionList> listConnections();

    CompletableFuture<BurpTcp.HistoryData> historySnapshot(
            String connId, BurpTcp.Direction direction, int maxChunks);

    CompletableFuture<BurpTcp.PendingList> pendingUnits();

    CompletableFuture<BurpTcp.DecideResult> decide(
            String unitId, long revision, BurpTcp.InterceptActionKind action, byte[] replaceBytes);

    CompletableFuture<BurpTcp.SetEnabledResult> setEnabled(
            BurpTcp.Direction direction, boolean enabled);

    CompletableFuture<BurpTcp.Stats> stats();

    CompletableFuture<BurpTcp.Stats> subscribe();

    CompletableFuture<BurpTcp.RepeaterStartResult> repeaterSend(
            String destinationHost,
            int destinationPort,
            byte[] payload,
            int responseByteLimit,
            long timeoutMs,
            BurpTcp.RepeaterCompletion completion,
            long idleTimeoutMs);

    CompletableFuture<BurpTcp.RepeaterStopResult> repeaterStop(String sendId);

    CompletableFuture<BurpTcp.RepeaterStatusResult> repeaterStatus(String sendId);

    /** Current Burp routing table (destinations handed to a Burp Proxy listener). */
    CompletableFuture<BurpTcp.BurpRouteList> listBurpRoutes();

    /**
     * Replace the Burp routing table; empty clears routing. Resolves with
     * the table the engine stored.
     */
    CompletableFuture<BurpTcp.BurpRouteList> setBurpRoutes(java.util.List<BurpTcp.BurpRoute> routes);

    /** Human-readable connection status for the UI. */
    String status();

    boolean isConnected();

    void addListener(IpcListener listener);

    void removeListener(IpcListener listener);
}
