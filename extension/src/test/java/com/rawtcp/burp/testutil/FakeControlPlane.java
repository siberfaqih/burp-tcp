package com.rawtcp.burp.testutil;

import com.rawtcp.burp.ipc.IpcListener;
import com.rawtcp.burp.ipc.IpcSession;
import com.rawtcp.burp.ipc.proto.BurpTcp;

import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * In-memory {@link IpcSession} for UI tests. Snapshot methods return
 * caller-completable futures so tests can simulate slow or reordered
 * responses; mutations are recorded for assertions.
 */
public final class FakeControlPlane implements IpcSession {

    public final List<BurpTcp.Decide> decideCalls = new CopyOnWriteArrayList<>();
    public final List<BurpTcp.SetEnabled> setEnabledCalls = new CopyOnWriteArrayList<>();
    public final List<BurpTcp.RepeaterSend> repeaterSendCalls = new CopyOnWriteArrayList<>();
    public final List<BurpTcp.RepeaterStop> repeaterStopCalls = new CopyOnWriteArrayList<>();
    public final List<BurpTcp.RepeaterStatus> repeaterStatusCalls = new CopyOnWriteArrayList<>();
    public final List<String> historyConnIds = new CopyOnWriteArrayList<>();
    public final List<CompletableFuture<BurpTcp.HistoryData>> historyCalls =
            new CopyOnWriteArrayList<>();
    public boolean started;

    /** Completed by default; replace to control timing. */
    public volatile CompletableFuture<BurpTcp.ConnectionList> listConnectionsResult =
            CompletableFuture.completedFuture(BurpTcp.ConnectionList.getDefaultInstance());
    public volatile CompletableFuture<BurpTcp.PendingList> pendingResult =
            CompletableFuture.completedFuture(BurpTcp.PendingList.getDefaultInstance());
    public volatile CompletableFuture<BurpTcp.Stats> statsResult =
            CompletableFuture.completedFuture(BurpTcp.Stats.getDefaultInstance());
    public volatile CompletableFuture<BurpTcp.SetEnabledResult> setEnabledResult =
            CompletableFuture.completedFuture(BurpTcp.SetEnabledResult.getDefaultInstance());
    /**
     * When true, {@link #setEnabled} returns a fresh, caller-completable future
     * per call (recorded in {@link #setEnabledFutures}) instead of the shared
     * {@link #setEnabledResult}. Lets a test complete overlapping toggles
     * independently.
     */
    public volatile boolean freshSetEnabledFutures;
    public final List<CompletableFuture<BurpTcp.SetEnabledResult>> setEnabledFutures =
            new CopyOnWriteArrayList<>();
    public volatile CompletableFuture<BurpTcp.DecideResult> decideResult =
            CompletableFuture.completedFuture(
                    BurpTcp.DecideResult.newBuilder().setCommitted(true).build());
    public volatile CompletableFuture<BurpTcp.RepeaterStartResult> repeaterStartResult =
            CompletableFuture.completedFuture(BurpTcp.RepeaterStartResult.getDefaultInstance());
    public volatile CompletableFuture<BurpTcp.RepeaterStopResult> repeaterStopResult =
            CompletableFuture.completedFuture(BurpTcp.RepeaterStopResult.getDefaultInstance());
    public volatile CompletableFuture<BurpTcp.RepeaterStatusResult> repeaterStatusResult =
            CompletableFuture.completedFuture(BurpTcp.RepeaterStatusResult.getDefaultInstance());

    private final List<IpcListener> listeners = new CopyOnWriteArrayList<>();

    @Override
    public CompletableFuture<BurpTcp.ConnectionList> listConnections() {
        return listConnectionsResult;
    }

    @Override
    public CompletableFuture<BurpTcp.HistoryData> historySnapshot(
            String connId, BurpTcp.Direction direction) {
        historyConnIds.add(connId);
        CompletableFuture<BurpTcp.HistoryData> future = new CompletableFuture<>();
        historyCalls.add(future);
        return future;
    }

    @Override
    public CompletableFuture<BurpTcp.PendingList> pendingUnits() {
        return pendingResult;
    }

    @Override
    public CompletableFuture<BurpTcp.DecideResult> decide(
            String unitId, long revision, BurpTcp.InterceptActionKind action, byte[] replaceBytes) {
        BurpTcp.Decide.Builder builder = BurpTcp.Decide.newBuilder()
                .setUnitId(unitId)
                .setRevision(revision)
                .setAction(action);
        if (replaceBytes != null) {
            builder.setReplaceBytes(com.google.protobuf.ByteString.copyFrom(replaceBytes));
        }
        decideCalls.add(builder.build());
        return decideResult;
    }

    @Override
    public CompletableFuture<BurpTcp.SetEnabledResult> setEnabled(
            BurpTcp.Direction direction, boolean enabled) {
        setEnabledCalls.add(BurpTcp.SetEnabled.newBuilder()
                .setDirection(direction)
                .setEnabled(enabled)
                .build());
        if (freshSetEnabledFutures) {
            CompletableFuture<BurpTcp.SetEnabledResult> future = new CompletableFuture<>();
            setEnabledFutures.add(future);
            return future;
        }
        return setEnabledResult;
    }

    @Override
    public CompletableFuture<BurpTcp.Stats> stats() {
        return statsResult;
    }

    @Override
    public CompletableFuture<BurpTcp.Stats> subscribe() {
        return statsResult;
    }

    @Override
    public CompletableFuture<BurpTcp.RepeaterStartResult> repeaterSend(
            String destinationHost,
            int destinationPort,
            byte[] payload,
            int responseByteLimit,
            long timeoutMs,
            BurpTcp.RepeaterCompletion completion,
            long idleTimeoutMs) {
        repeaterSendCalls.add(BurpTcp.RepeaterSend.newBuilder()
                .setDestinationHost(destinationHost)
                .setDestinationPort(destinationPort)
                .setPayload(payload == null
                        ? com.google.protobuf.ByteString.EMPTY
                        : com.google.protobuf.ByteString.copyFrom(payload))
                .setResponseByteLimit(responseByteLimit)
                .setTimeoutMs(timeoutMs)
                .setCompletion(completion)
                .setIdleTimeoutMs(idleTimeoutMs)
                .build());
        return repeaterStartResult;
    }

    @Override
    public CompletableFuture<BurpTcp.RepeaterStopResult> repeaterStop(String sendId) {
        repeaterStopCalls.add(BurpTcp.RepeaterStop.newBuilder()
                .setSendId(sendId)
                .build());
        return repeaterStopResult;
    }

    @Override
    public CompletableFuture<BurpTcp.RepeaterStatusResult> repeaterStatus(String sendId) {
        repeaterStatusCalls.add(BurpTcp.RepeaterStatus.newBuilder()
                .setSendId(sendId)
                .build());
        return repeaterStatusResult;
    }

    @Override
    public String status() {
        return "fake";
    }

    @Override
    public boolean isConnected() {
        return true;
    }

    @Override
    public void addListener(IpcListener listener) {
        listeners.add(listener);
    }

    @Override
    public void removeListener(IpcListener listener) {
        listeners.remove(listener);
    }

    @Override
    public void start(String host, int port, String token) {
        started = true;
    }

    @Override
    public void stop() {
        started = false;
    }

    @Override
    public void close() {
        started = false;
    }

    /** Number of attached listeners, for teardown assertions. */
    public int listenerCount() {
        return listeners.size();
    }
}
