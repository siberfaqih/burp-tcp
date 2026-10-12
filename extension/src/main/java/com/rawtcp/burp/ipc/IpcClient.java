package com.rawtcp.burp.ipc;

import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import com.rawtcp.burp.ipc.proto.BurpTcp;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.WebSocket;
import java.nio.ByteBuffer;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Consumer;

/**
 * WebSocket client for the rawtcp-engine control plane (Phase 4A protocol).
 *
 * <p>Wire contract: one binary WebSocket frame carries exactly one raw
 * protobuf message, with no length prefix. The first frame is a
 * {@link BurpTcp.Hello} carrying the per-launch capability token; the engine
 * replies with a {@link BurpTcp.HelloAck} (or closes on a token mismatch).
 *
 * <h2>Lifecycle isolation</h2>
 *
 * <p>Each connection attempt owns an independent {@link Connection}: its own
 * socket, frame buffer, pending-request map, and close latch. Callbacks and
 * send tasks capture the {@code Connection} they belong to, so a delayed
 * {@code onClose} or an in-flight send from a previous attempt can never touch
 * the current one. Every owned socket is physically closed
 * ({@link WebSocket#abort()}) during teardown — including on a protocol error —
 * so an authenticated controller can never be orphaned. Each connection loop
 * has an identity that a restart invalidates, and {@link #stop()} aborts every
 * live attempt, so a superseded loop can neither publish nor authenticate a
 * socket.
 *
 * <h2>Send serialization</h2>
 *
 * <p>Sends are chained <em>through completion</em> on a single-thread
 * executor: the next frame is not started until the previous send future
 * completes, so frame order is preserved even under WebSocket backpressure.
 * Each send is bounded by {@link #SEND_TIMEOUT_MS}, and the pending-request
 * map is bounded by {@link #MAX_PENDING}.
 *
 * <p>All I/O runs off the Swing event dispatch thread; every public method
 * returns immediately with a {@link CompletableFuture}.
 */
public final class IpcClient implements IpcSession {

    /** Protocol version the engine expects in {@code Hello.protocol_version}. */
    public static final int PROTOCOL_VERSION = 1;

    private static final Duration CONNECT_TIMEOUT = Duration.ofSeconds(5);
    private static final long HANDSHAKE_DEADLINE_SECONDS = 15L;
    private static final long RECONNECT_DELAY_MS = 3000L;
    private static final long SEND_TIMEOUT_MS = 10_000L;
    private static final int MAX_PENDING = 256;

    private final String clientName;
    private final String clientVersion;
    private final long handshakeDeadlineSeconds;
    private final long sendTimeoutMs;
    private final List<IpcListener> listeners = new CopyOnWriteArrayList<>();
    private final HttpClient http =
            HttpClient.newBuilder().connectTimeout(CONNECT_TIMEOUT).build();
    private final ExecutorService sender =
            Executors.newSingleThreadExecutor(r -> daemon("rawtcp-ipc-send", r));
    private final AtomicInteger nextRequestId = new AtomicInteger(0);
    /** Monotonic identity of the running connection loop; a restart bumps it. */
    private final AtomicLong loopGeneration = new AtomicLong(0);
    /**
     * Every connection attempt this client owns, regardless of which loop
     * created it. {@link #stop()} aborts all of them, so a superseded loop
     * cannot leave an authenticated socket behind.
     */
    private final Set<Connection> live = ConcurrentHashMap.newKeySet();

    /** Guards {@link #sendChain}; sends are serialized through completion. */
    private final Object sendLock = new Object();
    private CompletableFuture<Void> sendChain = CompletableFuture.completedFuture(null);

    private volatile String host;
    private volatile int port;
    private volatile String token;
    private volatile Connection current;
    private volatile boolean stopped = true;
    /** Terminal once {@link #close()} has run; no loop may start afterwards. */
    private volatile boolean closed;
    private volatile Thread loop;
    private volatile String status = "disconnected";
    private volatile String daemonEpoch;
    /**
     * Test seam: when non-null, {@link #runLoop} invokes it before its first
     * iteration. Lets a test deterministically delay a loop's entry so the
     * superseded-loop interleaving can be reproduced without timing guesses.
     */
    volatile Runnable loopEntryBarrier;

    public IpcClient(String clientName, String clientVersion) {
        this(clientName, clientVersion, HANDSHAKE_DEADLINE_SECONDS, SEND_TIMEOUT_MS);
    }

    /** Test seam: override the handshake deadline so it need not be waited out. */
    IpcClient(String clientName, String clientVersion, long handshakeDeadlineSeconds) {
        this(clientName, clientVersion, handshakeDeadlineSeconds, SEND_TIMEOUT_MS);
    }

    /** Test seam: override the handshake deadline and the send timeout. */
    IpcClient(String clientName, String clientVersion,
            long handshakeDeadlineSeconds, long sendTimeoutMs) {
        this.clientName = clientName;
        this.clientVersion = clientVersion;
        this.handshakeDeadlineSeconds = handshakeDeadlineSeconds;
        this.sendTimeoutMs = sendTimeoutMs;
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
    public String status() {
        return status;
    }

    @Override
    public boolean isConnected() {
        Connection conn = current;
        return conn != null && conn.acknowledged && !conn.closedOnce.get();
    }

    /** Daemon epoch of the current connection, or {@code null} when not connected. */
    public String daemonEpoch() {
        return daemonEpoch;
    }

    @Override
    public synchronized void start(String host, int port, String token) {
        if (closed) {
            // Unload already ran: refuse to launch a loop that would otherwise
            // authenticate and be orphaned when the sender is shut down.
            setStatus("closed");
            return;
        }
        stop();
        this.host = host;
        this.port = port;
        this.token = token;
        this.stopped = false;
        // Capture this loop's identity here, under the same monitor that
        // stop() uses. A thread that enters runLoop() late therefore still
        // carries the generation of the start() that spawned it, and can never
        // supersede a newer loop.
        long myLoop = loopGeneration.incrementAndGet();
        Thread thread = new Thread(() -> runLoop(myLoop), "rawtcp-ipc");
        thread.setDaemon(true);
        this.loop = thread;
        thread.start();
    }

    @Override
    public synchronized void stop() {
        stopped = true;
        // Invalidate any in-flight loop: a connection it is still creating
        // must not be published or allowed to authenticate.
        loopGeneration.incrementAndGet();
        for (Connection conn : live) {
            abort(conn, "client stopping");
        }
        Thread thread = loop;
        if (thread != null) {
            thread.interrupt();
        }
        loop = null;
        current = null;
        daemonEpoch = null;
        setStatus("stopped");
    }

    @Override
    public void close() {
        // Terminal: mark closed under the lifecycle monitor before stopping, so
        // a concurrent (or later) start() cannot launch a loop whose socket
        // shutdownNow() would then leave authenticated and orphaned.
        synchronized (this) {
            closed = true;
        }
        stop();
        sender.shutdownNow();
    }

    // --- RPC surface ---------------------------------------------------

    @Override
    public CompletableFuture<BurpTcp.ConnectionList> listConnections() {
        return request(r -> r.setListConnections(BurpTcp.ListConnections.getDefaultInstance()))
                .thenApply(resp -> require(resp, resp.hasConnectionList(),
                        resp.getConnectionList(), "ListConnections"));
    }

    @Override
    public CompletableFuture<BurpTcp.HistoryData> historySnapshot(
            String connId, BurpTcp.Direction direction) {
        BurpTcp.HistorySnapshot snapshot = BurpTcp.HistorySnapshot.newBuilder()
                .setConnId(connId)
                .setDirection(direction)
                .build();
        return request(r -> r.setHistorySnapshot(snapshot))
                .thenApply(resp -> require(resp, resp.hasHistoryData(),
                        resp.getHistoryData(), "HistorySnapshot"));
    }

    @Override
    public CompletableFuture<BurpTcp.PendingList> pendingUnits() {
        return request(r -> r.setPendingUnits(BurpTcp.PendingUnits.getDefaultInstance()))
                .thenApply(resp -> require(resp, resp.hasPendingList(),
                        resp.getPendingList(), "PendingUnits"));
    }

    @Override
    public CompletableFuture<BurpTcp.DecideResult> decide(
            String unitId, long revision, BurpTcp.InterceptActionKind action, byte[] replaceBytes) {
        BurpTcp.Decide.Builder decide = BurpTcp.Decide.newBuilder()
                .setUnitId(unitId)
                .setRevision(revision)
                .setAction(action);
        if (replaceBytes != null) {
            decide.setReplaceBytes(com.google.protobuf.ByteString.copyFrom(replaceBytes));
        }
        BurpTcp.Decide built = decide.build();
        return request(r -> r.setDecide(built))
                .thenApply(resp -> require(resp, resp.hasDecideResult(),
                        resp.getDecideResult(), "Decide"));
    }

    @Override
    public CompletableFuture<BurpTcp.SetEnabledResult> setEnabled(
            BurpTcp.Direction direction, boolean enabled) {
        BurpTcp.SetEnabled body = BurpTcp.SetEnabled.newBuilder()
                .setDirection(direction)
                .setEnabled(enabled)
                .build();
        return request(r -> r.setSetEnabled(body))
                .thenApply(resp -> require(resp, resp.hasSetEnabledResult(),
                        resp.getSetEnabledResult(), "SetEnabled"));
    }

    @Override
    public CompletableFuture<BurpTcp.Stats> stats() {
        return request(r -> r.setGetStats(BurpTcp.GetStats.getDefaultInstance()))
                .thenApply(resp -> require(resp, resp.hasStats(), resp.getStats(), "GetStats"));
    }

    @Override
    public CompletableFuture<BurpTcp.Stats> subscribe() {
        return request(r -> r.setSubscribe(BurpTcp.Subscribe.getDefaultInstance()))
                .thenApply(resp -> require(resp, resp.hasStats(), resp.getStats(), "Subscribe"));
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
        BurpTcp.RepeaterSend body = BurpTcp.RepeaterSend.newBuilder()
                .setDestinationHost(destinationHost)
                .setDestinationPort(destinationPort)
                .setPayload(payload == null
                        ? ByteString.EMPTY
                        : ByteString.copyFrom(payload))
                .setResponseByteLimit(responseByteLimit)
                .setTimeoutMs(timeoutMs)
                .setCompletion(completion)
                .setIdleTimeoutMs(idleTimeoutMs)
                .build();
        return request(r -> r.setRepeaterSend(body))
                .thenApply(resp -> require(resp, resp.hasRepeaterStartResult(),
                        resp.getRepeaterStartResult(), "RepeaterSend"));
    }

    @Override
    public CompletableFuture<BurpTcp.RepeaterStopResult> repeaterStop(String sendId) {
        BurpTcp.RepeaterStop body = BurpTcp.RepeaterStop.newBuilder()
                .setSendId(sendId)
                .build();
        return request(r -> r.setRepeaterStop(body))
                .thenApply(resp -> require(resp, resp.hasRepeaterStopResult(),
                        resp.getRepeaterStopResult(), "RepeaterStop"));
    }

    @Override
    public CompletableFuture<BurpTcp.RepeaterStatusResult> repeaterStatus(String sendId) {
        BurpTcp.RepeaterStatus body = BurpTcp.RepeaterStatus.newBuilder()
                .setSendId(sendId)
                .build();
        return request(r -> r.setRepeaterStatus(body))
                .thenApply(resp -> require(resp, resp.hasRepeaterStatusResult(),
                        resp.getRepeaterStatusResult(), "RepeaterStatus"));
    }

    // --- Internals -----------------------------------------------------

    private CompletableFuture<BurpTcp.Response> request(Consumer<BurpTcp.Request.Builder> build) {
        Connection conn = current;
        if (conn == null || conn.closedOnce.get()) {
            return failed(new IOException("not connected"));
        }
        return requestOn(conn, build);
    }

    private CompletableFuture<BurpTcp.Response> requestOn(
            Connection conn, Consumer<BurpTcp.Request.Builder> build) {
        if (conn.closedOnce.get()) {
            return failed(new IOException("not connected"));
        }
        // Reserve a slot atomically: concurrent callers must not all observe
        // size() < MAX_PENDING and overshoot the bound.
        if (conn.pendingCount.incrementAndGet() > MAX_PENDING) {
            conn.pendingCount.decrementAndGet();
            return failed(new IOException("too many outstanding requests"));
        }

        BurpTcp.Request.Builder requestBuilder = BurpTcp.Request.newBuilder();
        int id = nextRequestId.incrementAndGet();
        requestBuilder.setRequestId(id);
        build.accept(requestBuilder);
        byte[] bytes = BurpTcp.ClientMessage.newBuilder()
                .setRequest(requestBuilder.build())
                .build()
                .toByteArray();

        CompletableFuture<BurpTcp.Response> future = new CompletableFuture<>();
        if (conn.closedOnce.get()) {
            conn.pendingCount.decrementAndGet();
            future.completeExceptionally(new IOException("not connected"));
            return future;
        }
        conn.pending.put(id, future);
        try {
            enqueueSend(conn, id, bytes, future);
        } catch (RejectedExecutionException rejected) {
            removePending(conn, id);
            future.completeExceptionally(new IOException("client closed"));
        }
        return future;
    }

    /** Remove a pending request, keeping the outstanding-request count exact. */
    private static CompletableFuture<BurpTcp.Response> removePending(Connection conn, int id) {
        CompletableFuture<BurpTcp.Response> future = conn.pending.remove(id);
        if (future != null) {
            conn.pendingCount.decrementAndGet();
        }
        return future;
    }

    private void enqueueSend(
            Connection conn, int id, byte[] bytes, CompletableFuture<BurpTcp.Response> future) {
        synchronized (sendLock) {
            CompletableFuture<Void> next = sendChain
                    .handle((ignored, error) -> null)
                    .thenComposeAsync(ignored -> sendBinary(conn, bytes), sender);
            sendChain = next.exceptionally(error -> null);
            next.whenComplete((ignored, error) -> {
                if (error != null) {
                    CompletableFuture<BurpTcp.Response> pending = removePending(conn, id);
                    if (pending != null) {
                        pending.completeExceptionally(error);
                    }
                }
            });
        }
    }

    private CompletableFuture<Void> sendBinary(Connection conn, byte[] bytes) {
        WebSocket ws = conn.socket.get();
        if (ws == null || conn.closedOnce.get()) {
            return CompletableFuture.failedFuture(new IOException("not connected"));
        }
        CompletableFuture<Void> sent;
        try {
            sent = ws.sendBinary(ByteBuffer.wrap(bytes), true).thenAccept(ignored -> { });
        } catch (RuntimeException failure) {
            // A synchronous send failure means the socket is unusable; tear
            // it down with the same policy as an asynchronous failure rather
            // than letting the chain advance on a broken channel.
            handleClosed(conn, "send failed: " + describe(failure));
            return CompletableFuture.failedFuture(failure);
        }
        return sent.orTimeout(sendTimeoutMs, TimeUnit.MILLISECONDS)
                .whenComplete((ignored, error) -> {
                    if (error != null) {
                        // A timed-out or failed send leaves the socket with an
                        // uncertain outstanding frame. Tear the connection
                        // down instead of reusing it for the next frame, so
                        // the chain never advances past a half-sent message.
                        handleClosed(conn, "send failed: " + describe(error));
                    }
                });
    }

    private static <T> T require(
            BurpTcp.Response response, boolean present, T value, String what) {
        if (response.hasError()) {
            throw new CompletionException(
                    new IOException(what + " failed: " + response.getError().getMessage()));
        }
        if (!present) {
            throw new CompletionException(new IOException(what + ": unexpected response type"));
        }
        return value;
    }

    private static <T> CompletableFuture<T> failed(Throwable cause) {
        CompletableFuture<T> future = new CompletableFuture<>();
        future.completeExceptionally(cause);
        return future;
    }

    private void runLoop(long myLoop) {
        Runnable barrier = loopEntryBarrier;
        if (barrier != null) {
            barrier.run();
        }
        Connection conn = null;
        try {
            while (!stopped && myLoop == loopGeneration.get()) {
                conn = connectOnce(myLoop);
                // The latch is counted down on any teardown (handshake
                // failure, protocol error, remote close, or stop()). Waiting
                // on it is reliably interruptible, unlike a blocking get() on
                // the HTTP client's upgrade future.
                conn.closed.await();
                conn = null;
                if (stopped || myLoop != loopGeneration.get()) {
                    break;
                }
                Thread.sleep(RECONNECT_DELAY_MS);
            }
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
        } catch (RuntimeException failure) {
            setStatus("connect failed: " + describe(failure));
        } finally {
            // If the loop is torn down while an attempt is still in flight
            // (restart, stop), that attempt owns a socket nobody else will
            // close. Abort it here so it can never authenticate or linger.
            if (conn != null) {
                abort(conn, "connection attempt abandoned");
            }
        }
        synchronized (this) {
            if (myLoop == loopGeneration.get() && !stopped) {
                setStatus("stopped");
            }
        }
    }

    /**
     * Begin one connection attempt for loop {@code myLoop} and return
     * immediately; completion is signalled through {@link Connection#closed}.
     * The upgrade is driven asynchronously so a stop during a slow handshake
     * is observed promptly and never leaves an owned socket behind.
     */
    private Connection connectOnce(long myLoop) {
        Connection conn = new Connection();
        live.add(conn);
        if (!publish(conn, myLoop)) {
            // A restart or stop already superseded this loop; do not publish.
            abort(conn, "superseded before connect");
            return conn;
        }

        CompletableFuture<WebSocket> upgrade;
        try {
            upgrade = http.newWebSocketBuilder()
                    .connectTimeout(CONNECT_TIMEOUT)
                    .buildAsync(URI.create("ws://" + host + ":" + port + "/"), new Listener(conn));
        } catch (RuntimeException invalidEndpoint) {
            handleClosed(conn, "invalid endpoint: " + describe(invalidEndpoint));
            return conn;
        }
        upgrade.whenComplete((ws, error) -> {
            if (error != null) {
                handleClosed(conn, "connect failed: " + describe(error));
                return;
            }
            // Install the socket atomically with respect to teardown:
            // closeSocket() clears with getAndSet(null), so whichever side
            // runs second always sees (and aborts) the socket exactly once.
            conn.socket.set(ws);
            if (!isCurrent(conn, myLoop)) {
                // stop() or a restart won the race: own and close the socket
                // rather than publishing or authenticating it.
                handleClosed(conn, "stopped during connect");
                return;
            }
            sendHello(conn);
        });

        // A peer that completes the WebSocket upgrade but never answers Hello
        // must not wedge the loop forever.
        CompletableFuture.delayedExecutor(handshakeDeadlineSeconds, TimeUnit.SECONDS)
                .execute(() -> {
                    if (!conn.acknowledged && !conn.closedOnce.get()) {
                        handleClosed(conn, "handshake timeout");
                    }
                });

        return conn;
    }

    /**
     * Publish {@code conn} as the current connection, atomically with respect
     * to {@link #start}/{@link #stop}. Returns false if the loop was
     * superseded or the client was stopped.
     */
    private synchronized boolean publish(Connection conn, long myLoop) {
        if (stopped || myLoop != loopGeneration.get()) {
            return false;
        }
        current = conn;
        // Publish the status under the same monitor as stop(), so a superseded
        // attempt can never overwrite "stopped" with "connecting…".
        setStatus("connecting to " + host + ":" + port + "…");
        return true;
    }

    /**
     * True if {@code conn} is still the current connection of the live loop,
     * evaluated under the same monitor as {@link #start}/{@link #stop}.
     */
    private synchronized boolean isCurrent(Connection conn, long myLoop) {
        return !stopped && !conn.closedOnce.get()
                && myLoop == loopGeneration.get() && current == conn;
    }

    private void sendHello(Connection conn) {
        BurpTcp.Hello hello = BurpTcp.Hello.newBuilder()
                .setProtocolVersion(PROTOCOL_VERSION)
                .setClientName(clientName)
                .setClientVersion(clientVersion)
                .setCapabilityToken(token)
                .build();
        requestOn(conn, r -> r.setHello(hello)).whenComplete((response, error) -> {
            if (error != null) {
                handleClosed(conn, "handshake failed: " + describe(error));
                return;
            }
            if (response.hasHelloAck()) {
                BurpTcp.HelloAck ack = response.getHelloAck();
                if (ack.getProtocolVersion() != PROTOCOL_VERSION) {
                    synchronized (IpcClient.this) {
                        if (current == conn && !stopped && !conn.closedOnce.get()) {
                            setStatus("protocol mismatch: engine v" + ack.getProtocolVersion()
                                    + ", client v" + PROTOCOL_VERSION);
                        }
                    }
                    handleClosed(conn, "protocol mismatch");
                    return;
                }
                // Publish the connected state atomically with respect to
                // stop(): a late Hello completing after teardown must never
                // set the epoch, report connected, or re-enable the UI.
                synchronized (IpcClient.this) {
                    if (stopped || conn.closedOnce.get() || current != conn) {
                        return;
                    }
                    conn.acknowledged = true;
                    daemonEpoch = ack.getDaemonEpoch();
                    setStatus("connected to " + host + ":" + port
                            + " (engine " + ack.getServerVersion() + ")");
                    for (IpcListener listener : listeners) {
                        try {
                            listener.onConnected(ack);
                        } catch (RuntimeException ignored) {
                            // A faulty listener must not break the client loop.
                        }
                    }
                }
            } else if (response.hasError()) {
                handleClosed(conn, "handshake rejected: " + response.getError().getMessage());
            }
        });
    }

    private void handleFrame(Connection conn, byte[] frame) {
        if (conn.closedOnce.get()) {
            return;
        }
        BurpTcp.ServerMessage message;
        try {
            message = BurpTcp.ServerMessage.parseFrom(frame);
        } catch (InvalidProtocolBufferException malformed) {
            // Tear the socket down for real; do not merely forget it.
            handleClosed(conn, "protocol error: " + malformed.getMessage());
            return;
        }
        switch (message.getBodyCase()) {
            case RESPONSE -> {
                BurpTcp.Response response = message.getResponse();
                CompletableFuture<BurpTcp.Response> future =
                        removePending(conn, response.getRequestId());
                if (future != null) {
                    future.complete(response);
                }
            }
            case EVENT -> {
                BurpTcp.Event event = message.getEvent();
                for (IpcListener listener : listeners) {
                    try {
                        listener.onEvent(event);
                    } catch (RuntimeException ignored) {
                        // Isolate listener failures.
                    }
                }
            }
            default -> {
                // Unknown body: ignore rather than tear down the connection.
            }
        }
    }

    /** Physically close a connection and fail its pending requests. */
    private void abort(Connection conn, String reason) {
        conn.closedOnce.set(true);
        live.remove(conn);
        closeSocket(conn);
        failAllPending(conn, new IOException(reason));
        conn.closed.countDown();
    }

    private void handleClosed(Connection conn, String reason) {
        boolean first = conn.closedOnce.compareAndSet(false, true);
        live.remove(conn);
        closeSocket(conn);
        failAllPending(conn, new IOException(reason));
        conn.closed.countDown();
        if (!first) {
            return;
        }
        // Publish the disconnect atomically with respect to start()/stop(): a
        // connection that was already superseded or stopped must not clear
        // newer state or notify listeners. Notification happens under the same
        // monitor so an old disconnect cannot be delivered against a newer
        // session's state. Listeners must therefore not block (they marshal to
        // the EDT / record into latches).
        synchronized (this) {
            if (current != conn || stopped) {
                return;
            }
            daemonEpoch = null;
            setStatus("disconnected: " + reason);
            for (IpcListener listener : listeners) {
                try {
                    listener.onDisconnected(reason);
                } catch (RuntimeException ignored) {
                    // Isolate listener failures.
                }
            }
        }
    }

    private static void closeSocket(Connection conn) {
        // Clear and abort atomically: the upgrade callback installs with a
        // plain set, so whichever side runs second always observes the socket
        // exactly once and aborts it.
        WebSocket ws = conn.socket.getAndSet(null);
        if (ws != null) {
            try {
                ws.abort();
            } catch (RuntimeException ignored) {
                // Socket already gone; nothing to do.
            }
        }
    }

    private static void failAllPending(Connection conn, Throwable cause) {
        for (Integer id : conn.pending.keySet()) {
            CompletableFuture<BurpTcp.Response> future = removePending(conn, id);
            if (future != null) {
                future.completeExceptionally(cause);
            }
        }
    }

    private void setStatus(String value) {
        this.status = value;
    }

    private static String describe(Throwable error) {
        Throwable cause = error instanceof CompletionException && error.getCause() != null
                ? error.getCause() : error;
        String message = cause.getMessage();
        return message == null ? cause.getClass().getSimpleName() : message;
    }

    private static Thread daemon(String name, Runnable runnable) {
        Thread thread = new Thread(runnable, name);
        thread.setDaemon(true);
        return thread;
    }

    /** Per-connection-attempt state; never shared across loops. */
    private static final class Connection {

        final Map<Integer, CompletableFuture<BurpTcp.Response>> pending = new ConcurrentHashMap<>();
        final AtomicInteger pendingCount = new AtomicInteger(0);
        final Object bufferLock = new Object();
        final CountDownLatch closed = new CountDownLatch(1);
        final AtomicBoolean closedOnce = new AtomicBoolean(false);
        ByteArrayOutputStream frameBuffer = new ByteArrayOutputStream();
        final java.util.concurrent.atomic.AtomicReference<WebSocket> socket =
                new java.util.concurrent.atomic.AtomicReference<>();
        volatile boolean acknowledged;
    }

    /** Per-connection WebSocket listener bound to its {@link Connection}. */
    private final class Listener implements WebSocket.Listener {

        private final Connection conn;

        Listener(Connection conn) {
            this.conn = conn;
        }

        @Override
        public void onOpen(WebSocket webSocket) {
            if (conn.closedOnce.get() || current != conn) {
                // Superseded attempt: never let it linger.
                webSocket.abort();
                return;
            }
            webSocket.request(1);
        }

        @Override
        public CompletionStage<?> onBinary(WebSocket webSocket, ByteBuffer data, boolean last) {
            if (conn.closedOnce.get()) {
                webSocket.request(1);
                return null;
            }
            byte[] frame = null;
            synchronized (conn.bufferLock) {
                byte[] chunk = new byte[data.remaining()];
                data.get(chunk);
                conn.frameBuffer.write(chunk, 0, chunk.length);
                if (last) {
                    frame = conn.frameBuffer.toByteArray();
                    conn.frameBuffer.reset();
                }
            }
            if (frame != null) {
                handleFrame(conn, frame);
            }
            webSocket.request(1);
            return null;
        }

        @Override
        public CompletionStage<?> onText(WebSocket webSocket, CharSequence data, boolean last) {
            // The engine only ever sends binary frames; text is a violation.
            // Close code 1002 (protocol error); java.net.http.WebSocket only
            // names NORMAL_CLOSURE, so the RFC 6455 code is written out.
            webSocket.sendClose(1002, "text frames not supported");
            // Do not rely on the peer to complete the close handshake: tear
            // the connection down so status and pending requests are cleared.
            handleClosed(conn, "protocol error: text frame");
            return null;
        }

        @Override
        public CompletionStage<?> onClose(WebSocket webSocket, int statusCode, String reason) {
            handleClosed(conn, "closed (" + statusCode + (reason.isEmpty() ? "" : " " + reason) + ")");
            return null;
        }

        @Override
        public void onError(WebSocket webSocket, Throwable error) {
            handleClosed(conn, "error: " + describe(error));
        }
    }
}
