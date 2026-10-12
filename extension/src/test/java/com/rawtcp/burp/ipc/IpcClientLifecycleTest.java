package com.rawtcp.burp.ipc;

import com.rawtcp.burp.ipc.proto.BurpTcp;
import com.rawtcp.burp.testutil.TestWebSocketServer;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Lifecycle and teardown tests for {@link IpcClient}: the reviewer-required
 * regressions for unload-during-upgrade, protocol-error teardown, post-close
 * rejection, protocol-version validation, pending-future cleanup, and
 * many-queued-send ordering.
 */
class IpcClientLifecycleTest {

    private static final long TIMEOUT_SECONDS = 10;

    private static byte[] helloAck(int requestId, int protocolVersion) {
        return BurpTcp.ServerMessage.newBuilder()
                .setResponse(BurpTcp.Response.newBuilder()
                        .setRequestId(requestId)
                        .setHelloAck(BurpTcp.HelloAck.newBuilder()
                                .setProtocolVersion(protocolVersion)
                                .setDaemonEpoch("epoch-1")
                                .setServerVersion("test-engine")))
                .build()
                .toByteArray();
    }

    private static byte[] stats(int requestId, long offers) {
        return BurpTcp.ServerMessage.newBuilder()
                .setResponse(BurpTcp.Response.newBuilder()
                        .setRequestId(requestId)
                        .setStats(BurpTcp.Stats.newBuilder().setOffers(offers)))
                .build()
                .toByteArray();
    }

    /** Listener that records lifecycle callbacks. */
    private static final class Recording implements IpcListener {
        final CountDownLatch connected = new CountDownLatch(1);
        final CountDownLatch disconnected = new CountDownLatch(1);
        final AtomicReference<String> reason = new AtomicReference<>();
        final AtomicReference<String> epoch = new AtomicReference<>();

        @Override
        public void onConnected(BurpTcp.HelloAck ack) {
            epoch.set(ack.getDaemonEpoch());
            connected.countDown();
        }

        @Override
        public void onDisconnected(String detail) {
            reason.set(detail);
            disconnected.countDown();
        }

        @Override
        public void onEvent(BurpTcp.Event event) {
        }
    }

    @Test
    void stopDuringSlowUpgradeClosesTheSocket() throws Exception {
        AtomicBoolean serverSawEof = new AtomicBoolean();
        TestWebSocketServer server = new TestWebSocketServer(session -> {
            try {
                // Handshake is delayed; the client will stop mid-upgrade.
                if (session.readBinary() != null) {
                    // Drain until the client closes.
                }
                while (session.readBinary() != null) {
                    // Drain.
                }
            } catch (IOException ignored) {
                // Teardown.
            } finally {
                serverSawEof.set(true);
            }
        }, 1500L);

        IpcClient client = new IpcClient("test", "1.0");
        try {
            client.start("127.0.0.1", server.port(), "token");
            // Synchronize on the TCP accept rather than sleeping: the upgrade
            // is in flight as soon as the connection is accepted.
            assertTrue(server.firstAccept.await(TIMEOUT_SECONDS, TimeUnit.SECONDS),
                    "connect never reached the server");
            client.stop();
            long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(TIMEOUT_SECONDS);
            while ((!serverSawEof.get() || !"stopped".equals(client.status()))
                    && System.nanoTime() < deadline) {
                Thread.sleep(50);
            }
            assertTrue(serverSawEof.get(), "server never observed the socket closing");
            assertEquals("stopped", client.status(), "loop did not stop");
        } finally {
            client.close();
            server.close();
        }
    }

    @Test
    void malformedFrameAbortsSocketAndReportsDisconnect() throws Exception {
        AtomicBoolean serverSawEof = new AtomicBoolean();
        TestWebSocketServer server = new TestWebSocketServer(session -> {
            try {
                byte[] helloFrame = session.readBinary();
                if (helloFrame == null) {
                    return;
                }
                BurpTcp.Request hello = BurpTcp.ClientMessage.parseFrom(helloFrame).getRequest();
                session.sendBinary(helloAck(hello.getRequestId(), 1));
                // Wire type 7 is invalid protobuf: the client must tear down.
                session.sendBinary(new byte[] {0x0F});
                if (session.readBinary() == null) {
                    serverSawEof.set(true);
                }
            } catch (IOException ignored) {
                // Teardown.
            }
        });

        IpcClient client = new IpcClient("test", "1.0");
        Recording recording = new Recording();
        client.addListener(recording);
        try {
            client.start("127.0.0.1", server.port(), "token");
            assertTrue(recording.connected.await(TIMEOUT_SECONDS, TimeUnit.SECONDS), "never connected");
            assertTrue(recording.disconnected.await(TIMEOUT_SECONDS, TimeUnit.SECONDS),
                    "protocol error did not disconnect");
            assertTrue(recording.reason.get().contains("protocol error"),
                    "unexpected reason: " + recording.reason.get());
            long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(TIMEOUT_SECONDS);
            while (!serverSawEof.get() && System.nanoTime() < deadline) {
                Thread.sleep(50);
            }
            assertTrue(serverSawEof.get(), "malformed frame left the socket open");
        } finally {
            client.close();
            server.close();
        }
    }

    @Test
    void protocolVersionMismatchIsRejected() throws Exception {
        TestWebSocketServer server = new TestWebSocketServer(session -> {
            try {
                byte[] helloFrame = session.readBinary();
                if (helloFrame == null) {
                    return;
                }
                BurpTcp.Request hello = BurpTcp.ClientMessage.parseFrom(helloFrame).getRequest();
                // Claim an incompatible protocol version.
                session.sendBinary(helloAck(hello.getRequestId(), 99));
                while (session.readBinary() != null) {
                    // Drain until the client closes.
                }
            } catch (IOException ignored) {
                // Teardown.
            }
        });

        IpcClient client = new IpcClient("test", "1.0");
        Recording recording = new Recording();
        client.addListener(recording);
        try {
            client.start("127.0.0.1", server.port(), "token");
            assertTrue(recording.disconnected.await(TIMEOUT_SECONDS, TimeUnit.SECONDS),
                    "mismatched protocol version was accepted");
            assertEquals(1, recording.connected.getCount(), "connected fired on a bad version");
        } finally {
            client.close();
            server.close();
        }
    }

    @Test
    void pendingRequestFailsWhenConnectionDrops() throws Exception {
        TestWebSocketServer server = new TestWebSocketServer(session -> {
            try {
                byte[] helloFrame = session.readBinary();
                if (helloFrame == null) {
                    return;
                }
                BurpTcp.Request hello = BurpTcp.ClientMessage.parseFrom(helloFrame).getRequest();
                session.sendBinary(helloAck(hello.getRequestId(), 1));
                // Read the follow-up request but never answer it.
                session.readBinary();
                session.close();
            } catch (IOException ignored) {
                // Teardown.
            }
        });

        IpcClient client = new IpcClient("test", "1.0");
        Recording recording = new Recording();
        client.addListener(recording);
        try {
            client.start("127.0.0.1", server.port(), "token");
            assertTrue(recording.connected.await(TIMEOUT_SECONDS, TimeUnit.SECONDS), "never connected");
            CompletableFuture<BurpTcp.Stats> pending = client.stats();
            ExecutionException failure = assertThrows(ExecutionException.class,
                    () -> pending.get(TIMEOUT_SECONDS, TimeUnit.SECONDS));
            assertTrue(failure.getCause() instanceof IOException,
                    "unexpected cause: " + failure.getCause());
        } finally {
            client.close();
            server.close();
        }
    }

    @Test
    void rpcAfterCloseFailsFast() throws Exception {
        IpcClient client = new IpcClient("test", "1.0");
        client.close();
        ExecutionException failure = assertThrows(ExecutionException.class,
                () -> client.stats().get(TIMEOUT_SECONDS, TimeUnit.SECONDS));
        assertTrue(failure.getCause() instanceof IOException,
                "unexpected cause: " + failure.getCause());
    }

    @Test
    void manyQueuedRequestsCompleteInOrderUnderASlowReader() throws Exception {
        List<Integer> receivedOrder = new ArrayList<>();
        TestWebSocketServer server = new TestWebSocketServer(session -> {
            try {
                byte[] helloFrame = session.readBinary();
                if (helloFrame == null) {
                    return;
                }
                BurpTcp.Request hello = BurpTcp.ClientMessage.parseFrom(helloFrame).getRequest();
                session.sendBinary(helloAck(hello.getRequestId(), 1));
                byte[] frame;
                while ((frame = session.readBinary()) != null) {
                    // Slow reader: backpressure builds on the client's send
                    // chain while many requests are queued.
                    Thread.sleep(5);
                    BurpTcp.Request request = BurpTcp.ClientMessage.parseFrom(frame).getRequest();
                    synchronized (receivedOrder) {
                        receivedOrder.add(request.getRequestId());
                    }
                    session.sendBinary(stats(request.getRequestId(), 7));
                }
            } catch (IOException | InterruptedException ignored) {
                // Teardown.
            }
        });

        IpcClient client = new IpcClient("test", "1.0");
        Recording recording = new Recording();
        client.addListener(recording);
        try {
            client.start("127.0.0.1", server.port(), "token");
            assertTrue(recording.connected.await(TIMEOUT_SECONDS, TimeUnit.SECONDS), "never connected");

            int count = 100;
            List<CompletableFuture<BurpTcp.Stats>> requests = new ArrayList<>();
            for (int i = 0; i < count; i++) {
                requests.add(client.stats());
            }
            for (CompletableFuture<BurpTcp.Stats> request : requests) {
                assertEquals(7, request.get(TIMEOUT_SECONDS, TimeUnit.SECONDS).getOffers());
            }
            synchronized (receivedOrder) {
                assertEquals(count, receivedOrder.size(), "every request must reach the server");
                for (int i = 1; i < receivedOrder.size(); i++) {
                    assertTrue(receivedOrder.get(i) > receivedOrder.get(i - 1),
                            "frames must be sent in submission order, got " + receivedOrder);
                }
            }
        } finally {
            client.close();
            server.close();
        }
    }

    @Test
    void restartClosesThePreviousConnection() throws Exception {
        AtomicInteger open = new AtomicInteger();
        AtomicInteger accepted = new AtomicInteger();
        TestWebSocketServer server = new TestWebSocketServer(session -> {
            accepted.incrementAndGet();
            open.incrementAndGet();
            try {
                byte[] helloFrame = session.readBinary();
                if (helloFrame == null) {
                    return;
                }
                BurpTcp.Request hello = BurpTcp.ClientMessage.parseFrom(helloFrame).getRequest();
                session.sendBinary(helloAck(hello.getRequestId(), 1));
                while (session.readBinary() != null) {
                    // Drain until the client closes.
                }
            } catch (IOException ignored) {
                // Teardown.
            } finally {
                open.decrementAndGet();
            }
        });

        IpcClient client = new IpcClient("test", "1.0");
        Recording first = new Recording();
        client.addListener(first);
        try {
            client.start("127.0.0.1", server.port(), "token");
            assertTrue(first.connected.await(TIMEOUT_SECONDS, TimeUnit.SECONDS), "never connected");

            // Restart while the first connection is established and open.
            Recording second = new Recording();
            client.addListener(second);
            client.start("127.0.0.1", server.port(), "token");
            assertTrue(second.connected.await(TIMEOUT_SECONDS, TimeUnit.SECONDS),
                    "restart did not reconnect");

            // The first socket must be closed by the restart: exactly one
            // connection may remain open.
            long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(TIMEOUT_SECONDS);
            while (open.get() != 1 && System.nanoTime() < deadline) {
                Thread.sleep(50);
            }
            assertEquals(1, open.get(), "restart orphaned the previous connection");
            assertEquals(2, accepted.get(), "expected exactly one reconnect");
        } finally {
            client.close();
            server.close();
        }
    }

    @Test
    void stopDuringInFlightConnectClosesTheSocket() throws Exception {
        AtomicInteger open = new AtomicInteger();
        CountDownLatch handshaken = new CountDownLatch(1);
        TestWebSocketServer server = new TestWebSocketServer(session -> {
            open.incrementAndGet();
            handshaken.countDown();
            try {
                while (session.readBinary() != null) {
                    // Drain until the client closes.
                }
            } catch (IOException ignored) {
                // Teardown.
            } finally {
                open.decrementAndGet();
            }
        }, 600L);

        IpcClient client = new IpcClient("test", "1.0");
        try {
            client.start("127.0.0.1", server.port(), "token");
            // Stop while the upgrade is still in flight on the server side,
            // synchronized on the TCP accept rather than a sleep.
            assertTrue(server.firstAccept.await(TIMEOUT_SECONDS, TimeUnit.SECONDS),
                    "connect never reached the server");
            client.stop();

            assertTrue(handshaken.await(TIMEOUT_SECONDS, TimeUnit.SECONDS),
                    "server never completed the upgrade");
            // The upgrade completes ~600ms in; the client must own and close
            // that socket rather than orphan an authenticated connection.
            long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(TIMEOUT_SECONDS);
            while (open.get() != 0 && System.nanoTime() < deadline) {
                Thread.sleep(50);
            }
            assertEquals(0, open.get(), "stopping mid-connect orphaned the socket");
            assertFalse(client.isConnected());
        } finally {
            client.close();
            server.close();
        }
    }

    @Test
    void wedgedHandshakeIsClosedByTheDeadline() throws Exception {
        CountDownLatch serverSawEof = new CountDownLatch(1);
        TestWebSocketServer server = new TestWebSocketServer(session -> {
            try {
                // Read the Hello (proving the upgrade completed), then never
                // answer it.
                if (session.readBinary() != null) {
                    while (session.readBinary() != null) {
                        // Drain until the client gives up.
                    }
                }
            } catch (IOException ignored) {
                // Teardown.
            } finally {
                serverSawEof.countDown();
            }
        });

        // 1-second deadline so the test does not wait out the default.
        IpcClient client = new IpcClient("test", "1.0", 1L);
        Recording recording = new Recording();
        client.addListener(recording);
        try {
            client.start("127.0.0.1", server.port(), "token");
            assertTrue(recording.disconnected.await(TIMEOUT_SECONDS, TimeUnit.SECONDS),
                    "a peer that never answers Hello must be dropped");
            assertTrue(recording.reason.get() != null
                            && recording.reason.get().contains("handshake timeout"),
                    "unexpected reason: " + recording.reason.get());
            assertEquals(1, recording.connected.getCount(),
                    "a wedged handshake must not report connected");
            assertTrue(serverSawEof.await(TIMEOUT_SECONDS, TimeUnit.SECONDS),
                    "the client did not close the wedged socket");
        } finally {
            client.close();
            server.close();
        }
    }

    @Test
    void delayedSupersededLoopDoesNotSupersedeTheLiveLoop() throws Exception {
        AtomicInteger open = new AtomicInteger();
        TestWebSocketServer server = new TestWebSocketServer(session -> {
            open.incrementAndGet();
            try {
                byte[] helloFrame = session.readBinary();
                if (helloFrame == null) {
                    return;
                }
                BurpTcp.Request hello = BurpTcp.ClientMessage.parseFrom(helloFrame).getRequest();
                session.sendBinary(helloAck(hello.getRequestId(), 1));
                while (session.readBinary() != null) {
                    // Drain until the client closes.
                }
            } catch (IOException ignored) {
                // Teardown.
            } finally {
                open.decrementAndGet();
            }
        });

        IpcClient client = new IpcClient("test", "1.0");
        CountDownLatch firstEntered = new CountDownLatch(1);
        AtomicBoolean released = new AtomicBoolean();
        AtomicInteger entries = new AtomicInteger();
        AtomicReference<Thread> staleThread = new AtomicReference<>();
        // Park the first loop's thread before it can do anything, and keep it
        // parked *through* the restart's interrupt, so it only proceeds once
        // the new loop has authenticated. This reproduces the reviewer's
        // "delayed old loop" interleaving deterministically.
        client.loopEntryBarrier = () -> {
            if (entries.incrementAndGet() == 1) {
                staleThread.set(Thread.currentThread());
                firstEntered.countDown();
                while (!released.get()) {
                    try {
                        Thread.sleep(10);
                    } catch (InterruptedException interrupted) {
                        // The restart interrupts this thread; keep parking
                        // until the test explicitly releases it.
                    }
                }
                Thread.interrupted();
            }
        };

        Recording second = new Recording();
        client.addListener(second);
        try {
            client.start("127.0.0.1", server.port(), "token");
            assertTrue(firstEntered.await(TIMEOUT_SECONDS, TimeUnit.SECONDS),
                    "first loop never reached the barrier");

            // Restart while the first thread is still parked before its loop.
            client.start("127.0.0.1", server.port(), "token");
            assertTrue(second.connected.await(TIMEOUT_SECONDS, TimeUnit.SECONDS),
                    "restart did not connect");

            // Release the superseded thread and wait for it to finish. With the
            // fix it exits immediately (its generation is stale); a regression
            // that reallocates the generation inside the loop would instead
            // connect and keep the thread alive until this join times out.
            released.set(true);
            Thread stale = staleThread.get();
            assertTrue(stale != null, "barrier never recorded the first loop");
            stale.join(TimeUnit.SECONDS.toMillis(2));

            assertEquals(1, open.get(),
                    "a superseded loop opened a second connection");
            assertTrue(client.isConnected(),
                    "the live loop was superseded by a stale one");
        } finally {
            released.set(true);
            client.close();
            server.close();
        }
    }

    @Test
    void startAfterCloseDoesNotReconnect() throws Exception {
        TestWebSocketServer server = new TestWebSocketServer(session -> {
            try {
                while (session.readBinary() != null) {
                    // Drain until the client closes.
                }
            } catch (IOException ignored) {
                // Teardown.
            }
        });

        IpcClient client = new IpcClient("test", "1.0");
        try {
            // Unload is terminal: a later start() must not launch a loop whose
            // socket the shutdown sender can no longer own.
            client.close();
            client.start("127.0.0.1", server.port(), "token");
            assertFalse(server.firstAccept.await(1, TimeUnit.SECONDS),
                    "a closed client launched a connection loop");
            assertFalse(client.isConnected());
        } finally {
            server.close();
        }
    }

    @Test
    void wedgedSendTimesOutAndTearsDownTheConnection() throws Exception {
        TestWebSocketServer server = new TestWebSocketServer(session -> {
            try {
                byte[] helloFrame = session.readBinary();
                if (helloFrame == null) {
                    return;
                }
                BurpTcp.Request hello = BurpTcp.ClientMessage.parseFrom(helloFrame).getRequest();
                session.sendBinary(helloAck(hello.getRequestId(), 1));
                // Never read again: the client's next send cannot complete.
                Thread.sleep(TimeUnit.SECONDS.toMillis(30));
            } catch (IOException | InterruptedException ignored) {
                // Teardown.
            }
        }, 0L, 512);

        // 1-second send timeout so the wedged send is detected quickly.
        IpcClient client = new IpcClient("test", "1.0", 15L, 1000L);
        Recording recording = new Recording();
        client.addListener(recording);
        try {
            client.start("127.0.0.1", server.port(), "token");
            assertTrue(recording.connected.await(TIMEOUT_SECONDS, TimeUnit.SECONDS),
                    "never connected");

            // A multi-megabyte Replace payload exceeds the socket buffer; with
            // the server not reading, the physical send cannot complete and
            // must time out and tear the connection down rather than advance
            // the send chain.
            client.decide("unit-1", 0, BurpTcp.InterceptActionKind.REPLACE,
                    new byte[4 * 1024 * 1024]);

            assertTrue(recording.disconnected.await(TIMEOUT_SECONDS, TimeUnit.SECONDS),
                    "a wedged send did not tear the connection down");
            assertTrue(recording.reason.get() != null
                            && recording.reason.get().contains("send failed"),
                    "unexpected reason: " + recording.reason.get());
            assertFalse(client.isConnected());
        } finally {
            client.close();
            server.close();
        }
    }
}
