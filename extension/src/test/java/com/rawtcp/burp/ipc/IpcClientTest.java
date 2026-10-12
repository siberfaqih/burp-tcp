package com.rawtcp.burp.ipc;

import com.google.protobuf.ByteString;
import com.rawtcp.burp.ipc.proto.BurpTcp;
import com.rawtcp.burp.testutil.TestWebSocketServer;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * End-to-end tests for {@link IpcClient} against an in-process RFC 6455
 * server. These exercise the real handshake, framing, request/response
 * correlation, event dispatch, and reconnect loop.
 */
class IpcClientTest {

    private static final long TIMEOUT_SECONDS = 10;

    private static byte[] helloAck(int requestId) {
        return BurpTcp.ServerMessage.newBuilder()
                .setResponse(BurpTcp.Response.newBuilder()
                        .setRequestId(requestId)
                        .setHelloAck(BurpTcp.HelloAck.newBuilder()
                                .setProtocolVersion(1)
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

    @Test
    void unansweredRpcClosesSocketAndRecoversWithoutRestart() throws Exception {
        AtomicInteger accepts = new AtomicInteger();
        CountDownLatch firstConnected = new CountDownLatch(1);
        CountDownLatch reconnected = new CountDownLatch(1);
        CountDownLatch disconnected = new CountDownLatch(1);
        CountDownLatch oldSocketClosed = new CountDownLatch(1);
        AtomicReference<String> reason = new AtomicReference<>();
        IpcClient client = new IpcClient("test", "1", 5, 1000, 500);
        try (TestWebSocketServer server = new TestWebSocketServer(session -> {
            int attempt = accepts.incrementAndGet();
            try {
                var hello = BurpTcp.ClientMessage.parseFrom(session.readBinary()).getRequest();
                session.sendBinary(helloAck(hello.getRequestId()));
                byte[] frame;
                while ((frame = session.readBinary()) != null) {
                    var request = BurpTcp.ClientMessage.parseFrom(frame).getRequest();
                    // First socket accepts requests but deliberately never answers.
                    if (attempt > 1) session.sendBinary(stats(request.getRequestId(), 42));
                }
            } catch (IOException ignored) {
                // abort() may produce FIN or RST.
            } finally {
                if (attempt == 1) oldSocketClosed.countDown();
            }
        })) {
            client.addListener(new IpcListener() {
                @Override public void onConnected(BurpTcp.HelloAck ack) {
                    if (firstConnected.getCount() > 0) firstConnected.countDown();
                    else reconnected.countDown();
                }
                @Override public void onDisconnected(String value) {
                    reason.set(value);
                    disconnected.countDown();
                }
                @Override public void onEvent(BurpTcp.Event event) { }
            });
            client.start("127.0.0.1", server.port(), "token");
            assertTrue(firstConnected.await(10, TimeUnit.SECONDS));
            var pending = client.pendingUnits();
            var policy = client.stats();
            assertTrue(disconnected.await(10, TimeUnit.SECONDS));
            assertTrue(pending.isCompletedExceptionally());
            assertTrue(policy.isCompletedExceptionally());
            assertTrue(reason.get().contains("response timeout"), reason.get());
            assertTrue(oldSocketClosed.await(10, TimeUnit.SECONDS));
            assertTrue(reconnected.await(10, TimeUnit.SECONDS));
            assertEquals(42, client.stats().get(10, TimeUnit.SECONDS).getOffers());
        } finally {
            client.close();
        }
    }

    @Test
    void handshakeSendsTokenAndDispatchesEvents() throws Exception {
        AtomicReference<String> seenToken = new AtomicReference<>();
        CountDownLatch connected = new CountDownLatch(1);
        CountDownLatch eventSeen = new CountDownLatch(1);
        CountDownLatch disconnected = new CountDownLatch(1);
        AtomicLong eventSeq = new AtomicLong(-1);

        TestWebSocketServer server = new TestWebSocketServer(session -> {
            try {
                byte[] helloFrame = session.readBinary();
                if (helloFrame == null) {
                    return;
                }
                BurpTcp.Request hello = BurpTcp.ClientMessage.parseFrom(helloFrame).getRequest();
                seenToken.set(hello.getHello().getCapabilityToken());
                session.sendBinary(helloAck(hello.getRequestId()));
                BurpTcp.ServerMessage event = BurpTcp.ServerMessage.newBuilder()
                        .setEvent(BurpTcp.Event.newBuilder()
                                .setSeq(9)
                                .setStateChanged(BurpTcp.StateChanged.newBuilder()
                                        .setConnectionCount(2)
                                        .setPendingCount(1)))
                        .build();
                session.sendBinary(event.toByteArray());
                Thread.sleep(200);
                session.close();
            } catch (IOException | InterruptedException ignored) {
                // Test teardown.
            }
        });

        IpcClient client = new IpcClient("test", "1.0");
        client.addListener(new IpcListener() {
            @Override
            public void onConnected(BurpTcp.HelloAck ack) {
                assertEquals("test-engine", ack.getServerVersion());
                connected.countDown();
            }

            @Override
            public void onDisconnected(String reason) {
                disconnected.countDown();
            }

            @Override
            public void onEvent(BurpTcp.Event event) {
                eventSeq.set(event.getSeq());
                eventSeen.countDown();
            }
        });

        try {
            client.start("127.0.0.1", server.port(), "secret-token");
            assertTrue(connected.await(TIMEOUT_SECONDS, TimeUnit.SECONDS), "never connected");
            assertTrue(eventSeen.await(TIMEOUT_SECONDS, TimeUnit.SECONDS), "no event");
            assertTrue(disconnected.await(TIMEOUT_SECONDS, TimeUnit.SECONDS), "no disconnect");
            assertEquals("secret-token", seenToken.get());
            assertEquals(9, eventSeq.get());
        } finally {
            client.close();
            server.close();
        }
    }

    @Test
    void staleTokenReportsActionableRejection() throws Exception {
        CountDownLatch disconnected = new CountDownLatch(1);
        AtomicReference<String> reason = new AtomicReference<>();

        TestWebSocketServer server = new TestWebSocketServer(session -> {
            try {
                byte[] helloFrame = session.readBinary();
                if (helloFrame == null) {
                    return;
                }
                BurpTcp.Request hello = BurpTcp.ClientMessage.parseFrom(helloFrame).getRequest();
                byte[] rejection = BurpTcp.ServerMessage.newBuilder()
                        .setResponse(BurpTcp.Response.newBuilder()
                                .setRequestId(hello.getRequestId())
                                .setError(BurpTcp.Error.newBuilder()
                                        .setCode(4401)
                                        .setMessage("bad capability token: the engine restarted; paste the token it just printed")))
                        .build()
                        .toByteArray();
                session.sendBinary(rejection);
                session.close();
            } catch (IOException ignored) {
                // Test teardown.
            }
        });

        IpcClient client = new IpcClient("test", "1.0");
        client.addListener(new IpcListener() {
            @Override
            public void onConnected(BurpTcp.HelloAck ack) {
            }

            @Override
            public void onDisconnected(String value) {
                reason.set(value);
                disconnected.countDown();
            }

            @Override
            public void onEvent(BurpTcp.Event event) {
            }
        });

        try {
            client.start("127.0.0.1", server.port(), "stale-token");
            assertTrue(disconnected.await(TIMEOUT_SECONDS, TimeUnit.SECONDS), "no disconnect");
            assertTrue(reason.get().contains("bad capability token"),
                    "rejection must name the token, got: " + reason.get());
            assertTrue(client.status().contains("bad capability token"),
                    "status must name the token, got: " + client.status());
        } finally {
            client.close();
            server.close();
        }
    }

    @Test
    void correlatesResponseByRequestId() throws Exception {        CountDownLatch connected = new CountDownLatch(1);

        TestWebSocketServer server = new TestWebSocketServer(session -> {
            try {
                byte[] helloFrame = session.readBinary();
                if (helloFrame == null) {
                    return;
                }
                BurpTcp.Request hello = BurpTcp.ClientMessage.parseFrom(helloFrame).getRequest();
                session.sendBinary(helloAck(hello.getRequestId()));
                byte[] frame;
                while ((frame = session.readBinary()) != null) {
                    BurpTcp.Request request = BurpTcp.ClientMessage.parseFrom(frame).getRequest();
                    session.sendBinary(stats(request.getRequestId(), 5));
                }
            } catch (IOException ignored) {
                // Test teardown.
            }
        });

        IpcClient client = new IpcClient("test", "1.0");
        client.addListener(new IpcListener() {
            @Override
            public void onConnected(BurpTcp.HelloAck ack) {
                connected.countDown();
            }

            @Override
            public void onDisconnected(String reason) {
            }

            @Override
            public void onEvent(BurpTcp.Event event) {
            }
        });

        try {
            client.start("127.0.0.1", server.port(), "token");
            assertTrue(connected.await(TIMEOUT_SECONDS, TimeUnit.SECONDS), "never connected");
            BurpTcp.Stats result = client.stats().get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
            assertEquals(5, result.getOffers());
        } finally {
            client.close();
            server.close();
        }
    }

    @Test
    void reconnectsAndReauthenticatesAfterDisconnect() throws Exception {
        AtomicInteger connectionCount = new AtomicInteger();
        CountDownLatch reconnected = new CountDownLatch(1);

        TestWebSocketServer server = new TestWebSocketServer(session -> {
            try {
                byte[] helloFrame = session.readBinary();
                if (helloFrame == null) {
                    return;
                }
                BurpTcp.Request hello = BurpTcp.ClientMessage.parseFrom(helloFrame).getRequest();
                session.sendBinary(helloAck(hello.getRequestId()));
                if (connectionCount.incrementAndGet() == 1) {
                    session.close();
                } else {
                    byte[] frame;
                    while ((frame = session.readBinary()) != null) {
                        // Drain until the client closes.
                    }
                }
            } catch (IOException ignored) {
                // Test teardown.
            }
        });

        IpcClient client = new IpcClient("test", "1.0");
        AtomicInteger connects = new AtomicInteger();
        client.addListener(new IpcListener() {
            @Override
            public void onConnected(BurpTcp.HelloAck ack) {
                if (connects.incrementAndGet() == 2) {
                    reconnected.countDown();
                }
            }

            @Override
            public void onDisconnected(String reason) {
            }

            @Override
            public void onEvent(BurpTcp.Event event) {
            }
        });

        try {
            client.start("127.0.0.1", server.port(), "token");
            assertTrue(reconnected.await(15, TimeUnit.SECONDS), "did not reconnect");
        } finally {
            client.close();
            server.close();
        }
    }

    private static byte[] repeaterStart(int requestId, String sendId) {
        return BurpTcp.ServerMessage.newBuilder()
                .setResponse(BurpTcp.Response.newBuilder()
                        .setRequestId(requestId)
                        .setRepeaterStartResult(BurpTcp.RepeaterStartResult.newBuilder()
                                .setSendId(sendId)))
                .build()
                .toByteArray();
    }

    private static byte[] repeaterStop(int requestId, String sendId, boolean accepted) {
        return BurpTcp.ServerMessage.newBuilder()
                .setResponse(BurpTcp.Response.newBuilder()
                        .setRequestId(requestId)
                        .setRepeaterStopResult(BurpTcp.RepeaterStopResult.newBuilder()
                                .setSendId(sendId)
                                .setAccepted(accepted)))
                .build()
                .toByteArray();
    }

    private static byte[] repeaterStatus(int requestId, String sendId) {
        return BurpTcp.ServerMessage.newBuilder()
                .setResponse(BurpTcp.Response.newBuilder()
                        .setRequestId(requestId)
                        .setRepeaterStatusResult(BurpTcp.RepeaterStatusResult.newBuilder()
                                .setSendId(sendId)
                                .setFinished(true)
                                .setResult(BurpTcp.RepeaterResult.newBuilder()
                                        .setSendId(sendId)
                                        .setSent(true)
                                        .setBytesSent(3)
                                        .setResponse(ByteString.copyFrom(new byte[] {0x41}))
                                        .setOutcome(BurpTcp.RepeaterOutcome.COMPLETED_BYTE_COUNT))))
                .build()
                .toByteArray();
    }

    @Test
    void repeaterRpcRoundTrip() throws Exception {
        TestWebSocketServer server = new TestWebSocketServer(session -> {
            try {
                byte[] helloFrame = session.readBinary();
                if (helloFrame == null) {
                    return;
                }
                BurpTcp.Request hello = BurpTcp.ClientMessage.parseFrom(helloFrame).getRequest();
                session.sendBinary(helloAck(hello.getRequestId()));

                byte[] frame;
                while ((frame = session.readBinary()) != null) {
                    BurpTcp.Request request = BurpTcp.ClientMessage.parseFrom(frame).getRequest();
                    if (request.hasRepeaterSend()) {
                        BurpTcp.RepeaterSend send = request.getRepeaterSend();
                        assertEquals("127.0.0.1", send.getDestinationHost());
                        assertEquals(7, send.getDestinationPort());
                        assertEquals(
                                BurpTcp.RepeaterCompletion.READ_EXACT_BYTES, send.getCompletion());
                        session.sendBinary(repeaterStart(request.getRequestId(), "send-42"));
                    } else if (request.hasRepeaterStop()) {
                        assertEquals("send-42", request.getRepeaterStop().getSendId());
                        session.sendBinary(
                                repeaterStop(request.getRequestId(), "send-42", true));
                    } else if (request.hasRepeaterStatus()) {
                        assertEquals("send-42", request.getRepeaterStatus().getSendId());
                        session.sendBinary(repeaterStatus(request.getRequestId(), "send-42"));
                        return;
                    } else {
                        throw new IOException("unexpected repeater RPC");
                    }
                }
            } catch (IOException ignored) {
                // Test teardown.
            }
        });

        IpcClient client = new IpcClient("test", "1.0");
        CountDownLatch connected = new CountDownLatch(1);
        client.addListener(new IpcListener() {
            @Override
            public void onConnected(BurpTcp.HelloAck ack) {
                connected.countDown();
            }

            @Override
            public void onDisconnected(String reason) {
            }

            @Override
            public void onEvent(BurpTcp.Event event) {
            }
        });
        try {
            client.start("127.0.0.1", server.port(), "token");
            assertTrue(connected.await(TIMEOUT_SECONDS, TimeUnit.SECONDS), "never connected");
            BurpTcp.RepeaterStartResult started = client.repeaterSend(
                    "127.0.0.1", 7, new byte[] {0x41, 0x42, 0x43}, 1, 1000,
                    BurpTcp.RepeaterCompletion.READ_EXACT_BYTES, 0)
                    .get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
            assertEquals("send-42", started.getSendId());

            BurpTcp.RepeaterStopResult stopped = client.repeaterStop("send-42")
                    .get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
            assertTrue(stopped.getAccepted());

            BurpTcp.RepeaterStatusResult status = client.repeaterStatus("send-42")
                    .get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
            assertTrue(status.getFinished());
            assertEquals(
                    BurpTcp.RepeaterOutcome.COMPLETED_BYTE_COUNT, status.getResult().getOutcome());
        } finally {
            client.close();
            server.close();
        }
    }
}
