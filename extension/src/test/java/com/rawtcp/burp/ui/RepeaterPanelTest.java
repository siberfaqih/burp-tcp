package com.rawtcp.burp.ui;

import com.google.protobuf.ByteString;
import com.rawtcp.burp.ipc.proto.BurpTcp;
import com.rawtcp.burp.testutil.FakeControlPlane;
import org.junit.jupiter.api.Test;

import javax.swing.SwingUtilities;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Regression tests for the one-shot manual repeater workflow. */
class RepeaterPanelTest {

    private static void onEdt(Runnable action) throws Exception {
        SwingUtilities.invokeAndWait(action);
    }

    private static void flush() throws Exception {
        SwingUtilities.invokeAndWait(() -> { });
    }

    private static BurpTcp.RepeaterResult finishedResult(String sendId) {
        return BurpTcp.RepeaterResult.newBuilder()
                .setSendId(sendId)
                .setSent(true)
                .setBytesSent(2)
                .setResponse(ByteString.copyFrom(new byte[] {0x01, 0x02}))
                .setOutcome(BurpTcp.RepeaterOutcome.COMPLETED_BYTE_COUNT)
                .setElapsedMs(3)
                .build();
    }

    private static RepeaterPanel connectedPanel(
            FakeControlPlane fake, List<String> errors, AtomicReference<RepeaterPanel> ref)
            throws Exception {
        AtomicReference<RepeaterPanel> created = new AtomicReference<>();
        onEdt(() -> {
            RepeaterPanel panel = new RepeaterPanel(fake);
            panel.setNotifier(errors::add);
            panel.setConnected(true);
            created.set(panel);
        });
        ref.set(created.get());
        return created.get();
    }

    @Test
    void sendSendsOnceAndRendersAuthoritativeResult() throws Exception {
        FakeControlPlane fake = new FakeControlPlane();
        List<String> errors = new CopyOnWriteArrayList<>();
        AtomicReference<RepeaterPanel> ref = new AtomicReference<>();
        RepeaterPanel panel = connectedPanel(fake, errors, ref);
        fake.repeaterStartResult = CompletableFuture.completedFuture(
                BurpTcp.RepeaterStartResult.newBuilder().setSendId("send-1").build());
        fake.repeaterStatusResult = new CompletableFuture<>();

        byte[] payload = {0x01, 0x02};
        onEdt(() -> {
            panel.setHost("127.0.0.1");
            panel.setPort("7");
            panel.setPayload(payload);
            panel.setResponseLimit("2");
            panel.setTimeoutMs("1000");
            panel.setIdleTimeoutMs("0");
            panel.selectCompletion(1);
            panel.clickSend();
        });
        flush();

        assertEquals(1, fake.repeaterSendCalls.size(), "one click must issue one engine send");
        BurpTcp.RepeaterSend send = fake.repeaterSendCalls.get(0);
        assertEquals("127.0.0.1", send.getDestinationHost());
        assertEquals(7, send.getDestinationPort());
        assertArrayEquals(payload, send.getPayload().toByteArray());
        assertEquals(BurpTcp.RepeaterCompletion.READ_EXACT_BYTES, send.getCompletion());

        fake.repeaterStatusResult.complete(BurpTcp.RepeaterStatusResult.newBuilder()
                .setSendId("send-1")
                .setFinished(true)
                .setResult(finishedResult("send-1"))
                .build());
        flush();

        onEdt(() -> {
            assertTrue(panel.responseDump().contains("01 02"), panel.responseDump());
            assertTrue(panel.statusText().contains("exact byte count"), panel.statusText());
            assertTrue(panel.isSendEnabled());
            assertFalse(panel.isStopEnabled());
        });
        assertTrue(errors.isEmpty(), "unexpected notifications: " + errors);
    }

    @Test
    void stopCancelsExactlyOnce() throws Exception {
        FakeControlPlane fake = new FakeControlPlane();
        List<String> errors = new CopyOnWriteArrayList<>();
        AtomicReference<RepeaterPanel> ref = new AtomicReference<>();
        RepeaterPanel panel = connectedPanel(fake, errors, ref);
        fake.repeaterStartResult = CompletableFuture.completedFuture(
                BurpTcp.RepeaterStartResult.newBuilder().setSendId("send-1").build());
        fake.repeaterStatusResult = new CompletableFuture<>();
        fake.repeaterStopResult = CompletableFuture.completedFuture(
                BurpTcp.RepeaterStopResult.newBuilder()
                        .setSendId("send-1")
                        .setAccepted(true)
                        .build());

        onEdt(() -> {
            panel.setHost("127.0.0.1");
            panel.setPort("7");
            panel.setPayload(new byte[] {0x01});
            panel.setResponseLimit("4096");
            panel.setTimeoutMs("5000");
            panel.setIdleTimeoutMs("0");
            panel.selectCompletion(0);
            panel.clickSend();
        });
        flush();
        onEdt(panel::clickStop);
        fake.repeaterStatusResult.complete(BurpTcp.RepeaterStatusResult.newBuilder()
                .setSendId("send-1")
                .setFinished(true)
                .setResult(BurpTcp.RepeaterResult.newBuilder(finishedResult("send-1"))
                        .setOutcome(BurpTcp.RepeaterOutcome.STOPPED)
                        .setErrorKind("stopped")
                        .build())
                .build());
        flush();

        assertEquals(1, fake.repeaterSendCalls.size());
        assertEquals(1, fake.repeaterStopCalls.size(), "one stop click must issue one stop");
        assertEquals("send-1", fake.repeaterStopCalls.get(0).getSendId());
        onEdt(() -> {
            assertTrue(panel.statusText().contains("stopped"), panel.statusText());
            assertTrue(panel.isSendEnabled());
            assertFalse(panel.isStopEnabled());
        });
        assertTrue(errors.isEmpty(), "unexpected notifications: " + errors);
    }

    @Test
    void duplicateSendClicksDoNotDuplicateEngineSends() throws Exception {
        FakeControlPlane fake = new FakeControlPlane();
        AtomicReference<RepeaterPanel> ref = new AtomicReference<>();
        RepeaterPanel panel = connectedPanel(
                fake, new CopyOnWriteArrayList<>(), ref);
        fake.repeaterStartResult = new CompletableFuture<>();

        onEdt(() -> {
            panel.setPayload(new byte[] {0x01});
            panel.setResponseLimit("4096");
            panel.setTimeoutMs("5000");
            panel.setIdleTimeoutMs("0");
            panel.selectCompletion(0);
            panel.clickSend();
            panel.clickSend();
        });

        assertEquals(1, fake.repeaterSendCalls.size(),
                "rapid clicks must not issue duplicate engine sends");
        onEdt(() -> assertFalse(panel.isStopEnabled(),
                "stop is unavailable before the engine accepts the send"));
    }

    @Test
    void disconnectDropsALateResult() throws Exception {
        FakeControlPlane fake = new FakeControlPlane();
        AtomicReference<RepeaterPanel> ref = new AtomicReference<>();
        RepeaterPanel panel = connectedPanel(
                fake, new CopyOnWriteArrayList<>(), ref);
        fake.repeaterStartResult = CompletableFuture.completedFuture(
                BurpTcp.RepeaterStartResult.newBuilder().setSendId("send-1").build());
        fake.repeaterStatusResult = new CompletableFuture<>();

        onEdt(() -> {
            panel.setPayload(new byte[] {0x01});
            panel.setResponseLimit("4096");
            panel.setTimeoutMs("5000");
            panel.setIdleTimeoutMs("0");
            panel.selectCompletion(0);
            panel.clickSend();
        });
        flush();
        onEdt(() -> panel.setConnected(false));
        fake.repeaterStatusResult.complete(BurpTcp.RepeaterStatusResult.newBuilder()
                .setSendId("send-1")
                .setFinished(true)
                .setResult(finishedResult("send-1"))
                .build());
        flush();

        onEdt(() -> {
            assertEquals("", panel.responseDump());
            assertEquals("disconnected", panel.statusText());
            assertFalse(panel.isSendEnabled());
            assertFalse(panel.isStopEnabled());
        });
    }

    @Test
    void invalidFormDoesNotSend() throws Exception {
        FakeControlPlane fake = new FakeControlPlane();
        List<String> errors = new CopyOnWriteArrayList<>();
        AtomicReference<RepeaterPanel> ref = new AtomicReference<>();
        RepeaterPanel panel = connectedPanel(fake, errors, ref);

        onEdt(() -> {
            panel.setPort("0");
            panel.clickSend();
        });

        assertTrue(fake.repeaterSendCalls.isEmpty(), "invalid input must not reach the engine");
        assertTrue(errors.stream().anyMatch(message -> message.contains("Invalid repeater request")),
                "expected a validation notification, got " + errors);
    }

    @Test
    void invalidHostDoesNotSend() throws Exception {
        FakeControlPlane fake = new FakeControlPlane();
        List<String> errors = new CopyOnWriteArrayList<>();
        AtomicReference<RepeaterPanel> ref = new AtomicReference<>();
        RepeaterPanel panel = connectedPanel(fake, errors, ref);

        onEdt(() -> {
            panel.setHost("2001:db8::1");
            panel.clickSend();
        });

        assertTrue(fake.repeaterSendCalls.isEmpty(),
                "an IPv6 destination must be rejected by the form");
        assertTrue(errors.stream().anyMatch(message -> message.contains("IPv6")),
                "expected an IPv6 notification, got " + errors);
    }

    @Test
    void oversizedPayloadDoesNotSend() throws Exception {
        FakeControlPlane fake = new FakeControlPlane();
        List<String> errors = new CopyOnWriteArrayList<>();
        AtomicReference<RepeaterPanel> ref = new AtomicReference<>();
        RepeaterPanel panel = connectedPanel(fake, errors, ref);

        onEdt(() -> {
            panel.setPayload(new byte[65_537]);
            panel.clickSend();
        });

        assertTrue(fake.repeaterSendCalls.isEmpty(),
                "an oversized payload must be rejected by the form");
        assertTrue(errors.stream().anyMatch(message -> message.contains("at most 65536")),
                "expected a payload-bound notification, got " + errors);
    }

    @Test
    void repeatedStopClicksWhilePendingSendOnce() throws Exception {
        FakeControlPlane fake = new FakeControlPlane();
        AtomicReference<RepeaterPanel> ref = new AtomicReference<>();
        RepeaterPanel panel = connectedPanel(
                fake, new CopyOnWriteArrayList<>(), ref);
        fake.repeaterStartResult = CompletableFuture.completedFuture(
                BurpTcp.RepeaterStartResult.newBuilder().setSendId("send-1").build());
        fake.repeaterStatusResult = new CompletableFuture<>();
        fake.repeaterStopResult = new CompletableFuture<>();

        onEdt(() -> {
            panel.setPayload(new byte[] {0x01});
            panel.setResponseLimit("4096");
            panel.setTimeoutMs("5000");
            panel.setIdleTimeoutMs("0");
            panel.selectCompletion(0);
            panel.clickSend();
        });
        flush();
        // Stop while the stop response itself is still pending: extra clicks
        // must not issue duplicate stops for the one manual send.
        onEdt(() -> {
            panel.clickStop();
            panel.clickStop();
        });

        assertEquals(1, fake.repeaterStopCalls.size(),
                "pending stop clicks must not duplicate the engine stop");

        fake.repeaterStopResult.complete(BurpTcp.RepeaterStopResult.newBuilder()
                .setSendId("send-1")
                .setAccepted(true)
                .build());
        fake.repeaterStatusResult.complete(BurpTcp.RepeaterStatusResult.newBuilder()
                .setSendId("send-1")
                .setFinished(true)
                .setResult(finishedResult("send-1"))
                .build());
        flush();
        onEdt(() -> assertTrue(panel.isSendEnabled()));
    }

    @Test
    void delayedPollDoesNotQueryAfterDisconnect() throws Exception {
        FakeControlPlane fake = new FakeControlPlane();
        AtomicReference<RepeaterPanel> ref = new AtomicReference<>();
        RepeaterPanel panel = connectedPanel(
                fake, new CopyOnWriteArrayList<>(), ref);
        fake.repeaterStartResult = CompletableFuture.completedFuture(
                BurpTcp.RepeaterStartResult.newBuilder().setSendId("send-1").build());
        // Unfinished: schedules one delayed re-poll 100ms out.
        fake.repeaterStatusResult = CompletableFuture.completedFuture(
                BurpTcp.RepeaterStatusResult.newBuilder()
                        .setSendId("send-1")
                        .setFinished(false)
                        .build());

        onEdt(() -> {
            panel.setPayload(new byte[] {0x01});
            panel.setResponseLimit("4096");
            panel.setTimeoutMs("5000");
            panel.setIdleTimeoutMs("0");
            panel.selectCompletion(0);
            panel.clickSend();
        });
        flush();
        assertEquals(1, fake.repeaterStatusCalls.size());

        // Disconnect before the delayed poll fires: it must be dropped on
        // the EDT instead of querying the obsolete send ID.
        onEdt(() -> panel.setConnected(false));
        Thread.sleep(300);
        flush();

        assertEquals(1, fake.repeaterStatusCalls.size(),
                "a delayed poll must not query after disconnect");
    }

    @Test
    void newSendClearsPreviousResponse() throws Exception {
        FakeControlPlane fake = new FakeControlPlane();
        AtomicReference<RepeaterPanel> ref = new AtomicReference<>();
        RepeaterPanel panel = connectedPanel(
                fake, new CopyOnWriteArrayList<>(), ref);
        fake.repeaterStartResult = CompletableFuture.completedFuture(
                BurpTcp.RepeaterStartResult.newBuilder().setSendId("send-1").build());
        fake.repeaterStatusResult = CompletableFuture.completedFuture(
                BurpTcp.RepeaterStatusResult.newBuilder()
                        .setSendId("send-1")
                        .setFinished(true)
                        .setResult(finishedResult("send-1"))
                        .build());

        onEdt(() -> {
            panel.setPayload(new byte[] {0x01});
            panel.setResponseLimit("2");
            panel.setTimeoutMs("1000");
            panel.setIdleTimeoutMs("0");
            panel.selectCompletion(1);
            panel.clickSend();
        });
        flush();
        onEdt(() -> assertTrue(panel.responseDump().contains("01 02")));

        // A second send supersedes the displayed response immediately, even
        // before the engine accepts it.
        fake.repeaterStartResult = new CompletableFuture<>();
        onEdt(() -> panel.clickSend());
        onEdt(() -> assertEquals("", panel.responseDump(),
                "a new send must clear the previous response"));
    }
}
