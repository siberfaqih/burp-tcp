package com.rawtcp.burp.ui;

import com.rawtcp.burp.ipc.proto.BurpTcp;
import com.rawtcp.burp.testutil.FakeControlPlane;
import org.junit.jupiter.api.Test;

import javax.swing.SwingUtilities;
import java.io.IOException;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Regression tests for the Intercept tab's authoritative-state behaviour. */
class InterceptPanelTest {

    private static void onEdt(Runnable action) throws Exception {
        SwingUtilities.invokeAndWait(action);
    }

    /** Flush queued {@code invokeLater} callbacks. */
    private static void flush() throws Exception {
        SwingUtilities.invokeAndWait(() -> { });
    }

    private static BurpTcp.Stats stats(boolean c2sEnabled, boolean s2cEnabled) {
        return BurpTcp.Stats.newBuilder()
                .setC2SEnabled(c2sEnabled)
                .setS2CEnabled(s2cEnabled)
                .build();
    }

    private static BurpTcp.PendingUnitInfo unit(String unitId, long revision) {
        return unitAtSeq(unitId, revision, 0);
    }

    private static BurpTcp.PendingUnitInfo unitAtSeq(String unitId, long revision, long seq) {
        return BurpTcp.PendingUnitInfo.newBuilder()
                .setUnitId(unitId)
                .setConnId("conn-" + unitId)
                .setRevision(revision)
                .setSeq(seq)
                .setBytes(com.google.protobuf.ByteString.copyFrom(new byte[] {0x0A}))
                .build();
    }

    @Test
    void displaysAuthoritativePolicyFromStats() throws Exception {
        FakeControlPlane fake = new FakeControlPlane();
        AtomicReference<InterceptPanel> ref = new AtomicReference<>();
        onEdt(() -> {
            InterceptPanel panel = new InterceptPanel(fake);
            panel.setConnected(true);
            ref.set(panel);
        });
        fake.statsResult = CompletableFuture.completedFuture(stats(true, false));
        onEdt(() -> ref.get().refreshAll());
        flush();
        onEdt(() -> assertArrayEquals(new boolean[] {true, false},
                ref.get().displayedEnabledState(),
                "checkbox state must mirror the engine, not a local default"));
    }

    @Test
    void failedSetEnabledRevertsWithoutDependingOnStats() throws Exception {
        FakeControlPlane fake = new FakeControlPlane();
        List<String> errors = new CopyOnWriteArrayList<>();
        AtomicReference<InterceptPanel> ref = new AtomicReference<>();
        onEdt(() -> {
            InterceptPanel panel = new InterceptPanel(fake);
            panel.setNotifier(errors::add);
            panel.setConnected(true);
            ref.set(panel);
        });
        fake.statsResult = CompletableFuture.completedFuture(stats(false, false));
        onEdt(() -> ref.get().refreshAll());
        flush();
        onEdt(() -> assertFalse(ref.get().displayedEnabledState()[0]));

        fake.setEnabledResult = new CompletableFuture<>();
        onEdt(() -> ref.get().clickClientToServerToggle());
        // Both the SetEnabled call and the recovery Stats call fail: the UI
        // must still revert to the last authoritative state it saw.
        fake.statsResult = new CompletableFuture<>();
        fake.statsResult.completeExceptionally(new IOException("stats unavailable"));
        fake.setEnabledResult.completeExceptionally(new IOException("engine refused"));
        flush();

        onEdt(() -> assertFalse(ref.get().displayedEnabledState()[0],
                "a rejected toggle must not stick even when Stats also fails"));
        assertEquals(1, fake.setEnabledCalls.size());
        assertTrue(errors.stream().anyMatch(message -> message.contains("SetEnabled failed")),
                "expected an error notification, got " + errors);
    }

    @Test
    void refreshPolicyAdoptsExternalEnableChange() throws Exception {
        FakeControlPlane fake = new FakeControlPlane();
        AtomicReference<InterceptPanel> ref = new AtomicReference<>();
        onEdt(() -> {
            InterceptPanel panel = new InterceptPanel(fake);
            panel.setConnected(true);
            ref.set(panel);
        });
        fake.statsResult = CompletableFuture.completedFuture(stats(false, false));
        onEdt(() -> ref.get().refreshPolicy());
        flush();
        onEdt(() -> assertArrayEquals(new boolean[] {false, false},
                ref.get().displayedEnabledState()));

        // Another controller enables C→S; the periodic reconciliation adopts it.
        fake.statsResult = CompletableFuture.completedFuture(stats(true, false));
        onEdt(() -> ref.get().refreshPolicy());
        flush();
        onEdt(() -> assertArrayEquals(new boolean[] {true, false},
                ref.get().displayedEnabledState(),
                "external policy changes must be adopted without a local toggle"));
    }

    @Test
    void replaceCommitsAgainstCapturedUnitNotCurrentSelection() throws Exception {
        FakeControlPlane fake = new FakeControlPlane();
        fake.pendingResult = CompletableFuture.completedFuture(BurpTcp.PendingList.newBuilder()
                .addUnits(unit("unit-1", 3))
                .addUnits(unit("unit-2", 9))
                .build());
        AtomicReference<InterceptPanel> ref = new AtomicReference<>();
        onEdt(() -> {
            InterceptPanel panel = new InterceptPanel(fake);
            panel.setNotifier(message -> { });
            panel.setConnected(true);
            panel.refreshAll();
            ref.set(panel);
        });
        flush();

        AtomicReference<BurpTcp.PendingUnitInfo> captured = new AtomicReference<>();
        onEdt(() -> {
            ref.get().selectRow(0);
            captured.set(ref.get().captureReplaceTarget());
        });
        // A refresh/reselection happens while the editor would be open.
        onEdt(() -> ref.get().selectRow(1));

        byte[] replacement = {0x00, (byte) 0xFF};
        onEdt(() -> ref.get().commitReplace(captured.get(), replacement));
        flush();

        assertEquals(1, fake.decideCalls.size());
        BurpTcp.Decide decide = fake.decideCalls.get(0);
        assertEquals("unit-1", decide.getUnitId(), "decision must target the captured unit");
        assertEquals(3, decide.getRevision(),
                "decision must carry the captured unit's revision, not the new selection's");
        assertEquals(BurpTcp.InterceptActionKind.REPLACE, decide.getAction());
        assertArrayEquals(replacement, decide.getReplaceBytes().toByteArray());
    }

    @Test
    void disconnectedControlsAreDisabledAndDropInFlightSnapshots() throws Exception {
        FakeControlPlane fake = new FakeControlPlane();
        CompletableFuture<BurpTcp.PendingList> slow = new CompletableFuture<>();
        fake.pendingResult = slow;
        AtomicReference<InterceptPanel> ref = new AtomicReference<>();
        onEdt(() -> {
            InterceptPanel panel = new InterceptPanel(fake);
            panel.setConnected(true);
            ref.set(panel);
        });
        // A snapshot is in flight, then the panel disconnects.
        onEdt(() -> ref.get().refreshAll());
        onEdt(() -> ref.get().setConnected(false));

        slow.complete(BurpTcp.PendingList.newBuilder().addUnits(unit("unit-1", 0)).build());
        flush();
        onEdt(() -> {
            assertFalse(ref.get().controlsEnabled());
            assertTrue(ref.get().displayedUnits().isEmpty(),
                    "a snapshot completing after disconnect must be dropped");
        });
    }

    @Test
    void statsInFlightWhenAToggleStartsCannotOverwriteIt() throws Exception {
        FakeControlPlane fake = new FakeControlPlane();
        AtomicReference<InterceptPanel> ref = new AtomicReference<>();
        onEdt(() -> {
            InterceptPanel panel = new InterceptPanel(fake);
            panel.setNotifier(message -> { });
            panel.setConnected(true);
            ref.set(panel);
        });
        fake.statsResult = CompletableFuture.completedFuture(stats(false, false));
        onEdt(() -> ref.get().refreshPolicy());
        flush();
        onEdt(() -> assertFalse(ref.get().displayedEnabledState()[0]));

        // A Stats response is issued and left in flight.
        CompletableFuture<BurpTcp.Stats> staleStats = new CompletableFuture<>();
        fake.statsResult = staleStats;
        onEdt(() -> ref.get().refreshPolicy());

        // The user toggles while that Stats request is still outstanding.
        fake.setEnabledResult = new CompletableFuture<>();
        onEdt(() -> ref.get().clickClientToServerToggle());
        onEdt(() -> assertTrue(ref.get().displayedEnabledState()[0],
                "the toggle must show the user's intent while in flight"));

        // The stale Stats (still reporting disabled) lands after the toggle
        // began; it predates the user's action and must be dropped.
        staleStats.complete(stats(false, false));
        flush();
        onEdt(() -> assertTrue(ref.get().displayedEnabledState()[0],
                "a Stats response predating the toggle must not overwrite it"));
    }

    @Test
    void pollingStaysSuppressedUntilEveryToggleCompletes() throws Exception {
        FakeControlPlane fake = new FakeControlPlane();
        AtomicReference<InterceptPanel> ref = new AtomicReference<>();
        onEdt(() -> {
            InterceptPanel panel = new InterceptPanel(fake);
            panel.setNotifier(message -> { });
            panel.setConnected(true);
            ref.set(panel);
        });
        fake.statsResult = CompletableFuture.completedFuture(stats(false, false));
        onEdt(() -> ref.get().refreshPolicy());
        flush();

        // Two toggles in flight at once, each with its own future.
        fake.freshSetEnabledFutures = true;
        onEdt(() -> ref.get().clickClientToServerToggle());
        onEdt(() -> ref.get().clickServerToClientToggle());
        assertEquals(2, fake.setEnabledFutures.size(), "expected two in-flight toggles");

        // Complete only the first; the second is still in flight, so a poll
        // that would report both disabled must not overwrite either checkbox.
        fake.setEnabledFutures.get(0).complete(BurpTcp.SetEnabledResult.getDefaultInstance());
        fake.statsResult = CompletableFuture.completedFuture(stats(false, false));
        onEdt(() -> ref.get().refreshPolicy());
        flush();
        onEdt(() -> {
            assertTrue(ref.get().displayedEnabledState()[0],
                    "polling resumed while another toggle was still in flight");
            assertTrue(ref.get().displayedEnabledState()[1],
                    "polling resumed while another toggle was still in flight");
        });

        // Completing the second toggle clears suppression and reconciles.
        fake.setEnabledFutures.get(1).complete(BurpTcp.SetEnabledResult.getDefaultInstance());
        fake.statsResult = CompletableFuture.completedFuture(stats(true, true));
        flush();
        onEdt(() -> assertArrayEquals(new boolean[] {true, true},
                ref.get().displayedEnabledState(),
                "the panel must reconcile once every toggle completes"));
    }

    @Test
    void failedToggleRevertsBeforeNotifying() throws Exception {
        FakeControlPlane fake = new FakeControlPlane();
        List<boolean[]> statesAtNotify = new CopyOnWriteArrayList<>();
        AtomicReference<InterceptPanel> ref = new AtomicReference<>();
        onEdt(() -> {
            InterceptPanel panel = new InterceptPanel(fake);
            panel.setNotifier(message -> statesAtNotify.add(panel.displayedEnabledState()));
            panel.setConnected(true);
            ref.set(panel);
        });
        fake.statsResult = CompletableFuture.completedFuture(stats(false, false));
        onEdt(() -> ref.get().refreshAll());
        flush();

        fake.setEnabledResult = new CompletableFuture<>();
        onEdt(() -> ref.get().clickClientToServerToggle());
        fake.setEnabledResult.completeExceptionally(new IOException("engine refused"));
        flush();

        assertEquals(1, statesAtNotify.size(), "expected exactly one notification");
        assertFalse(statesAtNotify.get(0)[0],
                "the rejected toggle must be reverted before the failure is notified");
    }

    @Test
    void failedSecondToggleKeepsTheFirstToggleVisible() throws Exception {
        FakeControlPlane fake = new FakeControlPlane();
        List<String> errors = new CopyOnWriteArrayList<>();
        AtomicReference<InterceptPanel> ref = new AtomicReference<>();
        onEdt(() -> {
            InterceptPanel panel = new InterceptPanel(fake);
            panel.setNotifier(errors::add);
            panel.setConnected(true);
            ref.set(panel);
        });
        fake.statsResult = CompletableFuture.completedFuture(stats(false, false));
        onEdt(() -> ref.get().refreshAll());
        flush();

        fake.freshSetEnabledFutures = true;
        onEdt(() -> ref.get().clickClientToServerToggle());
        onEdt(() -> ref.get().clickServerToClientToggle());
        assertEquals(2, fake.setEnabledFutures.size());

        // The first toggle succeeds while the second is still pending; the
        // second then fails. Restoring must not hide the confirmed success.
        fake.setEnabledFutures.get(0).complete(BurpTcp.SetEnabledResult.getDefaultInstance());
        fake.setEnabledFutures.get(1).completeExceptionally(new IOException("engine refused"));
        flush();

        onEdt(() -> assertTrue(ref.get().displayedEnabledState()[0],
                "a failed second toggle must not hide the first toggle's success"));
        assertEquals(1, errors.size());
    }

    @Test
    void forwardAllForwardsEveryHeldUnitUnchanged() throws Exception {
        FakeControlPlane fake = new FakeControlPlane();
        fake.pendingResult = CompletableFuture.completedFuture(BurpTcp.PendingList.newBuilder()
                .addUnits(unit("unit-1", 3))
                .addUnits(unit("unit-2", 9))
                .build());
        AtomicReference<InterceptPanel> ref = new AtomicReference<>();
        onEdt(() -> {
            InterceptPanel panel = new InterceptPanel(fake);
            panel.setNotifier(message -> { });
            panel.setConnected(true);
            panel.refreshAll();
            ref.set(panel);
        });
        flush();

        onEdt(() -> assertTrue(ref.get().isForwardAllEnabled(), "queue non-empty must enable Forward all"));
        onEdt(() -> ref.get().clickForwardAll());
        flush();

        assertEquals(2, fake.decideCalls.size(), "each held unit gets exactly one decision");
        for (BurpTcp.Decide decide : fake.decideCalls) {
            assertEquals(BurpTcp.InterceptActionKind.FORWARD, decide.getAction());
            assertTrue(decide.getReplaceBytes().isEmpty(), "forward-all must not rewrite bytes");
        }
    }

    @Test
    void statsLineExposesQueueFullBypasses() throws Exception {
        FakeControlPlane fake = new FakeControlPlane();
        AtomicReference<InterceptPanel> ref = new AtomicReference<>();
        onEdt(() -> {
            ref.set(new InterceptPanel(fake));
            ref.get().setConnected(true);
        });
        fake.statsResult = CompletableFuture.completedFuture(BurpTcp.Stats.newBuilder()
                .setOffers(10).setCommits(7).setOverflowForwards(3).build());
        onEdt(() -> ref.get().refreshAll());
        flush();
        onEdt(() -> assertTrue(ref.get().statsText().contains("Bypassed (queue full): 3"),
                "queue-full passthrough must be visible, got: " + ref.get().statsText()));
    }

    @Test
    void midStreamSliceWarnsThatDropReplaceCorruptsTheTransfer() throws Exception {
        FakeControlPlane fake = new FakeControlPlane();
        fake.pendingResult = CompletableFuture.completedFuture(BurpTcp.PendingList.newBuilder()
                .addUnits(unitAtSeq("unit-7", 0, 6))
                .build());
        AtomicReference<InterceptPanel> ref = new AtomicReference<>();
        onEdt(() -> {
            InterceptPanel panel = new InterceptPanel(fake);
            panel.setNotifier(message -> { });
            panel.setConnected(true);
            panel.refreshAll();
            ref.set(panel);
        });
        flush();
        onEdt(() -> {
            assertTrue(ref.get().selectionText().contains("stream slice #7"),
                    "seq>0 must be called out, got: " + ref.get().selectionText());
            assertTrue(ref.get().selectionText().contains("Close breaks it"),
                    "got: " + ref.get().selectionText());
        });
    }

    @Test
    void firstSliceCarriesNoStreamWarning() throws Exception {
        FakeControlPlane fake = new FakeControlPlane();
        fake.pendingResult = CompletableFuture.completedFuture(BurpTcp.PendingList.newBuilder()
                .addUnits(unit("unit-1", 0))
                .build());
        AtomicReference<InterceptPanel> ref = new AtomicReference<>();
        onEdt(() -> {
            InterceptPanel panel = new InterceptPanel(fake);
            panel.setNotifier(message -> { });
            panel.setConnected(true);
            panel.refreshAll();
            ref.set(panel);
        });
        flush();
        onEdt(() -> assertTrue(!ref.get().selectionText().contains("stream slice"),
                "seq 0 must not warn, got: " + ref.get().selectionText()));
    }

    @Test
    void rawTextEditWithStaleContentLengthIsBlockedBeforeSending() throws Exception {
        FakeControlPlane fake = new FakeControlPlane();
        List<String> notices = new CopyOnWriteArrayList<>();
        String wire = "POST /login HTTP/1.1\r\nContent-Length:  3\r\n\r\na=1";
        fake.pendingResult = CompletableFuture.completedFuture(BurpTcp.PendingList.newBuilder()
                .addUnits(BurpTcp.PendingUnitInfo.newBuilder()
                        .setUnitId("http-1").setConnId("conn-1").setRevision(0)
                        .setBytes(com.google.protobuf.ByteString.copyFromUtf8(wire))
                        .build())
                .build());
        AtomicReference<InterceptPanel> ref = new AtomicReference<>();
        onEdt(() -> {
            InterceptPanel panel = new InterceptPanel(fake);
            panel.setNotifier(notices::add);
            panel.setConnected(true);
            panel.refreshAll();
            ref.set(panel);
        });
        flush();

        // Simulate a raw-text edit that lengthens the body but leaves the header.
        onEdt(() -> ref.get().editor().selectMode(false));
        flush();
        onEdt(() -> ref.get().editor().textArea().setText(
                wire.replace("a=1", "a=1&b=2")));
        flush();
        onEdt(() -> ref.get().forwardEdited());

        assertTrue(fake.decideCalls.isEmpty(), "stale Content-Length must not leave the UI");
        assertTrue(notices.stream().anyMatch(m -> m.contains("Content-Length says 3 but the body is 7 bytes")),
                "expected a framing error, got " + notices);
    }
}
