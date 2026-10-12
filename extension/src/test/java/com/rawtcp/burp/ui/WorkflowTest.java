package com.rawtcp.burp.ui;

import com.google.protobuf.ByteString;
import com.rawtcp.burp.SettingsStore;
import com.rawtcp.burp.ipc.proto.BurpTcp;
import com.rawtcp.burp.testutil.FakeControlPlane;
import org.junit.jupiter.api.Test;
import javax.swing.SwingUtilities;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicReference;
import static org.junit.jupiter.api.Assertions.*;

/** User workflows across asynchronous snapshots, editors and destination routing. */
class WorkflowTest {
    private static void edt(Runnable action) throws Exception { SwingUtilities.invokeAndWait(action); }
    private static void flush() throws Exception { edt(() -> {}); }

    private static BurpTcp.PendingUnitInfo unit(String id, long revision) {
        return BurpTcp.PendingUnitInfo.newBuilder().setUnitId(id).setConnId("connection")
                .setRevision(revision).setDirection(BurpTcp.Direction.CLIENT_TO_SERVER)
                .setBytes(ByteString.copyFrom(new byte[] {0, (byte) 255})).setLen(2)
                .setExpiresUnixMs(System.currentTimeMillis() + 30_000).build();
    }

    private static void queue(FakeControlPlane fake, BurpTcp.PendingUnitInfo... units) {
        fake.pendingResult = CompletableFuture.completedFuture(
                BurpTcp.PendingList.newBuilder().addAllUnits(List.of(units)).build());
    }

    @Test
    void inlineEditSurvivesReorderAndSendsOnceAgainstOriginalRevision() throws Exception {
        FakeControlPlane fake = new FakeControlPlane();
        queue(fake, unit("first", 3), unit("second", 7));
        AtomicReference<InterceptPanel> ref = new AtomicReference<>();
        edt(() -> {
            InterceptPanel panel = new InterceptPanel(fake);
            panel.setConnected(true);
            panel.refreshAll();
            ref.set(panel);
        });
        flush();
        edt(() -> {
            assertEquals("first", ref.get().selectedUnit().getUnitId());
            ref.get().editor().textArea().setText("00 ff 4"); // deliberately incomplete edit
            ref.get().editor().textArea().setCaretPosition(3);
        });
        queue(fake, unit("second", 7), unit("first", 3));
        edt(() -> ref.get().refreshAll());
        flush();
        fake.decideResult = new CompletableFuture<>();
        edt(() -> {
            assertEquals("first", ref.get().selectedUnit().getUnitId());
            assertEquals("00 ff 4", ref.get().editor().textArea().getText());
            assertEquals(3, ref.get().editor().textArea().getCaretPosition());
            ref.get().editor().textArea().setText("00 ff 41");
            ref.get().forwardEdited();
            ref.get().forwardEdited();
        });
        assertEquals(1, fake.decideCalls.size());
        BurpTcp.Decide decision = fake.decideCalls.getFirst();
        assertEquals("first", decision.getUnitId());
        assertEquals(3, decision.getRevision());
        assertEquals(BurpTcp.InterceptActionKind.REPLACE, decision.getAction());
        assertArrayEquals(new byte[] {0, (byte) 255, 65}, decision.getReplaceBytes().toByteArray());
        fake.decideResult.complete(BurpTcp.DecideResult.newBuilder().setCommitted(true).build());
        flush();
        flush();
        edt(() -> assertEquals("second", ref.get().selectedUnit().getUnitId(),
                "successful Forward advances, even if an older snapshot still contains the committed unit"));
    }

    @Test
    void editsBelongToTheirUnitAndRevisionNotTheRowNumber() throws Exception {
        FakeControlPlane fake = new FakeControlPlane();
        queue(fake, unit("a", 1), unit("b", 1));
        AtomicReference<InterceptPanel> ref = new AtomicReference<>();
        edt(() -> {
            ref.set(new InterceptPanel(fake));
            ref.get().setConnected(true);
            ref.get().refreshAll();
        });
        flush();
        edt(() -> {
            ref.get().editor().textArea().setText("42");
            ref.get().selectRow(1);
            assertArrayEquals(new byte[] {0, (byte) 255}, ref.get().editor().getBytes());
            ref.get().selectRow(0);
            assertArrayEquals(new byte[] {66}, ref.get().editor().getBytes());
        });
        queue(fake, unit("a", 2), unit("b", 1));
        edt(() -> ref.get().refreshAll());
        flush();
        edt(() -> {
            assertArrayEquals(new byte[] {0, (byte) 255}, ref.get().editor().getBytes());
            ref.get().forwardEdited();
        });
        assertEquals(BurpTcp.InterceptActionKind.FORWARD, fake.decideCalls.getFirst().getAction());
        assertEquals(2, fake.decideCalls.getFirst().getRevision());
    }

    @Test
    void decisionCompletionAfterDisconnectCannotRestoreQueue() throws Exception {
        FakeControlPlane fake = new FakeControlPlane();
        queue(fake, unit("a", 1));
        fake.decideResult = new CompletableFuture<>();
        AtomicReference<InterceptPanel> ref = new AtomicReference<>();
        edt(() -> {
            ref.set(new InterceptPanel(fake));
            ref.get().setConnected(true);
            ref.get().refreshAll();
        });
        flush();
        edt(() -> {
            ref.get().forwardEdited();
            ref.get().setConnected(false);
        });
        fake.decideResult.complete(BurpTcp.DecideResult.newBuilder().setCommitted(true).build());
        flush();
        edt(() -> {
            assertNull(ref.get().selectedUnit());
            assertEquals(0, ref.get().editor().getBytes().length);
            assertFalse(ref.get().controlsEnabled());
        });
    }

    @Test
    void filteredSortedHistoryRoutesExactBytesAndRetainsSelectionOnRefresh() throws Exception {
        FakeControlPlane fake = new FakeControlPlane();
        AtomicReference<HistoryPanel> ref = new AtomicReference<>();
        AtomicReference<byte[]> imported = new AtomicReference<>();
        BurpTcp.ConnectionInfo conn = BurpTcp.ConnectionInfo.newBuilder().setConnId("conn")
                .setRequestedHost("127.0.0.1").setRequestedPort(1433)
                .setBytesClientToServer(3).build();
        BurpTcp.TrafficChunkInfo first = BurpTcp.TrafficChunkInfo.newBuilder()
                .setChunkId("a").setSeq(10).setBytes(ByteString.copyFromUtf8("ten")).build();
        BurpTcp.TrafficChunkInfo second = BurpTcp.TrafficChunkInfo.newBuilder()
                .setChunkId("b").setSeq(2).setBytes(ByteString.copyFrom(new byte[] {0, (byte) 255})).build();
        edt(() -> {
            ref.set(new HistoryPanel(fake));
            ref.get().setRepeaterListener((id, bytes) -> {
                assertEquals("conn", id);
                imported.set(bytes);
            });
            ref.get().setConnections(List.of(conn));
            ref.get().setConnection("conn");
        });
        // Changing the filter must reuse the outstanding snapshot.
        assertEquals(1, fake.historyCalls.size());
        fake.historyCalls.get(0).complete(BurpTcp.HistoryData.newBuilder().addChunks(first).addChunks(second).build());
        flush();
        edt(() -> {
            ref.get().trafficTable().getRowSorter().toggleSortOrder(3);
            ref.get().selectRow(0); // numeric byte size puts the 2-byte payload first
            ref.get().sendSelectedToRepeater();
            assertArrayEquals(new byte[] {0, (byte) 255}, imported.get());
            // More bytes arrive: counters move, so the live view refetches on its own.
            ref.get().setConnections(List.of(conn.toBuilder().setBytesClientToServer(5).build()));
        });
        fake.historyCalls.get(1).complete(BurpTcp.HistoryData.newBuilder().addChunks(second).addChunks(first).build());
        flush();
        edt(() -> {
            ref.get().sendSelectedToRepeater();
            assertArrayEquals(new byte[] {0, (byte) 255}, imported.get());
            ref.get().setSearch("00 ff");
            assertEquals(1, ref.get().trafficTable().getRowCount());
            ref.get().selectRow(0);
            ref.get().sendSelectedToRepeater();
            assertArrayEquals(new byte[] {0, (byte) 255}, imported.get());
        });
        assertTrue(fake.repeaterSendCalls.isEmpty());
    }

    @Test
    void historyToRepeaterCarriesTargetAndBytesWithoutSendingOrOverwriting() throws Exception {
        FakeControlPlane fake = new FakeControlPlane();
        fake.listConnectionsResult = CompletableFuture.completedFuture(BurpTcp.ConnectionList.newBuilder()
                .addConnections(BurpTcp.ConnectionInfo.newBuilder().setConnId("conn")
                        .setRequestedHost("127.0.0.1").setRequestedPort(1433)).build());
        AtomicReference<RawTcpPanel> ref = new AtomicReference<>();
        AtomicReference<RepeaterPanel> original = new AtomicReference<>();
        edt(() -> {
            ref.set(new RawTcpPanel(fake, SettingsStore.IN_MEMORY));
            ref.get().onConnected(BurpTcp.HelloAck.newBuilder().setDaemonEpoch("epoch").build());
            original.set(ref.get().repeaterPanel());
            original.get().setPayload(new byte[] {65});
        });
        flush();
        flush();
        try {
            fake.historyCalls.getFirst().complete(BurpTcp.HistoryData.newBuilder()
                    .addChunks(BurpTcp.TrafficChunkInfo.newBuilder().setChunkId("chunk")
                            .setBytes(ByteString.copyFrom(new byte[] {0, (byte) 255}))).build());
            flush();
            edt(() -> {
                ref.get().historyPanel().sendSelectedToRepeater();
                assertNotSame(original.get(), ref.get().repeaterPanel());
                assertTrue(fake.repeaterSendCalls.isEmpty());
                ref.get().repeaterPanel().clickSend();
            });
            assertEquals(1, fake.repeaterSendCalls.size());
            BurpTcp.RepeaterSend sent = fake.repeaterSendCalls.getFirst();
            assertEquals("127.0.0.1", sent.getDestinationHost());
            assertEquals(1433, sent.getDestinationPort());
            assertArrayEquals(new byte[] {0, (byte) 255}, sent.getPayload().toByteArray());
        } finally {
            edt(() -> ref.get().dispose());
        }
    }

    @Test
    void draftsShareSingleSendSlotAndImportDoesNotReplaceActiveOperation() throws Exception {
        FakeControlPlane fake = new FakeControlPlane();
        fake.repeaterStartResult = new CompletableFuture<>();
        edt(() -> {
            RepeaterWorkspace workspace = new RepeaterWorkspace(fake);
            workspace.setConnected(true);
            RepeaterPanel first = workspace.selected();
            first.setPayload(new byte[] {1});
            first.clickSend();
            workspace.open("localhost", 1234, new byte[] {2}, "history");
            RepeaterPanel second = workspace.selected();
            assertFalse(second.isSendEnabled());
            second.clickSend();
            assertEquals(1, fake.repeaterSendCalls.size());
            assertTrue(first.isActive());
            workspace.setConnected(false);
            workspace.setConnected(true);
            assertTrue(second.isSendEnabled());
            assertEquals(2, workspace.draftCount());
        });
    }

    @Test
    void invalidUtf8ViewingCannotChangeForwardedBytes() throws Exception {
        edt(() -> {
            BinaryEditorPanel editor = new BinaryEditorPanel();
            byte[] all = new byte[256];
            for (int i = 0; i < all.length; i++) all[i] = (byte) i;
            editor.setBytes(all, true);
            editor.selectMode(false);
            assertFalse(editor.isHexMode(), "UTF-8 preference remains selected for binary previews");
            assertFalse(editor.textArea().isEditable());
            assertArrayEquals(all, editor.getBytes());
            editor.setBytes(all, false);
            assertArrayEquals(all, editor.getBytes());
        });
    }
}
