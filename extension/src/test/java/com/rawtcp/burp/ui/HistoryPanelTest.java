package com.rawtcp.burp.ui;

import com.rawtcp.burp.ipc.proto.BurpTcp;
import com.rawtcp.burp.testutil.FakeControlPlane;
import org.junit.jupiter.api.Test;

import javax.swing.SwingUtilities;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Unified all-connections history: merging, cheap refresh, and filter fallback. */
class HistoryPanelTest {

    private static void onEdt(Runnable action) throws Exception {
        SwingUtilities.invokeAndWait(action);
    }

    private static void flush() throws Exception {
        SwingUtilities.invokeAndWait(() -> { });
    }

    private static BurpTcp.ConnectionInfo conn(String id, long c2s, long s2c) {
        return BurpTcp.ConnectionInfo.newBuilder().setConnId(id)
                .setRequestedHost("127.0.0.1").setRequestedPort(1433)
                .setEstablished(true)
                .setBytesClientToServer(c2s).setBytesServerToClient(s2c).build();
    }

    private static BurpTcp.HistoryData history(String chunkId, long recordedMs) {
        return BurpTcp.HistoryData.newBuilder()
                .addChunks(BurpTcp.TrafficChunkInfo.newBuilder()
                        .setChunkId(chunkId).setRecordedUnixMs(recordedMs)
                        .setBytes(com.google.protobuf.ByteString.copyFrom(new byte[] {0x01})))
                .build();
    }

    @Test
    void allModeMergesChunksAcrossConnectionsInTimeOrder() throws Exception {
        FakeControlPlane fake = new FakeControlPlane();
        AtomicReference<HistoryPanel> ref = new AtomicReference<>();
        onEdt(() -> ref.set(new HistoryPanel(fake)));

        onEdt(() -> ref.get().setConnections(List.of(conn("conn-A", 1, 0), conn("conn-B", 0, 1))));
        assertEquals(2, fake.historyCalls.size(), "each changed connection is fetched once");

        // B's chunk is older; merged view sorts by recorded time across connections.
        fake.historyCalls.get(0).complete(history("from-A", 2000));
        fake.historyCalls.get(1).complete(history("from-B", 1000));
        flush();
        onEdt(() -> {
            assertEquals(2, ref.get().displayedChunks().size());
            assertEquals("from-B", ref.get().displayedChunks().get(0).getChunkId());
            assertEquals("from-A", ref.get().displayedChunks().get(1).getChunkId());
            assertNull(ref.get().connectionId(), "default view has no connection filter");
        });
    }

    @Test
    void unchangedConnectionsAreNotRefetched() throws Exception {
        FakeControlPlane fake = new FakeControlPlane();
        AtomicReference<HistoryPanel> ref = new AtomicReference<>();
        onEdt(() -> ref.set(new HistoryPanel(fake)));

        onEdt(() -> ref.get().setConnections(List.of(conn("conn-A", 5, 0))));
        fake.historyCalls.get(0).complete(history("chunk-1", 1000));
        flush();
        assertEquals(1, fake.historyCalls.size());

        // Same counters: refresh merges from cache without a new snapshot RPC.
        onEdt(() -> ref.get().setConnections(List.of(conn("conn-A", 5, 0))));
        flush();
        assertEquals(1, fake.historyCalls.size(), "quiet connections must not be refetched");
        onEdt(() -> assertEquals(1, ref.get().displayedChunks().size()));

        // Moved counters: the connection is refetched.
        onEdt(() -> ref.get().setConnections(List.of(conn("conn-A", 9, 0))));
        assertEquals(2, fake.historyCalls.size());
    }

    @Test
    void lateFetchCycleIsIgnored() throws Exception {
        FakeControlPlane fake = new FakeControlPlane();
        AtomicReference<HistoryPanel> ref = new AtomicReference<>();
        onEdt(() -> ref.set(new HistoryPanel(fake)));

        onEdt(() -> ref.get().setConnections(List.of(conn("conn-A", 1, 0))));
        assertEquals(1, fake.historyCalls.size());
        // New counters start a newer cycle before the first fetch lands.
        onEdt(() -> ref.get().setConnections(List.of(conn("conn-A", 2, 0))));
        assertEquals(2, fake.historyCalls.size());

        fake.historyCalls.get(0).complete(history("stale", 1000));
        flush();
        onEdt(() -> assertTrue(ref.get().displayedChunks().isEmpty(),
                "a fetch superseded by a newer cycle must be ignored"));
        fake.historyCalls.get(1).complete(history("fresh", 2000));
        flush();
        onEdt(() -> assertEquals("fresh", ref.get().displayedChunks().get(0).getChunkId()));
    }

    @Test
    void vanishedFilterFallsBackToAll() throws Exception {
        FakeControlPlane fake = new FakeControlPlane();
        AtomicReference<HistoryPanel> ref = new AtomicReference<>();
        onEdt(() -> ref.set(new HistoryPanel(fake)));

        onEdt(() -> {
            ref.get().setConnections(List.of(conn("conn-A", 1, 0), conn("conn-B", 1, 0)));
            ref.get().setConnection("conn-A");
        });
        assertEquals("conn-A", ref.get().connectionId());

        // conn-A closes and leaves the snapshot: follow live traffic, don't freeze.
        onEdt(() -> ref.get().setConnections(List.of(conn("conn-B", 1, 0))));
        onEdt(() -> assertNull(ref.get().connectionId(),
                "a filter pointing at a vanished connection must reset to all"));
    }

    @Test
    void directionFilterAppliesLocallyWithoutRefetch() throws Exception {
        FakeControlPlane fake = new FakeControlPlane();
        AtomicReference<HistoryPanel> ref = new AtomicReference<>();
        onEdt(() -> ref.set(new HistoryPanel(fake)));

        onEdt(() -> ref.get().setConnections(List.of(conn("conn-A", 1, 1))));
        BurpTcp.HistoryData both = BurpTcp.HistoryData.newBuilder()
                .addChunks(BurpTcp.TrafficChunkInfo.newBuilder().setChunkId("up")
                        .setDirection(BurpTcp.Direction.CLIENT_TO_SERVER)
                        .setBytes(com.google.protobuf.ByteString.copyFrom(new byte[] {0x01})))
                .addChunks(BurpTcp.TrafficChunkInfo.newBuilder().setChunkId("down")
                        .setDirection(BurpTcp.Direction.SERVER_TO_CLIENT)
                        .setBytes(com.google.protobuf.ByteString.copyFrom(new byte[] {0x02})))
                .build();
        fake.historyCalls.get(0).complete(both);
        flush();
        onEdt(() -> assertEquals(2, ref.get().trafficTable().getRowCount()));

        onEdt(() -> ref.get().selectDirection(1)); // To server
        flush();
        onEdt(() -> assertEquals(1, ref.get().trafficTable().getRowCount()));
        assertEquals(1, fake.historyCalls.size(), "direction is a local filter, not a new fetch");
    }

    @Test
    void clearInvalidatesInFlightFetches() throws Exception {
        FakeControlPlane fake = new FakeControlPlane();
        AtomicReference<HistoryPanel> ref = new AtomicReference<>();
        onEdt(() -> ref.set(new HistoryPanel(fake)));

        onEdt(() -> ref.get().setConnections(List.of(conn("conn-A", 1, 0))));
        onEdt(() -> ref.get().clear());

        fake.historyCalls.get(0).complete(history("late", 1000));
        flush();
        onEdt(() -> assertTrue(ref.get().displayedChunks().isEmpty(),
                "a fetch completing after clear must be ignored"));
    }

    @Test
    void snapshotsAreBoundedAndTotalsReported() throws Exception {
        FakeControlPlane fake = new FakeControlPlane();
        AtomicReference<HistoryPanel> ref = new AtomicReference<>();
        onEdt(() -> ref.set(new HistoryPanel(fake)));

        onEdt(() -> ref.get().setConnections(List.of(conn("conn-A", 9, 0))));
        assertEquals(1, fake.historyCalls.size());
        assertEquals(HistoryPanel.HISTORY_MAX_CHUNKS, fake.historyMaxChunks.get(0),
                "bulk transfers must not pull unbounded snapshots");

        BurpTcp.HistoryData partial = BurpTcp.HistoryData.newBuilder()
                .addChunks(BurpTcp.TrafficChunkInfo.newBuilder().setChunkId("tail")
                        .setBytes(com.google.protobuf.ByteString.copyFrom(new byte[] {0x01})))
                .setTotalChunks(6000)
                .build();
        fake.historyCalls.get(0).complete(partial);
        flush();
        onEdt(() -> assertTrue(ref.get().statusText().contains("newest 1 of 6000"),
                "truncation must be honest, got: " + ref.get().statusText()));
    }
}
