package com.rawtcp.burp.ui;

import com.rawtcp.burp.ipc.proto.BurpTcp;
import com.rawtcp.burp.testutil.FakeControlPlane;
import org.junit.jupiter.api.Test;

import javax.swing.SwingUtilities;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;

/** Regression tests for stale-snapshot handling in the Connections tab. */
class ConnectionsPanelTest {

    private static void onEdt(Runnable action) throws Exception {
        SwingUtilities.invokeAndWait(action);
    }

    private static void flush() throws Exception {
        SwingUtilities.invokeAndWait(() -> { });
    }

    private static BurpTcp.ConnectionList connections(String connId) {
        return BurpTcp.ConnectionList.newBuilder()
                .addConnections(BurpTcp.ConnectionInfo.newBuilder()
                        .setConnId(connId)
                        .setRequestedHost("host")
                        .setRequestedPort(80))
                .build();
    }

    @Test
    void rowsPopulateFromSnapshot() throws Exception {
        FakeControlPlane fake = new FakeControlPlane();
        fake.listConnectionsResult = CompletableFuture.completedFuture(connections("c1"));
        AtomicReference<ConnectionsPanel> ref = new AtomicReference<>();
        onEdt(() -> ref.set(new ConnectionsPanel(fake)));
        onEdt(() -> ref.get().refresh());
        flush();
        onEdt(() -> assertEquals(1, ref.get().rowCount()));
    }

    @Test
    void clearDropsRowsAndIgnoresLateResponse() throws Exception {
        FakeControlPlane fake = new FakeControlPlane();
        CompletableFuture<BurpTcp.ConnectionList> slow = new CompletableFuture<>();
        fake.listConnectionsResult = slow;
        AtomicReference<ConnectionsPanel> ref = new AtomicReference<>();
        onEdt(() -> ref.set(new ConnectionsPanel(fake)));

        onEdt(() -> ref.get().refresh());
        onEdt(() -> ref.get().clear());

        slow.complete(connections("late"));
        flush();
        onEdt(() -> assertEquals(0, ref.get().rowCount(),
                "a response after clear must be ignored"));
    }

    @Test
    void closedRowsShowTerminalReason() throws Exception {
        FakeControlPlane fake = new FakeControlPlane();
        fake.listConnectionsResult = CompletableFuture.completedFuture(
                BurpTcp.ConnectionList.newBuilder()
                        .addConnections(BurpTcp.ConnectionInfo.newBuilder()
                                .setConnId("dead")
                                .setRequestedHost("10.0.0.9").setRequestedPort(7007)
                                .setEstablished(false).setClosed(true)
                                .setBytesClientToServer(433).setBytesServerToClient(0)
                                .setCloseReason("client_to_server: connection reset"))
                        .addConnections(BurpTcp.ConnectionInfo.newBuilder()
                                .setConnId("live")
                                .setRequestedHost("10.0.0.9").setRequestedPort(7007)
                                .setEstablished(true))
                        .build());
        AtomicReference<ConnectionsPanel> ref = new AtomicReference<>();
        onEdt(() -> ref.set(new ConnectionsPanel(fake)));
        onEdt(() -> ref.get().refresh());
        flush();
        onEdt(() -> {
            assertEquals(2, ref.get().rowCount());
            assertEquals("client_to_server: connection reset", ref.get().cellValue(0, 6));
            assertEquals("", ref.get().cellValue(1, 6),
                    "live connections have no terminal reason");
        });
    }

    @Test
    void routedRowsShowBurpListener() throws Exception {
        FakeControlPlane fake = new FakeControlPlane();
        fake.listConnectionsResult = CompletableFuture.completedFuture(
                BurpTcp.ConnectionList.newBuilder()
                        .addConnections(BurpTcp.ConnectionInfo.newBuilder()
                                .setConnId("routed")
                                .setRequestedHost("10.0.0.9").setRequestedPort(7007)
                                .setEstablished(true)
                                .setRouted(true).setRouteTarget("127.0.0.1:8081"))
                        .addConnections(BurpTcp.ConnectionInfo.newBuilder()
                                .setConnId("direct")
                                .setRequestedHost("10.0.0.9").setRequestedPort(7007)
                                .setEstablished(true))
                        .build());
        AtomicReference<ConnectionsPanel> ref = new AtomicReference<>();
        onEdt(() -> ref.set(new ConnectionsPanel(fake)));
        onEdt(() -> ref.get().refresh());
        flush();
        onEdt(() -> {
            assertEquals(2, ref.get().rowCount());
            assertEquals("via Burp 127.0.0.1:8081", ref.get().cellValue(0, 7));
            assertEquals("", ref.get().cellValue(1, 7),
                    "direct connections show no Burp marker");
        });
    }
}
