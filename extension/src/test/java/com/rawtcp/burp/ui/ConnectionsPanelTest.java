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
}
