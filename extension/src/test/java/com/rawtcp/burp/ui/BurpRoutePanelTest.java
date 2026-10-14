package com.rawtcp.burp.ui;

import com.rawtcp.burp.ipc.proto.BurpTcp;
import com.rawtcp.burp.testutil.FakeControlPlane;
import org.junit.jupiter.api.Test;

import javax.swing.SwingUtilities;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Wiring of the Burp Route tab: add/apply/refresh against the control plane. */
class BurpRoutePanelTest {

    private static void onEdt(Runnable action) throws Exception {
        SwingUtilities.invokeAndWait(action);
    }

    private static void flush() throws Exception {
        SwingUtilities.invokeAndWait(() -> { });
    }

    @Test
    void controlsFollowConnection() throws Exception {
        FakeControlPlane fake = new FakeControlPlane();
        AtomicReference<BurpRoutePanel> ref = new AtomicReference<>();
        onEdt(() -> ref.set(new BurpRoutePanel(fake)));
        onEdt(() -> ref.get().setConnected(true));
        flush();
        onEdt(() -> assertTrue(ref.get().controlsEnabled()));
        onEdt(() -> ref.get().setConnected(false));
        flush();
        onEdt(() -> assertFalse(ref.get().controlsEnabled()));
    }

    @Test
    void addValidRuleThenApplyPushesToEngine() throws Exception {
        FakeControlPlane fake = new FakeControlPlane();
        AtomicReference<BurpRoutePanel> ref = new AtomicReference<>();
        onEdt(() -> ref.set(new BurpRoutePanel(fake)));
        onEdt(() -> ref.get().setConnected(true));
        flush();

        onEdt(() -> {
            ref.get().setRuleInput("10.0.0.5:7007=>127.0.0.1:8081");
            ref.get().addFromField();
        });
        onEdt(() -> assertEquals(1, ref.get().rowCount()));

        onEdt(() -> ref.get().apply());
        flush();
        assertEquals(1, fake.setBurpRoutesCalls.size());
        assertEquals("10.0.0.5", fake.setBurpRoutesCalls.get(0).get(0).getHostPattern());
        assertEquals(7007, fake.setBurpRoutesCalls.get(0).get(0).getPort());
        assertEquals("127.0.0.1:8081", fake.setBurpRoutesCalls.get(0).get(0).getBurpAddr());
    }

    @Test
    void addInvalidRuleShowsErrorAndAddsNothing() throws Exception {
        FakeControlPlane fake = new FakeControlPlane();
        AtomicReference<BurpRoutePanel> ref = new AtomicReference<>();
        onEdt(() -> ref.set(new BurpRoutePanel(fake)));
        onEdt(() -> ref.get().setConnected(true));
        flush();

        onEdt(() -> {
            ref.get().setRuleInput("not-a-rule");
            ref.get().addFromField();
        });
        onEdt(() -> {
            assertEquals(0, ref.get().rowCount());
            assertTrue(ref.get().statusText().startsWith("Invalid rule:"),
                    "got: " + ref.get().statusText());
        });
        assertTrue(fake.setBurpRoutesCalls.isEmpty());
    }

    @Test
    void refreshLoadsEngineTable() throws Exception {
        FakeControlPlane fake = new FakeControlPlane();
        fake.burpRouteListResult = CompletableFuture.completedFuture(
                BurpTcp.BurpRouteList.newBuilder()
                        .addRoutes(BurpTcp.BurpRoute.newBuilder()
                                .setHostPattern("*").setPort(0).setBurpAddr("127.0.0.1:8080"))
                        .build());
        AtomicReference<BurpRoutePanel> ref = new AtomicReference<>();
        onEdt(() -> ref.set(new BurpRoutePanel(fake)));
        onEdt(() -> ref.get().setConnected(true));
        flush();

        onEdt(() -> ref.get().refresh());
        flush();
        onEdt(() -> assertEquals(1, ref.get().rowCount()));
        assertEquals(1, fake.listBurpRoutesCalls);
    }
}
