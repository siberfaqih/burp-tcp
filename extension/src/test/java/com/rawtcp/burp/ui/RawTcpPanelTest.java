package com.rawtcp.burp.ui;

import com.rawtcp.burp.SettingsStore;
import com.rawtcp.burp.ipc.proto.BurpTcp;
import com.rawtcp.burp.testutil.FakeControlPlane;
import org.junit.jupiter.api.Test;

import javax.swing.SwingUtilities;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Teardown and daemon-epoch behaviour of the top-level workspace panel. */
class RawTcpPanelTest {

    private static void onEdt(Runnable action) throws Exception {
        SwingUtilities.invokeAndWait(action);
    }

    private static void flush() throws Exception {
        SwingUtilities.invokeAndWait(() -> { });
    }

    private static BurpTcp.HelloAck ack(String epoch) {
        return BurpTcp.HelloAck.newBuilder()
                .setProtocolVersion(1)
                .setDaemonEpoch(epoch)
                .setServerVersion("test")
                .build();
    }

    @Test
    void disposeStopsTimerAndDetachesListener() throws Exception {
        FakeControlPlane fake = new FakeControlPlane();
        AtomicReference<RawTcpPanel> ref = new AtomicReference<>();
        onEdt(() -> ref.set(new RawTcpPanel(fake, SettingsStore.IN_MEMORY)));
        assertEquals(1, fake.listenerCount(), "panel should attach one listener");

        onEdt(() -> ref.get().dispose());
        assertEquals(0, fake.listenerCount(), "dispose must detach the listener");
        onEdt(() -> assertFalse(ref.get().isStatusTimerRunning(),
                "dispose must stop the status timer"));
    }

    @Test
    void disconnectClearsPanels() throws Exception {
        FakeControlPlane fake = new FakeControlPlane();
        fake.listConnectionsResult = CompletableFuture.completedFuture(
                BurpTcp.ConnectionList.newBuilder()
                        .addConnections(BurpTcp.ConnectionInfo.newBuilder().setConnId("c1"))
                        .build());
        AtomicReference<RawTcpPanel> ref = new AtomicReference<>();
        onEdt(() -> ref.set(new RawTcpPanel(fake, SettingsStore.IN_MEMORY)));

        onEdt(() -> ref.get().connectionsPanel().refresh());
        flush();
        onEdt(() -> assertEquals(1, ref.get().connectionsPanel().rowCount()));

        onEdt(() -> ref.get().onDisconnected("socket closed"));
        flush();
        onEdt(() -> {
            assertEquals(0, ref.get().connectionsPanel().rowCount(),
                    "disconnect must clear stale connection rows");
            assertFalse(ref.get().interceptPanel().controlsEnabled(),
                    "disconnect must disable interception controls");
        });
        onEdt(() -> ref.get().dispose());
    }

    @Test
    void daemonEpochChangeClearsHistory() throws Exception {
        FakeControlPlane fake = new FakeControlPlane();
        AtomicReference<RawTcpPanel> ref = new AtomicReference<>();
        onEdt(() -> ref.set(new RawTcpPanel(fake, SettingsStore.IN_MEMORY)));

        onEdt(() -> ref.get().historyPanel().setConnection("c1"));
        flush();
        onEdt(() -> assertEquals("c1", ref.get().historyPanel().connectionId()));

        // Same epoch: history is retained across a reconnect.
        onEdt(() -> ref.get().onConnected(ack("epoch-1")));
        flush();
        onEdt(() -> assertEquals("c1", ref.get().historyPanel().connectionId()));

        // A new daemon epoch invalidates previously observed state.
        onEdt(() -> ref.get().onConnected(ack("epoch-2")));
        flush();
        onEdt(() -> assertNull(ref.get().historyPanel().connectionId(),
                "a daemon restart must clear history"));
        onEdt(() -> ref.get().dispose());
    }

    @Test
    void repeaterTabFollowsConnection() throws Exception {        FakeControlPlane fake = new FakeControlPlane();
        AtomicReference<RawTcpPanel> ref = new AtomicReference<>();
        onEdt(() -> ref.set(new RawTcpPanel(fake, SettingsStore.IN_MEMORY)));
        try {
            onEdt(() -> ref.get().onConnected(ack("epoch-1")));
            flush();
            onEdt(() -> assertTrue(ref.get().repeaterPanel().controlsEnabled(),
                    "connect must enable the repeater tab"));

            onEdt(() -> ref.get().onDisconnected("socket closed"));
            flush();
            onEdt(() -> assertFalse(ref.get().repeaterPanel().controlsEnabled(),
                    "disconnect must disable the repeater tab"));
        } finally {
            onEdt(() -> ref.get().dispose());
        }
    }

    @Test
    void callbackAfterDisposeDoesNotReEnableControls() throws Exception {
        FakeControlPlane fake = new FakeControlPlane();
        AtomicReference<RawTcpPanel> ref = new AtomicReference<>();
        onEdt(() -> ref.set(new RawTcpPanel(fake, SettingsStore.IN_MEMORY)));

        onEdt(() -> ref.get().dispose());
        // A callback that captured the panel before removal (or a stale
        // iteration of the listener list) must not act after disposal.
        onEdt(() -> ref.get().onConnected(ack("epoch-1")));
        flush();

        onEdt(() -> assertFalse(ref.get().interceptPanel().controlsEnabled(),
                "a callback after dispose must not re-enable controls"));
    }

    @Test
    void queuedConnectedCallbackAfterDisconnectDoesNotReEnableControls() throws Exception {
        FakeControlPlane fake = new FakeControlPlane();
        SettingsStore settings = new SettingsStore() {
            private final java.util.Map<String, String> values = new java.util.HashMap<>();

            @Override
            public String get(String key, String fallback) {
                return values.getOrDefault(key, fallback);
            }

            @Override
            public void put(String key, String value) {
                values.put(key, value);
            }
        };
        settings.put("rawtcp.ipc.port", "1234");
        settings.put("rawtcp.ipc.token", "token");

        AtomicReference<RawTcpPanel> ref = new AtomicReference<>();
        onEdt(() -> ref.set(new RawTcpPanel(fake, settings)));
        try {
            onEdt(() -> ref.get().toggleConnection());
            onEdt(() -> assertTrue(ref.get().isStarted()));

            onEdt(() -> {
                // The client reports connected: the listener queues an EDT
                // action against the current session.
                ref.get().onConnected(ack("epoch-1"));
                // The user disconnects before that queued action is dequeued.
                ref.get().toggleConnection();
            });
            flush();

            onEdt(() -> {
                assertFalse(ref.get().isStarted());
                assertFalse(ref.get().interceptPanel().controlsEnabled(),
                        "a callback queued before disconnect must not re-enable controls");
            });
        } finally {
            onEdt(() -> ref.get().dispose());
        }
    }

    private static BurpTcp.HelloAck ackWithSocks(String epoch, String socks) {
        return BurpTcp.HelloAck.newBuilder()
                .setProtocolVersion(1)
                .setDaemonEpoch(epoch)
                .setServerVersion("test")
                .setSocksAddr(socks)
                .build();
    }

    @Test
    void bannerSummarizesSetupWhileConnected() throws Exception {
        FakeControlPlane fake = new FakeControlPlane();
        fake.listConnectionsResult = CompletableFuture.completedFuture(
                BurpTcp.ConnectionList.newBuilder()
                        .addConnections(BurpTcp.ConnectionInfo.newBuilder()
                                .setConnId("c1").setRequestedHost("10.0.0.9")
                                .setRequestedPort(7007).setEstablished(true))
                        .build());
        fake.statsResult = CompletableFuture.completedFuture(BurpTcp.Stats.newBuilder()
                .setC2SEnabled(true).setS2CEnabled(false)
                .setActiveConnections(1).setAcceptedConnections(7).build());
        AtomicReference<RawTcpPanel> ref = new AtomicReference<>();
        onEdt(() -> ref.set(new RawTcpPanel(fake, SettingsStore.IN_MEMORY)));
        try {
            onEdt(() -> ref.get().onConnected(ackWithSocks("epoch-123456789", "127.0.0.1:1080")));
            flush();
            flush();
            onEdt(() -> {
                String banner = ref.get().bannerText();
                assertTrue(banner.contains("epoch-12"), "banner shows engine epoch: " + banner);
                assertTrue(banner.contains("127.0.0.1:1080"), "banner shows proxy address: " + banner);
                assertTrue(banner.contains("to server ON"), "banner shows policy: " + banner);
                assertTrue(banner.contains("to client off"), "banner shows policy: " + banner);
                assertTrue(banner.contains("1 live"), "banner shows live count: " + banner);
                assertTrue(!banner.contains("NOT CONNECTED"), "connected banner is not alarming: " + banner);
            });
        } finally {
            onEdt(() -> ref.get().dispose());
        }
    }

    @Test
    void bannerScreamsWhenDisconnected() throws Exception {
        FakeControlPlane fake = new FakeControlPlane();
        AtomicReference<RawTcpPanel> ref = new AtomicReference<>();
        onEdt(() -> ref.set(new RawTcpPanel(fake, SettingsStore.IN_MEMORY)));
        try {
            onEdt(() -> ref.get().onDisconnected("handshake rejected: bad capability token"));
            flush();
            onEdt(() -> {
                String banner = ref.get().bannerText();
                assertTrue(banner.contains("NOT CONNECTED"), "got: " + banner);
                assertTrue(banner.contains("bad capability token"), "got: " + banner);
            });
        } finally {
            onEdt(() -> ref.get().dispose());
        }
    }

    @Test
    void connectButtonReconnectsWhenStartedButSocketDead() throws Exception {
        FakeControlPlane fake = new FakeControlPlane();
        SettingsStore settings = new SettingsStore() {
            private final java.util.Map<String, String> values = new java.util.HashMap<>();

            @Override
            public String get(String key, String fallback) {
                return values.getOrDefault(key, fallback);
            }

            @Override
            public void put(String key, String value) {
                values.put(key, value);
            }
        };
        settings.put("rawtcp.ipc.port", "1234");
        settings.put("rawtcp.ipc.token", "fresh-token");
        AtomicReference<RawTcpPanel> ref = new AtomicReference<>();
        onEdt(() -> ref.set(new RawTcpPanel(fake, settings)));
        try {
            onEdt(() -> ref.get().toggleConnection());
            onEdt(() -> assertTrue(ref.get().isStarted()));
            assertEquals(1, fake.startCalls);

            // The socket died (engine restarted) while the session is
            // started: one press reconnects with the current fields instead
            // of toggling into a full disconnect.
            fake.connectedOverride = false;
            onEdt(() -> ref.get().toggleConnection());
            onEdt(() -> assertTrue(ref.get().isStarted(),
                    "reconnect must keep the session started"));
            assertEquals(2, fake.startCalls, "reconnect must start a fresh loop");
        } finally {
            onEdt(() -> ref.get().dispose());
        }
    }
}
