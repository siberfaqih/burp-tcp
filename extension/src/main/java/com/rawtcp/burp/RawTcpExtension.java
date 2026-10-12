package com.rawtcp.burp;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.persistence.Preferences;
import com.rawtcp.burp.ipc.IpcClient;
import com.rawtcp.burp.ui.RawTcpPanel;

/**
 * Burp Suite entry point for the Raw TCP workspace (Phase 4B).
 *
 * <p>Registers a suite tab that connects to the rawtcp-engine control plane
 * over the authenticated localhost WebSocket IPC from Phase 4A. The
 * extension holds no relay state of its own: all connection, history, and
 * interception data lives in the engine and is fetched on demand, so
 * unloading the extension only closes the socket.
 *
 * <p>Unload safety: the registered unloading handler closes the IPC client,
 * which the engine observes as the last controller leaving and turns into a
 * fail-open disable of both interception directions.
 */
public final class RawTcpExtension implements BurpExtension {

    /** Extension version, reported in the {@code Hello} handshake. */
    public static final String VERSION = "0.1.4";

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("Raw TCP");

        SettingsStore settings = new PreferencesStore(api.persistence().preferences());
        IpcClient client = new IpcClient("burp-raw-tcp", VERSION);
        RawTcpPanel panel = new RawTcpPanel(client, settings);

        panel.setTheme(api.userInterface()::applyThemeToComponent);
        api.userInterface().registerSuiteTab("Raw TCP", panel);

        // Unload safety: stop the panel's timers and detach its listener, then
        // close the client so the engine drops the last controller and fails
        // open. Never leave a timer or socket running after unload.
        api.extension().registerUnloadingHandler(() -> {
            panel.dispose();
            client.close();
        });

        api.logging().logToOutput("Raw TCP " + VERSION + " loaded. "
                + "Start the engine with --ipc-port PORT and paste the printed "
                + "capability token into the Raw TCP tab.");
    }

    /** Burp preference-backed settings store. */
    private static final class PreferencesStore implements SettingsStore {

        private final Preferences preferences;

        PreferencesStore(Preferences preferences) {
            this.preferences = preferences;
        }

        @Override
        public String get(String key, String fallback) {
            String value = preferences.getString(key);
            return value == null ? fallback : value;
        }

        @Override
        public void put(String key, String value) {
            preferences.setString(key, value);
        }
    }
}
