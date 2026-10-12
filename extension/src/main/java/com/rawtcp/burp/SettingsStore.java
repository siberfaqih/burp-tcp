package com.rawtcp.burp;

/**
 * Minimal key/value store for the few persisted settings (IPC port and
 * capability token). The extension backs this with Burp preferences; tests
 * use the in-memory default.
 */
public interface SettingsStore {

    String get(String key, String fallback);

    void put(String key, String value);

    /** Volatile in-memory store, used when no persistence is available. */
    SettingsStore IN_MEMORY = new SettingsStore() {
        private final java.util.Map<String, String> values = new java.util.concurrent.ConcurrentHashMap<>();

        @Override
        public String get(String key, String fallback) {
            return values.getOrDefault(key, fallback);
        }

        @Override
        public void put(String key, String value) {
            values.put(key, value);
        }
    };
}
