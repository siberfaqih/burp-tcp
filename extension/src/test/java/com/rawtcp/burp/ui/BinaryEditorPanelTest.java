package com.rawtcp.burp.ui;

import org.junit.jupiter.api.Test;

import javax.swing.SwingUtilities;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class BinaryEditorPanelTest {

    private static void onEdt(Runnable action) throws Exception {
        SwingUtilities.invokeAndWait(action);
    }

    @Test
    void hexModeRoundTripsArbitraryBytes() throws Exception {
        AtomicReference<byte[]> result = new AtomicReference<>();
        onEdt(() -> {
            BinaryEditorPanel editor = new BinaryEditorPanel();
            byte[] bytes = {0x00, (byte) 0xFF, 0x41, 0x0A};
            editor.setBytes(bytes, true);
            result.set(editor.getBytes());
        });
        assertArrayEquals(new byte[] {0x00, (byte) 0xFF, 0x41, 0x0A}, result.get());
    }

    @Test
    void malformedHexIsRejected() throws Exception {
        AtomicReference<Throwable> thrown = new AtomicReference<>();
        onEdt(() -> {
            BinaryEditorPanel editor = new BinaryEditorPanel();
            editor.textArea().setText("not-hex");
            try {
                editor.getBytes();
            } catch (IllegalArgumentException invalid) {
                thrown.set(invalid);
            }
        });
        assertNotNull(thrown.get(), "expected malformed hex to be rejected");
    }

    @Test
    void switchingHexToTextConvertsBytesNotCharacters() throws Exception {
        AtomicReference<byte[]> result = new AtomicReference<>();
        AtomicReference<String> warning = new AtomicReference<>();
        onEdt(() -> {
            BinaryEditorPanel editor = new BinaryEditorPanel();
            // "00ff" as hex is the two bytes 0x00 0xFF.
            editor.setBytes(new byte[] {0x00, (byte) 0xFF}, true);
            editor.selectMode(false);
            warning.set(editor.lossWarning());
            // Text mode cannot represent 0x00/0xFF, so it must not claim a
            // lossless round trip.
            result.set(editor.getBytes());
        });
        // The literal characters "00ff" would be 4 bytes; conversion must not
        // produce that.
        assertFalse(result.get().length == 4 && result.get()[0] == '0',
                "hex digits must not be reinterpreted as literal text");
        assertTrue(warning.get().contains("not valid UTF-8"),
                "expected a lossy warning, got: " + warning.get());
    }

    @Test
    void switchingTextToHexIsLossless() throws Exception {
        AtomicReference<byte[]> result = new AtomicReference<>();
        onEdt(() -> {
            BinaryEditorPanel editor = new BinaryEditorPanel();
            editor.setBytes("AB".getBytes(java.nio.charset.StandardCharsets.UTF_8), false);
            editor.selectMode(true);
            result.set(editor.getBytes());
        });
        assertArrayEquals(new byte[] {'A', 'B'}, result.get());
    }
}
