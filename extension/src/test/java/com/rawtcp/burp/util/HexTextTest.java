package com.rawtcp.burp.util;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class HexTextTest {

    @Test
    void hexRoundTripsArbitraryBytes() {
        byte[] bytes = new byte[256];
        for (int i = 0; i < 256; i++) {
            bytes[i] = (byte) i;
        }
        assertArrayEquals(bytes, HexText.fromHex(HexText.toHex(bytes)));
    }

    @Test
    void fromHexIgnoresWhitespaceAndPrefix() {
        assertArrayEquals(new byte[] {0x00, (byte) 0xFF, 0x10},
                HexText.fromHex("0x00 ff\n10"));
    }

    @Test
    void fromHexRejectsOddDigitCount() {
        assertThrows(IllegalArgumentException.class, () -> HexText.fromHex("abc"));
    }

    @Test
    void fromHexRejectsNonHexCharacters() {
        assertThrows(IllegalArgumentException.class, () -> HexText.fromHex("zz"));
    }

    @Test
    void printableTextReplacesNonPrintableWithDot() {
        assertEquals("A.B", HexText.toPrintableText(new byte[] {'A', 0x00, 'B'}));
    }

    @Test
    void hexDumpShowsOffsetAndAscii() {
        String dump = HexText.toHexDump(new byte[] {'A', 'B'});
        assertTrue(dump.startsWith("00000000  41 42"), "unexpected dump: " + dump);
        assertTrue(dump.contains("|AB|"), "unexpected dump: " + dump);
    }

    @Test
    void previewTruncatesAndReportsRemainder() {
        String preview = HexText.preview(new byte[] {1, 2, 3, 4, 5}, 2);
        assertTrue(preview.startsWith("01 02"), "unexpected preview: " + preview);
        assertTrue(preview.contains("+3 B"), "unexpected preview: " + preview);
    }
}
