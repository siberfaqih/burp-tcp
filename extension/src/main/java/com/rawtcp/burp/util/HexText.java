package com.rawtcp.burp.util;

import java.util.Locale;

/**
 * Binary-safe hex/text rendering for the Raw TCP workspace.
 *
 * <p>TCP payloads are arbitrary bytes, never text. Rendering always goes
 * through this class so no lossy {@code String} conversion can silently
 * mutate a payload. Hex is the authoritative representation; the text
 * view is a lossy convenience that replaces every non-printable byte with
 * {@code '.'}.
 */
public final class HexText {

    private HexText() {}

    private static final char[] HEX = "0123456789abcdef".toCharArray();

    /** Lower-case hex, no separators. Empty input yields an empty string. */
    public static String toHex(byte[] bytes) {
        char[] out = new char[bytes.length * 2];
        for (int i = 0; i < bytes.length; i++) {
            int v = bytes[i] & 0xFF;
            out[i * 2] = HEX[v >>> 4];
            out[i * 2 + 1] = HEX[v & 0x0F];
        }
        return new String(out);
    }

    /**
     * Classic offset / hex / ASCII dump, 16 bytes per row. Printable
     * bytes (0x20..0x7E) appear literally in the ASCII column; all others
     * become {@code '.'}. The hex column is authoritative.
     */
    public static String toHexDump(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (int offset = 0; offset < bytes.length; offset += 16) {
            int rowLen = Math.min(16, bytes.length - offset);
            sb.append(String.format(Locale.ROOT, "%08x  ", offset));
            StringBuilder ascii = new StringBuilder(16);
            for (int i = 0; i < 16; i++) {
                if (i < rowLen) {
                    int v = bytes[offset + i] & 0xFF;
                    sb.append(HEX[v >>> 4]).append(HEX[v & 0x0F]).append(' ');
                    ascii.append(v >= 0x20 && v <= 0x7E ? (char) v : '.');
                } else {
                    sb.append("   ");
                }
                if (i == 7) {
                    sb.append(' ');
                }
            }
            sb.append(" |").append(ascii).append('|').append('\n');
        }
        return sb.toString();
    }

    /** Printable-only view; every non-printable byte becomes {@code '.'}. */
    public static String toPrintableText(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length);
        for (byte b : bytes) {
            int v = b & 0xFF;
            sb.append(v >= 0x20 && v <= 0x7E ? (char) v : '.');
        }
        return sb.toString();
    }

    /**
     * Parse hex, ignoring all whitespace and an optional {@code 0x} prefix.
     *
     * @throws IllegalArgumentException if any non-hex character is present
     *     or the digit count is odd.
     */
    public static byte[] fromHex(String text) {
        String cleaned = text.replaceAll("\\s+", "");
        if (cleaned.startsWith("0x") || cleaned.startsWith("0X")) {
            cleaned = cleaned.substring(2);
        }
        if (cleaned.length() % 2 != 0) {
            throw new IllegalArgumentException("hex input has an odd number of digits");
        }
        byte[] out = new byte[cleaned.length() / 2];
        for (int i = 0; i < out.length; i++) {
            int hi = Character.digit(cleaned.charAt(i * 2), 16);
            int lo = Character.digit(cleaned.charAt(i * 2 + 1), 16);
            if (hi < 0 || lo < 0) {
                throw new IllegalArgumentException(
                        "invalid hex digit at position " + (i * 2));
            }
            out[i] = (byte) ((hi << 4) | lo);
        }
        return out;
    }

    /** Short one-line preview for tables: {@code 0a 0b 0c ...}. */
    public static String preview(byte[] bytes, int maxBytes) {
        int n = Math.min(maxBytes, bytes.length);
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < n; i++) {
            if (i > 0) {
                sb.append(' ');
            }
            int v = bytes[i] & 0xFF;
            sb.append(HEX[v >>> 4]).append(HEX[v & 0x0F]);
        }
        if (bytes.length > n) {
            sb.append(" … (+").append(bytes.length - n).append(" B)");
        }
        return sb.toString();
    }
}
