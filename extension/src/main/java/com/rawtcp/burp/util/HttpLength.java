package com.rawtcp.burp.util;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Consistency guard for complete HTTP/1.x messages held as a single unit.
 *
 * <p>A replace that changes the body without updating {@code Content-Length}
 * makes the server wait for bytes that never come (or read into the next
 * message), which surfaces downstream as a hung login or a closed connection
 * with no response bytes. This checker blocks that specific silent corruption
 * before it leaves the UI: when the <em>original</em> unit is one complete
 * {@code Content-Length} message and the <em>replacement</em> no longer
 * matches its declared length, forwarding is refused with exact numbers.
 *
 * <p>Partial units (one TCP chunk of a larger message), chunked or compressed
 * bodies, and non-HTTP payloads are left alone and return {@code null}: the
 * length-change warning on Forward covers those cases.
 */
public final class HttpLength {

    private HttpLength() {}

    /**
     * Validate a replacement against the original unit.
     *
     * @return an error describing the mismatch, or {@code null} when the
     *     replacement is safe to send from a framing perspective
     */
    public static String checkReplace(byte[] original, byte[] replacement) {
        Message before = parse(original);
        if (before == null || before.contentLengths.size() != 1 || before.framed) {
            return null;
        }
        if (original.length - before.headerEnd != before.contentLengths.get(0)) {
            return null; // Original itself is a fragment; nothing to protect.
        }
        Message after = parse(replacement);
        if (after == null) {
            return "Replacement is no longer one complete HTTP message "
                    + "(headers incomplete or not HTTP/1.x); original had Content-Length "
                    + before.contentLengths.get(0) + ". Restore the headers or edit via Body parameters.";
        }
        if (after.framed) {
            return null; // Chunked/compressed: length is not declared; warning covers it.
        }
        if (after.contentLengths.size() != 1) {
            return "Replacement must carry exactly one Content-Length header "
                    + "(original declared " + before.contentLengths.get(0) + ").";
        }
        long declared = after.contentLengths.get(0);
        long actual = replacement.length - after.headerEnd;
        if (declared != actual) {
            return "Content-Length says " + declared + " but the body is " + actual + " bytes. "
                    + "Fix the header or edit via Body parameters (which updates it automatically).";
        }
        return null;
    }

    private static final class Message {
        int headerEnd;
        List<Long> contentLengths = new ArrayList<>();
        boolean framed;
    }

    private static Message parse(byte[] bytes) {
        String eol = "\r\n";
        int end = indexOf(bytes, "\r\n\r\n");
        if (end < 0) {
            eol = "\n";
            end = indexOf(bytes, "\n\n");
        }
        if (end < 0) {
            return null;
        }
        end += eol.length() * 2;
        String headers = new String(bytes, 0, end, StandardCharsets.ISO_8859_1);
        String[] lines = headers.split(eol);
        if (lines.length == 0) {
            return null;
        }
        String first = lines[0];
        boolean request = first.matches("^[A-Z]+ [^\\r\\n]+ HTTP/1\\.[01]$");
        boolean response = first.matches("^HTTP/1\\.[01] [0-9]{3}( .*)?$");
        if (!request && !response) {
            return null;
        }
        Message message = new Message();
        message.headerEnd = end;
        for (int i = 1; i < lines.length; i++) {
            String line = lines[i];
            if (line.isEmpty()) {
                continue;
            }
            int colon = line.indexOf(':');
            if (colon < 0) {
                return null;
            }
            String name = line.substring(0, colon).trim().toLowerCase(Locale.ROOT);
            String value = line.substring(colon + 1).trim().toLowerCase(Locale.ROOT);
            if (name.equals("content-length")) {
                try {
                    message.contentLengths.add(Long.parseLong(value.split("\\s+")[0]));
                } catch (NumberFormatException invalid) {
                    return null;
                }
            } else if (name.equals("transfer-encoding") && !value.equals("identity")
                    || name.equals("content-encoding") && !value.equals("identity")) {
                message.framed = true;
            }
        }
        return message;
    }

    private static int indexOf(byte[] bytes, String marker) {
        byte[] needle = marker.getBytes(StandardCharsets.ISO_8859_1);
        for (int i = 0; i + needle.length <= bytes.length; i++) {
            boolean match = true;
            for (int j = 0; j < needle.length; j++) {
                if (bytes[i + j] != needle[j]) {
                    match = false;
                    break;
                }
            }
            if (match) {
                return i;
            }
        }
        return -1;
    }
}
