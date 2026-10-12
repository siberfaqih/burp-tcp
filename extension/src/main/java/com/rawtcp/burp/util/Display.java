package com.rawtcp.burp.util;

import com.rawtcp.burp.ipc.proto.BurpTcp;

import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;

/** Small formatting helpers shared by the workspace panels. */
public final class Display {

    private Display() {}

    private static final DateTimeFormatter TIME =
            DateTimeFormatter.ofPattern("HH:mm:ss.SSS").withZone(ZoneId.systemDefault());

    /** First 8 characters of a UUID-ish id, or the whole id if shorter. */
    public static String shortId(String id) {
        if (id == null || id.isEmpty()) {
            return "";
        }
        return id.length() <= 8 ? id : id.substring(0, 8);
    }

    public static String direction(BurpTcp.Direction direction) {
        return switch (direction) {
            case CLIENT_TO_SERVER -> "To server";
            case SERVER_TO_CLIENT -> "To client";
            default -> "?";
        };
    }

    public static String preview(byte[] bytes) {
        int length = Math.min(bytes.length, 80);
        byte[] head = java.util.Arrays.copyOf(bytes, length);
        long printable = 0;
        for (byte b : head) if ((b & 255) >= 32 && (b & 255) < 127 || b == '\n' || b == '\r' || b == '\t') printable++;
        if (length > 0 && printable * 100 / length >= 80)
            return HexText.toPrintableText(head) + (length < bytes.length ? "…" : "");
        return HexText.preview(bytes, 16);
    }

    public static String connectionState(BurpTcp.ConnectionInfo info) {
        if (info.getClosed()) {
            return "closed";
        }
        if (info.getEstablished()) {
            return "established";
        }
        return "negotiating";
    }

    public static String time(long unixMillis) {
        if (unixMillis <= 0) {
            return "";
        }
        return TIME.format(Instant.ofEpochMilli(unixMillis));
    }
}
