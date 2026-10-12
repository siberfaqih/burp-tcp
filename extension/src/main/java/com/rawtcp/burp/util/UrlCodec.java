package com.rawtcp.burp.util;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;

/** One-layer percent encoding. Malformed escapes/UTF-8 are never silently replaced. */
public final class UrlCodec {
    private UrlCodec() {}

    public static byte[] utf8(String text) {
        try {
            ByteBuffer buffer = StandardCharsets.UTF_8.newEncoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT).encode(CharBuffer.wrap(text));
            byte[] bytes = new byte[buffer.remaining()];
            buffer.get(bytes);
            return bytes;
        } catch (CharacterCodingException error) {
            throw new IllegalArgumentException("Text contains an incomplete Unicode character");
        }
    }

    public static String text(byte[] bytes) {
        try {
            return StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes)).toString();
        } catch (CharacterCodingException error) {
            throw new IllegalArgumentException("Bytes are not valid UTF-8");
        }
    }

    public static String encode(String text, boolean form) {
        StringBuilder out = new StringBuilder();
        for (byte b : utf8(text)) {
            int c = b & 255;
            if (c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
                    || c == '-' || c == '_' || c == '.' || c == (form ? '*' : '~')) out.append((char) c);
            else if (c == ' ' && form) out.append('+');
            else out.append('%').append("0123456789ABCDEF".charAt(c >> 4))
                    .append("0123456789ABCDEF".charAt(c & 15));
        }
        return out.toString();
    }

    public static String decode(String text, boolean form) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (int i = 0; i < text.length();) {
            char c = text.charAt(i);
            if (c == '%') {
                if (i + 2 >= text.length()) throw new IllegalArgumentException("Incomplete % escape");
                int hi = Character.digit(text.charAt(i + 1), 16);
                int lo = Character.digit(text.charAt(i + 2), 16);
                if (hi < 0 || lo < 0 || text.charAt(i + 1) > 127 || text.charAt(i + 2) > 127)
                    throw new IllegalArgumentException("Invalid % escape at " + i);
                out.write(hi * 16 + lo);
                i += 3;
            } else if (c == '+' && form) {
                out.write(' ');
                i++;
            } else {
                int end = i + 1;
                while (end < text.length() && text.charAt(end) != '%' && !(form && text.charAt(end) == '+')) end++;
                out.writeBytes(utf8(text.substring(i, end)));
                i = end;
            }
        }
        return text(out.toByteArray());
    }
}
