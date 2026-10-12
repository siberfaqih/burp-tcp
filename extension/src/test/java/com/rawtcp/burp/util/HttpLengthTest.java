package com.rawtcp.burp.util;

import org.junit.jupiter.api.Test;
import java.nio.charset.StandardCharsets;
import static org.junit.jupiter.api.Assertions.*;

class HttpLengthTest {
    private static byte[] bytes(String text) { return text.getBytes(StandardCharsets.UTF_8); }

    private static String post(int length, String body) {
        return "POST /login HTTP/1.1\r\nHost: x\r\nContent-Length:  " + length + "\r\n\r\n" + body;
    }

    @Test void unchangedCompleteMessagePasses() {
        byte[] original = bytes(post(11, "hello world".substring(0, 11)));
        assertNull(HttpLength.checkReplace(original, original.clone()));
    }

    @Test void fixedLengthAfterEditPasses() {
        byte[] original = bytes(post(3, "a=1"));
        byte[] fixed = bytes(post(7, "a=1&b=2"));
        assertNull(HttpLength.checkReplace(original, fixed));
    }

    @Test void staleLengthAfterTextEditIsBlocked() {
        byte[] original = bytes(post(3, "a=1"));
        byte[] broken = bytes(post(3, "a=1&b=2"));
        String error = HttpLength.checkReplace(original, broken);
        assertNotNull(error);
        assertTrue(error.contains("Content-Length says 3 but the body is 7 bytes"), error);
    }

    @Test void destroyedHeadersAreBlocked() {
        byte[] original = bytes(post(3, "a=1"));
        String error = HttpLength.checkReplace(original, bytes("a=1&b=2"));
        assertNotNull(error);
        assertTrue(error.contains("no longer one complete HTTP message"), error);
    }

    @Test void partialChunkIsLeftAlone() {
        // No header terminator: a fragment of a larger message, not ours to judge.
        assertNull(HttpLength.checkReplace(bytes("a=1"), bytes("a=1&b=2")));
        // Original itself incomplete (declared 99, only 3 present): fragment path.
        assertNull(HttpLength.checkReplace(bytes(post(99, "a=1")), bytes(post(99, "a=1&b=2"))));
    }

    @Test void chunkedBodyIsLeftAlone() {
        String wire = "POST /x HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n";
        assertNull(HttpLength.checkReplace(bytes(wire), bytes(wire + "x")));
    }

    @Test void nonHttpBinaryIsLeftAlone() {
        byte[] original = {0x12, 0x01, 0x00, 0x2c, 0x00, 0x00, 0x01};
        byte[] changed = {0x12, 0x01, 0x00, 0x2d, 0x00, 0x00, 0x01, 0x02};
        assertNull(HttpLength.checkReplace(original, changed));
    }

    @Test void lfOnlyStaleLengthIsBlockedAndFixedLengthPasses() {
        String original = "POST /login HTTP/1.1\nContent-Length: 3\n\na=1";
        String broken = "POST /login HTTP/1.1\nContent-Length: 3\n\na=1&b=2";
        String error = HttpLength.checkReplace(bytes(original), bytes(broken));
        assertNotNull(error);
        assertTrue(error.contains("Content-Length says 3 but the body is 7 bytes"), error);
        String fixed = "POST /login HTTP/1.1\nContent-Length: 7\n\na=1&b=2";
        assertNull(HttpLength.checkReplace(bytes(original), bytes(fixed)));
    }

    @Test void fixContentLengthCorrectsStaleDeclarations() {
        assertEquals("POST /x HTTP/1.1\r\nContent-Length:  7\r\n\r\na=1&b=2",
                new String(HttpLength.fixContentLength(bytes("POST /x HTTP/1.1\r\nContent-Length:  3\r\n\r\na=1&b=2")),
                        StandardCharsets.UTF_8));
        assertEquals("POST /x HTTP/1.1\nContent-Length: 7\n\na=1&b=2",
                new String(HttpLength.fixContentLength(bytes("POST /x HTTP/1.1\nContent-Length: 3\n\na=1&b=2")),
                        StandardCharsets.UTF_8));
    }

    @Test void fixContentLengthLeavesEverythingElseAlone() {
        // Already consistent.
        assertNull(HttpLength.fixContentLength(bytes("POST /x HTTP/1.1\r\nContent-Length:  3\r\n\r\na=1")));
        // Chunked, multi-message-shaped, and non-HTTP bytes are never rewritten.
        assertNull(HttpLength.fixContentLength(
                bytes("POST /x HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n")));
        assertNull(HttpLength.fixContentLength(bytes("a=1&b=2")));
        assertNull(HttpLength.fixContentLength(new byte[] {0x12, 0x01, 0x00}));
    }
}
