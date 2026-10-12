package com.rawtcp.burp.util;

import org.junit.jupiter.api.Test;
import java.nio.charset.StandardCharsets;
import static org.junit.jupiter.api.Assertions.*;

class FormBodyTest {
    private static byte[] bytes(String text) { return text.getBytes(StandardCharsets.UTF_8); }
    private static String text(byte[] bytes) { return new String(bytes, StandardCharsets.UTF_8); }

    @Test void viewingPreservesEscapesDuplicatesFlagsAndEmptyFieldsExactly() {
        String wire = "a=one+two&a=%2f%252F&empty=&flag&&=value&";
        FormBody form = FormBody.parse(bytes(wire));
        assertEquals("one two", form.fields().get(0).value());
        assertEquals("/%2F", form.fields().get(1).value());
        assertEquals("a", form.fields().get(1).name());
        assertArrayEquals(bytes(wire), form.bytes());
        assertArrayEquals(bytes(wire), form.edit(1, "a", "/%2F").bytes());
    }

    @Test void editingOneDuplicateEncodesOnlyThatFieldAndPreservesSpaceStyle() {
        FormBody form = FormBody.parse(bytes("q=hello%20world&q=%2f&token=a+b%2Bc"));
        String result = text(form.edit(0, "q", "A B&x=+%é").bytes());
        assertEquals("q=A%20B%26x%3D%2B%25%C3%A9&q=%2f&token=a+b%2Bc", result);
        FormBody decoded = FormBody.parse(bytes(result));
        assertEquals("A B&x=+%é", decoded.fields().getFirst().value());
        assertEquals("a b+c", decoded.fields().get(2).value());
    }

    @Test void completeHttpBodyUpdatesByteLengthAndPreservesOtherHeaders() {
        String body = "name=Ali&untouched=%2f";
        String headers = "POST /test HTTP/1.1\r\nHost: localhost\r\n"
                + "Content-Type: application/x-www-form-urlencoded; charset=UTF-8\r\n"
                + "content-length:  " + bytes(body).length + "\r\nX-Test: keep\r\n\r\n";
        FormBody form = FormBody.parse(bytes(headers + body));
        assertArrayEquals(bytes(headers + body), form.bytes());
        String edited = "name=%E2%9C%93+ok&untouched=%2f";
        assertEquals(headers.replace("  " + bytes(body).length, "  " + bytes(edited).length) + edited,
                text(form.edit(0, "name", "✓ ok").bytes()));
    }

    @Test void rejectsAmbiguousPartialChunkedAndInvalidEncodedBodies() {
        String header = "POST / HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\n";
        for (String wire : new String[] {
                header + "Content-Length: 99\r\n\r\nx=1",
                header + "Content-Length: 3\r\n\r\nx=1extra",
                header + "Transfer-Encoding: chunked\r\nContent-Length: 3\r\n\r\nx=1",
                header + "Content-Length: 3\r\nContent-Length: invalid\r\n\r\nx=1",
                "x=%FF", "x=%", "x=%GG", "{\"x\": \"a=b\"}"
        }) assertThrows(IllegalArgumentException.class, () -> FormBody.parse(bytes(wire)), wire);
    }

    @Test void rejectsNonAsciiAndUnicodeNamesAsForm() {
        // Proper form encoding is ASCII-only; raw UTF-8 bytes must stay in the raw editor.
        assertThrows(IllegalArgumentException.class,
                () -> FormBody.parse(bytes("name=caf\u00e9")));
        assertThrows(IllegalArgumentException.class,
                () -> FormBody.parse("naïve=value".getBytes(StandardCharsets.UTF_8)));
    }

    @Test void lfOnlyHttpRequestParsesAndKeepsLfOnEdit() {
        String body = "name=Ali&token=%2f";
        String wire = "POST /login HTTP/1.1\nHost: localhost\n"
                + "Content-Type: application/x-www-form-urlencoded\n"
                + "Content-Length:  " + bytes(body).length + "\n\n" + body;
        FormBody form = FormBody.parse(bytes(wire));
        assertEquals("Ali", form.fields().get(0).value());
        assertArrayEquals(bytes(wire), form.bytes());
        String edited = text(form.edit(0, "name", "Budi & Co").bytes());
        assertTrue(edited.contains("Content-Length:  " + bytes("name=Budi+%26+Co&token=%2f").length),
                edited);
        assertTrue(!edited.contains("\r"), "LF style request must stay LF, got: " + edited);
        assertEquals("Budi & Co", FormBody.parse(bytes(edited)).fields().get(0).value());
    }

    @Test void bareFormWithTrailingNewlineKeepsItLosslessly() {
        String wire = "a=one+two&b=%2f\n";
        FormBody form = FormBody.parse(bytes(wire));
        assertEquals("one two", form.fields().get(0).value());
        assertArrayEquals(bytes(wire), form.bytes());
        String edited = text(form.edit(1, "b", "/%2F").bytes());
        assertEquals("a=one+two&b=%2F%252F\n", edited);
    }

    @Test void damagedLineEndingFallsBackToNormalizedView() {
        // One Delete keystroke eating the CR of a CRLF pair leaves \n\r\n.
        String damaged = "POST /x HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length:  3\n\r\na=1";
        FormBody form = FormBody.parse(bytes(damaged));
        assertTrue(form.isNormalized());
        assertEquals("1", form.fields().get(0).value());
        // An edit from the normalized view rebuilds clean LF bytes.
        assertEquals("POST /x HTTP/1.1\nContent-Type: application/x-www-form-urlencoded\nContent-Length:  3\n\na=2",
                text(form.edit(0, "a", "2").bytes()));
        assertFalse(FormBody.parse(bytes("POST /x HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length:  3\r\n\r\na=1")).isNormalized());
    }

    @Test void genuinelyBrokenMessagesStillReportTheOriginalError() {
        // Truncated headers with no recoverable structure: strict error stands.
        IllegalArgumentException error = assertThrows(IllegalArgumentException.class,
                () -> FormBody.parse(bytes("POST /x HTTP/1.1\r\nHost: h")));
        assertTrue(error.getMessage().contains("no blank line"), error.getMessage());
        // Stale length on clean endings is not a line-ending problem.
        IllegalArgumentException stale = assertThrows(IllegalArgumentException.class,
                () -> FormBody.parse(bytes("POST /x HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length:  99\r\n\r\na=1")));
        assertTrue(stale.getMessage().contains("Partial or multiple"), stale.getMessage());
    }

    @Test void urlToolsDecodeExactlyOneLayerAndDistinguishPlusFromSpace() {
        assertEquals("%2F+ test", UrlCodec.decode("%252F%2B+test", true));
        assertEquals("a+b", UrlCodec.decode("a+b", false));
        assertEquals("%2B+%26%3D%25%C3%A9", UrlCodec.encode("+ &=%é", true));
        assertEquals("a%20b%2Bc", UrlCodec.encode("a b+c", false));
        for (String bad : new String[] {"%", "%A", "%GG", "%FF", "%C0%AF", "%ＦＦ"})
            assertThrows(IllegalArgumentException.class, () -> UrlCodec.decode(bad, true));
        assertThrows(IllegalArgumentException.class, () -> UrlCodec.encode("\uD800", true));
    }
}
