package com.rawtcp.burp.util;

import com.rawtcp.burp.ipc.proto.BurpTcp;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/** Rule-string parsing for Burp routing, mirroring the engine CLI format. */
class BurpRoutesTest {

    @Test
    void parsesFullRule() {
        BurpTcp.BurpRoute route = BurpRoutes.parse("10.0.0.5:7007=>127.0.0.1:8081");
        assertEquals("10.0.0.5", route.getHostPattern());
        assertEquals(7007, route.getPort());
        assertEquals("127.0.0.1:8081", route.getBurpAddr());
    }

    @Test
    void missingPortMeansAnyPort() {
        BurpTcp.BurpRoute route = BurpRoutes.parse("example.com=>127.0.0.1:8080");
        assertEquals("example.com", route.getHostPattern());
        assertEquals(0, route.getPort());
    }

    @Test
    void wildcardHostIsAccepted() {
        BurpTcp.BurpRoute route = BurpRoutes.parse("*=>127.0.0.1:8080");
        assertEquals("*", route.getHostPattern());
    }

    @Test
    void rejectsMalformedRules() {
        assertThrows(IllegalArgumentException.class, () -> BurpRoutes.parse(""));
        assertThrows(IllegalArgumentException.class, () -> BurpRoutes.parse("no-arrow-here"));
        assertThrows(IllegalArgumentException.class, () -> BurpRoutes.parse("=>127.0.0.1:8080"));
        assertThrows(IllegalArgumentException.class, () -> BurpRoutes.parse("host:notaport=>127.0.0.1:8080"));
        assertThrows(IllegalArgumentException.class, () -> BurpRoutes.parse("host:0=>127.0.0.1:8080"));
    }

    @Test
    void rejectsNonLoopbackBurpListener() {
        assertThrows(
                IllegalArgumentException.class, () -> BurpRoutes.parse("*=>192.168.1.1:8080"));
    }

    @Test
    void formatRoundTrips() {
        BurpTcp.BurpRoute route = BurpRoutes.parse("10.0.0.5:7007=>127.0.0.1:8081");
        assertEquals("10.0.0.5:7007=>127.0.0.1:8081", BurpRoutes.format(route));
        BurpTcp.BurpRoute anyPort = BurpRoutes.parse("example.com=>127.0.0.1:8080");
        assertEquals("example.com=>127.0.0.1:8080", BurpRoutes.format(anyPort));
    }
}
