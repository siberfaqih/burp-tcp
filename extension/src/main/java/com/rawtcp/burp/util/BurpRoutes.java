package com.rawtcp.burp.util;

import com.rawtcp.burp.ipc.proto.BurpTcp;

import java.net.InetAddress;

/**
 * Rule strings for Burp routing, shared by the route panel and its tests.
 *
 * <p>Format matches the engine {@code --burp-route} flag:
 * {@code HOST[:PORT]=>BURP_ADDR}, e.g. {@code 10.0.0.5:7007=>127.0.0.1:8081}.
 * A missing destination port means any port. {@code *} matches any host.
 */
public final class BurpRoutes {

    private BurpRoutes() {}

    /** Parse a rule string; throws {@link IllegalArgumentException} when invalid. */
    public static BurpTcp.BurpRoute parse(String rule) {
        if (rule == null) {
            throw new IllegalArgumentException("route must not be empty");
        }
        int arrow = rule.indexOf("=>");
        if (arrow < 0) {
            throw new IllegalArgumentException(
                    "invalid route (expected HOST[:PORT]=>BURP_ADDR): " + rule);
        }
        String left = rule.substring(0, arrow).trim();
        String right = rule.substring(arrow + 2).trim();
        if (left.isEmpty()) {
            throw new IllegalArgumentException("route destination must not be empty: " + rule);
        }
        String host;
        int port = 0;
        int colon = left.lastIndexOf(':');
        if (colon >= 0) {
            host = left.substring(0, colon).trim();
            String portRaw = left.substring(colon + 1).trim();
            if (host.isEmpty()) {
                throw new IllegalArgumentException("route host must not be empty: " + rule);
            }
            try {
                port = Integer.parseInt(portRaw);
            } catch (NumberFormatException invalid) {
                throw new IllegalArgumentException("route port is not a number: " + portRaw);
            }
            if (port < 1 || port > 65535) {
                throw new IllegalArgumentException("route port must be 1..65535: " + portRaw);
            }
        } else {
            host = left;
        }
        if (host.isEmpty()) {
            throw new IllegalArgumentException("route host must not be empty: " + rule);
        }
        checkBurpAddr(right);
        return BurpTcp.BurpRoute.newBuilder()
                .setHostPattern(host)
                .setPort(port)
                .setBurpAddr(right)
                .build();
    }

    /** Render a route in the same {@code HOST[:PORT]=>BURP_ADDR} format. */
    public static String format(BurpTcp.BurpRoute route) {
        String left = route.getPort() == 0
                ? route.getHostPattern()
                : route.getHostPattern() + ":" + route.getPort();
        return left + "=>" + route.getBurpAddr();
    }

    private static void checkBurpAddr(String addr) {
        if (addr == null || addr.isEmpty()) {
            throw new IllegalArgumentException("Burp listener address must not be empty");
        }
        int colon = addr.lastIndexOf(':');
        if (colon < 0) {
            throw new IllegalArgumentException(
                    "Burp listener address must be IP:port: " + addr);
        }
        String ip = addr.substring(0, colon);
        String portRaw = addr.substring(colon + 1);
        int port;
        try {
            port = Integer.parseInt(portRaw);
        } catch (NumberFormatException invalid) {
            throw new IllegalArgumentException("Burp listener port is not a number: " + portRaw);
        }
        if (port < 1 || port > 65535) {
            throw new IllegalArgumentException("Burp listener port must be 1..65535: " + portRaw);
        }
        try {
            InetAddress resolved = InetAddress.getByName(ip);
            if (!resolved.isLoopbackAddress()) {
                throw new IllegalArgumentException(
                        "Burp listener must be loopback: " + addr);
            }
        } catch (IllegalArgumentException error) {
            throw error;
        } catch (Exception error) {
            throw new IllegalArgumentException("Burp listener IP is invalid: " + ip);
        }
    }
}
