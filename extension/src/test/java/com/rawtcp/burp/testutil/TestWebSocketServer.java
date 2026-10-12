package com.rawtcp.burp.testutil;

import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.function.Consumer;

/**
 * Minimal RFC 6455 server for tests: performs the opening handshake and
 * exchanges unmasked server frames / masked client frames. It accepts
 * connections concurrently (one worker thread each) and is deliberately
 * message-per-frame — enough to drive {@code IpcClient} end to end without
 * pulling in a WebSocket library.
 */
public final class TestWebSocketServer implements Closeable {

    private static final String GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

    /** Server-side view of one connection. */
    public interface Session {
        /** Next binary message payload, or {@code null} after a close frame/EOF. */
        byte[] readBinary() throws IOException;

        void sendBinary(byte[] payload) throws IOException;

        /** Send one message split across continuation frames (opcode 0x2 then 0x0). */
        void sendFragmented(byte[]... chunks) throws IOException;

        void close() throws IOException;
    }

    private final ServerSocket serverSocket;
    private final Thread thread;
    private final List<Thread> workers = Collections.synchronizedList(new ArrayList<>());
    private final int receiveBufferBytes;

    /**
     * Counted down when the first TCP connection is accepted, before the
     * WebSocket upgrade completes. Lets a test synchronize on "the connect is
     * in flight" instead of sleeping.
     */
    public final CountDownLatch firstAccept = new CountDownLatch(1);

    public TestWebSocketServer(Consumer<Session> handler) throws IOException {
        this(handler, 0L, 0);
    }

    public TestWebSocketServer(Consumer<Session> handler, long handshakeDelayMillis) throws IOException {
        this(handler, handshakeDelayMillis, 0);
    }

    public TestWebSocketServer(
            Consumer<Session> handler, long handshakeDelayMillis, int receiveBufferBytes)
            throws IOException {
        this.receiveBufferBytes = receiveBufferBytes;
        this.serverSocket = new ServerSocket(0, 16, java.net.InetAddress.getLoopbackAddress());
        this.thread = new Thread(() -> serve(handler, handshakeDelayMillis), "test-ws-server");
        this.thread.setDaemon(true);
        this.thread.start();
    }

    public int port() {
        return serverSocket.getLocalPort();
    }

    private void serve(Consumer<Session> handler, long handshakeDelayMillis) {
        while (!serverSocket.isClosed()) {
            Socket socket;
            try {
                socket = serverSocket.accept();
            } catch (IOException stopped) {
                // Server socket closed by the test.
                return;
            }
            firstAccept.countDown();
            if (receiveBufferBytes > 0) {
                try {
                    socket.setReceiveBufferSize(receiveBufferBytes);
                } catch (java.net.SocketException ignored) {
                    // Best effort: the test only needs to encourage backpressure.
                }
            }
            Thread worker = new Thread(() -> {
                try (Socket accepted = socket) {
                    if (handshakeDelayMillis > 0) {
                        Thread.sleep(handshakeDelayMillis);
                    }
                    handshake(accepted);
                    handler.accept(new SocketSession(accepted));
                } catch (IOException | InterruptedException ended) {
                    // The connection ended, or the server is closing.
                }
            }, "test-ws-session");
            worker.setDaemon(true);
            workers.add(worker);
            worker.start();
        }
    }

    @Override
    public void close() throws IOException {
        serverSocket.close();
        thread.interrupt();
        synchronized (workers) {
            for (Thread worker : workers) {
                worker.interrupt();
            }
        }
    }

    private static void handshake(Socket socket) throws IOException {
        InputStream in = socket.getInputStream();
        OutputStream out = socket.getOutputStream();
        ByteArrayOutputStream headerBytes = new ByteArrayOutputStream();
        int matched = 0;
        byte[] terminator = {'\r', '\n', '\r', '\n'};
        int b;
        while ((b = in.read()) != -1) {
            headerBytes.write(b);
            matched = (b == terminator[matched]) ? matched + 1 : (b == terminator[0] ? 1 : 0);
            if (matched == terminator.length) {
                break;
            }
        }
        String headers = headerBytes.toString(StandardCharsets.US_ASCII);
        String key = null;
        for (String line : headers.split("\r\n")) {
            if (line.toLowerCase().startsWith("sec-websocket-key:")) {
                key = line.substring(line.indexOf(':') + 1).trim();
            }
        }
        if (key == null) {
            throw new IOException("missing Sec-WebSocket-Key");
        }
        String accept = Base64.getEncoder()
                .encodeToString(sha1((key + GUID).getBytes(StandardCharsets.US_ASCII)));
        String response = "HTTP/1.1 101 Switching Protocols\r\n"
                + "Upgrade: websocket\r\n"
                + "Connection: Upgrade\r\n"
                + "Sec-WebSocket-Accept: " + accept + "\r\n\r\n";
        out.write(response.getBytes(StandardCharsets.US_ASCII));
        out.flush();
    }

    private static byte[] sha1(byte[] input) {
        try {
            return MessageDigest.getInstance("SHA-1").digest(input);
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException(impossible);
        }
    }

    private static final class SocketSession implements Session {

        private final Socket socket;
        private final InputStream in;
        private final OutputStream out;

        SocketSession(Socket socket) throws IOException {
            this.socket = socket;
            this.in = socket.getInputStream();
            this.out = socket.getOutputStream();
        }

        @Override
        public byte[] readBinary() throws IOException {
            while (true) {
                int first = in.read();
                if (first == -1) {
                    return null;
                }
                int opcode = first & 0x0F;
                int second = in.read();
                if (second == -1) {
                    return null;
                }
                boolean masked = (second & 0x80) != 0;
                long length = second & 0x7F;
                if (length == 126) {
                    length = ((long) readByte() << 8) | readByte();
                } else if (length == 127) {
                    length = 0;
                    for (int i = 0; i < 8; i++) {
                        length = (length << 8) | readByte();
                    }
                }
                byte[] mask = new byte[4];
                if (masked) {
                    readFully(mask);
                }
                byte[] payload = new byte[(int) length];
                readFully(payload);
                if (masked) {
                    for (int i = 0; i < payload.length; i++) {
                        payload[i] ^= mask[i % 4];
                    }
                }
                if (opcode == 0x8) {
                    return null;
                }
                if (opcode == 0x2) {
                    return payload;
                }
                // Ignore ping/pong/text for the test harness.
            }
        }

        @Override
        public void sendBinary(byte[] payload) throws IOException {
            writeFrame(true, 0x2, payload);
        }

        @Override
        public void sendFragmented(byte[]... chunks) throws IOException {
            for (int i = 0; i < chunks.length; i++) {
                int opcode = i == 0 ? 0x2 : 0x0;
                writeFrame(i == chunks.length - 1, opcode, chunks[i]);
            }
        }

        @Override
        public void close() throws IOException {
            writeFrame(true, 0x8, new byte[0]);
            socket.close();
        }

        private void writeFrame(boolean fin, int opcode, byte[] payload) throws IOException {
            out.write((fin ? 0x80 : 0x00) | opcode);
            int length = payload.length;
            if (length < 126) {
                out.write(length);
            } else if (length < 65536) {
                out.write(126);
                out.write((length >>> 8) & 0xFF);
                out.write(length & 0xFF);
            } else {
                out.write(127);
                for (int i = 7; i >= 0; i--) {
                    out.write((int) (((long) length >>> (8 * i)) & 0xFF));
                }
            }
            out.write(payload);
            out.flush();
        }

        private int readByte() throws IOException {
            int value = in.read();
            if (value == -1) {
                throw new IOException("unexpected EOF");
            }
            return value;
        }

        private void readFully(byte[] target) throws IOException {
            int read = 0;
            while (read < target.length) {
                int n = in.read(target, read, target.length - read);
                if (n == -1) {
                    throw new IOException("unexpected EOF");
                }
                read += n;
            }
        }
    }
}
