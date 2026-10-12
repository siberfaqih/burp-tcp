package com.rawtcp.burp.ipc.proto;

import com.google.protobuf.ByteString;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Golden wire-format tests. The byte sequences asserted here are identical
 * to those in the Rust engine's {@code ipc::proto::tests} module, so the two
 * implementations are pinned to the same encoding. A change to
 * {@code proto/burp_tcp.proto} that alters tags or oneof layout fails on
 * both sides.
 */
class WireFormatTest {

    @Test
    void helloWireFormatIsStable() {
        BurpTcp.Hello hello = BurpTcp.Hello.newBuilder()
                .setProtocolVersion(1)
                .setCapabilityToken("abc")
                .build();
        byte[] expected = {0x08, 0x01, 0x22, 0x03, 'a', 'b', 'c'};
        assertArrayEquals(expected, hello.toByteArray());
    }

    @Test
    void requestWireFormatIsStable() {
        BurpTcp.Request request = BurpTcp.Request.newBuilder()
                .setRequestId(7)
                .setHello(BurpTcp.Hello.newBuilder()
                        .setProtocolVersion(1)
                        .setCapabilityToken("abc"))
                .build();
        byte[] expected = {
                0x08, 0x07,
                0x12, 0x07,
                0x08, 0x01, 0x22, 0x03, 'a', 'b', 'c',
        };
        assertArrayEquals(expected, request.toByteArray());
    }

    @Test
    void clientMessageWireFormatIsStable() {
        BurpTcp.ClientMessage message = BurpTcp.ClientMessage.newBuilder()
                .setRequest(BurpTcp.Request.newBuilder()
                        .setRequestId(7)
                        .setHello(BurpTcp.Hello.newBuilder()
                                .setProtocolVersion(1)
                                .setCapabilityToken("abc")))
                .build();
        byte[] expected = {
                0x0A, 0x0B,
                0x08, 0x07,
                0x12, 0x07,
                0x08, 0x01, 0x22, 0x03, 'a', 'b', 'c',
        };
        assertArrayEquals(expected, message.toByteArray());
    }

    @Test
    void serverMessageWireFormatIsStable() {
        BurpTcp.ServerMessage message = BurpTcp.ServerMessage.newBuilder()
                .setResponse(BurpTcp.Response.newBuilder()
                        .setRequestId(7)
                        .setHelloAck(BurpTcp.HelloAck.newBuilder().setProtocolVersion(1)))
                .build();
        byte[] expected = {
                0x0A, 0x06,
                0x08, 0x07,
                0x12, 0x02,
                0x08, 0x01,
        };
        assertArrayEquals(expected, message.toByteArray());
    }

    @Test
    void repeaterSendWireFormatIsStable() {
        BurpTcp.RepeaterSend send = BurpTcp.RepeaterSend.newBuilder()
                .setDestinationHost("h")
                .setDestinationPort(7)
                .setPayload(ByteString.copyFrom(new byte[] {0x01}))
                .setResponseByteLimit(2)
                .setTimeoutMs(3)
                .setCompletion(BurpTcp.RepeaterCompletion.READ_EXACT_BYTES)
                .setIdleTimeoutMs(4)
                .build();
        byte[] expected = {
                0x0A, 0x01, 'h',
                0x10, 0x07,
                0x1A, 0x01, 0x01,
                0x20, 0x02,
                0x28, 0x03,
                0x30, 0x02,
                0x38, 0x04,
        };
        assertArrayEquals(expected, send.toByteArray());
    }

    @Test
    void decideRoundTripsThroughBytes() throws Exception {
        BurpTcp.ClientMessage original = BurpTcp.ClientMessage.newBuilder()
                .setRequest(BurpTcp.Request.newBuilder()
                        .setRequestId(42)
                        .setDecide(BurpTcp.Decide.newBuilder()
                                .setUnitId("unit-1")
                                .setRevision(0)
                                .setAction(BurpTcp.InterceptActionKind.REPLACE)
                                .setReplaceBytes(ByteString.copyFrom(new byte[] {0x00, (byte) 0xFF, 0x10}))))
                .build();
        byte[] bytes = original.toByteArray();
        assertEquals(original, BurpTcp.ClientMessage.parseFrom(bytes));
    }
}
