//! Phase 4A integration tests: authenticated localhost IPC.
//!
//! Each test spawns a relay with IPC enabled, connects a real WebSocket
//! client speaking the protobuf protocol, and exercises the RPCs and
//! event stream end to end. The backpressure gate is covered by a test
//! that freezes a client and proves the relay keeps forwarding.

use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use prost::Message as ProstMessage;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::{tungstenite::Message as WsMessage, WebSocketStream};

use rawtcp_engine::ipc::proto::{
    self, ClientMessage, Decide, GetStats, Hello, HistorySnapshot, ListConnections, PendingUnits,
    Request, RequestBody, ServerMessage, ServerMessageBody, SetEnabled,
};
use rawtcp_engine::ipc::PROTOCOL_VERSION;
use rawtcp_engine::telemetry::memory_telemetry;
use rawtcp_engine::{spawn_relay_with, RelayConfig};

use testlab::socks_client::{self, Destination, GreetingStyle, RequestStyle};

/// Connect a WebSocket client to the IPC server.
async fn ws_connect(addr: std::net::SocketAddr) -> WebSocketStream<TcpStream> {
    let tcp = TcpStream::connect(addr).await.expect("tcp connect");
    let request = format!("ws://{addr}/")
        .into_client_request()
        .expect("build ws request");
    let (ws, _response) = tokio_tungstenite::client_async(request, tcp)
        .await
        .expect("ws handshake");
    ws
}

/// Connect, send Hello, and await HelloAck. Returns the stream ready for RPCs.
async fn connect_and_handshake(
    addr: std::net::SocketAddr,
    token: &str,
) -> WebSocketStream<TcpStream> {
    let mut ws = ws_connect(addr).await;

    // Send Hello.
    let hello = ClientMessage {
        request: Some(Request {
            request_id: 1,
            body: Some(RequestBody::Hello(Hello {
                protocol_version: PROTOCOL_VERSION,
                client_name: "phase4a-test".into(),
                client_version: "0.1".into(),
                capability_token: token.into(),
            })),
        }),
    };
    let mut buf = Vec::new();
    hello.encode(&mut buf).unwrap();
    ws.send(WsMessage::Binary(buf)).await.expect("send hello");

    // Receive HelloAck.
    let frame = ws.next().await.expect("ack frame").expect("ws read");
    let bytes = match frame {
        WsMessage::Binary(b) => b,
        _ => panic!("expected binary HelloAck, got {frame:?}"),
    };
    let msg = ServerMessage::decode(&bytes[..]).expect("decode ack");
    match msg.body {
        Some(ServerMessageBody::Response(resp)) => {
            assert_eq!(resp.request_id, 1);
            match resp.body {
                Some(proto::ResponseBody::HelloAck(ack)) => {
                    assert_eq!(ack.protocol_version, PROTOCOL_VERSION);
                    assert!(!ack.daemon_epoch.is_empty());
                    assert!(
                        !ack.socks_addr.is_empty(),
                        "HelloAck must name the SOCKS endpoint for setup"
                    );
                }
                other => panic!("expected HelloAck, got {other:?}"),
            }
        }
        other => panic!("expected Response, got {other:?}"),
    }
    ws
}

/// Send a request and await the matching response, skipping events.
async fn rpc(
    ws: &mut WebSocketStream<TcpStream>,
    request_id: u32,
    body: RequestBody,
) -> proto::Response {
    tokio::time::timeout(Duration::from_secs(10), rpc_inner(ws, request_id, body))
        .await
        .expect("IPC response deadline")
}

async fn rpc_inner(
    ws: &mut WebSocketStream<TcpStream>,
    request_id: u32,
    body: RequestBody,
) -> proto::Response {
    let msg = ClientMessage {
        request: Some(Request {
            request_id,
            body: Some(body),
        }),
    };
    let mut buf = Vec::new();
    msg.encode(&mut buf).unwrap();
    ws.send(WsMessage::Binary(buf)).await.expect("send rpc");

    loop {
        let frame = ws.next().await.expect("frame").expect("ws read");
        let bytes = match frame {
            WsMessage::Binary(b) => b,
            WsMessage::Ping(_) => continue,
            _ => panic!("expected binary, got {frame:?}"),
        };
        let msg = ServerMessage::decode(&bytes[..]).expect("decode");
        match msg.body {
            Some(ServerMessageBody::Response(resp)) if resp.request_id == request_id => {
                return resp;
            }
            Some(ServerMessageBody::Event(_)) => continue,
            other => panic!("unexpected server message: {other:?}"),
        }
    }
}

async fn wait_for_unit(
    ws: &mut WebSocketStream<TcpStream>,
    direction: i32,
) -> proto::PendingUnitInfo {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let response = rpc(ws, 20, RequestBody::PendingUnits(PendingUnits {})).await;
            if let Some(proto::ResponseBody::PendingList(list)) = response.body {
                if let Some(unit) = list
                    .units
                    .into_iter()
                    .find(|unit| unit.direction == direction)
                {
                    return unit;
                }
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("intercepted unit must become visible")
}

#[tokio::test]
async fn repeated_direction_toggles_and_controller_reconnect_keep_same_tcp_session_usable() {
    let harness = IpcHarness::start().await;
    let echo = testlab::echo_server().await;
    let mut ws = connect_and_handshake(harness.ipc_addr, &harness.token).await;
    let mut stream = socks_client::connect_through_proxy(
        harness.relay.local_addr(),
        Destination::Ip(echo.addr().ip()),
        echo.addr().port(),
        GreetingStyle::Single,
        RequestStyle::Single,
    )
    .await
    .expect("SOCKS connect");

    for round in 0..12u8 {
        let direction = i32::from(round % 2) + 1;
        rpc(
            &mut ws,
            2,
            RequestBody::SetEnabled(SetEnabled {
                direction,
                enabled: true,
            }),
        )
        .await;
        let payload = [round, 0, 0xff, b'X'];
        stream.write_all(&payload).await.unwrap();
        let unit = wait_for_unit(&mut ws, direction).await;
        assert_eq!(unit.bytes, payload);
        let mut echoed = [0u8; 4];
        assert!(
            tokio::time::timeout(Duration::from_millis(20), stream.read_exact(&mut echoed))
                .await
                .is_err(),
            "bytes must stay held until disable"
        );
        rpc(
            &mut ws,
            3,
            RequestBody::SetEnabled(SetEnabled {
                direction,
                enabled: false,
            }),
        )
        .await;
        tokio::time::timeout(Duration::from_secs(2), stream.read_exact(&mut echoed))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(echoed, payload);
        // History queries share this same control channel throughout toggling.
        let response = rpc(
            &mut ws,
            4,
            RequestBody::HistorySnapshot(HistorySnapshot {
                conn_id: unit.conn_id,
                direction,
                max_chunks: 1,
            }),
        )
        .await;
        match response.body {
            Some(proto::ResponseBody::HistoryData(data)) => {
                assert_eq!(data.chunks.last().unwrap().bytes, payload)
            }
            other => panic!("history response: {other:?}"),
        }
    }

    rpc(
        &mut ws,
        5,
        RequestBody::SetEnabled(SetEnabled {
            direction: 1,
            enabled: true,
        }),
    )
    .await;
    stream.write_all(b"held").await.unwrap();
    wait_for_unit(&mut ws, 1).await;
    drop(ws);
    let mut echoed = [0u8; 4];
    tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut echoed))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        &echoed, b"held",
        "controller loss must release pending bytes"
    );
    let mut ws = connect_and_handshake(harness.ipc_addr, &harness.token).await;
    let response = rpc(&mut ws, 6, RequestBody::GetStats(GetStats {})).await;
    match response.body {
        Some(proto::ResponseBody::Stats(stats)) => {
            assert!(!stats.c2s_enabled && !stats.s2c_enabled);
            assert_eq!(stats.accepted_connections, 1);
        }
        other => panic!("stats response: {other:?}"),
    }
    rpc(
        &mut ws,
        7,
        RequestBody::SetEnabled(SetEnabled {
            direction: 1,
            enabled: true,
        }),
    )
    .await;
    stream.write_all(b"back").await.unwrap();
    let unit = wait_for_unit(&mut ws, 1).await;
    assert_eq!(unit.bytes, b"back");
    rpc(
        &mut ws,
        8,
        RequestBody::Decide(Decide {
            unit_id: unit.unit_id,
            revision: unit.revision,
            action: 1,
            replace_bytes: Vec::new(),
        }),
    )
    .await;
    tokio::time::timeout(Duration::from_secs(2), stream.read_exact(&mut echoed))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&echoed, b"back");
    harness.relay.shutdown().await;
    echo.shutdown().await;
}

#[tokio::test]
async fn live_counters_survive_history_eviction_and_snapshots_obey_byte_budget() {
    let harness = IpcHarness::start().await;
    let echo = testlab::echo_server().await;
    let mut ws = connect_and_handshake(harness.ipc_addr, &harness.token).await;
    let mut stream = socks_client::connect_through_proxy(
        harness.relay.local_addr(),
        Destination::Ip(echo.addr().ip()),
        echo.addr().port(),
        GreetingStyle::Single,
        RequestStyle::Single,
    )
    .await
    .unwrap();
    let payload = vec![0xab; 32 * 1024];
    let mut received = vec![0; payload.len()];
    for _ in 0..160 {
        stream.write_all(&payload).await.unwrap();
        tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut received))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(received, payload);
    }
    // >8 MiB total history forces FIFO eviction; transport counters stay exact.
    let response = rpc(&mut ws, 2, RequestBody::ListConnections(ListConnections {})).await;
    let conn = match response.body {
        Some(proto::ResponseBody::ConnectionList(list)) => list.connections[0].clone(),
        other => panic!("connection response: {other:?}"),
    };
    assert_eq!(conn.bytes_client_to_server, 160 * 32 * 1024);
    assert_eq!(conn.bytes_server_to_client, conn.bytes_client_to_server);
    for max_chunks in [0, u32::MAX] {
        let response = rpc(
            &mut ws,
            3,
            RequestBody::HistorySnapshot(HistorySnapshot {
                conn_id: conn.conn_id.clone(),
                direction: 0,
                max_chunks,
            }),
        )
        .await;
        match response.body {
            Some(proto::ResponseBody::HistoryData(data)) => {
                assert!(data.total_chunks > data.chunks.len() as u64);
                for direction in [1, 2] {
                    let chunks: Vec<_> = data
                        .chunks
                        .iter()
                        .filter(|c| c.direction == direction)
                        .collect();
                    assert!(!chunks.is_empty());
                    assert!(chunks.len() <= 300);
                    assert!(chunks.iter().map(|c| c.bytes.len()).sum::<usize>() <= 1024 * 1024);
                }
            }
            other => panic!("history response: {other:?}"),
        }
        // Control RPC remains usable after a full-size history response.
        rpc(
            &mut ws,
            4,
            RequestBody::SetEnabled(SetEnabled {
                direction: 1,
                enabled: true,
            }),
        )
        .await;
        stream.write_all(b"next").await.unwrap();
        wait_for_unit(&mut ws, 1).await;
        rpc(
            &mut ws,
            5,
            RequestBody::SetEnabled(SetEnabled {
                direction: 1,
                enabled: false,
            }),
        )
        .await;
        let mut small = [0; 4];
        tokio::time::timeout(Duration::from_secs(2), stream.read_exact(&mut small))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&small, b"next");
    }
    harness.relay.shutdown().await;
    echo.shutdown().await;
}

#[tokio::test]
async fn refused_connect_remains_visible_without_fabricated_traffic() {
    let harness = IpcHarness::start().await;
    let refused = testlab::refused_endpoint().await;
    let mut ws = connect_and_handshake(harness.ipc_addr, &harness.token).await;
    let mut stream = socks_client::open(harness.relay.local_addr())
        .await
        .unwrap();
    socks_client::greeting(&mut stream, GreetingStyle::Single, &[0])
        .await
        .unwrap();
    socks_client::send_request(
        &mut stream,
        &Destination::Ip(refused.ip()),
        refused.port(),
        RequestStyle::Single,
    )
    .await
    .unwrap();
    let reply = socks_client::read_reply(&mut stream).await.unwrap();
    assert_eq!(reply.code, 0x05);
    let closed = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let response = rpc(&mut ws, 2, RequestBody::ListConnections(ListConnections {})).await;
            if let Some(proto::ResponseBody::ConnectionList(list)) = response.body {
                if let Some(conn) = list.connections.into_iter().find(|c| c.closed) {
                    break conn;
                }
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("failed CONNECT must remain in Connections");
    assert_eq!(closed.requested_host, refused.ip().to_string());
    assert_eq!(closed.requested_port, u32::from(refused.port()));
    assert!(
        closed.close_reason.contains("0x05"),
        "{}",
        closed.close_reason
    );
    assert_eq!(closed.bytes_client_to_server, 0);
    assert_eq!(closed.bytes_server_to_client, 0);
    let response = rpc(
        &mut ws,
        3,
        RequestBody::HistorySnapshot(HistorySnapshot {
            conn_id: closed.conn_id,
            direction: 0,
            max_chunks: 1,
        }),
    )
    .await;
    match response.body {
        Some(proto::ResponseBody::HistoryData(data)) => assert!(data.chunks.is_empty()),
        other => panic!("history response: {other:?}"),
    }
    harness.relay.shutdown().await;
}

#[tokio::test]
async fn idle_controller_expires_despite_periodic_server_polling() {
    let harness = IpcHarness::start().await;
    let mut ws = connect_and_handshake(harness.ipc_addr, &harness.token).await;
    rpc(
        &mut ws,
        2,
        RequestBody::SetEnabled(SetEnabled {
            direction: 1,
            enabled: true,
        }),
    )
    .await;
    // Keep TCP open and read outbound events, but send no further activity.
    tokio::time::timeout(Duration::from_secs(65), async {
        while let Some(Ok(frame)) = ws.next().await {
            if matches!(frame, WsMessage::Close(_)) {
                break;
            }
        }
    })
    .await
    .expect("100ms poll ticks must not reset the 60s idle deadline");
    assert!(!harness
        .relay
        .intercept()
        .enabled(rawtcp_engine::Direction::ClientToServer));
    let mut recovered = connect_and_handshake(harness.ipc_addr, &harness.token).await;
    rpc(&mut recovered, 3, RequestBody::GetStats(GetStats {})).await;
    harness.relay.shutdown().await;
}

/// Helper: relay + IPC handles.
struct IpcHarness {
    relay: rawtcp_engine::RunningRelay,
    ipc_addr: std::net::SocketAddr,
    token: String,
}

impl IpcHarness {
    async fn start() -> Self {
        Self::start_with_capacity(64).await
    }

    async fn start_with_capacity(event_capacity: usize) -> Self {
        let (_sink, shared) = memory_telemetry();
        let config = RelayConfig::default()
            .with_endpoint(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 0)
            .with_ipc_port(0)
            .with_ipc_event_capacity(event_capacity);
        let relay = spawn_relay_with(config, shared).await.expect("relay bind");
        let ipc = relay.ipc().expect("ipc enabled");
        Self {
            ipc_addr: ipc.local_addr(),
            token: ipc.capability_token().to_string(),
            relay,
        }
    }
}

/// 1. A wrong token is rejected with an explicit error naming the token.
#[tokio::test]
async fn wrong_token_is_rejected() {
    let harness = IpcHarness::start().await;
    let mut ws = ws_connect(harness.ipc_addr).await;

    let hello = ClientMessage {
        request: Some(Request {
            request_id: 1,
            body: Some(RequestBody::Hello(Hello {
                protocol_version: PROTOCOL_VERSION,
                client_name: "bad".into(),
                client_version: "0".into(),
                capability_token: "wrong-token".into(),
            })),
        }),
    };
    let mut buf = Vec::new();
    hello.encode(&mut buf).unwrap();
    ws.send(WsMessage::Binary(buf)).await.unwrap();

    // The server answers with an explicit rejection naming the token, so
    // the control plane can tell the operator to paste the fresh one.
    let frame = tokio::time::timeout(Duration::from_secs(2), ws.next())
        .await
        .expect("rejection")
        .expect("frame")
        .expect("ws read");
    let bytes = match frame {
        WsMessage::Binary(b) => b,
        other => panic!("expected binary rejection, got {other:?}"),
    };
    let msg = ServerMessage::decode(&bytes[..]).expect("decode");
    match msg.body {
        Some(ServerMessageBody::Response(resp)) => match resp.body {
            Some(proto::ResponseBody::Error(error)) => {
                assert_eq!(error.code, 4401);
                assert!(
                    error.message.contains("token"),
                    "rejection must name the token: {}",
                    error.message
                );
            }
            other => panic!("expected Error, got {other:?}"),
        },
        other => panic!("expected Response, got {other:?}"),
    }

    // ...then the socket closes without a HelloAck.
    let frame = tokio::time::timeout(Duration::from_secs(2), ws.next()).await;
    match frame {
        Ok(Some(Ok(WsMessage::Close(_)))) | Ok(None) => {}
        Ok(Some(Ok(other))) => panic!("expected close, got {other:?}"),
        Ok(Some(Err(_))) => {}
        Err(_) => panic!("timeout waiting for close"),
    }

    harness.relay.shutdown().await;
}

/// 2. GetStats on a fresh relay returns zero counters and both
///    directions disabled.
#[tokio::test]
async fn get_stats_returns_initial_state() {
    let harness = IpcHarness::start().await;
    let mut ws = connect_and_handshake(harness.ipc_addr, &harness.token).await;

    let resp = rpc(&mut ws, 2, RequestBody::GetStats(GetStats {})).await;
    match resp.body {
        Some(proto::ResponseBody::Stats(stats)) => {
            assert_eq!(stats.offers, 0);
            assert_eq!(stats.commits, 0);
            assert!(!stats.c2s_enabled);
            assert!(!stats.s2c_enabled);
        }
        other => panic!("expected Stats, got {other:?}"),
    }

    harness.relay.shutdown().await;
}

/// 3. SetEnabled over IPC enables c2s interception; a real session's
///    unit appears in PendingUnits; Decide over IPC forwards it.
#[tokio::test]
async fn ipc_round_trip_set_enabled_pending_decide() {
    let harness = IpcHarness::start().await;
    let echo = testlab::echo_server().await;
    let mut ws = connect_and_handshake(harness.ipc_addr, &harness.token).await;

    // Enable c2s via IPC.
    let resp = rpc(
        &mut ws,
        2,
        RequestBody::SetEnabled(SetEnabled {
            direction: 1, // CLIENT_TO_SERVER
            enabled: true,
        }),
    )
    .await;
    match resp.body {
        Some(proto::ResponseBody::SetEnabledResult(r)) => {
            assert_eq!(r.released, 0, "nothing to release on enable");
        }
        other => panic!("expected SetEnabledResult, got {other:?}"),
    }

    // Connect and write through the relay.
    let mut stream = socks_client::connect_through_proxy(
        harness.relay.local_addr(),
        Destination::Ip(echo.addr().ip()),
        echo.addr().port(),
        GreetingStyle::Single,
        RequestStyle::Single,
    )
    .await
    .expect("connect");
    stream.write_all(b"hello-ipc").await.expect("write");

    // Poll PendingUnits until the unit appears.
    let unit = loop {
        tokio::time::sleep(Duration::from_millis(50)).await;
        let resp = rpc(&mut ws, 3, RequestBody::PendingUnits(PendingUnits {})).await;
        match resp.body {
            Some(proto::ResponseBody::PendingList(pl)) => {
                if let Some(u) = pl.units.into_iter().find(|u| u.bytes == b"hello-ipc") {
                    break u;
                }
            }
            other => panic!("expected PendingList, got {other:?}"),
        }
    };
    assert_eq!(unit.direction, 1); // CLIENT_TO_SERVER
    assert_eq!(unit.bytes, b"hello-ipc");

    // Decide Forward over IPC.
    let resp = rpc(
        &mut ws,
        4,
        RequestBody::Decide(Decide {
            unit_id: unit.unit_id,
            revision: unit.revision,
            action: 1, // FORWARD
            replace_bytes: Vec::new(),
        }),
    )
    .await;
    match resp.body {
        Some(proto::ResponseBody::DecideResult(r)) => {
            assert!(r.committed, "decide must commit");
            assert!(r.error_kind.is_empty());
        }
        other => panic!("expected DecideResult, got {other:?}"),
    }

    // The echo arrives.
    let mut echoed = [0u8; 9];
    tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut echoed))
        .await
        .expect("echo must resolve")
        .expect("read");
    assert_eq!(&echoed, b"hello-ipc");

    harness.relay.shutdown().await;
    echo.shutdown().await;
}

/// 4. ListConnections reports the established session.
#[tokio::test]
async fn list_connections_reports_session() {
    let harness = IpcHarness::start().await;
    let echo = testlab::echo_server().await;
    let mut ws = connect_and_handshake(harness.ipc_addr, &harness.token).await;

    let mut stream = socks_client::connect_through_proxy(
        harness.relay.local_addr(),
        Destination::Ip(echo.addr().ip()),
        echo.addr().port(),
        GreetingStyle::Single,
        RequestStyle::Single,
    )
    .await
    .expect("connect");
    stream.write_all(b"x").await.expect("write");

    // Wait for the connection to appear.
    let found = loop {
        tokio::time::sleep(Duration::from_millis(50)).await;
        let resp = rpc(&mut ws, 2, RequestBody::ListConnections(ListConnections {})).await;
        match resp.body {
            Some(proto::ResponseBody::ConnectionList(cl)) => {
                if cl.connections.iter().any(|c| c.established) {
                    break true;
                }
                if !cl.connections.is_empty() {
                    break false;
                }
            }
            other => panic!("expected ConnectionList, got {other:?}"),
        }
    };
    assert!(
        found,
        "established connection must appear in ListConnections"
    );

    harness.relay.shutdown().await;
    echo.shutdown().await;
}

/// 5. HistorySnapshot returns the captured bytes for a session.
#[tokio::test]
async fn history_snapshot_returns_captured_bytes() {
    let harness = IpcHarness::start().await;
    let echo = testlab::echo_server().await;
    let mut ws = connect_and_handshake(harness.ipc_addr, &harness.token).await;

    let mut stream = socks_client::connect_through_proxy(
        harness.relay.local_addr(),
        Destination::Ip(echo.addr().ip()),
        echo.addr().port(),
        GreetingStyle::Single,
        RequestStyle::Single,
    )
    .await
    .expect("connect");
    stream.write_all(b"hist-data").await.expect("write");
    // Read the echo so the bytes flow through both directions.
    let mut echoed = [0u8; 9];
    tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut echoed))
        .await
        .expect("echo")
        .expect("read");
    assert_eq!(&echoed, b"hist-data");

    // Get the connection list to find a conn_id.
    let resp = rpc(&mut ws, 2, RequestBody::ListConnections(ListConnections {})).await;
    let conn_id = match resp.body {
        Some(proto::ResponseBody::ConnectionList(cl)) => cl
            .connections
            .into_iter()
            .find(|c| c.established)
            .map(|c| c.conn_id)
            .expect("established connection"),
        other => panic!("expected ConnectionList, got {other:?}"),
    };

    // Request c2s history.
    let resp = rpc(
        &mut ws,
        3,
        RequestBody::HistorySnapshot(HistorySnapshot {
            conn_id: conn_id.clone(),
            direction: 1, // CLIENT_TO_SERVER
            max_chunks: 0,
        }),
    )
    .await;
    match resp.body {
        Some(proto::ResponseBody::HistoryData(hd)) => {
            let combined: Vec<u8> = hd
                .chunks
                .iter()
                .flat_map(|c| c.bytes.iter().copied())
                .collect();
            assert!(
                combined.windows(9).any(|w| w == b"hist-data"),
                "c2s history must contain the sent bytes; got {} bytes: {:?}",
                combined.len(),
                combined,
            );
        }
        other => panic!("expected HistoryData, got {other:?}"),
    }

    harness.relay.shutdown().await;
    echo.shutdown().await;
}

/// 5b. HistorySnapshot honors max_chunks (newest first) and reports totals.
#[tokio::test]
async fn history_snapshot_truncates_to_newest_chunks() {
    let harness = IpcHarness::start().await;
    let echo = testlab::echo_server().await;
    let mut ws = connect_and_handshake(harness.ipc_addr, &harness.token).await;

    let mut stream = socks_client::connect_through_proxy(
        harness.relay.local_addr(),
        Destination::Ip(echo.addr().ip()),
        echo.addr().port(),
        GreetingStyle::Single,
        RequestStyle::Single,
    )
    .await
    .expect("connect");
    // 20 KiB exceeds the 16 KiB relay buffer, so the client-to-server
    // stream is deterministically more than one chunk.
    let payload = vec![0xABu8; 20 * 1024];
    stream.write_all(&payload).await.expect("write");
    let mut echoed = vec![0u8; 20 * 1024];
    tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut echoed))
        .await
        .expect("echo")
        .expect("read");
    assert_eq!(echoed, payload);

    let resp = rpc(&mut ws, 2, RequestBody::ListConnections(ListConnections {})).await;
    let conn_id = match resp.body {
        Some(proto::ResponseBody::ConnectionList(cl)) => cl
            .connections
            .into_iter()
            .find(|c| c.established)
            .map(|c| c.conn_id)
            .expect("established connection"),
        other => panic!("expected ConnectionList, got {other:?}"),
    };

    // Full snapshot first: the retained count is the ground truth.
    let resp = rpc(
        &mut ws,
        3,
        RequestBody::HistorySnapshot(HistorySnapshot {
            conn_id: conn_id.clone(),
            direction: 1, // CLIENT_TO_SERVER
            max_chunks: 0,
        }),
    )
    .await;
    let full_total = match resp.body {
        Some(proto::ResponseBody::HistoryData(hd)) => {
            assert!(hd.chunks.len() >= 2, "20 KiB cannot fit one 16 KiB read");
            assert_eq!(hd.total_chunks as usize, hd.chunks.len());
            hd.total_chunks
        }
        other => panic!("expected HistoryData, got {other:?}"),
    };

    // Truncated snapshot: exactly the newest chunk, with the full total.
    let resp = rpc(
        &mut ws,
        4,
        RequestBody::HistorySnapshot(HistorySnapshot {
            conn_id,
            direction: 1, // CLIENT_TO_SERVER
            max_chunks: 1,
        }),
    )
    .await;
    match resp.body {
        Some(proto::ResponseBody::HistoryData(hd)) => {
            assert_eq!(hd.chunks.len(), 1);
            assert_eq!(hd.total_chunks, full_total);
            let tail = &hd.chunks[0];
            assert_eq!(
                tail.offset + tail.len,
                20 * 1024,
                "the retained chunk must be the stream tail"
            );
        }
        other => panic!("expected HistoryData, got {other:?}"),
    }

    harness.relay.shutdown().await;
    echo.shutdown().await;
}
#[tokio::test]
async fn state_changed_events_arrive_without_stalling_relay() {
    let harness = IpcHarness::start().await;
    let echo = testlab::echo_server().await;

    // Connect and do the handshake, then freeze (don't read).
    let mut ws = ws_connect(harness.ipc_addr).await;

    // Hello handshake.
    let hello = ClientMessage {
        request: Some(Request {
            request_id: 1,
            body: Some(RequestBody::Hello(Hello {
                protocol_version: PROTOCOL_VERSION,
                client_name: "frozen".into(),
                client_version: "0".into(),
                capability_token: harness.token.clone(),
            })),
        }),
    };
    let mut buf = Vec::new();
    hello.encode(&mut buf).unwrap();
    ws.send(WsMessage::Binary(buf)).await.unwrap();
    // Read the HelloAck so the server enters the request loop.
    let _ = ws.next().await;

    // Now freeze: don't read. Meanwhile, drive a SOCKS session through
    // the relay. It must complete within a deadline — the frozen IPC
    // client must not stall observe-only traffic.
    let mut stream = socks_client::connect_through_proxy(
        harness.relay.local_addr(),
        Destination::Ip(echo.addr().ip()),
        echo.addr().port(),
        GreetingStyle::Single,
        RequestStyle::Single,
    )
    .await
    .expect("connect");
    stream.write_all(b"unstalled").await.expect("write");
    let mut echoed = [0u8; 9];
    tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut echoed))
        .await
        .expect("relay must not stall while IPC client is frozen")
        .expect("read");
    assert_eq!(&echoed, b"unstalled");

    // The relay forwarded fine despite the frozen client. Now drain the
    // WebSocket and confirm at least one StateChanged event arrived.
    let mut got_event = false;
    for _ in 0..100 {
        let frame = tokio::time::timeout(Duration::from_millis(200), ws.next()).await;
        match frame {
            Ok(Some(Ok(WsMessage::Binary(bytes)))) => {
                let msg = ServerMessage::decode(&bytes[..]).expect("decode");
                if matches!(msg.body, Some(ServerMessageBody::Event(_))) {
                    got_event = true;
                    break;
                }
            }
            Ok(None) | Ok(Some(Err(_))) | Err(_) => break,
            Ok(Some(Ok(_))) => continue,
        }
    }
    assert!(
        got_event,
        "at least one StateChanged event must have arrived"
    );

    harness.relay.shutdown().await;
    echo.shutdown().await;
}

/// 7. When the IPC client disconnects after enabling interception, both
///    directions are disabled (fail-open). A subsequent session flows
///    without being held.
#[tokio::test]
async fn disconnect_disables_interception() {
    let harness = IpcHarness::start().await;
    let echo = testlab::echo_server().await;

    // Client 1: enable c2s interception, then disconnect.
    {
        let mut ws = connect_and_handshake(harness.ipc_addr, &harness.token).await;
        let resp = rpc(
            &mut ws,
            2,
            RequestBody::SetEnabled(SetEnabled {
                direction: 1,
                enabled: true,
            }),
        )
        .await;
        assert!(matches!(
            resp.body,
            Some(proto::ResponseBody::SetEnabledResult(_))
        ));
        // Drop the WebSocket — triggers disconnect cleanup.
        drop(ws);
    }

    // Give the server a moment to process the disconnect.
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Client 2: verify interception is now disabled.
    let mut ws2 = connect_and_handshake(harness.ipc_addr, &harness.token).await;
    let resp = rpc(&mut ws2, 3, RequestBody::GetStats(GetStats {})).await;
    match resp.body {
        Some(proto::ResponseBody::Stats(stats)) => {
            assert!(
                !stats.c2s_enabled,
                "c2s must be disabled after controller disconnect"
            );
        }
        other => panic!("expected Stats, got {other:?}"),
    }

    // A new session must flow without being held (no 30s lease delay).
    let mut stream = socks_client::connect_through_proxy(
        harness.relay.local_addr(),
        Destination::Ip(echo.addr().ip()),
        echo.addr().port(),
        GreetingStyle::Single,
        RequestStyle::Single,
    )
    .await
    .expect("connect");
    stream.write_all(b"post-disc").await.expect("write");
    let mut echoed = [0u8; 9];
    tokio::time::timeout(Duration::from_secs(3), stream.read_exact(&mut echoed))
        .await
        .expect("relay must forward without interception hold")
        .expect("read");
    assert_eq!(&echoed, b"post-disc");

    harness.relay.shutdown().await;
    echo.shutdown().await;
}

/// 8. A closed session remains discoverable in ListConnections so the
///    UI can query its retained history.
#[tokio::test]
async fn closed_session_remains_in_list_connections() {
    let harness = IpcHarness::start().await;
    let echo = testlab::echo_server().await;
    let mut ws = connect_and_handshake(harness.ipc_addr, &harness.token).await;

    // Create and close a session.
    let mut stream = socks_client::connect_through_proxy(
        harness.relay.local_addr(),
        Destination::Ip(echo.addr().ip()),
        echo.addr().port(),
        GreetingStyle::Single,
        RequestStyle::Single,
    )
    .await
    .expect("connect");
    stream.write_all(b"close-me").await.expect("write");
    let mut echoed = [0u8; 8];
    stream.read_exact(&mut echoed).await.expect("read");
    assert_eq!(&echoed, b"close-me");
    // Close the SOCKS session.
    drop(stream);

    // Wait for the closed connection to appear.
    let found_closed = loop {
        tokio::time::sleep(Duration::from_millis(100)).await;
        let resp = rpc(&mut ws, 2, RequestBody::ListConnections(ListConnections {})).await;
        match resp.body {
            Some(proto::ResponseBody::ConnectionList(cl)) => {
                if let Some(c) = cl.connections.iter().find(|c| c.closed) {
                    break c.clone();
                }
            }
            other => panic!("expected ConnectionList, got {other:?}"),
        }
    };
    assert!(!found_closed.conn_id.is_empty());
    assert!(
        !found_closed.close_reason.is_empty(),
        "closed sessions must report why they ended; got {:?}",
        found_closed
    );

    // History for the closed session is queryable.
    let resp = rpc(
        &mut ws,
        3,
        RequestBody::HistorySnapshot(HistorySnapshot {
            conn_id: found_closed.conn_id,
            direction: 1, // CLIENT_TO_SERVER
            max_chunks: 0,
        }),
    )
    .await;
    assert!(matches!(
        resp.body,
        Some(proto::ResponseBody::HistoryData(_))
    ));

    harness.relay.shutdown().await;
    echo.shutdown().await;
}

/// 9. IPC server shutdown reaps all connection tasks within a bounded
///    deadline — no detached tasks outlive the relay.
#[tokio::test]
async fn ipc_shutdown_reaps_connection_tasks() {
    let harness = IpcHarness::start().await;
    let echo = testlab::echo_server().await;

    // Connect two clients and leave them open.
    let ws1 = connect_and_handshake(harness.ipc_addr, &harness.token).await;
    let ws2 = connect_and_handshake(harness.ipc_addr, &harness.token).await;

    // Drive a session so the poll has something to track.
    let mut stream = socks_client::connect_through_proxy(
        harness.relay.local_addr(),
        Destination::Ip(echo.addr().ip()),
        echo.addr().port(),
        GreetingStyle::Single,
        RequestStyle::Single,
    )
    .await
    .expect("connect");
    stream.write_all(b"bye").await.expect("write");
    let mut echoed = [0u8; 3];
    stream.read_exact(&mut echoed).await.expect("read");
    assert_eq!(&echoed, b"bye");

    // Drop the SOCKS session and the WebSocket clients (they may have
    // pending writes, but drop closes the TCP sockets).
    drop(stream);
    drop(ws1);
    drop(ws2);

    // Shut down the relay. If any IPC task were detached, the shutdown
    // would hang or take longer than expected. The deadline proves no
    // task outlives the accept loop.
    tokio::time::timeout(Duration::from_secs(5), harness.relay.shutdown())
        .await
        .expect("relay shutdown must complete within 5s — no detached tasks");

    echo.shutdown().await;
}
