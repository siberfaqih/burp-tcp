//! Phase 5 integration tests: manual one-shot TCP repeater.
//!
//! Each test exercises the IPC RPCs end to end against loopback fixtures:
//! exactly one dial attempt, exactly one payload write, one bounded response
//! capture, and explicit stop/status lifecycle. No test performs an
//! automatic retry; duplicate sends are asserted absent through fixture
//! accept counts.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use prost::Message as ProstMessage;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::{tungstenite::Message as WsMessage, WebSocketStream};

use rawtcp_engine::ipc::proto::{
    self, ClientMessage, Hello, RepeaterSend, RepeaterStatus, RepeaterStop, Request, RequestBody,
    ServerMessage, ServerMessageBody,
};
use rawtcp_engine::ipc::PROTOCOL_VERSION;
use rawtcp_engine::telemetry::memory_telemetry;
use rawtcp_engine::{spawn_relay_with, RelayConfig};

/// Connect a WebSocket client to the IPC server. TCP connect and the
/// WebSocket upgrade are each bounded so a wedged server fails the test
/// instead of hanging it.
async fn ws_connect(addr: std::net::SocketAddr) -> WebSocketStream<TcpStream> {
    let tcp = tokio::time::timeout(Duration::from_secs(10), TcpStream::connect(addr))
        .await
        .expect("tcp connect timed out")
        .expect("tcp connect");
    let request = format!("ws://{addr}/")
        .into_client_request()
        .expect("build ws request");
    let (ws, _response) = tokio::time::timeout(
        Duration::from_secs(10),
        tokio_tungstenite::client_async(request, tcp),
    )
    .await
    .expect("ws upgrade timed out")
    .expect("ws handshake");
    ws
}

/// Connect, send Hello, and await HelloAck. Returns the stream ready for RPCs.
async fn connect_and_handshake(
    addr: std::net::SocketAddr,
    token: &str,
) -> WebSocketStream<TcpStream> {
    let mut ws = ws_connect(addr).await;
    let hello = ClientMessage {
        request: Some(Request {
            request_id: 1,
            body: Some(RequestBody::Hello(Hello {
                protocol_version: PROTOCOL_VERSION,
                client_name: "phase5-test".into(),
                client_version: "0.1".into(),
                capability_token: token.into(),
            })),
        }),
    };
    let mut buf = Vec::new();
    hello.encode(&mut buf).unwrap();
    ws.send(WsMessage::Binary(buf)).await.expect("send hello");

    // Bounded so a wedged server fails the test instead of hanging it.
    let frame = tokio::time::timeout(Duration::from_secs(10), ws.next())
        .await
        .expect("ack timeout")
        .expect("ack frame")
        .expect("ws read");
    let bytes = match frame {
        WsMessage::Binary(bytes) => bytes,
        _ => panic!("expected binary HelloAck, got {frame:?}"),
    };
    let msg = ServerMessage::decode(&bytes[..]).expect("decode ack");
    match msg.body {
        Some(ServerMessageBody::Response(response)) => match response.body {
            Some(proto::ResponseBody::HelloAck(_)) => {}
            other => panic!("expected HelloAck, got {other:?}"),
        },
        other => panic!("expected Response, got {other:?}"),
    }
    ws
}

/// Send a request and await the matching response, skipping events.
/// The whole wait is bounded so a wedged server fails the test instead of
/// hanging it, even under a continuous event stream.
async fn rpc(
    ws: &mut WebSocketStream<TcpStream>,
    request_id: u32,
    body: RequestBody,
) -> proto::Response {
    tokio::time::timeout(Duration::from_secs(20), rpc_inner(ws, request_id, body))
        .await
        .expect("rpc timed out")
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
        // Bounded so a wedged server fails the test instead of hanging it.
        let frame = tokio::time::timeout(Duration::from_secs(10), ws.next())
            .await
            .expect("rpc frame timeout")
            .expect("frame")
            .expect("ws read");
        let bytes = match frame {
            WsMessage::Binary(bytes) => bytes,
            WsMessage::Ping(_) => continue,
            _ => panic!("expected binary, got {frame:?}"),
        };
        let msg = ServerMessage::decode(&bytes[..]).expect("decode");
        match msg.body {
            Some(ServerMessageBody::Response(response)) if response.request_id == request_id => {
                return response;
            }
            Some(ServerMessageBody::Event(_)) => continue,
            other => panic!("unexpected server message: {other:?}"),
        }
    }
}

/// Send one request frame without waiting for its response, so the test
/// can pipeline several requests and keep the server's request loop busy
/// while independently draining the responses.
async fn send_frame(ws: &mut WebSocketStream<TcpStream>, request_id: u32, body: RequestBody) {
    let msg = ClientMessage {
        request: Some(Request {
            request_id,
            body: Some(body),
        }),
    };
    let mut buf = Vec::new();
    msg.encode(&mut buf).unwrap();
    ws.send(WsMessage::Binary(buf)).await.expect("send frame");
}

struct IpcHarness {
    relay: rawtcp_engine::RunningRelay,
    ipc_addr: std::net::SocketAddr,
    token: String,
}

impl IpcHarness {
    async fn start() -> Self {
        let (_sink, shared) = memory_telemetry();
        let config = RelayConfig::default()
            .with_endpoint(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 0)
            .with_ipc_port(0);
        let relay = spawn_relay_with(config, shared).await.expect("relay bind");
        let ipc = relay.ipc().expect("ipc enabled");
        Self {
            ipc_addr: ipc.local_addr(),
            token: ipc.capability_token().to_string(),
            relay,
        }
    }
}

fn repeater_send(
    host: &str,
    port: u16,
    payload: &[u8],
    limit: u32,
    timeout_ms: u64,
    completion: i32,
    idle_timeout_ms: u64,
) -> RequestBody {
    RequestBody::RepeaterSend(RepeaterSend {
        destination_host: host.to_owned(),
        destination_port: u32::from(port),
        payload: payload.to_vec(),
        response_byte_limit: limit,
        timeout_ms,
        completion,
        idle_timeout_ms,
    })
}

fn start_send_id(response: proto::Response) -> String {
    match response.body {
        Some(proto::ResponseBody::RepeaterStartResult(started)) => {
            assert!(!started.send_id.is_empty(), "send_id must be assigned");
            started.send_id
        }
        other => panic!("expected RepeaterStartResult, got {other:?}"),
    }
}

async fn await_finished_result(
    ws: &mut WebSocketStream<TcpStream>,
    send_id: &str,
    request_id: &mut u32,
) -> proto::RepeaterResult {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        assert!(
            tokio::time::Instant::now() < deadline,
            "timed out waiting for repeater completion"
        );
        *request_id += 1;
        let response = rpc(
            ws,
            *request_id,
            RequestBody::RepeaterStatus(RepeaterStatus {
                send_id: send_id.to_owned(),
            }),
        )
        .await;
        match response.body {
            Some(proto::ResponseBody::RepeaterStatusResult(status)) => {
                assert_eq!(status.send_id, send_id);
                if status.finished {
                    return status.result.expect("finished status carries a result");
                }
            }
            other => panic!("expected RepeaterStatusResult, got {other:?}"),
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

/// Fixture that sends one partial response, then holds the socket open until
/// the test releases it. Used for idle-timeout coverage.
async fn partial_then_silent_server(
    partial: Vec<u8>,
) -> (
    std::net::SocketAddr,
    oneshot::Sender<()>,
    tokio::task::JoinHandle<()>,
) {
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("fixture bind");
    let addr = listener.local_addr().expect("fixture addr");
    let (done_tx, done_rx) = oneshot::channel();
    let join = tokio::spawn(async move {
        let Ok((socket, _)) = listener.accept().await else {
            return;
        };
        let (mut reader, mut writer) = socket.into_split();
        if writer.write_all(&partial).await.is_err() {
            return;
        }
        let _ = writer.flush().await;
        let mut drain = vec![0u8; 1024];
        tokio::select! {
            biased;
            _ = async {
                loop {
                    match reader.read(&mut drain).await {
                        Ok(0) => break,
                        Ok(_) => continue,
                        Err(_) => break,
                    }
                }
                // Hold the socket open after the repeater's one-shot FIN so
                // the idle policy, not an immediate close, ends the capture.
                let _ = done_rx.await;
            } => {}
        }
    });
    (addr, done_tx, join)
}

/// Stopping an already-finished operation reports that no cancellation
/// was needed instead of claiming to stop it.
#[tokio::test]
async fn repeater_stop_after_finish_is_not_accepted() {
    let harness = IpcHarness::start().await;
    let echo = testlab::echo_server().await;
    let mut ws = connect_and_handshake(harness.ipc_addr, &harness.token).await;

    let response = rpc(
        &mut ws,
        2,
        repeater_send("127.0.0.1", echo.addr().port(), b"ping", 4, 5_000, 2, 0),
    )
    .await;
    let send_id = start_send_id(response);
    let mut request_id = 2;
    let result = await_finished_result(&mut ws, &send_id, &mut request_id).await;
    assert_eq!(result.outcome, 2);

    let stopped = rpc(
        &mut ws,
        request_id + 1,
        RequestBody::RepeaterStop(RepeaterStop {
            send_id: send_id.clone(),
        }),
    )
    .await;
    match stopped.body {
        Some(proto::ResponseBody::RepeaterStopResult(stopped)) => {
            assert_eq!(stopped.send_id, send_id);
            assert!(!stopped.accepted);
        }
        other => panic!("expected RepeaterStopResult, got {other:?}"),
    }

    harness.relay.shutdown().await;
    echo.shutdown().await;
}

/// Outcome of probing whether the repeater peer is still connected.
#[derive(Debug, PartialEq, Eq)]
enum ProbeOutcome {
    /// Writes failed: the peer is gone.
    PeerGone,
    /// Writes succeeded or blocked past the probe budget: the peer is alive.
    PeerAlive,
}

/// Fixture that reads a repeater request to EOF, then holds its side open
/// until the test asks it to probe whether the peer is still there.
///
/// A repeater write-half shutdown produces request EOF during normal
/// execution, so EOF alone cannot prove teardown. The probe writes at most
/// 1 KiB in small chunks: a fully closed peer answers data with RST
/// (PeerGone; the first chunk may succeed before the RST arrives, later
/// ones fail), while a leaked engine socket absorbs the bytes into kernel
/// buffers or blocks them (PeerAlive). Tests use a 256 KiB response cap so
/// the probe can never complete a leaked operation by itself.
struct ProbeServer {
    addr: std::net::SocketAddr,
    accepted: Arc<AtomicU64>,
    request_eof: Arc<AtomicBool>,
    probe_tx: mpsc::Sender<()>,
    outcome_rx: mpsc::Receiver<ProbeOutcome>,
    join: JoinHandle<()>,
}

async fn probe_server() -> ProbeServer {
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("fixture bind");
    let addr = listener.local_addr().expect("fixture addr");
    let accepted = Arc::new(AtomicU64::new(0));
    let request_eof = Arc::new(AtomicBool::new(false));
    let (probe_tx, mut probe_rx) = mpsc::channel::<()>(1);
    let (outcome_tx, outcome_rx) = mpsc::channel::<ProbeOutcome>(1);
    let accepted_task = Arc::clone(&accepted);
    let eof_task = Arc::clone(&request_eof);
    let join = tokio::spawn(async move {
        let Ok((socket, _)) = listener.accept().await else {
            return;
        };
        accepted_task.fetch_add(1, Ordering::SeqCst);
        drop(listener);
        let (mut reader, mut writer) = socket.into_split();
        // Drain the one-shot request through the repeater's write-half FIN.
        // This EOF is normal execution, not teardown.
        let mut drain = vec![0u8; 1024];
        loop {
            match reader.read(&mut drain).await {
                Ok(0) => break,
                Ok(_) => continue,
                Err(_) => break,
            }
        }
        eof_task.store(true, Ordering::SeqCst);
        // Hold our side open until the test probes.
        if probe_rx.recv().await.is_none() {
            return;
        }
        // Small probe: at most 1 KiB total, far below the test's response
        // cap, so absorbed bytes can never complete a leaked operation.
        let chunk = vec![0x5Au8; 64];
        let mut total: u64 = 0;
        let outcome = loop {
            match tokio::time::timeout(Duration::from_secs(5), writer.write_all(&chunk)).await {
                Ok(Ok(())) => {
                    total += chunk.len() as u64;
                    if total >= 1024 {
                        break ProbeOutcome::PeerAlive;
                    }
                }
                Ok(Err(_)) => break ProbeOutcome::PeerGone,
                Err(_) => break ProbeOutcome::PeerAlive,
            }
        };
        let _ = outcome_tx.send(outcome).await;
    });
    ProbeServer {
        addr,
        accepted,
        request_eof,
        probe_tx,
        outcome_rx,
        join,
    }
}

/// Fixture that accepts connections and drops each one immediately without
/// reading. A repeater failure against it must not trigger a second dial.
async fn accept_then_drop_server() -> (std::net::SocketAddr, Arc<AtomicU64>, JoinHandle<()>) {
    use std::sync::atomic::Ordering;
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("fixture bind");
    let addr = listener.local_addr().expect("fixture addr");
    let accepted = Arc::new(AtomicU64::new(0));
    let accepted_task = Arc::clone(&accepted);
    let join = tokio::spawn(async move {
        loop {
            let Ok((socket, _)) = listener.accept().await else {
                return;
            };
            accepted_task.fetch_add(1, Ordering::SeqCst);
            drop(socket);
        }
    });
    (addr, accepted, join)
}

/// 1. An exact-byte send round-trips once through a fresh echo session.
#[tokio::test]
async fn repeater_send_echo_exact_bytes() {
    let harness = IpcHarness::start().await;
    let echo = testlab::echo_server().await;
    let mut ws = connect_and_handshake(harness.ipc_addr, &harness.token).await;

    let response = rpc(
        &mut ws,
        2,
        repeater_send(
            "127.0.0.1",
            echo.addr().port(),
            b"ping-phase5",
            11,
            5_000,
            2,
            0,
        ),
    )
    .await;
    let send_id = start_send_id(response);
    let mut request_id = 2;
    let result = await_finished_result(&mut ws, &send_id, &mut request_id).await;

    assert_eq!(result.send_id, send_id);
    assert!(result.sent, "full payload must be reported sent");
    assert_eq!(result.bytes_sent, 11);
    assert_eq!(result.response, b"ping-phase5");
    assert!(!result.response_truncated);
    assert_eq!(result.outcome, 2, "expected READ_EXACT_BYTES completion");
    assert!(result.error_kind.is_empty());
    assert_eq!(echo.accepted(), 1, "exactly one repeater dial is allowed");

    harness.relay.shutdown().await;
    echo.shutdown().await;
}

/// 2. An empty payload can capture a server-first banner, then close.
#[tokio::test]
async fn repeater_empty_payload_reads_server_banner() {
    let harness = IpcHarness::start().await;
    let banner = testlab::server_first_server(b"READY\n".to_vec()).await;
    let mut ws = connect_and_handshake(harness.ipc_addr, &harness.token).await;

    let response = rpc(
        &mut ws,
        2,
        repeater_send("127.0.0.1", banner.addr().port(), b"", 64, 5_000, 1, 0),
    )
    .await;
    let send_id = start_send_id(response);
    let mut request_id = 2;
    let result = await_finished_result(&mut ws, &send_id, &mut request_id).await;

    assert!(result.sent);
    assert_eq!(result.bytes_sent, 0);
    assert_eq!(result.response, b"READY\n");
    assert_eq!(result.outcome, 1, "expected close completion");
    assert_eq!(banner.accepted(), 1);

    harness.relay.shutdown().await;
    banner.shutdown().await;
}

/// 3. A refused target fails without retrying the dial (see also the
/// elapsed-time bound in `repeater_refused_target_fails_fast_without_retry`).
#[tokio::test]
async fn repeater_refused_target_fails_without_retry() {
    let harness = IpcHarness::start().await;
    let refused = testlab::refused_endpoint().await;
    let mut ws = connect_and_handshake(harness.ipc_addr, &harness.token).await;

    let response = rpc(
        &mut ws,
        2,
        repeater_send("127.0.0.1", refused.port(), b"hello", 64, 5_000, 2, 0),
    )
    .await;
    let send_id = start_send_id(response);
    let mut request_id = 2;
    let result = await_finished_result(&mut ws, &send_id, &mut request_id).await;

    assert!(!result.sent);
    assert_eq!(result.bytes_sent, 0);
    assert!(result.response.is_empty());
    assert_eq!(result.outcome, 7, "expected FAILED");
    assert_eq!(result.error_kind, "connect_failed");

    harness.relay.shutdown().await;
}

/// 4. Malformed repeater requests are rejected before any socket opens.
#[tokio::test]
async fn repeater_invalid_request_is_rejected() {
    let harness = IpcHarness::start().await;
    let mut ws = connect_and_handshake(harness.ipc_addr, &harness.token).await;

    let response = rpc(
        &mut ws,
        2,
        repeater_send("127.0.0.1", 0, b"hello", 64, 5_000, 2, 0),
    )
    .await;
    match response.body {
        Some(proto::ResponseBody::Error(error)) => {
            assert_eq!(error.code, 4410);
            assert!(
                error.message.contains("destination port"),
                "unexpected error: {error:?}"
            );
        }
        other => panic!("expected repeater validation error, got {other:?}"),
    }

    harness.relay.shutdown().await;
}

/// 5. A second send while one is active is rejected, and stop cancels the
/// first operation without duplicating its payload dial.
#[tokio::test]
async fn repeater_second_send_is_busy_and_stop_cancels() {
    let harness = IpcHarness::start().await;
    let silent = testlab::silent_server(Duration::from_secs(5)).await;
    let mut ws = connect_and_handshake(harness.ipc_addr, &harness.token).await;

    let response = rpc(
        &mut ws,
        2,
        repeater_send(
            "127.0.0.1",
            silent.addr().port(),
            b"stop-me",
            64,
            5_000,
            1,
            0,
        ),
    )
    .await;
    let send_id = start_send_id(response);

    let busy = rpc(
        &mut ws,
        3,
        repeater_send(
            "127.0.0.1",
            silent.addr().port(),
            b"second",
            64,
            5_000,
            1,
            0,
        ),
    )
    .await;
    match busy.body {
        Some(proto::ResponseBody::Error(error)) => assert_eq!(error.code, 4411),
        other => panic!("expected busy error, got {other:?}"),
    }

    let stopped = rpc(
        &mut ws,
        4,
        RequestBody::RepeaterStop(RepeaterStop {
            send_id: send_id.clone(),
        }),
    )
    .await;
    match stopped.body {
        Some(proto::ResponseBody::RepeaterStopResult(stopped)) => {
            assert_eq!(stopped.send_id, send_id);
            assert!(stopped.accepted);
        }
        other => panic!("expected RepeaterStopResult, got {other:?}"),
    }

    let mut request_id = 4;
    let result = await_finished_result(&mut ws, &send_id, &mut request_id).await;
    assert_eq!(result.outcome, 4, "expected STOPPED");
    assert_eq!(result.error_kind, "stopped");
    assert_eq!(
        silent.accepted(),
        1,
        "the stopped send must not be repeated"
    );

    harness.relay.shutdown().await;
    silent.shutdown().await;
}

/// 6. Response capture stops at the requested cap and says so explicitly.
#[tokio::test]
async fn repeater_response_cap_truncates() {
    let harness = IpcHarness::start().await;
    let echo = testlab::echo_server().await;
    let mut ws = connect_and_handshake(harness.ipc_addr, &harness.token).await;

    let payload = vec![0xA5u8; 4096];
    let response = rpc(
        &mut ws,
        2,
        repeater_send("127.0.0.1", echo.addr().port(), &payload, 1024, 5_000, 1, 0),
    )
    .await;
    let send_id = start_send_id(response);
    let mut request_id = 2;
    let result = await_finished_result(&mut ws, &send_id, &mut request_id).await;

    assert!(result.sent);
    assert_eq!(result.bytes_sent, 4096);
    assert_eq!(result.response.len(), 1024);
    assert_eq!(result.response, vec![0xA5u8; 1024]);
    assert!(result.response_truncated);
    assert_eq!(result.outcome, 6, "expected TRUNCATED");
    assert_eq!(echo.accepted(), 1);

    harness.relay.shutdown().await;
    echo.shutdown().await;
}

/// 7. An idle policy completes with a partial response instead of waiting
/// for close.
#[tokio::test]
async fn repeater_idle_timeout_completes_partial_response() {
    let harness = IpcHarness::start().await;
    let (addr, done, join) = partial_then_silent_server(b"partial".to_vec()).await;
    let mut ws = connect_and_handshake(harness.ipc_addr, &harness.token).await;

    let response = rpc(
        &mut ws,
        2,
        repeater_send("127.0.0.1", addr.port(), b"ping", 64, 5_000, 3, 100),
    )
    .await;
    let send_id = start_send_id(response);
    let mut request_id = 2;
    let result = await_finished_result(&mut ws, &send_id, &mut request_id).await;

    assert!(result.sent);
    assert_eq!(result.response, b"partial");
    assert!(!result.response_truncated);
    assert_eq!(result.outcome, 3, "expected idle-timeout completion");

    let _ = done.send(());
    let _ = join.await;
    harness.relay.shutdown().await;
}

/// 8. The overall deadline bounds a silent target.
#[tokio::test]
async fn repeater_overall_timeout_bounds_silent_target() {
    let harness = IpcHarness::start().await;
    let silent = testlab::silent_server(Duration::from_secs(5)).await;
    let mut ws = connect_and_handshake(harness.ipc_addr, &harness.token).await;

    let response = rpc(
        &mut ws,
        2,
        repeater_send("127.0.0.1", silent.addr().port(), b"ping", 64, 300, 1, 0),
    )
    .await;
    let send_id = start_send_id(response);
    let mut request_id = 2;
    let result = await_finished_result(&mut ws, &send_id, &mut request_id).await;

    assert_eq!(result.outcome, 5, "expected TIMED_OUT");
    assert!(result.error_kind.is_empty());
    assert!(result.elapsed_ms < 5_000, "deadline must bound the send");

    harness.relay.shutdown().await;
    silent.shutdown().await;
}

/// Disconnecting the IPC client promptly closes an active repeater socket:
/// no detached send or receive may outlive the control connection. The
/// probe runs only after the engine has reached the response-read stage,
/// so it observes the receive socket, not the request FIN.
#[tokio::test]
async fn repeater_ipc_disconnect_closes_active_socket() {
    use std::sync::atomic::Ordering;
    let harness = IpcHarness::start().await;
    let mut server = probe_server().await;
    let mut ws = connect_and_handshake(harness.ipc_addr, &harness.token).await;

    let response = rpc(
        &mut ws,
        2,
        repeater_send(
            "127.0.0.1",
            server.addr.port(),
            b"ping",
            262_144,
            30_000,
            1,
            0,
        ),
    )
    .await;
    let send_id = start_send_id(response);
    assert!(!send_id.is_empty());

    // Wait until the engine has dialled and reached the response read.
    let ready_deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while server.accepted.load(Ordering::SeqCst) == 0 || !server.request_eof.load(Ordering::SeqCst)
    {
        assert!(
            tokio::time::Instant::now() < ready_deadline,
            "engine never reached the repeater response read"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }

    // Drop the control connection mid-operation.
    let _ = ws.close(None).await;
    // Wait until our own control connection observes the engine's teardown
    // (EOF/close): this proves the handler future — and with it the active
    // repeater future — was dropped, before the probe runs.
    let eof_deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        match tokio::time::timeout(Duration::from_secs(10), ws.next()).await {
            Ok(None) | Ok(Some(Err(_))) | Ok(Some(Ok(WsMessage::Close(_)))) => break,
            Ok(Some(Ok(_))) => {
                assert!(
                    tokio::time::Instant::now() < eof_deadline,
                    "control connection never observed engine teardown"
                );
                continue;
            }
            Err(_) => panic!("timed out waiting for control-connection teardown"),
        }
    }
    drop(ws);
    // Grace period for kernel FIN/RST propagation to the fixture.
    tokio::time::sleep(Duration::from_millis(250)).await;

    server
        .probe_tx
        .send(())
        .await
        .expect("fixture takes the probe");
    let outcome = tokio::time::timeout(Duration::from_secs(20), server.outcome_rx.recv())
        .await
        .expect("probe timed out")
        .expect("fixture reports the probe");
    assert_eq!(
        outcome,
        ProbeOutcome::PeerGone,
        "active repeater socket outlived the IPC disconnect"
    );

    let _ = server.join.await;
    harness.relay.shutdown().await;
}

/// Engine shutdown promptly closes an active repeater socket.
#[tokio::test]
async fn repeater_engine_shutdown_closes_active_socket() {
    use std::sync::atomic::Ordering;
    let harness = IpcHarness::start().await;
    let mut server = probe_server().await;
    let mut ws = connect_and_handshake(harness.ipc_addr, &harness.token).await;

    let response = rpc(
        &mut ws,
        2,
        repeater_send(
            "127.0.0.1",
            server.addr.port(),
            b"ping",
            262_144,
            30_000,
            1,
            0,
        ),
    )
    .await;
    let send_id = start_send_id(response);
    assert!(!send_id.is_empty());

    let ready_deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while server.accepted.load(Ordering::SeqCst) == 0 || !server.request_eof.load(Ordering::SeqCst)
    {
        assert!(
            tokio::time::Instant::now() < ready_deadline,
            "engine never reached the repeater response read"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }

    harness.relay.shutdown().await;

    // Grace period for kernel FIN/RST propagation to the fixture.
    tokio::time::sleep(Duration::from_millis(250)).await;

    server
        .probe_tx
        .send(())
        .await
        .expect("fixture takes the probe");
    let outcome = tokio::time::timeout(Duration::from_secs(20), server.outcome_rx.recv())
        .await
        .expect("probe timed out")
        .expect("fixture reports the probe");
    assert_eq!(
        outcome,
        ProbeOutcome::PeerGone,
        "active repeater socket outlived engine shutdown"
    );

    let _ = server.join.await;
}

/// A target that accepts then immediately drops must not trigger a second
/// dial: one send, exactly one accepted connection, whatever the outcome.
#[tokio::test]
async fn repeater_early_peer_close_dials_exactly_once() {
    use std::sync::atomic::Ordering;
    let harness = IpcHarness::start().await;
    let (addr, accepted, join) = accept_then_drop_server().await;
    let mut ws = connect_and_handshake(harness.ipc_addr, &harness.token).await;

    let response = rpc(
        &mut ws,
        2,
        repeater_send("127.0.0.1", addr.port(), b"ping", 64, 5_000, 1, 0),
    )
    .await;
    let send_id = start_send_id(response);
    let mut request_id = 2;
    let result = await_finished_result(&mut ws, &send_id, &mut request_id).await;

    // Either the write landed before the peer's RST (close completion) or it
    // failed outright; both are single-attempt terminal outcomes.
    assert!(
        result.outcome == 1 || result.outcome == 7,
        "expected close completion or failure, got {result:?}"
    );

    // Give any illicit retry a chance to dial, then assert a single attempt.
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(
        accepted.load(Ordering::SeqCst),
        1,
        "a failed send must not be retried"
    );

    join.abort();
    harness.relay.shutdown().await;
}

/// Stop and status against an unknown send ID are rejected explicitly.
#[tokio::test]
async fn repeater_unknown_send_id_is_rejected() {
    let harness = IpcHarness::start().await;
    let mut ws = connect_and_handshake(harness.ipc_addr, &harness.token).await;

    let response = rpc(
        &mut ws,
        2,
        RequestBody::RepeaterStatus(RepeaterStatus {
            send_id: "no-such-send".to_owned(),
        }),
    )
    .await;
    match response.body {
        Some(proto::ResponseBody::Error(error)) => assert_eq!(error.code, 4412),
        other => panic!("expected unknown-send error, got {other:?}"),
    }

    let response = rpc(
        &mut ws,
        3,
        RequestBody::RepeaterStop(RepeaterStop {
            send_id: "no-such-send".to_owned(),
        }),
    )
    .await;
    match response.body {
        Some(proto::ResponseBody::Error(error)) => assert_eq!(error.code, 4412),
        other => panic!("expected unknown-send error, got {other:?}"),
    }

    harness.relay.shutdown().await;
}

/// The repeater progresses and observes its deadline under continuous IPC
/// traffic on the same connection: a flood of stats RPCs must not starve
/// the inlined operation or postpone its timeout.
#[tokio::test]
async fn repeater_deadline_holds_under_continuous_ipc_traffic() {
    let harness = IpcHarness::start().await;
    let silent = testlab::silent_server(Duration::from_secs(30)).await;
    let mut ws = connect_and_handshake(harness.ipc_addr, &harness.token).await;

    let response = rpc(
        &mut ws,
        2,
        repeater_send("127.0.0.1", silent.addr().port(), b"ping", 64, 300, 1, 0),
    )
    .await;
    let send_id = start_send_id(response);

    // Flood the connection with pipelined stats RPCs while polling for
    // completion: each round fires several requests without waiting, so the
    // server's request loop stays busy independently of response draining.
    // Wall-clock from acceptance to terminal result is asserted below.
    let accepted_at = tokio::time::Instant::now();
    let mut request_id = 2u32;
    let traffic_deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    let result = loop {
        assert!(
            tokio::time::Instant::now() < traffic_deadline,
            "repeater never completed under traffic"
        );
        request_id += 1;
        let status_id = request_id;
        for _ in 0..4 {
            request_id += 1;
            send_frame(
                &mut ws,
                request_id,
                RequestBody::GetStats(proto::GetStats {}),
            )
            .await;
        }
        send_frame(
            &mut ws,
            status_id,
            RequestBody::RepeaterStatus(RepeaterStatus {
                send_id: send_id.clone(),
            }),
        )
        .await;
        // Drain this round's five responses (plus any events). A round
        // ends once all five arrived, whether or not the operation has
        // finished: an unfinished status schedules the next round.
        let mut stats_seen = 0;
        let mut status_seen = false;
        let mut finished: Option<proto::RepeaterResult> = None;
        while stats_seen < 4 || !status_seen {
            let frame = tokio::time::timeout(Duration::from_secs(10), ws.next())
                .await
                .expect("drain timed out")
                .expect("frame")
                .expect("ws read");
            let bytes = match frame {
                WsMessage::Binary(bytes) => bytes,
                WsMessage::Ping(_) => continue,
                _ => panic!("expected binary, got {frame:?}"),
            };
            let msg = ServerMessage::decode(&bytes[..]).expect("decode");
            match msg.body {
                Some(ServerMessageBody::Response(response)) => {
                    if response.request_id == status_id {
                        match response.body {
                            Some(proto::ResponseBody::RepeaterStatusResult(status)) => {
                                assert_eq!(status.send_id, send_id);
                                status_seen = true;
                                if status.finished {
                                    finished =
                                        Some(status.result.expect("finished carries a result"));
                                }
                            }
                            other => panic!("expected RepeaterStatusResult, got {other:?}"),
                        }
                    } else {
                        match response.body {
                            Some(proto::ResponseBody::Stats(_)) => stats_seen += 1,
                            other => panic!("expected Stats, got {other:?}"),
                        }
                    }
                }
                Some(ServerMessageBody::Event(_)) => continue,
                other => panic!("unexpected server message: {other:?}"),
            }
        }
        if let Some(result) = finished {
            break result;
        }
    };
    let wall_elapsed = accepted_at.elapsed();

    assert_eq!(result.outcome, 5, "expected TIMED_OUT, got {result:?}");
    assert!(result.error_kind.is_empty());
    assert!(
        result.elapsed_ms < 5_000,
        "deadline must bound the send under traffic, took {}ms",
        result.elapsed_ms
    );
    assert!(
        wall_elapsed < Duration::from_secs(10),
        "acceptance-to-terminal wall time must stay bounded under traffic, took {wall_elapsed:?}"
    );

    harness.relay.shutdown().await;
    silent.shutdown().await;
}

/// A refused target fails fast: a retry-until-deadline dialer would burn the
/// whole operation window, while a single attempt fails in milliseconds.
/// (Dial attempts against a refused port are unobservable from user space —
/// there is no listener to count them — so elapsed time is the signal. The
/// accept-then-drop test above counts dials where a listener exists.)
#[tokio::test]
async fn repeater_refused_target_fails_fast_without_retry() {
    let harness = IpcHarness::start().await;
    let refused = testlab::refused_endpoint().await;
    let mut ws = connect_and_handshake(harness.ipc_addr, &harness.token).await;

    let response = rpc(
        &mut ws,
        2,
        repeater_send("127.0.0.1", refused.port(), b"ping", 64, 10_000, 1, 0),
    )
    .await;
    let send_id = start_send_id(response);

    let mut request_id = 2;
    let result = await_finished_result(&mut ws, &send_id, &mut request_id).await;
    assert_eq!(result.outcome, 7, "expected FAILED, got {result:?}");
    assert_eq!(result.error_kind, "connect_failed");
    assert!(
        result.elapsed_ms < 3_000,
        "a single refused dial fails in ms; retries would burn the 10s window, took {}ms",
        result.elapsed_ms
    );

    harness.relay.shutdown().await;
}
