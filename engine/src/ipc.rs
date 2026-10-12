//! Phase 4A — authenticated localhost IPC for the Burp Raw TCP workspace.
//!
//! A binary WebSocket on `127.0.0.1` speaks protobuf messages that expose
//! the Phase 2 history and Phase 3 interception surfaces to an external
//! control plane (the Burp Montoya extension in Phase 4B; a Rust test
//! client in Phase 4A).
//!
//! # Protocol (v1)
//!
//! See `proto/burp_tcp.proto` for the canonical schema. The Rust structs
//! in [`proto`] mirror it exactly; the Java extension compiles the
//! `.proto` with `protoc`. The two MUST stay in sync.
//!
//! One WebSocket binary frame = one raw protobuf message (no length
//! prefix; the WebSocket frame itself provides message delimitation). The
//! client sends [`proto::ClientMessage`] (wrapping a [`proto::Request`]);
//! the server sends [`proto::ServerMessage`] (wrapping either a
//! [`proto::Response`] matching a request id, or an async [`proto::Event`]).
//!
//! # Auth
//!
//! The first client message must carry a [`proto::Hello`] with the
//! per-launch capability token printed by the engine at startup. A
//! mismatch closes the socket without revealing state. The Hello must
//! arrive within [`HANDSHAKE_DEADLINE`] of the TCP accept.
//!
//! # Backpressure gate
//!
//! The relay data plane never awaits an IPC client. The server is a
//! pure consumer of existing public APIs ([`crate::history`],
//! [`crate::intercept`], [`crate::connection`]); no new tap is added to
//! the relay. Async [`proto::StateChanged`] events come from a poll
//! integrated into each connection's select loop (no detached task);
//! the poll calls `try_send` into a bounded per-client channel (capacity
//! [`EVENT_CHANNEL_CAPACITY`]); a full channel drops the event, increments
//! `ipc_dropped_events`, and does **not** advance the last-sent baseline
//! so the next poll retries. A slow or frozen client therefore loses
//! events but never stalls observe-only traffic or a decision commit.
//!
//! # Unload safety
//!
//! Each authenticated client holds a [`ControllerGuard`] (RAII). When
//! the **last** authenticated client disconnects — voluntarily, via
//! error, or via task cancellation/abort at any await point (Drop runs
//! regardless) — both interception directions are disabled (fail-open),
//! releasing any held units and preventing new holds from accumulating
//! with no controller. While at least one client remains connected, a
//! disconnecting observer cannot disable another controller's policy.
//! Extension unload therefore orphans no control state.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use futures_util::{future, SinkExt, StreamExt};
use prost::Message;
use std::future::Future;
use std::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, watch, Semaphore};
use tokio::task::{JoinHandle, JoinSet};
use tokio_tungstenite::tungstenite::Message as WsMessage;
use uuid::Uuid;

use crate::connection::ConnectionRegistry;
use crate::history::{Direction, MemoryHistory};
use crate::intercept::{DecisionError, InterceptAction, InterceptCoordinator};
use crate::repeater;

/// Protobuf message types mirroring `proto/burp_tcp.proto`.
pub mod proto;

/// Protocol version this server speaks.
pub const PROTOCOL_VERSION: u32 = 1;

/// Per-client event channel capacity. A full channel drops the event
/// (counted in `ipc_dropped_events`) rather than blocking the poll or
/// the relay. Configurable via `RelayConfig::ipc_event_capacity`.
const DEFAULT_EVENT_CHANNEL_CAPACITY: usize = 64;

/// Poll interval for [`proto::StateChanged`] events.
const STATE_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(100);

/// Maximum concurrent IPC clients (authenticated + in-handshake).
const MAX_IPC_CLIENTS: usize = 8;

/// Deadline for the first client frame (Hello) after TCP accept.
const HANDSHAKE_DEADLINE: std::time::Duration = std::time::Duration::from_secs(5);

/// Maximum time to wait for an outbound WebSocket frame to flush. If
/// the client is not reading, the send blocks; after this deadline the
/// handler terminates so the [`ControllerGuard`] can run its cleanup
/// (fail-open) instead of waiting indefinitely for a Close frame the
/// handler cannot read.
const IPC_SEND_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// RPC error codes for malformed repeater requests and repeater lifecycle
/// conflicts. `44xx` continues the existing IPC error namespace.
const REPEATER_INVALID_REQUEST: u32 = 4410;
const REPEATER_BUSY: u32 = 4411;
const REPEATER_UNKNOWN_SEND: u32 = 4412;

/// Handle to a running IPC server: bound address, the capability token
/// the operator must configure into the client, and graceful shutdown.
pub struct IpcHandle {
    local_addr: SocketAddr,
    capability_token: String,
    daemon_epoch: String,
    shutdown: Option<watch::Sender<bool>>,
    join: Option<JoinHandle<()>>,
}

impl IpcHandle {
    /// The WebSocket endpoint (`127.0.0.1:<port>`).
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// The per-launch capability token the client must present.
    pub fn capability_token(&self) -> &str {
        &self.capability_token
    }

    /// The daemon epoch UUID (fresh per engine start).
    pub fn daemon_epoch(&self) -> &str {
        &self.daemon_epoch
    }

    /// Signal the IPC server to stop accepting. Idempotent.
    pub fn begin_shutdown(&self) {
        if let Some(sender) = &self.shutdown {
            let _ = sender.send(true);
        }
    }

    /// Await the accept loop and all spawned connection handlers.
    pub async fn wait_stopped(&mut self) {
        if let Some(handle) = self.join.as_mut() {
            let _ = handle.await;
        }
        self.join.take();
    }

    /// Signal shutdown and await completion (consuming the handle).
    pub async fn shutdown(mut self) {
        self.begin_shutdown();
        self.wait_stopped().await;
    }
}

/// State the IPC server reads (all `Arc` clones from the relay).
struct IpcState {
    registry: Arc<ConnectionRegistry>,
    history: Arc<MemoryHistory>,
    intercept: Arc<InterceptCoordinator>,
    daemon_epoch: String,
    capability_token: String,
    ipc_dropped_events: Arc<AtomicU64>,
    /// Shared per-server event sequence. Every `StateChanged` event
    /// across every client gets the next value.
    event_seq: Arc<AtomicU64>,
    /// Per-client event channel capacity.
    event_capacity: usize,
    /// Number of authenticated clients currently connected, protected
    /// by a mutex so the last-controller cleanup (decrement + disable)
    /// is atomic with a concurrent controller registration (increment).
    /// When the last controller leaves, both interception directions are
    /// disabled (fail-open).
    authed_clients: Arc<Mutex<usize>>,
}

/// RAII controller guard. Created after a client successfully
/// authenticates; `Drop` decrements the authenticated-client count and,
/// when the last controller leaves, disables both interception
/// directions (fail-open).
///
/// `Drop` runs on every exit path — normal disconnect, protocol error,
/// and task cancellation/abort — so a cancelled handler cannot skip
/// cleanup. `set_enabled` is synchronous, so the cleanup needs no await
/// points.
///
/// The mutex is held across the decrement and the `set_enabled(false)`
/// calls, which serializes last-controller cleanup with a concurrent
/// `ControllerGuard::new` (increment). This prevents a newly
/// authenticated controller's `set_enabled(true)` from being overridden
/// by a stale disable from the previous last controller.
struct ControllerGuard {
    state: Arc<IpcState>,
}

impl ControllerGuard {
    fn new(state: Arc<IpcState>) -> Self {
        let mut count = state.authed_clients.lock().unwrap();
        *count += 1;
        drop(count);
        Self { state }
    }
}

impl Drop for ControllerGuard {
    fn drop(&mut self) {
        let mut count = self.state.authed_clients.lock().unwrap();
        *count = count.saturating_sub(1);
        if *count == 0 {
            // Last controller left: fail-open so no held unit waits out
            // its lease with nobody to decide it, and no new holds
            // accumulate. The mutex is still held, so a concurrent
            // ControllerGuard::new cannot increment past 0 before these
            // disables complete.
            self.state
                .intercept
                .set_enabled(Direction::ClientToServer, false);
            self.state
                .intercept
                .set_enabled(Direction::ServerToClient, false);
        }
    }
}

/// One in-flight repeater operation owned by a single IPC connection.
///
/// The future runs inline in that connection's request loop: it is polled
/// alongside incoming frames and events, never spawned as a detached task.
/// Dropping the connection future therefore drops the socket, so teardown
/// cannot leave a send or receive behind.
struct ActiveRepeater {
    id: String,
    cancel: watch::Sender<bool>,
    finished: Arc<AtomicBool>,
    task: Pin<Box<dyn Future<Output = proto::RepeaterResult> + Send>>,
}

/// A waker that does nothing, for polling an in-flight repeater future once
/// without waiting. Readiness that arrives later wakes the connection loop
/// through the normal select branches; this poll only guarantees progress
/// under select bias.
fn noop_waker() -> Waker {
    fn clone_waker(_: *const ()) -> RawWaker {
        RawWaker::new(std::ptr::null(), &WAKER_VTABLE)
    }
    fn noop(_: *const ()) {}
    static WAKER_VTABLE: RawWakerVTable = RawWakerVTable::new(clone_waker, noop, noop, noop);
    // SAFETY: the raw waker carries no data and all vtable functions are
    // no-ops, so construction and use are sound.
    unsafe { Waker::from_raw(RawWaker::new(std::ptr::null(), &WAKER_VTABLE)) }
}

/// Start the IPC server on `127.0.0.1:<port>` (0 = ephemeral).
///
/// Returns the handle with the resolved address and the capability token.
pub(crate) async fn spawn_ipc(
    port: u16,
    event_capacity: usize,
    registry: Arc<ConnectionRegistry>,
    history: Arc<MemoryHistory>,
    intercept: Arc<InterceptCoordinator>,
) -> Result<IpcHandle, std::io::Error> {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
    let listener = TcpListener::bind(addr).await?;
    let local_addr = listener.local_addr()?;
    let capability_token = Uuid::new_v4().to_string();
    let daemon_epoch = Uuid::new_v4().to_string();
    let ipc_dropped_events = Arc::new(AtomicU64::new(0));
    let event_seq = Arc::new(AtomicU64::new(0));
    let authed_clients = Arc::new(Mutex::new(0usize));
    let event_capacity = if event_capacity == 0 {
        DEFAULT_EVENT_CHANNEL_CAPACITY
    } else {
        event_capacity
    };

    let state = Arc::new(IpcState {
        registry,
        history,
        intercept,
        daemon_epoch: daemon_epoch.clone(),
        capability_token: capability_token.clone(),
        ipc_dropped_events: Arc::clone(&ipc_dropped_events),
        event_seq: Arc::clone(&event_seq),
        event_capacity,
        authed_clients: Arc::clone(&authed_clients),
    });

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let join = tokio::spawn(accept_loop(listener, state, shutdown_rx));

    Ok(IpcHandle {
        local_addr,
        capability_token,
        daemon_epoch,
        shutdown: Some(shutdown_tx),
        join: Some(join),
    })
}

/// Accept loop: bounds concurrent connections with a semaphore and
/// tracks every handler in a `JoinSet` so shutdown can reap them.
async fn accept_loop(
    listener: TcpListener,
    state: Arc<IpcState>,
    mut shutdown: watch::Receiver<bool>,
) {
    let sem = Arc::new(Semaphore::new(MAX_IPC_CLIENTS));
    let mut handlers: JoinSet<()> = JoinSet::new();

    loop {
        tokio::select! {
            biased;
            _ = shutdown.changed() => break,
            // Reap completed handlers to free JoinSet entries.
            Some(_) = handlers.join_next(), if !handlers.is_empty() => {}
            accept = listener.accept() => {
                let (stream, _) = match accept {
                    Ok(pair) => pair,
                    Err(_) => continue,
                };

                // Reject immediately when at capacity so accepted
                // sockets do not pile up waiting for a permit.
                let permit = match Arc::clone(&sem).try_acquire_owned() {
                    Ok(p) => p,
                    Err(_) => {
                        // Close the excess socket; the client may retry.
                        drop(stream);
                        continue;
                    }
                };

                let state = Arc::clone(&state);
                let mut child_shutdown = shutdown.clone();
                handlers.spawn(async move {
                    let _permit = permit; // held for the connection's lifetime
                    let _ = tokio::select! {
                        biased;
                        _ = child_shutdown.changed() => Ok::<(), ()>(()),
                        result = handle_connection(stream, state) => result,
                    };
                });
            }
        }
    }

    // Shutdown: abort all live handlers and await them so no task
    // outlives the accept loop.
    handlers.abort_all();
    while handlers.join_next().await.is_some() {}
}

/// Read the WebSocket upgrade and the first `Hello` frame. The whole
/// pre-auth phase must complete within [`HANDSHAKE_DEADLINE`] of the TCP
/// accept so an unauthenticated client cannot hold a permit indefinitely.
async fn read_hello(
    stream: tokio::net::TcpStream,
) -> Result<
    (
        tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>,
        proto::Hello,
        u32,
    ),
    (),
> {
    let mut ws = tokio_tungstenite::accept_async(stream)
        .await
        .map_err(|_| ())?;
    let first = match ws.next().await {
        Some(Ok(WsMessage::Binary(bytes))) => bytes,
        _ => return Err(()),
    };
    let client_msg = proto::ClientMessage::decode(&first[..]).map_err(|_| ())?;
    let request = client_msg.request.ok_or(())?;
    let request_id = request.request_id;
    let hello = match request.body {
        Some(proto::RequestBody::Hello(h)) => h,
        _ => return Err(()),
    };
    Ok((ws, hello, request_id))
}

/// One WebSocket connection lifecycle: handshake, then request loop
/// with an inlined state-change poll.
///
/// The [`ControllerGuard`] is created after successful authentication
/// and lives for the entire request loop. `Drop` runs on every exit
/// path — normal disconnect, protocol error, and task cancellation
/// (abort) — so cleanup is never skipped.
async fn handle_connection(stream: tokio::net::TcpStream, state: Arc<IpcState>) -> Result<(), ()> {
    // Pre-auth: WebSocket upgrade + first Hello frame, under one deadline.
    // Failures here close without cleanup — an unauthenticated client
    // cannot have modified control state.
    let (mut ws, hello, request_id) =
        match tokio::time::timeout(HANDSHAKE_DEADLINE, read_hello(stream)).await {
            Ok(Ok(triple)) => triple,
            _ => return Err(()),
        };

    if hello.capability_token != state.capability_token {
        // Token mismatch: close without revealing state.
        let _ = ws.send(WsMessage::Close(None)).await;
        return Err(());
    }
    if hello.protocol_version != PROTOCOL_VERSION {
        let error = proto::ServerMessage {
            body: Some(proto::ServerMessageBody::Response(proto::Response {
                request_id,
                body: Some(proto::ResponseBody::Error(proto::Error {
                    code: 4402,
                    message: format!(
                        "unsupported protocol version: client {}, server {}",
                        hello.protocol_version, PROTOCOL_VERSION
                    ),
                })),
            })),
        };
        let _ = ws.send(WsMessage::Binary(encode(&error))).await;
        return Err(());
    }

    // HelloAck. If the send fails, the client never became a controller,
    // so no guard is created and no cleanup is needed.
    let ack = proto::ServerMessage {
        body: Some(proto::ServerMessageBody::Response(proto::Response {
            request_id,
            body: Some(proto::ResponseBody::HelloAck(proto::HelloAck {
                protocol_version: PROTOCOL_VERSION,
                daemon_epoch: state.daemon_epoch.clone(),
                server_version: env!("CARGO_PKG_VERSION").to_string(),
            })),
        })),
    };
    if ws.send(WsMessage::Binary(encode(&ack))).await.is_err() {
        return Err(());
    }

    // Authenticated: create the controller guard. Its Drop disables
    // interception when the last controller leaves, on any exit path.
    let _controller = ControllerGuard::new(Arc::clone(&state));

    // Per-client event channel. The poll is inlined in the select loop
    // below — no detached task.
    let (event_tx, mut event_rx) = mpsc::channel::<proto::Event>(state.event_capacity);
    let mut poll_interval = tokio::time::interval(STATE_POLL_INTERVAL);
    poll_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    // Skip the immediate first tick (interval fires at t=0).
    poll_interval.tick().await;

    let mut last_conns = u64::MAX;
    let mut last_pending = u64::MAX;
    // At most one repeater operation is active per connection. Its future is
    // polled inline below; the latest finished result is retained until the
    // next operation replaces it.
    let mut repeater_active: Option<ActiveRepeater> = None;
    let mut repeater_finished: Option<proto::RepeaterResult> = None;

    // Split the WebSocket for concurrent read + write.
    let (mut sink, mut stream) = ws.split();

    loop {
        // Poll an in-flight repeater operation once per iteration so
        // continuous IPC traffic cannot starve its progress or completion
        // under select bias. Its deadline is absolute from Send acceptance
        // (see start_repeater), so it cannot be postponed by delaying the
        // first poll either.
        if let Some(active) = repeater_active.as_mut() {
            let waker = noop_waker();
            let mut cx = Context::from_waker(&waker);
            if let Poll::Ready(done) = active.task.as_mut().poll(&mut cx) {
                repeater_active = None;
                repeater_finished = Some(done);
            }
        }
        let repeater_pending = repeater_active.is_some();
        tokio::select! {
            biased;
            // Client request.
            frame = stream.next() => {
                let bytes = match frame {
                    Some(Ok(WsMessage::Binary(b))) => b,
                    Some(Ok(WsMessage::Close(_))) | None => break,
                    Some(Ok(_)) => continue,
                    Some(Err(_)) => break,
                };
                let client_msg = match proto::ClientMessage::decode(&bytes[..]) {
                    Ok(msg) => msg,
                    Err(_) => break,
                };
                let request = match client_msg.request {
                    Some(req) => req,
                    None => break,
                };
                let response = handle_request(
                    &request,
                    &state,
                    &mut repeater_active,
                    &mut repeater_finished,
                )
                .await;
                let server_msg = proto::ServerMessage {
                    body: Some(proto::ServerMessageBody::Response(response)),
                };
                let send_result =
                    tokio::time::timeout(IPC_SEND_TIMEOUT, sink.send(WsMessage::Binary(encode(&server_msg))))
                        .await;
                if !matches!(send_result, Ok(Ok(()))) {
                    break;
                }
            }
            // Async event queued by the inlined poll.
            maybe_event = event_rx.recv() => {
                let Some(event) = maybe_event else { break };
                let server_msg = proto::ServerMessage {
                    body: Some(proto::ServerMessageBody::Event(event)),
                };
                let send_result =
                    tokio::time::timeout(IPC_SEND_TIMEOUT, sink.send(WsMessage::Binary(encode(&server_msg))))
                        .await;
                if !matches!(send_result, Ok(Ok(()))) {
                    break;
                }
            }
            // In-flight repeater operation. Its future is polled here, not in a
            // detached task, so connection teardown drops its socket.
            repeater_done = async {
                if let Some(active) = repeater_active.as_mut() {
                    active.task.as_mut().await
                } else {
                    future::pending().await
                }
            }, if repeater_pending => {
                repeater_active = None;
                repeater_finished = Some(repeater_done);
            }
            // Inlined state-change poll. No detached task: this dies
            // with the connection.
            _ = poll_interval.tick() => {
                let conns = state.registry.snapshot().len() as u64;
                let pending = state.intercept.pending().len() as u64;
                if conns != last_conns || pending != last_pending {
                    let seq = state.event_seq.fetch_add(1, Ordering::Relaxed) + 1;
                    let event = proto::Event {
                        seq,
                        timestamp_unix_ms: std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map(|d| d.as_millis() as u64)
                            .unwrap_or(0),
                        state_changed: Some(proto::StateChanged {
                            connection_count: conns,
                            pending_count: pending,
                        }),
                    };
                    // try_send: never block the connection on a slow client.
                    match event_tx.try_send(event) {
                        Ok(()) => {
                            // Advance baseline only on success so the
                            // next poll retries if this event was dropped.
                            last_conns = conns;
                            last_pending = pending;
                        }
                        Err(mpsc::error::TrySendError::Full(_)) => {
                            state.ipc_dropped_events.fetch_add(1, Ordering::Relaxed);
                            // Do NOT advance baseline; retry next tick.
                        }
                        Err(mpsc::error::TrySendError::Closed(_)) => break,
                    }
                }
            }
        }
    }

    // Guard drops here: decrements authed_clients; last controller
    // out disables both interception directions (fail-open).
    Ok(())
}

/// Dispatch one RPC request to the engine, returning the matching response.
async fn handle_request(
    request: &proto::Request,
    state: &IpcState,
    repeater_active: &mut Option<ActiveRepeater>,
    repeater_finished: &mut Option<proto::RepeaterResult>,
) -> proto::Response {
    let body = match &request.body {
        Some(proto::RequestBody::Hello(_)) => Some(proto::ResponseBody::Error(proto::Error {
            code: 4403,
            message: "hello already completed".into(),
        })),
        Some(proto::RequestBody::ListConnections(_)) => {
            Some(proto::ResponseBody::ConnectionList(list_connections(state)))
        }
        Some(proto::RequestBody::HistorySnapshot(hs)) => Some(proto::ResponseBody::HistoryData(
            history_snapshot(state, hs),
        )),
        Some(proto::RequestBody::PendingUnits(_)) => {
            Some(proto::ResponseBody::PendingList(pending_units(state)))
        }
        Some(proto::RequestBody::Decide(d)) => {
            Some(proto::ResponseBody::DecideResult(decide(state, d)))
        }
        Some(proto::RequestBody::SetEnabled(se)) => Some(proto::ResponseBody::SetEnabledResult(
            set_enabled(state, se),
        )),
        Some(proto::RequestBody::GetStats(_)) => {
            Some(proto::ResponseBody::Stats(stats_snapshot(state)))
        }
        Some(proto::RequestBody::Subscribe(_)) => {
            // Events are unconditional in v1. Return stats as a baseline
            // snapshot so the client has an initial state.
            Some(proto::ResponseBody::Stats(stats_snapshot(state)))
        }
        Some(proto::RequestBody::RepeaterSend(send)) => Some(start_repeater(send, repeater_active)),
        Some(proto::RequestBody::RepeaterStop(stop)) => {
            Some(stop_repeater(stop, repeater_active, repeater_finished).await)
        }
        Some(proto::RequestBody::RepeaterStatus(status)) => {
            Some(repeater_status(status, repeater_active, repeater_finished))
        }
        None => Some(proto::ResponseBody::Error(proto::Error {
            code: 4404,
            message: "empty request body".into(),
        })),
    };
    proto::Response {
        request_id: request.request_id,
        body,
    }
}

fn start_repeater(
    send: &proto::RepeaterSend,
    repeater_active: &mut Option<ActiveRepeater>,
) -> proto::ResponseBody {
    let validated = match repeater::validate_send(send) {
        Ok(validated) => validated,
        Err(message) => {
            return proto::ResponseBody::Error(proto::Error {
                code: REPEATER_INVALID_REQUEST,
                message: message.to_owned(),
            });
        }
    };
    if repeater_active.is_some() {
        return proto::ResponseBody::Error(proto::Error {
            code: REPEATER_BUSY,
            message: "a repeater operation is already active on this connection".into(),
        });
    }

    let send_id = Uuid::new_v4().to_string();
    let (cancel_tx, cancel_rx) = watch::channel(false);
    let finished = Arc::new(AtomicBool::new(false));
    let task_send_id = send_id.clone();
    let task_finished = Arc::clone(&finished);
    // Absolute from acceptance: delaying the future's first poll cannot
    // postpone the timeout, and the per-iteration poll above guarantees the
    // future is actually driven under IPC traffic.
    let deadline = tokio::time::Instant::now() + validated.timeout();
    let task = Box::pin(async move {
        let report = repeater::run_send(validated, cancel_rx, deadline).await;
        task_finished.store(true, Ordering::SeqCst);
        repeater::result_to_proto(&task_send_id, &report)
    });
    *repeater_active = Some(ActiveRepeater {
        id: send_id.clone(),
        cancel: cancel_tx,
        finished,
        task,
    });
    proto::ResponseBody::RepeaterStartResult(proto::RepeaterStartResult { send_id })
}

async fn stop_repeater(
    stop: &proto::RepeaterStop,
    repeater_active: &mut Option<ActiveRepeater>,
    repeater_finished: &mut Option<proto::RepeaterResult>,
) -> proto::ResponseBody {
    let active_matches = repeater_active
        .as_ref()
        .is_some_and(|active| active.id == stop.send_id);
    if active_matches {
        let active = repeater_active.take().expect("active repeater was checked");
        // A stop that arrives after natural completion must not claim to
        // have cancelled the operation. The finished flag is set by the
        // task immediately before it returns its result.
        let already_finished = active.finished.load(Ordering::SeqCst);
        if !already_finished {
            // Signal cancellation, then await the inlined future so the stop
            // response reflects the operation's terminal state.
            let _ = active.cancel.send(true);
        }
        let result = active.task.await;
        *repeater_finished = Some(result.clone());
        return proto::ResponseBody::RepeaterStopResult(proto::RepeaterStopResult {
            send_id: stop.send_id.clone(),
            accepted: !already_finished,
        });
    }
    if repeater_finished
        .as_ref()
        .is_some_and(|finished| finished.send_id == stop.send_id)
    {
        return proto::ResponseBody::RepeaterStopResult(proto::RepeaterStopResult {
            send_id: stop.send_id.clone(),
            accepted: false,
        });
    }
    proto::ResponseBody::Error(proto::Error {
        code: REPEATER_UNKNOWN_SEND,
        message: "unknown repeater send_id".into(),
    })
}

fn repeater_status(
    status: &proto::RepeaterStatus,
    repeater_active: &Option<ActiveRepeater>,
    repeater_finished: &Option<proto::RepeaterResult>,
) -> proto::ResponseBody {
    if repeater_active
        .as_ref()
        .is_some_and(|active| active.id == status.send_id)
    {
        return proto::ResponseBody::RepeaterStatusResult(proto::RepeaterStatusResult {
            send_id: status.send_id.clone(),
            finished: false,
            result: None,
        });
    }
    if let Some(finished) = repeater_finished {
        if finished.send_id == status.send_id {
            return proto::ResponseBody::RepeaterStatusResult(proto::RepeaterStatusResult {
                send_id: status.send_id.clone(),
                finished: true,
                result: Some(finished.clone()),
            });
        }
    }
    proto::ResponseBody::Error(proto::Error {
        code: REPEATER_UNKNOWN_SEND,
        message: "unknown repeater send_id".into(),
    })
}

// --- RPC implementations ---

fn list_connections(state: &IpcState) -> proto::ConnectionList {
    // Merge active registry entries with retained history records so
    // closed sessions remain discoverable for history queries.
    let active = state.registry.snapshot();
    let history_conns = state.history.connections();

    // Build a set of active conn_ids to avoid duplicates.
    let active_ids: std::collections::HashSet<&str> =
        active.iter().map(|c| c.id.as_str()).collect();

    let mut info: Vec<proto::ConnectionInfo> =
        Vec::with_capacity(active.len() + history_conns.len());

    // Active connections from the registry.
    for conn in &active {
        let established = matches!(conn.state, crate::connection::ConnectionState::Forwarding);
        let closed = matches!(conn.state, crate::connection::ConnectionState::Closed);
        let bytes_c2s: u64 = state
            .history
            .chunks_for_direction(&conn.id, Direction::ClientToServer)
            .iter()
            .map(|c| c.bytes.len() as u64)
            .sum();
        let bytes_s2c: u64 = state
            .history
            .chunks_for_direction(&conn.id, Direction::ServerToClient)
            .iter()
            .map(|c| c.bytes.len() as u64)
            .sum();
        info.push(proto::ConnectionInfo {
            conn_id: conn.id.clone(),
            requested_host: conn.requested_target.clone().unwrap_or_default(),
            requested_port: conn.requested_port.unwrap_or(0) as u32,
            established,
            closed,
            bytes_client_to_server: bytes_c2s,
            bytes_server_to_client: bytes_s2c,
        });
    }

    // Closed connections retained only in history.
    for rec in &history_conns {
        if active_ids.contains(rec.conn_id.as_str()) {
            continue;
        }
        info.push(proto::ConnectionInfo {
            conn_id: rec.conn_id.clone(),
            requested_host: rec.requested_target.clone(),
            requested_port: rec.requested_port as u32,
            established: false,
            closed: rec.closed_wall.is_some(),
            bytes_client_to_server: rec.bytes_client_to_server,
            bytes_server_to_client: rec.bytes_server_to_client,
        });
    }

    proto::ConnectionList { connections: info }
}

fn history_snapshot(state: &IpcState, hs: &proto::HistorySnapshot) -> proto::HistoryData {
    let direction = proto_direction_to_engine(hs.direction);
    let chunks = match direction {
        Some(dir) => state.history.chunks_for_direction(&hs.conn_id, dir),
        None => {
            let mut all = state
                .history
                .chunks_for_direction(&hs.conn_id, Direction::ClientToServer);
            all.extend(
                state
                    .history
                    .chunks_for_direction(&hs.conn_id, Direction::ServerToClient),
            );
            all
        }
    };
    let chunk_infos = chunks
        .iter()
        .map(|c| proto::TrafficChunkInfo {
            chunk_id: c.id.clone(),
            seq: c.seq,
            offset: c.offset,
            len: c.bytes.len() as u64,
            bytes: c.bytes.clone(),
            recorded_unix_ms: c
                .captured_wall
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0),
            direction: engine_direction_to_proto(c.direction),
        })
        .collect();
    proto::HistoryData {
        chunks: chunk_infos,
    }
}

fn pending_units(state: &IpcState) -> proto::PendingList {
    let pending = state.intercept.pending();
    let lease_ms = state.intercept.limits().hold_lease.as_millis() as u64;
    let units = pending
        .iter()
        .map(|u| proto::PendingUnitInfo {
            unit_id: u.id.clone(),
            conn_id: u.conn_id.clone(),
            direction: engine_direction_to_proto(u.direction),
            seq: u.seq,
            offset: u.offset,
            len: u.bytes.len() as u64,
            bytes: u.bytes.clone(),
            revision: u.revision,
            expires_unix_ms: u
                .held_wall
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| (d.as_millis() as u64).saturating_add(lease_ms))
                .unwrap_or(0),
        })
        .collect();
    proto::PendingList { units }
}

fn decide(state: &IpcState, d: &proto::Decide) -> proto::DecideResult {
    let action = match d.action {
        1 => InterceptAction::Forward,
        2 => InterceptAction::Replace(d.replace_bytes.clone()),
        3 => InterceptAction::Suppress,
        4 => InterceptAction::Close,
        _ => {
            return proto::DecideResult {
                committed: false,
                error_kind: "invalid_action".into(),
                expected_revision: 0,
            };
        }
    };
    match state.intercept.decide(&d.unit_id, d.revision, action) {
        Ok(()) => proto::DecideResult {
            committed: true,
            error_kind: String::new(),
            expected_revision: 0,
        },
        Err(DecisionError::UnknownUnit { .. }) => proto::DecideResult {
            committed: false,
            error_kind: "unknown_unit".into(),
            expected_revision: 0,
        },
        Err(DecisionError::StaleRevision { expected, .. }) => proto::DecideResult {
            committed: false,
            error_kind: "stale_revision".into(),
            expected_revision: expected,
        },
        Err(DecisionError::ReplaceTooLarge { .. }) => proto::DecideResult {
            committed: false,
            error_kind: "replace_too_large".into(),
            expected_revision: 0,
        },
    }
}

fn set_enabled(state: &IpcState, se: &proto::SetEnabled) -> proto::SetEnabledResult {
    let direction = match proto_direction_to_engine(se.direction) {
        Some(d) => d,
        None => return proto::SetEnabledResult { released: 0 },
    };
    let released = state.intercept.set_enabled(direction, se.enabled);
    proto::SetEnabledResult { released }
}

fn stats_snapshot(state: &IpcState) -> proto::Stats {
    proto::Stats {
        offers: state.intercept.offers(),
        overflow_forwards: state.intercept.overflow_forwards(),
        lease_releases: state.intercept.lease_releases(),
        disable_releases: state.intercept.disable_releases(),
        abandoned: state.intercept.abandoned(),
        commits: state.intercept.commits(),
        c2s_enabled: state.intercept.enabled(Direction::ClientToServer),
        s2c_enabled: state.intercept.enabled(Direction::ServerToClient),
        ipc_dropped_events: state.ipc_dropped_events.load(Ordering::Relaxed),
    }
}

// --- Helpers ---

fn proto_direction_to_engine(d: i32) -> Option<Direction> {
    match d {
        1 => Some(Direction::ClientToServer),
        2 => Some(Direction::ServerToClient),
        _ => None,
    }
}

fn engine_direction_to_proto(d: Direction) -> i32 {
    match d {
        Direction::ClientToServer => 1,
        Direction::ServerToClient => 2,
    }
}

fn encode(msg: &proto::ServerMessage) -> Vec<u8> {
    let mut buf = Vec::new();
    msg.encode(&mut buf)
        .expect("protobuf encode is infallible for a Vec buffer");
    buf
}
