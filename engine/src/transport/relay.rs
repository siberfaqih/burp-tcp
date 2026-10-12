//! Protocol-independent bidirectional TCP relay.
//!
//! TCP is a byte stream: a single `read()` may return part of one logical
//! message or many messages. Nothing here interprets message boundaries. On
//! the passive path bytes are copied verbatim, so arbitrary binary payloads —
//! including `0x00` and `0xff` — round-trip unchanged. Phase 3 adds an
//! **opt-in** interception gate: when a relay is given an
//! [`InterceptCoordinator`] and a direction is enabled, each read chunk is
//! offered as a unit, held until the control plane decides
//! forward/replace/suppress/close, and the decision — not the original bytes —
//! may then be delivered. The passive path (no coordinator, disabled
//! direction, or overflow passthrough) performs no editing.
//!
//! Three properties matter for correctness:
//!
//! * **Counters are monotonic.** A direction reports every byte it managed to
//!   hand to the destination socket, even when that direction later fails. A
//!   failed write must not erase bytes that were already forwarded.
//! * **Half-close is preserved.** Reaching EOF in one direction shuts down only
//!   that direction's write half, so the reverse direction keeps flowing.
//! * **Errors tear down.** A fatal error in one direction cancels the other one.
//!   Without this, a silent peer could pin the session — and its registry slot
//!   — forever. Clean EOF does *not* cancel the reverse direction.
//!
//! Ownership model: this module spawns **no tasks**. Both copy directions run
//! as futures owned by the [`relay`] future itself. Dropping or aborting the
//! surrounding session task therefore drops both directions and releases all
//! socket halves immediately. There is no detached child that could keep
//! forwarding after the session is considered drained.

use std::io;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::watch;

use crate::history::{Direction, SessionObserver};
use crate::intercept::{InterceptAction, InterceptCoordinator, OfferOutcome};

/// Terminal reason recorded for a relayed session.
pub const REASON_EOF: &str = "eof";
/// Terminal reason recorded when an interception decision closes the
/// session (Phase 3).
pub const REASON_INTERCEPT_CLOSE: &str = "closed by interception decision";

/// Directional byte counters and the terminal reason for a relayed session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayOutcome {
    /// Bytes copied client -> server, including progress before a failure.
    pub bytes_client_to_server: u64,
    /// Bytes copied server -> client, including progress before a failure.
    pub bytes_server_to_client: u64,
    /// Why forwarding stopped.
    pub reason: String,
}

/// Result of copying one direction.
#[derive(Debug)]
struct HalfOutcome {
    /// Bytes successfully written to the destination socket.
    bytes: u64,
    /// First transport error seen, if any.
    error: Option<io::Error>,
    /// Whether the engine shutdown cut the direction short.
    cancelled: bool,
    /// Whether an interception `Close` decision ended the direction.
    closed_by_decision: bool,
}

/// Resolve once the engine has been asked to shut down.
///
/// Also resolves if the shutdown sender is dropped, which happens when the relay
/// handle goes away without an explicit shutdown. Either way, sessions must not
/// outlive the engine.
pub async fn wait_for_shutdown(mut rx: watch::Receiver<bool>) {
    loop {
        if *rx.borrow_and_update() {
            return;
        }
        if rx.changed().await.is_err() {
            return;
        }
    }
}

/// Relay bytes between a SOCKS client and an upstream server until both
/// directions finish, one direction fails, or the engine shuts down.
///
/// Both directions are driven concurrently inside this future; no child task is
/// spawned. Cancelling or aborting the surrounding session task drops both copy
/// futures and their socket halves, so no transport work can outlive the
/// session. A failed direction drops its peer (clean EOF still preserves the
/// reverse flow); the dropped peer's progress is recovered from its shared
/// atomic counter.
///
/// Byte counters are owned by the caller through [`relay_with_counters`]: they
/// are updated as bytes are forwarded and stay readable after this future is
/// dropped, so a supervisor can still report progress for an aborted session.
///
/// `observer` receives every successfully forwarded byte run for passive
/// Phase 2 history; forwarding itself is unchanged.
pub async fn relay(
    client: TcpStream,
    server: TcpStream,
    buffer_bytes: usize,
    shutdown: watch::Receiver<bool>,
    observer: SessionObserver,
) -> RelayOutcome {
    relay_with_counters(
        client,
        server,
        buffer_bytes,
        shutdown,
        Arc::new(AtomicU64::new(0)),
        Arc::new(AtomicU64::new(0)),
        observer,
        None,
    )
    .await
}

/// [`relay`] with caller-owned directional byte counters.
///
/// `c2s_progress` / `s2c_progress` are incremented as bytes are handed to the
/// destination socket and remain valid after the relay future ends — including
/// when it is dropped via task abort — so lifecycle accounting can read final
/// progress for sessions that never returned an outcome.
///
/// `intercept` is the Phase 3 manual interception coordinator. `None`
/// (or a coordinator with both directions disabled) reproduces the
/// passive Phase 2 relay byte for byte: offers happen only for enabled
/// directions.
// Eight parameters is the honest relay shape (two sockets, buffer,
// shutdown, two counters, observer, coordinator); bundling them would
// hide which side owns each socket half.
#[allow(clippy::too_many_arguments)]
pub async fn relay_with_counters(
    client: TcpStream,
    server: TcpStream,
    buffer_bytes: usize,
    shutdown: watch::Receiver<bool>,
    c2s_progress: Arc<AtomicU64>,
    s2c_progress: Arc<AtomicU64>,
    observer: SessionObserver,
    intercept: Option<Arc<InterceptCoordinator>>,
) -> RelayOutcome {
    let buffer_bytes = buffer_bytes.max(1);

    let (client_read, client_write) = client.into_split();
    let (server_read, server_write) = server.into_split();

    // These Arcs are shared three ways: the copy loops update them, the
    // in-task peer-drop path reads them, and the caller retains them, so
    // progress survives even if this future is dropped by task abort.
    let mut c2s_fut = Box::pin(copy_half(
        client_read,
        server_write,
        buffer_bytes,
        shutdown.clone(),
        Arc::clone(&c2s_progress),
        observer.clone(),
        Direction::ClientToServer,
        intercept.clone(),
    ));
    let mut s2c_fut = Box::pin(copy_half(
        server_read,
        client_write,
        buffer_bytes,
        shutdown,
        Arc::clone(&s2c_progress),
        observer,
        Direction::ServerToClient,
        intercept,
    ));

    let (upstream, downstream) = tokio::select! {
        biased;
        upstream = &mut c2s_fut => {
            if is_failure(Some(&upstream)) {
                // Tear down: release the peer's socket halves immediately.
                // Its forwarded-byte progress survives in `s2c_progress`.
                drop(s2c_fut);
                let downstream = HalfOutcome {
                    bytes: s2c_progress.load(Ordering::Relaxed),
                    error: None,
                    cancelled: false,
                    closed_by_decision: false,
                };
                (upstream, downstream)
            } else {
                // Clean EOF: the reverse direction keeps flowing.
                let downstream = s2c_fut.await;
                (upstream, downstream)
            }
        }
        downstream = &mut s2c_fut => {
            if is_failure(Some(&downstream)) {
                drop(c2s_fut);
                let upstream = HalfOutcome {
                    bytes: c2s_progress.load(Ordering::Relaxed),
                    error: None,
                    cancelled: false,
                    closed_by_decision: false,
                };
                (upstream, downstream)
            } else {
                let upstream = c2s_fut.await;
                (upstream, downstream)
            }
        }
    };

    RelayOutcome {
        bytes_client_to_server: upstream.bytes,
        bytes_server_to_client: downstream.bytes,
        reason: terminal_reason(&upstream, &downstream),
    }
}

/// A direction counts as failed when it errored, was cut short by
/// shutdown, or was closed by an interception decision. Clean EOF is not
/// a failure: the reverse direction keeps flowing.
fn is_failure(outcome: Option<&HalfOutcome>) -> bool {
    matches!(
        outcome,
        Some(HalfOutcome { error: Some(_), .. })
            | Some(HalfOutcome {
                cancelled: true,
                ..
            })
            | Some(HalfOutcome {
                closed_by_decision: true,
                ..
            })
    )
}

/// Terminal reason for a finished relay: shutdown wins over interception
/// closes, interception closes over transport errors, and a lone
/// transport error names its direction.
fn terminal_reason(upstream: &HalfOutcome, downstream: &HalfOutcome) -> String {
    if upstream.cancelled || downstream.cancelled {
        return "engine shutdown".to_owned();
    }
    if upstream.closed_by_decision || downstream.closed_by_decision {
        return REASON_INTERCEPT_CLOSE.to_owned();
    }

    match (&upstream.error, &downstream.error) {
        (None, None) => REASON_EOF.to_owned(),
        (Some(error), None) => format!("client_to_server: {error}"),
        (None, Some(error)) => format!("server_to_client: {error}"),
        (Some(upstream), Some(downstream)) => {
            format!("client_to_server: {upstream}; server_to_client: {downstream}")
        }
    }
}

/// Copy one direction until EOF, then shut down the destination write half.
///
/// `buffer_bytes` bounds memory: one fixed buffer is reused and bytes are never
/// accumulated. `bytes` counts only bytes the destination accepted, so a partial
/// write is accounted for exactly. `progress` mirrors the count into shared
/// memory so it survives the peer being dropped after a failure in the other
/// direction.
///
/// `observer` receives every byte run the destination accepted, in order, for
/// passive history. Observation adds synchronous bookkeeping/copying after
/// each successful write; it does not modify bytes or add network awaits.
/// The built-in sink drops/counts observations under lock contention rather
/// than waiting for snapshot readers.
///
/// Phase 3: when `intercept` is present and enabled for `direction`, each
/// read chunk is first offered to the coordinator as a pending unit and
/// **nothing is delivered until the unit resolves**. The sequential loop
/// therefore guarantees held bytes can never be overtaken by later
/// same-direction reads. Resolution is one of:
///
/// * `Forward` — deliver the original bytes;
/// * `Replace` — deliver the replacement bytes instead (history records
///   what was actually delivered, keeping the Phase 2 contract);
/// * `Suppress` — deliver nothing and continue;
/// * `Close` — deliver nothing and tear the session down (the peer
///   direction is cancelled via the failure path).
///
/// Units whose session dies while held (task abort, engine shutdown) are
/// released by the coordinator's lazy sweep, so the loop never outlives
/// the session. With interception disabled or absent, this function is
/// byte-for-byte the Phase 2 copy loop.
// Eight parameters: reader, writer, buffer, shutdown, counter,
// observer, direction, coordinator. Each is used exactly once and none
// belongs to a natural group.
#[allow(clippy::too_many_arguments)]
async fn copy_half<R, W>(
    mut reader: R,
    mut writer: W,
    buffer_bytes: usize,
    shutdown: watch::Receiver<bool>,
    progress: Arc<AtomicU64>,
    observer: SessionObserver,
    direction: Direction,
    intercept: Option<Arc<InterceptCoordinator>>,
) -> HalfOutcome
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buffer = vec![0u8; buffer_bytes];
    let mut bytes: u64 = 0;
    let mut error: Option<io::Error> = None;
    let mut cancelled = false;
    let mut closed_by_decision = false;
    // Source-read accounting for interception offers: position among
    // this direction's reads, independent of what history stores (held
    // bytes may be replaced or suppressed before delivery).
    let mut source_seq: u64 = 0;
    let mut source_offset: u64 = 0;

    'copy: loop {
        let read = tokio::select! {
            biased;
            _ = wait_for_shutdown(shutdown.clone()) => {
                cancelled = true;
                break 'copy;
            }
            result = reader.read(&mut buffer) => result,
        };

        let read = match read {
            Ok(0) => break 'copy,
            Ok(count) => count,
            Err(failure) => {
                error = Some(failure);
                break 'copy;
            }
        };

        // Offer position in read order; advanced now so every arm below
        // sees consistent accounting whether the unit is held or not.
        let (seq, offset) = (source_seq, source_offset);
        source_seq += 1;
        source_offset += read as u64;

        // Phase 3 interception gate. A held unit blocks this direction
        // entirely — by design, and bounded by the finite lease — while
        // bytes stay in the kernel socket buffer rather than engine
        // memory. The passive path (`None`/disabled/passthrough/forward)
        // writes straight out of the read buffer with no extra copy.
        enum Payload<'a> {
            Read(&'a [u8]),
            Replaced(Vec<u8>),
        }
        let payload = match &intercept {
            None => Payload::Read(&buffer[..read]),
            Some(coordinator) => {
                match coordinator.offer(observer.conn_id(), direction, seq, offset, &buffer[..read])
                {
                    OfferOutcome::Passthrough => Payload::Read(&buffer[..read]),
                    OfferOutcome::Held(handle) => {
                        // A held unit still yields to engine shutdown: the
                        // dropped resolve future drops the receiver, and the
                        // coordinator's lazy sweep retires the unit, so
                        // neither the session nor the queue outlives the
                        // engine.
                        let action = tokio::select! {
                            biased;
                            _ = wait_for_shutdown(shutdown.clone()) => {
                                cancelled = true;
                                break 'copy;
                            }
                            action = handle.resolve() => action,
                        };
                        match action {
                            InterceptAction::Forward => Payload::Read(&buffer[..read]),
                            InterceptAction::Replace(replacement) => Payload::Replaced(replacement),
                            InterceptAction::Suppress => continue 'copy,
                            InterceptAction::Close => {
                                closed_by_decision = true;
                                break 'copy;
                            }
                        }
                    }
                }
            }
        };
        let delivered: &[u8] = match &payload {
            Payload::Read(bytes) => bytes,
            Payload::Replaced(replacement) => replacement,
        };

        let mut written = 0usize;
        while written < delivered.len() {
            let attempt = tokio::select! {
                biased;
                _ = wait_for_shutdown(shutdown.clone()) => {
                    cancelled = true;
                    break 'copy;
                }
                result = writer.write(&delivered[written..]) => result,
            };

            match attempt {
                Ok(0) => {
                    error = Some(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "destination accepted zero bytes",
                    ));
                    break 'copy;
                }
                Ok(count) => {
                    // Counters advance BEFORE observation: if the history
                    // sink panics, delivered-byte accounting must survive
                    // even though this session dies with it. (Sink panics
                    // still propagate, consistent with telemetry sinks.)
                    written += count;
                    bytes += count as u64;
                    progress.fetch_add(count as u64, Ordering::Relaxed);
                    observer.observe(direction, &delivered[written - count..written]);
                }
                Err(failure) => {
                    error = Some(failure);
                    break 'copy;
                }
            }
        }
    }

    // Always signal EOF downstream. On a clean EOF this is half-close; on error
    // or shutdown it avoids turning a graceful close into a reset.
    let _ = writer.shutdown().await;

    HalfOutcome {
        bytes,
        error,
        cancelled,
        closed_by_decision,
    }
}
