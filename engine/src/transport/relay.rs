//! Protocol-independent bidirectional TCP relay.
//!
//! TCP is a byte stream: a single `read()` may return part of one logical
//! message or many messages. Nothing here interprets message boundaries. Bytes
//! are copied verbatim, so arbitrary binary payloads — including `0x00` and
//! `0xff` — round-trip unchanged.
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

/// Terminal reason recorded for a relayed session.
pub const REASON_EOF: &str = "eof";

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
pub async fn relay(
    client: TcpStream,
    server: TcpStream,
    buffer_bytes: usize,
    shutdown: watch::Receiver<bool>,
) -> RelayOutcome {
    relay_with_counters(
        client,
        server,
        buffer_bytes,
        shutdown,
        Arc::new(AtomicU64::new(0)),
        Arc::new(AtomicU64::new(0)),
    )
    .await
}

/// [`relay`] with caller-owned directional byte counters.
///
/// `c2s_progress` / `s2c_progress` are incremented as bytes are handed to the
/// destination socket and remain valid after the relay future ends — including
/// when it is dropped via task abort — so lifecycle accounting can read final
/// progress for sessions that never returned an outcome.
pub async fn relay_with_counters(
    client: TcpStream,
    server: TcpStream,
    buffer_bytes: usize,
    shutdown: watch::Receiver<bool>,
    c2s_progress: Arc<AtomicU64>,
    s2c_progress: Arc<AtomicU64>,
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
    ));
    let mut s2c_fut = Box::pin(copy_half(
        server_read,
        client_write,
        buffer_bytes,
        shutdown,
        Arc::clone(&s2c_progress),
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

/// A direction counts as failed when it errored or was cut short by shutdown.
/// Clean EOF is not a failure: the reverse direction keeps flowing.
fn is_failure(outcome: Option<&HalfOutcome>) -> bool {
    matches!(
        outcome,
        Some(HalfOutcome { error: Some(_), .. })
            | Some(HalfOutcome {
                cancelled: true,
                ..
            })
    )
}

/// Terminal reason for a finished relay: shutdown wins over transport errors,
/// and a lone transport error names its direction.
fn terminal_reason(upstream: &HalfOutcome, downstream: &HalfOutcome) -> String {
    if upstream.cancelled || downstream.cancelled {
        return "engine shutdown".to_owned();
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
async fn copy_half<R, W>(
    mut reader: R,
    mut writer: W,
    buffer_bytes: usize,
    shutdown: watch::Receiver<bool>,
    progress: Arc<AtomicU64>,
) -> HalfOutcome
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buffer = vec![0u8; buffer_bytes];
    let mut bytes: u64 = 0;
    let mut error: Option<io::Error> = None;
    let mut cancelled = false;

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

        let mut written = 0usize;
        while written < read {
            let attempt = tokio::select! {
                biased;
                _ = wait_for_shutdown(shutdown.clone()) => {
                    cancelled = true;
                    break 'copy;
                }
                result = writer.write(&buffer[written..read]) => result,
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
                    written += count;
                    bytes += count as u64;
                    progress.fetch_add(count as u64, Ordering::Relaxed);
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
    }
}
