//! SOCKS5 listener and per-session handling.
//!
//! Session flow (Phase 1A):
//!
//! ```text
//! accept -> reserve slot -> greeting -> method selection -> request
//!        -> resolve + dial upstream -> SOCKS success -> bidirectional relay
//! ```
//!
//! Every stage is bounded. A session holds a registry slot from accept until
//! close, so the configured connection cap also covers sessions still
//! negotiating, and each session observes engine shutdown so in-flight sockets
//! are released rather than leaked.

use std::net::SocketAddr;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};
use std::time::{Duration, Instant};

use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::task::JoinSet;

use crate::burp_route::{BurpRouter, SharedBurpRouter};
use crate::config::RelayConfig;
use crate::connection::{Admission, ConnectionRegistry};
use crate::error::{reply, ServeError, SocksError};
use crate::history::{
    ConnectionClose, ConnectionOpen, MemoryHistory, SessionObserver, SharedHistory,
};
use crate::intercept::InterceptCoordinator;
use crate::socks5::greeting::{read_greeting, write_no_acceptable, METHOD_NO_AUTH, SOCKS_VERSION};
use crate::socks5::reply::write_reply;
use crate::socks5::request::read_request;
use crate::telemetry::{Event, SharedTelemetry, StderrTelemetry};
use crate::transport::{dial_burp, dial_upstream, relay_with_counters, wait_for_shutdown};

/// Fallback address for logs when a socket has no local address.
const UNKNOWN_ADDR: SocketAddr =
    SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0);

/// Upper bound on how long shutdown waits for live sessions to release their
/// sockets before giving up on them.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(5);

/// Cap on grace-drain bytes before a rejection reply is framed.
///
/// A SOCKS request tail is at most a domain length byte plus 255 name bytes
/// plus 2 port bytes; the cap covers that with slack for pipelined junk.
const REJECT_DRAIN_CAP_BYTES: usize = 512;
/// Total budget for the grace drain. Loopback clients deliver in-flight
/// bytes in microseconds; the budget only bounds slow or hostile dribblers.
const REJECT_DRAIN_BUDGET: Duration = Duration::from_millis(250);

/// Handle to a running relay: bound address plus graceful shutdown.
pub struct RunningRelay {
    local_addr: SocketAddr,
    shutdown: Option<watch::Sender<bool>>,
    join: Option<tokio::task::JoinHandle<()>>,
    registry: Arc<ConnectionRegistry>,
    history: Arc<MemoryHistory>,
    intercept: Arc<InterceptCoordinator>,
    burp_router: SharedBurpRouter,
    ipc: Option<crate::ipc::IpcHandle>,
}

impl RunningRelay {
    /// Actual bound endpoint; resolves the ephemeral port when `port` was 0.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Shared connection registry.
    pub fn registry(&self) -> Arc<ConnectionRegistry> {
        Arc::clone(&self.registry)
    }

    /// Passive capture history for this relay (Phase 2).
    pub fn history(&self) -> Arc<MemoryHistory> {
        Arc::clone(&self.history)
    }

    /// Manual interception coordinator for this relay (Phase 3).
    ///
    /// Both directions are disabled by default; a relay whose control
    /// plane never enables interception is byte-for-byte the passive
    /// Phase 2 relay.
    pub fn intercept(&self) -> Arc<InterceptCoordinator> {
        Arc::clone(&self.intercept)
    }

    /// IPC server handle (Phase 4A), if the relay was configured with
    /// `RelayConfig::ipc_port`. The capability token printed at startup
    /// must be configured into the control-plane client.
    pub fn ipc(&self) -> Option<&crate::ipc::IpcHandle> {
        self.ipc.as_ref()
    }

    /// Destination routing table for Burp Proxy handoff. Shared with the
    /// SOCKS supervisor and the IPC server, so `SetBurpRoutes` takes
    /// effect on subsequently accepted sessions.
    pub fn burp_router(&self) -> SharedBurpRouter {
        Arc::clone(&self.burp_router)
    }

    /// Ask the engine to stop accepting and to close live sessions.
    ///
    /// Signals both the SOCKS5 listener and the IPC server. Live
    /// sessions observe the flag and release their sockets; use
    /// [`RunningRelay::wait_stopped`] to await completion.
    pub fn begin_shutdown(&self) {
        if let Some(sender) = &self.shutdown {
            sender.send_replace(true);
        }
        if let Some(ipc) = &self.ipc {
            ipc.begin_shutdown();
        }
    }

    /// Await listener, session, and IPC shutdown.
    ///
    /// The join handles are only removed after their tasks complete, so a
    /// cancelled or timed-out wait can be retried instead of silently
    /// detaching engine tasks.
    pub async fn wait_stopped(&mut self) {
        // Await the IPC server first so no control-plane connections
        // remain while the relay drains.
        if let Some(ipc) = self.ipc.as_mut() {
            ipc.wait_stopped().await;
        }
        if let Some(handle) = self.join.as_mut() {
            let _ = handle.await;
        }
        self.join.take();
    }

    /// Signal shutdown and await completion.
    pub async fn shutdown(mut self) {
        self.begin_shutdown();
        self.wait_stopped().await;
    }
}

/// Bind the SOCKS5 listener and run it until `shutdown` resolves.
///
/// Returns the actual bound address. Fails with [`ServeError::Bind`] when the
/// endpoint is unavailable, which enforces "refuse startup if the port is
/// already in use".
pub async fn serve(
    config: RelayConfig,
    telemetry: SharedTelemetry,
    shutdown: watch::Receiver<bool>,
) -> Result<SocketAddr, ServeError> {
    let listener = bind_listener(&config).await?;
    let local_addr = listener.local_addr().map_err(ServeError::LocalAddr)?;

    telemetry.emit(Event::ListenerStarted { local_addr });

    let registry = Arc::new(ConnectionRegistry::new(config.max_connections));
    let history = Arc::new(MemoryHistory::new(config.history_limits));
    let intercept = InterceptCoordinator::new(config.intercept_limits);
    let burp_router: SharedBurpRouter = Arc::new(BurpRouter::new(config.burp_routes.clone()));
    accept_loop(
        listener,
        config,
        Arc::clone(&telemetry),
        registry,
        Arc::clone(&history),
        Arc::clone(&intercept),
        Arc::clone(&burp_router),
        shutdown,
    )
    .await;
    Ok(local_addr)
}

/// Spawn a relay with default stderr telemetry.
pub async fn spawn_relay(config: RelayConfig) -> Result<RunningRelay, ServeError> {
    spawn_relay_with(config, Arc::new(StderrTelemetry)).await
}

/// Spawn a relay with caller-provided telemetry.
///
/// Binding happens before this returns, so bind failures surface immediately.
pub async fn spawn_relay_with(
    config: RelayConfig,
    telemetry: SharedTelemetry,
) -> Result<RunningRelay, ServeError> {
    let listener = bind_listener(&config).await?;
    let local_addr = listener.local_addr().map_err(ServeError::LocalAddr)?;

    telemetry.emit(Event::ListenerStarted { local_addr });

    let registry = Arc::new(ConnectionRegistry::new(config.max_connections));
    let history = Arc::new(MemoryHistory::new(config.history_limits));
    let intercept = InterceptCoordinator::new(config.intercept_limits);
    let burp_router: SharedBurpRouter = Arc::new(BurpRouter::new(config.burp_routes.clone()));
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    // Start the IPC server if configured. The capability token is
    // generated inside spawn_ipc; the handle carries it back so the
    // caller (engine binary or test) can print or assert on it. A bind
    // failure is propagated, not swallowed: a relay that requested IPC
    // must not start without it.
    let ipc = if let Some(ipc_port) = config.ipc_port {
        let ipc_addr = format!("127.0.0.1:{ipc_port}");
        Some(
            crate::ipc::spawn_ipc(
                ipc_port,
                config.ipc_event_capacity,
                Arc::clone(&registry),
                Arc::clone(&history),
                Arc::clone(&intercept),
                Arc::clone(&burp_router),
                local_addr,
            )
            .await
            .map_err(|source| ServeError::IpcBind {
                addr: ipc_addr,
                source,
            })?,
        )
    } else {
        None
    };

    let join = tokio::spawn(accept_loop(
        listener,
        config,
        Arc::clone(&telemetry),
        Arc::clone(&registry),
        Arc::clone(&history),
        Arc::clone(&intercept),
        Arc::clone(&burp_router),
        shutdown_rx,
    ));

    Ok(RunningRelay {
        local_addr,
        shutdown: Some(shutdown_tx),
        join: Some(join),
        registry,
        history,
        intercept,
        burp_router,
        ipc,
    })
}

async fn bind_listener(config: &RelayConfig) -> Result<TcpListener, ServeError> {
    config.validate().map_err(|error| ServeError::Bind {
        addr: format!("{}:{}", config.bind_addr, config.port),
        source: std::io::Error::new(std::io::ErrorKind::InvalidInput, error),
    })?;

    TcpListener::bind((config.bind_addr, config.port))
        .await
        .map_err(|source| ServeError::Bind {
            addr: format!("{}:{}", config.bind_addr, config.port),
            source,
        })
}

/// Eight parameters is the honest shape of everything the supervisor owns
/// (socket, config, telemetry, registry, history, interception, Burp
/// routing, shutdown); bundling them would hide the construction order.
#[allow(clippy::too_many_arguments)]
async fn accept_loop(
    listener: TcpListener,
    config: RelayConfig,
    telemetry: SharedTelemetry,
    registry: Arc<ConnectionRegistry>,
    history: Arc<MemoryHistory>,
    intercept: Arc<InterceptCoordinator>,
    burp_router: SharedBurpRouter,
    shutdown: watch::Receiver<bool>,
) {
    // Session tasks are tracked so shutdown can drain them instead of
    // abandoning live sockets. Completed tasks are reaped as they finish to
    // keep the set bounded.
    let mut sessions: JoinSet<()> = JoinSet::new();
    // True only when the engine was asked to shut down. A fatal accept error
    // takes the other path: sessions never observed a shutdown flag there, so
    // they are aborted instead of being waited on.
    let mut graceful = false;

    loop {
        tokio::select! {
            biased;
            // A cloned receiver keeps the shutdown flag live for spawned
            // sessions; polling it here breaks the accept loop.
            _ = wait_for_shutdown(shutdown.clone()) => {
                graceful = true;
                break;
            }
            result = sessions.join_next(), if !sessions.is_empty() => {
                // Session lifecycle (slot release + terminal record) is owned
                // by a guard inside each session task, so it already ran for
                // normal completions, aborts, and unwinding panics alike.
                // Join errors therefore need no recovery here.
                let _ = result;
            }
            accepted = listener.accept() => {
                let (socket, client_addr) = match accepted {
                    Ok(pair) => pair,
                    Err(error) => {
                        telemetry.emit(Event::SessionRejected {
                            conn_id: String::from("-"),
                            client_addr: listener.local_addr().unwrap_or(UNKNOWN_ADDR),
                            requested_target: None,
                            requested_port: None,
                            reason: format!("accept failed: {error}"),
                        });
                        if is_transient_accept_error(&error) {
                            continue;
                        }
                        break;
                    }
                };

                let conn_id = match registry.reserve(client_addr) {
                    Admission::Admitted(connection) => connection.id,
                    Admission::Rejected { conn_id } => {
                        telemetry.emit(Event::SessionRejected {
                            conn_id,
                            client_addr,
                            requested_target: None,
                            requested_port: None,
                            reason: format!(
                                "connection limit reached ({})", registry.capacity()
                            ),
                        });
                        // No reply is possible: nothing has been negotiated yet.
                        drop(socket);
                        continue;
                    }
                };

                // Ownership starts here, before the first emit. `start_session`
                // builds the guard eagerly and returns a future that already
                // owns it, so from this point on every exit — including a panic
                // raised by the acceptance log below — releases the slot and
                // leaves a terminal record. Emitting first would admit a
                // connection whose only owner is a panicking log call.
                let session = start_session(
                    socket,
                    config.clone(),
                    shutdown.clone(),
                    Arc::clone(&telemetry),
                    Arc::clone(&registry),
                    Arc::clone(&history),
                    Arc::clone(&intercept),
                    Arc::clone(&burp_router),
                    conn_id.clone(),
                    client_addr,
                );

                telemetry.emit(Event::SessionAccepted {
                    conn_id,
                    client_addr,
                });

                sessions.spawn(session);
            }
        }
    }

    // Required shutdown ordering: the listener socket is closed *before* any
    // draining state is entered. Until the socket is dropped the kernel can
    // still complete TCP handshakes into the accept backlog, so a client could
    // connect successfully and then hang with no task accepting it. Dropping
    // first turns post-shutdown connects into prompt refusals instead.
    let listener_addr = listener.local_addr().unwrap_or(UNKNOWN_ADDR);
    drop(listener);

    // Live sessions observe the shutdown flag, release their sockets, and are
    // reaped; only then is shutdown complete.
    telemetry.emit(Event::ShutdownStarted {
        remaining_sessions: sessions.len(),
    });

    if graceful {
        let drained = tokio::time::timeout(SHUTDOWN_GRACE, async {
            while sessions.join_next().await.is_some() {}
        })
        .await
        .is_ok();

        if !drained {
            telemetry.emit(Event::SessionRejected {
                conn_id: String::from("-"),
                client_addr: listener_addr,
                requested_target: None,
                requested_port: None,
                reason: format!(
                    "{} session(s) did not stop within the shutdown grace period; aborting",
                    sessions.len()
                ),
            });
        }
    } else if !sessions.is_empty() {
        telemetry.emit(Event::SessionRejected {
            conn_id: String::from("-"),
            client_addr: listener_addr,
            requested_target: None,
            requested_port: None,
            reason: format!(
                "listener failed; aborting {} live session(s)",
                sessions.len()
            ),
        });
    }

    // Stragglers are terminated and reaped before shutdown is reported. Each
    // session owns all of its transport work inside its own task (the relay
    // spawns no child tasks), so reaping every session task guarantees no
    // forwarding can outlive the engine while the log claims it drained.
    sessions.abort_all();
    while sessions.join_next().await.is_some() {}

    // Recorded only once no session task remains. Emitted after the drain, so
    // its position in the log proves shutdown waited for sessions instead of
    // abandoning them.
    telemetry.emit(Event::SessionsDrained);

    registry.clear();
    telemetry.emit(Event::ListenerStopped);
}

fn is_transient_accept_error(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::Interrupted
            | std::io::ErrorKind::WouldBlock
    )
}

/// Outcome of one bounded negotiation stage.
enum Stage<T> {
    /// Stage completed.
    Done(T),
    /// Stage failed with a protocol or transport error.
    Failed(SocksError),
    /// Stage exceeded the negotiation deadline.
    TimedOut,
    /// Engine shutdown cut the stage short.
    Cancelled,
}

/// Run `fut` under a shared negotiation deadline and engine shutdown.
async fn run_stage<T, F>(deadline: Instant, shutdown: watch::Receiver<bool>, fut: F) -> Stage<T>
where
    F: std::future::Future<Output = Result<T, SocksError>>,
{
    tokio::select! {
        biased;
        _ = wait_for_shutdown(shutdown) => Stage::Cancelled,
        result = tokio::time::timeout_at(deadline.into(), fut) => match result {
            Ok(Ok(value)) => Stage::Done(value),
            Ok(Err(error)) => Stage::Failed(error),
            Err(_) => Stage::TimedOut,
        },
    }
}

/// Owns one session's lifecycle record and registry slot.
///
/// Constructed by [`start_session`] immediately after admission and moved into
/// the session future, so the task owns lifecycle finalization from creation:
/// the slot is released and a terminal record is emitted on EVERY exit path,
/// including abort-before-first-poll, task abort/cancellation, and unwinding
/// panics. (Building the guard inside an `async fn` body would leave the window
/// between spawn and first poll uncovered.) Normal paths report explicitly
/// through [`SessionFinalizer::report_closed`] or
/// [`SessionFinalizer::report_rejected`]; the [`Drop`] impl only fires when
/// the session was cut short before reporting.
///
/// A `JoinSet` join error carries no connection ID, so the supervisor cannot
/// finalize an aborted session itself. The guard solves that by travelling
/// with the session: it shares the relay byte counters (which stay readable
/// after the relay future is dropped) and the negotiated metadata, and emits
/// the terminal record when the task ends without reporting.
struct SessionFinalizer {
    telemetry: SharedTelemetry,
    registry: Arc<ConnectionRegistry>,
    history: SharedHistory,
    conn_id: String,
    client_addr: SocketAddr,
    opened_at: Instant,
    requested_target: Option<String>,
    requested_port: Option<u16>,
    resolved_upstream: Option<SocketAddr>,
    routed: bool,
    route_target: Option<SocketAddr>,
    established: bool,
    bytes_c2s: Arc<AtomicU64>,
    bytes_s2c: Arc<AtomicU64>,
    reported: bool,
}

impl SessionFinalizer {
    fn new(
        telemetry: SharedTelemetry,
        registry: Arc<ConnectionRegistry>,
        history: SharedHistory,
        conn_id: String,
        client_addr: SocketAddr,
    ) -> Self {
        Self {
            telemetry,
            registry,
            history,
            conn_id,
            client_addr,
            opened_at: Instant::now(),
            requested_target: None,
            requested_port: None,
            resolved_upstream: None,
            routed: false,
            route_target: None,
            established: false,
            bytes_c2s: Arc::new(AtomicU64::new(0)),
            bytes_s2c: Arc::new(AtomicU64::new(0)),
            reported: false,
        }
    }

    /// Record the negotiated destination in the registry and locally.
    fn set_destination(&mut self, target: String, port: u16) {
        self.registry
            .set_destination(&self.conn_id, target.clone(), port);
        self.requested_target = Some(target);
        self.requested_port = Some(port);
    }

    /// Mark this session as relayed through a Burp Proxy listener.
    fn mark_routed(&mut self, route_target: SocketAddr) {
        self.routed = true;
        self.route_target = Some(route_target);
        self.registry.mark_routed(&self.conn_id, route_target);
    }

    /// Transition to forwarding and emit `ConnectionEstablished`.
    ///
    /// State is stored before emitting, so a panicking telemetry sink still
    /// leaves the guard with full metadata for its terminal record. The
    /// history open record is written first: capture starts exactly when
    /// forwarding starts, so no forwarded byte predates its connection.
    fn mark_established(&mut self, resolved_upstream: SocketAddr) {
        self.registry.set_counters(
            &self.conn_id,
            Arc::clone(&self.bytes_c2s),
            Arc::clone(&self.bytes_s2c),
        );
        self.registry.mark_forwarding(&self.conn_id);
        self.established = true;
        self.resolved_upstream = Some(resolved_upstream);
        self.history.record_connection_open(ConnectionOpen {
            conn_id: self.conn_id.clone(),
            requested_target: self
                .requested_target
                .clone()
                .unwrap_or_else(|| String::from("-")),
            requested_port: self.requested_port.unwrap_or(0),
            resolved_upstream,
            routed: self.routed,
            route_target: self.route_target,
        });
        self.telemetry.emit(Event::ConnectionEstablished {
            conn_id: self.conn_id.clone(),
            client_addr: self.client_addr,
            requested_target: self
                .requested_target
                .clone()
                .unwrap_or_else(|| String::from("-")),
            requested_port: self.requested_port.unwrap_or(0),
            resolved_upstream: Some(resolved_upstream),
        });
    }

    /// Emit `ConnectionClosed` for a finished relay and free the slot.
    ///
    /// The report is marked done and the slot released BEFORE emitting: if
    /// the telemetry sink panics, cleanup must not depend on it, and `Drop`
    /// must not attempt a second terminal emission while unwinding (which
    /// would abort the process).
    fn report_closed(&mut self, outcome: crate::transport::RelayOutcome) {
        self.reported = true;
        self.registry.close(&self.conn_id);
        self.history.record_connection_close(
            &self.conn_id,
            ConnectionClose {
                bytes_client_to_server: outcome.bytes_client_to_server,
                bytes_server_to_client: outcome.bytes_server_to_client,
                reason: outcome.reason.clone(),
            },
        );
        self.telemetry.emit(Event::ConnectionClosed {
            conn_id: self.conn_id.clone(),
            requested_target: self
                .requested_target
                .clone()
                .unwrap_or_else(|| String::from("-")),
            requested_port: self.requested_port.unwrap_or(0),
            bytes_client_to_server: outcome.bytes_client_to_server,
            bytes_server_to_client: outcome.bytes_server_to_client,
            duration: self.opened_at.elapsed(),
            reason: outcome.reason,
        });
    }

    /// Log a terminal failure, optionally framing a SOCKS reply, and free the
    /// slot. `send_reply` is false while the greeting is still incomplete,
    /// because a reply frame cannot be interpreted at that point.
    ///
    /// As in [`SessionFinalizer::report_closed`], bookkeeping completes before
    /// the emit so a panicking sink cannot cause a repeated terminal attempt.
    async fn report_rejected(
        &mut self,
        socket: &mut TcpStream,
        error: SocksError,
        send_reply: bool,
    ) {
        if send_reply {
            if let Some(code) = error.reply_code() {
                // Drain first: closing with pending receive data makes
                // Windows reset the connection, discarding even the reply
                // bytes already delivered to the peer, so the client would
                // observe `ConnectionReset` instead of this failure reply.
                drain_request_tail(socket).await;
                let bind_addr = socket.local_addr().unwrap_or(UNKNOWN_ADDR);
                let _ = write_reply(socket, code, bind_addr).await;
            }
        }

        self.reported = true;
        self.registry.close(&self.conn_id);
        self.history
            .record_connection_rejected(crate::history::ConnectionRejected {
                conn_id: self.conn_id.clone(),
                requested_target: self.requested_target.clone().unwrap_or_default(),
                requested_port: self.requested_port.unwrap_or(0),
                reason: match error.reply_code() {
                    Some(code) => {
                        format!("SOCKS CONNECT failed (0x{code:02x}): {}", error.reason())
                    }
                    None => format!("SOCKS negotiation failed: {}", error.reason()),
                },
            });
        self.telemetry.emit(Event::SessionRejected {
            conn_id: self.conn_id.clone(),
            client_addr: self.client_addr,
            requested_target: self.requested_target.clone(),
            requested_port: self.requested_port,
            reason: error.reason(),
        });
    }
}

impl Drop for SessionFinalizer {
    /// Finalize a session that never reported: task abort/cancellation or an
    /// unwinding panic. Releases the slot (fixing the capacity leak) and emits
    /// the terminal per-connection record with the retained byte counters, so
    /// forced shutdowns keep per-session IDs and directional counters instead
    /// of only an aggregate rejection.
    fn drop(&mut self) {
        if self.reported {
            return;
        }
        self.reported = true;
        self.registry.close(&self.conn_id);
        // Panics cannot be distinguished from aborts here by any cheaper
        // means; `panicking()` is true while unwinding through this Drop.
        let abnormal = if std::thread::panicking() {
            "session task panicked"
        } else {
            "session aborted"
        };
        let event = if self.established {
            Event::ConnectionClosed {
                conn_id: self.conn_id.clone(),
                requested_target: self
                    .requested_target
                    .clone()
                    .unwrap_or_else(|| String::from("-")),
                requested_port: self.requested_port.unwrap_or(0),
                bytes_client_to_server: self.bytes_c2s.load(Ordering::Relaxed),
                bytes_server_to_client: self.bytes_s2c.load(Ordering::Relaxed),
                duration: self.opened_at.elapsed(),
                reason: abnormal.to_owned(),
            }
        } else {
            Event::SessionRejected {
                conn_id: self.conn_id.clone(),
                client_addr: self.client_addr,
                requested_target: self.requested_target.clone(),
                requested_port: self.requested_port,
                reason: abnormal.to_owned(),
            }
        };
        // History close for sessions that never reported through the normal
        // path. Rejected sessions retain only failure metadata. The built-in history enqueues with
        // try-locks and never waits for metadata snapshots/store locks,
        // including in this abort/unwind path. Metadata loss is counted.
        // The telemetry emit below remains guarded against sink panics.
        if self.established {
            self.history.record_connection_close(
                &self.conn_id,
                ConnectionClose {
                    bytes_client_to_server: self.bytes_c2s.load(Ordering::Relaxed),
                    bytes_server_to_client: self.bytes_s2c.load(Ordering::Relaxed),
                    reason: abnormal.to_owned(),
                },
            );
        } else {
            self.history
                .record_connection_rejected(crate::history::ConnectionRejected {
                    conn_id: self.conn_id.clone(),
                    requested_target: self.requested_target.clone().unwrap_or_default(),
                    requested_port: self.requested_port.unwrap_or(0),
                    reason: abnormal.to_owned(),
                });
        }
        // A panicking sink must never escape cleanup: during unwinding this
        // would be a second panic and abort the process. The slot is already
        // released above, so swallowing only loses one log record. Panics on
        // the normal reporting paths still propagate (failing that session
        // visibly); only the destructor is non-panicking.
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.telemetry.emit(event);
        }));
    }
}

/// Build one session's future with lifecycle ownership already attached.
///
/// Deliberately **not** an `async fn`: an async fn body does not run until its
/// first poll, so a guard created inside one would not exist during the window
/// between spawning the task and its first poll — an abort in that window
/// would drop a future owning nothing and leak the reservation. Here the
/// [`SessionFinalizer`] is constructed eagerly and moved into the returned
/// future, so the task owns the slot and the terminal record from creation.
///
/// This is the single construction path: the supervisor builds every session
/// through it, and the lifecycle regressions build theirs through it too, so
/// the pre-poll guarantee is exercised as shipped rather than re-implemented
/// inside a test.
///
/// Nine parameters is the honest shape of everything a session owns from
/// creation (socket, config, shutdown, telemetry, registry, history,
/// interception, ID, peer address); bundling them would hide the
/// construction order this helper exists to enforce.
#[allow(clippy::too_many_arguments)]
fn start_session(
    socket: TcpStream,
    config: RelayConfig,
    shutdown: watch::Receiver<bool>,
    telemetry: SharedTelemetry,
    registry: Arc<ConnectionRegistry>,
    history: Arc<MemoryHistory>,
    intercept: Arc<InterceptCoordinator>,
    burp_router: SharedBurpRouter,
    conn_id: String,
    client_addr: SocketAddr,
) -> impl std::future::Future<Output = ()> + Send {
    let history: SharedHistory = history;
    let finalizer = SessionFinalizer::new(telemetry, registry, history, conn_id, client_addr);
    async move { handle_session(socket, config, shutdown, finalizer, intercept, burp_router).await }
}

async fn handle_session(
    mut socket: TcpStream,
    config: RelayConfig,
    shutdown: watch::Receiver<bool>,
    mut finalizer: SessionFinalizer,
    intercept: Arc<InterceptCoordinator>,
    burp_router: SharedBurpRouter,
) {
    let deadline = Instant::now() + config.negotiation_timeout;

    // 1. Greeting.
    let greeting = match run_stage(deadline, shutdown.clone(), read_greeting(&mut socket)).await {
        Stage::Done(greeting) => greeting,
        Stage::Failed(error) => {
            // The greeting may be incomplete, so no reply can be framed.
            finalizer.report_rejected(&mut socket, error, false).await;
            return;
        }
        Stage::TimedOut => {
            finalizer
                .report_rejected(
                    &mut socket,
                    SocksError::NegotiationTimeout {
                        after: config.negotiation_timeout,
                    },
                    false,
                )
                .await;
            return;
        }
        Stage::Cancelled => {
            finalizer
                .report_rejected(&mut socket, SocksError::EngineShutdown, false)
                .await;
            return;
        }
    };

    if !greeting.offers_no_auth() {
        let _ = write_no_acceptable(&mut socket).await;
        finalizer
            .report_rejected(&mut socket, SocksError::NoAcceptableMethod, false)
            .await;
        return;
    }

    // Only NO AUTHENTICATION REQUIRED is offered by this engine.
    if write_selection(&mut socket).await.is_err() {
        finalizer
            .report_rejected(
                &mut socket,
                SocksError::Io(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "failed to write method selection",
                )),
                false,
            )
            .await;
        return;
    }

    // 2. Request.
    let request = match run_stage(deadline, shutdown.clone(), read_request(&mut socket)).await {
        Stage::Done(request) => request,
        Stage::Failed(error) => {
            // The greeting completed, so a failure reply can be framed.
            finalizer.report_rejected(&mut socket, error, true).await;
            return;
        }
        Stage::TimedOut => {
            finalizer
                .report_rejected(
                    &mut socket,
                    SocksError::NegotiationTimeout {
                        after: config.negotiation_timeout,
                    },
                    true,
                )
                .await;
            return;
        }
        Stage::Cancelled => {
            finalizer
                .report_rejected(&mut socket, SocksError::EngineShutdown, true)
                .await;
            return;
        }
    };

    let requested_target = request.target().display();
    let requested_port = request.port();
    finalizer.set_destination(requested_target.clone(), requested_port);

    // Burp handoff: a matching route dials the local Burp Proxy listener
    // instead of the original destination. The original destination stays
    // in history; the resolved endpoint is the Burp listener.
    let burp_target = burp_router.route_for(&requested_target, requested_port);

    // 3. Upstream connect. SOCKS success is only reported after this succeeds.
    let upstream = if let Some(burp_addr) = burp_target {
        let dialed = tokio::select! {
            biased;
            _ = wait_for_shutdown(shutdown.clone()) => {
                finalizer
                    .report_rejected(&mut socket, SocksError::EngineShutdown, true)
                    .await;
                return;
            }
            result = dial_burp(burp_addr, config.connect_timeout) => {
                match result {
                    Ok(upstream) => upstream,
                    Err(error) => {
                        finalizer.report_rejected(&mut socket, error, true).await;
                        return;
                    }
                }
            }
        };
        finalizer.mark_routed(burp_addr);
        dialed
    } else {
        tokio::select! {
        biased;
        _ = wait_for_shutdown(shutdown.clone()) => {
            finalizer
                .report_rejected(&mut socket, SocksError::EngineShutdown, true)
                .await;
            return;
        }
        result = dial_upstream(request.target(), requested_port, config.connect_timeout) => {
            match result {
                Ok(upstream) => upstream,
                Err(error) => {
                    finalizer.report_rejected(&mut socket, error, true).await;
                    return;
                }
            }
        }
        }
    };

    // RFC 1928: BND.ADDR/BND.PORT report the server's bound endpoint for the
    // connection, which for CONNECT is the upstream socket, not the SOCKS
    // listener the client happens to be talking to.
    let bind_addr = upstream.stream.local_addr().unwrap_or(UNKNOWN_ADDR);
    if write_reply(&mut socket, reply::SUCCEEDED, bind_addr)
        .await
        .is_err()
    {
        drop(upstream.stream);
        finalizer
            .report_rejected(
                &mut socket,
                SocksError::Io(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "failed to write SOCKS success reply",
                )),
                false,
            )
            .await;
        return;
    }

    finalizer.mark_established(upstream.resolved_addr);

    // 4. Forwarding. Bytes the client sent after its request are already queued
    //    in the socket buffer and are read by the relay. The counters are owned
    //    by the finalizer, so progress stays readable if this task is aborted
    //    mid-relay and the outcome never arrives. The observer records every
    //    successfully forwarded byte run into passive history. The coordinator
    //    holds traffic only for directions the control plane enabled (Phase 3);
    //    by default both are off and this is the passive Phase 2 path.
    //    Routed sessions bypass interception entirely: Burp owns the hold
    //    queue there, and a second engine queue would need two Forward
    //    clicks per chunk.
    let observer = SessionObserver::new(Arc::clone(&finalizer.history), finalizer.conn_id.clone());
    let intercept_plane = if finalizer.routed {
        None
    } else {
        Some(intercept)
    };
    let outcome = relay_with_counters(
        socket,
        upstream.stream,
        config.buffer_bytes,
        shutdown,
        Arc::clone(&finalizer.bytes_c2s),
        Arc::clone(&finalizer.bytes_s2c),
        observer,
        intercept_plane,
    )
    .await;

    finalizer.report_closed(outcome);
}

async fn write_selection(socket: &mut TcpStream) -> Result<(), std::io::Error> {
    use tokio::io::AsyncWriteExt;
    socket.write_all(&[SOCKS_VERSION, METHOD_NO_AUTH]).await?;
    socket.flush().await
}

/// Read and discard unread request bytes before framing a rejection reply.
///
/// Closing a socket with pending receive data makes Windows reset the
/// connection, which discards even the reply bytes already delivered to the
/// peer. Draining first turns the close into a graceful FIN carrying the
/// truthful SOCKS failure. Bounded by byte cap and total budget so a slow
/// or hostile client cannot pin the session slot; greeting-stage failures
/// (which frame no reply) skip draining entirely.
async fn drain_request_tail(socket: &mut TcpStream) {
    use tokio::io::AsyncReadExt;
    let deadline = Instant::now() + REJECT_DRAIN_BUDGET;
    let mut remaining = REJECT_DRAIN_CAP_BYTES;
    let mut probe = [0u8; 256];
    while remaining > 0 {
        let budget = deadline.saturating_duration_since(Instant::now());
        if budget.is_zero() {
            break;
        }
        let chunk = probe.len().min(remaining);
        match tokio::time::timeout(budget, socket.read(&mut probe[..chunk])).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => remaining -= n,
            Ok(Err(_)) | Err(_) => break,
        }
    }
}

#[cfg(test)]
mod lifecycle_tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Aborting a session mid-relay must stop transport, free the slot, and
    /// still record the terminal per-connection event with byte counters.
    ///
    /// Uses the same abnormal-termination operation the listener applies to
    /// stragglers (`abort`), against a live session driven through a real
    /// SOCKS handshake.
    #[tokio::test]
    async fn aborted_session_finalizes_record_and_frees_slot() {
        let ingress = TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("ingress bind");
        let ingress_addr = ingress.local_addr().expect("ingress addr");
        let upstream = TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("upstream bind");
        let target = upstream.local_addr().expect("upstream addr");

        let registry = Arc::new(ConnectionRegistry::new(8));
        let (sink, shared) = crate::telemetry::memory_telemetry();
        // Held for the whole test: dropping the sender would itself resolve
        // `wait_for_shutdown` and end the session cooperatively, not by abort.
        let (_shutdown_tx, shutdown_rx) = watch::channel(false);

        let (client_side, accepted) =
            tokio::join!(TcpStream::connect(ingress_addr), ingress.accept());
        let mut client = client_side.expect("client connect");
        let (socket, client_addr) = accepted.expect("accept");

        let Admission::Admitted(record) = registry.reserve(client_addr) else {
            panic!("slot must be available");
        };
        let conn_id = record.id.clone();

        // The production construction path, not a test-local copy of it.
        let history = Arc::new(crate::history::MemoryHistory::default());
        let intercept = crate::intercept::InterceptCoordinator::new(
            crate::intercept::InterceptLimits::default(),
        );
        let burp_router: SharedBurpRouter = Arc::new(crate::burp_route::BurpRouter::new(vec![]));
        let task = tokio::spawn(start_session(
            socket,
            RelayConfig::default(),
            shutdown_rx,
            shared,
            registry.clone(),
            Arc::clone(&history),
            intercept,
            burp_router,
            conn_id.clone(),
            client_addr,
        ));

        testlab::socks_client::greeting(
            &mut client,
            testlab::socks_client::GreetingStyle::Single,
            &[testlab::socks_client::consts::METHOD_NO_AUTH],
        )
        .await
        .expect("greeting");
        testlab::socks_client::send_request(
            &mut client,
            &testlab::socks_client::Destination::Ip(target.ip()),
            target.port(),
            testlab::socks_client::RequestStyle::Single,
        )
        .await
        .expect("request");
        let reply = testlab::socks_client::read_reply(&mut client)
            .await
            .expect("reply");
        assert!(reply.is_success());
        let (mut server, _) = upstream.accept().await.expect("upstream accept");

        // Bidirectional traffic so both counters are nonzero before the abort.
        client.write_all(b"before").await.expect("write");
        let mut probe = [0u8; 6];
        tokio::time::timeout(Duration::from_secs(5), server.read_exact(&mut probe))
            .await
            .expect("c2s must be active")
            .expect("read");
        assert_eq!(&probe, b"before");
        server.write_all(b"return").await.expect("write back");
        tokio::time::timeout(Duration::from_secs(5), client.read_exact(&mut probe))
            .await
            .expect("s2c must be active")
            .expect("read");
        assert_eq!(&probe, b"return");

        task.abort();
        let err = task.await.expect_err("abort must cancel the session");
        assert!(err.is_cancelled());

        // Transport stopped: no post-abort bytes may arrive.
        let _ = client.write_all(b"after!").await;
        let mut after = [0u8; 6];
        let ended = tokio::time::timeout(Duration::from_secs(2), server.read(&mut after))
            .await
            .expect("peer must resolve after abort");
        assert!(
            !matches!(ended, Ok(n) if n > 0),
            "no forwarding may survive the abort"
        );

        // Lifecycle finalized with IDs and retained counters despite the abort.
        assert_eq!(registry.active(), 0, "aborted session must free its slot");
        let events = sink.events();
        assert!(
            events.iter().any(
                |event| matches!(event, Event::ConnectionEstablished { conn_id: id, .. } if id == &conn_id)
            ),
            "establishment must be recorded"
        );
        let counters = events.iter().find_map(|event| match event {
            Event::ConnectionClosed {
                conn_id: id,
                bytes_client_to_server,
                bytes_server_to_client,
                ..
            } if id == &conn_id => Some((*bytes_client_to_server, *bytes_server_to_client)),
            _ => None,
        });
        assert_eq!(
            counters,
            Some((6, 6)),
            "aborted session must still emit its terminal record with retained counters"
        );

        // The abort path (Drop, not report_closed) must also leave a history
        // close record with the same retained counters.
        let history_record = history
            .connection(&conn_id)
            .expect("aborted session must leave a history close record");
        assert!(history_record.is_closed());
        assert_eq!(
            history_record.close_reason.as_deref(),
            Some("session aborted")
        );
        assert_eq!(history_record.bytes_client_to_server, 6);
        assert_eq!(history_record.bytes_server_to_client, 6);
    }

    /// Aborting before the session future is first polled must still free the
    /// slot and record a terminal event: the guard travels with the future
    /// from creation, not from its first poll.
    ///
    /// On a current-thread runtime nothing runs between `spawn` and `abort`
    /// without an await, so the session body provably never started. The
    /// session is built through `start_session` — the same helper the
    /// supervisor uses — so this covers the shipped construction order.
    #[tokio::test(flavor = "current_thread")]
    async fn aborted_before_first_poll_frees_slot_and_reports() {
        let ingress = TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("ingress bind");
        let ingress_addr = ingress.local_addr().expect("ingress addr");
        let _client = TcpStream::connect(ingress_addr)
            .await
            .expect("client connect");
        let (socket, client_addr) = ingress.accept().await.expect("accept");

        let registry = Arc::new(ConnectionRegistry::new(1));
        let (sink, shared) = crate::telemetry::memory_telemetry();
        let Admission::Admitted(record) = registry.reserve(client_addr) else {
            panic!("slot must be available");
        };
        let conn_id = record.id.clone();
        let (_shutdown_tx, shutdown_rx) = watch::channel(false);

        let intercept = crate::intercept::InterceptCoordinator::new(
            crate::intercept::InterceptLimits::default(),
        );
        let burp_router: SharedBurpRouter = Arc::new(crate::burp_route::BurpRouter::new(vec![]));
        let task = tokio::spawn(start_session(
            socket,
            RelayConfig::default(),
            shutdown_rx,
            shared,
            registry.clone(),
            Arc::new(crate::history::MemoryHistory::default()),
            intercept,
            burp_router,
            conn_id.clone(),
            client_addr,
        ));
        task.abort();
        let err = task.await.expect_err("abort must cancel the session");
        assert!(err.is_cancelled());

        assert_eq!(
            registry.active(),
            0,
            "abort-before-first-poll must free the reservation"
        );
        assert!(
            sink.events().iter().any(
                |event| matches!(event, Event::SessionRejected { conn_id: id, .. } if id == &conn_id)
            ),
            "abort-before-first-poll must leave a terminal record"
        );
    }

    /// Sink that panics on terminal close records while counting attempts.
    struct PanicOnClose {
        attempts: Arc<std::sync::atomic::AtomicUsize>,
    }

    impl crate::telemetry::Telemetry for PanicOnClose {
        fn emit(&self, event: Event) {
            if matches!(event, Event::ConnectionClosed { .. }) {
                self.attempts
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                panic!("controlled terminal sink panic");
            }
        }
    }

    /// A telemetry panic during terminal logging must propagate as an
    /// ordinary task failure: the slot is already released, the event is
    /// attempted exactly once, and the process survives (no double panic).
    #[test]
    fn terminal_emit_panic_frees_slot_without_double_emit() {
        use std::panic::{catch_unwind, AssertUnwindSafe};

        let attempts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let sink: SharedTelemetry = Arc::new(PanicOnClose {
            attempts: Arc::clone(&attempts),
        });
        let registry = Arc::new(ConnectionRegistry::new(4));
        let addr: SocketAddr = "127.0.0.1:10443".parse().unwrap();
        let Admission::Admitted(record) = registry.reserve(addr) else {
            panic!("admission");
        };
        let mut finalizer = SessionFinalizer::new(
            sink,
            Arc::clone(&registry),
            Arc::new(crate::history::MemoryHistory::default()),
            record.id,
            addr,
        );
        finalizer.set_destination("example".to_owned(), 443);
        let outcome = crate::transport::RelayOutcome {
            bytes_client_to_server: 7,
            bytes_server_to_client: 3,
            reason: "eof".to_owned(),
        };
        let result = catch_unwind(AssertUnwindSafe(|| {
            finalizer.report_closed(outcome);
        }));
        assert!(result.is_err(), "sink panic must propagate (not be hidden)");
        assert_eq!(
            registry.active(),
            0,
            "slot must be released despite the sink panic"
        );
        assert_eq!(
            attempts.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "terminal event must be attempted exactly once"
        );
    }

    /// The destructor itself must never panic: with a sink that fails every
    /// terminal emission, dropping an unreported guard still frees the slot
    /// and returns normally instead of aborting the process.
    #[test]
    fn drop_swallows_terminal_sink_panic() {
        struct PanicOnlyOnClose;
        impl crate::telemetry::Telemetry for PanicOnlyOnClose {
            fn emit(&self, event: Event) {
                if matches!(event, Event::ConnectionClosed { .. }) {
                    panic!("controlled drop-time sink panic");
                }
            }
        }

        let registry = Arc::new(ConnectionRegistry::new(4));
        let addr: SocketAddr = "127.0.0.1:10444".parse().unwrap();
        let Admission::Admitted(record) = registry.reserve(addr) else {
            panic!("admission");
        };
        let mut finalizer = SessionFinalizer::new(
            Arc::new(PanicOnlyOnClose),
            Arc::clone(&registry),
            Arc::new(crate::history::MemoryHistory::default()),
            record.id,
            addr,
        );
        finalizer.set_destination("example".to_owned(), 443);
        // Establishment emit is tolerated; only the terminal emit panics.
        finalizer.mark_established("127.0.0.1:443".parse().unwrap());
        drop(finalizer);
        assert_eq!(
            registry.active(),
            0,
            "destructor must free the slot even when the sink panics"
        );
    }
}
