//! Telemetry for Phase 1A.
//!
//! Emits **operational metadata only**. Application payloads are never logged
//! (`CURRENT_TASK.md`, Observability).

use std::io::Write;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// One observable engine event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// Listener bound successfully.
    ListenerStarted {
        /// Actual bound endpoint (may differ from requested when port is 0).
        local_addr: SocketAddr,
    },
    /// Listener stopped accepting new sessions.
    ListenerStopped,
    /// A session was accepted and is negotiating.
    SessionAccepted {
        /// Opaque connection ID.
        conn_id: String,
        /// SOCKS client address.
        client_addr: SocketAddr,
    },
    /// A session was closed before forwarding started.
    SessionRejected {
        /// Opaque connection ID.
        conn_id: String,
        /// SOCKS client address.
        client_addr: SocketAddr,
        /// Destination as requested, once the request had been parsed.
        requested_target: Option<String>,
        /// Destination port as requested, once the request had been parsed.
        requested_port: Option<u16>,
        /// Short failure reason.
        reason: String,
    },
    /// Listener shutdown began; live sessions are being closed.
    ShutdownStarted {
        /// Sessions still open when shutdown started.
        remaining_sessions: usize,
    },
    /// Every live session has released its socket.
    ///
    /// Emitted before [`Event::ListenerStopped`]; its presence proves shutdown
    /// drained sessions rather than abandoning them.
    SessionsDrained,
    /// A CONNECT succeeded and forwarding began.
    ConnectionEstablished {
        /// Opaque connection ID.
        conn_id: String,
        /// SOCKS client address.
        client_addr: SocketAddr,
        /// Destination exactly as requested by the client.
        requested_target: String,
        /// Destination port as requested.
        requested_port: u16,
        /// Endpoint actually dialled after resolution, when applicable.
        resolved_upstream: Option<SocketAddr>,
    },
    /// A forwarding session ended.
    ConnectionClosed {
        /// Opaque connection ID.
        conn_id: String,
        /// Destination as requested.
        requested_target: String,
        /// Destination port as requested.
        requested_port: u16,
        /// Bytes forwarded client -> server.
        bytes_client_to_server: u64,
        /// Bytes forwarded server -> client.
        bytes_server_to_client: u64,
        /// Wall-clock session duration.
        duration: Duration,
        /// Terminal reason (EOF, reset, shutdown, error detail).
        reason: String,
    },
}

/// Sink for engine events.
pub trait Telemetry: Send + Sync + 'static {
    /// Record an event.
    fn emit(&self, event: Event);
}

/// Telemetry sink writing single-line JSON records to stderr.
#[derive(Debug, Default)]
pub struct StderrTelemetry;

impl Telemetry for StderrTelemetry {
    fn emit(&self, event: Event) {
        let mut stderr = std::io::stderr().lock();
        let _ = writeln!(stderr, "{}", format_event(&event));
    }
}

/// In-memory telemetry sink for tests.
#[derive(Debug, Default)]
pub struct MemoryTelemetry {
    events: Mutex<Vec<Event>>,
}

impl MemoryTelemetry {
    /// Create an empty sink.
    pub fn new() -> Self {
        Self::default()
    }

    /// Snapshot of all recorded events.
    pub fn events(&self) -> Vec<Event> {
        self.events
            .lock()
            .expect("memory telemetry poisoned")
            .clone()
    }
}

impl Telemetry for MemoryTelemetry {
    fn emit(&self, event: Event) {
        self.events
            .lock()
            .expect("memory telemetry poisoned")
            .push(event);
    }
}

/// Shared telemetry handle.
pub type SharedTelemetry = Arc<dyn Telemetry>;

/// Build an empty in-memory sink and its shared handle.
pub fn memory_telemetry() -> (Arc<MemoryTelemetry>, SharedTelemetry) {
    let sink = Arc::new(MemoryTelemetry::new());
    let handle: SharedTelemetry = sink.clone();
    (sink, handle)
}

/// Current UTC time as a Unix-epoch duration.
pub fn now_epoch() -> Duration {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
}

/// Render an event as a single JSON line.
pub fn format_event(event: &Event) -> String {
    let mut fields: Vec<(&str, String)> = vec![("event", event_name(event).to_owned())];
    match event {
        Event::ListenerStarted { local_addr } => {
            fields.push(("local_addr", local_addr.to_string()));
        }
        Event::ListenerStopped => {}
        Event::SessionAccepted {
            conn_id,
            client_addr,
        } => {
            fields.push(("conn_id", conn_id.clone()));
            fields.push(("client_addr", client_addr.to_string()));
        }
        Event::SessionRejected {
            conn_id,
            client_addr,
            requested_target,
            requested_port,
            reason,
        } => {
            fields.push(("conn_id", conn_id.clone()));
            fields.push(("client_addr", client_addr.to_string()));
            fields.push((
                "target",
                requested_target.clone().unwrap_or_else(|| "-".into()),
            ));
            fields.push((
                "target_port",
                requested_port.map_or_else(|| "-".into(), |port| port.to_string()),
            ));
            fields.push(("reason", reason.clone()));
        }
        Event::ShutdownStarted { remaining_sessions } => {
            fields.push(("remaining_sessions", remaining_sessions.to_string()));
        }
        Event::SessionsDrained => {}
        Event::ConnectionEstablished {
            conn_id,
            client_addr,
            requested_target,
            requested_port,
            resolved_upstream,
        } => {
            fields.push(("conn_id", conn_id.clone()));
            fields.push(("client_addr", client_addr.to_string()));
            fields.push(("requested_target", requested_target.clone()));
            fields.push(("requested_port", requested_port.to_string()));
            fields.push((
                "resolved_upstream",
                resolved_upstream.map_or_else(|| "-".into(), |a| a.to_string()),
            ));
        }
        Event::ConnectionClosed {
            conn_id,
            requested_target,
            requested_port,
            bytes_client_to_server,
            bytes_server_to_client,
            duration,
            reason,
        } => {
            fields.push(("conn_id", conn_id.clone()));
            fields.push(("requested_target", requested_target.clone()));
            fields.push(("requested_port", requested_port.to_string()));
            fields.push(("bytes_client_to_server", bytes_client_to_server.to_string()));
            fields.push(("bytes_server_to_client", bytes_server_to_client.to_string()));
            fields.push(("duration_ms", duration.as_millis().to_string()));
            fields.push(("reason", reason.clone()));
        }
    }

    let ts = now_epoch().as_millis();
    let mut line = String::from("{\"ts_ms\":");
    line.push_str(&ts.to_string());
    for (key, value) in fields {
        line.push_str(",\"");
        line.push_str(key);
        line.push_str("\":\"");
        escape_into(&mut line, &value);
        line.push('"');
    }
    line.push('}');
    line
}

fn event_name(event: &Event) -> &'static str {
    match event {
        Event::ListenerStarted { .. } => "listener_started",
        Event::ListenerStopped => "listener_stopped",
        Event::SessionAccepted { .. } => "session_accepted",
        Event::SessionRejected { .. } => "session_rejected",
        Event::ShutdownStarted { .. } => "shutdown_started",
        Event::SessionsDrained => "sessions_drained",
        Event::ConnectionEstablished { .. } => "connection_established",
        Event::ConnectionClosed { .. } => "connection_closed",
    }
}

fn escape_into(out: &mut String, value: &str) {
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
}
