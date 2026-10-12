//! # Phase 1A — Standalone SOCKS5 CONNECT relay
//!
//! Proves the data path `SOCKS5 client -> 127.0.0.1:1080 -> engine -> TCP target`
//! with correct byte-stream semantics.
//!
//! Scope boundary (see `ARCHITECTURE.md` and `CURRENT_TASK.md`): this crate
//! contains **no** TLS, certificate, Burp/Montoya, persistence, UDP,
//! or protocol decoding beyond the RFC 1928 subset required for CONNECT.
//! Traffic editing is likewise absent from the default path: the passive
//! relay copies bytes verbatim. Phase 3 adds **opt-in** manual interception
//! via the [`intercept`] module — a control plane may hold a read unit per
//! direction and decide `Forward`/`Replace`/`Suppress`/`Close` — which is
//! disabled by default; a relay that never enables it behaves exactly like
//! the passive engine.

pub mod config;
pub mod connection;
pub mod error;
pub mod history;
pub mod intercept;
pub mod ipc;
pub mod listener;
pub mod repeater;
pub mod socks5;
pub mod telemetry;
pub mod transport;

pub use config::{ConfigError, RelayConfig};
pub use connection::{ConnectionRegistry, ConnectionState};
pub use error::{ServeError, SocksError};
pub use history::{
    hex_view, text_view, ConnectionClose, ConnectionOpen, ConnectionRecord, Direction,
    HistoryLimits, HistorySink, MemoryHistory, SessionObserver, SharedHistory, TrafficChunk,
};
pub use intercept::{
    DecisionError, HeldUnit, InterceptAction, InterceptCoordinator, InterceptLimits,
};
pub use ipc::{IpcHandle, PROTOCOL_VERSION};
pub use listener::{serve, spawn_relay, spawn_relay_with, RunningRelay};
pub use telemetry::{
    memory_telemetry, Event, MemoryTelemetry, SharedTelemetry, StderrTelemetry, Telemetry,
};
pub use transport::{RelayOutcome, UpstreamConnection};
