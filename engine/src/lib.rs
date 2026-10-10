//! # Phase 1A — Standalone SOCKS5 CONNECT relay
//!
//! Proves the data path `SOCKS5 client -> 127.0.0.1:1080 -> engine -> TCP target`
//! with correct byte-stream semantics.
//!
//! Scope boundary (see `ARCHITECTURE.md` and `CURRENT_TASK.md`): this crate
//! contains **no** TLS, certificate, Burp/Montoya, replay, persistence, traffic
//! editing, UDP, or protocol decoding beyond the RFC 1928 subset required for
//! CONNECT.

pub mod config;
pub mod connection;
pub mod error;
pub mod listener;
pub mod socks5;
pub mod telemetry;
pub mod transport;

pub use config::{ConfigError, RelayConfig};
pub use connection::{ConnectionRegistry, ConnectionState};
pub use error::{ServeError, SocksError};
pub use listener::{serve, spawn_relay, spawn_relay_with, RunningRelay};
pub use telemetry::{
    memory_telemetry, Event, MemoryTelemetry, SharedTelemetry, StderrTelemetry, Telemetry,
};
pub use transport::{RelayOutcome, UpstreamConnection};
