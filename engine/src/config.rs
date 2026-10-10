//! Runtime configuration for the Phase 1A relay.
//!
//! Phase 1A is loopback-only (`CURRENT_TASK.md`, Listener): a non-loopback bind
//! is rejected rather than merely warned about, so the engine cannot be exposed
//! to the network by an accidental flag.

use std::fmt;
use std::net::IpAddr;
use std::time::Duration;

/// Default listener endpoint.
pub const DEFAULT_BIND: IpAddr = IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
/// Default SOCKS5 listener port.
pub const DEFAULT_PORT: u16 = 1080;
/// Default per-connection upstream connect timeout.
pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Default deadline for the whole SOCKS greeting + request exchange.
pub const DEFAULT_NEGOTIATION_TIMEOUT: Duration = Duration::from_secs(5);
/// Default cap on concurrent SOCKS sessions (bounds memory per Phase 1A).
pub const DEFAULT_MAX_CONNECTIONS: usize = 128;
/// Default per-direction relay buffer. Bounded: bytes are never accumulated.
pub const DEFAULT_BUFFER_BYTES: usize = 16 * 1024;

/// Validated relay configuration.
#[derive(Debug, Clone)]
pub struct RelayConfig {
    /// Listener address. Must be loopback in Phase 1A.
    pub bind_addr: IpAddr,
    /// Listener port. `0` requests an ephemeral port (used by tests).
    pub port: u16,
    /// Finite timeout for the upstream TCP connect.
    pub connect_timeout: Duration,
    /// Deadline covering greeting and request parsing.
    pub negotiation_timeout: Duration,
    /// Maximum concurrent SOCKS sessions, including ones still negotiating.
    pub max_connections: usize,
    /// Per-direction relay buffer size.
    pub buffer_bytes: usize,
}

impl Default for RelayConfig {
    fn default() -> Self {
        Self {
            bind_addr: DEFAULT_BIND,
            port: DEFAULT_PORT,
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            negotiation_timeout: DEFAULT_NEGOTIATION_TIMEOUT,
            max_connections: DEFAULT_MAX_CONNECTIONS,
            buffer_bytes: DEFAULT_BUFFER_BYTES,
        }
    }
}

impl RelayConfig {
    /// Loopback relay on `127.0.0.1:1080`.
    pub fn loopback_default() -> Self {
        Self::default()
    }

    /// Bind `addr:port`.
    pub fn with_endpoint(mut self, addr: IpAddr, port: u16) -> Self {
        self.bind_addr = addr;
        self.port = port;
        self
    }

    /// Set the upstream connect timeout.
    pub fn with_connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = timeout;
        self
    }

    /// Set the greeting + request deadline.
    pub fn with_negotiation_timeout(mut self, timeout: Duration) -> Self {
        self.negotiation_timeout = timeout;
        self
    }

    /// Set the concurrent session cap.
    pub fn with_max_connections(mut self, max: usize) -> Self {
        self.max_connections = max;
        self
    }

    /// Set the per-direction relay buffer size.
    pub fn with_buffer_bytes(mut self, bytes: usize) -> Self {
        self.buffer_bytes = bytes;
        self
    }

    /// Reject configurations that cannot be served safely.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.max_connections == 0 {
            return Err(ConfigError::ZeroMaxConnections);
        }
        if self.buffer_bytes == 0 {
            return Err(ConfigError::ZeroBufferBytes);
        }
        if self.negotiation_timeout.is_zero() {
            return Err(ConfigError::ZeroNegotiationTimeout);
        }
        if self.connect_timeout.is_zero() {
            return Err(ConfigError::ZeroConnectTimeout);
        }
        if !self.is_loopback() {
            return Err(ConfigError::NonLoopbackBind {
                addr: self.bind_addr,
            });
        }
        Ok(())
    }

    /// True when the listener is bound to a loopback address.
    pub fn is_loopback(&self) -> bool {
        self.bind_addr.is_loopback()
    }
}

/// Configuration validation failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigError {
    ZeroMaxConnections,
    ZeroBufferBytes,
    ZeroNegotiationTimeout,
    ZeroConnectTimeout,
    /// Phase 1A only serves loopback clients.
    NonLoopbackBind {
        addr: IpAddr,
    },
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroMaxConnections => f.write_str("max_connections must be at least 1"),
            Self::ZeroBufferBytes => f.write_str("buffer_bytes must be at least 1"),
            Self::ZeroNegotiationTimeout => {
                f.write_str("negotiation_timeout must be greater than zero")
            }
            Self::ZeroConnectTimeout => f.write_str("connect_timeout must be greater than zero"),
            Self::NonLoopbackBind { addr } => {
                write!(f, "Phase 1A binds loopback only; refusing to bind {addr}")
            }
        }
    }
}

impl std::error::Error for ConfigError {}
