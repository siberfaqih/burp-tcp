//! Error types and RFC 1928 reply-code mapping.

use std::io;
use std::time::Duration;

/// RFC 1928 §6 SOCKS5 reply codes used by this engine.
pub mod reply {
    pub const SUCCEEDED: u8 = 0x00;
    pub const GENERAL_FAILURE: u8 = 0x01;
    pub const HOST_UNREACHABLE: u8 = 0x04;
    pub const CONNECTION_REFUSED: u8 = 0x05;
    pub const COMMAND_NOT_SUPPORTED: u8 = 0x07;
    pub const ADDRESS_TYPE_NOT_SUPPORTED: u8 = 0x08;
}

/// Failure while negotiating or establishing a SOCKS5 CONNECT.
#[derive(Debug)]
pub enum SocksError {
    /// Peer did not present SOCKS version 5. No valid reply can be framed.
    UnsupportedVersion { found: u8 },
    /// Structurally invalid greeting (e.g. zero-length method list).
    InvalidGreeting { reason: &'static str },
    /// Peer offered no method the engine accepts. `05 FF` is sent, then close.
    NoAcceptableMethod,
    /// CONNECT failed. Always answered with an explicit reply code.
    Connect { code: u8, detail: String },
    /// Command other than CONNECT. Answered with `COMMAND_NOT_SUPPORTED`.
    UnsupportedCommand { command: u8 },
    /// Address type other than IPv4/domain. Answered with
    /// `ADDRESS_TYPE_NOT_SUPPORTED`.
    UnsupportedAddressType { atyp: u8 },
    /// Request framing violated RFC 1928 (e.g. non-zero reserved byte).
    /// Answered with `GENERAL_FAILURE`: the request was understood as SOCKS5
    /// but is not well-formed.
    MalformedRequest { reason: &'static str },
    /// Domain field was empty or otherwise unusable.
    MalformedDomain { reason: &'static str },
    /// Negotiation or upstream dial exceeded its deadline.
    Timeout { stage: &'static str },
    /// Greeting or request parsing exceeded the negotiation deadline.
    ///
    /// No reply is framed: the client may not have finished its greeting, and
    /// RFC 1928 defines no reply code for a stalled client.
    NegotiationTimeout { after: Duration },
    /// Engine shutdown cut the session short.
    EngineShutdown,
    /// Transport error while negotiating.
    Io(io::Error),
}

impl SocksError {
    /// RFC 1928 reply code to send, or `None` when the session must be closed
    /// without a framed reply (version mismatch / no acceptable method).
    pub fn reply_code(&self) -> Option<u8> {
        match self {
            Self::UnsupportedVersion { .. } | Self::InvalidGreeting { .. } => None,
            Self::NoAcceptableMethod => None,
            Self::Connect { code, .. } => Some(*code),
            Self::UnsupportedCommand { .. } => Some(reply::COMMAND_NOT_SUPPORTED),
            Self::UnsupportedAddressType { .. } | Self::MalformedDomain { .. } => {
                Some(reply::ADDRESS_TYPE_NOT_SUPPORTED)
            }
            Self::MalformedRequest { .. } | Self::Io(_) => Some(reply::GENERAL_FAILURE),
            Self::Timeout { .. } => Some(reply::HOST_UNREACHABLE),
            Self::NegotiationTimeout { .. } | Self::EngineShutdown => None,
        }
    }

    /// Short operator-facing reason recorded in lifecycle logs.
    pub fn reason(&self) -> String {
        match self {
            Self::UnsupportedVersion { found } => format!("unsupported socks version {found}"),
            Self::InvalidGreeting { reason } => (*reason).to_owned(),
            Self::NoAcceptableMethod => "no acceptable authentication method".to_owned(),
            Self::Connect { detail, .. } => detail.clone(),
            Self::UnsupportedCommand { command } => format!("unsupported command 0x{command:02x}"),
            Self::UnsupportedAddressType { atyp } => {
                format!("unsupported address type 0x{atyp:02x}")
            }
            Self::MalformedDomain { reason } => (*reason).to_owned(),
            Self::MalformedRequest { reason } => (*reason).to_owned(),
            Self::Timeout { stage } => format!("{stage} timeout"),
            Self::NegotiationTimeout { after } => {
                format!("negotiation timeout after {}ms", after.as_millis())
            }
            Self::EngineShutdown => "engine shutdown".to_owned(),
            Self::Io(error) => error.to_string(),
        }
    }
}

impl std::fmt::Display for SocksError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.reason())
    }
}

impl std::error::Error for SocksError {}

impl From<io::Error> for SocksError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

/// Failure to start or run the listener.
#[derive(Debug)]
pub enum ServeError {
    /// Listener could not bind, e.g. the port is already in use.
    Bind { addr: String, source: io::Error },
    /// Listener bind address could not be queried.
    LocalAddr(io::Error),
    /// IPC (WebSocket control-plane) listener could not bind.
    IpcBind { addr: String, source: io::Error },
}

impl std::fmt::Display for ServeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Bind { addr, source } => {
                write!(f, "cannot bind SOCKS5 listener on {addr}: {source}")
            }
            Self::LocalAddr(source) => write!(f, "cannot query listener address: {source}"),
            Self::IpcBind { addr, source } => {
                write!(f, "cannot bind IPC listener on {addr}: {source}")
            }
        }
    }
}

impl std::error::Error for ServeError {}
