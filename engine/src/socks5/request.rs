//! SOCKS5 request parsing (`VER CMD RSV ATYP DST.ADDR DST.PORT`).
//!
//! Every field is filled with `read_exact`, so a request split across any
//! number of TCP segments — including one byte per segment — parses correctly.

use std::fmt;
use std::net::{Ipv4Addr, SocketAddr};

use tokio::io::{AsyncRead, AsyncReadExt};

use crate::error::SocksError;
use crate::socks5::greeting::SOCKS_VERSION;

/// CONNECT command.
pub const CMD_CONNECT: u8 = 0x01;
/// BIND command (rejected in Phase 1A).
pub const CMD_BIND: u8 = 0x02;
/// UDP ASSOCIATE command (rejected in Phase 1A).
pub const CMD_UDP_ASSOCIATE: u8 = 0x03;

/// IPv4 address type.
pub const ATYP_IPV4: u8 = 0x01;
/// Domain-name address type.
pub const ATYP_DOMAIN: u8 = 0x03;
/// IPv6 address type (rejected in Phase 1A).
pub const ATYP_IPV6: u8 = 0x04;

/// Maximum domain length, bounded by the single on-wire length byte.
pub const MAX_DOMAIN_BYTES: usize = 255;

/// Requested destination as supplied by the client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestTarget {
    /// IPv4 literal destination.
    Ipv4(Ipv4Addr),
    /// Domain name to resolve with the host OS resolver.
    Domain(String),
}

impl RequestTarget {
    /// The target exactly as requested, for lifecycle logging.
    pub fn display(&self) -> String {
        match self {
            Self::Ipv4(address) => address.to_string(),
            Self::Domain(name) => name.clone(),
        }
    }
}

impl fmt::Display for RequestTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.display())
    }
}

/// A validated CONNECT request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectRequest {
    target: RequestTarget,
    port: u16,
}

impl ConnectRequest {
    /// Requested destination.
    pub fn target(&self) -> &RequestTarget {
        &self.target
    }

    /// Requested destination port, decoded from network byte order.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Requested endpoint as an address literal, when the client supplied one.
    pub fn literal_addr(&self) -> Option<SocketAddr> {
        match &self.target {
            RequestTarget::Ipv4(address) => Some(SocketAddr::from((*address, self.port))),
            RequestTarget::Domain(_) => None,
        }
    }
}

/// Read and validate a SOCKS5 request.
///
/// Accepts only CONNECT with an IPv4 or domain destination, per Phase 1A scope.
/// BIND, UDP ASSOCIATE, and IPv6 destinations are rejected with a truthful
/// reply code rather than being silently accepted or rewritten.
pub async fn read_request<R>(reader: &mut R) -> Result<ConnectRequest, SocksError>
where
    R: AsyncRead + Unpin,
{
    let mut header = [0u8; 4];
    reader.read_exact(&mut header).await?;

    if header[0] != SOCKS_VERSION {
        return Err(SocksError::UnsupportedVersion { found: header[0] });
    }

    // RFC 1928 §4: the reserved byte must be X'00'. A non-zero RSV means the
    // frame is not a well-formed SOCKS5 request.
    if header[2] != 0x00 {
        return Err(SocksError::MalformedRequest {
            reason: "request reserved byte was not zero",
        });
    }

    let command = header[1];
    if command != CMD_CONNECT {
        // BIND and UDP ASSOCIATE are both out of scope for this phase.
        return Err(SocksError::UnsupportedCommand { command });
    }

    let atyp = header[3];
    let target = match atyp {
        ATYP_IPV4 => {
            let mut octets = [0u8; 4];
            reader.read_exact(&mut octets).await?;
            RequestTarget::Ipv4(Ipv4Addr::from(octets))
        }
        ATYP_DOMAIN => {
            let mut length_byte = [0u8; 1];
            reader.read_exact(&mut length_byte).await?;
            let length = usize::from(length_byte[0]);
            if length == 0 {
                return Err(SocksError::MalformedDomain {
                    reason: "domain name length was zero",
                });
            }
            // `length` came from a single on-wire byte, so it cannot exceed
            // `MAX_DOMAIN_BYTES` (255); the wire format itself is the bound.
            debug_assert!(length <= MAX_DOMAIN_BYTES);
            let mut name = vec![0u8; length];
            reader.read_exact(&mut name).await?;
            let name = String::from_utf8(name).map_err(|_| SocksError::MalformedDomain {
                reason: "domain name was not valid UTF-8/ASCII",
            })?;
            if name.trim().is_empty() {
                return Err(SocksError::MalformedDomain {
                    reason: "domain name was empty after trimming",
                });
            }
            RequestTarget::Domain(name)
        }
        ATYP_IPV6 => {
            // Phase 1A excludes IPv6. Drain is unnecessary: we reject and close.
            return Err(SocksError::UnsupportedAddressType { atyp });
        }
        other => {
            return Err(SocksError::UnsupportedAddressType { atyp: other });
        }
    };

    let mut port_bytes = [0u8; 2];
    reader.read_exact(&mut port_bytes).await?;
    let port = u16::from_be_bytes(port_bytes);

    Ok(ConnectRequest { target, port })
}
