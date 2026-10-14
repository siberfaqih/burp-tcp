//! Upstream TCP dialing with the host OS resolver and a finite timeout.

use std::net::SocketAddr;
use std::time::Duration;

use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::error::{reply, SocksError};
use crate::socks5::request::RequestTarget;

/// Bound on name resolution, independent of the per-address connect timeout.
const RESOLVE_TIMEOUT: Duration = Duration::from_secs(10);

/// A successfully established upstream connection.
#[derive(Debug)]
pub struct UpstreamConnection {
    /// The connected stream.
    pub stream: TcpStream,
    /// The endpoint actually dialled after resolution, for logging.
    pub resolved_addr: SocketAddr,
}

/// Establish a TCP connection to the requested destination.
///
/// Domains are resolved with the host OS resolver. A finite timeout covers both
/// resolution and connect, so a stalled target cannot pin a session forever.
pub async fn dial_upstream(
    target: &RequestTarget,
    port: u16,
    connect_timeout: Duration,
) -> Result<UpstreamConnection, SocksError> {
    let addrs = resolve(target, port).await?;
    connect_first(addrs, connect_timeout).await
}

/// Establish a TCP connection to a Burp Proxy listener for a routed session.
///
/// The original SOCKS destination is preserved in history; only the dial
/// target changes. A refused listener surfaces as `CONNECTION_REFUSED` so
/// the client sees the same reply shape as a refused upstream.
pub async fn dial_burp(
    burp_addr: SocketAddr,
    connect_timeout: Duration,
) -> Result<UpstreamConnection, SocksError> {
    connect_first(vec![burp_addr], connect_timeout).await
}

async fn resolve(target: &RequestTarget, port: u16) -> Result<Vec<SocketAddr>, SocksError> {
    match target {
        RequestTarget::Ipv4(address) => Ok(vec![SocketAddr::from((*address, port))]),
        RequestTarget::Domain(name) => {
            let lookup = format!("{name}:{port}");
            let resolved = timeout(RESOLVE_TIMEOUT, tokio::net::lookup_host(lookup.as_str())).await;
            match resolved {
                Err(_) => Err(SocksError::Timeout {
                    stage: "upstream resolve",
                }),
                Ok(Ok(mut addrs)) => {
                    let collected: Vec<SocketAddr> = addrs.by_ref().collect();
                    if collected.is_empty() {
                        Err(SocksError::Connect {
                            code: reply::HOST_UNREACHABLE,
                            detail: format!("no address returned for {name}"),
                        })
                    } else {
                        retain_ipv4(name, collected)
                    }
                }
                Ok(Err(error)) => Err(SocksError::Connect {
                    code: reply::HOST_UNREACHABLE,
                    detail: format!("failed to resolve {name}: {error}"),
                }),
            }
        }
    }
}

/// Keep only the IPv4 candidates from a resolved address list.
///
/// Phase 1A rejects IPv6 destinations (`CURRENT_TASK.md`, Negotiation): an
/// `ATYP_IPV6` literal is answered with `ADDRESS_TYPE_NOT_SUPPORTED`, so an
/// IPv6 address obtained through resolution must not be dialled either.
/// Without this, a domain resolving to both families (e.g. `localhost` ->
/// `::1` + `127.0.0.1`) could establish an IPv6 upstream while IPv6 literals
/// are refused, and the success reply would carry an IPv6 bound endpoint.
/// A name resolving solely to IPv6 is rejected with
/// `ADDRESS_TYPE_NOT_SUPPORTED` rather than dialled.
fn retain_ipv4(name: &str, addrs: Vec<SocketAddr>) -> Result<Vec<SocketAddr>, SocksError> {
    let v4: Vec<SocketAddr> = addrs.into_iter().filter(|addr| addr.is_ipv4()).collect();
    if v4.is_empty() {
        Err(SocksError::Connect {
            code: reply::ADDRESS_TYPE_NOT_SUPPORTED,
            detail: format!("no IPv4 address returned for {name}"),
        })
    } else {
        Ok(v4)
    }
}

async fn connect_first(
    addrs: Vec<SocketAddr>,
    connect_timeout: Duration,
) -> Result<UpstreamConnection, SocksError> {
    let mut last_error: Option<SocksError> = None;

    for addr in addrs {
        match timeout(connect_timeout, TcpStream::connect(addr)).await {
            Ok(Ok(stream)) => {
                return Ok(UpstreamConnection {
                    stream,
                    resolved_addr: addr,
                })
            }
            Ok(Err(error)) => {
                let code = if error.kind() == std::io::ErrorKind::ConnectionRefused {
                    reply::CONNECTION_REFUSED
                } else if error.kind() == std::io::ErrorKind::TimedOut {
                    reply::HOST_UNREACHABLE
                } else {
                    reply::GENERAL_FAILURE
                };
                last_error = Some(SocksError::Connect {
                    code,
                    detail: format!("failed to connect to {addr}: {error}"),
                });
            }
            Err(_) => {
                last_error = Some(SocksError::Connect {
                    code: reply::HOST_UNREACHABLE,
                    detail: format!("connect to {addr} timed out"),
                });
            }
        }
    }

    Err(last_error.unwrap_or(SocksError::Connect {
        code: reply::HOST_UNREACHABLE,
        detail: "no upstream address available".into(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn mixed_resolution_keeps_ipv4_candidates_in_order() {
        let addrs = vec![
            SocketAddr::from((Ipv6Addr::LOCALHOST, 1433)),
            SocketAddr::from((Ipv4Addr::LOCALHOST, 1433)),
            SocketAddr::from((Ipv4Addr::new(192, 168, 1, 18), 1433)),
        ];
        let kept = retain_ipv4("localhost", addrs).expect("IPv4 candidates exist");
        assert_eq!(
            kept,
            vec![
                SocketAddr::from((Ipv4Addr::LOCALHOST, 1433)),
                SocketAddr::from((Ipv4Addr::new(192, 168, 1, 18), 1433)),
            ]
        );
    }

    #[test]
    fn ipv6_only_resolution_is_rejected_as_address_type() {
        let addrs = vec![
            SocketAddr::from((Ipv6Addr::LOCALHOST, 1433)),
            SocketAddr::from((Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1), 80)),
        ];
        let error = retain_ipv4("v6-only.example", addrs).expect_err("must reject");
        assert_eq!(error.reply_code(), Some(reply::ADDRESS_TYPE_NOT_SUPPORTED));
    }
}
