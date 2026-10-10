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
                        Ok(collected)
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
