//! Minimal SOCKS5-aware client for exercising the relay.
//!
//! Deliberately configurable so tests can force TCP segmentation (byte-at-a-time
//! greeting and request), choose the command, or use unsupported address types.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// SOCKS5 constants used by the test client.
pub mod consts {
    pub const VERSION: u8 = 0x05;
    pub const METHOD_NO_AUTH: u8 = 0x00;
    pub const METHOD_USERPASS: u8 = 0x02;
    pub const CMD_CONNECT: u8 = 0x01;
    pub const CMD_BIND: u8 = 0x02;
    pub const CMD_UDP_ASSOCIATE: u8 = 0x03;
    pub const ATYP_IPV4: u8 = 0x01;
    pub const ATYP_DOMAIN: u8 = 0x03;
    pub const ATYP_IPV6: u8 = 0x04;

    pub const REP_SUCCEEDED: u8 = 0x00;
    pub const REP_GENERAL_FAILURE: u8 = 0x01;
    pub const REP_COMMAND_NOT_SUPPORTED: u8 = 0x07;
    pub const REP_ADDRESS_TYPE_NOT_SUPPORTED: u8 = 0x08;
}

/// How the greeting should be presented to the relay.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GreetingStyle {
    /// Normal single-write greeting.
    Single,
    /// Write the greeting one byte at a time (worst-case segmentation).
    ByteByByte,
}

/// Destination encoding for the CONNECT request.
#[derive(Debug, Clone)]
pub enum Destination {
    /// IPv4 literal.
    Ipv4(Ipv4Addr),
    /// IPv4 address supplied as a generic [`IpAddr`]; must be IPv4.
    Ip(IpAddr),
    /// Domain name.
    Domain(String),
    /// Raw IPv6 bytes, to assert rejection.
    Ipv6([u8; 16]),
}

/// How the request should be presented to the relay.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestStyle {
    /// Normal single-write request.
    Single,
    /// Write the request one byte at a time.
    ByteByByte,
    /// Write the request in three chunks.
    Chunked,
}

/// A decoded SOCKS5 reply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reply {
    /// RFC 1928 reply code.
    pub code: u8,
    /// Bound address as reported by the proxy.
    pub bind_addr: SocketAddr,
}

impl Reply {
    /// True when the reply reported success.
    pub fn is_success(&self) -> bool {
        self.code == consts::REP_SUCCEEDED
    }
}

/// Connect to the relay and return the raw socket without negotiating.
pub async fn open(proxy: SocketAddr) -> std::io::Result<TcpStream> {
    TcpStream::connect(proxy).await
}

/// Send only a greeting and return the selected method byte.
pub async fn greeting(
    stream: &mut TcpStream,
    style: GreetingStyle,
    methods: &[u8],
) -> std::io::Result<u8> {
    let mut frame = vec![consts::VERSION, methods.len() as u8];
    frame.extend_from_slice(methods);

    match style {
        GreetingStyle::Single => {
            stream.write_all(&frame).await?;
        }
        GreetingStyle::ByteByByte => {
            for byte in &frame {
                stream.write_all(std::slice::from_ref(byte)).await?;
                stream.flush().await?;
                tokio::task::yield_now().await;
            }
        }
    }
    stream.flush().await?;

    let mut response = [0u8; 2];
    stream.read_exact(&mut response).await?;
    if response[0] != consts::VERSION {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("unexpected reply version 0x{:02x}", response[0]),
        ));
    }
    Ok(response[1])
}

/// Encode a CONNECT request for `destination` and `port`.
pub fn encode_request(destination: &Destination, port: u16) -> Vec<u8> {
    let mut out = vec![consts::VERSION, consts::CMD_CONNECT, 0x00];
    match destination {
        Destination::Ipv4(address) => {
            out.push(consts::ATYP_IPV4);
            out.extend_from_slice(&address.octets());
        }
        Destination::Ip(IpAddr::V4(address)) => {
            out.push(consts::ATYP_IPV4);
            out.extend_from_slice(&address.octets());
        }
        Destination::Ip(IpAddr::V6(octets)) => {
            out.push(consts::ATYP_IPV6);
            out.extend_from_slice(&octets.octets());
        }
        Destination::Domain(name) => {
            out.push(consts::ATYP_DOMAIN);
            out.push(name.len() as u8);
            out.extend_from_slice(name.as_bytes());
        }
        Destination::Ipv6(octets) => {
            out.push(consts::ATYP_IPV6);
            out.extend_from_slice(octets);
        }
    }
    out.extend_from_slice(&port.to_be_bytes());
    out
}

/// Send a raw CONNECT request with the requested segmentation style.
pub async fn send_request(
    stream: &mut TcpStream,
    destination: &Destination,
    port: u16,
    style: RequestStyle,
) -> std::io::Result<()> {
    let frame = encode_request(destination, port);
    match style {
        RequestStyle::Single => stream.write_all(&frame).await?,
        RequestStyle::ByteByByte => {
            for byte in &frame {
                stream.write_all(std::slice::from_ref(byte)).await?;
                stream.flush().await?;
                tokio::task::yield_now().await;
            }
        }
        RequestStyle::Chunked => {
            let third = frame.len() / 3;
            stream.write_all(&frame[..third]).await?;
            stream.flush().await?;
            tokio::task::yield_now().await;
            stream.write_all(&frame[third..2 * third]).await?;
            stream.flush().await?;
            tokio::task::yield_now().await;
            stream.write_all(&frame[2 * third..]).await?;
        }
    }
    stream.flush().await
}

/// Read and decode a SOCKS5 reply.
pub async fn read_reply(stream: &mut TcpStream) -> std::io::Result<Reply> {
    let mut header = [0u8; 4];
    stream.read_exact(&mut header).await?;
    if header[0] != consts::VERSION {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "reply version was not 5",
        ));
    }
    let code = header[1];

    let addr: IpAddr = match header[3] {
        consts::ATYP_IPV4 => {
            let mut octets = [0u8; 4];
            stream.read_exact(&mut octets).await?;
            IpAddr::V4(Ipv4Addr::from(octets))
        }
        consts::ATYP_IPV6 => {
            let mut octets = [0u8; 16];
            stream.read_exact(&mut octets).await?;
            let mut value = [0u8; 16];
            value.copy_from_slice(&octets);
            IpAddr::from(value)
        }
        consts::ATYP_DOMAIN => {
            let mut length = [0u8; 1];
            stream.read_exact(&mut length).await?;
            let mut name = vec![0u8; usize::from(length[0])];
            stream.read_exact(&mut name).await?;
            // Domain-form replies are not produced by this engine; resolve for
            // comparison purposes only.
            let host = String::from_utf8_lossy(&name).to_string();
            let resolved = tokio::net::lookup_host((host.as_str(), 0u16)).await;
            resolved
                .ok()
                .and_then(|mut addrs| addrs.next())
                .map(|addr| addr.ip())
                .unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST))
        }
        other => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("unknown reply address type 0x{other:02x}"),
            ))
        }
    };

    let mut port = [0u8; 2];
    stream.read_exact(&mut port).await?;
    Ok(Reply {
        code,
        bind_addr: SocketAddr::new(addr, u16::from_be_bytes(port)),
    })
}

/// Perform a full greeting + CONNECT negotiation and return the live socket.
pub async fn connect_through_proxy(
    proxy: SocketAddr,
    destination: Destination,
    port: u16,
    greeting_style: GreetingStyle,
    request_style: RequestStyle,
) -> std::io::Result<TcpStream> {
    let mut stream = open(proxy).await?;
    let method = greeting(&mut stream, greeting_style, &[consts::METHOD_NO_AUTH]).await?;
    if method != consts::METHOD_NO_AUTH {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("proxy selected method 0x{method:02x}"),
        ));
    }
    send_request(&mut stream, &destination, port, request_style).await?;
    let reply = read_reply(&mut stream).await?;
    if !reply.is_success() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            format!("proxy returned reply 0x{:02x}", reply.code),
        ));
    }
    Ok(stream)
}

/// Send a request with a non-CONNECT command byte.
pub async fn send_raw_command(stream: &mut TcpStream, command: u8) -> std::io::Result<()> {
    let mut frame = vec![consts::VERSION, command, 0x00, consts::ATYP_IPV4];
    frame.extend_from_slice(&[127, 0, 0, 1]);
    frame.extend_from_slice(&9u16.to_be_bytes());
    stream.write_all(&frame).await?;
    stream.flush().await
}

/// Send a domain request with an explicit length byte (for malformed tests).
pub async fn send_domain_with_length(
    stream: &mut TcpStream,
    name: &str,
    declared_len: u8,
    port: u16,
) -> std::io::Result<()> {
    let mut frame = vec![
        consts::VERSION,
        consts::CMD_CONNECT,
        0x00,
        consts::ATYP_DOMAIN,
        declared_len,
    ];
    frame.extend_from_slice(name.as_bytes());
    frame.extend_from_slice(&port.to_be_bytes());
    stream.write_all(&frame).await?;
    stream.flush().await
}
