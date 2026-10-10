//! SOCKS5 reply encoding (`VER REP RSV ATYP BND.ADDR BND.PORT`).
//!
//! Success replies report the local endpoint of the engine's own upstream
//! socket (RFC 1928 §6 BND.ADDR/BND.PORT), not the SOCKS listener the client
//! happens to be talking to. Failure replies echo the accepted socket's local
//! endpoint so the frame stays syntactically valid.

use std::net::SocketAddr;

use tokio::io::{AsyncWrite, AsyncWriteExt};

use crate::socks5::greeting::SOCKS_VERSION;
use crate::socks5::request::{ATYP_DOMAIN, ATYP_IPV4, ATYP_IPV6};

/// Maximum domain length accepted in a reply bound-address field.
const MAX_DOMAIN: usize = 255;

/// Encode and write a SOCKS5 reply for the given bound endpoint.
///
/// `code` is an RFC 1928 reply code; on failure the bound address is still
/// syntactically valid so the client can parse the reply.
pub async fn write_reply<W>(
    writer: &mut W,
    code: u8,
    bind_addr: SocketAddr,
) -> Result<(), std::io::Error>
where
    W: AsyncWrite + Unpin,
{
    let buffer = encode_reply(code, bind_addr);
    writer.write_all(&buffer).await?;
    writer.flush().await
}

/// Build the 10-or-more byte reply frame for `code` and `bind_addr`.
pub fn encode_reply(code: u8, bind_addr: SocketAddr) -> Vec<u8> {
    let mut out = Vec::with_capacity(22);
    out.push(SOCKS_VERSION);
    out.push(code);
    out.push(0x00); // RSV

    match bind_addr.ip() {
        std::net::IpAddr::V4(v4) => {
            out.push(ATYP_IPV4);
            out.extend_from_slice(&v4.octets());
        }
        std::net::IpAddr::V6(v6) => {
            out.push(ATYP_IPV6);
            out.extend_from_slice(&v6.octets());
        }
    }

    out.extend_from_slice(&bind_addr.port().to_be_bytes());
    out
}

/// Build a reply frame whose bound address uses the domain form.
///
/// Provided for completeness; Phase 1A replies use the address literal form.
/// Truncation is by bytes on a character boundary, so the length byte always
/// matches the emitted bytes and multibyte characters are never split.
#[allow(dead_code)]
pub fn encode_reply_with_domain(code: u8, host: &str, port: u16) -> Vec<u8> {
    let mut out = Vec::with_capacity(7 + host.len().min(MAX_DOMAIN));
    out.push(SOCKS_VERSION);
    out.push(code);
    out.push(0x00);
    let mut end = host.len().min(MAX_DOMAIN);
    while !host.is_char_boundary(end) {
        end -= 1;
    }
    out.push(ATYP_DOMAIN);
    out.push(end as u8);
    out.extend_from_slice(&host.as_bytes()[..end]);
    out.extend_from_slice(&port.to_be_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_reply_length_matches_emitted_bytes() {
        // ASCII host longer than the one-byte length field truncates to 255.
        let long = "a".repeat(300);
        let frame = encode_reply_with_domain(0x00, &long, 80);
        assert_eq!(frame[3], ATYP_DOMAIN);
        assert_eq!(frame[4], 255);
        assert_eq!(&frame[5..5 + 255], long.as_bytes()[..255].as_ref());
        assert_eq!(frame[5 + 255..], 80u16.to_be_bytes());

        // Multibyte host: length byte matches emitted bytes and no char is split.
        let wide = "é".repeat(200); // 400 bytes in UTF-8
        let frame = encode_reply_with_domain(0x00, &wide, 443);
        let len = usize::from(frame[4]);
        assert!(len <= MAX_DOMAIN);
        let body = std::str::from_utf8(&frame[5..5 + len]).expect("valid prefix");
        assert_eq!(frame[5 + len..], 443u16.to_be_bytes());
        assert!(body.chars().all(|c| c == 'é'));
    }
}
