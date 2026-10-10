//! SOCKS5 greeting parsing (`VER NMETHODS METHODS...`).
//!
//! Reads use `read_exact`, which internally loops over partial socket reads and
//! only completes once every required byte has arrived. This is what makes the
//! parser tolerate byte-by-byte segmentation.

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::error::SocksError;

/// SOCKS protocol version supported by this engine.
pub const SOCKS_VERSION: u8 = 0x05;
/// `NO AUTHENTICATION REQUIRED` method identifier.
pub const METHOD_NO_AUTH: u8 = 0x00;
/// `NO ACCEPTABLE METHODS` selection.
pub const METHOD_NONE_ACCEPTABLE: u8 = 0xff;
/// Upper bound on the advertised method list length (single byte on the wire).
pub const MAX_METHODS: usize = 255;

/// A validated client greeting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Greeting {
    methods: Vec<u8>,
}

impl Greeting {
    /// Methods offered by the client, in advertised order.
    pub fn methods(&self) -> &[u8] {
        &self.methods
    }

    /// True when the client offered `NO AUTHENTICATION REQUIRED`.
    pub fn offers_no_auth(&self) -> bool {
        self.methods.contains(&METHOD_NO_AUTH)
    }
}

/// Read and validate a client greeting.
///
/// Rejects non-`0x05` versions and an empty method list.
pub async fn read_greeting<R>(reader: &mut R) -> Result<Greeting, SocksError>
where
    R: AsyncRead + Unpin,
{
    let mut header = [0u8; 2];
    reader.read_exact(&mut header).await?;

    if header[0] != SOCKS_VERSION {
        return Err(SocksError::UnsupportedVersion { found: header[0] });
    }

    let method_count = usize::from(header[1]);
    if method_count == 0 {
        return Err(SocksError::InvalidGreeting {
            reason: "greeting advertised zero authentication methods",
        });
    }

    let mut methods = vec![0u8; method_count];
    reader.read_exact(&mut methods).await?;

    Ok(Greeting { methods })
}

/// Choose a method and write the 2-byte method selection.
///
/// Returns the selected method. `METHOD_NONE_ACCEPTABLE` is written when the
/// client offered nothing the engine supports; the caller must then close the
/// session because no RFC 1928 reply can follow.
pub async fn select_method<W>(writer: &mut W, greeting: &Greeting) -> Result<u8, std::io::Error>
where
    W: AsyncWrite + Unpin,
{
    let method = if greeting.offers_no_auth() {
        METHOD_NO_AUTH
    } else {
        METHOD_NONE_ACCEPTABLE
    };
    writer.write_all(&[SOCKS_VERSION, method]).await?;
    writer.flush().await?;
    Ok(method)
}

/// Write `05 FF` (no acceptable methods) using a byte slice source.
pub async fn write_no_acceptable<W>(writer: &mut W) -> Result<(), std::io::Error>
where
    W: AsyncWrite + Unpin,
{
    writer
        .write_all(&[SOCKS_VERSION, METHOD_NONE_ACCEPTABLE])
        .await?;
    writer.flush().await
}
