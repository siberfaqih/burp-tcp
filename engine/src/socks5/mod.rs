//! RFC 1928 SOCKS5 subset required for Phase 1A.
//!
//! Only the CONNECT command with IPv4 and domain destinations is supported.
//! Parsing is incremental and tolerant of TCP segmentation: every field is
//! produced by a loop of bounded reads, never by assuming one `read()` returns a
//! complete structure. Per `CLEANROOM_RE_FINDINGS.md`, no IPv6, BIND, or
//! UDP ASSOCIATE support is included.

pub mod greeting;
pub mod reply;
pub mod request;

pub use greeting::{
    select_method, Greeting, METHOD_NONE_ACCEPTABLE, METHOD_NO_AUTH, SOCKS_VERSION,
};
pub use reply::write_reply;
pub use request::{ConnectRequest, RequestTarget, CMD_CONNECT};
