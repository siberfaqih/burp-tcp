//! Local Phase 1A test lab: TCP fixtures, deterministic payloads, and a
//! SOCKS5-aware client.

pub mod fixtures;
pub mod payloads;
pub mod socks_client;

pub use fixtures::{
    echo_server, flood_server, half_close_server, login_server, read_then_silent_server,
    recording_half_close_server, refused_endpoint, server_first_server, server_first_server_on,
    silent_server, Fixture, ReadThenSilentServer, RecordingServer,
};
pub use payloads::{
    count_nuls, deterministic_payload, AUTH_OK_RESPONSE, BINARY_SAMPLE, LOGIN_REQUEST,
};
pub use socks_client::{
    connect_through_proxy, encode_request, greeting, open, read_reply, send_domain_with_length,
    send_raw_command, send_request, Destination, GreetingStyle, Reply, RequestStyle,
};
