//! Phase 1A integration tests: SOCKS5 negotiation, upstream connection,
//! byte-exact bidirectional forwarding, half-close, concurrency, and shutdown.
//!
//! Required cases from `CURRENT_TASK.md` §Test cases are numbered in comments.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;

use rawtcp_engine::telemetry::memory_telemetry;
use rawtcp_engine::telemetry::{Event, MemoryTelemetry};
use rawtcp_engine::{spawn_relay_with, ConnectionRegistry, RelayConfig};
use testlab::socks_client::{self, consts, Destination, GreetingStyle, RequestStyle};
use testlab::{count_nuls, deterministic_payload, BINARY_SAMPLE, LOGIN_REQUEST};

/// Relay + telemetry pair used by most tests.
struct Harness {
    relay: rawtcp_engine::RunningRelay,
    telemetry: Arc<MemoryTelemetry>,
    proxy: SocketAddr,
}

impl Harness {
    async fn start() -> Self {
        Self::start_with(RelayConfig::default()).await
    }

    async fn start_with(config: RelayConfig) -> Self {
        let (sink, shared) = rawtcp_engine::telemetry::memory_telemetry();
        let config = config.with_endpoint(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let relay = spawn_relay_with(config, shared).await.expect("relay bind");
        let proxy = relay.local_addr();
        assert!(proxy.ip().is_loopback(), "relay must bind loopback");
        Self {
            relay,
            telemetry: sink,
            proxy,
        }
    }

    async fn shutdown(self) {
        self.relay.shutdown().await;
    }

    fn closed_events(&self) -> Vec<Event> {
        self.telemetry
            .events()
            .into_iter()
            .filter(|event| matches!(event, Event::ConnectionClosed { .. }))
            .collect()
    }
}

/// Give the relay a moment to finish emitting a close event after a peer EOF.
async fn wait_for_closed(harness: &Harness, expected: usize) -> Vec<Event> {
    for _ in 0..200 {
        let closed = harness.closed_events();
        if closed.len() >= expected {
            return closed;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    harness.closed_events()
}

/// Accept happens on the engine task, so slot reservations land asynchronously.
async fn wait_for_active(registry: &ConnectionRegistry, expected: usize) {
    for _ in 0..200 {
        if registry.active() == expected {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

fn closed_counters(event: &Event) -> (u64, u64) {
    match event {
        Event::ConnectionClosed {
            bytes_client_to_server,
            bytes_server_to_client,
            ..
        } => (*bytes_client_to_server, *bytes_server_to_client),
        other => panic!("not a close event: {other:?}"),
    }
}

// --- 1. SOCKS greeting --------------------------------------------------------

/// Case 1 (part a): greeting split byte-by-byte is still parsed correctly.
#[tokio::test]
async fn greeting_split_byte_by_byte_is_parsed() {
    let harness = Harness::start().await;
    let echo = testlab::echo_server().await;

    let mut stream = socks_client::open(harness.proxy).await.expect("open");
    let method = socks_client::greeting(
        &mut stream,
        GreetingStyle::ByteByByte,
        &[consts::METHOD_NO_AUTH],
    )
    .await
    .expect("greeting");
    assert_eq!(method, consts::METHOD_NO_AUTH);

    socks_client::send_request(
        &mut stream,
        &Destination::Ip(echo.addr().ip()),
        echo.addr().port(),
        RequestStyle::Single,
    )
    .await
    .expect("request");

    let reply = socks_client::read_reply(&mut stream).await.expect("reply");
    assert!(
        reply.is_success(),
        "expected success, got 0x{:02x}",
        reply.code
    );

    harness.shutdown().await;
    echo.shutdown().await;
}

/// Greeting offering only an unsupported method is rejected with `05 FF`.
#[tokio::test]
async fn greeting_without_acceptable_method_is_rejected() {
    let harness = Harness::start().await;

    let mut stream = socks_client::open(harness.proxy).await.expect("open");
    let method = socks_client::greeting(
        &mut stream,
        GreetingStyle::Single,
        &[consts::METHOD_USERPASS],
    )
    .await
    .expect("greeting reply");
    assert_eq!(method, 0xff, "expected NO ACCEPTABLE METHODS");

    let closed = wait_for_closed(&harness, 1).await;
    assert!(closed.is_empty(), "no CONNECT should have been established");

    harness.shutdown().await;
}

/// A non-5 version byte closes the session without a framed reply.
#[tokio::test]
async fn unsupported_socks_version_is_rejected() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let harness = Harness::start().await;

    let mut stream = socks_client::open(harness.proxy).await.expect("open");
    stream.write_all(&[0x04, 0x01, 0x00]).await.expect("write");

    // RFC 1928 gives no valid reply frame for a wrong version; expect EOF.
    let mut buf = Vec::new();
    let read = stream.read_to_end(&mut buf).await;
    assert!(
        read.is_err() || buf.is_empty(),
        "unexpected reply bytes {buf:?}"
    );

    harness.shutdown().await;
}

// --- 2 & 3. CONNECT requests, IPv4 and domain ---------------------------------

/// Case 4: CONNECT with an IPv4 destination succeeds and forwards bytes.
#[tokio::test]
async fn ipv4_connect_forwards_both_directions() {
    let harness = Harness::start().await;
    let echo = testlab::echo_server().await;

    let mut stream = socks_client::connect_through_proxy(
        harness.proxy,
        Destination::Ip(echo.addr().ip()),
        echo.addr().port(),
        GreetingStyle::Single,
        RequestStyle::Single,
    )
    .await
    .expect("connect through proxy");

    stream.write_all(BINARY_SAMPLE).await.expect("write");

    use tokio::io::AsyncReadExt;
    let mut received = vec![0u8; BINARY_SAMPLE.len()];
    stream.read_exact(&mut received).await.expect("echo read");
    assert_eq!(received, BINARY_SAMPLE, "binary payload must round-trip");

    drop(stream);
    let closed = wait_for_closed(&harness, 1).await;
    assert_eq!(closed.len(), 1);
    let (c2s, s2c) = closed_counters(&closed[0]);
    assert_eq!(c2s, BINARY_SAMPLE.len() as u64);
    assert_eq!(s2c, BINARY_SAMPLE.len() as u64);

    harness.shutdown().await;
    echo.shutdown().await;
}

/// Case 3: CONNECT with a domain destination resolves via the host resolver.
#[tokio::test]
async fn domain_connect_resolves_via_host_resolver() {
    let harness = Harness::start().await;
    let echo = testlab::echo_server().await;

    let mut stream = socks_client::connect_through_proxy(
        harness.proxy,
        Destination::Domain("localhost".to_owned()),
        echo.addr().port(),
        GreetingStyle::Single,
        RequestStyle::Single,
    )
    .await
    .expect("domain connect");

    stream.write_all(b"ping").await.expect("write");

    use tokio::io::AsyncReadExt;
    let mut received = [0u8; 4];
    stream.read_exact(&mut received).await.expect("read");
    assert_eq!(&received, b"ping");

    drop(stream);
    wait_for_closed(&harness, 1).await;

    // Assert on the established event (destination as requested), not on close
    // events: a client that closes immediately may produce no close event.
    let events = harness.telemetry.events();
    let established = events
        .iter()
        .find(|event| matches!(event, Event::ConnectionEstablished { .. }))
        .expect("established event");
    match established {
        Event::ConnectionEstablished {
            requested_target,
            requested_port,
            resolved_upstream,
            ..
        } => {
            assert_eq!(
                requested_target, "localhost",
                "domain must be logged as requested"
            );
            assert_eq!(*requested_port, echo.addr().port());
            assert!(
                resolved_upstream.is_some(),
                "resolved endpoint must be logged"
            );
        }
        other => panic!("unexpected event: {other:?}"),
    }

    harness.shutdown().await;
    echo.shutdown().await;
}

/// Case 2: CONNECT request split byte-by-byte still parses.
#[tokio::test]
async fn connect_request_split_byte_by_byte_is_parsed() {
    let harness = Harness::start().await;
    let echo = testlab::echo_server().await;

    let mut stream = socks_client::open(harness.proxy).await.expect("open");
    socks_client::greeting(
        &mut stream,
        GreetingStyle::Single,
        &[consts::METHOD_NO_AUTH],
    )
    .await
    .expect("greeting");

    socks_client::send_request(
        &mut stream,
        &Destination::Domain("localhost".to_owned()),
        echo.addr().port(),
        RequestStyle::ByteByByte,
    )
    .await
    .expect("request");

    let reply = socks_client::read_reply(&mut stream).await.expect("reply");
    assert!(reply.is_success());

    drop(stream);
    harness.shutdown().await;
    echo.shutdown().await;
}

// --- 5. Unsupported commands --------------------------------------------------

/// Case 5: BIND and UDP ASSOCIATE are rejected with COMMAND_NOT_SUPPORTED.
#[tokio::test]
async fn unsupported_commands_are_rejected() {
    let harness = Harness::start().await;

    for command in [consts::CMD_BIND, consts::CMD_UDP_ASSOCIATE] {
        let mut stream = socks_client::open(harness.proxy).await.expect("open");
        socks_client::greeting(
            &mut stream,
            GreetingStyle::Single,
            &[consts::METHOD_NO_AUTH],
        )
        .await
        .expect("greeting");

        socks_client::send_raw_command(&mut stream, command)
            .await
            .expect("send command");

        let reply = socks_client::read_reply(&mut stream).await.expect("reply");
        assert_eq!(
            reply.code,
            consts::REP_COMMAND_NOT_SUPPORTED,
            "command 0x{command:02x} must be rejected"
        );
    }

    let closed = wait_for_closed(&harness, 2).await;
    assert!(
        closed.is_empty(),
        "rejected commands must not forward bytes"
    );

    harness.shutdown().await;
}

/// IPv6 destinations are rejected in Phase 1A.
#[tokio::test]
async fn ipv6_destination_is_rejected() {
    let harness = Harness::start().await;

    let mut stream = socks_client::open(harness.proxy).await.expect("open");
    socks_client::greeting(
        &mut stream,
        GreetingStyle::Single,
        &[consts::METHOD_NO_AUTH],
    )
    .await
    .expect("greeting");

    socks_client::send_request(
        &mut stream,
        &Destination::Ipv6([0u8; 16]),
        443,
        RequestStyle::Single,
    )
    .await
    .expect("request");

    let reply = socks_client::read_reply(&mut stream).await.expect("reply");
    assert_eq!(reply.code, consts::REP_ADDRESS_TYPE_NOT_SUPPORTED);

    harness.shutdown().await;
}

/// A domain resolving to both loopback families is dialled over IPv4 only.
///
/// `localhost` resolves to `::1` and `127.0.0.1`. With a banner server on
/// each family sharing one port, the relay must reach the IPv4 server:
/// Phase 1A rejects IPv6, so resolved IPv6 addresses are never dialled.
#[tokio::test]
async fn domain_resolving_to_ipv6_dials_ipv4_only() {
    let v6 = testlab::server_first_server_on("[::1]:0", b"V6".to_vec()).await;
    let port = v6.addr().port();
    let v4 = testlab::server_first_server_on(&format!("127.0.0.1:{port}"), b"V4".to_vec()).await;

    let harness = Harness::start().await;
    let mut stream = socks_client::connect_through_proxy(
        harness.proxy,
        Destination::Domain("localhost".to_owned()),
        port,
        GreetingStyle::Single,
        RequestStyle::Single,
    )
    .await
    .expect("domain connect");

    use tokio::io::AsyncReadExt;
    let mut banner = [0u8; 2];
    stream.read_exact(&mut banner).await.expect("banner");
    assert_eq!(&banner, b"V4", "relay must dial the IPv4 server");

    assert_eq!(v6.accepted(), 0, "IPv6 server must see no connection");
    assert_eq!(v4.accepted(), 1, "IPv4 server must see the connection");

    let events = harness.telemetry.events();
    let established = events
        .iter()
        .find(|event| matches!(event, Event::ConnectionEstablished { .. }))
        .expect("established event");
    match established {
        Event::ConnectionEstablished {
            resolved_upstream, ..
        } => match resolved_upstream {
            Some(addr) => assert!(addr.is_ipv4(), "resolved upstream must be IPv4, got {addr}"),
            None => panic!("resolved endpoint must be logged"),
        },
        other => panic!("unexpected event: {other:?}"),
    }

    drop(stream);
    harness.shutdown().await;
    v6.shutdown().await;
    v4.shutdown().await;
}

/// A zero-length domain is treated as malformed.
#[tokio::test]
async fn zero_length_domain_is_rejected() {
    let harness = Harness::start().await;

    let mut stream = socks_client::open(harness.proxy).await.expect("open");
    socks_client::greeting(
        &mut stream,
        GreetingStyle::Single,
        &[consts::METHOD_NO_AUTH],
    )
    .await
    .expect("greeting");

    socks_client::send_domain_with_length(&mut stream, "", 0, 80)
        .await
        .expect("send domain");

    let reply = socks_client::read_reply(&mut stream).await.expect("reply");
    assert_eq!(reply.code, consts::REP_ADDRESS_TYPE_NOT_SUPPORTED);

    harness.shutdown().await;
}

/// A non-zero reserved byte violates RFC 1928 §4 and is rejected with a
/// general failure instead of being forwarded.
#[tokio::test]
async fn nonzero_reserved_byte_is_rejected() {
    use tokio::io::AsyncWriteExt;
    let harness = Harness::start().await;
    let echo = testlab::echo_server().await;

    let mut stream = socks_client::open(harness.proxy).await.expect("open");
    socks_client::greeting(
        &mut stream,
        GreetingStyle::Single,
        &[consts::METHOD_NO_AUTH],
    )
    .await
    .expect("greeting");

    // A well-formed CONNECT frame with only the RSV byte corrupted.
    let mut frame =
        socks_client::encode_request(&Destination::Ip(echo.addr().ip()), echo.addr().port());
    frame[2] = 0x01;
    stream.write_all(&frame).await.expect("request");
    stream.flush().await.expect("flush");

    let reply = socks_client::read_reply(&mut stream).await.expect("reply");
    assert_eq!(
        reply.code,
        consts::REP_GENERAL_FAILURE,
        "non-zero RSV must be rejected, not forwarded"
    );

    let closed = wait_for_closed(&harness, 1).await;
    assert!(
        closed.is_empty(),
        "a malformed request must not reach forwarding"
    );

    harness.shutdown().await;
    echo.shutdown().await;
}

// --- 6. Upstream failure ------------------------------------------------------

/// Case 6: a refused upstream yields a failure reply and forwards no bytes.
#[tokio::test]
async fn refused_upstream_returns_failure_reply() {
    let harness = Harness::start().await;
    let refused = testlab::refused_endpoint().await;

    let mut stream = socks_client::open(harness.proxy).await.expect("open");
    socks_client::greeting(
        &mut stream,
        GreetingStyle::Single,
        &[consts::METHOD_NO_AUTH],
    )
    .await
    .expect("greeting");

    socks_client::send_request(
        &mut stream,
        &Destination::Ip(refused.ip()),
        refused.port(),
        RequestStyle::Single,
    )
    .await
    .expect("request");

    let reply = socks_client::read_reply(&mut stream).await.expect("reply");
    assert!(
        !reply.is_success(),
        "refused upstream must not report success (got 0x{:02x})",
        reply.code
    );

    harness.shutdown().await;
}

/// A domain that cannot resolve yields a failure reply.
#[tokio::test]
async fn unresolvable_domain_returns_failure_reply() {
    let harness = Harness::start().await;

    let mut stream = socks_client::open(harness.proxy).await.expect("open");
    socks_client::greeting(
        &mut stream,
        GreetingStyle::Single,
        &[consts::METHOD_NO_AUTH],
    )
    .await
    .expect("greeting");

    socks_client::send_request(
        &mut stream,
        &Destination::Domain("invalid.invalid.".to_owned()),
        80,
        RequestStyle::Single,
    )
    .await
    .expect("request");

    let reply = socks_client::read_reply(&mut stream).await.expect("reply");
    assert!(!reply.is_success(), "unresolvable domain must fail");

    harness.shutdown().await;
}

// --- 7 & 8. Binary safety and buffer sizes -----------------------------------

/// Case 7: deterministic random bytes including NULs round-trip unchanged.
#[tokio::test]
async fn deterministic_binary_payload_round_trips() {
    let harness = Harness::start().await;
    let echo = testlab::echo_server().await;
    let payload = deterministic_payload(64 * 1024);
    assert!(
        count_nuls(&payload) > 100,
        "payload must exercise NUL bytes"
    );

    let mut stream = socks_client::connect_through_proxy(
        harness.proxy,
        Destination::Ip(echo.addr().ip()),
        echo.addr().port(),
        GreetingStyle::Single,
        RequestStyle::Single,
    )
    .await
    .expect("connect");

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    stream.write_all(&payload).await.expect("write");

    let mut received = vec![0u8; payload.len()];
    stream.read_exact(&mut received).await.expect("echo read");
    assert_eq!(
        received, payload,
        "64 KiB payload must round-trip unchanged"
    );

    drop(stream);
    harness.shutdown().await;
    echo.shutdown().await;
}

/// Case 8: a payload larger than the relay buffer still round-trips, proving no
/// buffer-boundary assumptions.
#[tokio::test]
async fn payload_larger_than_relay_buffer_round_trips() {
    let harness = Harness::start_with(RelayConfig::default().with_buffer_bytes(1024)).await;
    let echo = testlab::echo_server().await;
    let payload = deterministic_payload(256 * 1024);
    assert!(payload.len() > 1024);

    let mut stream = socks_client::connect_through_proxy(
        harness.proxy,
        Destination::Ip(echo.addr().ip()),
        echo.addr().port(),
        GreetingStyle::Single,
        RequestStyle::Single,
    )
    .await
    .expect("connect");

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    stream.write_all(&payload).await.expect("write");

    let mut received = vec![0u8; payload.len()];
    stream.read_exact(&mut received).await.expect("echo read");
    assert_eq!(received, payload);

    drop(stream);
    harness.shutdown().await;
    echo.shutdown().await;
}

// --- 9. Server-first ----------------------------------------------------------

/// Case 9: a server-first banner reaches the client without client input.
#[tokio::test]
async fn server_first_banner_reaches_client() {
    let harness = Harness::start().await;
    let banner = b"SERVER-FIRST-BANNER\n".to_vec();
    let server = testlab::server_first_server(banner.clone()).await;

    let mut stream = socks_client::connect_through_proxy(
        harness.proxy,
        Destination::Ip(server.addr().ip()),
        server.addr().port(),
        GreetingStyle::Single,
        RequestStyle::Single,
    )
    .await
    .expect("connect");

    use tokio::io::AsyncReadExt;
    let mut received = vec![0u8; banner.len()];
    stream.read_exact(&mut received).await.expect("banner read");
    assert_eq!(
        received, banner,
        "server-first banner must arrive unchanged"
    );

    harness.shutdown().await;
    server.shutdown().await;
}

// --- 10. Half-close -----------------------------------------------------------

/// Case 10: client half-closes its write side; the reverse flow still completes.
#[tokio::test]
async fn client_half_close_preserves_reverse_flow() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let harness = Harness::start().await;
    let echo = testlab::echo_server().await;

    let mut stream = socks_client::connect_through_proxy(
        harness.proxy,
        Destination::Ip(echo.addr().ip()),
        echo.addr().port(),
        GreetingStyle::Single,
        RequestStyle::Single,
    )
    .await
    .expect("connect");

    let payload = deterministic_payload(32 * 1024);
    stream.write_all(&payload).await.expect("write");
    stream.shutdown().await.expect("client half-close");

    let mut received = vec![0u8; payload.len()];
    let mut reader = stream;
    reader.read_exact(&mut received).await.expect("echo read");
    assert_eq!(
        received, payload,
        "reverse flow must survive client half-close"
    );

    drop(reader);
    let closed = wait_for_closed(&harness, 1).await;
    assert_eq!(closed.len(), 1);
    let (c2s, s2c) = closed_counters(&closed[0]);
    assert_eq!(c2s, payload.len() as u64);
    assert_eq!(s2c, payload.len() as u64);

    harness.shutdown().await;
    echo.shutdown().await;
}

/// The server half-closes its *write* side, and the client can still forward
/// bytes to it afterwards.
///
/// Uses a fixture that genuinely half-closes rather than a banner-then-echo
/// server, so a regression that tore down both directions would fail here.
#[tokio::test]
async fn server_half_close_preserves_forward_flow() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let harness = Harness::start().await;
    let banner = b"GOTCHA\n".to_vec();
    let server = testlab::recording_half_close_server(banner.clone()).await;

    let mut stream = socks_client::connect_through_proxy(
        harness.proxy,
        Destination::Ip(server.addr().ip()),
        server.addr().port(),
        GreetingStyle::Single,
        RequestStyle::Single,
    )
    .await
    .expect("connect");

    let mut received_banner = vec![0u8; banner.len()];
    stream
        .read_exact(&mut received_banner)
        .await
        .expect("banner");
    assert_eq!(received_banner, banner);

    // The server has already sent FIN, so the client must observe clean EOF.
    let mut trailing = Vec::new();
    let read_to_end = stream.read_to_end(&mut trailing);
    tokio::time::timeout(Duration::from_secs(5), read_to_end)
        .await
        .expect("client must observe the server FIN")
        .expect("FIN must be a clean EOF, not a reset");
    assert!(trailing.is_empty(), "no bytes should follow the banner");

    // Forwarding to the server must still work after its FIN.
    stream
        .write_all(b"tail-bytes")
        .await
        .expect("write after server FIN");
    // Half-close so the fixture sees EOF and the session can complete.
    stream.shutdown().await.expect("client half-close");

    let closed = wait_for_closed(&harness, 1).await;
    assert_eq!(closed.len(), 1);
    let (c2s, s2c) = closed_counters(&closed[0]);
    assert_eq!(c2s, "tail-bytes".len() as u64);
    assert_eq!(s2c, banner.len() as u64);

    // The fixture itself must have received the post-FIN bytes. The relay close
    // event is not sufficient here: it only proves bytes reached the fixture's
    // socket, so await the fixture's own completion signal instead.
    tokio::time::timeout(Duration::from_secs(5), server.wait_done())
        .await
        .expect("fixture must finish reading after client EOF");
    assert_eq!(
        server.received(),
        b"tail-bytes",
        "server must receive client bytes after half-closing its write side"
    );

    harness.shutdown().await;
    server.shutdown().await;
}

// --- 11. Concurrency ----------------------------------------------------------

/// Case 11: 20+ simultaneous sessions stay isolated, each echoing its own bytes.
#[tokio::test]
async fn concurrent_connections_remain_isolated() {
    let harness = Harness::start_with(RelayConfig::default().with_max_connections(64)).await;
    let echo = testlab::echo_server().await;

    const COUNT: usize = 24;
    let mut tasks = Vec::with_capacity(COUNT);

    for index in 0..COUNT {
        let proxy = harness.proxy;
        let target = echo.addr();
        tasks.push(tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let mut stream = socks_client::connect_through_proxy(
                proxy,
                Destination::Ip(target.ip()),
                target.port(),
                GreetingStyle::Single,
                RequestStyle::Single,
            )
            .await
            .expect("connect");

            let payload = deterministic_payload(1024 + index * 64);
            stream.write_all(&payload).await.expect("write");

            let mut received = vec![0u8; payload.len()];
            stream.read_exact(&mut received).await.expect("read");
            assert_eq!(received, payload, "session {index} corrupted");
            (payload.len(), index)
        }));
    }

    for task in tasks {
        task.await.expect("session task");
    }

    let closed = wait_for_closed(&harness, COUNT).await;
    assert_eq!(closed.len(), COUNT, "every session must be accounted for");
    for event in &closed {
        let (c2s, s2c) = closed_counters(event);
        assert_eq!(c2s, s2c, "counters must match per session");
        assert!(c2s > 0);
    }

    harness.shutdown().await;
    echo.shutdown().await;
}

// --- 12. Lifecycle, counters, shutdown ----------------------------------------

/// The functional login flow forwards both directions unchanged.
#[tokio::test]
async fn login_flow_forwards_both_directions_unchanged() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let harness = Harness::start().await;
    let login = testlab::login_server().await;

    let mut stream = socks_client::connect_through_proxy(
        harness.proxy,
        Destination::Ip(login.addr().ip()),
        login.addr().port(),
        GreetingStyle::Single,
        RequestStyle::Single,
    )
    .await
    .expect("connect");

    stream.write_all(LOGIN_REQUEST).await.expect("write login");

    let mut response = vec![0u8; testlab::AUTH_OK_RESPONSE.len()];
    stream
        .read_exact(&mut response)
        .await
        .expect("read response");
    assert_eq!(&response, testlab::AUTH_OK_RESPONSE);

    drop(stream);
    let closed = wait_for_closed(&harness, 1).await;
    let (c2s, s2c) = closed_counters(&closed[0]);
    assert_eq!(c2s, LOGIN_REQUEST.len() as u64);
    assert_eq!(s2c, testlab::AUTH_OK_RESPONSE.len() as u64);

    harness.shutdown().await;
    login.shutdown().await;
}

/// Lifecycle logs carry connection ID, destination, and directional counters.
#[tokio::test]
async fn lifecycle_events_report_id_destination_and_counters() {
    use tokio::io::AsyncWriteExt;
    let harness = Harness::start().await;
    let echo = testlab::echo_server().await;

    let mut stream = socks_client::connect_through_proxy(
        harness.proxy,
        Destination::Ip(echo.addr().ip()),
        echo.addr().port(),
        GreetingStyle::Single,
        RequestStyle::Single,
    )
    .await
    .expect("connect");
    stream.write_all(b"hello").await.expect("write");

    drop(stream);
    let closed = wait_for_closed(&harness, 1).await;
    assert_eq!(closed.len(), 1);

    let events = harness.telemetry.events();
    let established = events
        .iter()
        .find(|event| matches!(event, Event::ConnectionEstablished { .. }))
        .expect("established event");
    let close = &closed[0];

    match (established, close) {
        (
            Event::ConnectionEstablished {
                conn_id: open_id,
                requested_target,
                requested_port,
                resolved_upstream,
                ..
            },
            Event::ConnectionClosed { conn_id, .. },
        ) => {
            assert!(!open_id.is_empty(), "connection ID must be present");
            assert_eq!(open_id, conn_id, "close must reference the same ID");
            assert_eq!(*requested_port, echo.addr().port());
            assert_eq!(requested_target, &echo.addr().ip().to_string());
            assert!(
                resolved_upstream.is_some(),
                "resolved endpoint must be logged"
            );
        }
        other => panic!("unexpected event pair: {other:?}"),
    }

    harness.shutdown().await;
    echo.shutdown().await;
}

/// Case 12: shutdown closes the listener *and* tears down live sessions.
///
/// The earlier version of this test dropped its session before shutting down, so
/// it never actually exercised session cleanup.
#[tokio::test]
async fn shutdown_stops_accepting_and_closes_live_sessions() {
    use tokio::io::AsyncReadExt;
    // Built without the Harness helper so the relay handle stays alive across
    // the assertions: only the shutdown flag may close the session, never the
    // accidental drop of the shutdown sender.
    let (sink, shared) = memory_telemetry();
    let config = RelayConfig::default().with_endpoint(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
    let mut relay = spawn_relay_with(config, shared).await.expect("relay bind");
    let proxy = relay.local_addr();
    let echo = testlab::echo_server().await;

    let mut live = socks_client::connect_through_proxy(
        proxy,
        Destination::Ip(echo.addr().ip()),
        echo.addr().port(),
        GreetingStyle::Single,
        RequestStyle::Single,
    )
    .await
    .expect("connect before shutdown");

    // Prove the session is genuinely usable, then hold it open without reading.
    live.write_all(b"before-shutdown").await.expect("write");

    let registry = relay.registry();
    wait_for_active(&registry, 1).await;
    assert_eq!(registry.active(), 1, "live session must hold a slot");

    relay.begin_shutdown();

    // Shutdown must not report completion until the live session has finished.
    let wait_stopped = relay.wait_stopped();
    tokio::time::timeout(Duration::from_secs(5), wait_stopped)
        .await
        .expect("shutdown must complete");

    assert_eq!(
        registry.active(),
        0,
        "shutdown must free every connection slot"
    );

    let events = sink.events();
    assert!(
        events
            .iter()
            .any(|event| matches!(event, Event::SessionsDrained)),
        "shutdown must drain live sessions, not abandon them"
    );
    assert!(
        events
            .iter()
            .any(|event| matches!(event, Event::ListenerStopped)),
        "listener shutdown must be recorded"
    );
    assert!(
        events
            .iter()
            .any(|event| matches!(event, Event::ConnectionClosed { .. })),
        "the live session must be closed before shutdown returns"
    );
    // Ordering, not just presence: sessions drain before the listener is
    // reported stopped.
    let position =
        |predicate: fn(&Event) -> bool| events.iter().position(predicate).unwrap_or(usize::MAX);
    let closed = position(|event| matches!(event, Event::ConnectionClosed { .. }));
    let drained = position(|event| matches!(event, Event::SessionsDrained));
    let stopped = position(|event| matches!(event, Event::ListenerStopped));
    assert!(closed < drained, "session close must precede drain");
    assert!(drained < stopped, "drain must precede listener-stopped");

    // The client must observe the session ending, not hang.
    let mut trailing = Vec::new();
    let read_to_end = live.read_to_end(&mut trailing);
    let _ = tokio::time::timeout(Duration::from_secs(5), read_to_end)
        .await
        .expect("live session must be closed by shutdown");
    assert!(
        socks_client::open(proxy).await.is_err(),
        "listener must stop accepting after shutdown"
    );

    echo.shutdown().await;
}

/// Binding an already-used port fails instead of silently succeeding.
#[tokio::test]
async fn bind_fails_when_port_already_in_use() {
    let harness = Harness::start().await;
    let taken = harness.proxy.port();

    let conflict = spawn_relay_with(
        RelayConfig::default().with_endpoint(IpAddr::V4(Ipv4Addr::LOCALHOST), taken),
        Arc::new(rawtcp_engine::StderrTelemetry),
    )
    .await;

    assert!(conflict.is_err(), "second bind on a used port must fail");

    harness.shutdown().await;
}

/// The active-session cap rejects extra sessions instead of unbounded growth.
#[tokio::test]
async fn active_connection_cap_is_enforced() {
    use tokio::io::AsyncReadExt;
    let harness = Harness::start_with(RelayConfig::default().with_max_connections(2)).await;
    let echo = testlab::echo_server().await;

    let mut held = Vec::new();
    for _ in 0..2 {
        held.push(
            socks_client::connect_through_proxy(
                harness.proxy,
                Destination::Ip(echo.addr().ip()),
                echo.addr().port(),
                GreetingStyle::Single,
                RequestStyle::Single,
            )
            .await
            .expect("connect"),
        );
    }

    let registry = harness.relay.registry();
    assert_eq!(registry.active(), 2);
    assert!(!registry.has_capacity());

    // A third session must be refused rather than served.
    let mut extra = socks_client::open(harness.proxy).await.expect("tcp accept");
    let mut buf = Vec::new();
    let read = extra.read_to_end(&mut buf).await;
    assert!(
        read.is_err() || buf.is_empty(),
        "over-capacity session must not be negotiated"
    );
    assert_eq!(
        registry.active(),
        2,
        "rejected session must not consume a slot"
    );

    held.clear();
    harness.shutdown().await;
    echo.shutdown().await;
}

/// Phase 1A is loopback-only: a non-loopback bind is refused, not warned about.
#[tokio::test]
async fn non_loopback_bind_is_rejected() {
    for addr in [
        IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
    ] {
        let result = spawn_relay_with(
            RelayConfig::default().with_endpoint(addr, 0),
            Arc::new(rawtcp_engine::StderrTelemetry),
        )
        .await;
        assert!(result.is_err(), "bind on {addr} must be refused");
    }
}

/// Sessions still negotiating hold capacity from the moment they are accepted,
/// so a stalled client cannot occupy unbounded sockets and tasks.
#[tokio::test]
async fn negotiating_sessions_hold_capacity() {
    let harness = Harness::start_with(
        RelayConfig::default()
            .with_max_connections(2)
            .with_negotiation_timeout(Duration::from_secs(30)),
    )
    .await;

    // These sockets never send a greeting and never disconnect.
    let mut stalled = Vec::new();
    for _ in 0..2 {
        stalled.push(socks_client::open(harness.proxy).await.expect("tcp accept"));
    }

    let registry = harness.relay.registry();
    wait_for_active(&registry, 2).await;
    assert_eq!(
        registry.active(),
        2,
        "negotiating sessions must reserve capacity from accept"
    );
    assert!(!registry.has_capacity());

    drop(stalled);
    harness.shutdown().await;
}

/// A client that opens a socket and sends nothing is dropped once the
/// negotiation deadline passes.
#[tokio::test]
async fn stalled_client_is_closed_after_negotiation_timeout() {
    use tokio::io::AsyncReadExt;
    let harness = Harness::start_with(
        RelayConfig::default().with_negotiation_timeout(Duration::from_millis(200)),
    )
    .await;

    let mut idle = socks_client::open(harness.proxy).await.expect("open");

    let mut buf = Vec::new();
    let read_to_end = idle.read_to_end(&mut buf);
    tokio::time::timeout(Duration::from_secs(5), read_to_end)
        .await
        .expect("stalled client must be closed by the negotiation deadline")
        .expect("close must be a clean EOF");

    let registry = harness.relay.registry();
    assert_eq!(
        registry.active(),
        0,
        "timed-out session must release its slot"
    );

    let events = harness.telemetry.events();
    assert!(
        events.iter().any(|event| matches!(
            event,
            Event::SessionRejected { reason, .. } if reason.contains("negotiation timeout")
        )),
        "timeout must be reported with a reason"
    );
    assert!(
        events
            .iter()
            .any(|event| matches!(event, Event::SessionAccepted { .. })),
        "every accepted socket must be assigned a connection ID"
    );

    harness.shutdown().await;
}

/// RFC 1928 CONNECT reply reports the upstream socket's bound endpoint, not the
/// SOCKS listener the client is talking to.
#[tokio::test]
async fn success_reply_reports_upstream_bound_endpoint() {
    let harness = Harness::start().await;
    let echo = testlab::echo_server().await;

    let mut stream = socks_client::open(harness.proxy).await.expect("open");
    socks_client::greeting(
        &mut stream,
        GreetingStyle::Single,
        &[consts::METHOD_NO_AUTH],
    )
    .await
    .expect("greeting");

    socks_client::send_request(
        &mut stream,
        &Destination::Ip(echo.addr().ip()),
        echo.addr().port(),
        RequestStyle::Single,
    )
    .await
    .expect("request");

    let reply = socks_client::read_reply(&mut stream).await.expect("reply");
    assert!(reply.is_success());
    // The relay reports the local endpoint of its own upstream socket. Its port
    // is ephemeral, so the meaningful assertion is that it is not the SOCKS
    // listener's port, which is what the previous implementation returned.
    assert_ne!(
        reply.bind_addr.port(),
        harness.proxy.port(),
        "BND must not echo the SOCKS listener endpoint"
    );
    assert!(
        reply.bind_addr.ip().is_loopback(),
        "BND.ADDR must be the proxy's own upstream address"
    );

    harness.shutdown().await;
    echo.shutdown().await;
}

/// Byte counters are monotonic: bytes already forwarded survive a later failure
/// in the same direction instead of being reported as zero.
#[tokio::test]
async fn byte_counters_survive_forwarding_errors() {
    let harness = Harness::start().await;
    // Far more than socket buffers can hold, so writes to the client eventually
    // fail once the client disappears.
    let flood = testlab::flood_server(64 * 1024 * 1024).await;

    let stream = socks_client::connect_through_proxy(
        harness.proxy,
        Destination::Ip(flood.addr().ip()),
        flood.addr().port(),
        GreetingStyle::Single,
        RequestStyle::Single,
    )
    .await
    .expect("connect");

    // Let server->client make real progress, then drop the socket mid-flight.
    tokio::time::sleep(Duration::from_millis(200)).await;
    drop(stream);

    let closed = wait_for_closed(&harness, 1).await;
    assert_eq!(closed.len(), 1);

    match &closed[0] {
        Event::ConnectionClosed {
            bytes_server_to_client,
            reason,
            ..
        } => {
            assert!(
                *bytes_server_to_client > 0,
                "progress made before the failure must still be counted, not zeroed"
            );
            assert_ne!(reason, "eof", "expected an error, not a clean EOF");
        }
        other => panic!("not a close event: {other:?}"),
    }

    harness.shutdown().await;
    flood.shutdown().await;
}

/// Rejected sessions still log a connection ID and, once the request was
/// parsed, the requested destination and port.
#[tokio::test]
async fn rejected_sessions_log_connection_metadata() {
    let harness = Harness::start().await;
    let refused = testlab::refused_endpoint().await;

    let mut stream = socks_client::open(harness.proxy).await.expect("open");
    socks_client::greeting(
        &mut stream,
        GreetingStyle::Single,
        &[consts::METHOD_NO_AUTH],
    )
    .await
    .expect("greeting");
    socks_client::send_request(
        &mut stream,
        &Destination::Domain("localhost".to_owned()),
        refused.port(),
        RequestStyle::Single,
    )
    .await
    .expect("request");

    let reply = socks_client::read_reply(&mut stream).await.expect("reply");
    assert!(!reply.is_success());

    let events = harness.telemetry.events();
    let (conn_id, requested_target, requested_port) = events
        .iter()
        .find_map(|event| match event {
            Event::SessionRejected {
                conn_id,
                requested_target,
                requested_port,
                ..
            } => Some((conn_id, requested_target, requested_port)),
            _ => None,
        })
        .expect("a rejection event must be recorded");

    assert!(!conn_id.is_empty(), "rejection must carry a connection ID");
    assert_eq!(
        requested_target.as_deref(),
        Some("localhost"),
        "rejection must log the requested destination"
    );
    assert_eq!(
        *requested_port,
        Some(refused.port()),
        "rejection must log the requested port"
    );

    harness.shutdown().await;
}

/// A fatal error in one direction cancels the other one instead of pinning the
/// session.
///
/// The server reads the client's bytes, confirms receipt, then stays silent
/// forever, so the server-to-client direction would block indefinitely. The
/// client resets mid-stream, which fails the client-to-server direction; the
/// session must still finish and release its slot.
///
/// Waiting for the fixture's receipt before resetting makes the forwarded
/// byte count deterministic: on stacks where a reset discards data the relay
/// has not consumed yet, resetting immediately races the relay's read loop
/// and the counter may legitimately be zero.
#[tokio::test]
async fn relay_error_cancels_blocked_peer() {
    let harness = Harness::start().await;
    let silent = testlab::read_then_silent_server(b"doomed".len() as u64).await;

    let mut stream = socks_client::connect_through_proxy(
        harness.proxy,
        Destination::Ip(silent.addr().ip()),
        silent.addr().port(),
        GreetingStyle::Single,
        RequestStyle::Single,
    )
    .await
    .expect("connect");

    stream.write_all(b"doomed").await.expect("write");

    // Only reset once the fixture confirms receipt: the relay necessarily
    // forwarded all six bytes, so the counter below is exact on every stack.
    tokio::time::timeout(Duration::from_secs(5), silent.wait_received())
        .await
        .expect("fixture must receive the client bytes");

    // Reset instead of closing so the relay observes an error, not EOF.
    // (`std`'s `set_linger` is still unstable, so this goes through socket2.)
    let std_stream = stream.into_std().expect("into_std");
    let socket = socket2::Socket::from(std_stream);
    socket.set_linger(Some(Duration::ZERO)).expect("set_linger");
    drop(socket);

    let closed = wait_for_closed(&harness, 1).await;
    assert_eq!(
        closed.len(),
        1,
        "a failed direction must not leave the session hanging on a silent peer"
    );

    match &closed[0] {
        Event::ConnectionClosed {
            bytes_client_to_server,
            bytes_server_to_client,
            reason,
            ..
        } => {
            assert_eq!(*bytes_client_to_server, b"doomed".len() as u64);
            assert_eq!(*bytes_server_to_client, 0);
            assert_ne!(reason, "eof", "expected an error, not a clean EOF");
        }
        other => panic!("not a close event: {other:?}"),
    }

    let registry = harness.relay.registry();
    assert_eq!(registry.active(), 0, "failed session must release its slot");

    harness.shutdown().await;
    silent.shutdown().await;
}

/// Cancelling a `wait_stopped` must not detach shutdown: a second wait still
/// observes completion.
///
/// Deterministic: no shutdown is signalled before the first wait, so it must
/// pend. A biased `select!` against an already-ready cancel channel polls the
/// wait once (proving it pends) and then drops it while pending — no timeout
/// involved. The retry must then also pend; an immediate return would prove the
/// handle was detached, as the old take-before-await implementation did.
#[tokio::test]
async fn wait_stopped_survives_cancellation() {
    let (sink, shared) = memory_telemetry();
    let config = RelayConfig::default().with_endpoint(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
    let mut relay = spawn_relay_with(config, shared).await.expect("relay bind");
    let echo = testlab::echo_server().await;

    let mut live = socks_client::connect_through_proxy(
        relay.local_addr(),
        Destination::Ip(echo.addr().ip()),
        echo.addr().port(),
        GreetingStyle::Single,
        RequestStyle::Single,
    )
    .await
    .expect("connect");
    live.write_all(b"held").await.expect("write");

    let registry = relay.registry();
    wait_for_active(&registry, 1).await;

    // Force the first wait into a genuinely pending state (no shutdown yet, so
    // it cannot complete), then cancel it while pending.
    let (cancel_tx, cancel_rx) = tokio::sync::oneshot::channel::<()>();
    cancel_tx.send(()).expect("cancel must be ready");
    let mut first_completed = false;
    tokio::select! {
        biased;
        _ = relay.wait_stopped() => { first_completed = true; }
        _ = cancel_rx => {}
    }
    assert!(
        !first_completed,
        "first wait must not complete without shutdown: cancellation was not exercised"
    );

    // The retry must genuinely wait for shutdown. With `biased`, a detached
    // handle (old bug) completes immediately and takes the first branch; a
    // retained handle pends and the `yield_now` branch wins.
    let mut spurious = false;
    tokio::select! {
        biased;
        _ = relay.wait_stopped() => { spurious = true; }
        _ = tokio::task::yield_now() => {}
    }
    assert!(
        !spurious,
        "cancelled wait must not detach shutdown: retry completed without shutdown"
    );

    // Trigger the event the retry is waiting for and verify it completes.
    relay.begin_shutdown();
    tokio::time::timeout(Duration::from_secs(5), relay.wait_stopped())
        .await
        .expect("retried wait must complete shutdown");

    assert_eq!(registry.active(), 0);
    let events = sink.events();
    assert!(
        events
            .iter()
            .any(|event| matches!(event, Event::SessionsDrained)),
        "shutdown must drain live sessions, not abandon them"
    );
    assert!(
        events
            .iter()
            .any(|event| matches!(event, Event::ListenerStopped)),
        "listener shutdown must be recorded"
    );

    echo.shutdown().await;
}

/// Aborting a session releases all transport work: no detached copy task may
/// keep forwarding after cleanup.
///
/// Ownership model: `relay` spawns no child tasks, so aborting its task drops
/// both directions and their socket halves. The previous spawn-and-detach
/// design kept forwarding `after` bytes even after the parent was aborted and
/// reaped.
#[tokio::test]
async fn aborted_relay_cannot_forward_after_cleanup() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    async fn connected_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("pair bind");
        let addr = listener.local_addr().expect("pair addr");
        let (accepted, connected) = tokio::join!(listener.accept(), TcpStream::connect(addr));
        (
            connected.expect("pair connect"),
            accepted.expect("pair accept").0,
        )
    }

    let (mut client_peer, relay_client) = connected_pair().await;
    let (relay_server, mut server_peer) = connected_pair().await;

    // Never signalled: this test exercises task abort, not the shutdown flag.
    let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let observer = rawtcp_engine::SessionObserver::new(
        std::sync::Arc::new(rawtcp_engine::MemoryHistory::default()),
        "aborted-relay-probe".to_owned(),
    );
    let relay_task = tokio::spawn(rawtcp_engine::transport::relay(
        relay_client,
        relay_server,
        16 * 1024,
        shutdown_rx,
        observer,
    ));

    // Prove forwarding is active before the abort.
    client_peer
        .write_all(b"before")
        .await
        .expect("write before");
    let mut active = [0u8; 6];
    tokio::time::timeout(Duration::from_secs(5), server_peer.read_exact(&mut active))
        .await
        .expect("forwarding must be active before abort")
        .expect("read before");
    assert_eq!(&active, b"before");

    // Abnormal termination: abort the parent and reap it. Cleanup completes
    // when the join handle resolves.
    relay_task.abort();
    let join_error = tokio::time::timeout(Duration::from_secs(5), relay_task)
        .await
        .expect("aborted relay must resolve promptly")
        .expect_err("aborted relay must report cancellation");
    assert!(
        join_error.is_cancelled(),
        "expected task cancellation, got {join_error}"
    );

    // After cleanup no forwarding may occur. The relay dropped its socket
    // halves, so the server peer must observe EOF/reset promptly instead of
    // receiving the post-abort bytes. A detached implementation would deliver
    // `after!` here.
    let _ = client_peer.write_all(b"after!").await;
    let mut after = [0u8; 6];
    let read = tokio::time::timeout(Duration::from_secs(2), server_peer.read(&mut after))
        .await
        .expect("peer must resolve after abort instead of hanging");
    match read {
        Ok(0) => {}
        Ok(n) => panic!(
            "detached relay forwarded {n} byte(s) after abort: {:?}",
            &after[..n]
        ),
        Err(_) => {}
    }
}

/// The listener socket is closed before session draining begins.
///
/// The probe attempts a blocking TCP handshake from inside the
/// `ShutdownStarted` emission, which runs synchronously in the accept loop:
/// with correct ordering the listener is already dropped (handshake refused),
/// while the old ordering still held it (handshake succeeded). Existing live
/// sessions must still drain per policy instead of being abandoned.
#[tokio::test]
async fn listener_is_closed_before_draining_sessions() {
    use rawtcp_engine::Telemetry;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Mutex;

    struct ShutdownProbe {
        inner: Arc<MemoryTelemetry>,
        listener_addr: Mutex<Option<SocketAddr>>,
        connected_during_shutdown: AtomicBool,
    }

    impl Telemetry for ShutdownProbe {
        fn emit(&self, event: Event) {
            match &event {
                Event::ListenerStarted { local_addr } => {
                    *self.listener_addr.lock().expect("probe lock") = Some(*local_addr);
                }
                Event::ShutdownStarted { .. } => {
                    if let Some(addr) = *self.listener_addr.lock().expect("probe lock") {
                        // Runs inside the accept loop: deterministic observation,
                        // not a timing window. Open listener → handshake
                        // succeeds; dropped listener → prompt refusal.
                        let connected =
                            std::net::TcpStream::connect_timeout(&addr, Duration::from_millis(200))
                                .is_ok();
                        self.connected_during_shutdown
                            .store(connected, Ordering::SeqCst);
                    }
                    self.inner.emit(event);
                }
                _ => self.inner.emit(event),
            }
        }
    }

    let inner = Arc::new(MemoryTelemetry::new());
    let probe = Arc::new(ShutdownProbe {
        inner: Arc::clone(&inner),
        listener_addr: Mutex::new(None),
        connected_during_shutdown: AtomicBool::new(false),
    });
    let shared: rawtcp_engine::SharedTelemetry = probe.clone();
    let config = RelayConfig::default().with_endpoint(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
    let mut relay = spawn_relay_with(config, shared).await.expect("relay bind");
    let proxy = relay.local_addr();
    let echo = testlab::echo_server().await;

    // Live session ensures draining has work and proves existing sessions are
    // still honoured (closed via the drain policy, not abandoned).
    let mut live = socks_client::connect_through_proxy(
        proxy,
        Destination::Ip(echo.addr().ip()),
        echo.addr().port(),
        GreetingStyle::Single,
        RequestStyle::Single,
    )
    .await
    .expect("connect before shutdown");
    live.write_all(b"held").await.expect("write");

    let registry = relay.registry();
    wait_for_active(&registry, 1).await;

    relay.begin_shutdown();
    tokio::time::timeout(Duration::from_secs(5), relay.wait_stopped())
        .await
        .expect("shutdown must complete");

    assert!(
        !probe.connected_during_shutdown.load(Ordering::SeqCst),
        "new TCP handshake must not succeed after shutdown starts: \
         listener must be closed before draining"
    );

    let events = inner.events();
    assert!(
        events
            .iter()
            .any(|event| matches!(event, Event::ConnectionClosed { .. })),
        "the live session must be closed by shutdown instead of abandoned"
    );
    assert!(
        events
            .iter()
            .any(|event| matches!(event, Event::SessionsDrained)),
        "shutdown must drain live sessions, not abandon them"
    );
    assert!(
        events
            .iter()
            .any(|event| matches!(event, Event::ListenerStopped)),
        "listener shutdown must be recorded"
    );
    assert_eq!(registry.active(), 0);

    // After shutdown completes, new connects must fail (refused, not accepted).
    // Retried: a host packet interceptor can drop the first SYN of a fresh
    // flow, delaying the refusal past a single short timeout. A listener that
    // is still open accepts promptly, so success fails fast on every attempt.
    let mut refused = false;
    for _ in 0..4 {
        match tokio::time::timeout(
            Duration::from_secs(3),
            tokio::net::TcpStream::connect(proxy),
        )
        .await
        {
            Ok(Err(_)) => {
                refused = true;
                break;
            }
            Ok(Ok(_)) => panic!("listener must refuse new connections after shutdown"),
            Err(_) => continue,
        }
    }
    assert!(
        refused,
        "listener must refuse new connections after shutdown"
    );

    echo.shutdown().await;
}

/// A panicking session must not leak its connection slot: the next client can
/// still connect, and the failed session still leaves a terminal record.
///
/// The slot guard travels with the session task, so unwinding releases the
/// reservation even though the normal return path never runs.
#[tokio::test]
async fn panicked_session_frees_capacity_and_reports() {
    use rawtcp_engine::Telemetry;
    use std::sync::atomic::{AtomicBool, Ordering};
    use tokio::io::AsyncReadExt;

    struct PanicOnce {
        inner: Arc<MemoryTelemetry>,
        fired: AtomicBool,
    }

    impl Telemetry for PanicOnce {
        fn emit(&self, event: Event) {
            if matches!(event, Event::ConnectionEstablished { .. })
                && !self.fired.swap(true, Ordering::SeqCst)
            {
                panic!("controlled session panic for lifecycle review");
            }
            self.inner.emit(event);
        }
    }

    let inner = Arc::new(MemoryTelemetry::new());
    let probe = Arc::new(PanicOnce {
        inner: Arc::clone(&inner),
        fired: AtomicBool::new(false),
    });
    let shared: rawtcp_engine::SharedTelemetry = probe;
    let config = RelayConfig::default()
        .with_endpoint(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)
        .with_max_connections(1);
    let relay = spawn_relay_with(config, shared).await.expect("relay bind");
    let echo = testlab::echo_server().await;

    // Negotiates fully (success reply precedes establishment), then the
    // session panics while emitting `ConnectionEstablished`.
    let mut first = socks_client::connect_through_proxy(
        relay.local_addr(),
        Destination::Ip(echo.addr().ip()),
        echo.addr().port(),
        GreetingStyle::Single,
        RequestStyle::Single,
    )
    .await
    .expect("first CONNECT negotiates before the controlled panic");

    // The panicked task drops its sockets, so the peer observes EOF.
    let mut byte = [0u8; 1];
    let ended = tokio::time::timeout(Duration::from_secs(5), first.read(&mut byte))
        .await
        .expect("panicked session socket must resolve");
    assert!(
        !matches!(ended, Ok(n) if n > 0),
        "panicked session must close its sockets"
    );

    // The slot must be released: with capacity 1 a leak would refuse this.
    for _ in 0..200 {
        if relay.registry().active() == 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(
        relay.registry().active(),
        0,
        "panicked session must free its slot"
    );

    let mut second = socks_client::connect_through_proxy(
        relay.local_addr(),
        Destination::Ip(echo.addr().ip()),
        echo.addr().port(),
        GreetingStyle::Single,
        RequestStyle::Single,
    )
    .await
    .expect("slot must be reusable after the panic");
    second.write_all(b"again").await.expect("write");
    let mut echoed = [0u8; 5];
    tokio::time::timeout(Duration::from_secs(5), second.read_exact(&mut echoed))
        .await
        .expect("echo must work after the panic")
        .expect("read");
    assert_eq!(&echoed, b"again");
    drop(second);

    // The failed session still leaves a terminal record under its own ID.
    let events = inner.events();
    let accepted = events
        .iter()
        .find_map(|event| match event {
            Event::SessionAccepted { conn_id, .. } => Some(conn_id.clone()),
            _ => None,
        })
        .expect("accept must be recorded");
    let closed = events.iter().find_map(|event| match event {
        Event::ConnectionClosed {
            conn_id, reason, ..
        } if conn_id == &accepted => Some(reason.clone()),
        _ => None,
    });
    assert!(
        closed.is_some_and(|reason| reason.contains("panicked")),
        "panicked session must leave a terminal record, got: {events:?}"
    );

    relay.shutdown().await;
    echo.shutdown().await;
}

/// A panic raised by the `SessionAccepted` log must not leak the reservation:
/// the guard is built before that emit, so unwinding still frees the slot and
/// leaves a terminal record.
///
/// This goes through the real supervisor (`spawn_relay_with`), not a
/// test-local construction helper, so it covers the shipped accept ordering.
/// If production ever emits acceptance before owning the session, this fails on
/// the leaked slot with no terminal event.
#[tokio::test]
async fn acceptance_event_panic_still_frees_slot() {
    use rawtcp_engine::Telemetry;
    use std::sync::atomic::{AtomicBool, Ordering};
    use tokio::net::TcpStream;

    struct PanicOnAccepted {
        inner: Arc<MemoryTelemetry>,
        fired: AtomicBool,
    }

    impl Telemetry for PanicOnAccepted {
        fn emit(&self, event: Event) {
            let accepted = matches!(event, Event::SessionAccepted { .. });
            // Record first so the test can correlate the terminal record.
            self.inner.emit(event);
            if accepted && !self.fired.swap(true, Ordering::SeqCst) {
                panic!("controlled acceptance-event panic");
            }
        }
    }

    let inner = Arc::new(MemoryTelemetry::new());
    let probe = Arc::new(PanicOnAccepted {
        inner: Arc::clone(&inner),
        fired: AtomicBool::new(false),
    });
    let shared: rawtcp_engine::SharedTelemetry = probe;
    let config = RelayConfig::default()
        .with_endpoint(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)
        .with_max_connections(1);
    let mut relay = spawn_relay_with(config, shared).await.expect("relay bind");

    let _client = TcpStream::connect(relay.local_addr())
        .await
        .expect("client connect");

    // The supervisor panics while logging acceptance, so its task ends;
    // `wait_stopped` must resolve instead of hanging on a leaked session.
    tokio::time::timeout(Duration::from_secs(5), relay.wait_stopped())
        .await
        .expect("supervisor must stop after the acceptance panic");

    let events = inner.events();
    let accepted = events
        .iter()
        .find_map(|event| match event {
            Event::SessionAccepted { conn_id, .. } => Some(conn_id.clone()),
            _ => None,
        })
        .expect("accept must be recorded before the panic");
    assert_eq!(
        relay.registry().active(),
        0,
        "acceptance panic must free the reservation"
    );
    assert!(
        events.iter().any(|event| match event {
            Event::SessionRejected { conn_id, .. } if conn_id == &accepted => true,
            Event::ConnectionClosed { conn_id, .. } if conn_id == &accepted => true,
            _ => false,
        }),
        "acceptance panic must leave a terminal record, got: {events:?}"
    );
}
