//! Phase 2 integration tests: passive capture and bounded history.
//!
//! Every test drives real SOCKS5 sessions through `spawn_relay_with` and
//! asserts on the relay's history handle. Forwarding assertions mirror the
//! Phase 1A transparency bar: received bytes, captured bytes, and sent
//! bytes must all agree.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use rawtcp_engine::telemetry::{memory_telemetry, Event, MemoryTelemetry};
use rawtcp_engine::{spawn_relay_with, Direction, HistoryLimits, RelayConfig};
use testlab::socks_client::{self, Destination, GreetingStyle, RequestStyle};
use testlab::{deterministic_payload, BINARY_SAMPLE};

/// Relay + history + telemetry handles used by most tests.
struct Harness {
    relay: rawtcp_engine::RunningRelay,
    history: Arc<rawtcp_engine::MemoryHistory>,
    telemetry: Arc<MemoryTelemetry>,
}

impl Harness {
    async fn start() -> Self {
        Self::start_with(RelayConfig::default()).await
    }

    async fn start_with(config: RelayConfig) -> Self {
        let (sink, shared) = memory_telemetry();
        let config = config.with_endpoint(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let relay = spawn_relay_with(config, shared).await.expect("relay bind");
        let history = relay.history();
        Self {
            relay,
            history,
            telemetry: sink,
        }
    }

    async fn shutdown(self) {
        self.relay.shutdown().await;
    }

    /// Connection ID of the established session to `port`, if any.
    fn established_for_port(&self, port: u16) -> Option<String> {
        self.telemetry
            .events()
            .into_iter()
            .find_map(|event| match event {
                Event::ConnectionEstablished {
                    conn_id,
                    requested_port,
                    ..
                } if requested_port == port => Some(conn_id),
                _ => None,
            })
    }

    /// Telemetry close event for `conn_id`, waiting briefly for delivery.
    async fn wait_telemetry_close(&self, conn_id: &str) -> Event {
        for _ in 0..200 {
            let found = self.telemetry.events().into_iter().find(|event| {
                matches!(event, Event::ConnectionClosed { conn_id: id, .. } if id == conn_id)
            });
            if let Some(event) = found {
                return event;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("telemetry close event never arrived for {conn_id}");
    }

    /// History close record for `conn_id`, waiting briefly for delivery.
    async fn wait_history_close(&self, conn_id: &str) -> rawtcp_engine::ConnectionRecord {
        for _ in 0..200 {
            if let Some(record) = self.history.connection(conn_id) {
                if record.is_closed() {
                    return record;
                }
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("history close record never arrived for {conn_id}");
    }
}

fn concat(chunks: &[rawtcp_engine::TrafficChunk]) -> Vec<u8> {
    chunks
        .iter()
        .flat_map(|chunk| chunk.bytes.iter().copied())
        .collect()
}

/// 1/11/12/13: C→S events, open metadata, close metadata, counter agreement.
#[tokio::test]
async fn c2s_capture_with_open_and_close_metadata() {
    let harness = Harness::start().await;
    let echo = testlab::echo_server().await;

    let mut stream = socks_client::connect_through_proxy(
        harness.relay.local_addr(),
        Destination::Ip(echo.addr().ip()),
        echo.addr().port(),
        GreetingStyle::Single,
        RequestStyle::Single,
    )
    .await
    .expect("connect");

    let conn_id = harness
        .established_for_port(echo.addr().port())
        .expect("established event");

    // Open metadata is available while the session is still forwarding.
    let open = harness
        .history
        .connection(&conn_id)
        .expect("history open record");
    assert_eq!(open.requested_port, echo.addr().port());
    assert_eq!(open.requested_target, echo.addr().ip().to_string());
    assert_eq!(open.resolved_upstream, Some(echo.addr()));
    assert!(!open.is_closed());
    assert!(open.close_reason.is_none());

    let payload = deterministic_payload(4096);
    stream.write_all(&payload).await.expect("write");
    let mut received = vec![0u8; payload.len()];
    stream.read_exact(&mut received).await.expect("echo read");
    assert_eq!(received, payload);
    drop(stream);

    let history_close = harness.wait_history_close(&conn_id).await;
    let telemetry_close = harness.wait_telemetry_close(&conn_id).await;

    let captured = concat(
        &harness
            .history
            .chunks_for_direction(&conn_id, Direction::ClientToServer),
    );
    assert_eq!(captured, payload, "captured C→S must equal sent bytes");
    assert_eq!(history_close.bytes_client_to_server, payload.len() as u64);
    assert_eq!(history_close.bytes_server_to_client, payload.len() as u64);
    assert!(history_close.is_closed());

    match telemetry_close {
        Event::ConnectionClosed {
            bytes_client_to_server,
            bytes_server_to_client,
            reason,
            ..
        } => {
            assert_eq!(bytes_client_to_server, payload.len() as u64);
            assert_eq!(bytes_server_to_client, payload.len() as u64);
            assert_eq!(history_close.close_reason.as_deref(), Some(reason.as_str()));
        }
        other => panic!("not a close event: {other:?}"),
    }

    harness.shutdown().await;
    echo.shutdown().await;
}

/// 2: server-first traffic captures S→C with empty C→S.
#[tokio::test]
async fn s2c_server_first_capture() {
    let harness = Harness::start().await;
    let banner = b"PHASE2-BANNER".to_vec();
    let server = testlab::server_first_server(banner.clone()).await;

    let mut stream = socks_client::connect_through_proxy(
        harness.relay.local_addr(),
        Destination::Ip(server.addr().ip()),
        server.addr().port(),
        GreetingStyle::Single,
        RequestStyle::Single,
    )
    .await
    .expect("connect");
    let conn_id = harness
        .established_for_port(server.addr().port())
        .expect("established event");

    let mut seen = vec![0u8; banner.len()];
    stream.read_exact(&mut seen).await.expect("banner read");
    assert_eq!(seen, banner);
    drop(stream);
    harness.wait_history_close(&conn_id).await;

    let s2c = harness
        .history
        .chunks_for_direction(&conn_id, Direction::ServerToClient);
    assert_eq!(concat(&s2c), banner);
    assert!(
        harness
            .history
            .chunks_for_direction(&conn_id, Direction::ClientToServer)
            .is_empty(),
        "no client bytes were ever sent"
    );

    harness.shutdown().await;
    server.shutdown().await;
}

/// 3/4: NUL bytes and the full 0x00–0xFF range survive capture exactly.
#[tokio::test]
async fn binary_and_full_range_capture() {
    let harness = Harness::start().await;
    let echo = testlab::echo_server().await;

    let mut payload = BINARY_SAMPLE.to_vec();
    payload.extend((0u8..=255u8).flat_map(|byte| [byte, byte, byte, byte]));

    let mut stream = socks_client::connect_through_proxy(
        harness.relay.local_addr(),
        Destination::Ip(echo.addr().ip()),
        echo.addr().port(),
        GreetingStyle::Single,
        RequestStyle::Single,
    )
    .await
    .expect("connect");
    let conn_id = harness
        .established_for_port(echo.addr().port())
        .expect("established event");

    stream.write_all(&payload).await.expect("write");
    let mut received = vec![0u8; payload.len()];
    stream.read_exact(&mut received).await.expect("echo read");
    assert_eq!(received, payload);
    drop(stream);
    harness.wait_history_close(&conn_id).await;

    for direction in [Direction::ClientToServer, Direction::ServerToClient] {
        let captured = concat(&harness.history.chunks_for_direction(&conn_id, direction));
        assert_eq!(captured, payload, "binary must survive {direction:?}");
    }

    harness.shutdown().await;
    echo.shutdown().await;
}

/// 5/10: sequential writes stay ordered with contiguous seq and offsets.
#[tokio::test]
async fn sequential_writes_are_ordered_with_offsets() {
    let harness = Harness::start().await;
    let echo = testlab::echo_server().await;

    let mut stream = socks_client::connect_through_proxy(
        harness.relay.local_addr(),
        Destination::Ip(echo.addr().ip()),
        echo.addr().port(),
        GreetingStyle::Single,
        RequestStyle::Single,
    )
    .await
    .expect("connect");
    let conn_id = harness
        .established_for_port(echo.addr().port())
        .expect("established event");

    // Round-trip each write before sending the next, so the relay observes
    // at least one read per write: chunk boundaries stay deterministic
    // without assuming anything about read() coalescing.
    let parts: [&[u8]; 3] = [b"alpha-", b"beta--", b"gamma-"];
    for part in parts {
        stream.write_all(part).await.expect("write");
        let mut back = vec![0u8; part.len()];
        stream.read_exact(&mut back).await.expect("echo read");
        assert_eq!(back, part);
    }
    drop(stream);
    harness.wait_history_close(&conn_id).await;

    let chunks = harness
        .history
        .chunks_for_direction(&conn_id, Direction::ClientToServer);
    assert!(
        chunks.len() >= parts.len(),
        "one read per round-trip, got {}",
        chunks.len()
    );
    let mut offset = 0u64;
    for (index, chunk) in chunks.iter().enumerate() {
        assert_eq!(chunk.seq, index as u64, "seq must be contiguous from 0");
        assert_eq!(chunk.offset, offset, "offsets must accumulate lengths");
        offset += chunk.len() as u64;
    }
    let expected: Vec<u8> = parts.concat();
    assert_eq!(concat(&chunks), expected);

    // Each direction sequences independently from zero.
    let s2c = harness
        .history
        .chunks_for_direction(&conn_id, Direction::ServerToClient);
    assert_eq!(concat(&s2c), expected);
    assert_eq!(s2c[0].seq, 0);

    harness.shutdown().await;
    echo.shutdown().await;
}

/// 6: full duplex after a server-first banner.
#[tokio::test]
async fn server_first_then_full_duplex_capture() {
    let harness = Harness::start().await;
    let banner = b"GO".to_vec();
    let server = testlab::server_first_server(banner.clone()).await;

    let mut stream = socks_client::connect_through_proxy(
        harness.relay.local_addr(),
        Destination::Ip(server.addr().ip()),
        server.addr().port(),
        GreetingStyle::Single,
        RequestStyle::Single,
    )
    .await
    .expect("connect");
    let conn_id = harness
        .established_for_port(server.addr().port())
        .expect("established event");

    let mut seen = vec![0u8; banner.len()];
    stream.read_exact(&mut seen).await.expect("banner read");

    let payload = deterministic_payload(1024);
    stream.write_all(&payload).await.expect("write");
    let mut received = vec![0u8; payload.len()];
    stream.read_exact(&mut received).await.expect("echo read");
    assert_eq!(received, payload);
    drop(stream);
    harness.wait_history_close(&conn_id).await;

    let s2c = concat(
        &harness
            .history
            .chunks_for_direction(&conn_id, Direction::ServerToClient),
    );
    assert_eq!(&s2c[..banner.len()], banner.as_slice());
    assert_eq!(&s2c[banner.len()..], payload.as_slice());
    let c2s = concat(
        &harness
            .history
            .chunks_for_direction(&conn_id, Direction::ClientToServer),
    );
    assert_eq!(c2s, payload);

    harness.shutdown().await;
    server.shutdown().await;
}

/// 7/8: concurrent connections stay isolated by connection ID.
#[tokio::test]
async fn concurrent_connections_stay_isolated() {
    let harness = Harness::start().await;
    let echo = testlab::echo_server().await;
    let proxy = harness.relay.local_addr();
    let target = echo.addr();

    let payloads: Vec<Vec<u8>> = (0..8)
        .map(|index| {
            let mut payload = deterministic_payload(2048);
            payload[0] = index as u8;
            payload[1] = (index as u8).wrapping_mul(31);
            payload
        })
        .collect();

    let sessions = payloads.iter().map(|payload| {
        let payload = payload.clone();
        async move {
            let mut stream = socks_client::connect_through_proxy(
                proxy,
                Destination::Ip(target.ip()),
                target.port(),
                GreetingStyle::Single,
                RequestStyle::Single,
            )
            .await
            .expect("connect");
            stream.write_all(&payload).await.expect("write");
            let mut received = vec![0u8; payload.len()];
            stream.read_exact(&mut received).await.expect("echo read");
            assert_eq!(received, payload);
        }
    });
    futures_unordered_join(sessions).await;

    // Every payload must appear under exactly one connection: any cross-talk
    // between sessions would corrupt the byte-exact comparison.
    let mut established = Vec::new();
    for event in harness.telemetry.events() {
        if let Event::ConnectionEstablished { conn_id, .. } = event {
            established.push(conn_id);
        }
    }
    assert_eq!(established.len(), payloads.len());
    for payload in &payloads {
        let mut matches = 0;
        for conn_id in &established {
            let captured = concat(
                &harness
                    .history
                    .chunks_for_direction(conn_id, Direction::ClientToServer),
            );
            if captured == *payload {
                matches += 1;
            }
            // Direction filtering must never leak the peer direction.
            for chunk in harness
                .history
                .chunks_for_direction(conn_id, Direction::ServerToClient)
            {
                assert_eq!(chunk.direction, Direction::ServerToClient);
            }
        }
        assert_eq!(
            matches, 1,
            "payload must appear under exactly one connection"
        );
    }

    harness.shutdown().await;
    echo.shutdown().await;
}

/// Drive futures concurrently and collect results in completion order.
async fn futures_unordered_join<F, T>(futures: impl IntoIterator<Item = F>) -> Vec<T>
where
    F: std::future::Future<Output = T> + Send + 'static,
    T: Send + 'static,
{
    let mut set = tokio::task::JoinSet::new();
    for future in futures {
        set.spawn(future);
    }
    let mut out = Vec::new();
    while let Some(joined) = set.join_next().await {
        out.push(joined.expect("session task"));
    }
    out
}

/// 9: direction filtering returns disjoint, complete sets.
#[tokio::test]
async fn direction_filtering_is_disjoint_and_complete() {
    let harness = Harness::start().await;
    let echo = testlab::echo_server().await;

    let mut stream = socks_client::connect_through_proxy(
        harness.relay.local_addr(),
        Destination::Ip(echo.addr().ip()),
        echo.addr().port(),
        GreetingStyle::Single,
        RequestStyle::Single,
    )
    .await
    .expect("connect");
    let conn_id = harness
        .established_for_port(echo.addr().port())
        .expect("established event");

    let payload = deterministic_payload(512);
    stream.write_all(&payload).await.expect("write");
    let mut received = vec![0u8; payload.len()];
    stream.read_exact(&mut received).await.expect("echo read");
    drop(stream);
    harness.wait_history_close(&conn_id).await;

    let all = harness.history.chunks_for(&conn_id);
    let c2s = harness
        .history
        .chunks_for_direction(&conn_id, Direction::ClientToServer);
    let s2c = harness
        .history
        .chunks_for_direction(&conn_id, Direction::ServerToClient);
    assert_eq!(all.len(), c2s.len() + s2c.len());
    assert!(c2s.iter().all(|c| c.direction == Direction::ClientToServer));
    assert!(s2c.iter().all(|c| c.direction == Direction::ServerToClient));
    assert_eq!(concat(&c2s), payload);
    assert_eq!(concat(&s2c), payload);

    harness.shutdown().await;
    echo.shutdown().await;
}

/// 14: client half-close still leaves complete history on both sides.
#[tokio::test]
async fn half_close_keeps_history_complete() {
    let harness = Harness::start().await;
    let echo = testlab::echo_server().await;

    let mut stream = socks_client::connect_through_proxy(
        harness.relay.local_addr(),
        Destination::Ip(echo.addr().ip()),
        echo.addr().port(),
        GreetingStyle::Single,
        RequestStyle::Single,
    )
    .await
    .expect("connect");
    let conn_id = harness
        .established_for_port(echo.addr().port())
        .expect("established event");

    let payload = deterministic_payload(32 * 1024);
    stream.write_all(&payload).await.expect("write");
    stream.shutdown().await.expect("client half-close");

    let mut received = vec![0u8; payload.len()];
    stream.read_exact(&mut received).await.expect("echo read");
    assert_eq!(received, payload);
    drop(stream);
    let close = harness.wait_history_close(&conn_id).await;

    assert_eq!(
        concat(
            &harness
                .history
                .chunks_for_direction(&conn_id, Direction::ClientToServer)
        ),
        payload
    );
    assert_eq!(
        concat(
            &harness
                .history
                .chunks_for_direction(&conn_id, Direction::ServerToClient)
        ),
        payload
    );
    assert_eq!(close.bytes_client_to_server, payload.len() as u64);
    assert_eq!(close.bytes_server_to_client, payload.len() as u64);

    harness.shutdown().await;
    echo.shutdown().await;
}

/// 15/16: shutdown with live traffic still records the close; history stays
/// queryable and no observer task can outlive the engine (observation spawns
/// no tasks by construction).
#[tokio::test]
async fn shutdown_with_live_traffic_records_close() {
    let mut harness = Harness::start().await;
    let echo = testlab::echo_server().await;

    let mut stream = socks_client::connect_through_proxy(
        harness.relay.local_addr(),
        Destination::Ip(echo.addr().ip()),
        echo.addr().port(),
        GreetingStyle::Single,
        RequestStyle::Single,
    )
    .await
    .expect("connect");
    let conn_id = harness
        .established_for_port(echo.addr().port())
        .expect("established event");

    let payload = deterministic_payload(256);
    stream.write_all(&payload).await.expect("write");
    // The session stays open with traffic potentially in flight.
    harness.relay.begin_shutdown();
    tokio::time::timeout(Duration::from_secs(10), harness.relay.wait_stopped())
        .await
        .expect("shutdown must complete with live traffic");

    let close = harness
        .history
        .connection(&conn_id)
        .expect("history open record");
    assert!(close.is_closed(), "shutdown must close the history record");
    assert_eq!(close.close_reason.as_deref(), Some("engine shutdown"));
    // Whatever was recorded is a prefix of what was sent: observation only
    // ever appends bytes the destination accepted, in order.
    let captured = concat(
        &harness
            .history
            .chunks_for_direction(&conn_id, Direction::ClientToServer),
    );
    assert_eq!(&payload[..captured.len()], captured.as_slice());

    drop(stream);
    echo.shutdown().await;
}

/// 17: bounds are enforced; newest entries survive, oldest are evicted.
#[tokio::test]
async fn eviction_keeps_newest_within_bounds() {
    let config = RelayConfig::default().with_history_limits(HistoryLimits {
        max_events: 4,
        max_bytes: u64::MAX,
        max_connections: 1,
    });
    let harness = Harness::start_with(config).await;
    let echo = testlab::echo_server().await;

    // Six sequential single-byte round-trips: each relay read observes
    // exactly the one available byte, so chunk boundaries are deterministic.
    let mut stream = socks_client::connect_through_proxy(
        harness.relay.local_addr(),
        Destination::Ip(echo.addr().ip()),
        echo.addr().port(),
        GreetingStyle::Single,
        RequestStyle::Single,
    )
    .await
    .expect("connect");
    let first = harness
        .established_for_port(echo.addr().port())
        .expect("established event");
    for byte in *b"abcdef" {
        stream
            .write_all(std::slice::from_ref(&byte))
            .await
            .expect("write");
        let mut back = [0u8; 1];
        stream.read_exact(&mut back).await.expect("echo read");
        assert_eq!(back, [byte]);
    }
    drop(stream);
    harness.wait_history_close(&first).await;

    // C→S and S→C interleave one byte at a time; the last four retained
    // chunks are deterministic: the final two round-trips, both directions.
    let all = harness.history.chunks();
    assert_eq!(all.len(), 4);
    let flat: Vec<(Direction, u8)> = all
        .iter()
        .map(|chunk| (chunk.direction, chunk.bytes[0]))
        .collect();
    assert_eq!(
        flat,
        [
            (Direction::ClientToServer, b'e'),
            (Direction::ServerToClient, b'e'),
            (Direction::ClientToServer, b'f'),
            (Direction::ServerToClient, b'f'),
        ]
    );

    // A second connection evicts the first connection record, while its
    // chunks remain retrievable (bounds are independent).
    let second = socks_client::connect_through_proxy(
        harness.relay.local_addr(),
        Destination::Ip(echo.addr().ip()),
        echo.addr().port(),
        GreetingStyle::Single,
        RequestStyle::Single,
    )
    .await
    .expect("connect");
    let second_id = harness
        .telemetry
        .events()
        .into_iter()
        .filter_map(|event| match event {
            Event::ConnectionEstablished { conn_id, .. } if conn_id != first => Some(conn_id),
            _ => None,
        })
        .next()
        .expect("second established");
    drop(second);
    assert!(harness.history.connection(&first).is_none());
    assert!(harness.history.connection(&second_id).is_some());

    harness.shutdown().await;
    echo.shutdown().await;
}

/// 18: end-to-end transparency — app bytes, captured bytes, and sent bytes
/// all agree on a large binary payload.
#[tokio::test]
async fn payload_transparency_end_to_end() {
    let harness = Harness::start().await;
    let echo = testlab::echo_server().await;

    let payload = deterministic_payload(64 * 1024);
    assert!(payload.contains(&0x00) && payload.contains(&0xff));

    let mut stream = socks_client::connect_through_proxy(
        harness.relay.local_addr(),
        Destination::Ip(echo.addr().ip()),
        echo.addr().port(),
        GreetingStyle::Single,
        RequestStyle::Single,
    )
    .await
    .expect("connect");
    let conn_id = harness
        .established_for_port(echo.addr().port())
        .expect("established event");

    stream.write_all(&payload).await.expect("write");
    let mut received = vec![0u8; payload.len()];
    stream.read_exact(&mut received).await.expect("echo read");
    assert_eq!(received, payload, "destination must see the exact payload");
    drop(stream);
    harness.wait_history_close(&conn_id).await;

    for direction in [Direction::ClientToServer, Direction::ServerToClient] {
        assert_eq!(
            concat(&harness.history.chunks_for_direction(&conn_id, direction)),
            payload,
            "history must equal forwarded bytes for {direction:?}"
        );
    }

    harness.shutdown().await;
    echo.shutdown().await;
}

/// Observer panic must not erase delivered-byte accounting.
///
/// Counters advance before observation, so a sink that panics still leaves
/// the exact delivered count behind. Reproduces the original defect shape:
/// 6 bytes delivered, 0 counted.
#[tokio::test]
async fn observer_panic_keeps_byte_accounting() {
    use tokio::net::{TcpListener, TcpStream};

    struct PanicSink;
    impl rawtcp_engine::HistorySink for PanicSink {
        fn record_connection_open(&self, _open: rawtcp_engine::ConnectionOpen) {}
        fn record_chunk(&self, _chunk: rawtcp_engine::TrafficChunk) {
            panic!("controlled observer panic");
        }
        fn record_connection_close(&self, _conn_id: &str, _close: rawtcp_engine::ConnectionClose) {}
    }

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
    let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let c2s = Arc::new(AtomicU64::new(0));
    let s2c = Arc::new(AtomicU64::new(0));
    let observer =
        rawtcp_engine::SessionObserver::new(Arc::new(PanicSink), "panic-acct".to_owned());
    let task = tokio::spawn(rawtcp_engine::transport::relay_with_counters(
        relay_client,
        relay_server,
        16 * 1024,
        shutdown_rx,
        Arc::clone(&c2s),
        Arc::clone(&s2c),
        observer,
        None,
    ));

    client_peer.write_all(b"doomed").await.expect("write");
    // The bytes reach the server peer: the write completed before the
    // observer ran, so delivery does not depend on the sink.
    let mut got = [0u8; 6];
    tokio::time::timeout(Duration::from_secs(5), server_peer.read_exact(&mut got))
        .await
        .expect("delivery must resolve")
        .expect("server read");
    assert_eq!(&got, b"doomed");

    let err = tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .expect("task must resolve");
    let err = err.expect_err("observer panic must fail the session");
    assert!(err.is_panic());
    assert_eq!(
        c2s.load(Ordering::SeqCst),
        6,
        "delivered bytes must be counted despite the panic"
    );
}

/// Snapshot reads during active forwarding neither stall nor corrupt it.
///
/// Readers share read access while capture writes take the brief write
/// lock; a 1 MiB transfer under snapshot hammering must complete promptly
/// with exact bytes.
#[tokio::test]
async fn snapshots_during_forwarding_stay_transparent() {
    let harness = Harness::start().await;
    let echo = testlab::echo_server().await;

    let mut stream = socks_client::connect_through_proxy(
        harness.relay.local_addr(),
        Destination::Ip(echo.addr().ip()),
        echo.addr().port(),
        GreetingStyle::Single,
        RequestStyle::Single,
    )
    .await
    .expect("connect");
    let conn_id = harness
        .established_for_port(echo.addr().port())
        .expect("established event");

    let payload = deterministic_payload(1024 * 1024);
    let history = Arc::clone(&harness.history);
    let hammer_conn = conn_id.clone();
    let hammer = tokio::spawn(async move {
        for _ in 0..500 {
            let _ = history.chunks();
            let _ = history.connections();
            let _ = history.chunks_for_direction(&hammer_conn, Direction::ClientToServer);
            tokio::task::yield_now().await;
        }
    });

    stream.write_all(&payload).await.expect("write");
    let mut received = vec![0u8; payload.len()];
    tokio::time::timeout(Duration::from_secs(30), stream.read_exact(&mut received))
        .await
        .expect("transfer must complete under snapshot load")
        .expect("echo read");
    assert_eq!(received, payload);
    hammer.await.expect("snapshotter");
    drop(stream);
    harness.wait_history_close(&conn_id).await;

    // Drops under snapshot pressure are counted loss, not corruption:
    // every retained chunk must sit at its true stream position, and
    // retention order must match seq order (single critical section).
    let retained = harness
        .history
        .chunks_for_direction(&conn_id, Direction::ClientToServer);
    let mut ordered = retained.clone();
    ordered.sort_by_key(|chunk| chunk.seq);
    assert_eq!(retained, ordered, "emission order matches seq order");
    for chunk in &ordered {
        let start = chunk.offset as usize;
        assert_eq!(
            &payload[start..start + chunk.len()],
            chunk.bytes.as_slice(),
            "retained bytes must match the payload at their offset"
        );
    }

    harness.shutdown().await;
    echo.shutdown().await;
}

/// Shutdown completes under snapshot pressure with consistent history.
///
/// Snapshots hammer both stores while a live session shuts down: chunk
/// drops are counted loss, metadata stages without waiting, and the
/// engine still drains on time.
#[tokio::test]
async fn shutdown_completes_under_snapshot_pressure() {
    let mut harness = Harness::start().await;
    let echo = testlab::echo_server().await;

    let mut stream = socks_client::connect_through_proxy(
        harness.relay.local_addr(),
        Destination::Ip(echo.addr().ip()),
        echo.addr().port(),
        GreetingStyle::Single,
        RequestStyle::Single,
    )
    .await
    .expect("connect");
    let conn_id = harness
        .established_for_port(echo.addr().port())
        .expect("established event");

    let payload = deterministic_payload(4096);
    stream.write_all(&payload).await.expect("write");

    let history = Arc::clone(&harness.history);
    let hammer = tokio::spawn(async move {
        for _ in 0..200 {
            let _ = history.chunks();
            let _ = history.connections();
            tokio::task::yield_now().await;
        }
    });

    harness.relay.begin_shutdown();
    tokio::time::timeout(Duration::from_secs(10), harness.relay.wait_stopped())
        .await
        .expect("shutdown must complete under snapshot pressure");
    hammer.await.expect("snapshotter");
    drop(stream);

    let record = harness
        .history
        .connection(&conn_id)
        .expect("history open record");
    assert!(record.is_closed(), "shutdown must close the history record");
    let captured = concat(
        &harness
            .history
            .chunks_for_direction(&conn_id, Direction::ClientToServer),
    );
    assert_eq!(&payload[..captured.len()], captured.as_slice());

    echo.shutdown().await;
}
