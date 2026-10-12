//! Phase 3 integration tests: manual interception.
//!
//! Every test drives real SOCKS5 sessions through `spawn_relay_with` and
//! the relay's interception handle. The Phase 3 gate is exercised end to
//! end: duplicate/stale decisions never cause duplicate emission, and
//! held bytes are never overtaken in the same direction. Transparency
//! defaults (no policy enabled) are covered by the whole Phase 2 suite
//! running unchanged against this build.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use rawtcp_engine::intercept::{InterceptAction, InterceptLimits};
use rawtcp_engine::telemetry::{memory_telemetry, Event, MemoryTelemetry};
use rawtcp_engine::{spawn_relay_with, Direction, InterceptCoordinator, RelayConfig};
use testlab::socks_client::{self, Destination, GreetingStyle, RequestStyle};

/// Relay + handles used by every test.
struct Harness {
    relay: rawtcp_engine::RunningRelay,
    intercept: Arc<InterceptCoordinator>,
    telemetry: Arc<MemoryTelemetry>,
}

impl Harness {
    async fn start_with(limits: InterceptLimits) -> Self {
        let (sink, shared) = memory_telemetry();
        let config = RelayConfig::default()
            .with_endpoint(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)
            .with_intercept_limits(limits);
        let relay = spawn_relay_with(config, shared).await.expect("relay bind");
        let intercept = relay.intercept();
        Self {
            relay,
            intercept,
            telemetry: sink,
        }
    }

    async fn start() -> Self {
        Self::start_with(InterceptLimits {
            max_pending: 16,
            hold_lease: Duration::from_secs(30),
            max_replace_bytes: 1024 * 1024,
        })
        .await
    }

    /// Connection ID of the established session to `port`.
    fn established_for_port(&self, port: u16) -> String {
        for _ in 0..200 {
            if let Some(id) = self
                .telemetry
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
            {
                return id;
            }
        }
        panic!("no established session for port {port}");
    }

    /// Wait until the pending queue holds at least one unit, then return
    /// the first (oldest) one.
    async fn wait_pending(&self) -> rawtcp_engine::HeldUnit {
        for _ in 0..500 {
            if let Some(unit) = self.intercept.pending().first().cloned() {
                return unit;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("no pending unit appeared");
    }

    /// Wait until exactly `n` units are pending (offer count is
    /// deterministic: one per connection write), returning them in
    /// queue order.
    async fn wait_pending_exact(&self, n: usize) -> Vec<rawtcp_engine::HeldUnit> {
        for _ in 0..500 {
            let pending = self.intercept.pending();
            if pending.len() == n {
                return pending;
            }
            assert!(
                pending.len() < n,
                "more than {n} pending units: {pending:?}"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("{n} pending units never appeared");
    }

    /// Telemetry close event for `conn_id`.
    async fn wait_close_reason(&self, conn_id: &str) -> String {
        for _ in 0..500 {
            if let Some(reason) =
                self.telemetry
                    .events()
                    .into_iter()
                    .find_map(|event| match event {
                        Event::ConnectionClosed {
                            conn_id: id,
                            reason,
                            ..
                        } if id == conn_id => Some(reason),
                        _ => None,
                    })
            {
                return reason;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("no close event for {conn_id}");
    }
}

/// 1. Forward delivers the original bytes and records them in history.
#[tokio::test]
async fn forward_decision_delivers_original_bytes() {
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
    let conn_id = harness.established_for_port(echo.addr().port());

    harness
        .intercept
        .set_enabled(Direction::ClientToServer, true);
    stream.write_all(b"payload").await.expect("write");

    let unit = harness.wait_pending().await;
    assert_eq!(unit.conn_id, conn_id);
    assert_eq!(unit.direction, Direction::ClientToServer);
    assert_eq!(unit.bytes, b"payload");
    assert_eq!(unit.seq, 0);
    assert_eq!(unit.offset, 0);
    assert_eq!(unit.revision, 0);

    harness
        .intercept
        .decide(&unit.id, 0, InterceptAction::Forward)
        .expect("forward commits");

    let mut echoed = [0u8; 7];
    tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut echoed))
        .await
        .expect("echo must resolve")
        .expect("echo read");
    assert_eq!(&echoed, b"payload");

    // History records the delivered bytes with contiguous seq/offset.
    let chunks = harness
        .relay
        .history()
        .chunks_for_direction(&conn_id, Direction::ClientToServer);
    assert_eq!(chunks.len(), 1);
    assert_eq!(chunks[0].bytes, b"payload");
    assert_eq!(chunks[0].seq, 0);
    assert_eq!(chunks[0].offset, 0);

    harness.relay.shutdown().await;
    echo.shutdown().await;
}

/// 2. Replace delivers the replacement bytes instead; history records
///    what was actually delivered (Phase 2 contract preserved).
#[tokio::test]
async fn replace_decision_delivers_replacement_bytes() {
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
    let conn_id = harness.established_for_port(echo.addr().port());

    harness
        .intercept
        .set_enabled(Direction::ClientToServer, true);
    // Binary-unsafe replacement: NUL and 0xFF must survive verbatim.
    stream.write_all(b"orig").await.expect("write");

    let unit = harness.wait_pending().await;
    harness
        .intercept
        .decide(
            &unit.id,
            0,
            InterceptAction::Replace(vec![0x00, 0xff, b'!']),
        )
        .expect("replace commits");

    let mut echoed = [0u8; 3];
    tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut echoed))
        .await
        .expect("echo must resolve")
        .expect("echo read");
    assert_eq!(&echoed, &[0x00, 0xff, b'!']);

    let chunks = harness
        .relay
        .history()
        .chunks_for_direction(&conn_id, Direction::ClientToServer);
    assert_eq!(chunks.len(), 1);
    assert_eq!(chunks[0].bytes, vec![0x00, 0xff, b'!']);
    assert_eq!(chunks[0].seq, 0);
    assert_eq!(chunks[0].offset, 0, "offset counts delivered bytes");

    harness.relay.shutdown().await;
    echo.shutdown().await;
}

/// 3. Suppress delivers nothing for the unit but keeps the session
///    flowing; subsequent units are unaffected.
#[tokio::test]
async fn suppress_decision_delivers_nothing_and_keeps_flow() {
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
    let conn_id = harness.established_for_port(echo.addr().port());

    harness
        .intercept
        .set_enabled(Direction::ClientToServer, true);

    stream.write_all(b"first").await.expect("write one");
    let first = harness.wait_pending().await;
    harness
        .intercept
        .decide(&first.id, first.revision, InterceptAction::Suppress)
        .expect("suppress commits");

    stream.write_all(b"second").await.expect("write two");
    let second = harness.wait_pending().await;
    assert_eq!(second.seq, 1, "suppressed unit still consumes read order");
    assert_eq!(second.offset, 5, "offer offsets count source reads");
    harness
        .intercept
        .decide(&second.id, second.revision, InterceptAction::Forward)
        .expect("forward commits");

    // Only "second" comes back.
    let mut echoed = [0u8; 6];
    tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut echoed))
        .await
        .expect("echo must resolve")
        .expect("echo read");
    assert_eq!(&echoed, b"second");

    let chunks = harness
        .relay
        .history()
        .chunks_for_direction(&conn_id, Direction::ClientToServer);
    assert_eq!(chunks.len(), 1, "suppressed unit never reaches history");
    assert_eq!(chunks[0].bytes, b"second");
    assert_eq!(chunks[0].seq, 0, "history seq is delivery order");
    assert_eq!(chunks[0].offset, 0);

    harness.relay.shutdown().await;
    echo.shutdown().await;
}

/// 4. Close tears the session down with a truthful terminal reason.
#[tokio::test]
async fn close_decision_ends_session_with_truthful_reason() {
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
    let conn_id = harness.established_for_port(echo.addr().port());

    harness
        .intercept
        .set_enabled(Direction::ClientToServer, true);
    stream.write_all(b"doomed").await.expect("write");

    let unit = harness.wait_pending().await;
    harness
        .intercept
        .decide(&unit.id, 0, InterceptAction::Close)
        .expect("close commits");

    // The client observes EOF promptly.
    let mut tail = [0u8; 1];
    let ended = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut tail))
        .await
        .expect("session must end");
    assert_eq!(ended.unwrap_or(0), 0, "close must deliver EOF, not bytes");

    let reason = harness.wait_close_reason(&conn_id).await;
    assert_eq!(
        reason, "closed by interception decision",
        "terminal reason must name the interception close"
    );

    harness.relay.shutdown().await;
    echo.shutdown().await;
}

/// 5. THE GATE: held bytes cannot be overtaken in the same direction.
///    While a unit is held, later same-direction bytes must not reach the
///    server; after the decision everything arrives in source order.
#[tokio::test]
async fn held_bytes_cannot_be_overtaken() {
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
    harness.established_for_port(echo.addr().port());

    harness
        .intercept
        .set_enabled(Direction::ClientToServer, true);

    stream.write_all(b"held").await.expect("write held");
    let unit = harness.wait_pending().await;

    // Send later bytes while the first unit is held.
    stream.write_all(b"later").await.expect("write later");

    // Nothing may arrive at the server while the unit is held.
    let mut probe = [0u8; 5];
    let leaked = tokio::time::timeout(Duration::from_millis(300), stream.read(&mut probe)).await;
    assert!(
        leaked.is_err(),
        "no byte may overtake a held unit: got {leaked:?}"
    );

    // Now decide: the held unit goes first, then the later bytes.
    harness
        .intercept
        .decide(&unit.id, 0, InterceptAction::Forward)
        .expect("forward commits");

    let second = harness.wait_pending().await;
    assert_eq!(second.bytes, b"later");
    harness
        .intercept
        .decide(&second.id, 0, InterceptAction::Forward)
        .expect("forward commits");

    let mut received = Vec::new();
    let mut buffer = [0u8; 16];
    loop {
        let n = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buffer))
            .await
            .expect("echo must resolve")
            .expect("echo read");
        if n == 0 {
            break;
        }
        received.extend_from_slice(&buffer[..n]);
        if received.len() >= 9 {
            break;
        }
    }
    assert_eq!(received, b"heldlater", "order must be held-then-later");

    harness.relay.shutdown().await;
    echo.shutdown().await;
}

/// 6. THE GATE: duplicate and stale decisions never cause duplicate
///    emission.
#[tokio::test]
async fn duplicate_and_stale_decisions_are_rejected() {
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
    harness.established_for_port(echo.addr().port());

    harness
        .intercept
        .set_enabled(Direction::ClientToServer, true);
    stream.write_all(b"once").await.expect("write");

    let unit = harness.wait_pending().await;

    // Stale revision: rejected, unit stays pending.
    let stale = harness
        .intercept
        .decide(&unit.id, unit.revision + 5, InterceptAction::Close);
    assert_eq!(
        stale,
        Err(rawtcp_engine::DecisionError::StaleRevision {
            unit_id: unit.id.clone(),
            presented: unit.revision + 5,
            expected: unit.revision,
        })
    );
    assert_eq!(harness.intercept.pending().len(), 1);

    // Correct revision commits...
    harness
        .intercept
        .decide(&unit.id, unit.revision, InterceptAction::Forward)
        .expect("forward commits");

    // ...and every later attempt — duplicate or stale — is rejected.
    for revision in [unit.revision, 99] {
        let duplicate = harness
            .intercept
            .decide(&unit.id, revision, InterceptAction::Forward);
        assert_eq!(
            duplicate,
            Err(rawtcp_engine::DecisionError::UnknownUnit {
                unit_id: unit.id.clone()
            })
        );
    }
    assert!(harness.intercept.pending().is_empty());
    assert_eq!(harness.intercept.commits(), 1);

    // Exactly one delivery: the echo returns "once" exactly once.
    let mut echoed = [0u8; 4];
    tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut echoed))
        .await
        .expect("echo must resolve")
        .expect("echo read");
    assert_eq!(&echoed, b"once");

    // No further bytes may arrive: a duplicate emission would surface
    // as extra echo bytes on the still-open stream.
    let mut probe = [0u8; 4];
    let leaked = tokio::time::timeout(Duration::from_millis(300), stream.read(&mut probe)).await;
    assert!(
        leaked.is_err(),
        "no extra bytes may follow the single delivery: got {leaked:?}"
    );

    // The duplicate attempts must not have corrupted the session: a
    // fresh write still flows, and only its echo comes back.
    stream.write_all(b"again").await.expect("write again");
    let next = harness.wait_pending().await;
    assert_eq!(next.bytes, b"again");
    harness
        .intercept
        .decide(&next.id, next.revision, InterceptAction::Forward)
        .expect("session still accepts decisions");
    let mut echoed = [0u8; 5];
    tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut echoed))
        .await
        .expect("second echo must resolve")
        .expect("echo read");
    assert_eq!(&echoed, b"again");

    // Final no-extra-bytes check: exactly the new payload came back.
    let mut probe = [0u8; 4];
    let leaked = tokio::time::timeout(Duration::from_millis(300), stream.read(&mut probe)).await;
    assert!(
        leaked.is_err(),
        "no extra bytes may follow the second delivery: got {leaked:?}"
    );

    harness.relay.shutdown().await;
    echo.shutdown().await;
}

/// 7. The finite hold lease: an undecided unit is forwarded unchanged
///    when the lease expires, and a late decision is rejected.
#[tokio::test]
async fn lease_expiry_forwards_and_rejects_late_decisions() {
    let harness = Harness::start_with(InterceptLimits {
        max_pending: 16,
        hold_lease: Duration::from_millis(150),
        max_replace_bytes: 1024 * 1024,
    })
    .await;
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
    harness.established_for_port(echo.addr().port());

    harness
        .intercept
        .set_enabled(Direction::ClientToServer, true);
    stream.write_all(b"leased").await.expect("write");

    let unit = harness.wait_pending().await;
    // No decision at all: the lease must forward the original bytes.
    let mut echoed = [0u8; 6];
    tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut echoed))
        .await
        .expect("lease must release the unit")
        .expect("echo read");
    assert_eq!(&echoed, b"leased");

    // The late decision finds the unit already resolved.
    let late = harness
        .intercept
        .decide(&unit.id, 0, InterceptAction::Suppress);
    assert_eq!(
        late,
        Err(rawtcp_engine::DecisionError::UnknownUnit {
            unit_id: unit.id.clone()
        })
    );
    assert!(harness.intercept.pending().is_empty());
    assert_eq!(harness.intercept.commits(), 0);
    assert!(harness.intercept.lease_releases() >= 1);

    harness.relay.shutdown().await;
    echo.shutdown().await;
}

/// 8. Directional policy: enabling server-to-client only (BEFORE
///    connecting, since the server-first fixture writes its banner on
///    accept, so the hold must be in place deterministically) holds the
///    banner and its echo, while client-to-server traffic is never held.
#[tokio::test]
async fn directional_policy_holds_only_enabled_direction() {
    let harness = Harness::start().await;
    let server = testlab::server_first_server(b"banner".to_vec()).await;

    // Enable before connecting: the fixture writes its banner the moment
    // the relay connects upstream, so the policy must already be in
    // place for the banner hold to be deterministic.
    harness
        .intercept
        .set_enabled(Direction::ServerToClient, true);
    assert!(!harness.intercept.enabled(Direction::ClientToServer));

    let mut stream = socks_client::connect_through_proxy(
        harness.relay.local_addr(),
        Destination::Ip(server.addr().ip()),
        server.addr().port(),
        GreetingStyle::Single,
        RequestStyle::Single,
    )
    .await
    .expect("connect");
    harness.established_for_port(server.addr().port());

    // The server-first banner is held...
    let unit = harness.wait_pending().await;
    assert_eq!(unit.direction, Direction::ServerToClient);
    assert_eq!(unit.bytes, b"banner");
    // ...and the client has received nothing yet.
    let mut probe = [0u8; 6];
    let leaked = tokio::time::timeout(Duration::from_millis(200), stream.read(&mut probe)).await;
    assert!(leaked.is_err(), "held banner must not reach the client");

    harness
        .intercept
        .decide(&unit.id, 0, InterceptAction::Forward)
        .expect("forward commits");
    let mut banner = [0u8; 6];
    tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut banner))
        .await
        .expect("banner must resolve")
        .expect("banner read");
    assert_eq!(&banner, b"banner");

    // Client-to-server stays transparent, proven by receipt: the request
    // flows to the server without ever being held (no c2s unit appears)
    // and returns as an s2c unit — the echo.
    stream.write_all(b"request").await.expect("write");
    let echo = harness.wait_pending().await;
    assert_eq!(echo.direction, Direction::ServerToClient);
    assert_eq!(echo.bytes, b"request");
    let pending = harness.intercept.pending();
    assert!(
        pending
            .iter()
            .all(|unit| unit.direction == Direction::ServerToClient),
        "client_to_server must never be held: {pending:?}"
    );

    harness
        .intercept
        .decide(&echo.id, 0, InterceptAction::Forward)
        .expect("forward commits");
    let mut echoed = [0u8; 7];
    tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut echoed))
        .await
        .expect("echo must resolve")
        .expect("echo read");
    assert_eq!(&echoed, b"request");

    harness.relay.shutdown().await;
    server.shutdown().await;
}

/// 9. Disabling interception releases the direction's pending units.
#[tokio::test]
async fn disabling_releases_pending_units() {
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
    harness.established_for_port(echo.addr().port());

    harness
        .intercept
        .set_enabled(Direction::ClientToServer, true);
    stream.write_all(b"release-me").await.expect("write");
    let unit = harness.wait_pending().await;

    let released = harness
        .intercept
        .set_enabled(Direction::ClientToServer, false);
    assert_eq!(released, 1, "disable must release the held unit");
    assert!(harness.intercept.pending().is_empty());
    assert_eq!(harness.intercept.disable_releases(), 1);

    let mut echoed = [0u8; 10];
    tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut echoed))
        .await
        .expect("released unit must be delivered")
        .expect("echo read");
    assert_eq!(&echoed, b"release-me");

    // A decision for the released unit is stale.
    let late = harness
        .intercept
        .decide(&unit.id, 0, InterceptAction::Suppress);
    assert!(matches!(
        late,
        Err(rawtcp_engine::DecisionError::UnknownUnit { .. })
    ));

    // After disabling, further traffic is never held.
    stream.write_all(b"free").await.expect("write");
    let mut echoed = [0u8; 4];
    tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut echoed))
        .await
        .expect("post-disable traffic must flow")
        .expect("echo read");
    assert_eq!(&echoed, b"free");
    assert!(harness.intercept.pending().is_empty());

    harness.relay.shutdown().await;
    echo.shutdown().await;
}

/// 10. Bounded pending queue: offers beyond capacity are forwarded
///     without interception and counted, never stalling the relay.
#[tokio::test]
async fn full_pending_queue_forwards_without_interception() {
    let harness = Harness::start_with(InterceptLimits {
        max_pending: 1,
        hold_lease: Duration::from_secs(30),
        max_replace_bytes: 1024 * 1024,
    })
    .await;
    let echo = testlab::echo_server().await;

    // Connection A: its first c2s unit fills the queue.
    let mut a = socks_client::connect_through_proxy(
        harness.relay.local_addr(),
        Destination::Ip(echo.addr().ip()),
        echo.addr().port(),
        GreetingStyle::Single,
        RequestStyle::Single,
    )
    .await
    .expect("connect a");
    harness.established_for_port(echo.addr().port());
    harness
        .intercept
        .set_enabled(Direction::ClientToServer, true);
    a.write_all(b"held").await.expect("write a");
    let held = harness.wait_pending().await;
    assert_eq!(held.bytes, b"held");

    // Connection B: the queue is full, so its traffic passes through.
    let mut b = socks_client::connect_through_proxy(
        harness.relay.local_addr(),
        Destination::Ip(echo.addr().ip()),
        echo.addr().port(),
        GreetingStyle::Single,
        RequestStyle::Single,
    )
    .await
    .expect("connect b");
    harness.established_for_port(echo.addr().port());
    b.write_all(b"overflow").await.expect("write b");

    let mut echoed = [0u8; 8];
    tokio::time::timeout(Duration::from_secs(5), b.read_exact(&mut echoed))
        .await
        .expect("overflow traffic must not stall")
        .expect("echo read");
    assert_eq!(&echoed, b"overflow");
    assert!(harness.intercept.overflow_forwards() >= 1);

    // The held unit is still pending and still decidable.
    harness
        .intercept
        .decide(&held.id, 0, InterceptAction::Forward)
        .expect("held unit is unaffected by the overflow");
    let mut echoed = [0u8; 4];
    tokio::time::timeout(Duration::from_secs(5), a.read_exact(&mut echoed))
        .await
        .expect("held unit must be delivered after decision")
        .expect("echo read");
    assert_eq!(&echoed, b"held");

    harness.relay.shutdown().await;
    echo.shutdown().await;
}

/// 11. Engine shutdown completes even while a unit is held: the session
///     observes the shutdown flag, the unit is abandoned (swept), and no
///     forwarding outlives the engine.
#[tokio::test]
async fn shutdown_completes_while_unit_is_held() {
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
    let conn_id = harness.established_for_port(echo.addr().port());

    harness
        .intercept
        .set_enabled(Direction::ClientToServer, true);
    stream.write_all(b"held-at-shutdown").await.expect("write");
    let _unit = harness.wait_pending().await;

    // Shutdown must complete within the grace period despite the hold.
    // The harness is dismantled first so its telemetry handle stays
    // usable for the terminal-record check below.
    let Harness {
        relay,
        intercept,
        telemetry,
    } = harness;
    tokio::time::timeout(Duration::from_secs(10), relay.shutdown())
        .await
        .expect("shutdown must complete while a unit is held");

    // The held session was torn down: the client sees EOF.
    let mut tail = [0u8; 1];
    let ended = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut tail))
        .await
        .expect("session must resolve");
    assert_eq!(ended.unwrap_or(0), 0);

    // The abandoned unit is swept out of the queue...
    assert!(intercept.pending().is_empty());
    assert!(intercept.abandoned() >= 1);
    // ...and its session still left a truthful terminal record.
    for _ in 0..500 {
        if let Some(reason) = telemetry
            .events()
            .into_iter()
            .find_map(|event| match event {
                Event::ConnectionClosed {
                    conn_id: id,
                    reason,
                    ..
                } if id == conn_id => Some(reason),
                _ => None,
            })
        {
            assert_eq!(reason, "engine shutdown");
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("no close event for {conn_id}");
}

/// 12. Default transparency: a relay whose control plane never enables
///     interception forwards normally and never queues anything.
#[tokio::test]
async fn untouched_coordinator_is_fully_transparent() {
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
    let conn_id = harness.established_for_port(echo.addr().port());

    stream.write_all(b"plain").await.expect("write");
    let mut echoed = [0u8; 5];
    tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut echoed))
        .await
        .expect("echo must resolve")
        .expect("echo read");
    assert_eq!(&echoed, b"plain");

    assert!(!harness.intercept.enabled(Direction::ClientToServer));
    assert!(!harness.intercept.enabled(Direction::ServerToClient));
    assert_eq!(harness.intercept.offers(), 0);
    assert!(harness.intercept.pending().is_empty());

    let chunks = harness
        .relay
        .history()
        .chunks_for_direction(&conn_id, Direction::ClientToServer);
    assert_eq!(chunks.len(), 1);
    assert_eq!(chunks[0].bytes, b"plain");

    harness.relay.shutdown().await;
    echo.shutdown().await;
}

/// 13. Both directions can be held independently on one session: a
///     client-to-server unit is decided Forward, then the server-to-client
///     echo reply is held and decided with a Replace delivered to the
///     client.
#[tokio::test]
async fn both_directions_held_independently() {
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
    let conn_id = harness.established_for_port(echo.addr().port());

    harness
        .intercept
        .set_enabled(Direction::ClientToServer, true);
    harness
        .intercept
        .set_enabled(Direction::ServerToClient, true);

    stream.write_all(b"up").await.expect("write up");
    let up = harness.wait_pending().await;
    assert_eq!(up.direction, Direction::ClientToServer);
    harness
        .intercept
        .decide(&up.id, 0, InterceptAction::Forward)
        .expect("forward up");

    // The echo reply is held in the reverse direction.
    let down = harness.wait_pending().await;
    assert_eq!(down.direction, Direction::ServerToClient);
    assert_eq!(down.bytes, b"up");
    harness
        .intercept
        .decide(&down.id, 0, InterceptAction::Replace(b"dn".to_vec()))
        .expect("replace down");

    let mut echoed = [0u8; 2];
    tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut echoed))
        .await
        .expect("replaced reply must resolve")
        .expect("echo read");
    assert_eq!(&echoed, b"dn");

    // Both directions are recorded with their delivered bytes.
    let up_chunks = harness
        .relay
        .history()
        .chunks_for_direction(&conn_id, Direction::ClientToServer);
    let down_chunks = harness
        .relay
        .history()
        .chunks_for_direction(&conn_id, Direction::ServerToClient);
    assert_eq!(up_chunks.len(), 1);
    assert_eq!(up_chunks[0].bytes, b"up");
    assert_eq!(down_chunks.len(), 1);
    assert_eq!(down_chunks[0].bytes, b"dn");

    harness.relay.shutdown().await;
    echo.shutdown().await;
}

/// 14. Many concurrent held sessions all decide exactly once; every
///     decision is delivered, none is duplicated.
#[tokio::test]
async fn concurrent_sessions_decide_exactly_once() {
    let harness = Harness::start().await;
    let echo = testlab::echo_server().await;
    harness
        .intercept
        .set_enabled(Direction::ClientToServer, true);

    let count = 8;
    let mut streams = Vec::with_capacity(count);
    let mut payloads = Vec::with_capacity(count);
    for index in 0..count {
        let payload = format!("payload-{index}").into_bytes();
        let mut stream = socks_client::connect_through_proxy(
            harness.relay.local_addr(),
            Destination::Ip(echo.addr().ip()),
            echo.addr().port(),
            GreetingStyle::Single,
            RequestStyle::Single,
        )
        .await
        .expect("connect");
        harness.established_for_port(echo.addr().port());
        stream.write_all(&payload).await.expect("write");
        streams.push(stream);
        payloads.push(payload);
    }
    // Every connection holds exactly one unit; queue order may differ
    // from offer order across threads, so units are matched to payloads
    // by their bytes rather than by position.
    let units = harness.wait_pending_exact(count).await;
    let mut unit_by_payload = std::collections::HashMap::new();
    for unit in units {
        let expected = payloads
            .iter()
            .find(|payload| **payload == unit.bytes)
            .expect("each held unit carries its connection's payload");
        assert!(
            unit_by_payload.insert(expected.clone(), unit).is_none(),
            "two units carry the same payload"
        );
    }

    // Decide every unit, half Forward, half Replace.
    for (index, payload) in payloads.iter().enumerate() {
        let unit = &unit_by_payload[payload];
        let action = if index % 2 == 0 {
            InterceptAction::Forward
        } else {
            InterceptAction::Replace(vec![b'X'; payload.len()])
        };
        harness
            .intercept
            .decide(&unit.id, unit.revision, action)
            .expect("each decision commits exactly once");
    }
    assert!(harness.intercept.pending().is_empty());
    assert_eq!(harness.intercept.commits(), count as u64);

    for (index, stream) in streams.iter_mut().enumerate() {
        let expected: Vec<u8> = if index % 2 == 0 {
            format!("payload-{index}").into_bytes()
        } else {
            vec![b'X'; format!("payload-{index}").len()]
        };
        let mut echoed = vec![0u8; expected.len()];
        tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut echoed))
            .await
            .expect("echo must resolve")
            .expect("echo read");
        assert_eq!(
            echoed, expected,
            "session {index} must receive its decision exactly once"
        );
    }

    // No duplicated payload tails: after the exact reads, none of the
    // streams may hold further bytes. Checking every stream keeps the
    // assertion strong and is cheap compared to per-stream gaps.
    for (index, stream) in streams.iter_mut().enumerate() {
        let mut probe = [0u8; 8];
        let leaked =
            tokio::time::timeout(Duration::from_millis(300), stream.read(&mut probe)).await;
        assert!(
            leaked.is_err(),
            "session {index} must not receive extra bytes after its single delivery: got {leaked:?}"
        );
    }

    harness.relay.shutdown().await;
    echo.shutdown().await;
}

/// 15. Snapshot pressure is transparent: while a control plane hammers
///     `pending()` (every call copying all held payloads), a live session
///     still holds, decides, and receives its delivery, and engine
///     shutdown completes within its grace period.
#[tokio::test]
async fn snapshot_pressure_does_not_stall_decisions_or_shutdown() {
    use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};

    let harness = Harness::start().await;
    let echo = testlab::echo_server().await;
    harness
        .intercept
        .set_enabled(Direction::ClientToServer, true);

    // Eight sessions each hold one 4 KiB unit (below the relay buffer
    // size, so each write is exactly one read chunk).
    let mut streams = Vec::new();
    for _ in 0..8 {
        let mut stream = socks_client::connect_through_proxy(
            harness.relay.local_addr(),
            Destination::Ip(echo.addr().ip()),
            echo.addr().port(),
            GreetingStyle::Single,
            RequestStyle::Single,
        )
        .await
        .expect("connect");
        stream
            .write_all(&testlab::deterministic_payload(4096))
            .await
            .expect("write");
        streams.push(stream);
    }
    harness.wait_pending_exact(8).await;

    // Continuous snapshot pressure: every call copies every held payload
    // (32 KiB per call here), and each call takes the queue lock.
    let hammer_stop = Arc::new(AtomicBool::new(false));
    let hammer_stop_for_task = Arc::clone(&hammer_stop);
    let hammer_intercept = Arc::clone(&harness.intercept);
    let hammer = tokio::spawn(async move {
        while !hammer_stop_for_task.load(AtomicOrdering::Relaxed) {
            let _ = hammer_intercept.pending();
            tokio::task::yield_now().await;
        }
    });

    // A ninth session holds, decides, and receives its echo while the
    // hammer runs.
    let mut live = socks_client::connect_through_proxy(
        harness.relay.local_addr(),
        Destination::Ip(echo.addr().ip()),
        echo.addr().port(),
        GreetingStyle::Single,
        RequestStyle::Single,
    )
    .await
    .expect("connect live");
    live.write_all(b"live").await.expect("write live");
    let units = harness.wait_pending_exact(9).await;
    let live_unit = units
        .into_iter()
        .find(|unit| unit.bytes == b"live")
        .expect("the live session's unit must be held");
    harness
        .intercept
        .decide(&live_unit.id, live_unit.revision, InterceptAction::Forward)
        .expect("decision commits under snapshot pressure");
    let mut echoed = [0u8; 4];
    tokio::time::timeout(Duration::from_secs(5), live.read_exact(&mut echoed))
        .await
        .expect("delivery must not stall under snapshot pressure")
        .expect("echo read");
    assert_eq!(&echoed, b"live");

    // Shutdown completes within its grace period despite the pressure
    // and the eight still-held sessions.
    tokio::time::timeout(Duration::from_secs(10), harness.relay.shutdown())
        .await
        .expect("shutdown must complete under snapshot pressure");

    hammer_stop.store(true, AtomicOrdering::Relaxed);
    let _ = tokio::time::timeout(Duration::from_secs(5), hammer).await;
    // The eight held sessions died with the engine: their units must be
    // swept (nothing may stay pending after shutdown).
    assert!(harness.intercept.pending().is_empty());
    echo.shutdown().await;
}
