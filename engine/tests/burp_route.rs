//! Burp routing integration tests: SOCKS sessions matching a route are
//! relayed through a Burp Proxy listener instead of dialled directly.
//!
//! Every test drives real SOCKS5 sessions through `spawn_relay_with`. The
//! fake Burp listener is a plain TCP echo server: routing is a TCP handoff,
//! so an echo proves the bytes reached the Burp address.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use prost::Message as ProstMessage;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::{tungstenite::Message as WsMessage, WebSocketStream};

use rawtcp_engine::ipc::proto::{
    self, ClientMessage, Hello, ListBurpRoutes, PendingUnits, Request, RequestBody, ServerMessage,
    ServerMessageBody, SetBurpRoutes, SetEnabled,
};
use rawtcp_engine::ipc::PROTOCOL_VERSION;
use rawtcp_engine::{spawn_relay_with, BurpRoute, RelayConfig};
use testlab::socks_client::{self, Destination, GreetingStyle, RequestStyle};

async fn relay_with_routes(routes: Vec<BurpRoute>) -> rawtcp_engine::RunningRelay {
    let (_, shared) = rawtcp_engine::telemetry::memory_telemetry();
    let config = RelayConfig::default()
        .with_endpoint(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)
        .with_burp_routes(routes);
    spawn_relay_with(config, shared).await.expect("relay bind")
}

async fn socks_connect(proxy: SocketAddr, target: SocketAddr) -> TcpStream {
    let mut stream = socks_client::open(proxy).await.expect("open");
    socks_client::greeting(
        &mut stream,
        GreetingStyle::Single,
        &[socks_client::consts::METHOD_NO_AUTH],
    )
    .await
    .expect("greeting");
    socks_client::send_request(
        &mut stream,
        &Destination::Ip(target.ip()),
        target.port(),
        RequestStyle::Single,
    )
    .await
    .expect("request");
    let reply = socks_client::read_reply(&mut stream).await.expect("reply");
    assert!(reply.is_success(), "SOCKS reply must succeed: {reply:?}");
    stream
}

/// A refused target routed to a live listener must succeed: the engine
/// dials the Burp address, and bytes flow both ways through it.
#[tokio::test]
async fn routed_session_dials_burp_listener_not_target() {
    let burp = TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("burp bind");
    let burp_addr = burp.local_addr().expect("burp addr");
    let refused = testlab::refused_endpoint().await;

    let route = BurpRoute {
        host_pattern: refused.ip().to_string(),
        port: refused.port(),
        burp_addr,
    };
    let relay = relay_with_routes(vec![route]).await;
    let proxy = relay.local_addr();

    let burp_task = tokio::spawn(async move {
        let (mut server, _) = burp.accept().await.expect("burp accept");
        let mut probe = [0u8; 5];
        server.read_exact(&mut probe).await.expect("burp read");
        assert_eq!(&probe, b"hello");
        server.write_all(b"world").await.expect("burp write");
        // Hold the socket until the client goes away so the relay stays up.
        let mut rest = Vec::new();
        let _ = server.read_to_end(&mut rest).await;
    });

    let mut client = socks_connect(proxy, refused).await;
    client.write_all(b"hello").await.expect("client write");
    let mut back = [0u8; 5];
    tokio::time::timeout(Duration::from_secs(5), client.read_exact(&mut back))
        .await
        .expect("response deadline")
        .expect("client read");
    assert_eq!(&back, b"world");
    drop(client);
    burp_task.await.expect("burp task");

    // History keeps the ORIGINAL destination and marks the session routed.
    let records = relay.history().connections();
    let record = records
        .iter()
        .find(|record| {
            record.requested_target == refused.ip().to_string()
                && record.requested_port == refused.port()
        })
        .expect("routed session must be recorded under its requested target");
    assert!(record.routed, "record must be marked routed");
    assert_eq!(record.route_target, Some(burp_addr));
    assert_eq!(record.resolved_upstream, Some(burp_addr));

    relay.shutdown().await;
}

/// Without a matching route the same echo path dials directly.
#[tokio::test]
async fn unmatched_session_dials_directly_and_is_not_routed() {
    let echo = testlab::echo_server().await;
    let relay = relay_with_routes(vec![]).await;
    let proxy = relay.local_addr();

    let mut client = socks_connect(proxy, echo.addr()).await;
    client.write_all(b"ping").await.expect("write");
    let mut back = [0u8; 4];
    tokio::time::timeout(Duration::from_secs(5), client.read_exact(&mut back))
        .await
        .expect("deadline")
        .expect("read");
    assert_eq!(&back, b"ping");
    drop(client);

    // Give the close record a moment to land.
    tokio::time::sleep(Duration::from_millis(200)).await;
    let records = relay.history().connections();
    let record = records
        .iter()
        .find(|record| record.requested_port == echo.addr().port())
        .expect("direct session must be recorded");
    assert!(!record.routed);
    assert_eq!(record.route_target, None);

    relay.shutdown().await;
    echo.shutdown().await;
}

// --- IPC route management -----------------------------------------------

async fn ws_connect(addr: SocketAddr) -> WebSocketStream<TcpStream> {
    let tcp = TcpStream::connect(addr).await.expect("tcp connect");
    let request = format!("ws://{addr}/")
        .into_client_request()
        .expect("ws request");
    let (ws, _) = tokio_tungstenite::client_async(request, tcp)
        .await
        .expect("ws handshake");
    ws
}

async fn handshake(addr: SocketAddr, token: &str) -> WebSocketStream<TcpStream> {
    let mut ws = ws_connect(addr).await;
    let hello = ClientMessage {
        request: Some(Request {
            request_id: 1,
            body: Some(RequestBody::Hello(Hello {
                protocol_version: PROTOCOL_VERSION,
                client_name: "burp-route-test".into(),
                client_version: "0.1".into(),
                capability_token: token.into(),
            })),
        }),
    };
    let mut buf = Vec::new();
    hello.encode(&mut buf).unwrap();
    ws.send(WsMessage::Binary(buf)).await.expect("hello");
    loop {
        let frame = ws.next().await.expect("frame").expect("read");
        let WsMessage::Binary(bytes) = frame else {
            continue;
        };
        let msg = ServerMessage::decode(&bytes[..]).expect("decode");
        if matches!(
            msg.body,
            Some(ServerMessageBody::Response(ref resp))
                if matches!(resp.body, Some(proto::ResponseBody::HelloAck(_)))
        ) {
            return ws;
        }
    }
}

async fn rpc(
    ws: &mut WebSocketStream<TcpStream>,
    request_id: u32,
    body: RequestBody,
) -> proto::Response {
    let msg = ClientMessage {
        request: Some(Request {
            request_id,
            body: Some(body),
        }),
    };
    let mut buf = Vec::new();
    msg.encode(&mut buf).unwrap();
    ws.send(WsMessage::Binary(buf)).await.expect("send");
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let frame = ws.next().await.expect("frame").expect("read");
            let bytes = match frame {
                WsMessage::Binary(b) => b,
                WsMessage::Ping(_) => continue,
                other => panic!("expected binary, got {other:?}"),
            };
            let msg = ServerMessage::decode(&bytes[..]).expect("decode");
            match msg.body {
                Some(ServerMessageBody::Response(resp)) if resp.request_id == request_id => {
                    return resp;
                }
                Some(ServerMessageBody::Event(_)) => continue,
                other => panic!("unexpected message: {other:?}"),
            }
        }
    })
    .await
    .expect("rpc deadline")
}

#[tokio::test]
async fn ipc_set_and_list_burp_routes_round_trip() {
    let (_, shared) = rawtcp_engine::telemetry::memory_telemetry();
    let config = RelayConfig::default()
        .with_endpoint(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)
        .with_ipc_port(0);
    let relay = spawn_relay_with(config, shared).await.expect("relay");
    let ipc_addr = relay.ipc().expect("ipc enabled").local_addr();
    let token = relay
        .ipc()
        .expect("ipc enabled")
        .capability_token()
        .to_owned();
    let mut ws = handshake(ipc_addr, &token).await;

    // Initially empty.
    let resp = rpc(
        ws.by_ref(),
        2,
        RequestBody::ListBurpRoutes(ListBurpRoutes {}),
    )
    .await;
    match resp.body {
        Some(proto::ResponseBody::BurpRouteList(list)) => assert!(list.routes.is_empty()),
        other => panic!("expected route list, got {other:?}"),
    }

    // Set two routes; the server echoes the table back.
    let resp = rpc(
        ws.by_ref(),
        3,
        RequestBody::SetBurpRoutes(SetBurpRoutes {
            routes: vec![
                proto::BurpRoute {
                    host_pattern: "10.0.0.5".into(),
                    port: 7007,
                    burp_addr: "127.0.0.1:8081".into(),
                },
                proto::BurpRoute {
                    host_pattern: "*".into(),
                    port: 0,
                    burp_addr: "127.0.0.1:8080".into(),
                },
            ],
        }),
    )
    .await;
    match resp.body {
        Some(proto::ResponseBody::BurpRouteList(list)) => {
            assert_eq!(list.routes.len(), 2);
            assert_eq!(list.routes[0].host_pattern, "10.0.0.5");
            assert_eq!(list.routes[0].port, 7007);
        }
        other => panic!("expected route list, got {other:?}"),
    }

    // A route set via IPC applies to subsequently accepted sessions.
    assert_eq!(
        relay.burp_router().route_for("10.0.0.5", 7007),
        Some("127.0.0.1:8081".parse().unwrap())
    );

    // Clearing works: empty replaces the table.
    let resp = rpc(
        ws.by_ref(),
        4,
        RequestBody::SetBurpRoutes(SetBurpRoutes { routes: vec![] }),
    )
    .await;
    match resp.body {
        Some(proto::ResponseBody::BurpRouteList(list)) => assert!(list.routes.is_empty()),
        other => panic!("expected empty route list, got {other:?}"),
    }
    assert_eq!(relay.burp_router().route_for("10.0.0.5", 7007), None);
}

#[tokio::test]
async fn ipc_rejects_invalid_burp_routes() {
    let (_, shared) = rawtcp_engine::telemetry::memory_telemetry();
    let config = RelayConfig::default()
        .with_endpoint(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)
        .with_ipc_port(0);
    let relay = spawn_relay_with(config, shared).await.expect("relay");
    let ipc_addr = relay.ipc().expect("ipc enabled").local_addr();
    let token = relay
        .ipc()
        .expect("ipc enabled")
        .capability_token()
        .to_owned();
    let mut ws = handshake(ipc_addr, &token).await;

    // Non-loopback Burp listener is rejected.
    let resp = rpc(
        ws.by_ref(),
        2,
        RequestBody::SetBurpRoutes(SetBurpRoutes {
            routes: vec![proto::BurpRoute {
                host_pattern: "*".into(),
                port: 0,
                burp_addr: "192.168.1.1:8080".into(),
            }],
        }),
    )
    .await;
    match resp.body {
        Some(proto::ResponseBody::Error(error)) => {
            assert_eq!(error.code, 4420);
            assert!(error.message.contains("loopback"));
        }
        other => panic!("expected validation error, got {other:?}"),
    }

    // The rejected update must not have replaced the table.
    let resp = rpc(
        ws.by_ref(),
        3,
        RequestBody::ListBurpRoutes(ListBurpRoutes {}),
    )
    .await;
    match resp.body {
        Some(proto::ResponseBody::BurpRouteList(list)) => assert!(list.routes.is_empty()),
        other => panic!("expected route list, got {other:?}"),
    }
}

/// A routed session must not appear in the interception hold queue even
/// with interception enabled: Burp owns the hold queue there.
#[tokio::test]
async fn routed_session_bypasses_interception_hold_queue() {
    let burp = TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("burp bind");
    let burp_addr = burp.local_addr().expect("burp addr");
    let refused = testlab::refused_endpoint().await;

    let route = BurpRoute {
        host_pattern: refused.ip().to_string(),
        port: refused.port(),
        burp_addr,
    };
    let (_, shared) = rawtcp_engine::telemetry::memory_telemetry();
    let config = RelayConfig::default()
        .with_endpoint(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)
        .with_ipc_port(0)
        .with_burp_routes(vec![route]);
    let relay = spawn_relay_with(config, shared).await.expect("relay");
    let proxy = relay.local_addr();
    let ipc_addr = relay.ipc().expect("ipc").local_addr();
    let token = relay.ipc().expect("ipc").capability_token().to_owned();
    let mut ws = handshake(ipc_addr, &token).await;

    // Enable interception in both directions.
    for (id, direction) in [
        (10u32, proto::Direction::ClientToServer),
        (11u32, proto::Direction::ServerToClient),
    ] {
        let resp = rpc(
            ws.by_ref(),
            id,
            RequestBody::SetEnabled(SetEnabled {
                direction: direction as i32,
                enabled: true,
            }),
        )
        .await;
        assert!(
            matches!(resp.body, Some(proto::ResponseBody::SetEnabledResult(_))),
            "enable must succeed: {resp:?}"
        );
    }

    let burp_task = tokio::spawn(async move {
        let (mut server, _) = burp.accept().await.expect("accept");
        let mut probe = [0u8; 4];
        server.read_exact(&mut probe).await.expect("read");
        server.write_all(b"pong").await.expect("write");
        let mut rest = Vec::new();
        let _ = server.read_to_end(&mut rest).await;
    });

    let mut client = socks_connect(proxy, refused).await;
    client.write_all(b"ping").await.expect("write");
    // Bytes must flow WITHOUT any Forward decision: the read would time
    // out if the engine held the chunk for interception.
    let mut back = [0u8; 4];
    tokio::time::timeout(Duration::from_secs(5), client.read_exact(&mut back))
        .await
        .expect("routed bytes must not be held")
        .expect("read");
    assert_eq!(&back, b"pong");

    // The hold queue stays empty while routed traffic flows.
    let resp = rpc(ws.by_ref(), 12, RequestBody::PendingUnits(PendingUnits {})).await;
    match resp.body {
        Some(proto::ResponseBody::PendingList(list)) => {
            assert!(list.units.is_empty(), "routed traffic must not be held");
        }
        other => panic!("expected pending list, got {other:?}"),
    }

    drop(client);
    burp_task.await.expect("burp task");
}
