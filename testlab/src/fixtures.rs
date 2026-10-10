//! Controlled local TCP fixtures for Phase 1A testing.
//!
//! All fixtures bind `127.0.0.1` on an ephemeral port and are driven only by
//! test code. No fixture listens on a routable interface.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Notify;

/// Handle to a running fixture listener.
pub struct Fixture {
    addr: SocketAddr,
    accepted: Arc<AtomicU64>,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    join: tokio::task::JoinHandle<()>,
}

impl Fixture {
    /// Bound address, including the ephemeral port.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Number of connections accepted so far.
    pub fn accepted(&self) -> u64 {
        self.accepted.load(Ordering::SeqCst)
    }

    /// Stop the fixture and await its listener task.
    pub async fn shutdown(mut self) {
        if let Some(sender) = self.shutdown.take() {
            let _ = sender.send(());
        }
        let _ = self.join.await;
    }
}

async fn spawn_fixture<F, Fut>(handler: F) -> Fixture
where
    F: Fn(TcpStream) -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("fixture bind");
    let addr = listener.local_addr().expect("fixture local_addr");
    let accepted = Arc::new(AtomicU64::new(0));
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel();

    let counter = Arc::clone(&accepted);
    let join = tokio::spawn(async move {
        loop {
            let accepted_socket = tokio::select! {
                biased;
                _ = &mut shutdown_rx => break,
                result = listener.accept() => result,
            };
            let Ok((socket, _)) = accepted_socket else {
                break;
            };
            counter.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(handler(socket));
        }
    });

    Fixture {
        addr,
        accepted,
        shutdown: Some(shutdown_tx),
        join,
    }
}

/// Echo server: returns every received byte unchanged, preserving order.
///
/// Supports half-close: after the client shuts down its write half the fixture
/// keeps echoing until it has read EOF, then closes.
pub async fn echo_server() -> Fixture {
    spawn_fixture(|socket: TcpStream| async move {
        let (mut reader, mut writer) = socket.into_split();
        let mut buffer = vec![0u8; 8 * 1024];
        loop {
            match reader.read(&mut buffer).await {
                Ok(0) => break,
                Ok(n) => {
                    if writer.write_all(&buffer[..n]).await.is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        let _ = writer.shutdown().await;
    })
    .await
}

/// Server-first fixture: writes `banner` immediately on connect, then echoes.
///
/// Proves the relay does not require client-first traffic.
pub async fn server_first_server(banner: Vec<u8>) -> Fixture {
    spawn_fixture(move |socket: TcpStream| {
        let banner = Arc::new(banner.clone());
        async move {
            let (mut reader, mut writer) = socket.into_split();
            if writer.write_all(&banner).await.is_err() {
                return;
            }
            let _ = writer.flush().await;

            let mut buffer = vec![0u8; 8 * 1024];
            loop {
                match reader.read(&mut buffer).await {
                    Ok(0) => break,
                    Ok(n) => {
                        if writer.write_all(&buffer[..n]).await.is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
            let _ = writer.shutdown().await;
        }
    })
    .await
}

/// Half-close-capable fixture.
///
/// Sends `banner`, shuts down *only* its write half, and then keeps reading
/// until the client also half-closes. This is the required Phase 1A fixture
/// that proves a server may close its write side while the forward direction
/// remains usable.
pub async fn half_close_server(banner: Vec<u8>) -> Fixture {
    spawn_fixture(move |socket: TcpStream| {
        let banner = Arc::new(banner.clone());
        async move {
            let (mut reader, mut writer) = socket.into_split();
            if writer.write_all(&banner).await.is_err() {
                return;
            }
            let _ = writer.flush().await;

            // Half-close: signal EOF downstream, then keep reading.
            let _ = writer.shutdown().await;

            let mut buffer = vec![0u8; 8 * 1024];
            while let Ok(n) = reader.read(&mut buffer).await {
                if n == 0 {
                    break;
                }
            }
        }
    })
    .await
}

/// Newline-delimited login fixture.
///
/// Reads one `LOGIN <user> <password>\n` line and always answers
/// `AUTH_OK\n`. There is no account database and no authorization decision; the
/// fixed reply exists so tests can assert byte-exact forwarding.
pub async fn login_server() -> Fixture {
    spawn_fixture(|socket: TcpStream| async move {
        let (mut reader, mut writer) = socket.into_split();
        let mut line = Vec::new();
        let mut byte = [0u8; 1];

        loop {
            match reader.read(&mut byte).await {
                Ok(0) => break,
                Ok(_) => {
                    line.push(byte[0]);
                    if byte[0] == b'\n' {
                        let _ = writer.write_all(b"AUTH_OK\n").await;
                        let _ = writer.flush().await;
                        line.clear();
                    }
                }
                Err(_) => break,
            }
        }
        let _ = writer.shutdown().await;
    })
    .await
}

/// Reserve a loopback port and release it, so connections are refused.
pub async fn refused_endpoint() -> SocketAddr {
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("refused-endpoint bind");
    let addr = listener.local_addr().expect("refused-endpoint local_addr");
    drop(listener);
    addr
}

/// Read until the peer closes or `max_bytes` have arrived.
pub async fn read_exact_or_eof(stream: &mut TcpStream, max_bytes: usize) -> Vec<u8> {
    let mut out = Vec::new();
    let mut buffer = vec![0u8; 4096];
    while out.len() < max_bytes {
        match stream.read(&mut buffer).await {
            Ok(0) => break,
            Ok(n) => out.extend_from_slice(&buffer[..n]),
            Err(_) => break,
        }
    }
    out
}

/// A fixture that records the exact bytes it received, for asserting that the
/// relay delivered a client stream unchanged across a server-initiated FIN.
pub struct RecordingServer {
    fixture: Fixture,
    received: Arc<std::sync::Mutex<Vec<u8>>>,
    completed: Arc<AtomicBool>,
    done: Arc<Notify>,
}

impl RecordingServer {
    /// Bound address, including the ephemeral port.
    pub fn addr(&self) -> SocketAddr {
        self.fixture.addr()
    }

    /// Bytes received so far.
    pub fn received(&self) -> Vec<u8> {
        self.received
            .lock()
            .expect("recording buffer poisoned")
            .clone()
    }

    /// Resolve once the handler has finished reading (EOF or error).
    ///
    /// A relay close event only proves bytes reached the fixture's socket, not
    /// that the fixture task consumed them. Awaiting this removes that
    /// scheduling race.
    pub async fn wait_done(&self) {
        loop {
            if self.completed.load(Ordering::SeqCst) {
                return;
            }
            self.done.notified().await;
        }
    }

    /// Stop the fixture and await its listener task.
    pub async fn shutdown(self) {
        self.fixture.shutdown().await;
    }
}

/// Half-closes its write half immediately, then records everything it reads.
///
/// Backs [`half_close_server`] semantics while giving tests visibility into what
/// the relay forwarded after the server-side FIN.
pub async fn recording_half_close_server(banner: Vec<u8>) -> RecordingServer {
    let received = Arc::new(std::sync::Mutex::new(Vec::new()));
    let completed = Arc::new(AtomicBool::new(false));
    let done = Arc::new(Notify::new());

    let banner_for_handler = Arc::new(banner);
    let received_for_handler = Arc::clone(&received);
    let completed_for_handler = Arc::clone(&completed);
    let done_for_handler = Arc::clone(&done);
    let fixture = spawn_fixture(move |socket: TcpStream| {
        let banner = Arc::clone(&banner_for_handler);
        let received = Arc::clone(&received_for_handler);
        let completed = Arc::clone(&completed_for_handler);
        let done = Arc::clone(&done_for_handler);
        async move {
            async {
                let (mut reader, mut writer) = socket.into_split();
                if writer.write_all(&banner).await.is_err() {
                    return;
                }
                let _ = writer.flush().await;

                // Half-close the write side, then keep reading.
                let _ = writer.shutdown().await;

                let mut buffer = vec![0u8; 8 * 1024];
                loop {
                    match reader.read(&mut buffer).await {
                        Ok(0) => break,
                        Ok(n) => received
                            .lock()
                            .expect("recording buffer poisoned")
                            .extend_from_slice(&buffer[..n]),
                        Err(_) => break,
                    }
                }
            }
            .await;
            completed.store(true, Ordering::SeqCst);
            done.notify_one();
        }
    })
    .await;

    RecordingServer {
        fixture,
        received,
        completed,
        done,
    }
}

/// Fixture that accepts a connection and then stays silent: it never reads,
/// never writes, and holds the socket open.
///
/// Used to prove a relay error in one direction cancels the other one. If the
/// reverse direction were left waiting on this peer, the session would never
/// finish.
pub async fn silent_server(hold: Duration) -> Fixture {
    spawn_fixture(move |socket: TcpStream| async move {
        // Hold the socket without reading or writing so the peer direction
        // blocks until it is cancelled.
        tokio::time::sleep(hold).await;
        drop(socket);
    })
    .await
}
/// socket accepts, ignoring backpressure errors.
///
/// Used to drive the relay's write path past socket buffer limits so a
/// forwarding error can be observed deterministically.
pub async fn flood_server(total_bytes: u64) -> Fixture {
    let budget = Arc::new(total_bytes);
    spawn_fixture(move |socket: TcpStream| {
        let budget = Arc::clone(&budget);
        async move {
            let (mut reader, mut writer) = socket.into_split();

            // Drain whatever the client sends and discard it, so our own writes
            // are not blocked by the peer not reading.
            let drain = tokio::spawn(async move {
                let mut buffer = vec![0u8; 8 * 1024];
                while let Ok(n) = reader.read(&mut buffer).await {
                    if n == 0 {
                        break;
                    }
                }
            });

            let total = *budget;
            let mut written: u64 = 0;
            let buffer = vec![0x5Au8; 64 * 1024];
            while written < total {
                let remaining = (total - written) as usize;
                let chunk = remaining.min(buffer.len());
                if writer.write_all(&buffer[..chunk]).await.is_err() {
                    break;
                }
                written += chunk as u64;
            }
            let _ = writer.shutdown().await;
            drain.abort();
        }
    })
    .await
}
