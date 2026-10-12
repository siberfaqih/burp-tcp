//! Connection registry: opaque IDs, lifecycle state, and active-session bounds.
//!
//! A slot is reserved the moment a socket is accepted, *before* any SOCKS
//! negotiation begins. Reserving later would let half-open or stalled clients
//! occupy sockets and tasks outside the configured bound, because greeting and
//! request parsing are attacker-controlled in length and timing.

use std::net::SocketAddr;
use std::sync::{atomic::AtomicU64, Arc, Mutex};

use uuid::Uuid;

/// Lifecycle state of a relayed connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    /// Accepted; SOCKS negotiation in progress.
    Negotiating,
    /// Upstream established; forwarding in progress.
    Forwarding,
    /// Session finished.
    Closed,
}

/// An opaque connection record.
#[derive(Debug, Clone)]
pub struct Connection {
    /// Opaque connection identifier, never derived from the destination.
    pub id: String,
    /// SOCKS client address.
    pub client_addr: SocketAddr,
    /// Destination as requested by the client, once known.
    pub requested_target: Option<String>,
    /// Destination port as requested, once known.
    pub requested_port: Option<u16>,
    /// Current lifecycle state.
    pub state: ConnectionState,
    /// Forwarded bytes, independent of lossy history retention.
    pub bytes_c2s: Arc<AtomicU64>,
    /// Forwarded bytes in the reverse direction.
    pub bytes_s2c: Arc<AtomicU64>,
}

/// Result of trying to admit an accepted socket.
#[derive(Debug)]
pub enum Admission {
    /// A slot was reserved and the connection is tracked.
    Admitted(Connection),
    /// The registry is full. An ID is still allocated so the rejection is
    /// traceable in logs.
    Rejected { conn_id: String },
}

/// Tracks active connections and enforces a bounded active count.
#[derive(Debug)]
pub struct ConnectionRegistry {
    connections: Mutex<Vec<Connection>>,
    max_active: usize,
    accepted: AtomicU64,
}

impl ConnectionRegistry {
    /// Create a registry bounded to `max_active` concurrent connections.
    pub fn new(max_active: usize) -> Self {
        Self {
            connections: Mutex::new(Vec::new()),
            max_active: max_active.max(1),
            accepted: AtomicU64::new(0),
        }
    }

    /// Try to reserve a slot for a freshly accepted socket.
    ///
    /// Allocation and the capacity check happen under one lock, so concurrent
    /// accepts cannot race past the limit.
    pub fn reserve(&self, client_addr: SocketAddr) -> Admission {
        let mut guard = self.lock();

        if guard.len() >= self.max_active {
            return Admission::Rejected {
                conn_id: new_connection_id(),
            };
        }

        let connection = Connection {
            id: new_connection_id(),
            client_addr,
            requested_target: None,
            requested_port: None,
            state: ConnectionState::Negotiating,
            bytes_c2s: Arc::new(AtomicU64::new(0)),
            bytes_s2c: Arc::new(AtomicU64::new(0)),
        };
        guard.push(connection.clone());
        self.accepted
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Admission::Admitted(connection)
    }

    /// Current active connection count.
    pub fn active(&self) -> usize {
        self.lock().len()
    }

    /// Admitted SOCKS sockets since this engine started, including negotiation.
    pub fn accepted(&self) -> u64 {
        self.accepted.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Maximum concurrent connections allowed by configuration.
    pub fn capacity(&self) -> usize {
        self.max_active
    }

    /// Whether a new connection may be admitted right now.
    pub fn has_capacity(&self) -> bool {
        self.active() < self.max_active
    }

    /// Snapshot of tracked connections.
    pub fn snapshot(&self) -> Vec<Connection> {
        self.lock().clone()
    }

    /// Record the destination requested by the client.
    pub fn set_destination(&self, id: &str, target: String, port: u16) {
        self.update(id, |connection| {
            connection.requested_target = Some(target);
            connection.requested_port = Some(port);
        });
    }

    /// Transition a connection to forwarding.
    pub fn mark_forwarding(&self, id: &str) {
        self.update(id, |connection| {
            connection.state = ConnectionState::Forwarding;
        });
    }

    /// Attach the transport's lifetime counters before forwarding starts.
    pub fn set_counters(&self, id: &str, c2s: Arc<AtomicU64>, s2c: Arc<AtomicU64>) {
        self.update(id, |connection| {
            connection.bytes_c2s = c2s;
            connection.bytes_s2c = s2c;
        });
    }

    fn update(&self, id: &str, mutate: impl FnOnce(&mut Connection)) {
        let Ok(mut guard) = self.connections.lock() else {
            return;
        };
        if let Some(connection) = guard.iter_mut().find(|connection| connection.id == id) {
            mutate(connection);
        }
    }

    /// Release a connection slot.
    pub fn close(&self, id: &str) {
        if let Ok(mut guard) = self.connections.lock() {
            guard.retain(|connection| connection.id != id);
        }
    }

    /// Drop every tracked connection (shutdown path).
    pub fn clear(&self) {
        if let Ok(mut guard) = self.connections.lock() {
            guard.clear();
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Vec<Connection>> {
        self.connections
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

/// Opaque, non-guessable connection identifier.
fn new_connection_id() -> String {
    Uuid::new_v4().to_string()
}
