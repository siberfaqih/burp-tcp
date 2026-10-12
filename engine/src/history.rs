//! Passive capture and bounded in-memory history for Phase 2.
//!
//! The relay calls [`HistorySink`] as bytes are handed to their destination
//! socket; the sink never modifies, delays, drops, or replays traffic.
//!
//! # Vocabulary
//!
//! History records observed stream chunks, never application messages:
//! a single `read()` may hold part of one logical message or many, and
//! Phase 2 does not solve framing. The types are therefore named
//! [`TrafficChunk`] (not request/response/message).
//!
//! # Ordering guarantees
//!
//! * Per connection **and** direction, the observer assigns a contiguous
//!   `seq` starting at 0 in the order writes to the destination completed,
//!   and an `offset` equal to the cumulative bytes forwarded before the
//!   chunk. What is *stored* may skip: contention drops
//!   ([`MemoryHistory::dropped_chunks`]) and bound eviction remove entries
//!   after assignment. Concatenating the *stored* chunks in `seq` order
//!   reproduces the delivered stream exactly when nothing was lost;
//!   otherwise every retained chunk is still positioned truthfully by its
//!   `offset`. Internal/prefix gaps are visible in offsets; detecting a
//!   missing suffix also requires the final forwarded-byte counters.
//! * Sequencing lives in [`SessionObserver`], which is constructed once per
//!   session by the supervisor: cursor state dies with the session, so no
//!   cursor storage can accumulate across sessions. Assignment and emission
//!   happen under one critical section, so even observers shared across
//!   threads on one direction cannot emit out of order.
//! * Across directions or connections **no total order is guaranteed**: the
//!   two copy directions run concurrently. Each chunk also carries a wall
//!   (`SystemTime`, UTC) and a monotonic (`Instant`) timestamp for
//!   approximate correlation only; do not treat timestamp order as exact.
//!
//! # Bounded policy and forwarding safety
//!
//! [`MemoryHistory`] retains at most [`HistoryLimits::max_events`] chunks,
//! [`HistoryLimits::max_bytes`] of chunk payload, and
//! [`HistoryLimits::max_connections`] connection records. When a bound
//! would be exceeded, the **oldest entries are evicted first** (FIFO).
//! Connection records and chunks are bounded independently: evicting a
//! connection record never deletes chunks, and a closing connection whose
//! record was already evicted is re-inserted as closed **without**
//! fabricated opening metadata (`opened_*` stays `None`).
//! Oversized chunks are immediately evicted. Contention can reject new
//! observations too: loss counters cover contention, not FIFO eviction.
//! Empty chunks are ignored, not counted as lost application bytes.
//!
//! Chunk recording uses `try_write`: any competing reader or writer can
//! cause a counted drop, never a wait for the chunk store. Metadata uses a
//! bounded ingress queue (4096 ops) separate from a single-drainer lock.
//! Producers use only try-locks; ingress contention drops the new op,
//! overflow evicts the oldest queued op, both counted by `pending_dropped`.
//! Drain serialization protects FIFO application without holding ingress
//! while waiting on the metadata store, applying a batch, or cloning a
//! snapshot. Snapshots may block, but recording and finalization never wait
//! on snapshot locks. Snapshots apply all accepted, non-evicted operations
//! completed before they began; dropped/evicted metadata is not recoverable.
//! Timestamps are sampled at record invocation, not deferred application.
//! No observer task, await, network I/O, or disk I/O is introduced.

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::{Mutex, RwLock};
use std::time::{Instant, SystemTime};

use uuid::Uuid;

/// Direction of a captured byte flow, relative to the SOCKS client.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Direction {
    /// Bytes read from the SOCKS client and written to the upstream server.
    ClientToServer,
    /// Bytes read from the upstream server and written to the SOCKS client.
    ServerToClient,
}

impl Direction {
    /// Stable short name for logs and derived views.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ClientToServer => "client_to_server",
            Self::ServerToClient => "server_to_client",
        }
    }
}

/// One observed transport write: the exact bytes handed to a destination
/// socket, in write-completion order.
///
/// Assigned `seq` is contiguous per session and direction from 0; retained
/// chunks can have gaps after contention or eviction. `offset` counts the
/// bytes forwarded before this chunk, including unretained observations.
/// `bytes` are authoritative: any hex/text rendering must derive from them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrafficChunk {
    /// Unique chunk identifier (UUID v4).
    pub id: String,
    /// Connection this chunk belongs to.
    pub conn_id: String,
    /// Which direction the bytes flowed.
    pub direction: Direction,
    /// Position in the per-direction write-completion order, from 0, as
    /// allocated by the observer. Stored chunks may skip numbers when
    /// entries are dropped under contention or evicted under pressure;
    /// see `offset` for positioning that survives loss.
    pub seq: u64,
    /// Cumulative bytes forwarded in this direction before this chunk.
    pub offset: u64,
    /// Exact bytes written to the destination socket. Never empty.
    pub bytes: Vec<u8>,
    /// Wall-clock (UTC) capture time.
    pub captured_wall: SystemTime,
    /// Monotonic capture time, for durations and approximate correlation.
    pub captured_mono: Instant,
}

impl TrafficChunk {
    /// Payload length in bytes.
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// True when the chunk carries no payload (never stored).
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

/// Metadata supplied when a forwarding session starts.
#[derive(Debug, Clone)]
pub struct ConnectionOpen {
    /// Connection this record belongs to.
    pub conn_id: String,
    /// Destination exactly as requested by the client.
    pub requested_target: String,
    /// Destination port as requested.
    pub requested_port: u16,
    /// Endpoint actually dialled after resolution.
    pub resolved_upstream: SocketAddr,
}

/// Metadata supplied when a forwarding session ends.
#[derive(Debug, Clone)]
pub struct ConnectionClose {
    /// Total bytes forwarded client -> server, as reported by transport.
    pub bytes_client_to_server: u64,
    /// Total bytes forwarded server -> client, as reported by transport.
    pub bytes_server_to_client: u64,
    /// Why forwarding stopped.
    pub reason: String,
}

/// Connection-level metadata, kept separately from traffic chunks so large
/// per-connection facts are not duplicated into every chunk.
#[derive(Debug, Clone)]
pub struct ConnectionRecord {
    /// Connection this record belongs to.
    pub conn_id: String,
    /// Destination exactly as requested by the client.
    pub requested_target: String,
    /// Destination port as requested.
    pub requested_port: u16,
    /// Endpoint actually dialled after resolution, when known.
    pub resolved_upstream: Option<SocketAddr>,
    /// Wall-clock (UTC) time the session started forwarding, if the open
    /// record was retained. `None` means the open was evicted under
    /// pressure (or its Open operation was dropped) before the close
    /// arrived: no opening time is fabricated.
    pub opened_wall: Option<SystemTime>,
    /// Monotonic time the session started forwarding, if retained.
    pub opened_mono: Option<Instant>,
    /// Wall-clock (UTC) time the session ended, if it has.
    pub closed_wall: Option<SystemTime>,
    /// Monotonic time the session ended, if it has.
    pub closed_mono: Option<Instant>,
    /// Why forwarding stopped, once known.
    pub close_reason: Option<String>,
    /// Total bytes forwarded client -> server, once known.
    pub bytes_client_to_server: u64,
    /// Total bytes forwarded server -> client, once known.
    pub bytes_server_to_client: u64,
}

impl ConnectionRecord {
    /// True once an accepted Close operation has been applied to this record.
    pub fn is_closed(&self) -> bool {
        self.close_reason.is_some()
    }
}

/// Explicit bounds for [`MemoryHistory`]. All three must be at least 1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HistoryLimits {
    /// Maximum retained traffic chunks (oldest evicted first).
    pub max_events: usize,
    /// Maximum retained chunk payload bytes (oldest evicted first).
    pub max_bytes: u64,
    /// Maximum retained connection records (oldest evicted first).
    pub max_connections: usize,
}

impl HistoryLimits {
    /// Smallest usable bounds, for eviction tests.
    pub fn minimal() -> Self {
        Self {
            max_events: 1,
            max_bytes: 1,
            max_connections: 1,
        }
    }
}

impl Default for HistoryLimits {
    fn default() -> Self {
        Self {
            max_events: 8192,
            max_bytes: 8 * 1024 * 1024,
            max_connections: 1024,
        }
    }
}

/// Storage abstraction for capture. The transport layer knows only this
/// trait, so persistence can replace [`MemoryHistory`] later without
/// touching the relay.
///
/// Sequencing (`seq`/`offset`) is assigned by [`SessionObserver`], which is
/// constructed once per session: the sink only stores fully formed chunks.
/// Implementations must be synchronous and must never block on network or
/// disk I/O: they run inline with forwarding. Lossy-under-pressure
/// behaviour (like [`MemoryHistory`]'s oldest-first eviction) must be
/// documented on the implementation.
pub trait HistorySink: Send + Sync + 'static {
    /// Record that a session started forwarding.
    fn record_connection_open(&self, open: ConnectionOpen);
    /// Store one fully sequenced chunk.
    ///
    /// Empty chunks carry no information and may be ignored. Because this
    /// runs inline with forwarding, implementations must not wait on
    /// readers: drop (and count) rather than block when a snapshot is in
    /// progress.
    fn record_chunk(&self, chunk: TrafficChunk);
    /// Record that a session stopped forwarding.
    fn record_connection_close(&self, conn_id: &str, close: ConnectionClose);
}

/// Shared history handle.
pub type SharedHistory = std::sync::Arc<dyn HistorySink>;

/// Per-direction write-completion cursor: next sequence number and the
/// cumulative byte offset before it.
#[derive(Debug, Default)]
struct DirCursor {
    next_seq: u64,
    offset: u64,
}

/// Per-connection cursors, one per direction. Owned by [`SessionObserver`],
/// so cursor state dies with the session and can never accumulate across
/// sessions the way a sink-side cursor map would.
#[derive(Debug, Default)]
struct ConnCursors {
    client_to_server: DirCursor,
    server_to_client: DirCursor,
}

impl ConnCursors {
    fn for_direction(&mut self, direction: Direction) -> &mut DirCursor {
        match direction {
            Direction::ClientToServer => &mut self.client_to_server,
            Direction::ServerToClient => &mut self.server_to_client,
        }
    }
}

/// Chunk payload store with its own lock, so chunk snapshots (read) and
/// capture writes contend only with each other — never with connection
/// metadata, and concurrent snapshots never block one another.
#[derive(Debug, Default)]
struct ChunkStore {
    chunks: VecDeque<TrafficChunk>,
    bytes_retained: u64,
}

/// Connection metadata operation staged when the store is contended.
///
/// Accepted staged ops apply in enqueue order on the next store access. Staging keeps
/// the record path off the store lock: forwarding and shutdown never wait
/// for a snapshot reader.
#[derive(Debug)]
enum ConnOp {
    Open {
        open: ConnectionOpen,
        at: RecordTime,
    },
    Close {
        conn_id: String,
        close: ConnectionClose,
        at: RecordTime,
    },
}

/// Captured at the recording boundary, never reconstructed at application.
#[derive(Debug, Clone, Copy)]
struct RecordTime {
    wall: SystemTime,
    mono: Instant,
}

impl RecordTime {
    fn now() -> Self {
        Self {
            wall: SystemTime::now(),
            mono: Instant::now(),
        }
    }
}

/// Queue cap; up to one additional batch of this size can be in flight.
/// Oldest queued ops are dropped (counted) rather than stalling recording.
const MAX_PENDING_OPS: usize = 4096;

/// Connection metadata store with its own lock, independent of chunks.
#[derive(Debug, Default)]
struct ConnStore {
    conns: VecDeque<ConnectionRecord>,
}

/// Bounded in-memory [`HistorySink`].
///
/// Chunk capture is nonblocking: [`HistorySink::record_chunk`] drops (and
/// counts) a chunk instead of waiting when a snapshot holds the store.
/// Metadata producers never wait either: ingress contention and queue
/// overflow are counted losses. Read APIs drain accepted pending metadata
/// first, and are allowed to block off the forwarding path.
///
/// See the module docs for ordering guarantees, eviction policy, and
/// forwarding-safety properties.
#[derive(Debug)]
pub struct MemoryHistory {
    limits: HistoryLimits,
    chunks: RwLock<ChunkStore>,
    conns: RwLock<ConnStore>,
    /// Serializes batch extraction/application and metadata snapshots.
    /// Producers only try this lock, never wait for a snapshot's drain.
    drainer: Mutex<()>,
    /// Staged metadata ops; this guard never covers store acquisition,
    /// application, or snapshot cloning. Batch take uses `mem::take`.
    pending: Mutex<VecDeque<ConnOp>>,
    dropped_chunks: std::sync::atomic::AtomicU64,
    dropped_bytes: std::sync::atomic::AtomicU64,
    /// Metadata ops lost to ingress contention or pending-queue overflow.
    pending_dropped: std::sync::atomic::AtomicU64,
}

impl Default for MemoryHistory {
    fn default() -> Self {
        Self::new(HistoryLimits::default())
    }
}

impl MemoryHistory {
    /// Create a history bound by `limits`.
    pub fn new(limits: HistoryLimits) -> Self {
        Self {
            limits,
            chunks: RwLock::new(ChunkStore::default()),
            conns: RwLock::new(ConnStore::default()),
            drainer: Mutex::new(()),
            pending: Mutex::new(VecDeque::new()),
            dropped_chunks: std::sync::atomic::AtomicU64::new(0),
            dropped_bytes: std::sync::atomic::AtomicU64::new(0),
            pending_dropped: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Active bounds.
    pub fn limits(&self) -> HistoryLimits {
        self.limits
    }

    /// Snapshot of all retained connection records, oldest first.
    ///
    /// Applies every accepted, non-evicted metadata operation completed
    /// before this call. Concurrent calls may be included too. Lost ops
    /// (`pending_dropped`) cannot be recovered. May block off the data path.
    pub fn connections(&self) -> Vec<ConnectionRecord> {
        self.snapshot_conns(|conns| conns.iter().cloned().collect())
    }

    /// Snapshot of one connection record, if retained.
    ///
    /// Applies staged metadata first; see [`MemoryHistory::connections`].
    pub fn connection(&self, conn_id: &str) -> Option<ConnectionRecord> {
        self.snapshot_conns(|conns| {
            conns
                .iter()
                .find(|record| record.conn_id == conn_id)
                .cloned()
        })
    }

    /// Snapshot of all retained chunks, oldest first.
    ///
    /// Note: retention order is global push order, which interleaves
    /// directions and connections. Use per-direction `seq` for stream order.
    pub fn chunks(&self) -> Vec<TrafficChunk> {
        self.read_chunks().chunks.iter().cloned().collect()
    }

    /// Snapshot of retained chunks for one connection, oldest first.
    pub fn chunks_for(&self, conn_id: &str) -> Vec<TrafficChunk> {
        self.read_chunks()
            .chunks
            .iter()
            .filter(|chunk| chunk.conn_id == conn_id)
            .cloned()
            .collect()
    }

    /// Snapshot of retained chunks for one connection and direction, oldest
    /// first. Only lossless retention reconstructs the entire delivered
    /// stream; otherwise use offsets and final counters to locate gaps.
    pub fn chunks_for_direction(&self, conn_id: &str, direction: Direction) -> Vec<TrafficChunk> {
        self.read_chunks()
            .chunks
            .iter()
            .filter(|chunk| chunk.conn_id == conn_id && chunk.direction == direction)
            .cloned()
            .collect()
    }

    /// Retained chunk payload bytes (for bound assertions in tests).
    pub fn bytes_retained(&self) -> u64 {
        self.read_chunks().bytes_retained
    }

    /// Chunks dropped instead of waiting for the store lock, cumulative.
    ///
    /// A competing reader or writer can cause a drop. This excludes FIFO
    /// eviction, oversized-chunk eviction, and ignored empty slices. Dropped sequence
    /// numbers leave gaps: use `offset` ranges, not `seq` contiguity, to
    /// detect loss.
    pub fn dropped_chunks(&self) -> u64 {
        self.dropped_chunks
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Payload bytes dropped with [`MemoryHistory::dropped_chunks`].
    pub fn dropped_bytes(&self) -> u64 {
        self.dropped_bytes
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Metadata ops lost to ingress contention or queue overflow, cumulative.
    /// This does not count eviction of already-applied connection records.
    pub fn pending_dropped(&self) -> u64 {
        self.pending_dropped
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Enqueue without waiting, then opportunistically apply one batch.
    /// Loss of an observation affects history only, never network bytes.
    fn record_op(&self, op: ConnOp) {
        {
            let mut pending = match self.pending.try_lock() {
                Ok(guard) => guard,
                Err(std::sync::TryLockError::Poisoned(error)) => error.into_inner(),
                Err(std::sync::TryLockError::WouldBlock) => {
                    self.pending_dropped
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    return;
                }
            };
            if pending.len() == MAX_PENDING_OPS {
                pending.pop_front();
                self.pending_dropped
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
            pending.push_back(op);
        }
        self.try_drain();
    }

    /// Exactly one drainer may extract/apply a batch at a time. Ingress
    /// is released before application; snapshots never hold it while
    /// waiting for a store lock or cloning records.
    fn try_drain(&self) {
        let _drainer = match self.drainer.try_lock() {
            Ok(guard) => guard,
            Err(std::sync::TryLockError::Poisoned(error)) => error.into_inner(),
            Err(std::sync::TryLockError::WouldBlock) => return,
        };
        let mut store = match self.conns.try_write() {
            Ok(guard) => guard,
            Err(std::sync::TryLockError::Poisoned(error)) => error.into_inner(),
            Err(std::sync::TryLockError::WouldBlock) => return,
        };
        let batch = {
            let mut pending = match self.pending.try_lock() {
                Ok(guard) => guard,
                Err(std::sync::TryLockError::Poisoned(error)) => error.into_inner(),
                Err(std::sync::TryLockError::WouldBlock) => return,
            };
            std::mem::take(&mut *pending)
        };
        for op in batch {
            Self::apply_op(&mut store.conns, &self.limits, op);
        }
    }

    /// Serialized drain + snapshot, with no ingress guard during store
    /// wait, batch application, or projection. Readers may block; record
    /// calls enqueue (or count a loss) without waiting for these locks.
    fn snapshot_conns<R>(&self, project: impl FnOnce(&VecDeque<ConnectionRecord>) -> R) -> R {
        let _drainer = self
            .drainer
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut store = self
            .conns
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let batch = {
            let mut pending = self
                .pending
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            std::mem::take(&mut *pending)
        };
        for op in batch {
            Self::apply_op(&mut store.conns, &self.limits, op);
        }
        project(&store.conns)
    }

    /// Apply under the single-drainer guard, in accepted enqueue order.
    /// Event timestamps travel with the op and are independent of delays.
    fn apply_op(conns: &mut VecDeque<ConnectionRecord>, limits: &HistoryLimits, op: ConnOp) {
        match op {
            ConnOp::Open { open, at } => {
                conns.push_back(ConnectionRecord {
                    conn_id: open.conn_id,
                    requested_target: open.requested_target,
                    requested_port: open.requested_port,
                    resolved_upstream: Some(open.resolved_upstream),
                    opened_wall: Some(at.wall),
                    opened_mono: Some(at.mono),
                    closed_wall: None,
                    closed_mono: None,
                    close_reason: None,
                    bytes_client_to_server: 0,
                    bytes_server_to_client: 0,
                });
            }
            ConnOp::Close { conn_id, close, at } => {
                match conns.iter_mut().find(|record| record.conn_id == conn_id) {
                    Some(record) => {
                        record.closed_wall = Some(at.wall);
                        record.closed_mono = Some(at.mono);
                        record.close_reason = Some(close.reason);
                        record.bytes_client_to_server = close.bytes_client_to_server;
                        record.bytes_server_to_client = close.bytes_server_to_client;
                    }
                    // The open record was already evicted under pressure:
                    // retain the close metadata rather than losing the
                    // session's outcome, but leave the opening timestamps
                    // empty instead of fabricating a zero-duration session.
                    None => {
                        conns.push_back(ConnectionRecord {
                            conn_id,
                            requested_target: String::from("-"),
                            requested_port: 0,
                            resolved_upstream: None,
                            opened_wall: None,
                            opened_mono: None,
                            closed_wall: Some(at.wall),
                            closed_mono: Some(at.mono),
                            close_reason: Some(close.reason),
                            bytes_client_to_server: close.bytes_client_to_server,
                            bytes_server_to_client: close.bytes_server_to_client,
                        });
                    }
                }
            }
        }
        while conns.len() > limits.max_connections {
            conns.pop_front();
        }
    }

    fn read_chunks(&self) -> std::sync::RwLockReadGuard<'_, ChunkStore> {
        self.chunks
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

impl HistorySink for MemoryHistory {
    fn record_connection_open(&self, open: ConnectionOpen) {
        self.record_op(ConnOp::Open {
            open,
            at: RecordTime::now(),
        });
    }

    fn record_chunk(&self, chunk: TrafficChunk) {
        if chunk.is_empty() {
            return;
        }
        // Any competing reader/writer costs us this observation (counted),
        // never forwarded bytes. Metadata uses a separate bounded ingress.
        let mut chunks = match self.chunks.try_write() {
            Ok(guard) => guard,
            Err(std::sync::TryLockError::Poisoned(poisoned)) => poisoned.into_inner(),
            Err(std::sync::TryLockError::WouldBlock) => {
                self.dropped_chunks
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                self.dropped_bytes
                    .fetch_add(chunk.len() as u64, std::sync::atomic::Ordering::Relaxed);
                return;
            }
        };
        chunks.bytes_retained += chunk.len() as u64;
        chunks.chunks.push_back(chunk);
        while chunks.chunks.len() > self.limits.max_events
            || chunks.bytes_retained > self.limits.max_bytes
        {
            match chunks.chunks.pop_front() {
                Some(evicted) => {
                    chunks.bytes_retained =
                        chunks.bytes_retained.saturating_sub(evicted.len() as u64);
                }
                None => break,
            }
        }
    }

    fn record_connection_close(&self, conn_id: &str, close: ConnectionClose) {
        let at = RecordTime::now();
        self.record_op(ConnOp::Close {
            conn_id: conn_id.to_owned(),
            close,
            at,
        });
    }
}

/// Per-session observation handle handed to the transport layer.
///
/// Constructed once per session by the supervisor and cloned cheaply per
/// copy direction. Sequencing cursors live here (not in the sink), so
/// cursor state dies with the session and can never accumulate across
/// sessions. Every `observe` call records exactly the bytes just written
/// to the destination socket.
#[derive(Clone)]
pub struct SessionObserver {
    history: SharedHistory,
    conn_id: String,
    cursors: std::sync::Arc<Mutex<ConnCursors>>,
}

impl SessionObserver {
    /// Observe on behalf of `conn_id` through `history`.
    pub fn new(history: SharedHistory, conn_id: String) -> Self {
        Self {
            history,
            conn_id,
            cursors: std::sync::Arc::new(Mutex::new(ConnCursors::default())),
        }
    }

    /// Connection the observer tags every chunk with. Phase 3 interception
    /// offers are attributed with the same id.
    pub fn conn_id(&self) -> &str {
        &self.conn_id
    }

    /// Record `bytes` as forwarded in `direction`, assigning this
    /// session's next `seq`/`offset`. Empty slices are ignored.
    ///
    /// Assignment and emission share one critical section, so observers
    /// shared across threads on one direction cannot emit out of `seq`
    /// order. Synchronous and brief: one short mutex plus the sink's own
    /// short lock. Never awaits, never blocks on I/O.
    pub fn observe(&self, direction: Direction, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }
        let mut cursors = self
            .cursors
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let cursor = cursors.for_direction(direction);
        let (seq, offset) = (cursor.next_seq, cursor.offset);
        cursor.next_seq += 1;
        cursor.offset += bytes.len() as u64;
        // Inside the cursor lock on purpose: no other thread can slip an
        // emission between this assignment and the store below. Lock order
        // is always observer-then-sink and the sink never calls back, so
        // this cannot deadlock; both locks stay brief and await-free.
        self.history.record_chunk(TrafficChunk {
            id: Uuid::new_v4().to_string(),
            conn_id: self.conn_id.clone(),
            direction,
            seq,
            offset,
            bytes: bytes.to_vec(),
            captured_wall: SystemTime::now(),
            captured_mono: Instant::now(),
        });
    }
}

/// Render bytes as uppercase hex pairs separated by spaces: `00 01 FF 41 42`.
///
/// Derived view only; [`TrafficChunk::bytes`] remain canonical.
pub fn hex_view(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(bytes.len() * 3);
    for (index, byte) in bytes.iter().enumerate() {
        if index > 0 {
            out.push(' ');
        }
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

/// Render bytes as ASCII-safe text: printable ASCII (0x20–0x7E) as-is,
/// anything else as `.`. The `...AB` shape for `00 01 FF 41 42`.
///
/// Derived view only; [`TrafficChunk::bytes`] remain canonical. Never
/// assumes UTF-8.
pub fn text_view(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| {
            if (0x20..=0x7e).contains(byte) {
                *byte as char
            } else {
                '.'
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Observer wired to a fresh history, for unit tests of sequencing.
    fn observed(history: &std::sync::Arc<MemoryHistory>, conn: &str) -> SessionObserver {
        SessionObserver::new(history.clone(), conn.to_owned())
    }

    fn limits() -> HistoryLimits {
        HistoryLimits {
            max_events: 64,
            max_bytes: 64 * 1024,
            max_connections: 16,
        }
    }

    fn open(id: &str) -> ConnectionOpen {
        ConnectionOpen {
            conn_id: id.to_owned(),
            requested_target: "127.0.0.1".to_owned(),
            requested_port: 1433,
            resolved_upstream: "127.0.0.1:1433".parse().expect("addr"),
        }
    }

    fn close(c2s: u64, s2c: u64) -> ConnectionClose {
        ConnectionClose {
            bytes_client_to_server: c2s,
            bytes_server_to_client: s2c,
            reason: "eof".to_owned(),
        }
    }

    #[test]
    fn traffic_is_sequenced_per_direction_with_offsets() {
        let history = std::sync::Arc::new(MemoryHistory::new(limits()));
        history.record_connection_open(open("a"));
        let observer = observed(&history, "a");
        observer.observe(Direction::ClientToServer, b"he");
        observer.observe(Direction::ServerToClient, b"XY");
        observer.observe(Direction::ClientToServer, b"llo");

        let c2s = history.chunks_for_direction("a", Direction::ClientToServer);
        assert_eq!(c2s.len(), 2);
        assert_eq!(c2s[0].seq, 0);
        assert_eq!(c2s[0].offset, 0);
        assert_eq!(c2s[0].bytes, b"he");
        assert_eq!(c2s[1].seq, 1);
        assert_eq!(c2s[1].offset, 2);
        assert_eq!(c2s[1].bytes, b"llo");

        let s2c = history.chunks_for_direction("a", Direction::ServerToClient);
        assert_eq!(s2c.len(), 1);
        assert_eq!(s2c[0].seq, 0, "each direction sequences from zero");
        assert_eq!(s2c[0].offset, 0);
    }

    #[test]
    fn sequencing_is_per_session_not_per_sink() {
        // Two observers for one connection sequence independently: cursor
        // state travels with the session handle, never with the sink.
        let history = std::sync::Arc::new(MemoryHistory::new(limits()));
        let first = observed(&history, "a");
        first.observe(Direction::ClientToServer, b"x");
        first.observe(Direction::ClientToServer, b"y");
        drop(first);
        let second = observed(&history, "a");
        second.observe(Direction::ClientToServer, b"z");
        let seqs: Vec<u64> = history
            .chunks_for_direction("a", Direction::ClientToServer)
            .iter()
            .map(|chunk| chunk.seq)
            .collect();
        assert_eq!(seqs, vec![0, 1, 0]);
    }

    #[test]
    fn capture_drops_instead_of_blocking_under_snapshot_pressure() {
        // Another thread holds the chunk-store read lock exactly as a long
        // snapshot clone would. Recording must return immediately, count
        // the loss, and store nothing — never wait for the reader.
        let history = std::sync::Arc::new(MemoryHistory::new(limits()));
        history.record_connection_open(open("a"));
        let observer = observed(&history, "a");

        let (held_tx, held_rx) = std::sync::mpsc::channel::<()>();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let holder = std::sync::Arc::clone(&history);
        let handle = std::thread::spawn(move || {
            let _guard = holder.chunks.read().unwrap();
            held_tx.send(()).expect("holder rendezvous");
            release_rx.recv().expect("release");
            // Guard drops here, after the recording below completed.
        });
        held_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("lock is held");

        // Recording runs on a worker thread with a completion timeout: a
        // regression back to a blocking store would otherwise hang the
        // suite here instead of failing. Cleanup below runs on every path;
        // the worker self-cleans once the holder releases, so even the
        // failure path cannot hang.
        let (done_tx, done_rx) = std::sync::mpsc::channel::<()>();
        let worker_observer = observer.clone();
        let worker = std::thread::spawn(move || {
            worker_observer.observe(Direction::ClientToServer, b"dropped?");
            done_tx.send(()).expect("recording finished");
        });
        let completed = done_rx.recv_timeout(std::time::Duration::from_secs(5));
        release_tx.send(()).expect("release");
        handle.join().expect("holder thread");
        worker.join().expect("worker thread");
        completed.expect("recording must not wait for the reader");

        assert_eq!(history.dropped_chunks(), 1);
        assert_eq!(history.dropped_bytes(), 8);
        assert!(history.chunks().is_empty());

        observer.observe(Direction::ClientToServer, b"kept");
        assert_eq!(history.dropped_chunks(), 1, "no loss once free");
        let stored = history.chunks();
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].seq, 1, "dropped chunks still consume seq");
        assert_eq!(stored[0].offset, 8);
        assert_eq!(stored[0].bytes, b"kept");
    }

    #[test]
    fn staged_metadata_applies_in_push_order() {
        // Hold the store lock while two ordered threads stage Open then
        // Close: after release a snapshot must show exactly one record,
        // closed, with its opening metadata intact — never a metadata-less
        // close plus a stale open. The separate drainer guard serializes
        // extraction/application, never holding ingress during application.
        let history = std::sync::Arc::new(MemoryHistory::new(limits()));

        let (held_tx, held_rx) = std::sync::mpsc::channel::<()>();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let holder = std::sync::Arc::clone(&history);
        let store_guard = std::thread::spawn(move || {
            let _guard = holder.conns.write().unwrap();
            held_tx.send(()).expect("holder rendezvous");
            release_rx.recv().expect("release");
        });
        held_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("store lock is held");

        let (a_done_tx, a_done_rx) = std::sync::mpsc::channel::<()>();
        let worker_hist = std::sync::Arc::clone(&history);
        let thread_a = std::thread::spawn(move || {
            worker_hist.record_connection_open(open("x"));
            a_done_tx.send(()).expect("open staged");
        });
        a_done_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("open staged");
        let worker_hist = std::sync::Arc::clone(&history);
        let thread_b = std::thread::spawn(move || {
            worker_hist.record_connection_close("x", close(9, 8));
        });
        thread_a.join().expect("staging thread A");
        thread_b.join().expect("staging thread B");

        release_tx.send(()).expect("release");
        store_guard.join().expect("holder thread");

        let record = history.connection("x").expect("one record");
        assert!(record.is_closed());
        assert_eq!(record.requested_target, "127.0.0.1");
        assert!(record.opened_wall.is_some());
        assert_eq!(record.bytes_client_to_server, 9);
        assert_eq!(record.bytes_server_to_client, 8);
        assert_eq!(history.connections().len(), 1);
    }

    #[test]
    fn concurrent_metadata_stays_consistent() {
        // Many threads opening/closing distinct connections while
        // snapshots hammer. Counted ingress losses are deliberate. Every
        // retained record must be unique and agree with accepted ops;
        // missing operations must be covered by the metadata loss count.
        let history = std::sync::Arc::new(MemoryHistory::new(HistoryLimits {
            max_events: 1_000_000,
            max_bytes: u64::MAX,
            max_connections: 100_000,
        }));
        std::thread::scope(|scope| {
            for thread in 0..8 {
                let history = std::sync::Arc::clone(&history);
                scope.spawn(move || {
                    for index in 0..100u64 {
                        let id = format!("c{thread}-{index}");
                        history.record_connection_open(open(&id));
                        let _ = history.connection(&id);
                        history.record_connection_close(&id, close(index, index));
                    }
                });
            }
        });
        let records = history.connections();
        let ids: std::collections::HashSet<_> =
            records.iter().map(|record| &record.conn_id).collect();
        assert_eq!(ids.len(), records.len(), "never duplicate a connection");
        let mut absent_ops = 0;
        for thread in 0..8 {
            for index in 0..100u64 {
                let id = format!("c{thread}-{index}");
                if let Some(record) = history.connection(&id) {
                    if record.opened_wall.is_some() {
                        assert_eq!(record.requested_target, "127.0.0.1");
                    } else {
                        absent_ops += 1;
                    }
                    if record.is_closed() {
                        assert_eq!(record.bytes_client_to_server, index);
                        assert_eq!(record.bytes_server_to_client, index);
                    } else {
                        absent_ops += 1;
                    }
                } else {
                    absent_ops += 2;
                }
            }
        }
        assert_eq!(absent_ops, history.pending_dropped());
        assert!(records.len() <= 800);
    }

    #[test]
    fn metadata_recording_returns_while_snapshot_is_cloning() {
        use std::sync::{mpsc, Arc};
        use std::time::Duration;

        let history = Arc::new(MemoryHistory::new(limits()));
        let (held_tx, held_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let snapshot_history = Arc::clone(&history);
        let snapshot = std::thread::spawn(move || {
            snapshot_history.snapshot_conns(|_| {
                // Real snapshot path: both store/drainer are held here.
                held_tx.send(()).unwrap();
                release_rx.recv().unwrap();
            });
        });
        held_rx.recv_timeout(Duration::from_secs(5)).unwrap();

        let (done_tx, done_rx) = mpsc::channel();
        let record_history = Arc::clone(&history);
        let worker = std::thread::spawn(move || {
            record_history.record_connection_open(open("snapshot-race"));
            record_history.record_connection_close("snapshot-race", close(6, 9));
            done_tx.send(()).unwrap();
        });
        let completed = done_rx.recv_timeout(Duration::from_secs(2));
        // Always release/join before asserting: blocking regressions fail
        // within a deadline instead of hanging the process.
        release_tx.send(()).unwrap();
        snapshot.join().unwrap();
        worker.join().unwrap();
        completed.expect("recording must finish before snapshot releases its locks");

        assert_eq!(history.pending_dropped(), 0);
        let record = history.connection("snapshot-race").unwrap();
        assert!(record.is_closed());
        assert_eq!(record.requested_port, 1433);
        assert_eq!(record.bytes_client_to_server, 6);
        assert_eq!(record.bytes_server_to_client, 9);
    }

    #[test]
    fn metadata_recording_returns_while_snapshot_waits_for_store() {
        use std::sync::{mpsc, Arc};
        use std::time::Duration;

        let history = Arc::new(MemoryHistory::new(limits()));
        let store = history.conns.write().unwrap();
        let (started_tx, started_rx) = mpsc::channel();
        let snapshot_history = Arc::clone(&history);
        let snapshot = std::thread::spawn(move || {
            started_tx.send(()).unwrap();
            snapshot_history.connections()
        });
        started_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while history.drainer.try_lock().is_ok() {
            if Instant::now() >= deadline {
                drop(store);
                snapshot.join().unwrap();
                panic!("snapshot must acquire drainer before waiting on store");
            }
            std::thread::yield_now();
        }

        let (done_tx, done_rx) = mpsc::channel();
        let record_history = Arc::clone(&history);
        let worker = std::thread::spawn(move || {
            record_history.record_connection_open(open("waiting-snapshot"));
            record_history.record_connection_close("waiting-snapshot", close(1, 2));
            done_tx.send(()).unwrap();
        });
        let completed = done_rx.recv_timeout(Duration::from_secs(2));
        drop(store);
        let records = snapshot.join().unwrap();
        worker.join().unwrap();
        completed.expect("metadata recording cannot wait for a store-blocked snapshot");
        assert_eq!(history.pending_dropped(), 0);
        assert_eq!(records.len(), 1, "snapshot must drain prior accepted ops");
        assert!(records[0].is_closed());
    }

    #[test]
    fn metadata_timestamps_are_sampled_when_recorded_not_when_drained() {
        use std::sync::Arc;

        let history = Arc::new(MemoryHistory::new(limits()));
        let store = history.conns.write().unwrap();
        let open_before = RecordTime::now();
        history.record_connection_open(open("timestamps"));
        let open_after = RecordTime::now();
        let observer = observed(&history, "timestamps");
        observer.observe(Direction::ClientToServer, b"x");
        let close_before = RecordTime::now();
        history.record_connection_close("timestamps", close(1, 0));
        let close_after = RecordTime::now();
        let apply_before = RecordTime::now();
        drop(store);

        let record = history.connection("timestamps").unwrap();
        let chunk = &history.chunks()[0];
        let opened = record.opened_mono.unwrap();
        let closed = record.closed_mono.unwrap();
        assert!(open_before.mono <= opened && opened <= open_after.mono);
        assert!(close_before.mono <= closed && closed <= close_after.mono);
        assert!(closed <= apply_before.mono);
        assert!(opened <= chunk.captured_mono && chunk.captured_mono <= closed);
        let opened_wall = record.opened_wall.unwrap();
        let closed_wall = record.closed_wall.unwrap();
        assert!(open_before.wall <= opened_wall && opened_wall <= open_after.wall);
        assert!(close_before.wall <= closed_wall && closed_wall <= close_after.wall);
    }

    #[test]
    fn metadata_queue_overflow_and_ingress_contention_are_counted() {
        use std::sync::{mpsc, Arc};
        use std::time::Duration;

        let history = Arc::new(MemoryHistory::new(limits()));
        let drainer = history.drainer.lock().unwrap();
        for index in 0..MAX_PENDING_OPS + 2 {
            history.record_connection_open(open(&format!("overflow-{index}")));
        }
        assert_eq!(history.pending.lock().unwrap().len(), MAX_PENDING_OPS);
        assert_eq!(history.pending_dropped(), 2);
        {
            let ingress = history.pending.lock().unwrap();
            let (done_tx, done_rx) = mpsc::channel();
            let worker_history = Arc::clone(&history);
            let worker = std::thread::spawn(move || {
                worker_history.record_connection_close("overflow-2", close(0, 0));
                done_tx.send(()).unwrap();
            });
            let completed = done_rx.recv_timeout(Duration::from_secs(2));
            drop(ingress);
            worker.join().unwrap();
            completed.expect("ingress contention must count a loss rather than wait");
        }
        assert_eq!(history.pending_dropped(), 3);
        drop(drainer);
        let records = history.connections();
        assert_eq!(records.len(), limits().max_connections);
        assert!(records.iter().all(|r| r.opened_mono.is_some()));
        assert!(history.pending.lock().unwrap().is_empty());
    }

    #[test]
    fn relay_start_forward_and_shutdown_finish_before_metadata_snapshot_releases() {
        use std::sync::{mpsc, Arc};
        use std::time::Duration;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        // The runtime is on a separate OS thread: a blocking regression
        // cannot prevent the controlling thread's timeout and cleanup.
        let (history_tx, history_rx) = mpsc::channel();
        let (start_tx, start_rx) = mpsc::channel();
        let (done_tx, done_rx) = mpsc::channel();
        let worker = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async {
                let config =
                    crate::RelayConfig::default().with_endpoint("127.0.0.1".parse().unwrap(), 0);
                let (_, telemetry) = crate::telemetry::memory_telemetry();
                let mut relay = crate::spawn_relay_with(config, telemetry).await.unwrap();
                let echo = testlab::echo_server().await;
                history_tx.send(relay.history()).unwrap();
                start_rx.recv().unwrap();
                let mut client = testlab::connect_through_proxy(
                    relay.local_addr(),
                    testlab::Destination::Ip(echo.addr().ip()),
                    echo.addr().port(),
                    testlab::GreetingStyle::Single,
                    testlab::RequestStyle::Single,
                )
                .await
                .unwrap();
                client.write_all(b"abcdef").await.unwrap();
                let mut reply = [0u8; 6];
                client.read_exact(&mut reply).await.unwrap();
                assert_eq!(&reply, b"abcdef");
                relay.begin_shutdown();
                relay.wait_stopped().await;
                done_tx.send(()).unwrap();
                echo.shutdown().await;
            });
        });
        let history: Arc<MemoryHistory> = history_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        let (held_tx, held_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let snapshot_history = Arc::clone(&history);
        let snapshot = std::thread::spawn(move || {
            snapshot_history.snapshot_conns(|_| {
                held_tx.send(()).unwrap();
                release_rx.recv().unwrap();
            });
        });
        held_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        start_tx.send(()).unwrap();
        let completed = done_rx.recv_timeout(Duration::from_secs(5));
        release_tx.send(()).unwrap();
        snapshot.join().unwrap();
        worker.join().unwrap();
        completed.expect("start, forwarding and shutdown must not wait for metadata snapshot");

        let records = history.connections();
        assert_eq!(history.pending_dropped(), 0);
        assert_eq!(records.len(), 1);
        assert!(records[0].is_closed());
        assert_eq!(records[0].bytes_client_to_server, 6);
        assert_eq!(records[0].bytes_server_to_client, 6);
    }

    #[test]
    fn concurrent_same_direction_observers_keep_emission_order() {
        // Clones of one observer hammering a single direction must store
        // chunks in seq order: assignment and emission share one critical
        // section, so no thread can slip an emission between another
        // thread's assignment and store.
        let history = std::sync::Arc::new(MemoryHistory::new(HistoryLimits {
            max_events: 1_000_000,
            max_bytes: u64::MAX,
            max_connections: 16,
        }));
        history.record_connection_open(open("a"));
        let observer = observed(&history, "a");
        std::thread::scope(|scope| {
            for _ in 0..4 {
                let observer = observer.clone();
                scope.spawn(move || {
                    for _ in 0..200 {
                        observer.observe(Direction::ClientToServer, b"x");
                    }
                });
            }
        });
        assert_eq!(history.dropped_chunks(), 0);
        let seqs: Vec<u64> = history
            .chunks_for_direction("a", Direction::ClientToServer)
            .iter()
            .map(|chunk| chunk.seq)
            .collect();
        assert_eq!(seqs.len(), 800);
        assert_eq!(seqs, (0..800u64).collect::<Vec<_>>());
    }

    #[test]
    fn connections_are_isolated_by_id() {
        let history = std::sync::Arc::new(MemoryHistory::new(limits()));
        history.record_connection_open(open("a"));
        history.record_connection_open(open("b"));
        observed(&history, "a").observe(Direction::ClientToServer, b"aaa");
        observed(&history, "b").observe(Direction::ClientToServer, b"b");

        let only_a = history.chunks_for("a");
        assert_eq!(only_a.len(), 1);
        assert_eq!(only_a[0].bytes, b"aaa");
        assert!(history.chunks_for("missing").is_empty());
    }

    #[test]
    fn binary_bytes_round_trip_exactly() {
        let history = std::sync::Arc::new(MemoryHistory::new(limits()));
        let full_range: Vec<u8> = (0u8..=255u8).collect();
        history.record_connection_open(open("bin"));
        let observer = observed(&history, "bin");
        observer.observe(Direction::ClientToServer, &full_range);
        observer.observe(Direction::ServerToClient, &full_range);

        for direction in [Direction::ClientToServer, Direction::ServerToClient] {
            let chunks = history.chunks_for_direction("bin", direction);
            let joined: Vec<u8> = chunks
                .iter()
                .flat_map(|c| c.bytes.iter().copied())
                .collect();
            assert_eq!(joined, full_range, "0x00-0xFF must survive {direction:?}");
        }
    }

    #[test]
    fn empty_slices_are_not_recorded() {
        let history = std::sync::Arc::new(MemoryHistory::new(limits()));
        history.record_connection_open(open("a"));
        observed(&history, "a").observe(Direction::ClientToServer, b"");
        assert!(history.chunks().is_empty());
    }

    #[test]
    fn metadata_records_never_wait_for_the_store() {
        // Another thread holds the conn-store write guard exactly as a
        // stalled snapshot would. Open/close recording must stage and
        // return immediately — never wait for the store — so session
        // startup and shutdown (including the abort Drop path) proceed.
        let history = std::sync::Arc::new(MemoryHistory::new(limits()));

        let (held_tx, held_rx) = std::sync::mpsc::channel::<()>();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let holder = std::sync::Arc::clone(&history);
        let handle = std::thread::spawn(move || {
            let _guard = holder.conns.write().unwrap();
            held_tx.send(()).expect("holder rendezvous");
            release_rx.recv().expect("release");
            // Guard drops here, after the recordings below completed.
        });
        held_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("store lock is held");

        // Recording runs on a worker so that a regression back to a
        // blocking store fails via timeout instead of hanging the suite;
        // cleanup below runs on every path.
        let worker_hist = std::sync::Arc::clone(&history);
        let (done_tx, done_rx) = std::sync::mpsc::channel::<()>();
        let worker = std::thread::spawn(move || {
            worker_hist.record_connection_open(open("s"));
            worker_hist.record_connection_close("s", close(1, 2));
            done_tx.send(()).expect("recordings finished");
        });
        let completed = done_rx.recv_timeout(std::time::Duration::from_secs(5));
        release_tx.send(()).expect("release");
        handle.join().expect("holder thread");
        worker.join().expect("worker thread");
        completed.expect("metadata recording must not wait for the store");

        // Once the store is free, a snapshot drains the staged ops into
        // view with their data intact.
        let record = history.connection("s").expect("staged close visible");
        assert!(record.is_closed());
        assert_eq!(record.requested_target, "127.0.0.1");
        assert_eq!(record.bytes_client_to_server, 1);
        assert_eq!(record.bytes_server_to_client, 2);
        assert_eq!(history.pending_dropped(), 0);
    }

    #[test]
    fn eviction_drops_oldest_first_by_count() {
        let history = std::sync::Arc::new(MemoryHistory::new(HistoryLimits {
            max_events: 3,
            max_bytes: u64::MAX,
            max_connections: 16,
        }));
        history.record_connection_open(open("a"));
        let observer = observed(&history, "a");
        for byte in *b"abcde" {
            observer.observe(Direction::ClientToServer, std::slice::from_ref(&byte));
        }
        let kept: Vec<u8> = history
            .chunks_for_direction("a", Direction::ClientToServer)
            .iter()
            .map(|chunk| chunk.bytes[0])
            .collect();
        assert_eq!(kept, vec![b'c', b'd', b'e']);
    }

    #[test]
    fn eviction_drops_oldest_first_by_bytes() {
        let history = std::sync::Arc::new(MemoryHistory::new(HistoryLimits {
            max_events: usize::MAX,
            max_bytes: 4,
            max_connections: 16,
        }));
        history.record_connection_open(open("a"));
        let observer = observed(&history, "a");
        observer.observe(Direction::ClientToServer, b"ab");
        observer.observe(Direction::ClientToServer, b"cd");
        observer.observe(Direction::ClientToServer, b"ef");
        assert!(history.bytes_retained() <= 4);
        let kept: Vec<u8> = history
            .chunks_for_direction("a", Direction::ClientToServer)
            .iter()
            .flat_map(|chunk| chunk.bytes.iter().copied())
            .collect();
        // Eviction fires only while a bound is exceeded: "ab" leaves, the
        // rest fits exactly 4 bytes.
        assert_eq!(kept, b"cdef");
    }

    #[test]
    fn connection_records_are_bounded_and_close_upserts_honestly() {
        let history = std::sync::Arc::new(MemoryHistory::new(HistoryLimits {
            max_events: 64,
            max_bytes: 64 * 1024,
            max_connections: 2,
        }));
        history.record_connection_open(open("a"));
        history.record_connection_open(open("b"));
        history.record_connection_open(open("c"));
        assert_eq!(history.connections().len(), 2);
        assert!(history.connection("a").is_none(), "oldest evicted first");

        history.record_connection_close("b", close(1, 2));
        let record = history.connection("b").expect("retained");
        assert!(record.is_closed());
        assert_eq!(record.bytes_client_to_server, 1);
        assert_eq!(record.bytes_server_to_client, 2);
        assert_eq!(record.close_reason.as_deref(), Some("eof"));
        assert!(record.closed_wall.is_some());

        // A close for an evicted connection still retains its outcome, but
        // the opening timestamps stay empty instead of fabricated.
        history.record_connection_close("a", close(3, 4));
        let resurrected = history.connection("a").expect("upserted close");
        assert_eq!(resurrected.bytes_client_to_server, 3);
        assert!(resurrected.opened_wall.is_none());
        assert!(resurrected.opened_mono.is_none());
        assert!(resurrected.is_closed());
    }

    #[test]
    fn open_metadata_is_available_before_close() {
        let history = std::sync::Arc::new(MemoryHistory::new(limits()));
        history.record_connection_open(open("a"));
        let record = history.connection("a").expect("open record");
        assert_eq!(record.requested_target, "127.0.0.1");
        assert_eq!(record.requested_port, 1433);
        assert_eq!(
            record.resolved_upstream,
            Some("127.0.0.1:1433".parse().expect("addr"))
        );
        assert!(record.opened_wall.is_some());
        assert!(!record.is_closed());
        assert!(record.close_reason.is_none());
    }

    #[test]
    fn chunk_ids_are_unique() {
        let history = std::sync::Arc::new(MemoryHistory::new(limits()));
        history.record_connection_open(open("a"));
        let observer = observed(&history, "a");
        observer.observe(Direction::ClientToServer, b"x");
        observer.observe(Direction::ClientToServer, b"y");
        let chunks = history.chunks();
        assert_ne!(chunks[0].id, chunks[1].id);
        assert_eq!(chunks[0].conn_id, "a");
    }

    #[test]
    fn derived_views_never_touch_raw_bytes() {
        assert_eq!(hex_view(&[0x00, 0x01, 0xff, 0x41, 0x42]), "00 01 FF 41 42");
        assert_eq!(hex_view(&[]), "");
        assert_eq!(text_view(&[0x00, 0x01, 0xff, 0x41, 0x42]), "...AB");
        assert_eq!(text_view(&[]), "");
        // Invalid UTF-8 is replaced per byte, never decoded
        // (0x28 is printable '(', 0xc3 is not).
        assert_eq!(text_view(&[0xc3, 0x28]), ".(");
    }
}
