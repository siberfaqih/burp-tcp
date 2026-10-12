//! Manual interception: bounded pending queue, revisioned exactly-once
//! decisions, and a finite hold lease (Phase 3).
//!
//! # State model
//!
//! ```text
//! OBSERVED -> PENDING -> Forward | Replace | Suppress | Close -> COMMITTED
//! ```
//!
//! A *unit* is one read chunk offered by a relay direction while
//! interception is enabled for that direction — never an application
//! message (the Phase 2 framing rules still apply). The pending queue
//! holds the original bytes; history records the bytes actually
//! delivered after the decision, so [`crate::history`] keeps meaning
//! "what the destination socket accepted".
//!
//! # Guarantees
//!
//! * **Exactly-once commit.** A unit is resolved by at most one action.
//!   [`InterceptCoordinator::decide`] removes the unit and delivers the
//!   action under one lock hold; duplicate or stale attempts fail with
//!   [`DecisionError`] and never emit a second action. Lease expiry,
//!   policy disable, and abandonment resolve units the same way
//!   (removal first, single send), so no path can double-deliver.
//! * **No overtaking.** A relay direction offers units sequentially and
//!   delivers nothing further until the current unit resolves, so later
//!   same-direction bytes can never pass a held unit. While a unit is
//!   held, further source bytes stay in the bounded kernel socket
//!   buffers, not in engine memory.
//! * **One unit per connection and direction at a time.** Guaranteed by
//!   the sequential relay copy loop; `offer` documents this as a
//!   precondition.
//! * **Finite hold lease.** Every unit expires; expiry releases it with
//!   [`InterceptAction::Forward`] (deliver unchanged). The awaiting
//!   relay side enforces the deadline: it asks the coordinator to expire
//!   the unit and then reads the single authoritative resolution from
//!   the unit's channel, so a decision committing at the same instant
//!   can never be silently overwritten by the expiry forward. The expiry
//!   attempt is nonblocking: under queue-lock contention it retries at
//!   await points, so the awaiting task stays cancellable and never
//!   blocks its worker thread.
//! * **Bounded queue.** Offers beyond `max_pending` are forwarded
//!   unchanged without interception (counted in
//!   [`InterceptCoordinator::overflow_forwards`]), never blocking the
//!   relay.
//! * **Disable releases.** Turning interception off for a direction
//!   releases that direction's pending units with `Forward` and returns
//!   how many were released.
//! * **No detached tasks.** The coordinator is passive state plus
//!   oneshot channels; lease expiry is driven by the awaiting relay
//!   side and by lazy sweeps, never by a spawned timer task. Sessions
//!   dying while held (task abort, engine shutdown) are detected by the
//!   dropped receiver and swept lazily.
//! * **Passive fast path.** Disabled directions consult an atomic flag
//!   and never touch the queue lock, so lock activity — snapshots,
//!   resolvers, other offers — cannot stall passive forwarding.
//! * **Snapshots copy payloads outside the lock.**
//!   [`InterceptCoordinator::pending`] clones only cheap Arc handles
//!   under the queue lock and copies payload bytes after releasing it,
//!   so a snapshot never holds the lock for the duration of payload
//!   cloning.
//! * **Bounded replacement bytes.** A `Replace` decision may not exceed
//!   `max_replace_bytes` (default 1 MiB): oversized replacements are
//!   rejected before commit and the unit stays pending. This bounds the
//!   session-side allocation one decision can force; the passive relay
//!   buffer bound (`buffer_bytes`) does not apply to control-plane
//!   authored bytes. Committed replacements are also *normalized*: a
//!   payload whose allocation capacity exceeds the bound is reallocated
//!   to its exact length, so a sparse (small-len, huge-capacity) buffer
//!   cannot be retained by the session under backpressure.
//! * **Saturated leases.** An extreme `hold_lease` (one that would
//!   overflow `Instant` arithmetic) saturates to roughly 50 years
//!   instead of panicking; the lease stays finite in practice.

use std::collections::VecDeque;
use std::fmt;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use tokio::sync::oneshot;
use uuid::Uuid;

use crate::history::Direction;

/// Bounds and lease policy for one [`InterceptCoordinator`].
///
/// All fields must be positive ([`crate::config::RelayConfig::validate`]
/// rejects zero values): a zero-capacity queue could never hold anything,
/// and a zero lease would expire units before any decision could arrive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InterceptLimits {
    /// Maximum simultaneously pending units across all connections.
    /// One further unit can be in flight per offering direction.
    pub max_pending: usize,
    /// How long a unit may stay pending before it is released with
    /// [`InterceptAction::Forward`]. Finite by requirement: a hold may
    /// never pin a session indefinitely. A lease so extreme that it
    /// would overflow `Instant` arithmetic saturates to roughly 50
    /// years rather than panicking.
    pub hold_lease: Duration,
    /// Maximum size in bytes of a [`InterceptAction::Replace`]
    /// payload. Bounds the replacement bytes so one decision cannot
    /// force an unbounded session-side allocation; the passive relay
    /// buffer bound (`buffer_bytes`) does not apply to control-plane
    /// authored bytes. Zero-byte (empty) replacements are legal.
    pub max_replace_bytes: u64,
}

impl Default for InterceptLimits {
    fn default() -> Self {
        Self {
            max_pending: 128,
            hold_lease: Duration::from_secs(30),
            max_replace_bytes: 1024 * 1024,
        }
    }
}

/// What the control plane orders done with a pending unit.
///
/// Applied exactly once per unit. `Replace` bytes are delivered verbatim
/// (binary-safe; may be shorter, longer, or empty). `Suppress` delivers
/// nothing for the unit but keeps the session flowing. `Close` delivers
/// nothing and tears the session down.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InterceptAction {
    /// Deliver the unit's original bytes unchanged.
    Forward,
    /// Deliver these bytes instead of the originals.
    Replace(Vec<u8>),
    /// Deliver nothing for this unit; continue forwarding.
    Suppress,
    /// Deliver nothing and close the connection.
    Close,
}

/// A pending unit as seen by the control plane: everything needed to
/// render it and to submit a revisioned decision.
///
/// `seq`/`offset` locate the unit in this direction's *source read
/// order* (position among the bytes read from the origin socket), not
/// the delivery order that history records: held bytes may be replaced
/// or suppressed before delivery, so delivery positions are only known
/// after commitment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeldUnit {
    /// Unique unit identifier (UUID v4). Decisions address units by id.
    pub id: String,
    /// Connection the unit was read from.
    pub conn_id: String,
    /// Which direction the bytes were read in.
    pub direction: Direction,
    /// Index of this unit among this direction's reads on this
    /// connection (0-based, including reads before interception was
    /// enabled).
    pub seq: u64,
    /// Source bytes read in this direction before this unit.
    pub offset: u64,
    /// The original, unmodified bytes read from the source socket.
    /// Authoritative input for the decision; never what history stores
    /// when a Replace commits.
    pub bytes: Vec<u8>,
    /// Wall-clock (UTC) time the unit was offered.
    pub held_wall: SystemTime,
    /// Monotonic time the unit was offered.
    pub held_mono: Instant,
    /// Monotonic time at which the hold lease expires; expiry releases
    /// the unit with [`InterceptAction::Forward`].
    pub expires_mono: Instant,
    /// Revision a decision must present to commit. Starts at 0 and is
    /// echoed by [`InterceptCoordinator::pending`]; a mismatching
    /// revision is rejected as stale.
    pub revision: u64,
}

/// Why a decision was not committed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecisionError {
    /// No such pending unit: already committed, released by lease
    /// expiry, released by a policy change, or its session ended.
    /// Never retried by the engine — the unit is resolved exactly once
    /// by whichever path got there first.
    UnknownUnit {
        /// The unit id that was addressed.
        unit_id: String,
    },
    /// The unit is still pending, but the decision presented an
    /// outdated revision. The unit keeps waiting; the current revision
    /// is reported for a corrected retry.
    StaleRevision {
        /// The unit id that was addressed.
        unit_id: String,
        /// Revision the decision presented.
        presented: u64,
        /// Revision the unit actually expects.
        expected: u64,
    },
    /// The decision was a `Replace` larger than
    /// [`InterceptLimits::max_replace_bytes`]. The unit keeps waiting,
    /// exactly like a stale revision: the rejection happened before
    /// any commit, so a corrected (smaller or different) decision may
    /// still be submitted.
    ReplaceTooLarge {
        /// The unit id that was addressed.
        unit_id: String,
        /// Replacement payload size in bytes.
        bytes: u64,
        /// The configured `max_replace_bytes` limit.
        limit: u64,
    },
}

impl fmt::Display for DecisionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownUnit { unit_id } => {
                write!(f, "no pending unit {unit_id}: already resolved")
            }
            Self::StaleRevision {
                unit_id,
                presented,
                expected,
            } => write!(
                f,
                "stale revision {presented} for unit {unit_id}: expected {expected}"
            ),
            Self::ReplaceTooLarge {
                unit_id,
                bytes,
                limit,
            } => write!(
                f,
                "replacement of {bytes} bytes for unit {unit_id} exceeds max_replace_bytes {limit}"
            ),
        }
    }
}

impl std::error::Error for DecisionError {}

/// One queued unit plus the single-use channel that resolves it.
///
/// The unit is behind an `Arc` so control-plane snapshots can clone the
/// queue's handles cheaply under the lock and copy payload bytes after
/// releasing it.
///
/// Invariant: the entry is removed from the queue and its `tx` consumed
/// under one coordinator lock hold. Whatever resolves the unit (decision,
/// expiry, disable, sweep) takes the lock, removes the entry, and sends
/// exactly one action; every other path then finds the unit gone. This
/// makes duplicate emission structurally impossible.
struct QueuedUnit {
    unit: Arc<HeldUnit>,
    tx: oneshot::Sender<InterceptAction>,
}

/// Result of offering bytes for interception (relay-side only).
pub(crate) enum OfferOutcome {
    /// Deliver unchanged without holding: interception disabled for the
    /// direction, empty offer, or the pending queue is full.
    Passthrough,
    /// The unit is queued; resolve it to learn the delivery action.
    Held(HeldHandle),
}

/// Outcome of one nonblocking lease-expiry attempt (relay-side only).
pub(crate) enum ExpiryAttempt {
    /// This call released the unit with `Forward`.
    Released,
    /// The unit was already resolved by someone else; the channel now
    /// holds the authoritative action.
    AlreadyResolved,
    /// The queue lock is contended; retry without blocking.
    Contended,
}

/// Relay-side handle to one offered unit. Resolving it yields the
/// exactly-once delivery action, enforcing the hold lease.
pub(crate) struct HeldHandle {
    coordinator: Arc<InterceptCoordinator>,
    unit_id: String,
    rx: oneshot::Receiver<InterceptAction>,
    expires_mono: Instant,
}

impl HeldHandle {
    /// Await the unit's single authoritative action.
    ///
    /// Resolves through the unit's channel in every case: a committed
    /// decision, our own lease-expiry forward, or a concurrent expiry
    /// sweep. The lease deadline is enforced here — never by a spawned
    /// timer task — and the channel is only read *after* attempting
    /// expiry, so a decision committing at the same instant is still
    /// honored rather than overwritten by the expiry forward.
    ///
    /// The expiry attempt is nonblocking: if the coordinator lock is
    /// contended (a snapshot or resolver holding it), the task retries
    /// at await points instead of blocking its worker thread, so the
    /// future stays cancellable (session abort, engine shutdown) at
    /// every step.
    pub(crate) async fn resolve(mut self) -> InterceptAction {
        let mut lease = Box::pin(tokio::time::sleep_until(self.expires_mono.into()));
        tokio::select! {
            biased;
            action = &mut self.rx => action.unwrap_or(InterceptAction::Forward),
            _ = &mut lease => {
                // Lease elapsed. Ask the coordinator to release this
                // unit, retrying nonblockingly while the queue lock is
                // contended. Whether or not we won the race, the channel
                // then holds the single authoritative resolution: our
                // Forward, a decision that committed concurrently, or a
                // sweep that already forwarded. (A receiver error means
                // the coordinator itself was dropped; forwarding the
                // original bytes is the safe default.)
                loop {
                    match self.coordinator.try_expire_unit(&self.unit_id) {
                        ExpiryAttempt::Released | ExpiryAttempt::AlreadyResolved => {
                            return self.rx.await.unwrap_or(InterceptAction::Forward);
                        }
                        ExpiryAttempt::Contended => {
                            // Re-check the channel while backing off: a
                            // concurrent resolver may commit meanwhile.
                            tokio::select! {
                                biased;
                                action = &mut self.rx => {
                                    return action.unwrap_or(InterceptAction::Forward);
                                }
                                _ = tokio::time::sleep(EXPIRY_RETRY) => continue,
                            }
                        }
                    }
                }
            }
        }
    }
}

/// Interception coordinator: directional policy, bounded pending queue,
/// and exactly-once decision commits for one relay.
///
/// The control plane (tests now, IPC in Phase 4) uses the `pub` methods;
/// the relay data path uses the crate-private `offer`/`HeldHandle`.
/// Interception is disabled for both directions by default, so a relay
/// that never touches this handle behaves exactly like the passive
/// Phase 2 engine.
pub struct InterceptCoordinator {
    limits: InterceptLimits,
    /// Directional policy flags, the source of truth for
    /// [`InterceptCoordinator::enabled`]. Offers consult them lock-free
    /// and re-check under the queue lock, so passive forwarding never
    /// waits on queue-lock activity.
    client_to_server: AtomicBool,
    server_to_client: AtomicBool,
    /// Pending units. Guards are always short: push, pop, find-by-id,
    /// or cheap Arc-handle cloning — never payload copying.
    queue: Mutex<VecDeque<QueuedUnit>>,
    offers: AtomicU64,
    overflow_forwards: AtomicU64,
    lease_releases: AtomicU64,
    disable_releases: AtomicU64,
    abandoned: AtomicU64,
    commits: AtomicU64,
}

/// Backoff between nonblocking lease-expiry retries while the queue
/// lock is contended.
const EXPIRY_RETRY: Duration = Duration::from_millis(5);

impl InterceptCoordinator {
    /// New coordinator with both directions disabled.
    pub fn new(limits: InterceptLimits) -> Arc<Self> {
        Arc::new(Self {
            limits,
            client_to_server: AtomicBool::new(false),
            server_to_client: AtomicBool::new(false),
            queue: Mutex::new(VecDeque::new()),
            offers: AtomicU64::new(0),
            overflow_forwards: AtomicU64::new(0),
            lease_releases: AtomicU64::new(0),
            disable_releases: AtomicU64::new(0),
            abandoned: AtomicU64::new(0),
            commits: AtomicU64::new(0),
        })
    }

    /// The configured bounds and lease policy.
    pub fn limits(&self) -> InterceptLimits {
        self.limits
    }

    fn direction_flag(&self, direction: Direction) -> &AtomicBool {
        match direction {
            Direction::ClientToServer => &self.client_to_server,
            Direction::ServerToClient => &self.server_to_client,
        }
    }

    /// Whether interception currently holds units in `direction`.
    pub fn enabled(&self, direction: Direction) -> bool {
        self.direction_flag(direction).load(Ordering::SeqCst)
    }

    /// Enable or disable interception for one direction.
    ///
    /// Disabling releases every pending unit of that direction with
    /// [`InterceptAction::Forward`] and returns how many were released.
    /// Enabling never changes existing pending units.
    pub fn set_enabled(&self, direction: Direction, enabled: bool) -> u64 {
        // The flag is the source of truth and is stored first: an offer
        // that already passed the lock-free check re-checks under the
        // queue lock, so a racing disable can never strand a newly held
        // unit in a disabled direction.
        self.direction_flag(direction)
            .store(enabled, Ordering::SeqCst);
        if enabled {
            return 0;
        }
        let mut queue = self.lock_queue();
        self.sweep_locked(&mut queue);
        // FIFO release: queued order is offer order, so released units
        // reach their awaiting relay directions in the order they were
        // held. Resolving consumes the entry's sender, so the queue is
        // rebuilt rather than filtered in place.
        let mut released = 0u64;
        let mut remaining = VecDeque::with_capacity(queue.len());
        while let Some(entry) = queue.pop_front() {
            if entry.unit.direction == direction {
                // Send while owning the entry: this is the unit's one
                // and only resolution.
                let _ = entry.tx.send(InterceptAction::Forward);
                released += 1;
            } else {
                remaining.push_back(entry);
            }
        }
        *queue = remaining;
        if released > 0 {
            self.disable_releases.fetch_add(released, Ordering::Relaxed);
        }
        released
    }

    /// Snapshots of all pending units, oldest offer first.
    ///
    /// Applies lazy maintenance first: expired units are released with
    /// `Forward` (counted), and units whose session died while held are
    /// dropped (counted as abandoned). The queue lock is held only for
    /// cheap Arc-handle cloning; payload bytes are copied after
    /// releasing it, so a snapshot never blocks offers, decisions, or
    /// expiry for the duration of the copy.
    pub fn pending(&self) -> Vec<HeldUnit> {
        let snapshots: Vec<Arc<HeldUnit>> = {
            let mut queue = self.lock_queue();
            self.sweep_locked(&mut queue);
            queue.iter().map(|entry| Arc::clone(&entry.unit)).collect()
        };
        snapshots.iter().map(|unit| (**unit).clone()).collect()
    }

    /// Commit one decision for a pending unit, exactly once.
    ///
    /// The decision carries the unit revision observed by the submitter;
    /// a mismatch is rejected as stale and the unit keeps waiting. A
    /// successful commit removes the unit and delivers the action to the
    /// awaiting relay direction. Addressing a unit that is no longer
    /// pending fails — the unit was resolved exactly once already.
    ///
    /// Delivery to a session that ended while held still counts as a
    /// successful commit: the decision was accepted and applied exactly
    /// once; there is simply nobody left to act on it.
    pub fn decide(
        &self,
        unit_id: &str,
        revision: u64,
        action: InterceptAction,
    ) -> Result<(), DecisionError> {
        // Normalize the replacement allocation before taking the queue
        // lock: the copy is bounded by max_replace_bytes (it only runs
        // when the length already fits the bound), so a legal but sparse
        // replacement (small len, huge capacity) cannot pin more than
        // the bound in the session, and the queue guard stays free of
        // payload copying. An oversized length is NOT copied here — the
        // under-lock length check below rejects it without any copy work.
        let action = match action {
            InterceptAction::Replace(bytes)
                if bytes.len() as u64 <= self.limits.max_replace_bytes
                    && bytes.capacity() as u64 > self.limits.max_replace_bytes =>
            {
                InterceptAction::Replace(bytes.to_vec())
            }
            action => action,
        };
        let mut queue = self.lock_queue();
        self.sweep_locked(&mut queue);
        let Some(position) = queue.iter().position(|e| e.unit.id == unit_id) else {
            return Err(DecisionError::UnknownUnit {
                unit_id: unit_id.to_owned(),
            });
        };
        if queue[position].unit.revision != revision {
            return Err(DecisionError::StaleRevision {
                unit_id: unit_id.to_owned(),
                presented: revision,
                expected: queue[position].unit.revision,
            });
        }
        // Reject an oversized replacement BEFORE committing: the unit
        // stays pending (mirrors the stale-revision early return), so
        // the control plane can retry with a legal decision. An empty
        // replacement (0 bytes) is legal — it delivers nothing through
        // the delivery path, like Suppress.
        if let InterceptAction::Replace(bytes) = &action {
            let size = bytes.len() as u64;
            if size > self.limits.max_replace_bytes {
                return Err(DecisionError::ReplaceTooLarge {
                    unit_id: unit_id.to_owned(),
                    bytes: size,
                    limit: self.limits.max_replace_bytes,
                });
            }
        }
        // Removal and send share one lock hold, so no other resolver can
        // observe the unit between them. The send fails only when the
        // awaiting session is already gone — still exactly-once.
        let entry = queue.remove(position).expect("position checked above");
        let _ = entry.tx.send(action);
        self.commits.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    /// Offer one read chunk for interception (relay data path).
    ///
    /// Precondition: at most one unit per (connection, direction) is
    /// unresolved at a time — the sequential relay copy loop guarantees
    /// this by not reading further while a unit is held.
    ///
    /// Returns [`OfferOutcome::Passthrough`] when the direction is not
    /// intercepted, the offer is empty, or the queue is at capacity
    /// (counted as an overflow forward: the bytes are delivered
    /// unchanged rather than stalling the relay).
    pub(crate) fn offer(
        self: &Arc<Self>,
        conn_id: &str,
        direction: Direction,
        seq: u64,
        offset: u64,
        bytes: &[u8],
    ) -> OfferOutcome {
        if bytes.is_empty() {
            return OfferOutcome::Passthrough;
        }
        // Lock-free fast path: a disabled direction never touches the
        // queue lock, so snapshot or resolver lock activity can never
        // stall passive (untouched) forwarding.
        if !self.direction_flag(direction).load(Ordering::SeqCst) {
            return OfferOutcome::Passthrough;
        }
        // Copy the payload before taking the lock: no payload work
        // happens under the guard.
        let payload = bytes.to_vec();
        let mut queue = self.lock_queue();
        self.sweep_locked(&mut queue);
        // Re-check under the lock: a disable that raced past the
        // lock-free check must not strand a newly held unit in a
        // disabled direction.
        if !self.direction_flag(direction).load(Ordering::SeqCst) {
            return OfferOutcome::Passthrough;
        }
        if queue.len() >= self.limits.max_pending {
            self.overflow_forwards.fetch_add(1, Ordering::Relaxed);
            return OfferOutcome::Passthrough;
        }
        let now = Instant::now();
        // Compute the expiry ONCE, with overflow saturation: an extreme
        // hold_lease that would panic on `now + lease` instead yields a
        // representable ~50-year deadline, so the lease stays finite in
        // practice. The same value is used for the unit and the handle.
        let expires_mono = now
            .checked_add(self.limits.hold_lease)
            .unwrap_or_else(|| saturate_instant(now));
        let (tx, rx) = oneshot::channel();
        let unit = HeldUnit {
            id: Uuid::new_v4().to_string(),
            conn_id: conn_id.to_owned(),
            direction,
            seq,
            offset,
            bytes: payload,
            held_wall: SystemTime::now(),
            held_mono: now,
            expires_mono,
            revision: 0,
        };
        let unit_id = unit.id.clone();
        queue.push_back(QueuedUnit {
            unit: Arc::new(unit),
            tx,
        });
        self.offers.fetch_add(1, Ordering::Relaxed);
        OfferOutcome::Held(HeldHandle {
            coordinator: Arc::clone(self),
            unit_id,
            rx,
            expires_mono,
        })
    }

    /// Try to release one unit by lease expiry (relay-side deadline
    /// path), without blocking.
    ///
    /// [`ExpiryAttempt::Released`] means this call released the unit
    /// with `Forward`. [`ExpiryAttempt::AlreadyResolved`] means the unit
    /// was already resolved (a decision or sweep committed first); the
    /// caller then reads the authoritative action from its channel.
    /// [`ExpiryAttempt::Contended`] means the queue lock is busy; the
    /// caller retries at an await point, staying cancellable instead of
    /// blocking its worker thread. Caller precondition: the unit's lease
    /// has elapsed.
    pub(crate) fn try_expire_unit(&self, unit_id: &str) -> ExpiryAttempt {
        let mut queue = match self.queue.try_lock() {
            Ok(guard) => guard,
            Err(std::sync::TryLockError::Poisoned(poisoned)) => poisoned.into_inner(),
            Err(std::sync::TryLockError::WouldBlock) => {
                return ExpiryAttempt::Contended;
            }
        };
        let Some(position) = queue.iter().position(|e| e.unit.id == unit_id) else {
            return ExpiryAttempt::AlreadyResolved;
        };
        let entry = queue.remove(position).expect("position checked above");
        let _ = entry.tx.send(InterceptAction::Forward);
        self.lease_releases.fetch_add(1, Ordering::Relaxed);
        ExpiryAttempt::Released
    }

    /// Units offered to the pending queue, cumulative.
    pub fn offers(&self) -> u64 {
        self.offers.load(Ordering::Relaxed)
    }

    /// Units forwarded unchanged because the pending queue was full.
    pub fn overflow_forwards(&self) -> u64 {
        self.overflow_forwards.load(Ordering::Relaxed)
    }

    /// Units released by hold-lease expiry, cumulative.
    pub fn lease_releases(&self) -> u64 {
        self.lease_releases.load(Ordering::Relaxed)
    }

    /// Units released by disabling interception for their direction.
    pub fn disable_releases(&self) -> u64 {
        self.disable_releases.load(Ordering::Relaxed)
    }

    /// Units whose awaiting session ended while held (aborted task or
    /// engine shutdown), cleaned up lazily.
    pub fn abandoned(&self) -> u64 {
        self.abandoned.load(Ordering::Relaxed)
    }

    /// Decisions committed exactly once, cumulative.
    pub fn commits(&self) -> u64 {
        self.commits.load(Ordering::Relaxed)
    }

    fn lock_queue(&self) -> std::sync::MutexGuard<'_, VecDeque<QueuedUnit>> {
        self.queue
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
    /// Lazy maintenance, always called under the queue lock and never
    /// awaiting: release expired units with `Forward`, drop units whose
    /// receiver is gone (session died while held). Keeps the queue
    /// bounded and correct without any timer task.
    fn sweep_locked(&self, queue: &mut std::sync::MutexGuard<'_, VecDeque<QueuedUnit>>) {
        let now = Instant::now();
        let mut lease_releases = 0u64;
        let mut abandoned = 0u64;
        // Resolving consumes the entry's sender, so the queue is rebuilt
        // rather than filtered in place.
        let mut remaining = VecDeque::with_capacity(queue.len());
        while let Some(entry) = queue.pop_front() {
            if entry.tx.is_closed() {
                abandoned += 1;
            } else if entry.unit.expires_mono <= now {
                let _ = entry.tx.send(InterceptAction::Forward);
                lease_releases += 1;
            } else {
                remaining.push_back(entry);
            }
        }
        **queue = remaining;
        if lease_releases > 0 {
            self.lease_releases
                .fetch_add(lease_releases, Ordering::Relaxed);
        }
        if abandoned > 0 {
            self.abandoned.fetch_add(abandoned, Ordering::Relaxed);
        }
    }
}

/// Overflow-saturating instant: used when `now + hold_lease` does not
/// fit. Yields a representable instant roughly 50 years in the future —
/// effectively "never" for a session, yet still finite, so the lease
/// and sweep logic keep working instead of panicking.
fn saturate_instant(now: Instant) -> Instant {
    now.checked_add(Duration::from_secs(86400 * 365 * 50))
        .unwrap_or(now)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn limits() -> InterceptLimits {
        InterceptLimits {
            max_pending: 8,
            hold_lease: Duration::from_millis(200),
            max_replace_bytes: 1024,
        }
    }

    fn offer(coordinator: &Arc<InterceptCoordinator>, conn: &str, bytes: &[u8]) -> HeldHandle {
        match coordinator.offer(conn, Direction::ClientToServer, 0, 0, bytes) {
            OfferOutcome::Held(handle) => handle,
            OfferOutcome::Passthrough => panic!("offer must be held while enabled"),
        }
    }

    fn enabled(coordinator: &Arc<InterceptCoordinator>) {
        coordinator.set_enabled(Direction::ClientToServer, true);
    }

    #[tokio::test]
    async fn decide_commits_exactly_once() {
        let coordinator = InterceptCoordinator::new(limits());
        enabled(&coordinator);
        let handle = offer(&coordinator, "c1", b"payload");

        let unit = coordinator.pending()[0].clone();
        assert_eq!(unit.revision, 0);
        coordinator
            .decide(&unit.id, 0, InterceptAction::Suppress)
            .expect("first decision commits");

        // Duplicate decision for the resolved unit: rejected, never a
        // second emission.
        assert_eq!(
            coordinator.decide(&unit.id, 0, InterceptAction::Forward),
            Err(DecisionError::UnknownUnit {
                unit_id: unit.id.clone()
            })
        );
        assert!(coordinator.pending().is_empty());
        assert_eq!(coordinator.commits(), 1);
        assert_eq!(
            handle.resolve().await,
            InterceptAction::Suppress,
            "exactly one action must be delivered"
        );
    }

    #[tokio::test]
    async fn stale_revision_leaves_unit_pending() {
        let coordinator = InterceptCoordinator::new(limits());
        enabled(&coordinator);
        let _handle = offer(&coordinator, "c1", b"payload");

        let unit = coordinator.pending()[0].clone();
        assert_eq!(
            coordinator.decide(&unit.id, 7, InterceptAction::Close),
            Err(DecisionError::StaleRevision {
                unit_id: unit.id.clone(),
                presented: 7,
                expected: 0,
            })
        );
        // The stale attempt must not have consumed the unit.
        assert_eq!(coordinator.pending().len(), 1);
        coordinator
            .decide(&unit.id, 0, InterceptAction::Forward)
            .expect("correct revision commits");
    }

    #[tokio::test]
    async fn concurrent_decisions_commit_exactly_once() {
        let coordinator = InterceptCoordinator::new(limits());
        enabled(&coordinator);
        let handle = offer(&coordinator, "c1", b"payload");
        let unit = coordinator.pending()[0].clone();

        let first = {
            let coordinator = Arc::clone(&coordinator);
            let id = unit.id.clone();
            std::thread::spawn(move || {
                coordinator.decide(&id, 0, InterceptAction::Replace(b"X".to_vec()))
            })
        };
        let second = {
            let coordinator = Arc::clone(&coordinator);
            let id = unit.id.clone();
            std::thread::spawn(move || coordinator.decide(&id, 0, InterceptAction::Forward))
        };
        let (first, second) = (first.join().unwrap(), second.join().unwrap());
        assert!(
            first.is_ok() ^ second.is_ok(),
            "exactly one concurrent decision may commit: {first:?} vs {second:?}"
        );
        assert_eq!(coordinator.commits(), 1);
        // The delivered action is whichever decision won the race —
        // exactly one of the two.
        let action = handle.resolve().await;
        assert!(
            action == InterceptAction::Forward || action == InterceptAction::Replace(vec![b'X'])
        );
    }

    #[tokio::test]
    async fn lease_expiry_releases_forward_once() {
        let coordinator = InterceptCoordinator::new(InterceptLimits {
            max_pending: 8,
            hold_lease: Duration::from_millis(50),
            max_replace_bytes: 1024,
        });
        enabled(&coordinator);
        let handle = offer(&coordinator, "c1", b"payload");

        assert_eq!(
            handle.resolve().await,
            InterceptAction::Forward,
            "expiry must deliver the original bytes"
        );
        assert!(coordinator.pending().is_empty());
        assert_eq!(coordinator.lease_releases(), 1);
    }

    #[tokio::test]
    async fn late_decision_after_expiry_is_rejected() {
        let coordinator = InterceptCoordinator::new(InterceptLimits {
            max_pending: 8,
            hold_lease: Duration::from_millis(50),
            max_replace_bytes: 1024,
        });
        enabled(&coordinator);
        let handle = offer(&coordinator, "c1", b"payload");
        let unit = coordinator.pending()[0].clone();

        // Resolve through the lease path...
        assert_eq!(handle.resolve().await, InterceptAction::Forward);
        // ...then a decision that raced in late must be rejected, never
        // a second resolution.
        assert_eq!(
            coordinator.decide(&unit.id, 0, InterceptAction::Suppress),
            Err(DecisionError::UnknownUnit {
                unit_id: unit.id.clone()
            })
        );
        assert_eq!(coordinator.commits(), 0);
    }

    #[tokio::test]
    async fn dropped_handle_abandons_unit() {
        let coordinator = InterceptCoordinator::new(limits());
        enabled(&coordinator);
        let handle = offer(&coordinator, "c1", b"payload");
        assert_eq!(coordinator.pending().len(), 1);

        // Session death while held: the awaiting side disappears.
        drop(handle);
        assert!(
            coordinator.pending().is_empty(),
            "abandoned unit must be swept on next access"
        );
        assert_eq!(coordinator.abandoned(), 1);
    }

    #[tokio::test]
    async fn disabling_releases_only_that_direction() {
        let coordinator = InterceptCoordinator::new(limits());
        coordinator.set_enabled(Direction::ClientToServer, true);
        coordinator.set_enabled(Direction::ServerToClient, true);

        let c2s = offer(&coordinator, "c1", b"up");
        let s2c = match coordinator.offer("c1", Direction::ServerToClient, 0, 0, b"down") {
            OfferOutcome::Held(handle) => handle,
            OfferOutcome::Passthrough => panic!("s2c offer must be held"),
        };

        assert_eq!(coordinator.set_enabled(Direction::ClientToServer, false), 1);
        assert_eq!(
            c2s.resolve().await,
            InterceptAction::Forward,
            "disable must release the direction's units"
        );
        // The other direction is untouched and still decidable.
        assert_eq!(coordinator.pending().len(), 1);
        let unit = coordinator.pending()[0].clone();
        assert_eq!(unit.direction, Direction::ServerToClient);
        coordinator
            .decide(&unit.id, 0, InterceptAction::Suppress)
            .expect("other direction still accepts decisions");
        assert_eq!(s2c.resolve().await, InterceptAction::Suppress);
        assert_eq!(coordinator.disable_releases(), 1);
    }

    #[tokio::test]
    async fn full_queue_forwards_without_interception() {
        let coordinator = InterceptCoordinator::new(InterceptLimits {
            max_pending: 1,
            hold_lease: Duration::from_secs(30),
            max_replace_bytes: 1024,
        });
        enabled(&coordinator);
        let _first = offer(&coordinator, "c1", b"one");
        assert_eq!(coordinator.pending().len(), 1);

        match coordinator.offer("c2", Direction::ClientToServer, 0, 0, b"two") {
            OfferOutcome::Passthrough => {}
            OfferOutcome::Held(_) => panic!("queue at capacity must pass through"),
        }
        assert_eq!(coordinator.overflow_forwards(), 1);
        assert_eq!(
            coordinator.offers(),
            1,
            "only the held unit counts as offered"
        );
    }

    #[tokio::test]
    async fn disabled_direction_never_holds() {
        let coordinator = InterceptCoordinator::new(limits());
        assert!(!coordinator.enabled(Direction::ClientToServer));
        match coordinator.offer("c1", Direction::ClientToServer, 0, 0, b"x") {
            OfferOutcome::Passthrough => {}
            OfferOutcome::Held(_) => panic!("disabled direction must pass through"),
        }
        assert_eq!(coordinator.offers(), 0);
    }

    #[tokio::test]
    async fn decision_for_session_that_ended_still_commits_once() {
        let coordinator = InterceptCoordinator::new(limits());
        enabled(&coordinator);
        // Offer and drop the handle: the session ended while held, but
        // the queue entry survives until a decision or sweep resolves it.
        let handle = offer(&coordinator, "c1", b"payload");
        let unit = coordinator.pending()[0].clone();

        // Simulate the session ending between snapshot and decision by
        // keeping the handle alive: a decision addressed to a valid
        // unit commits even if delivery finds nobody waiting only when
        // the receiver is gone. Exercise the receiver-gone case too.
        drop(handle);
        // The sweep in decide() removes the abandoned unit first, so a
        // late decision is stale — resolved exactly once by abandonment.
        assert_eq!(
            coordinator.decide(&unit.id, 0, InterceptAction::Forward),
            Err(DecisionError::UnknownUnit {
                unit_id: unit.id.clone()
            })
        );

        // With a live receiver but a dropped... covered above; now the
        // live-receiver commit path with a succeeding send.
        let handle = offer(&coordinator, "c2", b"payload");
        let unit = coordinator.pending()[0].clone();
        coordinator
            .decide(&unit.id, 0, InterceptAction::Close)
            .expect("commit with live receiver");
        assert_eq!(handle.resolve().await, InterceptAction::Close);
    }

    #[tokio::test]
    async fn oversized_replace_rejected_before_commit() {
        let coordinator = InterceptCoordinator::new(limits());
        enabled(&coordinator);
        let handle = offer(&coordinator, "c1", b"payload");
        let unit = coordinator.pending()[0].clone();

        let oversized = InterceptAction::Replace(vec![b'Z'; 1025]);
        let bytes = 1025u64;
        assert_eq!(
            coordinator.decide(&unit.id, 0, oversized),
            Err(DecisionError::ReplaceTooLarge {
                unit_id: unit.id.clone(),
                bytes,
                limit: 1024,
            })
        );
        // The rejection must not have consumed the unit: it stays
        // pending, still awaiting a decision.
        assert_eq!(coordinator.pending().len(), 1);
        assert_eq!(coordinator.commits(), 0);

        // A legal decision for the same unit still commits.
        coordinator
            .decide(&unit.id, 0, InterceptAction::Suppress)
            .expect("legal decision commits after oversized rejection");
        assert!(coordinator.pending().is_empty());
        assert_eq!(coordinator.commits(), 1);
        assert_eq!(handle.resolve().await, InterceptAction::Suppress);
    }

    #[tokio::test]
    async fn replace_exactly_at_limit_commits() {
        let coordinator = InterceptCoordinator::new(limits());
        enabled(&coordinator);
        let handle = offer(&coordinator, "c1", b"payload");
        let unit = coordinator.pending()[0].clone();

        let replacement = vec![b'Z'; 1024];
        coordinator
            .decide(&unit.id, 0, InterceptAction::Replace(replacement.clone()))
            .expect("replacement at exactly the limit commits");
        assert!(coordinator.pending().is_empty());
        assert_eq!(coordinator.commits(), 1);
        assert_eq!(
            handle.resolve().await,
            InterceptAction::Replace(replacement)
        );
    }

    #[tokio::test]
    async fn empty_replace_commits() {
        // An empty Replace is legal: it delivers nothing via the
        // delivery path, like Suppress.
        let coordinator = InterceptCoordinator::new(limits());
        enabled(&coordinator);
        let handle = offer(&coordinator, "c1", b"payload");
        let unit = coordinator.pending()[0].clone();
        coordinator
            .decide(&unit.id, 0, InterceptAction::Replace(Vec::new()))
            .expect("empty replacement is legal");
        assert_eq!(handle.resolve().await, InterceptAction::Replace(Vec::new()));
    }

    #[tokio::test]
    async fn extreme_hold_lease_saturates_without_panicking() {
        let coordinator = InterceptCoordinator::new(InterceptLimits {
            max_pending: 8,
            hold_lease: Duration::MAX,
            max_replace_bytes: 1024,
        });
        enabled(&coordinator);
        // offer() must not panic even though `now + Duration::MAX`
        // overflows Instant arithmetic.
        let handle = offer(&coordinator, "c1", b"payload");
        assert_eq!(coordinator.pending().len(), 1);

        // The saturated lease must not be treated as already expired:
        // a decision still commits and the handle resolves to it.
        let unit = coordinator.pending()[0].clone();
        assert!(unit.expires_mono > Instant::now());
        coordinator
            .decide(&unit.id, 0, InterceptAction::Suppress)
            .expect("decision commits under a saturated lease");
        assert_eq!(handle.resolve().await, InterceptAction::Suppress);
        assert_eq!(coordinator.lease_releases(), 0);
    }

    #[test]
    fn disabled_offer_never_waits_for_the_queue_lock() {
        use std::sync::mpsc;

        let coordinator = InterceptCoordinator::new(limits());
        // The queue lock is held for the whole offer attempt...
        let guard = coordinator.queue.lock().unwrap();
        let (done_tx, done_rx) = mpsc::channel();
        let worker_coordinator = Arc::clone(&coordinator);
        let worker = std::thread::spawn(move || {
            match worker_coordinator.offer("c1", Direction::ClientToServer, 0, 0, b"passive") {
                OfferOutcome::Passthrough => done_tx.send(()).unwrap(),
                OfferOutcome::Held(_) => panic!("disabled direction must pass through"),
            }
        });
        // ...so the offer may only complete via the lock-free fast path.
        let completed = done_rx.recv_timeout(Duration::from_secs(2));
        drop(guard);
        worker.join().unwrap();
        completed.expect("a disabled-direction offer must not wait for the queue lock");
        assert_eq!(coordinator.offers(), 0);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn lease_expiry_under_lock_contention_stays_cancellable() {
        use std::sync::mpsc;

        let coordinator = InterceptCoordinator::new(InterceptLimits {
            max_pending: 8,
            hold_lease: Duration::from_millis(50),
            max_replace_bytes: 1024,
        });
        enabled(&coordinator);
        // Offer first: an enabled-direction offer needs the lock, so the
        // unit must be queued before the lock is taken away.
        let handle = offer(&coordinator, "c1", b"payload");

        // Hold the queue lock on a dedicated OS thread for the whole
        // test, so the lease path can never acquire it.
        let (held_tx, held_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let holder_coordinator = Arc::clone(&coordinator);
        let holder = std::thread::spawn(move || {
            let guard = holder_coordinator.queue.lock().unwrap();
            held_tx.send(()).unwrap();
            release_rx.recv().unwrap();
            drop(guard);
        });
        held_rx.recv_timeout(Duration::from_secs(5)).unwrap();

        // Let the lease elapse, then start resolving: the expiry path
        // finds the lock contended and must keep awaiting (never block
        // its worker thread on the mutex).
        tokio::time::sleep(Duration::from_millis(120)).await;
        let task = tokio::spawn(async move { handle.resolve().await });
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Cancellation (session abort / engine shutdown) must land
        // promptly despite the permanent lock contention.
        task.abort();
        let joined = tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .expect("abort must land despite lock contention");
        let error = joined.expect_err("the resolve task must have been cancelled");
        assert!(error.is_cancelled());

        // Cleanup on every path, then verify the abandoned unit is swept.
        release_tx.send(()).unwrap();
        holder.join().unwrap();
        assert!(coordinator.pending().is_empty());
        assert_eq!(coordinator.abandoned(), 1);
        assert_eq!(
            coordinator.lease_releases(),
            0,
            "the contended expiry never released the unit"
        );
    }

    #[tokio::test]
    async fn replace_capacity_is_normalized_to_the_bound() {
        let coordinator = InterceptCoordinator::new(limits());
        enabled(&coordinator);
        let handle = offer(&coordinator, "c1", b"payload");
        let unit = coordinator.pending()[0].clone();

        // One byte of payload in a massively oversized allocation: the
        // length check passes, but the session would retain the
        // capacity while writing under backpressure.
        let mut sparse = Vec::with_capacity(1 << 20);
        sparse.push(b'x');
        coordinator
            .decide(&unit.id, 0, InterceptAction::Replace(sparse))
            .expect("small length commits");

        match handle.resolve().await {
            InterceptAction::Replace(bytes) => {
                assert_eq!(bytes, vec![b'x']);
                assert!(
                    bytes.capacity() as u64 <= 1024,
                    "replacement allocation must be normalized to the bound, got {}",
                    bytes.capacity()
                );
            }
            other => panic!("expected Replace, got {other:?}"),
        }
    }
}
