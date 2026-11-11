// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Pairing relay allocator bounds, clocks and typed refusals.
use ramflux_protocol::custody::pairing::WireError;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;
use subtle::ConstantTimeEq;

/// Combined issued+live slots per node process.
pub const MAX_SLOTS: usize = 64;
/// Issued+live slots that may belong to one `account_anchor`.
pub const MAX_SLOTS_PER_ACCOUNT: usize = 3;
/// Native Issue admissions per account per monotonic hour.
pub const MAX_ISSUES_PER_HOUR: usize = 10;
/// Per-account hour-counter map size. Full Busy, no eviction.
pub const MAX_HOUR_ENTRIES: usize = 1_024;
/// Root-free outstanding claims per node.
pub const MAX_CLAIMS: usize = 64;
/// Outstanding claims per IPv4 /24 or IPv6 /64 and /48.
pub const MAX_CLAIMS_PER_PREFIX: usize = 4;
/// Claim and disconnect-grace lifetime in milliseconds.
pub const CLAIM_GRACE_MS: u64 = 10_000;
/// Invitation lifetime in unix seconds and monotonic milliseconds.
pub const INVITATION_LIFETIME_SECS: u64 = 300;
/// Sliding Issue window.
pub const HOUR_MS: u64 = 3_600_000;
/// Polls admitted per role per second.
pub const MAX_POLLS_PER_SEC: usize = 2;
/// Queued complete frames per direction.
pub const MAX_FRAMES_PER_DIRECTION: usize = 2;
/// One Send/Polled body.
pub const MAX_FRAME_BYTES: usize = 16_384;
/// Two directions × two 16KiB frames.
pub const MAX_QUEUE_BYTES: usize = 65_536;
/// Descriptor 16000 + ticket 2048 + fixed ids/digests 3456.
pub const MAX_SLOT_METADATA: usize = 21_504;
/// Issued slot without a descriptor: ticket + fixed state (annex F bound, not a dummy buffer).
pub const ISSUED_RESERVE: usize = 2_048 + 3_456;
/// Live slot metadata and both queues (annex F bound, not a dummy buffer).
pub const LIVE_RESERVE: usize = MAX_SLOT_METADATA + MAX_QUEUE_BYTES;
/// Annex F registry ceiling (boot id, indexes, hour/source/closed maps). Charged as real
/// `HashMap::capacity() × ENTRY_OVERHEAD` at construction; no dummy 256 KiB allocation.
pub const SLACK_BYTES: usize = 262_144;
/// Floor charged once for every map bucket and held record. Per-table charges use
/// `size_of::<Entry>().max(ENTRY_OVERHEAD)` so the overhead is never below the real entry.
pub const ENTRY_OVERHEAD: usize = 64;
/// Closed-invitation tombstones. Live slot cap × issues-per-hour (retention-window factor 10):
/// closed hashes persist for the original 300 s invitation lifetime, and a frozen clock admits
/// at most 10 Issue→Create→Close cycles per account. 64 × 10 = 640. Busy, no eviction.
///
/// Policy, not a derived per-account bound: 64 accounts can fill all 640 closed entries
/// within 300 s. Further Close then returns Busy for every account until a tombstone
/// expires with its original invitation lifetime. Live slots still expire and prune
/// independently. This is accepted allocator policy.
pub const MAX_CLOSED: usize = MAX_SLOTS * MAX_ISSUES_PER_HOUR;
/// Total retained relay backing. Cap uses the accountant; 5832704 is the annex F plan total.
pub const MAX_BACKING: usize = MAX_SLOTS * LIVE_RESERVE + SLACK_BYTES;

const _: () = assert!(MAX_BACKING == 5_832_704);
const _: () = assert!(ISSUED_RESERVE < LIVE_RESERVE);
const _: () = assert!(MAX_CLOSED == 640);

/// Wall seconds plus monotonic milliseconds. Wall rollback cannot extend a deadline.
pub trait PairingClock: Send + Sync {
    /// # Errors
    /// Returns [`PairingRelayError::InvalidInput`] when the clock cannot be read.
    fn wall_unix_secs(&self) -> Result<u64, PairingRelayError>;
    fn monotonic_ms(&self) -> u64;
}

/// Production clock: `ramflux_core::Clock` wall time and a process `Instant`.
pub struct NodePairingClock {
    wall: Arc<dyn ramflux_core::Clock>,
    origin: Instant,
}

impl NodePairingClock {
    #[must_use]
    pub fn new(wall: Arc<dyn ramflux_core::Clock>) -> Self {
        Self { wall, origin: Instant::now() }
    }
    #[must_use]
    pub fn system() -> Self {
        Self::new(Arc::new(ramflux_core::SystemClock))
    }
}

impl PairingClock for NodePairingClock {
    fn wall_unix_secs(&self) -> Result<u64, PairingRelayError> {
        let millis = self.wall.now_millis().map_err(|_| PairingRelayError::invalid("clock"))?;
        Ok(millis.as_u64() / 1_000)
    }
    fn monotonic_ms(&self) -> u64 {
        u64::try_from(self.origin.elapsed().as_millis()).unwrap_or(u64::MAX)
    }
}

/// Injected test clock. Advances never sleep on the wall clock.
pub struct TestPairingClock {
    wall: AtomicU64,
    mono: AtomicU64,
}

impl TestPairingClock {
    #[must_use]
    pub fn new(wall_unix_secs: u64) -> Arc<Self> {
        Arc::new(Self { wall: AtomicU64::new(wall_unix_secs), mono: AtomicU64::new(0) })
    }
    pub fn set_wall(&self, wall_unix_secs: u64) {
        self.wall.store(wall_unix_secs, Ordering::SeqCst);
    }
    pub fn set_mono(&self, monotonic_ms: u64) {
        self.mono.store(monotonic_ms, Ordering::SeqCst);
    }
    pub fn advance_secs(&self, secs: u64) {
        self.wall.fetch_add(secs, Ordering::SeqCst);
        self.mono.fetch_add(secs.saturating_mul(1_000), Ordering::SeqCst);
    }
    pub fn advance_ms(&self, ms: u64) {
        self.mono.fetch_add(ms, Ordering::SeqCst);
    }
}

impl PairingClock for TestPairingClock {
    fn wall_unix_secs(&self) -> Result<u64, PairingRelayError> {
        Ok(self.wall.load(Ordering::SeqCst))
    }
    fn monotonic_ms(&self) -> u64 {
        self.mono.load(Ordering::SeqCst)
    }
}

/// Closed native/relay Failure codes owned by this allocator.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum PairingRelayError {
    #[error("Busy")]
    Busy { retry_after_ms: u64 },
    #[error("Retired")]
    Retired,
    #[error("Expired")]
    Expired,
    #[error("InvalidInput")]
    InvalidInput { field: &'static str },
    #[error("WrongContext")]
    WrongContext,
    #[error("WrongRole")]
    WrongRole,
    #[error("Replay")]
    Replay,
    #[error("NotFound")]
    NotFound,
    #[error("HeadChanged")]
    HeadChanged,
    #[error("LeaseExpired")]
    LeaseExpired,
    #[error("PublicationPending")]
    PublicationPending,
}

impl PairingRelayError {
    #[must_use]
    pub const fn invalid(field: &'static str) -> Self {
        Self::InvalidInput { field }
    }
    #[must_use]
    pub fn busy(monotonic_ms: u64) -> Self {
        Self::Busy { retry_after_ms: 1_000 + (monotonic_ms % 29_001) }
    }
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Busy { .. } => "Busy",
            Self::Retired => "Retired",
            Self::Expired => "Expired",
            Self::InvalidInput { .. } => "InvalidInput",
            Self::WrongContext => "WrongContext",
            Self::WrongRole => "WrongRole",
            Self::Replay => "Replay",
            Self::NotFound => "NotFound",
            Self::PublicationPending => "PublicationPending",
            Self::HeadChanged => "HeadChanged",
            Self::LeaseExpired => "LeaseExpired",
        }
    }
}

pub(super) fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    bool::from(left.ct_eq(right))
}

pub(super) fn token_hash(token: &[u8; 32]) -> [u8; 32] {
    ramflux_crypto::blake3_256("ramflux.identity.pairing.relay_token.v1", token)
}

pub(super) fn wire(error: &WireError) -> PairingRelayError {
    match error {
        WireError::Field(field) => PairingRelayError::invalid(field),
        WireError::Json => PairingRelayError::invalid("json"),
        WireError::Shape => PairingRelayError::invalid("shape"),
        WireError::Size => PairingRelayError::invalid("size"),
        WireError::NonCanonical => PairingRelayError::invalid("canonical"),
    }
}

/// IPv4 /24 and IPv6 /64+/48 keys used for the outstanding-claim budget.
#[must_use]
pub fn claim_source_prefixes(source: IpAddr) -> Vec<String> {
    crate::custody_source_prefixes(source)
        .into_iter()
        .filter(|key| key.ends_with("/24") || key.ends_with("/64") || key.ends_with("/48"))
        .collect()
}

/// Observed retained backing, split so queue/socket counters stay independent.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AllocatorStats {
    pub slots: usize,
    pub full: usize,
    pub issued: usize,
    pub live: usize,
    pub backing: usize,
    pub high_water: usize,
    pub queued_bytes: usize,
    pub queued_frames: usize,
    pub sockets: usize,
    pub claims: usize,
}
