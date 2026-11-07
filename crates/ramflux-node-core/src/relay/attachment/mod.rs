// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Dormant native attachment accounting. No endpoint calls this module yet.
//! The service authenticates the original owner before constructing its context;
//! this ledger is not a grant verifier or a local-reference retirement authority.
pub mod backend;
mod format;
mod grants;
mod identity;
pub use grants::*;
mod quota;
mod retention;
mod terminal;
pub use retention::{AttachmentDebtPage, AttachmentPolicy};
#[cfg(test)]
mod terminal_tests;
#[cfg(test)]
mod tests;
use ramflux_protocol::large_attachment::SegmentLayout;
use redb::{ReadableDatabase, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

const RECORDS: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("native_attachment_reservations_v1");
const TOTALS: TableDefinition<&str, &[u8]> =
    TableDefinition::new("native_attachment_owner_totals_v1");
const OBJECTS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("native_attachment_objects_v1");
const DEBTS: TableDefinition<&[u8], ()> = TableDefinition::new("native_attachment_cleanup_v1");
const DEADLINES: TableDefinition<&[u8], ()> =
    TableDefinition::new("native_attachment_deadlines_v1");

#[derive(Debug, thiserror::Error)]
pub enum AttachmentLedgerError {
    #[error("account quota exceeded: used={used}, reserved={reserved}, limit={limit}")]
    AccountQuotaExceeded { used: u64, reserved: u64, limit: u64 },
    #[error("attachment identity conflict")]
    Conflict,
    #[error("attachment expired")]
    Expired,
    #[error("invalid attachment policy or dimensions")]
    Invalid,
    #[error("attachment operation is not valid in this state")]
    State,
    #[error("attachment metadata capacity exceeded")]
    Capacity,
    #[error("terminal evidence capacity exceeded")]
    TerminalEvidenceCapacity,
    #[error("terminal owner capacity exceeded")]
    TerminalOwnerCapacity,
    #[error("attachment ledger storage: {0}")]
    Store(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// Construct only from a verified owner session, never a request tenant field.
/// Validation here checks representation, not authentication or root authority.
#[derive(Debug, Clone)]
pub struct AttachmentOwner(String);
impl AttachmentOwner {
    /// # Errors
    /// Refuses empty or oversized authenticated account anchors.
    pub fn from_authenticated_session(anchor: &str) -> Result<Self, AttachmentLedgerError> {
        if anchor.is_empty() || anchor.len() > 256 {
            return Err(AttachmentLedgerError::Invalid);
        }
        Ok(Self(anchor.into()))
    }
}
#[derive(Debug, Clone, Copy)]
pub struct AttachmentReservationRequest {
    pub upload_id: [u8; 32],
    pub object_id: [u8; 32],
    pub layout: SegmentLayout,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttachmentReservationState {
    Pending,
    Committed,
    DebtPending,
    DebtCommitted,
    Released,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttachmentReservation {
    pub owner: String,
    pub upload_id: [u8; 32],
    pub object_id: [u8; 32],
    pub plaintext_length: u64,
    pub network_chunk_bytes: u32,
    pub size: u64,
    pub manifest_hash: Option<[u8; 32]>,
    pub state: AttachmentReservationState,
    pub lease_until: u64,
    pub lease_hard_until: u64,
    pub lease_step: u64,
    pub retention_seconds: u64,
    pub expires_at: Option<u64>,
    /// Authoritative payload generation, allocated once at reserve. Legacy rows read as 0.
    #[serde(default)]
    pub pending_generation: u64,
    /// Set exactly once at commit, equal to `pending_generation`.
    #[serde(default)]
    pub committed_generation: Option<u64>,
}
impl AttachmentReservation {
    /// The one legacy-zero refusal shared by every admission and authority reader
    /// (ATTACH-LARGE-01 §4): a payload needs a nonzero pending generation and an equal
    /// committed generation before it can be read, granted or leased.
    pub(super) fn require_bound_generation(&self) -> Result<(), AttachmentLedgerError> {
        if self.pending_generation == 0
            || self.committed_generation != Some(self.pending_generation)
        {
            return Err(AttachmentLedgerError::State);
        }
        Ok(())
    }
}
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct AttachmentQuota {
    pub used: u64,
    pub reserved: u64,
    pub records: u64,
    #[serde(default)]
    pub fences: u64,
    #[serde(default)]
    pub terminal_slots: u64,
}
#[derive(Clone)]
pub struct AttachmentLedger {
    db: Arc<redb::Database>,
    policy: AttachmentPolicy,
}

pub(super) fn install(
    tx: &redb::WriteTransaction,
    replay_now: u64,
) -> Result<(), crate::NodeCoreError> {
    backend::install(tx)?;
    let map = |error: redb::TableError| crate::NodeCoreError::Redb(error.to_string());
    let _ = tx.open_table(RECORDS).map_err(map)?;
    let _ = tx.open_table(TOTALS).map_err(map)?;
    let _ = tx.open_table(OBJECTS).map_err(map)?;
    let _ = tx.open_table(DEADLINES).map_err(map)?;
    let _ = tx.open_table(DEBTS).map_err(map)?;
    identity::install(tx).map_err(|e| crate::NodeCoreError::Redb(e.to_string()))?;
    terminal::install(tx).map_err(|e| crate::NodeCoreError::Redb(e.to_string()))?;
    format::install(tx).map_err(|e| crate::NodeCoreError::Redb(e.to_string()))?;
    grants::install(tx, replay_now).map_err(|e| crate::NodeCoreError::Redb(e.to_string()))?;
    Ok(())
}
/// Why a bounded write-lock acquisition failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum BeginError {
    /// The deadline passed before the single ledger writer became available.
    Busy,
    Store(String),
}
/// A request deadline for ledger waits. The clock decides in production; a test can hold a
/// shared flag instead so "the deadline passes" is an explicit event, never a real wait.
#[derive(Clone, Debug)]
pub struct WriteDeadline {
    at: std::time::Instant,
    cancel: Option<Arc<std::sync::atomic::AtomicBool>>,
}
impl WriteDeadline {
    #[must_use]
    pub fn at(at: std::time::Instant) -> Self {
        Self { at, cancel: None }
    }
    /// The deadline also passes when `cancel` is raised.
    #[cfg(any(test, feature = "test-support"))]
    #[must_use]
    pub fn controlled(at: std::time::Instant, cancel: Arc<std::sync::atomic::AtomicBool>) -> Self {
        Self { at, cancel: Some(cancel) }
    }
    pub(crate) fn expired(&self) -> bool {
        self.cancel.as_ref().is_some_and(|c| c.load(std::sync::atomic::Ordering::Acquire))
            || std::time::Instant::now() >= self.at
    }
}
/// Abandoned waiters that are still parked on the writer lock.
static PARKED_WAITERS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
const MAX_PARKED_WAITERS: usize = 4;
/// Helper threads currently blocked on the ledger's write lock (test observation only).
#[cfg(any(test, feature = "test-support"))]
#[must_use]
pub fn parked_writer_waiters() -> usize {
    PARKED_WAITERS.load(std::sync::atomic::Ordering::Acquire)
}
/// How often a bounded wait re-checks its deadline.
const WAIT_SLICE: std::time::Duration = std::time::Duration::from_millis(2);

impl AttachmentLedger {
    /// Takes the ledger's single write lock, giving up at `deadline` (`None` waits as the
    /// plain `begin_write` does). `redb` has no timed acquisition, so the wait happens on a
    /// helper thread that rolls its transaction back if nobody is waiting any more. At most
    /// a few such threads may be parked at once; beyond that the caller is refused at once.
    pub(crate) fn begin_write_until(
        &self,
        deadline: Option<&WriteDeadline>,
    ) -> Result<redb::WriteTransaction, BeginError> {
        use std::sync::atomic::Ordering;
        let Some(deadline) = deadline else {
            return self.db.begin_write().map_err(|e| BeginError::Store(e.to_string()));
        };
        if deadline.expired() {
            return Err(BeginError::Busy);
        }
        if PARKED_WAITERS.fetch_add(1, Ordering::AcqRel) >= MAX_PARKED_WAITERS {
            PARKED_WAITERS.fetch_sub(1, Ordering::AcqRel);
            return Err(BeginError::Busy);
        }
        let (sender, receiver) = std::sync::mpsc::sync_channel(1);
        let db = Arc::clone(&self.db);
        std::thread::spawn(move || {
            let begun = db.begin_write();
            PARKED_WAITERS.fetch_sub(1, Ordering::AcqRel);
            // A receiver that has gone away drops (rolls back) the transaction.
            let _ = sender.send(begun);
        });
        loop {
            match receiver.recv_timeout(WAIT_SLICE) {
                Ok(begun) => {
                    let tx = begun.map_err(|e| BeginError::Store(e.to_string()))?;
                    // Nothing is admitted after the deadline, even if the lock was won at the wire.
                    if deadline.expired() {
                        return Err(BeginError::Busy);
                    }
                    return Ok(tx);
                }
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                    if deadline.expired() {
                        return Err(BeginError::Busy);
                    }
                }
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                    return Err(BeginError::Store("writer wait ended".into()));
                }
            }
        }
    }
    pub(super) fn new(
        db: Arc<redb::Database>,
        policy: AttachmentPolicy,
    ) -> Result<Self, AttachmentLedgerError> {
        policy.validate()?;
        terminal::recount(&db)?;
        Ok(Self { db, policy })
    }
    /// # Errors
    /// Returns durable original-owner accounting or a storage error.
    pub fn usage(&self, owner: &AttachmentOwner) -> Result<AttachmentQuota, AttachmentLedgerError> {
        let tx = self.db.begin_read().map_err(store)?;
        let table = tx.open_table(TOTALS).map_err(store)?;
        table
            .get(owner.0.as_str())
            .map_err(store)?
            .map_or(Ok(AttachmentQuota::default()), |v| decode(v.value()))
    }
    /// # Errors
    /// Refuses unknown identities or unreadable durable state. This is inspection
    /// metadata, not serving authority; read admission also requires `committed()`
    /// and the native grant verifier.
    pub fn reservation(
        &self,
        owner: &AttachmentOwner,
        id: &[u8; 32],
    ) -> Result<AttachmentReservation, AttachmentLedgerError> {
        let tx = self.db.begin_read().map_err(store)?;
        let table = tx.open_table(RECORDS).map_err(store)?;
        let value = table
            .get(key(owner, id).as_slice())
            .map_err(store)?
            .ok_or(AttachmentLedgerError::Conflict)?;
        decode(value.value())
    }
}
fn key(owner: &AttachmentOwner, id: &[u8; 32]) -> Vec<u8> {
    let mut key = Vec::new();
    key.extend_from_slice(&(owner.0.len() as u64).to_be_bytes());
    key.extend_from_slice(owner.0.as_bytes());
    key.extend_from_slice(id);
    key
}
fn deadline(time: u64, key: &[u8]) -> Vec<u8> {
    let mut out = time.to_be_bytes().to_vec();
    out.extend_from_slice(key);
    out
}
fn store(error: impl std::fmt::Display) -> AttachmentLedgerError {
    AttachmentLedgerError::Store(error.to_string())
}
fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, AttachmentLedgerError> {
    serde_json::to_vec(value).map_err(store)
}
fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, AttachmentLedgerError> {
    serde_json::from_slice(bytes).map_err(store)
}
