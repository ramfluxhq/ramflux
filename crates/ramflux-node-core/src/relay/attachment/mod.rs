// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Dormant native attachment accounting. No endpoint calls this module yet.
//! The service authenticates the original owner before constructing its context;
//! this ledger is not a grant verifier or a local-reference retirement authority.
mod quota;
mod retention;
pub use retention::AttachmentPolicy;
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
}
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct AttachmentQuota {
    pub used: u64,
    pub reserved: u64,
    pub records: u64,
}
#[derive(Clone)]
pub struct AttachmentLedger {
    db: Arc<redb::Database>,
    policy: AttachmentPolicy,
}

pub(super) fn install(tx: &redb::WriteTransaction) -> Result<(), crate::NodeCoreError> {
    let map = |error: redb::TableError| crate::NodeCoreError::Redb(error.to_string());
    let _ = tx.open_table(RECORDS).map_err(map)?;
    let _ = tx.open_table(TOTALS).map_err(map)?;
    let _ = tx.open_table(OBJECTS).map_err(map)?;
    let _ = tx.open_table(DEADLINES).map_err(map)?;
    let _ = tx.open_table(DEBTS).map_err(map)?;
    Ok(())
}
impl AttachmentLedger {
    pub(super) fn new(
        db: Arc<redb::Database>,
        policy: AttachmentPolicy,
    ) -> Result<Self, AttachmentLedgerError> {
        policy.validate()?;
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
