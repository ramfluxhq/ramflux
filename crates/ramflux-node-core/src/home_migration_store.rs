// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Durable cooperative migration transitions share the router's redb commit boundary.
use crate::{NodeCoreError, RouterCore, RouterRedbStore};
use ramflux_crypto::{
    custody::VerifiedRecord,
    home_migration::{self as crypto, VerifiedHome},
};
use ramflux_protocol::{
    custody::{Envelope, NodeIdentityRecord},
    home_migration::{
        Action, Authorization, BacklogProgress, CommitProof, DeliveryMapEntry, FORWARD_SECONDS,
        Genesis, HomeAttestation, HomeRecord, MAX_CHAIN_RECORDS, MAX_COMMIT_DELAY, MAX_SEAL_DELAY,
        NoncommitFence, Offer, Phase, Prepare, Receipt, RecordEvidence, Refusal, SKEW_SECONDS,
        Signed, delivery_map_hash, message_hash, record_hash,
    },
};
use redb::{ReadableDatabase, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};

mod destination;
pub use destination::PrepareMigration;
pub use source::{AttestMigration, AttestedHome, CommitMigration, FenceOutcome, MigrationPeer};
mod authority_evidence;
mod fence;
mod maintenance;
mod source;
#[cfg(test)]
mod tests;

const HEADS: TableDefinition<&str, &[u8]> = TableDefinition::new("home_head_v1");
const RECORDS: TableDefinition<&str, &[u8]> = TableDefinition::new("home_records_v1");
const PROOFS: TableDefinition<&str, &[u8]> = TableDefinition::new("migration_commit_index_v1");
const FENCES: TableDefinition<&str, &[u8]> = TableDefinition::new("migration_auth_fences_v1");
const FENCE_EXPIRES: TableDefinition<&str, &[u8]> =
    TableDefinition::new("migration_auth_fence_expiry_v1");
const OPS: TableDefinition<&str, &[u8]> = TableDefinition::new("migration_ops_v1");
const BUSINESS: TableDefinition<&str, &[u8]> = TableDefinition::new("migration_business_keys_v1");
const COURIER: TableDefinition<&str, &[u8]> = TableDefinition::new("migration_courier_due_v1");
const BACKLOG: TableDefinition<&str, &[u8]> = TableDefinition::new("migration_backlog_cursor_v1");
const BUDGETS: TableDefinition<&str, u64> = TableDefinition::new("migration_live_budgets_v1");
const TARGETS: TableDefinition<&str, &[u8]> = TableDefinition::new("migration_inbox_routes_v1");
const GUARDS: TableDefinition<&str, &str> = TableDefinition::new("migration_recovery_guards_v1");
const EXPIRES: TableDefinition<&str, &[u8]> = TableDefinition::new("migration_expiry_due_v1");
const CLOCK: TableDefinition<&str, u64> = TableDefinition::new("migration_time_floor_v1");

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MigrationOperation {
    pub role: MigrationRole,
    pub phase: Phase,
    pub prepare: Signed<Prepare>,
    pub offer: Signed<Offer>,
    pub authorization: Option<Signed<Authorization>>,
    pub seal: Option<Signed<Receipt>>,
    pub proof: Option<Signed<CommitProof>>,
    pub fence: Option<Signed<NoncommitFence>>,
    pub base: RecordEvidence,
    pub attestation: Signed<HomeAttestation>,
    pub delivery_map: Vec<DeliveryMapEntry>,
    pub state_version: u64,
    pub next_due: u64,
    pub expires_at: u64,
    pub recovery_guard: bool,
    pub live_budget: bool,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MigrationRole {
    Source,
    Destination,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MigrationBacklogCursor {
    pub account_anchor: String,
    pub migration_id: String,
    pub target_delivery_id: String,
    pub high_water: u64,
    pub next_seq: u64,
    pub progress: BacklogProgress,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BusinessOutcome {
    payload_hash: String,
    operation_key: String,
    expires_at: u64,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct InboxRoute {
    anchor: String,
    migration_id: String,
    epoch: u64,
    active: bool,
}

/// Immutable admission evidence on the mesh; never import a peer's live scheduler state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SealedMigration {
    pub prepare: Signed<Prepare>,
    pub offer: Signed<Offer>,
    pub authorization: Signed<Authorization>,
    pub seal: Signed<Receipt>,
    pub base: RecordEvidence,
    pub attestation: Signed<HomeAttestation>,
    pub delivery_map: Vec<DeliveryMapEntry>,
}
impl MigrationOperation {
    /// Export only the signed admission and its routing evidence.
    /// # Errors
    /// Rejects an operation that has not been sealed.
    pub fn sealed_evidence(&self) -> Result<SealedMigration, NodeCoreError> {
        Ok(SealedMigration {
            prepare: self.prepare.clone(),
            offer: self.offer.clone(),
            authorization: self
                .authorization
                .clone()
                .ok_or_else(|| refusal(Refusal::EvidenceRequired))?,
            seal: self.seal.clone().ok_or_else(|| refusal(Refusal::EvidenceRequired))?,
            base: self.base.clone(),
            attestation: self.attestation.clone(),
            delivery_map: self.delivery_map.clone(),
        })
    }
}
impl SealedMigration {
    fn source_operation(
        &self,
        base: RecordEvidence,
        now: u64,
    ) -> Result<MigrationOperation, NodeCoreError> {
        Ok(MigrationOperation {
            role: MigrationRole::Source,
            phase: Phase::Committed,
            prepare: self.prepare.clone(),
            offer: self.offer.clone(),
            authorization: Some(self.authorization.clone()),
            seal: Some(self.seal.clone()),
            proof: None,
            fence: None,
            base,
            attestation: self.attestation.clone(),
            delivery_map: self.delivery_map.clone(),
            state_version: 1,
            next_due: now,
            expires_at: crypto::hard_deadline(&self.authorization.body).map_err(auth_error)?,
            recovery_guard: false,
            live_budget: true,
        })
    }
}
/// Configured service authority. Never constructed from a request-supplied node key.
pub struct MigrationNode {
    pub(crate) record: Envelope<NodeIdentityRecord>,
    pub(crate) key: ed25519_dalek::SigningKey,
    pub(crate) gateway_tcp_addr: String,
    pub(crate) federation_endpoint: String,
    pub(crate) discovery_hash: String,
    pub(crate) server_record_hash: String,
}
impl MigrationNode {
    /// Enable only with a matching service signer and verified endpoint records.
    /// # Errors
    /// Rejects absent/mismatched node signing authority or invalid descriptors.
    pub fn new(
        record: Envelope<NodeIdentityRecord>,
        seed: [u8; 32],
        endpoints: MigrationEndpoints,
        now: u64,
    ) -> Result<Self, NodeCoreError> {
        let seed = zeroize::Zeroizing::new(seed);
        let key = ed25519_dalek::SigningKey::from_bytes(&seed);
        let public = ramflux_protocol::encode_base64url(key.verifying_key().to_bytes());
        ramflux_crypto::custody::verify_node_identity_record(
            &record,
            &record.body.node_id,
            &public,
            now,
        )
        .map_err(auth_error)?;
        if endpoints.gateway_tcp_addr.is_empty()
            || endpoints.gateway_tcp_addr.len() > 2048
            || endpoints.federation_endpoint.is_empty()
        {
            return Err(refusal(Refusal::PeeringUnavailable));
        }
        Ok(Self {
            record,
            key,
            gateway_tcp_addr: endpoints.gateway_tcp_addr,
            federation_endpoint: endpoints.federation_endpoint,
            discovery_hash: endpoints.discovery_hash,
            server_record_hash: endpoints.server_record_hash,
        })
    }
    #[must_use]
    pub fn node_id(&self) -> &str {
        &self.record.body.node_id
    }
    #[must_use]
    pub fn public_key(&self) -> &str {
        &self.record.body.node_signing_public_key
    }
}
pub struct MigrationEndpoints {
    pub gateway_tcp_addr: String,
    pub federation_endpoint: String,
    pub discovery_hash: String,
    pub server_record_hash: String,
}
fn refusal(code: Refusal) -> NodeCoreError {
    NodeCoreError::HomeMigration(code)
}
fn auth_error(_: impl std::fmt::Display) -> NodeCoreError {
    refusal(Refusal::AuthorityUpdateRequired)
}
fn storage(e: impl std::fmt::Display) -> NodeCoreError {
    NodeCoreError::Redb(e.to_string())
}
fn bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, NodeCoreError> {
    ramflux_protocol::canonical_json_bytes(value).map_err(storage)
}
fn decode<T: for<'a> Deserialize<'a>>(raw: &[u8]) -> Result<T, NodeCoreError> {
    serde_json::from_slice(raw).map_err(storage)
}
fn op_key(anchor: &str, id: &str, role: MigrationRole) -> Result<String, NodeCoreError> {
    serde_json::to_string(&(anchor, id, role)).map_err(storage)
}
fn business_key(anchor: &str, id: &str, action: Action) -> Result<String, NodeCoreError> {
    serde_json::to_string(&(anchor, id, action)).map_err(storage)
}
fn read<T: for<'a> Deserialize<'a>>(
    tx: &redb::WriteTransaction,
    table: TableDefinition<&str, &[u8]>,
    key: &str,
) -> Result<Option<T>, NodeCoreError> {
    tx.open_table(table)
        .map_err(storage)?
        .get(key)
        .map_err(storage)?
        .map(|v| decode(v.value()))
        .transpose()
}
fn write<T: Serialize>(
    tx: &redb::WriteTransaction,
    table: TableDefinition<&str, &[u8]>,
    key: &str,
    value: &T,
) -> Result<(), NodeCoreError> {
    tx.open_table(table)
        .map_err(storage)?
        .insert(key, bytes(value)?.as_slice())
        .map_err(storage)?;
    Ok(())
}
fn save_head(tx: &redb::WriteTransaction, evidence: &RecordEvidence) -> Result<(), NodeCoreError> {
    let hash = record_hash(&evidence.record).map_err(storage)?;
    write(tx, RECORDS, &hash, evidence)?;
    write(tx, HEADS, evidence.record.account_anchor(), evidence)
}
fn clock(tx: &redb::WriteTransaction, now: u64) -> Result<u64, NodeCoreError> {
    if now > ramflux_protocol::MAX_SAFE_JSON_INTEGER {
        return Err(refusal(Refusal::CommitExpired));
    }
    let mut table = tx.open_table(CLOCK).map_err(storage)?;
    let old = table.get("floor").map_err(storage)?.map_or(0, |v| v.value());
    let now = now.max(old);
    table.insert("floor", now).map_err(storage)?;
    Ok(now)
}
fn map_for(authority: &VerifiedRecord) -> Result<Vec<DeliveryMapEntry>, NodeCoreError> {
    authority
        .envelope()
        .body
        .devices
        .iter()
        .filter(|d| d.status == ramflux_protocol::DeviceSetStatus::Active)
        .map(|d| {
            let device_ref = ramflux_protocol::custody::DeviceRef {
                account_anchor: authority.envelope().body.account_anchor.clone(),
                device_id: d.device_id.clone(),
                device_epoch: d.device_epoch,
            };
            Ok(DeliveryMapEntry {
                target_delivery_id: ramflux_protocol::qualified_device_id(
                    &device_ref.account_anchor,
                    &device_ref.device_id,
                )
                .map_err(storage)?,
                device_ref,
            })
        })
        .collect()
}
impl RouterRedbStore {
    /// Read durable migration state; restart recovery never infers it from a lost reply.
    /// # Errors
    /// Returns durable read/decode failures.
    pub fn migration_operation(
        &self,
        anchor: &str,
        id: &str,
        role: MigrationRole,
    ) -> Result<Option<MigrationOperation>, NodeCoreError> {
        let tx = self.migration_db().begin_read().map_err(storage)?;
        let table = match tx.open_table(OPS) {
            Ok(table) => table,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
            Err(e) => return Err(storage(e)),
        };
        table
            .get(op_key(anchor, id, role)?.as_str())
            .map_err(storage)?
            .map(|v| decode(v.value()))
            .transpose()
    }
    /// Current persisted home; callers authenticate history against their retained pin.
    /// # Errors
    /// Returns durable read/decode failures.
    pub fn migration_home(&self, anchor: &str) -> Result<Option<RecordEvidence>, NodeCoreError> {
        let tx = self.migration_db().begin_read().map_err(storage)?;
        let table = match tx.open_table(HEADS) {
            Ok(table) => table,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
            Err(e) => return Err(storage(e)),
        };
        table.get(anchor).map_err(storage)?.map(|v| decode(v.value())).transpose()
    }
}

fn commit_transition(
    store: &RouterRedbStore,
    tx: redb::WriteTransaction,
) -> Result<(), NodeCoreError> {
    #[cfg(test)]
    if store.fail_next_migration_commit.swap(false, std::sync::atomic::Ordering::SeqCst) {
        return Err(storage("injected migration commit failure"));
    }
    let _ = store;
    tx.commit().map_err(storage)
}

fn authorization_key(auth: &Signed<Authorization>) -> Result<String, NodeCoreError> {
    serde_json::to_string(&(&auth.body.account_anchor, message_hash(auth).map_err(storage)?))
        .map_err(storage)
}
