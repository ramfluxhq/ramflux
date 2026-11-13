// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Disk-authoritative replay admission; no identity or membership map is loaded at startup.
use super::{GatewayRedbStore, GatewayReplayConfig, GatewayStoreWriter, replay_gc};
use crate::{NodeCoreError, serialize_snapshot_value};
use redb::{ReadableDatabase, ReadableTable, ReadableTableMetadata, TableDefinition};
use serde::{Deserialize, Serialize};

pub(super) const REPLAY: TableDefinition<&str, &[u8]> =
    TableDefinition::new("gateway_replay_entries_v3");
pub(super) const EXPIRY: TableDefinition<(i64, &str), u8> =
    TableDefinition::new("gateway_replay_expiry_v3");
pub(super) const ROOTS: TableDefinition<&str, &[u8]> =
    TableDefinition::new("gateway_replay_roots_v3");
pub(super) const ROOT_EXPIRY: TableDefinition<(i64, &str), u64> =
    TableDefinition::new("gateway_replay_root_expiry_v3");
pub(super) const OWN_EXPIRY: TableDefinition<(&str, u64, i64, &str), u8> =
    TableDefinition::new("gateway_replay_owner_expiry_v3");
const META: TableDefinition<&str, u64> = TableDefinition::new("gateway_replay_metadata_v3");

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ReplayEntry {
    pub owner: String,
    pub expiry: i64,
    pub generation: u64,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RootReservation {
    pub generation: u64,
    pub count: u64,
    pub latest_expiry: i64,
}
pub(super) fn decode_entry(bytes: &[u8]) -> Result<ReplayEntry, NodeCoreError> {
    if bytes.len() > 256 {
        return Err(NodeCoreError::PreAuthSnapshotInvalid);
    }
    serde_json::from_slice(bytes).map_err(|_| NodeCoreError::PreAuthSnapshotInvalid)
}
pub(super) fn decode_root(bytes: &[u8]) -> Result<RootReservation, NodeCoreError> {
    if bytes.len() > 256 {
        return Err(NodeCoreError::PreAuthSnapshotInvalid);
    }
    let root: RootReservation =
        serde_json::from_slice(bytes).map_err(|_| NodeCoreError::PreAuthSnapshotInvalid)?;
    if root.count == 0 || root.generation == 0 {
        return Err(NodeCoreError::PreAuthSnapshotInvalid);
    }
    Ok(root)
}
fn fence(write: &redb::WriteTransaction, now: i64) -> Result<(), NodeCoreError> {
    let now = u64::try_from(now).map_err(|_| NodeCoreError::PreAuthClockInvalid)?;
    let mut meta = write.open_table(META).map_err(error)?;
    if meta.get("fenced_now").map_err(error)?.is_some_and(|old| old.value() > now) {
        return Err(NodeCoreError::PreAuthClockRollback);
    }
    meta.insert("fenced_now", now).map_err(error)?;
    Ok(())
}

impl GatewayRedbStore {
    /// Fund the configured allocation and reconcile expired root leases before serving signed work.
    /// # Errors
    /// Refuses unfunded budgets, reductions of existing shares, rollback and storage failures.
    pub fn configure_replay(
        &self,
        config: GatewayReplayConfig,
        now: i64,
    ) -> Result<(), NodeCoreError> {
        config.require_funded(&self.path)?;
        let _writer = self.write_guard()?;
        loop {
            let write = self.db.begin_write().map_err(error)?;
            fence(&write, now)?;
            replay_gc::prune(&write, now, 64, None)?;
            write.commit().map_err(error)?;
            let pending = {
                let read = self.db.begin_read().map_err(error)?;
                let index = read.open_table(ROOT_EXPIRY).map_err(error)?;
                index
                    .iter()
                    .map_err(error)?
                    .next()
                    .transpose()
                    .map_err(error)?
                    .is_some_and(|(key, _)| key.value().0 < now)
            };
            if !pending {
                break;
            }
        }
        let write = self.db.begin_write().map_err(error)?;
        {
            let roots = write.open_table(ROOTS).map_err(error)?.len().map_err(error)?;
            let mut meta = write.open_table(META).map_err(error)?;
            let old_share = meta.get("share").map_err(error)?.map_or(0, |raw| raw.value());
            if roots > config.root_budget || (roots > 0 && config.per_root_share < old_share) {
                return Err(config.unfunded(fs2::available_space(&self.path).unwrap_or(0)));
            }
            meta.insert("share", config.per_root_share).map_err(error)?;
            meta.insert("root_budget", config.root_budget).map_err(error)?;
        }
        write.commit().map_err(error)?;
        *self.replay_config.lock().map_err(error)? = Some(config);
        Ok(())
    }
    /// Persist already authenticated signed work before acknowledging it.
    /// # Errors
    /// Refuses replay, unfunded/full allocations, rollback and failed commits.
    pub fn save_auth_replay(
        &self,
        source: &ramflux_crypto::RootQualifiedDeviceRef,
        request: &ramflux_protocol::SignedRequest,
        now: i64,
    ) -> Result<(), NodeCoreError> {
        self.write_guard()?.save_auth_replay(source, request, now)
    }
    pub(super) fn save_auth_replay_unlocked(
        &self,
        source: &ramflux_crypto::RootQualifiedDeviceRef,
        request: &ramflux_protocol::SignedRequest,
        now: i64,
    ) -> Result<(), NodeCoreError> {
        let config = self
            .replay_config
            .lock()
            .map_err(error)?
            .ok_or_else(|| GatewayReplayConfig::default().unfunded(0))?;
        ramflux_protocol::ReplayGuard::new()
            .check_signed_request(source, request, now)
            .map_err(|error| NodeCoreError::ReplayGuard(error.to_string()))?;
        let key = request
            .replay_tuple_key(source)
            .map_err(|error| NodeCoreError::ReplayGuard(error.to_string()))?;
        if key.len() != 54 || source.root_commitment().len() != 43 {
            return Err(NodeCoreError::PreAuthSnapshotInvalid);
        }
        let write = self.db.begin_write().map_err(error)?;
        fence(&write, now)?;
        // Reserve two expiry candidates for the owner's lease and a renewed incoming identity.
        replay_gc::prune(&write, now, 62, Some(source.root_commitment()))?;
        {
            let mut entries = write.open_table(REPLAY).map_err(error)?;
            let mut expiry = write.open_table(EXPIRY).map_err(error)?;
            let mut own_expiry = write.open_table(OWN_EXPIRY).map_err(error)?;
            let previous = entries
                .get(key.as_str())
                .map_err(error)?
                .map(|raw| decode_entry(raw.value()))
                .transpose()?;
            if previous
                .as_ref()
                .is_some_and(|entry| entry.expiry >= now || entry.owner != source.root_commitment())
            {
                return Err(NodeCoreError::ReplayGuard("signed request replay".into()));
            }
            let mut roots = write.open_table(ROOTS).map_err(error)?;
            let mut root_expiry = write.open_table(ROOT_EXPIRY).map_err(error)?;
            let mut root = roots
                .get(source.root_commitment())
                .map_err(error)?
                .map(|raw| decode_root(raw.value()))
                .transpose()?;
            // The owner lease consumes one of the two reserved expiry candidates.
            if let Some(old) = root.as_ref().filter(|root| root.latest_expiry < now) {
                roots.remove(source.root_commitment()).map_err(error)?;
                root_expiry.remove((old.latest_expiry, source.root_commitment())).map_err(error)?;
                root = None;
            }
            let mut root = if let Some(root) = root {
                root
            } else {
                allocate_root(&write, config, roots.len().map_err(error)?, request.expires_at)?
            };
            if let Some(previous) = previous {
                expiry.remove((previous.expiry, key.as_str())).map_err(error)?;
                own_expiry
                    .remove((
                        previous.owner.as_str(),
                        previous.generation,
                        previous.expiry,
                        key.as_str(),
                    ))
                    .map_err(error)?;
                if previous.generation == root.generation {
                    root.count =
                        root.count.checked_sub(1).ok_or(NodeCoreError::PreAuthSnapshotInvalid)?;
                }
            }
            if root.count >= config.per_root_share {
                return Err(NodeCoreError::GatewayReplayCapacity);
            }
            root_expiry.remove((root.latest_expiry, source.root_commitment())).map_err(error)?;
            root.count = root.count.checked_add(1).ok_or(NodeCoreError::GatewayReplayCapacity)?;
            root.latest_expiry = root.latest_expiry.max(request.expires_at);
            roots
                .insert(source.root_commitment(), serialize_snapshot_value(&root)?.as_slice())
                .map_err(error)?;
            root_expiry
                .insert((root.latest_expiry, source.root_commitment()), root.generation)
                .map_err(error)?;
            let entry = ReplayEntry {
                owner: source.root_commitment().to_owned(),
                expiry: request.expires_at,
                generation: root.generation,
            };
            entries
                .insert(key.as_str(), serialize_snapshot_value(&entry)?.as_slice())
                .map_err(error)?;
            expiry.insert((request.expires_at, key.as_str()), 0).map_err(error)?;
            own_expiry
                .insert(
                    (source.root_commitment(), root.generation, request.expires_at, key.as_str()),
                    0,
                )
                .map_err(error)?;
        }
        #[cfg(any(test, feature = "durability-test-hooks"))]
        self.before_admission_commit()?;
        write.commit().map_err(error)?;
        #[cfg(any(test, feature = "durability-test-hooks"))]
        self.record_incremental_commit();
        Ok(())
    }
    pub(super) fn has_replay_entries(&self) -> Result<bool, NodeCoreError> {
        let read = self.db.begin_read().map_err(error)?;
        Ok(!read.open_table(REPLAY).map_err(error)?.is_empty().map_err(error)?)
    }
    pub(super) fn prune_replay_unlocked(&self, now: i64) -> Result<(), NodeCoreError> {
        let write = self.db.begin_write().map_err(error)?;
        fence(&write, now)?;
        replay_gc::prune(&write, now, 64, None)?;
        write.commit().map_err(error)
    }
}
fn allocate_root(
    write: &redb::WriteTransaction,
    config: GatewayReplayConfig,
    existing_roots: u64,
    expiry: i64,
) -> Result<RootReservation, NodeCoreError> {
    if existing_roots >= config.root_budget {
        return Err(NodeCoreError::GatewayReplayCapacity);
    }
    let mut meta = write.open_table(META).map_err(error)?;
    let generation = meta
        .get("generation")
        .map_err(error)?
        .map_or(0, |raw| raw.value())
        .checked_add(1)
        .ok_or(NodeCoreError::GatewayReplayCapacity)?;
    meta.insert("generation", generation).map_err(error)?;
    Ok(RootReservation { generation, count: 0, latest_expiry: expiry })
}

impl GatewayStoreWriter<'_> {
    /// Verify root binding and signatures, then atomically admit the durable replay identity.
    /// # Errors
    /// Refuses invalid signatures, replay/capacity, rollback and failed commits.
    pub fn authenticate_gateway(
        &self,
        open: &crate::GatewayOpenFrame,
        auth: &crate::GatewayAuthFrame,
        registered: &crate::DeviceAuthKeyResponse,
        now: i64,
    ) -> Result<ramflux_crypto::RootQualifiedDeviceRef, NodeCoreError> {
        let source = crate::validate_gateway_auth_source(open, auth, now, registered)?;
        self.save_auth_replay(&source, &auth.signed_request, now)?;
        Ok(source)
    }
    /// Bound replay cleanup independently of the total evidence count.
    /// # Errors
    /// Refuses rollback and storage failures.
    pub fn prune_replay(&self, now: i64) -> Result<(), NodeCoreError> {
        self.store.prune_replay_unlocked(now)
    }
}
fn error(error: impl std::fmt::Display) -> NodeCoreError {
    NodeCoreError::Redb(error.to_string())
}
pub(super) fn initialize_tables(write: &redb::WriteTransaction) -> Result<(), NodeCoreError> {
    write.open_table(REPLAY).map_err(error)?;
    write.open_table(EXPIRY).map_err(error)?;
    write.open_table(ROOTS).map_err(error)?;
    write.open_table(ROOT_EXPIRY).map_err(error)?;
    write.open_table(OWN_EXPIRY).map_err(error)?;
    write.open_table(META).map_err(error)?;
    Ok(())
}
#[cfg(test)]
#[path = "gateway_replay_journal_tests.rs"]
mod tests;
