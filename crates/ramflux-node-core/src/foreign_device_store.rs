// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Per-root durable foreign authority observations; compact epoch fences are never evicted.
use crate::{
    NodeCoreError,
    foreign_device_heads::{EpochFence, ForeignDeviceHeads, HeadObservation},
};
use ramflux_protocol::SignedDeviceSetRecord;
use redb::{ReadableDatabase, ReadableTable, ReadableTableMetadata, TableDefinition};

type ForeignTable = TableDefinition<'static, &'static str, &'static [u8]>;

#[derive(Clone, Copy)]
pub(crate) enum Namespace {
    Router,
    Federation,
}
impl Namespace {
    fn tables(self) -> (ForeignTable, ForeignTable) {
        match self {
            Self::Router => (
                TableDefinition::new("router_foreign_set_fences_v1"),
                TableDefinition::new("router_foreign_full_sets_v1"),
            ),
            Self::Federation => (
                TableDefinition::new("federation_foreign_set_fences_v1"),
                TableDefinition::new("federation_foreign_full_sets_v1"),
            ),
        }
    }
}

fn error(error: impl std::fmt::Display) -> NodeCoreError {
    NodeCoreError::Redb(error.to_string())
}
fn encode(fence: EpochFence) -> [u8; 40] {
    let mut bytes = [0; 40];
    bytes[..8].copy_from_slice(&fence.epoch.to_be_bytes());
    bytes[8..].copy_from_slice(&fence.hash);
    bytes
}
fn decode(bytes: &[u8]) -> Result<EpochFence, NodeCoreError> {
    let raw: [u8; 40] =
        bytes.try_into().map_err(|_| NodeCoreError::Redb("invalid foreign epoch fence".into()))?;
    let mut epoch = [0; 8];
    epoch.copy_from_slice(&raw[..8]);
    let mut hash = [0; 32];
    hash.copy_from_slice(&raw[8..]);
    Ok(EpochFence { epoch: u64::from_be_bytes(epoch), hash })
}
pub(crate) fn validate(db: &redb::Database) -> Result<(), NodeCoreError> {
    // Only current per-root tables are accepted. Old snapshot data is never imported.
    let read = db.begin_read().map_err(error)?;
    for name in ["federated_source_device_sets_v1", "bounded_foreign_device_heads_v1"] {
        match read.open_table(TableDefinition::<&str, &[u8]>::new(name)) {
            Ok(_) | Err(redb::TableError::TableTypeMismatch { .. }) => {
                return Err(NodeCoreError::UnsupportedPersistedFormat("foreign authority store"));
            }
            Err(redb::TableError::TableDoesNotExist(_)) => {}
            Err(error) => return Err(self::error(error)),
        }
    }
    for namespace in [Namespace::Router, Namespace::Federation] {
        let (fences, sets) = namespace.tables();
        match read.open_table(fences) {
            Ok(table) => {
                for row in table.iter().map_err(error)? {
                    let (_, value) = row.map_err(error)?;
                    decode(value.value())?;
                }
            }
            Err(redb::TableError::TableDoesNotExist(_)) => {}
            Err(source) => return Err(error(source)),
        }
        match read.open_table(sets) {
            Ok(table) => {
                for row in table.iter().map_err(error)? {
                    let (_, value) = row.map_err(error)?;
                    let _: SignedDeviceSetRecord =
                        serde_json::from_slice(value.value()).map_err(error)?;
                }
            }
            Err(redb::TableError::TableDoesNotExist(_)) => {}
            Err(source) => return Err(error(source)),
        }
    }
    Ok(())
}
pub(crate) fn initialize(db: &redb::Database, namespace: Namespace) -> Result<(), NodeCoreError> {
    validate(db)?;
    let txn = crate::fatal_durability::run(|| db.begin_write().map_err(error))?;
    let _panic = crate::fatal_durability::UnwindGuard;
    let (fences, sets) = namespace.tables();
    txn.open_table(fences).map_err(error)?;
    txn.open_table(sets).map_err(error)?;
    crate::fatal_durability::run(|| txn.commit().map_err(error))
}
pub(crate) fn load(
    db: &redb::Database,
    namespace: Namespace,
) -> Result<ForeignDeviceHeads, NodeCoreError> {
    let (fence_table, set_table) = namespace.tables();
    let txn = db.begin_read().map_err(error)?;
    let fences = txn.open_table(fence_table).map_err(error)?;
    let sets = txn.open_table(set_table).map_err(error)?;
    let mut heads = ForeignDeviceHeads::default();
    for entry in fences.iter().map_err(error)? {
        let (root, value) = entry.map_err(error)?;
        heads.fences.insert(root.value().to_owned(), decode(value.value())?);
    }
    for entry in sets.iter().map_err(error)? {
        let (_, value) = entry.map_err(error)?;
        heads.records.push_back(
            serde_json::from_slice(value.value())
                .map_err(|e| NodeCoreError::ItestJson(e.to_string()))?,
        );
    }
    Ok(heads)
}
pub(crate) fn observe(
    db: &redb::Database,
    namespace: Namespace,
    record: &SignedDeviceSetRecord,
) -> Result<HeadObservation, NodeCoreError> {
    observe_inner(db, namespace, record, None)
}
pub(crate) fn observe_for_peer(
    db: &redb::Database,
    record: &SignedDeviceSetRecord,
    peer: &str,
    now: u64,
) -> Result<HeadObservation, NodeCoreError> {
    observe_inner(db, Namespace::Federation, record, Some((peer, now)))
}
fn observe_inner(
    db: &redb::Database,
    namespace: Namespace,
    record: &SignedDeviceSetRecord,
    peer: Option<(&str, u64)>,
) -> Result<HeadObservation, NodeCoreError> {
    let (fence_table, set_table) = namespace.tables();
    let txn = crate::fatal_durability::run(|| db.begin_write().map_err(error))?;
    let _panic = crate::fatal_durability::UnwindGuard;
    let mut fences = txn.open_table(fence_table).map_err(error)?;
    let mut sets = txn.open_table(set_table).map_err(error)?;
    let root = record.principal_commitment.as_str();
    let old_fence = fences.get(root).map_err(error)?.map(|r| decode(r.value())).transpose()?;
    let old_set: Option<SignedDeviceSetRecord> = sets
        .get(root)
        .map_err(error)?
        .map(|r| serde_json::from_slice(r.value()))
        .transpose()
        .map_err(|e| NodeCoreError::ItestJson(e.to_string()))?;
    let count = usize::try_from(sets.len().map_err(error)?).map_err(error)?;
    let observation = ForeignDeviceHeads::inspect(record, old_fence, old_set.as_ref(), count)?;
    if !observation.changed() {
        return Ok(observation);
    }
    if old_fence.is_none()
        && let Some((peer, now)) = peer
    {
        charge_peer_new_root(&txn, peer, now)?;
    }
    if observation.fence_changed {
        let bytes = encode(observation.fence);
        fences.insert(root, bytes.as_slice()).map_err(error)?;
    }
    if observation.set_changed {
        let bytes =
            serde_json::to_vec(record).map_err(|e| NodeCoreError::ItestJson(e.to_string()))?;
        sets.insert(root, bytes.as_slice()).map_err(error)?;
    }
    drop(fences);
    drop(sets);
    crate::fatal_durability::run(|| txn.commit().map_err(error))?;
    Ok(observation)
}

/// Explicit checkpoint import also preserves roots refused full-set admission.
pub(crate) fn save_fences(
    db: &redb::Database,
    namespace: Namespace,
    heads: &ForeignDeviceHeads,
) -> Result<(), NodeCoreError> {
    let (table, _) = namespace.tables();
    let txn = crate::fatal_durability::run(|| db.begin_write().map_err(error))?;
    let _panic = crate::fatal_durability::UnwindGuard;
    let mut fences = txn.open_table(table).map_err(error)?;
    let mut changed = false;
    for (root, next) in &heads.fences {
        let previous =
            fences.get(root.as_str()).map_err(error)?.map(|r| decode(r.value())).transpose()?;
        if let Some(previous) = previous {
            previous.check(*next)?;
        }
        if previous != Some(*next) {
            fences.insert(root.as_str(), encode(*next).as_slice()).map_err(error)?;
            changed = true;
        }
    }
    drop(fences);
    if changed {
        crate::fatal_durability::run(|| txn.commit().map_err(error))?;
    }
    Ok(())
}

// Checked and committed in the same write transaction as the first permanent fence.
fn charge_peer_new_root(
    txn: &redb::WriteTransaction,
    peer: &str,
    now: u64,
) -> Result<(), NodeCoreError> {
    const TABLE: TableDefinition<&str, &[u8]> =
        TableDefinition::new("federation_new_root_budget_v1");
    let mut table = txn.open_table(TABLE).map_err(error)?;
    let previous: Option<(u64, u64)> = table
        .get(peer)
        .map_err(error)?
        .map(|r| serde_json::from_slice(r.value()))
        .transpose()
        .map_err(error)?;
    let (start, count) =
        previous.filter(|(start, _)| now.saturating_sub(*start) < 60).unwrap_or((now, 0));
    if count >= 64 {
        return Err(NodeCoreError::Capacity { resource: "foreign_roots_per_peer" });
    }
    if previous.is_none() && table.len().map_err(error)? >= 4096 {
        let mut expired = Vec::new();
        for row in table.iter().map_err(error)? {
            let (key, value) = row.map_err(error)?;
            let (start, _): (u64, u64) = serde_json::from_slice(value.value()).map_err(error)?;
            if now.saturating_sub(start) >= 60 {
                expired.push(key.value().to_owned());
            }
        }
        for key in expired {
            table.remove(key.as_str()).map_err(error)?;
        }
        if table.len().map_err(error)? >= 4096 {
            return Err(NodeCoreError::Capacity { resource: "federation_peer_budgets" });
        }
    }
    let bytes = serde_json::to_vec(&(start, count + 1)).map_err(error)?;
    table.insert(peer, bytes.as_slice()).map_err(error)?;
    Ok(())
}

#[cfg(test)]
#[path = "foreign_device_store_tests.rs"]
mod format_guards;
