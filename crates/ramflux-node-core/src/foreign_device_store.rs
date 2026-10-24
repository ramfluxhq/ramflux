// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Per-root durable foreign authority observations; compact epoch fences are never evicted.
use crate::{
    NodeCoreError,
    foreign_device_heads::{EpochFence, ForeignDeviceHeads, HeadObservation},
};
use ramflux_protocol::SignedDeviceSetRecord;
use redb::{ReadableDatabase, ReadableTable, ReadableTableMetadata, TableDefinition};

#[derive(Clone, Copy)]
pub(crate) enum Namespace {
    Router,
    Federation,
}
impl Namespace {
    fn tables(
        self,
    ) -> (
        TableDefinition<'static, &'static str, &'static [u8]>,
        TableDefinition<'static, &'static str, &'static [u8]>,
    ) {
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
    fn name(self) -> &'static str {
        match self {
            Self::Router => "router",
            Self::Federation => "federation",
        }
    }
}
const MIGRATED: TableDefinition<&str, u8> = TableDefinition::new("foreign_set_fence_migration_v1");
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
fn import(
    heads: &mut ForeignDeviceHeads,
    record: &SignedDeviceSetRecord,
) -> Result<(), NodeCoreError> {
    if heads
        .fences
        .get(&record.principal_commitment)
        .is_some_and(|old| old.epoch > record.device_set_epoch)
    {
        return Ok(());
    }
    heads.observe(record)?;
    Ok(())
}
pub(crate) fn initialize(
    db: &redb::Database,
    namespace: Namespace,
    legacy: Option<&ForeignDeviceHeads>,
) -> Result<(), NodeCoreError> {
    const OLD_HEADS: TableDefinition<&str, &[u8]> =
        TableDefinition::new("federated_source_device_sets_v1");
    const OLD_CACHE: TableDefinition<&str, &[u8]> =
        TableDefinition::new("bounded_foreign_device_heads_v1");
    let txn = db.begin_write().map_err(error)?;
    let mut migrated = txn.open_table(MIGRATED).map_err(error)?;
    if migrated.get(namespace.name()).map_err(error)?.is_some() {
        return Ok(());
    }
    let mut heads = ForeignDeviceHeads::default();
    if let Some(legacy) = legacy {
        for record in &legacy.records {
            import(&mut heads, record)?;
        }
        for (root, fence) in &legacy.fences {
            if let Some(old) = heads.fences.get(root) {
                old.check(*fence)?;
            }
            heads.fences.insert(root.clone(), *fence);
        }
    }
    if matches!(namespace, Namespace::Federation) {
        let old = txn.open_table(OLD_HEADS).map_err(error)?;
        for entry in old.iter().map_err(error)? {
            let (_, row) = entry.map_err(error)?;
            import(
                &mut heads,
                &serde_json::from_slice(row.value())
                    .map_err(|e| NodeCoreError::ItestJson(e.to_string()))?,
            )?;
        }
        drop(old);
        let old = txn.open_table(OLD_CACHE).map_err(error)?;
        if let Some(row) = old.get("heads").map_err(error)? {
            let legacy: ForeignDeviceHeads = serde_json::from_slice(row.value())
                .map_err(|e| NodeCoreError::ItestJson(e.to_string()))?;
            for record in &legacy.records {
                import(&mut heads, record)?;
            }
        }
        drop(old);
        txn.delete_table(OLD_HEADS).map_err(error)?;
        txn.delete_table(OLD_CACHE).map_err(error)?;
    }
    let (fence_table, set_table) = namespace.tables();
    let mut fences = txn.open_table(fence_table).map_err(error)?;
    let mut sets = txn.open_table(set_table).map_err(error)?;
    for (root, fence) in &heads.fences {
        let bytes = encode(*fence);
        fences.insert(root.as_str(), bytes.as_slice()).map_err(error)?;
    }
    for record in &heads.records {
        let bytes =
            serde_json::to_vec(record).map_err(|e| NodeCoreError::ItestJson(e.to_string()))?;
        sets.insert(record.principal_commitment.as_str(), bytes.as_slice()).map_err(error)?;
    }
    migrated.insert(namespace.name(), 1).map_err(error)?;
    drop(fences);
    drop(sets);
    drop(migrated);
    txn.commit().map_err(error)
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
    let (fence_table, set_table) = namespace.tables();
    let txn = db.begin_write().map_err(error)?;
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
    txn.commit().map_err(error)?;
    Ok(observation)
}
