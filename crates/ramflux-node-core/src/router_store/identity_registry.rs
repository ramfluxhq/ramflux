// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Atomic identity admission deltas over the existing registry snapshot format.
use super::serialize_value;
use crate::mvp1_registry::registration::RegistrationDelta;
use crate::{
    IdentityRegistry, NodeCoreError, ROUTER_IDENTITY_REGISTRY_KEY, ROUTER_SESSION_ENTRY_TABLE,
    ROUTER_SNAPSHOT_TABLE, RouterRedbStore, SessionDescriptor,
};
use redb::ReadableTableMetadata;
use redb::{ReadableDatabase, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

const ADMISSIONS: TableDefinition<u64, &[u8]> =
    TableDefinition::new("router_identity_admission_v1");
const BUDGETS: TableDefinition<&str, &[u8]> = TableDefinition::new("router_registration_budget_v1");
const MAX_ADMISSIONS: u64 = 128;
const MAX_ADMISSION_BYTES: u64 = 4 * 1024 * 1024;
const JOURNAL_BYTES_KEY: &str = "identity_admission_bytes";
const SNAPSHOT_HASH_DOMAIN: &str = "ramflux.identity_admission.base_snapshot.v1";
const MISSING_SNAPSHOT_HASH_DOMAIN: &str = "ramflux.identity_admission.missing_snapshot.v1";

#[derive(Serialize, Deserialize)]
struct RegistrationJournalEntry {
    base_snapshot_hash: String,
    delta: RegistrationDelta,
}

fn error(error: impl std::fmt::Display) -> NodeCoreError {
    NodeCoreError::Redb(error.to_string())
}

fn snapshot_hash(snapshot: Option<&[u8]>) -> String {
    match snapshot {
        Some(snapshot) => ramflux_crypto::blake3_256_base64url(SNAPSHOT_HASH_DOMAIN, snapshot),
        None => ramflux_crypto::blake3_256_base64url(MISSING_SNAPSHOT_HASH_DOMAIN, b""),
    }
}

/// Every complete snapshot supersedes its delta prefix in the same transaction.
pub(super) fn checkpoint(
    txn: &redb::WriteTransaction,
    registry: &IdentityRegistry,
) -> Result<(), NodeCoreError> {
    let bytes = serialize_value(registry)?;
    let mut snapshots = txn.open_table(ROUTER_SNAPSHOT_TABLE).map_err(error)?;
    snapshots.insert(ROUTER_IDENTITY_REGISTRY_KEY, bytes.as_slice()).map_err(error)?;
    snapshots.insert(JOURNAL_BYTES_KEY, 0_u64.to_le_bytes().as_slice()).map_err(error)?;
    txn.open_table(ADMISSIONS).map_err(error)?.retain(|_, _| false).map_err(error)?;
    write_budgets(txn, registry)?;
    Ok(())
}
fn write_budgets(
    txn: &redb::WriteTransaction,
    registry: &IdentityRegistry,
) -> Result<(), NodeCoreError> {
    let mut budgets = txn.open_table(BUDGETS).map_err(error)?;
    budgets.retain(|_, _| false).map_err(error)?;
    for (key, value) in registry.registration_budgets() {
        budgets.insert(key.as_str(), serialize_value(value)?.as_slice()).map_err(error)?;
    }
    Ok(())
}
pub(super) fn initialize_budgets(
    db: &redb::Database,
    registry: &IdentityRegistry,
) -> Result<(), NodeCoreError> {
    let read = db.begin_read().map_err(error)?;
    match read.open_table(BUDGETS) {
        Ok(_) => return Ok(()),
        Err(redb::TableError::TableDoesNotExist(_)) => {}
        Err(e) => return Err(error(e)),
    }
    drop(read);
    let txn = db.begin_write().map_err(error)?;
    write_budgets(&txn, registry)?;
    txn.commit().map_err(error)
}
fn budget_delta(
    txn: &redb::WriteTransaction,
    delta: &RegistrationDelta,
    registry: &IdentityRegistry,
) -> Result<RegistrationDelta, NodeCoreError> {
    let mut table = txn.open_table(BUDGETS).map_err(error)?;
    let before: BTreeMap<String, Vec<i64>> = table
        .iter()
        .map_err(error)?
        .map(|row| {
            let (key, bytes) = row.map_err(error)?;
            Ok((key.value().to_owned(), serde_json::from_slice(bytes.value()).map_err(error)?))
        })
        .collect::<Result<_, NodeCoreError>>()?;
    let delta = delta.with_budget_changes(&before, registry);
    for (key, value) in &delta.source_budgets {
        if let Some(value) = value {
            table.insert(key.as_str(), serialize_value(value)?.as_slice()).map_err(error)?;
        } else {
            table.remove(key.as_str()).map_err(error)?;
        }
    }
    Ok(delta)
}
pub(super) fn replay(
    db: &redb::Database,
    registry: &mut IdentityRegistry,
) -> Result<(), NodeCoreError> {
    let txn = db.begin_read().map_err(error)?;
    let table = match txn.open_table(ADMISSIONS) {
        Ok(table) => table,
        Err(redb::TableError::TableDoesNotExist(_)) => return Ok(()),
        Err(e) => return Err(error(e)),
    };
    if table.is_empty().map_err(error)? {
        return Ok(());
    }
    let current_snapshot_hash = {
        let snapshots = txn.open_table(ROUTER_SNAPSHOT_TABLE).map_err(error)?;
        snapshots
            .get(ROUTER_IDENTITY_REGISTRY_KEY)
            .map_err(error)?
            .map_or_else(|| snapshot_hash(None), |bytes| snapshot_hash(Some(bytes.value())))
    };
    for row in table.iter().map_err(error)? {
        let (_, bytes) = row.map_err(error)?;
        let entry: RegistrationJournalEntry =
            serde_json::from_slice(bytes.value()).map_err(error)?;
        if entry.base_snapshot_hash != current_snapshot_hash {
            return Err(NodeCoreError::IdentityAdmissionJournalBaseMismatch {
                snapshot_hash: current_snapshot_hash,
                journal_hash: entry.base_snapshot_hash,
            });
        }
        entry.delta.apply(registry);
    }
    Ok(())
}
impl RouterRedbStore {
    /// Authority, replay receipt and session become durable together, before publication.
    pub(crate) fn record_registration_admission(
        &self,
        registry: &IdentityRegistry,
        delta: &RegistrationDelta,
        session: &SessionDescriptor,
    ) -> Result<(), NodeCoreError> {
        let session_bytes = serialize_value(session)?;
        let txn = self.db.begin_write().map_err(error)?;
        let delta = budget_delta(&txn, delta, registry)?;
        let base_snapshot_hash = {
            let snapshots = txn.open_table(ROUTER_SNAPSHOT_TABLE).map_err(error)?;
            snapshots
                .get(ROUTER_IDENTITY_REGISTRY_KEY)
                .map_err(error)?
                .map_or_else(|| snapshot_hash(None), |bytes| snapshot_hash(Some(bytes.value())))
        };
        let bytes = serialize_value(&RegistrationJournalEntry { base_snapshot_hash, delta })?;
        let journal_bytes = {
            let snapshots = txn.open_table(ROUTER_SNAPSHOT_TABLE).map_err(error)?;
            snapshots
                .get(JOURNAL_BYTES_KEY)
                .map_err(error)?
                .map(|value| {
                    <[u8; 8]>::try_from(value.value()).map(u64::from_le_bytes).map_err(error)
                })
                .transpose()?
                .unwrap_or(0)
        };
        let (count, last) = {
            let table = txn.open_table(ADMISSIONS).map_err(error)?;
            (
                table.len().map_err(error)?,
                table.last().map_err(error)?.map_or(0, |(key, _)| key.value()),
            )
        };
        let next_bytes =
            journal_bytes.saturating_add(u64::try_from(bytes.len()).unwrap_or(u64::MAX));
        if count + 1 >= MAX_ADMISSIONS || next_bytes >= MAX_ADMISSION_BYTES || last == u64::MAX {
            checkpoint(&txn, registry)?;
        } else {
            txn.open_table(ADMISSIONS)
                .map_err(error)?
                .insert(last + 1, bytes.as_slice())
                .map_err(error)?;
            txn.open_table(ROUTER_SNAPSHOT_TABLE)
                .map_err(error)?
                .insert(JOURNAL_BYTES_KEY, next_bytes.to_le_bytes().as_slice())
                .map_err(error)?;
        }
        txn.open_table(ROUTER_SESSION_ENTRY_TABLE)
            .map_err(error)?
            .insert(session.target_delivery_id.as_str(), session_bytes.as_slice())
            .map_err(error)?;
        #[cfg(test)]
        if self.fail_next_registration_admission.swap(false, std::sync::atomic::Ordering::Relaxed) {
            return Err(NodeCoreError::Redb(
                "injected registration admission store failure".to_owned(),
            ));
        }
        txn.commit().map_err(error)?;
        self.identity_registry_writes.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Ok(())
    }
}
