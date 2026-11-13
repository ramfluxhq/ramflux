// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Refuse retired notify storage before starting its commit writer or opening the WAL.
use super::{
    NOTIFY_PROVIDER_ATTEMPT_TABLE, NOTIFY_QUEUE_ENTRY_TABLE, NOTIFY_QUEUE_KEY, NOTIFY_QUEUE_TABLE,
    NodeCoreError, deserialize_notify_bounded_snapshot, deserialize_notify_provider_attempt,
    deserialize_notify_queue_entry,
};
use redb::{ReadableDatabase, ReadableTable, TableDefinition};

fn error(value: impl std::fmt::Display) -> NodeCoreError {
    NodeCoreError::Redb(value.to_string())
}

pub(super) fn validate_store(db: &redb::Database) -> Result<(), NodeCoreError> {
    let txn = db.begin_read().map_err(error)?;
    let old_fences: TableDefinition<&str, u64> = TableDefinition::new("notify_route_fence_v1");
    match txn.open_table(old_fences) {
        Ok(_) | Err(redb::TableError::TableTypeMismatch { .. }) => {
            return Err(NodeCoreError::UnsupportedPersistedFormat("notify route fence v1"));
        }
        Err(redb::TableError::TableDoesNotExist(_)) => {}
        Err(source) => return Err(error(source)),
    }
    match txn.open_table(NOTIFY_QUEUE_TABLE) {
        Ok(snapshots) => {
            if let Some(value) = snapshots.get(NOTIFY_QUEUE_KEY).map_err(error)? {
                deserialize_notify_bounded_snapshot(value.value())?;
            }
        }
        Err(redb::TableError::TableDoesNotExist(_)) => {}
        Err(source) => return Err(error(source)),
    }
    match txn.open_table(NOTIFY_QUEUE_ENTRY_TABLE) {
        Ok(table) => {
            for row in table.iter().map_err(error)? {
                let (_, value) = row.map_err(error)?;
                deserialize_notify_queue_entry(value.value())?;
            }
        }
        Err(redb::TableError::TableDoesNotExist(_)) => {}
        Err(source) => return Err(error(source)),
    }
    match txn.open_table(NOTIFY_PROVIDER_ATTEMPT_TABLE) {
        Ok(table) => {
            for row in table.iter().map_err(error)? {
                let (_, value) = row.map_err(error)?;
                deserialize_notify_provider_attempt(value.value())?;
            }
        }
        Err(redb::TableError::TableDoesNotExist(_)) => {}
        Err(source) => return Err(error(source)),
    }
    Ok(())
}
