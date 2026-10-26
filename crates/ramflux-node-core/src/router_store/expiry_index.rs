// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Deadline-ordered indexes let retention visit only due mailbox and replay rows.
//!
//! Mailbox rows store the server-assigned retention deadline next to the entry. Index keys
//! start with the zero-padded deadline, so a sweep is a prefix range scan up to `now`.
use super::{InboxEntry, NodeCoreError, ROUTER_INBOX_ENTRY_TABLE, ROUTER_REPLAY_TUPLE_TABLE};
use redb::{ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};

const INBOX_EXPIRY: TableDefinition<&str, &[u8]> = TableDefinition::new("router_inbox_expiry_v1");
const REPLAY_EXPIRY: TableDefinition<&str, &[u8]> = TableDefinition::new("router_replay_expiry_v1");
const FORMAT: TableDefinition<&str, u8> = TableDefinition::new("router_expiry_index_format_v1");
/// Deadlines computed once for WAL records written before acceptance times were logged.
const LEGACY_WAL_DEADLINES: TableDefinition<&str, i64> =
    TableDefinition::new("router_legacy_wal_deadlines_v1");

/// Durable mailbox row: the entry plus the deadline assigned when the router accepted it.
#[derive(Deserialize, Serialize)]
struct StoredInboxEntry {
    #[serde(flatten)]
    entry: InboxEntry,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    retain_until: Option<i64>,
}

fn db_error(error: impl std::fmt::Display) -> NodeCoreError {
    NodeCoreError::Redb(error.to_string())
}

fn deadline_prefix(deadline: i64) -> String {
    format!("{:020}", u64::try_from(deadline).unwrap_or(0))
}

fn index_key(deadline: i64, row_key: &str) -> String {
    format!("{}/{row_key}", deadline_prefix(deadline))
}

pub(super) fn encode_entry(
    entry: &InboxEntry,
    retain_until: i64,
) -> Result<Vec<u8>, NodeCoreError> {
    serde_json::to_vec(&StoredInboxEntry { entry: entry.clone(), retain_until: Some(retain_until) })
        .map_err(|error| NodeCoreError::SnapshotSerialization(error.to_string()))
}

/// Decodes a mailbox row; rows written before deadlines were stored use the envelope expiry.
pub(super) fn decode_entry(bytes: &[u8]) -> Result<(InboxEntry, i64), NodeCoreError> {
    let stored: StoredInboxEntry = serde_json::from_slice(bytes)
        .map_err(|error| NodeCoreError::SnapshotSerialization(error.to_string()))?;
    let deadline = stored.retain_until.unwrap_or_else(|| {
        crate::inbox_legacy_retain_until(
            &stored.entry.envelope,
            i64::try_from(crate::now_unix_seconds()).unwrap_or(i64::MAX),
        )
    });
    Ok((stored.entry, deadline))
}

fn has_stored_deadline(bytes: &[u8]) -> Result<bool, NodeCoreError> {
    let stored: StoredInboxEntry = serde_json::from_slice(bytes)
        .map_err(|error| NodeCoreError::SnapshotSerialization(error.to_string()))?;
    Ok(stored.retain_until.is_some())
}

pub(super) fn index_inbox_row(
    txn: &redb::WriteTransaction,
    row_key: &str,
    deadline: i64,
) -> Result<(), NodeCoreError> {
    txn.open_table(INBOX_EXPIRY)
        .map_err(db_error)?
        .insert(index_key(deadline, row_key).as_str(), [].as_slice())
        .map_err(db_error)?;
    Ok(())
}

/// Removes a mailbox row and its index key; returns whether a row existed.
pub(super) fn remove_inbox_row(
    txn: &redb::WriteTransaction,
    row_key: &str,
) -> Result<bool, NodeCoreError> {
    let mut rows = txn.open_table(ROUTER_INBOX_ENTRY_TABLE).map_err(db_error)?;
    let Some(bytes) = rows.remove(row_key).map_err(db_error)?.map(|value| value.value().to_vec())
    else {
        return Ok(false);
    };
    if let Ok((_entry, deadline)) = decode_entry(&bytes) {
        txn.open_table(INBOX_EXPIRY)
            .map_err(db_error)?
            .remove(index_key(deadline, row_key).as_str())
            .map_err(db_error)?;
    }
    Ok(true)
}

pub(super) fn index_replay_row(
    txn: &redb::WriteTransaction,
    replay_key: &str,
    expires_at: i64,
) -> Result<(), NodeCoreError> {
    txn.open_table(REPLAY_EXPIRY)
        .map_err(db_error)?
        .insert(index_key(expires_at, replay_key).as_str(), [].as_slice())
        .map_err(db_error)?;
    Ok(())
}

/// Index format 2 stores a fixed deadline in every mailbox row.
const FORMAT_VERSION: u8 = 2;

/// One-time migration for databases written before the indexes or stored deadlines existed.
/// Rows without a deadline get `min(created_at, now) + 7 d` (capped by the envelope expiry)
/// written into the row, so a far-future row from an older build still expires.
pub(super) fn upgrade(txn: &redb::WriteTransaction) -> Result<(), NodeCoreError> {
    let mut format = txn.open_table(FORMAT).map_err(db_error)?;
    let version = format.get("version").map_err(db_error)?.map(|value| value.value());
    if version.is_some_and(|version| version >= FORMAT_VERSION) {
        return Ok(());
    }
    let migrated_at = i64::try_from(crate::now_unix_seconds()).unwrap_or(i64::MAX);
    let mut rewrites = Vec::new();
    let mut inbox_index = Vec::new();
    for row in
        txn.open_table(ROUTER_INBOX_ENTRY_TABLE).map_err(db_error)?.iter().map_err(db_error)?
    {
        let (key, value) = row.map_err(db_error)?;
        let deadline = if has_stored_deadline(value.value())? {
            decode_entry(value.value())?.1
        } else {
            let (entry, _) = decode_entry(value.value())?;
            let deadline = crate::inbox_legacy_retain_until(&entry.envelope, migrated_at);
            rewrites.push((key.value().to_owned(), encode_entry(&entry, deadline)?));
            deadline
        };
        inbox_index.push(index_key(deadline, key.value()));
    }
    let mut replay_index = Vec::new();
    for row in
        txn.open_table(ROUTER_REPLAY_TUPLE_TABLE).map_err(db_error)?.iter().map_err(db_error)?
    {
        let (key, value) = row.map_err(db_error)?;
        let expires_at: i64 = serde_json::from_slice(value.value())
            .map_err(|error| NodeCoreError::SnapshotSerialization(error.to_string()))?;
        replay_index.push(index_key(expires_at, key.value()));
    }
    let mut rows = txn.open_table(ROUTER_INBOX_ENTRY_TABLE).map_err(db_error)?;
    for (key, bytes) in rewrites {
        rows.insert(key.as_str(), bytes.as_slice()).map_err(db_error)?;
    }
    drop(rows);
    clear(txn)?;
    let mut table = txn.open_table(INBOX_EXPIRY).map_err(db_error)?;
    for key in inbox_index {
        table.insert(key.as_str(), [].as_slice()).map_err(db_error)?;
    }
    let mut table = txn.open_table(REPLAY_EXPIRY).map_err(db_error)?;
    for key in replay_index {
        table.insert(key.as_str(), [].as_slice()).map_err(db_error)?;
    }
    format.insert("version", FORMAT_VERSION).map_err(db_error)?;
    Ok(())
}

/// Returns the persisted deadline of each legacy WAL record, storing `computed` the first
/// time a record is seen. Rows for records no longer in the WAL are removed.
pub(super) fn resolve_legacy_wal_deadlines(
    db: &redb::Database,
    records: &[(String, i64)],
) -> Result<std::collections::BTreeMap<String, i64>, NodeCoreError> {
    let txn = db.begin_write().map_err(db_error)?;
    let mut resolved = std::collections::BTreeMap::new();
    {
        let mut table = txn.open_table(LEGACY_WAL_DEADLINES).map_err(db_error)?;
        let stale = table
            .iter()
            .map_err(db_error)?
            .map(|row| row.map(|(key, _)| key.value().to_owned()).map_err(db_error))
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .filter(|key| !records.iter().any(|(record, _)| record == key))
            .collect::<Vec<_>>();
        for key in stale {
            table.remove(key.as_str()).map_err(db_error)?;
        }
        for (key, computed) in records {
            let stored = table.get(key.as_str()).map_err(db_error)?.map(|value| value.value());
            let deadline = if let Some(deadline) = stored {
                deadline
            } else {
                table.insert(key.as_str(), computed).map_err(db_error)?;
                *computed
            };
            resolved.insert(key.clone(), deadline);
        }
    }
    txn.commit().map_err(db_error)?;
    Ok(resolved)
}

/// Replaces both indexes after a full table rewrite.
pub(super) fn rebuild(
    txn: &redb::WriteTransaction,
    inbox_rows: impl Iterator<Item = (String, i64)>,
    replay_rows: &[(String, i64)],
) -> Result<(), NodeCoreError> {
    clear(txn)?;
    for (row_key, deadline) in inbox_rows {
        index_inbox_row(txn, &row_key, deadline)?;
    }
    for (replay_key, expires_at) in replay_rows {
        index_replay_row(txn, replay_key, *expires_at)?;
    }
    Ok(())
}

fn clear(txn: &redb::WriteTransaction) -> Result<(), NodeCoreError> {
    for definition in [INBOX_EXPIRY, REPLAY_EXPIRY] {
        let mut table = txn.open_table(definition).map_err(db_error)?;
        let keys = table
            .iter()
            .map_err(db_error)?
            .map(|row| row.map(|(key, _)| key.value().to_owned()).map_err(db_error))
            .collect::<Result<Vec<_>, _>>()?;
        for key in keys {
            table.remove(key.as_str()).map_err(db_error)?;
        }
    }
    Ok(())
}

fn due_keys(
    txn: &redb::WriteTransaction,
    definition: TableDefinition<&str, &[u8]>,
    end: &str,
) -> Result<Vec<String>, NodeCoreError> {
    txn.open_table(definition)
        .map_err(db_error)?
        .range::<&str>(..end)
        .map_err(db_error)?
        .map(|row| row.map(|(key, _)| key.value().to_owned()).map_err(db_error))
        .collect()
}

fn row_key_of(index_key: &str) -> &str {
    index_key.split_once('/').map_or(index_key, |(_, row)| row)
}

/// Removes due mailbox and replay rows; returns how many rows were (or would be) removed.
///
/// Each candidate's stored deadline is rechecked, so a stale index key never deletes a row
/// that was rewritten with a later deadline; that row keeps its own, later index key.
pub(super) fn sweep(
    txn: &redb::WriteTransaction,
    now: i64,
    dry_run: bool,
) -> Result<usize, NodeCoreError> {
    let mut removed = 0;
    let inbox_end = deadline_prefix(now.saturating_add(1));
    for key in due_keys(txn, INBOX_EXPIRY, &inbox_end)? {
        let row_key = row_key_of(&key);
        let due = txn
            .open_table(ROUTER_INBOX_ENTRY_TABLE)
            .map_err(db_error)?
            .get(row_key)
            .map_err(db_error)?
            .map(|value| decode_entry(value.value()).map(|(_, deadline)| deadline <= now))
            .transpose()?;
        if due == Some(true) {
            removed += 1;
            if !dry_run {
                txn.open_table(ROUTER_INBOX_ENTRY_TABLE)
                    .map_err(db_error)?
                    .remove(row_key)
                    .map_err(db_error)?;
            }
        }
        if !dry_run {
            txn.open_table(INBOX_EXPIRY)
                .map_err(db_error)?
                .remove(key.as_str())
                .map_err(db_error)?;
        }
    }
    for key in due_keys(txn, REPLAY_EXPIRY, &deadline_prefix(now))? {
        let row_key = row_key_of(&key);
        let due = txn
            .open_table(ROUTER_REPLAY_TUPLE_TABLE)
            .map_err(db_error)?
            .get(row_key)
            .map_err(db_error)?
            .map(|value| serde_json::from_slice::<i64>(value.value()).map(|expires| expires < now))
            .transpose()
            .map_err(|error| NodeCoreError::SnapshotSerialization(error.to_string()))?;
        if due == Some(true) {
            removed += 1;
            if !dry_run {
                txn.open_table(ROUTER_REPLAY_TUPLE_TABLE)
                    .map_err(db_error)?
                    .remove(row_key)
                    .map_err(db_error)?;
            }
        }
        if !dry_run {
            txn.open_table(REPLAY_EXPIRY)
                .map_err(db_error)?
                .remove(key.as_str())
                .map_err(db_error)?;
        }
    }
    Ok(removed)
}
