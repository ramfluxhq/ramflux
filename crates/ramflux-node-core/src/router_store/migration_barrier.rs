// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Incremental per-mailbox cutover view: indexed WAL and redb ranges, never startup recovery.
use super::{NodeCoreError, RouterRedbStore, expiry_index, inbox_entry_storage_key};
use crate::{
    CursorAckState, MigrationBacklogCursor, OpaqueDeviceInbox, ROUTER_CURSOR_STATE_TABLE,
    ROUTER_INBOX_ENTRY_TABLE,
};
use ramflux_protocol::home_migration::{BacklogProgress, DeliveryMapEntry};
use redb::{ReadableDatabase, ReadableTable, ReadableTableMetadata};
fn storage(error: impl std::fmt::Display) -> NodeCoreError {
    NodeCoreError::Redb(error.to_string())
}
impl RouterRedbStore {
    pub(crate) fn migration_backlog_barrier(
        &self,
        anchor: &str,
        id: &str,
        map: &[DeliveryMapEntry],
        now: u64,
    ) -> Result<Vec<MigrationBacklogCursor>, NodeCoreError> {
        let now = i64::try_from(now).map_err(storage)?;
        let tx = self.db.begin_read().map_err(storage)?;
        let rows = tx.open_table(ROUTER_INBOX_ENTRY_TABLE).map_err(storage)?;
        let cursors = tx.open_table(ROUTER_CURSOR_STATE_TABLE).map_err(storage)?;
        let legacy = match tx.open_table(expiry_index::LEGACY_WAL_DEADLINES) {
            Ok(table) => Some(table),
            Err(redb::TableError::TableDoesNotExist(_)) => None,
            Err(error) => return Err(storage(error)),
        };
        let mut result = Vec::with_capacity(map.len());
        for target in map {
            let target = &target.target_delivery_id;
            let cursor: Option<CursorAckState> = cursors
                .get(target.as_str())
                .map_err(storage)?
                .map(|value| serde_json::from_slice(value.value()))
                .transpose()
                .map_err(storage)?;
            let mut inbox = OpaqueDeviceInbox::new();
            let mut entries = std::collections::BTreeMap::new();
            for row in rows
                .range(
                    inbox_entry_storage_key(target, 0).as_str()
                        ..=inbox_entry_storage_key(target, u64::MAX).as_str(),
                )
                .map_err(storage)?
            {
                let (_, value) = row.map_err(storage)?;
                let (entry, until) = expiry_index::decode_entry(value.value())?;
                entries.insert(entry.inbox_seq, (entry, until));
            }
            let mut issued = 0;
            if let Some(wal) = &self.submission_wal {
                let (high_water, records) = wal.migration_target_view(target)?;
                issued = high_water;
                for record in records {
                    let mut until = record.retain_until();
                    let is_legacy = record.accepted_at.is_none();
                    if let Some(entry) = record.entry {
                        if is_legacy {
                            until = legacy
                                .as_ref()
                                .ok_or_else(|| {
                                    storage("legacy WAL deadlines were not initialized at startup")
                                })?
                                .get(inbox_entry_storage_key(target, entry.inbox_seq).as_str())
                                .map_err(storage)?
                                .ok_or_else(|| storage("legacy WAL deadline missing"))?
                                .value();
                        }
                        entries.entry(entry.inbox_seq).or_insert((entry, until));
                    }
                }
            }
            // Record the issued floor even for expired/settled ciphertext; never reuse a sequence.
            for (entry, until) in entries.into_values() {
                issued = issued.max(entry.inbox_seq);
                if until > now
                    && !cursor.as_ref().is_some_and(|cursor| {
                        cursor.acked_inbox_seqs.contains(&entry.inbox_seq)
                            || entry.inbox_seq <= cursor.settled_inbox_seq
                    })
                {
                    inbox.restore_pending_entry_until(entry, Some(until));
                }
            }
            if let Some(cursor) = cursor {
                inbox.restore_cursor_state(cursor);
            }
            inbox.observe_issued_seq(target, issued);
            let count = u64::try_from(inbox.pending_entries().count()).map_err(storage)?;
            result.push(MigrationBacklogCursor {
                account_anchor: anchor.into(),
                migration_id: id.into(),
                target_delivery_id: target.clone(),
                high_water: inbox.issued_sequence(target),
                next_seq: 0,
                progress: BacklogProgress {
                    scheduled: count,
                    remaining: count,
                    ..BacklogProgress::default()
                },
            });
        }
        Ok(result)
    }
}

/// Upgrade the legacy whole-inbox snapshot once, while the store is opening.
/// Cutover itself only reads indexed mailbox rows.
pub(super) fn upgrade_legacy_snapshot(tx: &redb::WriteTransaction) -> Result<(), NodeCoreError> {
    use super::{ROUTER_INBOX_SLICE_KEY, ROUTER_SNAPSHOT_TABLE, record_inbox_entry_until_in_txn};
    let marker = redb::TableDefinition::<&str, u8>::new("router_migration_mailbox_format_v1");
    if tx.open_table(marker).map_err(storage)?.get("version").map_err(storage)?.is_some() {
        return Ok(());
    }
    let has_incremental =
        !tx.open_table(ROUTER_INBOX_ENTRY_TABLE).map_err(storage)?.is_empty().map_err(storage)?
            || !tx
                .open_table(ROUTER_CURSOR_STATE_TABLE)
                .map_err(storage)?
                .is_empty()
                .map_err(storage)?;
    if !has_incremental {
        let value = tx
            .open_table(ROUTER_SNAPSHOT_TABLE)
            .map_err(storage)?
            .get(ROUTER_INBOX_SLICE_KEY)
            .map_err(storage)?
            .map(|value| value.value().to_vec());
        if let Some(value) = value {
            let inbox: OpaqueDeviceInbox = serde_json::from_slice(&value).map_err(storage)?;
            for (entry, until) in inbox.pending_entries_with_deadline() {
                record_inbox_entry_until_in_txn(tx, entry, until)?;
            }
            let mut table = tx.open_table(ROUTER_CURSOR_STATE_TABLE).map_err(storage)?;
            for cursor in inbox.cursor_states() {
                table
                    .insert(
                        cursor.target_delivery_id.as_str(),
                        serde_json::to_vec(cursor).map_err(storage)?.as_slice(),
                    )
                    .map_err(storage)?;
            }
        }
    }
    tx.open_table(marker).map_err(storage)?.insert("version", 1).map_err(storage)?;
    Ok(())
}

/// Recover retention and ACK projections once at startup; ordinary cutover never uses this scan.
pub(super) fn initialize_wal_view(
    db: &redb::Database,
    wal: Option<&crate::RouterWalStore>,
) -> Result<(), NodeCoreError> {
    let Some(wal) = wal else {
        return Ok(());
    };
    let legacy = wal
        .submissions(i64::try_from(crate::now_unix_seconds()).unwrap_or(i64::MAX))
        .into_iter()
        .filter(|record| record.accepted_at.is_none())
        .filter_map(|record| {
            record.entry.as_ref().map(|entry| {
                (
                    inbox_entry_storage_key(&entry.target_delivery_id, entry.inbox_seq),
                    record.retain_until(),
                )
            })
        })
        .collect::<Vec<_>>();
    expiry_index::resolve_legacy_wal_deadlines(db, &legacy)?;
    let tx = db.begin_read().map_err(storage)?;
    let cursors = tx.open_table(ROUTER_CURSOR_STATE_TABLE).map_err(storage)?;
    for row in cursors.iter().map_err(storage)? {
        let (_, value) = row.map_err(storage)?;
        wal.observe_settlement(&serde_json::from_slice(value.value()).map_err(storage)?)?;
    }
    Ok(())
}
