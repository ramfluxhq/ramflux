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
        let mut result = Vec::with_capacity(map.len());
        for target in map {
            let target = &target.target_delivery_id;
            let cursor: Option<CursorAckState> = cursors
                .get(target.as_str())
                .map_err(storage)?
                .map(|value| serde_json::from_slice(value.value()))
                .transpose()
                .map_err(storage)?;
            let mut view = MailboxCutoverView::new(cursor, now);
            if let Some(row) = tx
                .open_table(super::incarnation_state::TABLE)
                .map_err(storage)?
                .get(target.as_str())
                .map_err(storage)?
            {
                view.high_water =
                    view.high_water.max(super::incarnation_state::decode(row.value())?.1);
            }
            for row in rows
                .range(
                    inbox_entry_storage_key(target, 0).as_str()
                        ..=inbox_entry_storage_key(target, u64::MAX).as_str(),
                )
                .map_err(storage)?
            {
                let (_, value) = row.map_err(storage)?;
                let (entry, until) = expiry_index::decode_entry(value.value())?;
                view.observe(&entry, until)?;
            }
            if let Some(wal) = &self.submission_wal {
                let (issued, records) = wal.migration_target_view(target)?;
                view.high_water = view.high_water.max(issued);
                for record in records {
                    let until = record.retain_until();
                    if let Some(entry) = record.entry {
                        let key = inbox_entry_storage_key(target, entry.inbox_seq);
                        // redb owns the original deadline when the same coordinate is in both stores.
                        if rows.get(key.as_str()).map_err(storage)?.is_some() {
                            continue;
                        }
                        view.observe(&entry, until)?;
                    }
                }
            }
            result.push(MigrationBacklogCursor {
                account_anchor: anchor.into(),
                migration_id: id.into(),
                target_delivery_id: target.clone(),
                high_water: view.high_water,
                next_seq: 0,
                progress: BacklogProgress {
                    scheduled: view.pending,
                    remaining: view.pending,
                    ..BacklogProgress::default()
                },
            });
        }
        Ok(result)
    }
}

/// A counting projection, not a restored inbox: each queue row is visited once without sorting.
struct MailboxCutoverView {
    cursor: Option<CursorAckState>,
    high_water: u64,
    pending: u64,
    now: i64,
}
impl MailboxCutoverView {
    fn new(cursor: Option<CursorAckState>, now: i64) -> Self {
        let high_water = cursor.as_ref().map_or(0, |cursor| {
            cursor.issued_inbox_seq.max(cursor.inbox_seq).max(cursor.settled_inbox_seq)
        });
        Self { cursor, high_water, pending: 0, now }
    }
    fn observe(&mut self, entry: &crate::InboxEntry, until: i64) -> Result<(), NodeCoreError> {
        self.high_water = self.high_water.max(entry.inbox_seq);
        if until > self.now
            && !self.cursor.as_ref().is_some_and(|cursor| {
                entry.inbox_seq <= cursor.settled_inbox_seq
                    || cursor.acked_inbox_seqs.contains(&entry.inbox_seq)
            })
        {
            self.pending = self
                .pending
                .checked_add(1)
                .ok_or_else(|| storage("migration queue count overflow"))?;
        }
        Ok(())
    }
}

/// Index a current, deadline-bound inbox snapshot once while the store is opening.
/// Cutover itself only reads indexed mailbox rows.
pub(super) fn initialize_snapshot_index(tx: &redb::WriteTransaction) -> Result<(), NodeCoreError> {
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
                let mut cursor = cursor.clone();
                cursor.issued_inbox_seq =
                    cursor.issued_inbox_seq.max(inbox.issued_sequence(&cursor.target_delivery_id));
                table
                    .insert(
                        cursor.target_delivery_id.as_str(),
                        serde_json::to_vec(&cursor).map_err(storage)?.as_slice(),
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
    let tx = db.begin_read().map_err(storage)?;
    let cursors = tx.open_table(ROUTER_CURSOR_STATE_TABLE).map_err(storage)?;
    for row in cursors.iter().map_err(storage)? {
        let (_, value) = row.map_err(storage)?;
        wal.observe_settlement(&serde_json::from_slice(value.value()).map_err(storage)?)?;
    }
    Ok(())
}
