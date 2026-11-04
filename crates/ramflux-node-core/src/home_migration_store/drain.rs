// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Durable outstanding drain obligations and atomic settlement, independent of transport replies.
use super::{
    BACKLOG, Deserialize, MigrationBacklogCursor, NodeCoreError, ReadableDatabase, ReadableTable,
    RouterRedbStore, Serialize, TableDefinition, clock, commit_transition, decode, read, storage,
    write,
};
use crate::router_store::{expiry_index, inbox_entry_storage_key};
use crate::{CursorAckState, InboxEntry, ROUTER_CURSOR_STATE_TABLE, ROUTER_INBOX_ENTRY_TABLE};
const ENTRIES: TableDefinition<&str, &[u8]> = TableDefinition::new("migration_drain_entries_v1");

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum MigrationDrainState {
    #[default]
    Pending,
    Held,
    Rejected,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MigrationDrainEntry {
    pub account_anchor: String,
    pub migration_id: String,
    pub entry: InboxEntry,
    pub retain_until: i64,
    pub state: MigrationDrainState,
    pub attempts: u64,
    pub next_attempt: u64,
}
/// Only a durable B commit/duplicate reply is a `BAck`; transport failures are `Held`.
/// A late durable ACK may settle a rejected row; workers must not retry rejected rows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MigrationDrainOutcome {
    BAck,
    Held,
    Rejected,
    Expired,
}
#[cfg(test)]
#[derive(Clone, Copy)]
pub(super) enum DrainFailPoint {
    AfterBAckBeforeACommit,
}

fn cursor_key(row: &MigrationDrainEntry) -> Result<String, NodeCoreError> {
    serde_json::to_string(&(&row.account_anchor, &row.migration_id, &row.entry.target_delivery_id))
        .map_err(storage)
}
pub(super) fn capture(
    store: &RouterRedbStore,
    tx: &redb::WriteTransaction,
    cursors: &[MigrationBacklogCursor],
    now: u64,
) -> Result<(), NodeCoreError> {
    for cursor in cursors {
        let target = &cursor.target_delivery_id;
        let mut entries = std::collections::BTreeMap::new();
        if let Some(wal) = &store.submission_wal {
            for record in wal.migration_target_view(target)?.1 {
                let mut until = record.retain_until();
                let legacy = record.accepted_at.is_none();
                if let Some(entry) = record.entry {
                    if legacy {
                        until = tx
                            .open_table(expiry_index::LEGACY_WAL_DEADLINES)
                            .map_err(storage)?
                            .get(inbox_entry_storage_key(target, entry.inbox_seq).as_str())
                            .map_err(storage)?
                            .ok_or_else(|| storage("missing legacy WAL deadline"))?
                            .value();
                    }
                    entries.insert(entry.inbox_seq, (entry, until));
                }
            }
        }
        let rows = tx.open_table(ROUTER_INBOX_ENTRY_TABLE).map_err(storage)?;
        for row in rows
            .range(
                inbox_entry_storage_key(target, 0).as_str()
                    ..=inbox_entry_storage_key(target, cursor.high_water).as_str(),
            )
            .map_err(storage)?
        {
            let (_, value) = row.map_err(storage)?;
            let (entry, until) = expiry_index::decode_entry(value.value())?;
            entries.insert(entry.inbox_seq, (entry, until));
        }
        let settled: CursorAckState =
            read(tx, ROUTER_CURSOR_STATE_TABLE, target)?.unwrap_or_default();
        let mut count = 0;
        for (seq, (entry, until)) in entries {
            if seq > cursor.high_water
                || until <= i64::try_from(now).map_err(storage)?
                || seq <= settled.settled_inbox_seq
                || settled.acked_inbox_seqs.contains(&seq)
            {
                continue;
            }
            let row = MigrationDrainEntry {
                account_anchor: cursor.account_anchor.clone(),
                migration_id: cursor.migration_id.clone(),
                entry,
                retain_until: until,
                state: MigrationDrainState::Pending,
                attempts: 0,
                next_attempt: now,
            };
            let key = inbox_entry_storage_key(target, seq);
            if read::<MigrationDrainEntry>(tx, ENTRIES, &key)?.is_some() {
                return Err(storage("overlapping migration drain obligation"));
            }
            write(tx, ENTRIES, &key, &row)?;
            count += 1;
        }
        if count != cursor.progress.remaining {
            return Err(storage("migration drain snapshot count changed"));
        }
    }
    Ok(())
}
impl RouterRedbStore {
    /// Read at most 64 outstanding rows, including held/rejected obligations for expiry handling.
    /// # Errors
    /// Returns storage or decoding errors.
    pub fn migration_drain_page(
        &self,
        target: &str,
        after: u64,
    ) -> Result<Vec<MigrationDrainEntry>, NodeCoreError> {
        let tx = self.migration_db().begin_read().map_err(storage)?;
        let table = match tx.open_table(ENTRIES) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(vec![]),
            Err(e) => return Err(storage(e)),
        };
        table
            .range(
                inbox_entry_storage_key(target, after).as_str()
                    ..=inbox_entry_storage_key(target, u64::MAX).as_str(),
            )
            .map_err(storage)?
            .take(64)
            .map(|row| {
                let (_, value) = row.map_err(storage)?;
                decode(value.value())
            })
            .collect()
    }
    /// Read a bounded cross-account page strictly after an opaque worker position.
    /// # Errors
    /// Stops on storage or decoding failures without changing any obligation.
    pub fn migration_drain_work_page(
        &self,
        after: &str,
    ) -> Result<Vec<(String, MigrationDrainEntry)>, NodeCoreError> {
        let tx = self.migration_db().begin_read().map_err(storage)?;
        let table = match tx.open_table(ENTRIES) {
            Ok(table) => table,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(vec![]),
            Err(error) => return Err(storage(error)),
        };
        table
            .range::<&str>((std::ops::Bound::Excluded(after), std::ops::Bound::Unbounded))
            .map_err(storage)?
            .take(64)
            .map(|row| {
                let (key, value) = row.map_err(storage)?;
                Ok((key.value().to_owned(), decode(value.value())?))
            })
            .collect()
    }
    /// Apply a classified reply to the current obligation; repeated replies are idempotent.
    /// # Errors
    /// Refuses premature expiry, stale obligations, overflow and storage failures.
    pub fn settle_migration_drain(
        &self,
        row: &MigrationDrainEntry,
        outcome: MigrationDrainOutcome,
        now: u64,
    ) -> Result<(), NodeCoreError> {
        self.settle_drain_inner(row, outcome, now, false)
    }
    fn settle_drain_inner(
        &self,
        row: &MigrationDrainEntry,
        outcome: MigrationDrainOutcome,
        now: u64,
        fail: bool,
    ) -> Result<(), NodeCoreError> {
        let tx = self.migration_db().begin_write().map_err(storage)?;
        let now = clock(&tx, now)?;
        let key = inbox_entry_storage_key(&row.entry.target_delivery_id, row.entry.inbox_seq);
        let Some(current) = read::<MigrationDrainEntry>(&tx, ENTRIES, &key)? else {
            return Ok(());
        };
        if current.account_anchor != row.account_anchor
            || current.migration_id != row.migration_id
            || current.entry != row.entry
        {
            return Err(storage("stale migration drain obligation"));
        }
        if fail {
            return Err(storage("injected AfterBAckBeforeACommit"));
        }
        apply(&tx, current, outcome, now, false)?;
        commit_transition(self, tx)?;
        if let Some(wal) = &self.submission_wal {
            let tx = self.migration_db().begin_read().map_err(storage)?;
            let table = tx.open_table(ROUTER_CURSOR_STATE_TABLE).map_err(storage)?;
            if let Some(value) =
                table.get(row.entry.target_delivery_id.as_str()).map_err(storage)?
            {
                wal.observe_settlement(&decode::<CursorAckState>(value.value())?)?;
            }
        }
        Ok(())
    }
    #[cfg(test)]
    pub(super) fn fail_drain(
        &self,
        row: &MigrationDrainEntry,
        _: DrainFailPoint,
        now: u64,
    ) -> Result<(), NodeCoreError> {
        self.settle_drain_inner(row, MigrationDrainOutcome::BAck, now, true)
    }
}
fn sub(value: &mut u64) -> Result<(), NodeCoreError> {
    *value = value.checked_sub(1).ok_or_else(|| storage("migration counter underflow"))?;
    Ok(())
}
fn add(value: &mut u64) -> Result<(), NodeCoreError> {
    *value = value.checked_add(1).ok_or_else(|| storage("migration counter overflow"))?;
    Ok(())
}
fn apply(
    tx: &redb::WriteTransaction,
    mut row: MigrationDrainEntry,
    outcome: MigrationDrainOutcome,
    now: u64,
    receiver: bool,
) -> Result<(), NodeCoreError> {
    let ck = cursor_key(&row)?;
    let mut cursor: MigrationBacklogCursor =
        read(tx, BACKLOG, &ck)?.ok_or_else(|| storage("missing drain cursor"))?;
    let terminal =
        receiver || matches!(outcome, MigrationDrainOutcome::BAck | MigrationDrainOutcome::Expired);
    if outcome == MigrationDrainOutcome::Expired
        && !receiver
        && i64::try_from(now).map_err(storage)? < row.retain_until
    {
        return Err(storage("premature drain expiry"));
    }
    match row.state {
        MigrationDrainState::Held => sub(&mut cursor.progress.evidence_required)?,
        MigrationDrainState::Rejected => sub(&mut cursor.progress.rejected)?,
        MigrationDrainState::Pending => {}
    }
    let key = inbox_entry_storage_key(&row.entry.target_delivery_id, row.entry.inbox_seq);
    if terminal {
        sub(&mut cursor.progress.remaining)?;
        if receiver {
            add(&mut cursor.progress.receiver_acked)?;
        } else if outcome == MigrationDrainOutcome::BAck {
            add(&mut cursor.progress.forwarded)?;
        } else {
            add(&mut cursor.progress.expired)?;
        }

        tx.open_table(ENTRIES).map_err(storage)?.remove(key.as_str()).map_err(storage)?;
        // Never advance past an earlier held/rejected obligation.
        let rows = tx.open_table(ENTRIES).map_err(storage)?;
        let next = rows
            .range(
                inbox_entry_storage_key(&row.entry.target_delivery_id, 0).as_str()
                    ..=inbox_entry_storage_key(&row.entry.target_delivery_id, u64::MAX).as_str(),
            )
            .map_err(storage)?
            .next()
            .transpose()
            .map_err(storage)?;
        cursor.next_seq = next
            .map(|(_, value)| {
                decode::<MigrationDrainEntry>(value.value()).map(|r| r.entry.inbox_seq)
            })
            .transpose()?
            .unwrap_or(cursor.high_water.saturating_add(1));
        expiry_index::remove_inbox_row(tx, &key)?;
        let mut settled: CursorAckState =
            read(tx, ROUTER_CURSOR_STATE_TABLE, &row.entry.target_delivery_id)?.unwrap_or_else(
                || CursorAckState {
                    target_delivery_id: row.entry.target_delivery_id.clone(),
                    ..Default::default()
                },
            );
        settled.acked_inbox_seqs.insert(row.entry.inbox_seq);
        write(tx, ROUTER_CURSOR_STATE_TABLE, &row.entry.target_delivery_id, &settled)?;
    } else {
        // A repeated refusal never creates a second outstanding obligation.
        row.state = if row.state == MigrationDrainState::Rejected
            || outcome == MigrationDrainOutcome::Rejected
        {
            MigrationDrainState::Rejected
        } else {
            MigrationDrainState::Held
        };
        match row.state {
            MigrationDrainState::Held => add(&mut cursor.progress.evidence_required)?,
            MigrationDrainState::Rejected => add(&mut cursor.progress.rejected)?,
            MigrationDrainState::Pending => {}
        }
        row.attempts = row.attempts.saturating_add(1);
        row.next_attempt = now.saturating_add(1u64 << row.attempts.min(8));
        write(tx, ENTRIES, &key, &row)?;
    }
    if cursor.progress.scheduled
        != cursor
            .progress
            .remaining
            .checked_add(cursor.progress.forwarded)
            .and_then(|n| n.checked_add(cursor.progress.receiver_acked))
            .and_then(|n| n.checked_add(cursor.progress.expired))
            .ok_or_else(|| storage("migration counter overflow"))?
        || cursor.progress.rejected + cursor.progress.evidence_required > cursor.progress.remaining
    {
        return Err(storage("migration counters do not conserve"));
    }
    write(tx, BACKLOG, &ck, &cursor)
}
pub(crate) fn receiver_ack(
    tx: &redb::WriteTransaction,
    target: &str,
    seq: u64,
) -> Result<(), NodeCoreError> {
    let key = inbox_entry_storage_key(target, seq);
    if let Some(row) = read::<MigrationDrainEntry>(tx, ENTRIES, &key)? {
        apply(tx, row, MigrationDrainOutcome::BAck, 0, true)?;
    }
    Ok(())
}

/// Receiver retirement, including dead letters, counts as `receiver_acked`.
/// Select before mutating because settlement updates the same table and cursor.
pub(crate) fn receiver_settled(
    tx: &redb::WriteTransaction,
    cursor: &CursorAckState,
) -> Result<(), NodeCoreError> {
    let mut merged: CursorAckState =
        read(tx, ROUTER_CURSOR_STATE_TABLE, &cursor.target_delivery_id)?
            .unwrap_or_else(|| cursor.clone());
    merged.retired_inbox_seqs.extend(&cursor.retired_inbox_seqs);
    let cursor = &merged;
    let rows = {
        let table = tx.open_table(ENTRIES).map_err(storage)?;
        table
            .range(
                inbox_entry_storage_key(&cursor.target_delivery_id, 0).as_str()
                    ..=inbox_entry_storage_key(&cursor.target_delivery_id, u64::MAX).as_str(),
            )
            .map_err(storage)?
            .map(|row| {
                let (_, bytes) = row.map_err(storage)?;
                decode::<MigrationDrainEntry>(bytes.value())
            })
            .collect::<Result<Vec<_>, _>>()?
    };
    for row in rows {
        let seq = row.entry.inbox_seq;
        if seq <= cursor.settled_inbox_seq
            || cursor.acked_inbox_seqs.contains(&seq)
            || cursor.retired_inbox_seqs.contains(&seq)
            || cursor.last_acknowledged_inbox_seq == Some(seq)
        {
            receiver_ack(tx, &cursor.target_delivery_id, seq)?;
        }
    }
    Ok(())
}
