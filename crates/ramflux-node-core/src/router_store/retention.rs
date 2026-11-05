// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Expired delivery rows are removed without replacing concurrent live submissions.
//! Sweeps visit only due index entries and checkpoint only the mailboxes they changed.
use super::{
    CursorAckState, NodeCoreError, OpaqueDeviceInbox, ROUTER_CURSOR_STATE_TABLE,
    ROUTER_INBOX_SLICE_KEY, ROUTER_SNAPSHOT_TABLE, RouterRedbStore, serialize_value,
};
use redb::ReadableTable;
impl RouterRedbStore {
    /// Removes due mailbox and replay rows by range-scanning the deadline indexes.
    /// # Errors
    /// Returns serialization or durable storage errors; live rows are never overwritten.
    pub fn sweep_delivery_retention(
        &self,
        now: i64,
        dry_run: bool,
    ) -> Result<usize, NodeCoreError> {
        let txn = self.db.begin_write().map_err(redb_error)?;
        let mut removed = super::expiry_index::sweep(&txn, now, dry_run)?;
        {
            let mut table = txn.open_table(ROUTER_SNAPSHOT_TABLE).map_err(redb_error)?;
            let bytes = table
                .get(ROUTER_INBOX_SLICE_KEY)
                .map_err(redb_error)?
                .map(|value| value.value().to_vec());
            // Pre-incremental databases keep one legacy slice; it disappears once drained.
            if let Some(bytes) = bytes {
                let mut inbox: OpaqueDeviceInbox =
                    serde_json::from_slice(&bytes).map_err(redb_error)?;
                removed += inbox.expire(now);
                if !dry_run {
                    if inbox.pending_entries().next().is_none() {
                        table.remove(ROUTER_INBOX_SLICE_KEY).map_err(redb_error)?;
                    } else {
                        table
                            .insert(ROUTER_INBOX_SLICE_KEY, serialize_value(&inbox)?.as_slice())
                            .map_err(redb_error)?;
                    }
                }
            }
        }
        if dry_run {
            txn.abort().map_err(redb_error)?;
        } else {
            txn.commit().map_err(redb_error)?;
        }
        if let Some(wal) = &self.submission_wal {
            removed +=
                if dry_run { wal.retention_candidate_count(now)? } else { wal.prune_expired(now)? };
        }
        Ok(removed)
    }
    /// # Errors
    /// Persists an expiry watermark without regressing a newer ACK checkpoint.
    pub fn retain_cursor_checkpoint(&self, cursor: &CursorAckState) -> Result<(), NodeCoreError> {
        self.retain_cursor_checkpoints(std::slice::from_ref(cursor))
    }
    /// Persists the cursors a sweep touched in one transaction; an empty set writes nothing.
    /// # Errors
    /// Returns serialization or durable storage errors.
    pub fn retain_cursor_checkpoints(
        &self,
        cursors: &[CursorAckState],
    ) -> Result<(), NodeCoreError> {
        if cursors.is_empty() {
            return Ok(());
        }
        let txn = crate::durability_io::boundary(&self.path, "checkpoint_begin", || {
            self.db.begin_write().map_err(std::io::Error::other)
        })
        .map_err(redb_error)?;
        for cursor in cursors {
            self.checkpoint_incarnation(&txn, cursor)?;
        }
        for cursor in cursors {
            let bytes = cursor_bytes(&txn, cursor)?;
            txn.open_table(ROUTER_CURSOR_STATE_TABLE)
                .map_err(redb_error)?
                .insert(cursor.target_delivery_id.as_str(), bytes.as_slice())
                .map_err(redb_error)?;
        }
        for cursor in cursors {
            crate::home_migration_store::drain::receiver_settled(&txn, cursor)?;
            for sequence in &cursor.retired_inbox_seqs {
                super::expiry_index::remove_inbox_row(
                    &txn,
                    &super::inbox_entry_storage_key(&cursor.target_delivery_id, *sequence),
                )?;
            }
        }
        crate::durability_io::boundary(&self.path, "checkpoint_commit", || {
            txn.commit().map_err(std::io::Error::other)
        })
        .map_err(redb_error)
    }
}
pub(super) fn merge_cursor(
    previous: Option<CursorAckState>,
    incoming: &CursorAckState,
) -> CursorAckState {
    let mut result = incoming.clone();
    if let Some(old) = previous {
        result.settled_inbox_seq = result.settled_inbox_seq.max(old.settled_inbox_seq);
        result.issued_inbox_seq = result.issued_inbox_seq.max(old.issued_inbox_seq);
        if old.inbox_seq > result.inbox_seq {
            result.inbox_seq = old.inbox_seq;
            result.last_envelope_id = old.last_envelope_id;
        }
        result.acked_inbox_seqs.extend(old.acked_inbox_seqs);
    }
    result.acked_inbox_seqs.retain(|seq| *seq > result.settled_inbox_seq);
    result
}
fn redb_error(error: impl std::fmt::Display) -> NodeCoreError {
    NodeCoreError::Redb(error.to_string())
}

fn previous(
    txn: &redb::WriteTransaction,
    cursor: &CursorAckState,
) -> Result<Option<CursorAckState>, NodeCoreError> {
    txn.open_table(ROUTER_CURSOR_STATE_TABLE)
        .map_err(redb_error)?
        .get(cursor.target_delivery_id.as_str())
        .map_err(redb_error)?
        .map(|row| super::incarnation::decode_cursor(row.value()))
        .transpose()
}
fn merged_bytes(
    txn: &redb::WriteTransaction,
    cursor: &CursorAckState,
    previous: Option<CursorAckState>,
    metadata: Option<&(String, u64)>,
) -> Result<Vec<u8>, NodeCoreError> {
    let mut merged = merge_cursor(previous, cursor);
    if let Some((_, issued)) = metadata {
        merged.issued_inbox_seq = merged.issued_inbox_seq.max(*issued);
        let high_water = super::incarnation_state::high_water(&merged);
        if high_water > *issued {
            super::incarnation_state::set(
                txn,
                &cursor.target_delivery_id,
                high_water,
                metadata.map(|(id, _)| id.as_str()),
                false,
            )?;
        }
    }
    super::incarnation::encode_cursor(&merged, metadata.as_ref().map(|(id, _)| id.as_str()))
}
pub(super) fn cursor_bytes(
    txn: &redb::WriteTransaction,
    cursor: &CursorAckState,
) -> Result<Vec<u8>, NodeCoreError> {
    merged_bytes(
        txn,
        cursor,
        previous(txn, cursor)?,
        super::incarnation_state::read(txn, &cursor.target_delivery_id)?.as_ref(),
    )
}
/// Unknown ACK/NACK is a no-op only when neither a counter nor an entry exists.
pub(super) fn ack_cursor_bytes(
    txn: &redb::WriteTransaction,
    cursor: &CursorAckState,
) -> Result<Option<Vec<u8>>, NodeCoreError> {
    let previous = previous(txn, cursor)?;
    let metadata = super::incarnation_state::read(txn, &cursor.target_delivery_id)?;
    if metadata.is_none() {
        let table = txn.open_table(super::super::ROUTER_INBOX_ENTRY_TABLE).map_err(redb_error)?;
        let start = super::inbox_entry_storage_key(&cursor.target_delivery_id, 0);
        let end = super::inbox_entry_storage_key(&cursor.target_delivery_id, u64::MAX);
        let has_entry = table
            .range(start.as_str()..=end.as_str())
            .map_err(redb_error)?
            .next()
            .transpose()
            .map_err(redb_error)?
            .is_some();
        if previous.is_some() || has_entry {
            return Err(NodeCoreError::InboxIncarnationMissing);
        }
        return Ok(None);
    }
    merged_bytes(txn, cursor, previous, metadata.as_ref()).map(Some)
}
