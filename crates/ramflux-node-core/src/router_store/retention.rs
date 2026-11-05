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
        let core = self.publication.lock().map_err(redb_error)?.clone();
        crate::fatal_durability::run(|| {
            let mut txn = self.begin_write().map_err(redb_error)?;
            txn.set_durability(redb::Durability::Immediate).map_err(redb_error)?;
            let (mut removed, mut targets) = super::expiry_index::sweep(&txn, now, dry_run)?;
            if let Some(wal) = &self.submission_wal {
                targets.extend(wal.retention_targets(now)?);
            }
            let mut committed = Vec::new();
            if !dry_run {
                for target in targets {
                    let candidate =
                        CursorAckState { target_delivery_id: target, ..CursorAckState::default() };
                    let candidate = previous(&txn, &candidate)?.unwrap_or(candidate);
                    committed.push(self.write_retention_checkpoint(
                        &txn,
                        &candidate,
                        core.as_deref(),
                        Some(now),
                    )?);
                }
            }
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
                removed += if dry_run {
                    wal.retention_candidate_count(now)?
                } else {
                    wal.prune_expired(now)?
                };
            }
            if !dry_run {
                self.publish_retention_checkpoints(&committed, core.clone())?;
            }
            Ok(removed)
        })
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
        self.retain_cursor_checkpoints_at(cursors, None)
    }

    pub(super) fn retain_cursor_checkpoints_at(
        &self,
        cursors: &[CursorAckState],
        wal_expired_at: Option<i64>,
    ) -> Result<(), NodeCoreError> {
        if cursors.is_empty() {
            return Ok(());
        }

        let core = self.publication.lock().map_err(redb_error)?.clone();
        crate::fatal_durability::run(|| {
            let mut txn = crate::durability_io::boundary(&self.path, "checkpoint_begin", || {
                self.begin_write().map_err(std::io::Error::other)
            })
            .map_err(redb_error)?;
            txn.set_durability(redb::Durability::Immediate).map_err(redb_error)?;
            let mut committed = Vec::with_capacity(cursors.len());
            for cursor in cursors {
                self.checkpoint_incarnation(&txn, cursor)?;
                committed.push(self.write_retention_checkpoint(
                    &txn,
                    cursor,
                    core.as_deref(),
                    wal_expired_at,
                )?);
            }
            crate::durability_io::boundary(&self.path, "checkpoint_commit", || {
                txn.commit().map_err(std::io::Error::other)
            })
            .map_err(redb_error)?;
            self.publish_retention_checkpoints(&committed, core.clone())
        })
    }

    fn write_retention_checkpoint(
        &self,
        txn: &redb::WriteTransaction,
        incoming: &CursorAckState,
        core: Option<&super::publication::PublicationCore>,
        wal_expired_at: Option<i64>,
    ) -> Result<CursorAckState, NodeCoreError> {
        let previous = previous(txn, incoming)?;
        let retired = incoming
            .retired_inbox_seqs
            .iter()
            .chain(&incoming.acked_inbox_seqs)
            .copied()
            .chain(incoming.last_acknowledged_inbox_seq)
            .chain(previous.iter().flat_map(|old| old.acked_inbox_seqs.iter().copied()))
            .collect::<std::collections::BTreeSet<_>>();
        let (cursor, _) =
            self.checkpoint_settlement(txn, incoming, previous.as_ref(), core, wal_expired_at)?;
        let bytes = merged_bytes(
            txn,
            &cursor,
            previous,
            super::incarnation_state::read(txn, &cursor.target_delivery_id)?.as_ref(),
        )?;
        txn.open_table(ROUTER_CURSOR_STATE_TABLE)
            .map_err(redb_error)?
            .insert(cursor.target_delivery_id.as_str(), bytes.as_slice())
            .map_err(redb_error)?;
        crate::home_migration_store::drain::receiver_settled(txn, &cursor)?;
        for sequence in &retired {
            super::expiry_index::remove_inbox_row(
                txn,
                &super::inbox_entry_storage_key(&cursor.target_delivery_id, *sequence),
            )?;
        }
        // The cursor and removal share an Immediate transaction: no crash can
        // expose pruned reasons without the durable prefix that subsumes them.
        super::publication::persistence::prune_ranges(txn, &cursor)?;
        Ok(cursor)
    }

    fn publish_retention_checkpoints(
        &self,
        cursors: &[CursorAckState],
        core: Option<std::sync::Arc<super::publication::PublicationCore>>,
    ) -> Result<(), NodeCoreError> {
        let core = self.publication_after_commit(core)?;
        for cursor in cursors {
            if let Some(wal) = &self.submission_wal {
                wal.observe_settlement(cursor)?;
            }
            if let Some(core) = &core
                && let Some(id) = core.current_incarnation(&cursor.target_delivery_id)
            {
                core.commit_settled(&cursor.target_delivery_id, &id, cursor.settled_inbox_seq);
            }
        }
        Ok(())
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

pub(super) fn previous(
    txn: &redb::WriteTransaction,
    cursor: &CursorAckState,
) -> Result<Option<CursorAckState>, NodeCoreError> {
    txn.open_table(ROUTER_CURSOR_STATE_TABLE)
        .map_err(redb_error)?
        .get(cursor.target_delivery_id.as_str())
        .map_err(redb_error)?
        .map(|row| {
            #[cfg(test)]
            super::incarnation::work::read(row.value().len());
            let stored: super::incarnation::StoredCursor =
                serde_json::from_slice(row.value()).map_err(redb_error)?;
            if let Some(id) = &stored.inbox_incarnation_id
                && super::incarnation_state::read(txn, &cursor.target_delivery_id)?
                    .is_some_and(|(current, _)| current != *id)
            {
                return Err(redb_error("cursor checkpoint incarnation mismatch"));
            }
            Ok(stored.cursor)
        })
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
    store: &RouterRedbStore,
    txn: &redb::WriteTransaction,
    incoming: &CursorAckState,
) -> Result<Vec<u8>, NodeCoreError> {
    // Offline bootstrap has installed its pending rows before deriving R.
    // The same durable-head validation applies before any monotonic merge.
    let previous = previous(txn, incoming)?;
    let (cursor, _) = store.receiver_settlement(txn, incoming, previous.as_ref(), None)?;
    merged_bytes(
        txn,
        &cursor,
        previous,
        super::incarnation_state::read(txn, &cursor.target_delivery_id)?.as_ref(),
    )
}
/// Unknown ACK/NACK is a no-op only when neither a counter nor an entry exists.
pub(super) fn ack_cursor_bytes(
    txn: &redb::WriteTransaction,
    cursor: &CursorAckState,
    previous: Option<CursorAckState>,
) -> Result<Option<Vec<u8>>, NodeCoreError> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::router_store::{
        incarnation,
        publication::tests::{entry, fixture},
    };

    #[test]
    fn checkpoint_merge_validates_epoch_and_committed_floor()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = fixture("checkpoint-merge");
        let store = incarnation::test_store(&root, 0, 1 << 20)?;
        store.record_inbox_entry(&entry(1))?;
        let mut cursor = CursorAckState {
            target_delivery_id: "target".into(),
            issued_inbox_seq: 1,
            settled_inbox_seq: 1,
            ..Default::default()
        };
        store.retain_cursor_checkpoint(&cursor)?;
        let tx = store.db.begin_write()?;
        assert_eq!(
            previous(&tx, &cursor)?.ok_or("cursor")?.settled_inbox_seq,
            0,
            "a raw candidate is not committed authority"
        );
        tx.abort()?;
        cursor.last_acknowledged_inbox_seq = Some(1);
        cursor.acked_inbox_seqs.insert(1);
        store.retain_cursor_checkpoint(&cursor)?;
        cursor.last_acknowledged_inbox_seq = None;
        cursor.acked_inbox_seqs.clear();
        cursor.settled_inbox_seq = 0;
        store.retain_cursor_checkpoint(&cursor)?;
        let tx = store.db.begin_write()?;
        assert_eq!(
            previous(&tx, &cursor)?.ok_or("cursor")?.settled_inbox_seq,
            1,
            "stale candidates cannot regress committed R"
        );
        let other = incarnation::new_id()?;
        tx.open_table(ROUTER_CURSOR_STATE_TABLE)?
            .insert("target", incarnation::encode_cursor(&cursor, Some(&other))?.as_slice())?;
        assert!(
            previous(&tx, &cursor).is_err(),
            "never merge a committed prefix from a different E"
        );
        tx.abort()?;
        drop(store);
        std::fs::remove_dir_all(root)?;
        Ok(())
    }
}
