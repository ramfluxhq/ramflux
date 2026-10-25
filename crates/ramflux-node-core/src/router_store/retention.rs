// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Expired delivery rows are removed without replacing concurrent live submissions.
use super::{
    CursorAckState, InboxEntry, NodeCoreError, OpaqueDeviceInbox, ROUTER_CURSOR_STATE_TABLE,
    ROUTER_INBOX_ENTRY_TABLE, ROUTER_INBOX_SLICE_KEY, ROUTER_REPLAY_TUPLE_TABLE,
    ROUTER_SNAPSHOT_TABLE, RouterRedbStore, serialize_value,
};
use redb::ReadableTable;
impl RouterRedbStore {
    /// # Errors
    /// Returns serialization or durable storage errors; live rows are never overwritten.
    pub fn sweep_delivery_retention(
        &self,
        now: i64,
        dry_run: bool,
    ) -> Result<usize, NodeCoreError> {
        let txn = self.db.begin_write().map_err(redb_error)?;
        let mut removed = 0;
        {
            let mut table = txn.open_table(ROUTER_INBOX_ENTRY_TABLE).map_err(redb_error)?;
            let mut keys = Vec::new();
            for row in table.iter().map_err(redb_error)? {
                let (key, value) = row.map_err(redb_error)?;
                let entry: InboxEntry =
                    serde_json::from_slice(value.value()).map_err(redb_error)?;
                if expired(&entry, now) {
                    keys.push(key.value().to_owned());
                }
            }
            removed += keys.len();
            if !dry_run {
                for key in keys {
                    table.remove(key.as_str()).map_err(redb_error)?;
                }
            }
        }
        {
            let mut table = txn.open_table(ROUTER_REPLAY_TUPLE_TABLE).map_err(redb_error)?;
            let mut keys = Vec::new();
            for row in table.iter().map_err(redb_error)? {
                let (key, value) = row.map_err(redb_error)?;
                if serde_json::from_slice::<i64>(value.value()).map_err(redb_error)? < now {
                    keys.push(key.value().to_owned());
                }
            }
            removed += keys.len();
            if !dry_run {
                for key in keys {
                    table.remove(key.as_str()).map_err(redb_error)?;
                }
            }
        }
        {
            let mut table = txn.open_table(ROUTER_SNAPSHOT_TABLE).map_err(redb_error)?;
            let bytes = table
                .get(ROUTER_INBOX_SLICE_KEY)
                .map_err(redb_error)?
                .map(|value| value.value().to_vec());
            if let Some(bytes) = bytes {
                let mut inbox: OpaqueDeviceInbox =
                    serde_json::from_slice(&bytes).map_err(redb_error)?;
                removed += inbox.expire(now);
                if !dry_run {
                    table
                        .insert(ROUTER_INBOX_SLICE_KEY, serialize_value(&inbox)?.as_slice())
                        .map_err(redb_error)?;
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
        let txn = self.db.begin_write().map_err(redb_error)?;
        {
            let mut table = txn.open_table(ROUTER_CURSOR_STATE_TABLE).map_err(redb_error)?;
            let previous = table
                .get(cursor.target_delivery_id.as_str())
                .map_err(redb_error)?
                .map(|value| serde_json::from_slice::<CursorAckState>(value.value()))
                .transpose()
                .map_err(redb_error)?;
            let merged = merge_cursor(previous, cursor);
            table
                .insert(cursor.target_delivery_id.as_str(), serialize_value(&merged)?.as_slice())
                .map_err(redb_error)?;
        }
        txn.commit().map_err(redb_error)
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
fn expired(entry: &InboxEntry, now: i64) -> bool {
    entry.envelope.created_at.saturating_add(
        i64::from(entry.envelope.ttl).min(ramflux_protocol::MAX_ENVELOPE_TTL_SECONDS),
    ) <= now
}
fn redb_error(error: impl std::fmt::Display) -> NodeCoreError {
    NodeCoreError::Redb(error.to_string())
}

pub(super) fn cursor_bytes(
    txn: &redb::WriteTransaction,
    cursor: &CursorAckState,
) -> Result<Vec<u8>, NodeCoreError> {
    let table = txn.open_table(ROUTER_CURSOR_STATE_TABLE).map_err(redb_error)?;
    let previous = table
        .get(cursor.target_delivery_id.as_str())
        .map_err(redb_error)?
        .map(|value| serde_json::from_slice::<CursorAckState>(value.value()))
        .transpose()
        .map_err(redb_error)?;
    serialize_value(&merge_cursor(previous, cursor))
}
