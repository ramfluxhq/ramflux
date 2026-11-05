// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Receiver cursor candidates are validated against durable rows and publication
//! before commit. The transaction serializes receiver checkpoints without holding
//! the publication data mutex across storage I/O. New allocations are above this
//! observed prefix; resolving an existing guard can only enlarge it.
use super::{
    CursorAckState, NodeCoreError, ROUTER_CURSOR_STATE_TABLE, ROUTER_INBOX_ENTRY_TABLE,
    ReadableTable, RouterRedbStore, expiry_index, inbox_entry_storage_key, incarnation,
    incarnation_state,
};

pub(crate) fn retires(cursor: &CursorAckState, seq: u64) -> bool {
    cursor.last_acknowledged_inbox_seq == Some(seq)
        || cursor.acked_inbox_seqs.contains(&seq)
        || cursor.retired_inbox_seqs.contains(&seq)
}

impl RouterRedbStore {
    pub(super) fn receiver_settlement(
        &self,
        txn: &redb::WriteTransaction,
        incoming: &CursorAckState,
    ) -> Result<(CursorAckState, Option<String>), NodeCoreError> {
        let mut cursor = incoming.clone();
        let metadata = incarnation_state::read(txn, &cursor.target_delivery_id)?;
        let Some((id, issued)) = metadata else {
            return Ok((cursor, None));
        };
        let previous = txn
            .open_table(ROUTER_CURSOR_STATE_TABLE)
            .map_err(incarnation::error)?
            .get(cursor.target_delivery_id.as_str())
            .map_err(incarnation::error)?
            .map(|row| incarnation::decode_cursor(row.value()))
            .transpose()?;
        let previous_r = previous.as_ref().map_or(0, |old| old.settled_inbox_seq);
        // Keep independently committed out-of-order dispositions during concurrent
        // receiver updates; merge_cursor's wider writer migration is owned by P9.
        if let Some(old) = previous {
            cursor.acked_inbox_seqs.extend(old.acked_inbox_seqs);
        }
        let installed = self.publication.lock().map_err(incarnation::error)?.clone();
        let mut settled =
            installed.as_ref().map_or(issued, |core| core.view(&cursor.target_delivery_id, &id).0);
        let entries = txn.open_table(ROUTER_INBOX_ENTRY_TABLE).map_err(incarnation::error)?;
        let start =
            inbox_entry_storage_key(&cursor.target_delivery_id, previous_r.saturating_add(1));
        let end = inbox_entry_storage_key(&cursor.target_delivery_id, u64::MAX);
        for row in entries.range(start.as_str()..=end.as_str()).map_err(incarnation::error)? {
            let (_, bytes) = row.map_err(incarnation::error)?;
            let (entry, _) = expiry_index::decode_entry(bytes.value())?;
            if !retires(&cursor, entry.inbox_seq) {
                settled = settled.min(entry.inbox_seq.saturating_sub(1));
                break;
            }
        }
        if let Some(wal) = &self.submission_wal
            && let Some(seq) = wal.settlement_head(&cursor, previous_r)?
        {
            settled = settled.min(seq.saturating_sub(1));
        }
        cursor.settled_inbox_seq = settled;
        cursor.acked_inbox_seqs.retain(|seq| *seq > settled);
        Ok((cursor, Some(id)))
    }
}
