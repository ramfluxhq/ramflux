// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Copy only ACK-owned target state; apply committed retirements to the current inbox.
use super::{BTreeMap, BTreeSet, CursorAckState, InboxExpiryIndex, OpaqueDeviceInbox};
fn target_map<V: Clone>(rows: &BTreeMap<String, V>, target: &str) -> BTreeMap<String, V> {
    rows.get_key_value(target)
        .map(|(key, value)| (key.clone(), value.clone()))
        .into_iter()
        .collect()
}
impl OpaqueDeviceInbox {
    pub(crate) fn clone_ack_target(&self, target: &str) -> Self {
        Self {
            next_seq: target_map(&self.next_seq, target),
            publication: self.publication.clone(),
            aborted_ranges: target_map(&self.aborted_ranges, target),
            incarnations: target_map(&self.incarnations, target),
            pending: target_map(&self.pending, target),
            cursors: target_map(&self.cursors, target),
            dead_letter_index: target_map(&self.dead_letter_index, target),
            retain_until: target_map(&self.retain_until, target),
            // The candidate never sweeps. Retirement uses its target deadline map;
            // publication removes real expiry keys with each retired live row.
            expiry: InboxExpiryIndex::default(),
            checkpoint_due: BTreeSet::new(),
        }
    }
    pub(crate) fn publish_ack_cursor(&mut self, mut cursor: CursorAckState, acknowledged: &[u64]) {
        let target = cursor.target_delivery_id.clone();
        cursor.issued_inbox_seq = cursor.issued_inbox_seq.max(self.issued_sequence(&target));
        for seq in acknowledged.iter().chain(&cursor.retired_inbox_seqs) {
            self.retire_pending(&target, *seq);
        }
        // Keep rows appended during the disk commit, their deadlines and allocator.
        self.restore_cursor_state(cursor);
    }
}
