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
    pub(crate) fn publish_ack_cursor(
        &mut self,
        mut cursor: CursorAckState,
        acknowledged: &[u64],
        previous_dead_letters: &BTreeSet<u64>,
        boundary: u64,
    ) {
        let target = cursor.target_delivery_id.clone();
        let persisted_settled = cursor.settled_inbox_seq;
        cursor.issued_inbox_seq = cursor.issued_inbox_seq.max(self.issued_sequence(&target));
        // A removed baseline dead letter was pruned by retention while commit ran.
        // A new candidate dead letter also disappears if its pending row expired.
        let mut added = Vec::new();
        for record in &cursor.dead_letters {
            if !previous_dead_letters.contains(&record.inbox_seq)
                && let Some(entry) =
                    self.pending.get(&target).and_then(|rows| rows.get(&record.inbox_seq))
            {
                let mut record = record.clone();
                record.retain_until = record.retain_until.min(self.retain_until(entry));
                added.push(record);
            }
        }
        if let Some(live) = self.cursors.get(&target) {
            cursor.settled_inbox_seq = cursor.settled_inbox_seq.max(live.settled_inbox_seq);
            cursor.issued_inbox_seq = cursor.issued_inbox_seq.max(live.issued_inbox_seq);
            cursor.inbox_seq = cursor.inbox_seq.max(live.inbox_seq);
            cursor.acked_inbox_seqs.extend(&live.acked_inbox_seqs);
            cursor.acked_envelope_ids.extend(live.acked_envelope_ids.iter().cloned());
            cursor.nacked_envelope_ids.extend(live.nacked_envelope_ids.clone());
            let mut recent = live.recent_ack_ids.clone();
            let mut seen = recent.iter().cloned().collect::<BTreeSet<_>>();
            for id in &cursor.recent_ack_ids {
                if seen.insert(id.clone()) {
                    recent.push_back(id.clone());
                }
            }
            cursor.recent_ack_ids = recent;
            cursor.dead_letters.clone_from(&live.dead_letters);
        } else {
            cursor.dead_letters.clear();
        }
        let mut retained = cursor.dead_letters.iter().map(|r| r.inbox_seq).collect::<BTreeSet<_>>();
        cursor.dead_letters.extend(added.into_iter().filter(|r| retained.insert(r.inbox_seq)));
        while cursor.dead_letters.len() > super::ROUTER_DEAD_LETTER_LIMIT {
            cursor.dead_letters.pop_front();
        }
        for seq in acknowledged.iter().chain(&cursor.retired_inbox_seqs) {
            self.retire_pending(&target, *seq);
        }
        self.restore_cursor_state(cursor);
        // The caller captured P before entering the fatal gate: no registry lock
        // is acquired under that gate. This is advance_settled's shared sparse walk.
        self.advance_settled_through(&target, boundary);
        if self.cursor_state(&target).is_some_and(|c| c.settled_inbox_seq > persisted_settled) {
            self.checkpoint_due.insert(target);
        }
    }
}
