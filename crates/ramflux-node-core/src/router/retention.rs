// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Delivery expiry and bounded cursor indexes share the mailbox shard's lock.
use super::{RouterCore, lock_unpoisoned};
impl RouterCore {
    pub fn expire_target_delivery(&self, target: &str, now: i64) {
        self.target_shard(target).inbox.expire(now);
    }
    #[must_use]
    pub fn retention_cursors(&self) -> Vec<crate::CursorAckState> {
        self.target_shards
            .iter()
            .flat_map(|shard| {
                lock_unpoisoned(shard).inbox.cursor_states().cloned().collect::<Vec<_>>()
            })
            .collect()
    }

    /// Remove expired ciphertext and replay receipts from live service state.
    #[must_use]
    pub fn sweep_delivery_retention(&self, now: i64) -> usize {
        let mut removed = 0;
        for shard in &self.target_shards {
            let mut shard = lock_unpoisoned(shard);
            removed += shard.inbox.expire(now);
            let cursors: Vec<_> = shard.inbox.cursor_states().cloned().collect();
            for cursor in cursors {
                self.remove_target_index(&cursor.target_delivery_id);
                for entry in shard
                    .inbox
                    .pending_entries()
                    .filter(|entry| entry.target_delivery_id == cursor.target_delivery_id)
                {
                    self.index_envelope_target(entry);
                }
                self.index_cursor_targets(&cursor);
            }
        }
        for shard in &self.replay_guard_shards {
            lock_unpoisoned(shard).prune(now);
        }
        removed += lock_unpoisoned(&self.control).mvp1_identities.prune_registration_proofs(now);
        removed
    }
}
