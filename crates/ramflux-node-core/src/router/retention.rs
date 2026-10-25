// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Delivery expiry and bounded cursor indexes share the mailbox shard's lock.
use super::{RouterCore, envelope_target_index_shard_index, lock_unpoisoned};

impl RouterCore {
    /// Cursors changed by expiry, dead-lettering or recovery since the last call.
    ///
    /// Only these need a durable checkpoint; untouched mailboxes are not rewritten.
    #[must_use]
    pub fn take_retention_checkpoints(&self) -> Vec<crate::CursorAckState> {
        self.target_shards
            .iter()
            .flat_map(|shard| lock_unpoisoned(shard).inbox.take_checkpoint_due())
            .collect()
    }

    /// Keeps cursors dirty after a failed checkpoint save, so the next sweep retries them.
    pub fn requeue_retention_checkpoints(&self, cursors: &[crate::CursorAckState]) {
        for cursor in cursors {
            lock_unpoisoned(
                &self.target_shards[super::target_shard_index(&cursor.target_delivery_id)],
            )
            .inbox
            .requeue_checkpoints([cursor.target_delivery_id.clone()]);
        }
    }

    /// Remove expired ciphertext and replay receipts from live service state.
    ///
    /// Each shard visits only deliveries whose deadline index entry is due.
    #[must_use]
    pub fn sweep_delivery_retention(&self, now: i64) -> usize {
        let mut removed = 0;
        for shard in &self.target_shards {
            let expired = lock_unpoisoned(shard).inbox.expire_entries(now);
            removed += expired.len();
            for entry in expired {
                let mut index = lock_unpoisoned(
                    &self.envelope_target_index_shards
                        [envelope_target_index_shard_index(&entry.envelope.envelope_id)],
                );
                if index.get(&entry.envelope.envelope_id) == Some(&entry.target_delivery_id) {
                    index.remove(&entry.envelope.envelope_id);
                }
            }
        }
        for shard in &self.replay_guard_shards {
            lock_unpoisoned(shard).prune(now);
        }
        removed += lock_unpoisoned(&self.control).mvp1_identities.prune_registration_proofs(now);
        removed
    }
}
