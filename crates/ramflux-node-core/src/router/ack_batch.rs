// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Candidate ACK settlement: one durable commit before publishing the affected inbox.
use super::{CursorAckState, NodeCoreError, RouterCore};
use std::collections::BTreeSet;

impl RouterCore {
    /// Apply up to 64 ACKs under a target settlement lease.
    /// Each refused ACK leaves the candidate unchanged; storage failure publishes nothing.
    /// # Errors
    /// Returns admission, validation or storage errors before reporting any success.
    pub fn apply_ack_batch(
        &self,
        store: &crate::RouterRedbStore,
        target: &str,
        acks: &[ramflux_protocol::Ack],
    ) -> Result<Vec<Result<CursorAckState, NodeCoreError>>, NodeCoreError> {
        if acks.is_empty() || acks.len() > 64 {
            return Err(NodeCoreError::InvalidAckBatch("requires 1..64 members"));
        }
        self.bind_publication(store)?;
        let lease = store.acquire_acknowledgement(target)?;
        let mut candidate = self.target_shard(target).inbox.clone_ack_target(target);
        let mut results = Vec::with_capacity(acks.len());
        let mut retired = BTreeSet::new();
        let mut acknowledged = Vec::new();
        for ack in acks {
            if !ack.ext.ext.contains_key("inbox_seq") {
                let actual = self.indexed_target_for_envelope(&ack.envelope_id);
                match actual {
                    None => {
                        results.push(Err(NodeCoreError::EnvelopeNotFound(ack.envelope_id.clone())));
                        continue;
                    }
                    Some(actual) if actual != target => {
                        results.push(Err(NodeCoreError::EnvelopeTargetMismatch {
                            envelope_id: ack.envelope_id.clone(),
                            expected_target_delivery_id: target.into(),
                            actual_target_delivery_id: actual,
                        }));
                        continue;
                    }
                    Some(_) => {}
                }
            }
            match candidate.apply_ack_for_target(target, ack) {
                Ok(cursor) => {
                    retired.extend(cursor.retired_inbox_seqs.iter().copied());
                    if let Some(seq) = cursor.last_acknowledged_inbox_seq {
                        acknowledged.push(seq);
                    }
                    results.push(Ok(cursor));
                }
                Err(error) => results.push(Err(error)),
            }
        }
        if !acknowledged.is_empty() {
            let mut cursor = candidate
                .cursor_state(target)
                .cloned()
                .ok_or(NodeCoreError::InvalidAckBatch("candidate lacks cursor"))?;
            cursor.retired_inbox_seqs = retired.iter().copied().collect();
            store.record_leased_ack_batch(&cursor, &acknowledged, &lease)?;
            let mut shard = self.target_shard(target);
            let _publication = crate::fatal_durability::publication()?;
            shard.inbox.publish_ack_cursor(cursor, &acknowledged);
        }
        Ok(results)
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod concurrency_tests;
