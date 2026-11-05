// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! One durable forwarding-window decision shared by submissions and backlog drain.
use super::{
    HEADS, HomeRecord, InboxRoute, NodeCoreError, ReadableTable, RecordEvidence, Refusal,
    RouterRedbStore, TARGETS, TableDefinition, clock, commit_transition, read, record_hash,
    refusal, storage,
};
const CLOSED: TableDefinition<&str, u64> = TableDefinition::new("migration_window_closed_v1");
impl RouterRedbStore {
    /// Check A's committed window and permanently latch its first observed closure.
    /// # Errors
    /// Refuses unknown targets, non-source heads and any failed durable transition.
    pub fn migration_forward_window(
        &self,
        target: &str,
        now: u64,
    ) -> Result<Option<RecordEvidence>, NodeCoreError> {
        let tx = self.begin_write().map_err(storage)?;
        let route: InboxRoute =
            read(&tx, TARGETS, target)?.ok_or_else(|| refusal(Refusal::EvidenceRequired))?;
        let head: RecordEvidence =
            read(&tx, HEADS, &route.anchor)?.ok_or_else(|| refusal(Refusal::EvidenceRequired))?;
        let HomeRecord::Committed { commit_proof, .. } = &head.record else {
            return Err(refusal(Refusal::EvidenceRequired));
        };
        if route.active
            || route.epoch != head.record.epoch()
            || route.migration_id != commit_proof.body.migration_id
        {
            return Err(refusal(Refusal::BaseMismatch));
        }
        let key = record_hash(&head.record).map_err(storage)?;
        let closed =
            tx.open_table(CLOSED).map_err(storage)?.get(key.as_str()).map_err(storage)?.is_some();
        let now = clock(&tx, now)?;
        let open = !closed
            && now >= commit_proof.body.committed_at
            && now < commit_proof.body.forward_until;
        if now >= commit_proof.body.forward_until && !closed {
            tx.open_table(CLOSED).map_err(storage)?.insert(key.as_str(), now).map_err(storage)?;
        }
        // Persist the floor together with the latch, even if a caller supplied a rolled-back clock.
        commit_transition(self, tx)?;
        Ok(open.then_some(head))
    }
}
