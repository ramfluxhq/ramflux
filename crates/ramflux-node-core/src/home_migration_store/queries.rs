// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Bounded authenticated history/status readers and reservation abort transactions.
use super::{
    Action, BACKLOG, HomeRecord, MigrationBacklogCursor, MigrationOperation, MigrationRole,
    NodeCoreError, OPS, Phase, RECORDS, ReadableDatabase, RecordEvidence, Refusal, RouterCore,
    RouterRedbStore, Signed, auth_error, clock, commit_transition, crypto, decode, maintenance,
    op_key, read, record_hash, refusal, storage, write,
};
use ramflux_protocol::home_migration::{
    BacklogProgress, Control, MAX_CHAIN_RECORDS, MAX_RESOLVE_BYTES, ResolveResult,
};
impl RouterRedbStore {
    /// Read a complete verifiable suffix without creating state for an unknown root.
    /// # Errors
    /// Rejects unknown/nonancestor bases, cycles, truncated storage and excessive pages.
    pub fn resolve_migration_home(
        &self,
        anchor: &str,
        after: Option<&str>,
        limit: usize,
    ) -> Result<ResolveResult, NodeCoreError> {
        if limit == 0 || limit > MAX_CHAIN_RECORDS {
            return Err(refusal(Refusal::HomeCheckpointRequired));
        }
        let home =
            self.migration_home(anchor)?.ok_or_else(|| refusal(Refusal::HomeGenesisRequired))?;
        let tx = self.migration_db().begin_read().map_err(storage)?;
        let records = tx.open_table(RECORDS).map_err(storage)?;
        let mut current = home.clone();
        let mut predecessors = Vec::new();
        loop {
            if after == Some(record_hash(&current.record).map_err(storage)?.as_str()) {
                break;
            }
            let HomeRecord::Committed { authorization, .. } = &current.record else {
                if after.is_some() {
                    return Err(refusal(Refusal::BaseMismatch));
                }
                break;
            };
            let hash = &authorization.body.previous_home_hash;
            if after == Some(hash.as_str()) {
                break;
            }
            if predecessors.len() + 1 >= limit {
                return Err(refusal(Refusal::HomeCheckpointRequired));
            }
            let previous: RecordEvidence = records
                .get(hash.as_str())
                .map_err(storage)?
                .map(|v| decode(v.value()))
                .transpose()?
                .ok_or_else(|| storage("migration history predecessor missing"))?;
            if previous.record.account_anchor() != anchor
                || previous.record.epoch().checked_add(1) != Some(current.record.epoch())
                || record_hash(&previous.record).map_err(storage)? != *hash
            {
                return Err(refusal(Refusal::HomeFork));
            }
            predecessors.push(previous.clone());
            current = previous;
        }
        predecessors.reverse();
        let result = ResolveResult { home, predecessors };
        if ramflux_protocol::canonical_json_bytes(&result).map_err(storage)?.len()
            > MAX_RESOLVE_BYTES
        {
            return Err(refusal(Refusal::HomeCheckpointRequired));
        }
        Ok(result)
    }
    /// Aggregate disjoint durable backlog counters for an owner's signed status receipt.
    /// # Errors
    /// Propagates storage errors and refuses inconsistent or overflowing counters.
    pub fn migration_backlog_progress(
        &self,
        anchor: &str,
        id: &str,
        role: MigrationRole,
    ) -> Result<BacklogProgress, NodeCoreError> {
        let Some(op) = self.migration_operation(anchor, id, role)? else {
            return Ok(BacklogProgress::default());
        };
        let tx = self.migration_db().begin_read().map_err(storage)?;
        let table = match tx.open_table(BACKLOG) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(BacklogProgress::default()),
            Err(e) => return Err(storage(e)),
        };
        let mut total = BacklogProgress::default();
        for target in &op.delivery_map {
            let key = serde_json::to_string(&(anchor, id, &target.target_delivery_id))
                .map_err(storage)?;
            if let Some(cursor) = table
                .get(key.as_str())
                .map_err(storage)?
                .map(|v| decode::<MigrationBacklogCursor>(v.value()))
                .transpose()?
            {
                for (sum, value) in [
                    (&mut total.scheduled, cursor.progress.scheduled),
                    (&mut total.forwarded, cursor.progress.forwarded),
                    (&mut total.receiver_acked, cursor.progress.receiver_acked),
                    (&mut total.expired, cursor.progress.expired),
                    (&mut total.rejected, cursor.progress.rejected),
                    (&mut total.evidence_required, cursor.progress.evidence_required),
                    (&mut total.remaining, cursor.progress.remaining),
                ] {
                    *sum = sum
                        .checked_add(value)
                        .ok_or_else(|| storage("migration progress counter overflow"))?;
                }
            }
        }
        Ok(total)
    }
}
impl RouterCore {
    /// Abort only the preparer's unsealed reservation; a sealed move needs A's outcome.
    /// # Errors
    /// Rejects stale/current-authority mismatches, another preparer, and sealed operations.
    pub fn abort_prepared_home_migration(
        &self,
        store: &RouterRedbStore,
        node: &super::MigrationNode,
        control: &Signed<Control>,
        now: u64,
    ) -> Result<MigrationOperation, NodeCoreError> {
        let c = &control.body;
        self.with_migration_authority(&c.requester.account_anchor, now, |authority, _| {
            crypto::verify_actor(control, authority, now).map_err(auth_error)?;
            if c.action != Action::Abort || c.audience_node != node.node_id() {
                return Err(refusal(Refusal::PinMismatch));
            }
            let tx = store.migration_db().begin_write().map_err(storage)?;
            clock(&tx, now)?;
            let key =
                op_key(&c.requester.account_anchor, &c.migration_id, MigrationRole::Destination)?;
            let mut op: MigrationOperation =
                read(&tx, OPS, &key)?.ok_or_else(|| refusal(Refusal::EvidenceRequired))?;
            if op.prepare.body.actor != c.requester {
                return Err(refusal(Refusal::CustodyApprovalRequired));
            }
            if op.phase == Phase::Aborted {
                return Ok(op);
            }
            if op.phase != Phase::Prepared {
                return Err(refusal(Refusal::CommitOutcomeUnknown));
            }
            maintenance::release_budget(&tx, &c.requester.account_anchor, true)?;
            op.live_budget = false;
            op.phase = Phase::Aborted;
            op.state_version += 1;
            write(&tx, OPS, &key, &op)?;
            commit_transition(store, tx)?;
            Ok(op)
        })
    }
}
