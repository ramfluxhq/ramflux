// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Destination retries resolve only signed source outcomes; elapsed time never activates an inbox.
use crate::{
    HomeMigrationService, MigrationOperation, MigrationPeerReply, NodeCoreError, RouterRedbStore,
};
use ramflux_protocol::home_migration::{Refusal, ResolveResult, SKEW_SECONDS};
impl HomeMigrationService {
    /// Process at most 128 due items without retaining a database/authority lock over peer IO.
    /// The configured mesh must enforce a ten-second whole-exchange deadline.
    /// # Errors
    /// Stops on local durable-state failures; peer/protocol failures retain scheduled retry work.
    pub fn courier_tick(
        &self,
        store: &RouterRedbStore,
        now: u64,
        limit: usize,
    ) -> Result<usize, NodeCoreError> {
        let now = store.migration_clock_floor(now)?;
        let tick_started = std::time::Instant::now();
        let claimed = store.claim_migration_courier(now, limit)?;
        let count = claimed.len();
        for op in claimed {
            let item_now = now.saturating_add(tick_started.elapsed().as_secs());
            let deadline = op
                .seal
                .as_ref()
                .and_then(|s| s.body.commit_deadline)
                .ok_or(NodeCoreError::HomeMigration(Refusal::EvidenceRequired))?;
            let status_only = item_now > deadline;
            // Allow the source clock's full permitted skew before asking for an expiry outcome.
            let reply = if status_only && item_now <= deadline.saturating_add(SKEW_SECONDS) {
                None
            } else {
                self.exchange_courier(
                    &op,
                    status_only,
                    item_now,
                    std::time::Instant::now() + std::time::Duration::from_secs(10),
                )
                .ok()
            };
            let observed = now.saturating_add(tick_started.elapsed().as_secs());
            let applied = match reply {
                Some(MigrationPeerReply::Committed(record)) => store.activate_home_migration(
                    &self.node,
                    &ResolveResult { home: *record, predecessors: vec![] },
                    observed,
                ),
                Some(MigrationPeerReply::Fenced(fence)) => store.accept_home_noncommit_fence(
                    &fence,
                    &op.prepare.body.account_anchor,
                    observed,
                ),
                _ => Err(NodeCoreError::HomeMigration(Refusal::CommitOutcomeUnknown)),
            };
            match applied {
                Ok(()) => {}
                Err(NodeCoreError::HomeMigration(_)) => {
                    store.retry_migration_courier(&op, status_only, observed)?;
                }
                Err(error) => return Err(error),
            }
        }
        Ok(count)
    }
    pub(crate) fn exchange_courier(
        &self,
        op: &MigrationOperation,
        status_only: bool,
        now: u64,
        network_deadline: std::time::Instant,
    ) -> Result<MigrationPeerReply, NodeCoreError> {
        let deadline = op
            .seal
            .as_ref()
            .and_then(|seal| seal.body.commit_deadline)
            .ok_or(NodeCoreError::HomeMigration(Refusal::EvidenceRequired))?;
        if !status_only && now > deadline {
            return Err(NodeCoreError::HomeMigration(Refusal::CommitExpired));
        }
        let (source, pinned) = op.base.record.home();
        if self.mesh.peer_key(source, network_deadline)? != pinned {
            return Err(NodeCoreError::HomeMigration(Refusal::PinMismatch));
        }
        let request = if status_only {
            self.node.peer_status_call(
                op.authorization
                    .clone()
                    .ok_or(NodeCoreError::HomeMigration(Refusal::EvidenceRequired))?,
                now,
            )?
        } else {
            self.node.peer_commit_call(op.sealed_evidence()?, now)?
        };
        self.mesh.exchange(source, &request, network_deadline)
    }
}
