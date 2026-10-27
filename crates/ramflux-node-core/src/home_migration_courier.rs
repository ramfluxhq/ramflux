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
        // A fixed worker set shares one tick deadline. A stalled peer cannot occupy
        // more than four workers, and shutdown never waits for 128 serial timeouts.
        let deadline = tick_started + std::time::Duration::from_secs(10);
        let queue =
            std::sync::Mutex::new((claimed, std::collections::BTreeMap::<String, usize>::new()));
        let failed = std::sync::atomic::AtomicBool::new(false);
        std::thread::scope(|scope| -> Result<(), NodeCoreError> {
            let mut workers = Vec::new();
            for _ in 0..count.min(16) {
                workers.push(scope.spawn(|| -> Result<(), NodeCoreError> {
                    loop {
                        if failed.load(std::sync::atomic::Ordering::Acquire)
                            || std::time::Instant::now() >= deadline
                        {
                            return Ok(());
                        }
                        let claim = {
                            let mut queue = queue.lock().map_err(|_| {
                                NodeCoreError::Redb("migration courier queue poisoned".into())
                            })?;
                            let Some(index) = queue.0.iter().position(|claim| {
                                queue.1.get(&claim.peer).copied().unwrap_or(0) < 4
                            }) else {
                                return Ok(());
                            };
                            let claim = queue.0.remove(index);
                            *queue.1.entry(claim.peer.clone()).or_default() += 1;
                            claim
                        };
                        let result = self.courier_item(store, &claim, now, tick_started, deadline);
                        {
                            let mut queue = queue.lock().map_err(|_| {
                                NodeCoreError::Redb("migration courier queue poisoned".into())
                            })?;
                            if let Some(active) = queue.1.get_mut(&claim.peer) {
                                *active -= 1;
                            }
                        }
                        if let Err(error) = result {
                            failed.store(true, std::sync::atomic::Ordering::Release);
                            return Err(error);
                        }
                    }
                }));
            }
            let mut error = None;
            for worker in workers {
                let result = worker.join().unwrap_or_else(|_| {
                    Err(NodeCoreError::Redb("migration courier worker panicked".into()))
                });
                if let Err(failure) = result {
                    error.get_or_insert(failure);
                }
            }
            error.map_or(Ok(()), Err)
        })?;
        Ok(count)
    }
    fn courier_item(
        &self,
        store: &RouterRedbStore,
        claim: &crate::home_migration_store::MigrationCourierClaim,
        now: u64,
        started: std::time::Instant,
        network_deadline: std::time::Instant,
    ) -> Result<(), NodeCoreError> {
        let Some(op) = store.claimed_migration_courier(claim)? else {
            return Ok(());
        };
        let observed = || now.saturating_add(started.elapsed().as_secs());
        let deadline = op
            .seal
            .as_ref()
            .and_then(|s| s.body.commit_deadline)
            .ok_or(NodeCoreError::HomeMigration(Refusal::EvidenceRequired))?;
        let item_now = observed();
        let status_only = item_now > deadline
            || op.phase == ramflux_protocol::home_migration::Phase::CommitOutcomeUnknown;
        let _verification = match self.node.acquire_migration_verification() {
            Ok(permit) => permit,
            Err(NodeCoreError::HomeMigration(_)) => {
                return store.retry_migration_courier(&op, status_only, item_now);
            }
            Err(error) => return Err(error),
        };
        let reply = if status_only && item_now <= deadline.saturating_add(SKEW_SECONDS) {
            None
        } else {
            self.exchange_courier(&op, status_only, item_now, network_deadline).ok()
        };
        let applied = match reply {
            Some(MigrationPeerReply::Committed(record)) => store.activate_home_migration(
                &self.node,
                &ResolveResult { home: *record, predecessors: vec![] },
                observed(),
            ),
            Some(MigrationPeerReply::Fenced(fence)) => store.accept_home_noncommit_fence(
                &fence,
                &op.prepare.body.account_anchor,
                observed(),
            ),
            _ => Err(NodeCoreError::HomeMigration(Refusal::CommitOutcomeUnknown)),
        };
        match applied {
            Ok(()) => Ok(()),
            Err(NodeCoreError::HomeMigration(_)) => {
                store.retry_migration_courier(&op, status_only, observed())
            }
            Err(error) => Err(error),
        }
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
