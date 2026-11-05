// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Per-mailbox admission leases: queued cutovers fence new work without stripe collisions.
use super::{InboxEntry, NodeCoreError, RouterRedbStore};
use ramflux_protocol::home_migration::{DeliveryMapEntry, Refusal};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, Condvar, Mutex, Weak},
    time::{Duration, Instant},
};

#[derive(Default)]
pub(super) struct TargetGates(Arc<Mutex<BTreeMap<String, Arc<Gate>>>>);
#[derive(Default, Debug)]
struct Gate {
    state: Mutex<State>,
    changed: Condvar,
}
#[derive(Default, Debug)]
struct State {
    readers: usize,
    writer: bool,
    waiting: usize,
}
/// An admission lease must outlive in-memory acceptance and the durable WAL acknowledgement.
/// Cancelling an asynchronous submit transfers this lease to the WAL worker.
#[derive(Debug)]
pub struct SubmissionLease {
    target: String,
    gate: Arc<Gate>,
    owner: Weak<Mutex<BTreeMap<String, Arc<Gate>>>>,
    writer: bool,
    acquired: bool,
    admission: bool,
    root: Option<Box<SubmissionLease>>,
}
impl SubmissionLease {
    /// Retain source admission when a submission transfers to the durable writer.
    pub fn retain_home_operation(&mut self, mut source: Self) {
        source.root = self.root.take();
        self.root = Some(Box::new(source));
    }
    pub(super) fn target(&self) -> &str {
        &self.target
    }
}
impl Drop for SubmissionLease {
    fn drop(&mut self) {
        if self.acquired {
            let mut state =
                self.gate.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            if self.writer {
                state.writer = false;
            } else {
                state.readers -= 1;
            }
            self.gate.changed.notify_all();
        }
        if let Some(owner) = self.owner.upgrade() {
            let mut map = owner.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            // The map and this departing lease are the only owners. Removing here
            // bounds metadata by concurrent requests rather than all historical targets.
            if Arc::strong_count(&self.gate) == 2 {
                map.remove(&self.target);
            }
        }
    }
}
fn busy() -> NodeCoreError {
    NodeCoreError::HomeMigration(Refusal::MigrationInProgress)
}
impl TargetGates {
    fn acquire(
        &self,
        target: &str,
        deadline: Option<Instant>,
    ) -> Result<SubmissionLease, NodeCoreError> {
        crate::fatal_durability::check()?;
        let gate = self.0.lock().map_err(|_| busy())?.entry(target.into()).or_default().clone();
        let mut lease = SubmissionLease {
            target: target.into(),
            gate,
            owner: Arc::downgrade(&self.0),
            writer: deadline.is_some(),
            acquired: false,
            admission: false,
            root: None,
        };
        let mut state = lease.gate.state.lock().map_err(|_| busy())?;
        if let Some(deadline) = deadline {
            state.waiting += 1;
            lease.gate.changed.notify_all();
            while state.writer || state.readers != 0 {
                let Some(left) = deadline.checked_duration_since(Instant::now()) else {
                    state.waiting -= 1;
                    lease.gate.changed.notify_all();
                    // This object has not acquired a lease; its Drop must not release one.
                    drop(state);
                    drop(lease);
                    return Err(busy());
                };
                state = lease
                    .gate
                    .changed
                    .wait_timeout(state, left)
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .0;
            }
            state.waiting -= 1;
            state.writer = true;
        } else {
            if state.writer || state.waiting != 0 {
                drop(state);
                drop(lease);
                return Err(busy());
            }
            state.readers += 1;
        }
        drop(state);
        lease.acquired = true;
        Ok(lease)
    }
}
impl RouterRedbStore {
    /// Keep a root-wide read lease for a local client operation through durable acceptance.
    /// Unknown roots use the initial registration path; staged and former homes refuse.
    /// # Errors
    /// Returns the durable home refusal, or retryable busy while a root cutover is queued.
    pub fn acquire_home_operation(&self, anchor: &str) -> Result<SubmissionLease, NodeCoreError> {
        let lease = self.migration_root_gates.acquire(anchor, None)?;
        if let Some(reason) = self
            .inactive_migration_roots
            .read()
            .map_err(|e| NodeCoreError::Redb(e.to_string()))?
            .get(anchor)
        {
            return Err(NodeCoreError::HomeMigration(*reason));
        }
        Ok(lease)
    }
    pub(crate) fn migration_root_barrier(
        &self,
        anchor: &str,
    ) -> Result<SubmissionLease, NodeCoreError> {
        self.migration_root_gates.acquire(anchor, Some(Instant::now() + Duration::from_millis(250)))
    }
    /// Acquire before allocating a mailbox sequence, accepting replay state or pushing live data.
    /// # Errors
    /// Returns a typed migration refusal while cutover is queued or the target is inactive.
    pub fn acquire_submission(&self, target: &str) -> Result<SubmissionLease, NodeCoreError> {
        let root = ramflux_protocol::parse_qualified_device_id(target)
            .map_err(|e| NodeCoreError::Redb(e.to_string()))?
            .map(|(anchor, _)| self.acquire_home_operation(&anchor).map(Box::new))
            .transpose()?;
        let mut lease = self.submission_gates.acquire(target, None)?;
        lease.root = root;
        if let Some(reason) = self
            .inactive_migration_targets
            .read()
            .map_err(|error| NodeCoreError::Redb(error.to_string()))?
            .get(target)
        {
            return Err(NodeCoreError::HomeMigration(*reason));
        }
        lease.admission = true;
        Ok(lease)
    }
    /// Serialize receiver settlement with the same mailbox cutover boundary.
    /// # Errors
    /// Returns a retryable migration refusal when a cutover is queued.
    pub fn acquire_acknowledgement(&self, target: &str) -> Result<SubmissionLease, NodeCoreError> {
        self.submission_gates.acquire(target, None)
    }
    pub(super) fn validate_target_lease(
        &self,
        target: &str,
        lease: &SubmissionLease,
    ) -> Result<(), NodeCoreError> {
        if !lease.acquired
            || lease.writer
            || lease.target != target
            || !Weak::ptr_eq(&lease.owner, &Arc::downgrade(&self.submission_gates.0))
        {
            return Err(NodeCoreError::Redb(
                "submission lease does not match mailbox and store".into(),
            ));
        }
        Ok(())
    }
    pub(super) fn validate_submission_lease(
        &self,
        entry: Option<&InboxEntry>,
        lease: Option<&SubmissionLease>,
    ) -> Result<(), NodeCoreError> {
        if let Some(entry) = entry {
            if !lease.is_some_and(|lease| lease.admission) {
                return Err(NodeCoreError::Redb("submission requires an admission lease".into()));
            }
            self.validate_target_lease(&entry.target_delivery_id, lease.ok_or_else(busy)?)?;
        }
        Ok(())
    }
    pub(crate) fn submission_permit(
        &self,
        entry: Option<&InboxEntry>,
    ) -> Result<Option<SubmissionLease>, NodeCoreError> {
        entry.map(|entry| self.acquire_submission(&entry.target_delivery_id)).transpose()
    }
    /// Wait fairly for existing appends, with a bounded retry interval for the courier.
    /// # Errors
    /// Returns a retryable migration refusal after 250ms, or refuses oversized maps.
    pub fn migration_submission_barrier(
        &self,
        map: &[DeliveryMapEntry],
    ) -> Result<Vec<SubmissionLease>, NodeCoreError> {
        if map.len() > ramflux_protocol::custody::MAX_ROSTER {
            return Err(NodeCoreError::HomeMigration(Refusal::CapacityRefused));
        }
        let deadline = Instant::now() + Duration::from_millis(250);
        map.iter()
            .map(|entry| entry.target_delivery_id.as_str())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .map(|target| self.submission_gates.acquire(target, Some(deadline)))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn queued_cutover_fences_steady_readers_without_blocking_another_target()
    -> Result<(), Box<dyn std::error::Error>> {
        let gates = TargetGates::default();
        let first = gates.acquire("moving", None)?;
        let gate = Arc::clone(&first.gate);
        std::thread::scope(|scope| -> Result<(), Box<dyn std::error::Error>> {
            let (held, arrived) = std::sync::mpsc::sync_channel(1);
            let writer_gates = &gates;
            let writer = scope.spawn(move || {
                let cutover =
                    writer_gates.acquire("moving", Some(Instant::now() + Duration::from_secs(5)));
                held.send(cutover).map_err(|error| error.to_string())
            });
            let state = gate.state.lock().map_err(|_| "gate poisoned")?;
            let (state, timeout) = gate
                .changed
                .wait_timeout_while(state, Duration::from_secs(5), |state| state.waiting == 0)
                .map_err(|_| "gate poisoned")?;
            assert!(!timeout.timed_out());
            drop(state);
            for _ in 0..1024 {
                assert!(matches!(
                    gates.acquire("moving", None),
                    Err(NodeCoreError::HomeMigration(Refusal::MigrationInProgress))
                ));
                drop(gates.acquire("unrelated", None)?);
            }
            drop(first);
            let cutover = arrived.recv_timeout(Duration::from_secs(5))??;
            assert!(gates.acquire("moving", None).is_err());
            drop(cutover);
            writer.join().map_err(|_| "writer panicked")??;
            drop(gates.acquire("moving", None)?);
            Ok(())
        })?;
        drop(gate);
        // Rejected readers and timed-out waiters must not leak target metadata.
        drop(gates.acquire("moving", None)?);
        assert_eq!(gates.0.lock().map_err(|_| "map poisoned")?.len(), 0);
        Ok(())
    }
    #[test]
    fn timed_out_cutover_releases_pending_writer_fence() -> Result<(), Box<dyn std::error::Error>> {
        let gates = TargetGates::default();
        let reader = gates.acquire("moving", None)?;
        assert!(gates.acquire("moving", Some(Instant::now())).is_err());
        drop(gates.acquire("moving", None)?);
        drop(reader);
        assert_eq!(gates.0.lock().map_err(|_| "map poisoned")?.len(), 0);
        Ok(())
    }
}
