// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Durable assignment publication. Endpoint/allocator adoption is a separate step.
//!
//! A descriptor is its own preallocated resolver mailbox. Drop only sets a flag
//! and unparks the store thread; it never acquires a lock or writes storage.

mod persistence;
#[cfg(test)]
mod tests;

use super::incarnation::error;
use crate::NodeCoreError;
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};
use tokio::sync::Notify;

/// Maximum durable ranges plus reserved assignments per inbox.
pub const ABORTED_RANGE_CAPACITY: usize = 4_096;
const ABORT_CLAIM: u8 = 128;

/// Evidence owned by a store assignment, never inferred from a generic error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum PersistenceState {
    /// No storage operation has been issued.
    ReservedNoWrite,
    /// Caller-side validation proved that no operation was issued.
    DefiniteNonWrite,
    /// A writer owns the operation; failure is uncertain.
    HandedOff,
    /// The writer positively completed durability.
    AcceptedDurable,
    /// The resolver positively completed the aborted checkpoint.
    AbortedDurable,
    /// A handed-off operation did not positively complete.
    FatalUncertain,
}

/// Refusal before sequence allocation, with no registry or storage side effects.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum PublicationRefusal {
    /// Offline unsettled ranges exhaust the conservative reservation budget.
    #[error("capacity_retry_after (retry_after_ms={retry_after_ms})")]
    CapacityRetryAfter { retry_after_ms: u64 },
    /// The caller must initialize/register a durable inbox before allocating.
    #[error("incarnation_mismatch")]
    IncarnationMismatch,
    /// Allocation may not wrap the durable counter.
    #[error("inbox sequence exhausted")]
    SequenceExhausted,
}

/// Diagnostic observations; age never expires a descriptor or grants publication.
#[derive(Clone, Copy, Debug, Default)]
pub struct PublicationMetrics {
    pub in_flight_count: usize,
    pub oldest_in_flight_age_seconds: f64,
    pub warnings: u64,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct Key {
    target: String,
    incarnation: String,
}

struct Descriptor {
    key: Key,
    seq: u64,
    state: AtomicU8,
    detached: AtomicBool,
    created: Instant,
    warned: AtomicBool,
    resources: Vec<String>,
}

#[derive(Default)]
struct Inbox {
    allocated: u64,
    published: u64,
    in_flight: BTreeMap<u64, Arc<Descriptor>>,
    aborted: BTreeMap<u64, u64>,
    reservations: usize,
}

#[derive(Default)]
struct Registry {
    inboxes: BTreeMap<Key, Inbox>,
    // Each child owns a reference. Aborting it cannot delete a sibling's or
    // later assignment's reservation; accepted children retain their references.
    resources: BTreeMap<String, BTreeSet<(Key, u64)>>,
    warnings: u64,
}

struct Shared {
    registry: Mutex<Registry>,
    worker: OnceLock<thread::Thread>,
    stopping: AtomicBool,
    changed: Notify,
    db: Arc<redb::Database>,
    path: PathBuf,
}

/// Store-owned resolver and synchronized published view. Not restored as live state.
pub struct PublicationCore {
    shared: Arc<Shared>,
    worker: Option<JoinHandle<()>>,
}

/// One member of an all-or-nothing pre-allocation reservation.
pub struct AssignmentReservation<'a> {
    pub target: &'a str,
    pub incarnation: &'a str,
    pub resources: &'a [String],
}

/// A request owns only a handle; the store retains the actual descriptor.
pub struct AssignmentGuard {
    shared: Weak<Shared>,
    wake: Option<thread::Thread>,
    descriptor: Arc<Descriptor>,
}

/// Writer ownership, independent of cancellation of the request handle.
pub struct PublicationWrite {
    shared: Arc<Shared>,
    descriptor: Arc<Descriptor>,
}

fn lock(shared: &Shared) -> std::sync::MutexGuard<'_, Registry> {
    shared.registry.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

impl PublicationCore {
    /// Reserve a reason slot and descriptor under allocation synchronization.
    /// `resources` are shared replay/fan-out/custody reservation identities.
    /// # Errors
    /// Returns a typed refusal before any allocation or tentative side effect.
    pub fn reserve(
        &self,
        target: &str,
        incarnation: &str,
        resources: &[String],
    ) -> Result<AssignmentGuard, PublicationRefusal> {
        self.reserve_batch(&[AssignmentReservation { target, incarnation, resources }])?
            .pop()
            .ok_or(PublicationRefusal::SequenceExhausted)
    }

    /// Reserve every fan-out child before allocating any sequence. Duplicate
    /// inboxes share the same budget; a refusal leaves the entire batch untouched.
    /// # Errors
    /// Returns a typed admission refusal with zero allocation or registry effects.
    pub fn reserve_batch(
        &self,
        requests: &[AssignmentReservation<'_>],
    ) -> Result<Vec<AssignmentGuard>, PublicationRefusal> {
        let mut registry = lock(&self.shared);
        let mut needed = BTreeMap::<Key, usize>::new();
        for request in requests {
            let key =
                Key { target: request.target.into(), incarnation: request.incarnation.into() };
            *needed.entry(key).or_default() += 1;
        }
        for (key, count) in &needed {
            let inbox = registry.inboxes.get(key).ok_or(PublicationRefusal::IncarnationMismatch)?;
            if *count
                > ABORTED_RANGE_CAPACITY.saturating_sub(inbox.aborted.len() + inbox.reservations)
            {
                return Err(PublicationRefusal::CapacityRetryAfter { retry_after_ms: 1_000 });
            }
            let count = u64::try_from(*count).map_err(|_| PublicationRefusal::SequenceExhausted)?;
            inbox.allocated.checked_add(count).ok_or(PublicationRefusal::SequenceExhausted)?;
        }
        let mut guards = Vec::with_capacity(requests.len());
        for request in requests {
            let key =
                Key { target: request.target.into(), incarnation: request.incarnation.into() };
            let inbox =
                registry.inboxes.get_mut(&key).ok_or(PublicationRefusal::IncarnationMismatch)?;
            let seq = inbox.allocated + 1;
            let descriptor = Arc::new(Descriptor {
                key: key.clone(),
                seq,
                state: AtomicU8::new(PersistenceState::ReservedNoWrite as u8),
                detached: AtomicBool::new(false),
                created: Instant::now(),
                warned: AtomicBool::new(false),
                resources: request.resources.to_vec(),
            });
            inbox.allocated = seq;
            inbox.reservations += 1;
            inbox.in_flight.insert(seq, Arc::clone(&descriptor));
            for resource in request.resources {
                registry.resources.entry(resource.clone()).or_default().insert((key.clone(), seq));
            }
            guards.push(AssignmentGuard {
                shared: Arc::downgrade(&self.shared),
                wake: self.shared.worker.get().cloned(),
                descriptor,
            });
        }
        Ok(guards)
    }

    /// Published high-water and its aborted ranges in one synchronized observation.
    #[must_use]
    pub fn view(&self, target: &str, incarnation: &str) -> (u64, Vec<(u64, u64)>) {
        let registry = lock(&self.shared);
        registry
            .inboxes
            .get(&Key { target: target.into(), incarnation: incarnation.into() })
            .map_or((0, Vec::new()), |inbox| {
                (
                    inbox.published,
                    inbox
                        .aborted
                        .range(..=inbox.published)
                        .map(|(&start, &end)| (start, end.min(inbox.published)))
                        .collect(),
                )
            })
    }

    /// Cancel-safe async predicate, with notification registered before observation.
    pub async fn wait_published(&self, assignment: &AssignmentGuard) {
        loop {
            let notified = self.shared.changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self
                .view(&assignment.descriptor.key.target, &assignment.descriptor.key.incarnation)
                .0
                >= assignment.sequence()
            {
                return;
            }
            notified.await;
        }
    }

    /// Number of child references retaining a tentative or accepted identity.
    #[must_use]
    pub fn reservation_owners(&self, resource: &str) -> usize {
        lock(&self.shared).resources.get(resource).map_or(0, BTreeSet::len)
    }

    /// Diagnostic only; a held assignment remains live indefinitely.
    #[must_use]
    pub fn metrics(&self) -> PublicationMetrics {
        diagnostics(&self.shared, Instant::now())
    }
}

impl AssignmentGuard {
    #[must_use]
    pub fn sequence(&self) -> u64 {
        self.descriptor.seq
    }

    #[must_use]
    pub fn state(&self) -> PersistenceState {
        descriptor_state(&self.descriptor)
    }

    /// Atomically transfer ownership BEFORE issuing a storage operation.
    /// None means the resolver already claimed this descriptor: never issue a write.
    #[must_use]
    pub fn hand_off(&self) -> Option<PublicationWrite> {
        let shared = self.shared.upgrade()?;
        self.descriptor
            .state
            .compare_exchange(
                PersistenceState::ReservedNoWrite as u8,
                PersistenceState::HandedOff as u8,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .ok()?;
        Some(PublicationWrite { shared, descriptor: Arc::clone(&self.descriptor) })
    }

    /// Caller-side preflight rejected before hand-off. Generic store errors must
    /// never call this method. The resolver owns all physical cleanup.
    pub fn definite_non_write(&self) {
        if self
            .descriptor
            .state
            .compare_exchange(
                PersistenceState::ReservedNoWrite as u8,
                PersistenceState::DefiniteNonWrite as u8,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
        {
            self.detach();
        }
    }

    fn detach(&self) {
        self.descriptor.detached.store(true, Ordering::Release);
        if let Some(worker) = &self.wake {
            worker.unpark();
        }
    }
}

impl Drop for AssignmentGuard {
    fn drop(&mut self) {
        self.detach();
    }
}

impl PublicationWrite {
    /// Called by the writer only after its positive durable completion.
    pub fn accepted_durable(self) {
        self.descriptor.state.store(PersistenceState::AcceptedDurable as u8, Ordering::Release);
        finish(&self.shared, &self.descriptor, false);
    }
}

impl Drop for PublicationWrite {
    fn drop(&mut self) {
        if self
            .descriptor
            .state
            .compare_exchange(
                PersistenceState::HandedOff as u8,
                PersistenceState::FatalUncertain as u8,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
        {
            // An unwound writer cannot fabricate a proved-non-write outcome.
            // P5 installs the shared writer fence and dedicated fatal supervisor.
            tracing::error!("fatal_durability_uncertain");
            std::process::abort();
        }
    }
}

fn descriptor_state(descriptor: &Descriptor) -> PersistenceState {
    match descriptor.state.load(Ordering::Acquire) & !ABORT_CLAIM {
        0 => PersistenceState::ReservedNoWrite,
        1 => PersistenceState::DefiniteNonWrite,
        2 => PersistenceState::HandedOff,
        3 => PersistenceState::AcceptedDurable,
        4 => PersistenceState::AbortedDurable,
        _ => PersistenceState::FatalUncertain,
    }
}

fn finish(shared: &Shared, descriptor: &Descriptor, aborted: bool) {
    let mut registry = lock(shared);
    if aborted {
        for resource in &descriptor.resources {
            if let Some(owners) = registry.resources.get_mut(resource) {
                owners.remove(&(descriptor.key.clone(), descriptor.seq));
                if owners.is_empty() {
                    registry.resources.remove(resource);
                }
            }
        }
    }
    if let Some(inbox) = registry.inboxes.get_mut(&descriptor.key) {
        if aborted {
            coalesce(&mut inbox.aborted, descriptor.seq, descriptor.seq);
        }
        inbox.reservations -= 1;
        inbox.in_flight.remove(&descriptor.seq);
        inbox.published =
            inbox.in_flight.first_key_value().map_or(inbox.allocated, |(&seq, _)| seq - 1);
    }
    drop(registry);
    shared.changed.notify_waiters();
}

fn coalesce(ranges: &mut BTreeMap<u64, u64>, mut start: u64, mut end: u64) {
    if let Some((&left, &right)) = ranges.range(..=start).next_back()
        && right.saturating_add(1) >= start
    {
        ranges.remove(&left);
        start = left;
        end = end.max(right);
    }
    while let Some((&right, &last)) = ranges.range(start..).next()
        && right <= end.saturating_add(1)
    {
        ranges.remove(&right);
        end = end.max(last);
    }
    ranges.insert(start, end);
}

fn diagnostics(shared: &Shared, now: Instant) -> PublicationMetrics {
    let mut registry = lock(shared);
    let mut metrics = PublicationMetrics::default();
    let mut warnings = 0;
    for inbox in registry.inboxes.values() {
        for descriptor in inbox.in_flight.values() {
            metrics.in_flight_count += 1;
            let age = now.saturating_duration_since(descriptor.created).as_secs_f64();
            metrics.oldest_in_flight_age_seconds = metrics.oldest_in_flight_age_seconds.max(age);
            if age > 30.0 && !descriptor.warned.swap(true, Ordering::AcqRel) {
                warnings += 1;
                tracing::warn!(
                    in_flight_count = metrics.in_flight_count,
                    oldest_in_flight_age_seconds = age,
                    "inbox assignment remains in flight"
                );
            }
        }
    }
    registry.warnings += warnings;
    metrics.warnings = registry.warnings;
    metrics
}

fn resolver(shared: &Shared) {
    loop {
        let descriptors: Vec<_> = lock(shared)
            .inboxes
            .values()
            .flat_map(|inbox| inbox.in_flight.values().cloned())
            .collect();
        let stopping = shared.stopping.load(Ordering::Acquire);
        let mut claimed = Vec::new();
        for descriptor in descriptors {
            if !stopping && !descriptor.detached.load(Ordering::Acquire) {
                continue;
            }
            let state = descriptor.state.load(Ordering::Acquire);
            if state != PersistenceState::ReservedNoWrite as u8
                && state != PersistenceState::DefiniteNonWrite as u8
            {
                continue;
            }
            if descriptor
                .state
                .compare_exchange(
                    state,
                    PersistenceState::DefiniteNonWrite as u8 | ABORT_CLAIM,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_err()
            {
                continue;
            }
            claimed.push(descriptor);
        }
        if !claimed.is_empty() {
            if let Err(error) = persistence::abort_batch(shared, &claimed) {
                tracing::error!(%error, "fatal_tombstone_persistence");
                std::process::abort();
            }
            for descriptor in claimed {
                descriptor.state.store(PersistenceState::AbortedDurable as u8, Ordering::Release);
                finish(shared, &descriptor, true);
            }
        }
        let _metrics = diagnostics(shared, Instant::now());
        if stopping {
            if lock(shared).inboxes.values().any(|inbox| !inbox.in_flight.is_empty()) {
                tracing::error!("fatal_durability_uncertain during publication shutdown");
                std::process::abort();
            }
            return;
        }
        thread::park_timeout(Duration::from_secs(1));
    }
}

impl Drop for PublicationCore {
    fn drop(&mut self) {
        self.shared.stopping.store(true, Ordering::Release);
        if let Some(worker) = self.shared.worker.get() {
            worker.unpark();
        }
        if let Some(worker) = self.worker.take() {
            let _result = worker.join();
        }
    }
}
