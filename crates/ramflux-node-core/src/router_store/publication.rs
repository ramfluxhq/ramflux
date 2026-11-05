// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Durable assignment publication. Endpoint/allocator adoption is a separate step.
//!
//! A descriptor is its own preallocated resolver mailbox. Drop only sets a flag
//! and unparks the store thread; it never acquires a lock or writes storage.

pub(crate) mod operation;
pub(crate) mod persistence;
pub(crate) use operation::allocate as operation_allocate;
pub use operation::{PublishedOperation, capture};
#[cfg(test)]
mod lifetime_tests;
#[cfg(test)]
mod provisional_tests;
#[cfg(test)]
mod resource_tests;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod view_tests;

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
    /// The store has stopped its resolver and no longer accepts allocation.
    #[error("store_closed")]
    StoreClosed,
    /// The process is fail-stopping after an uncertain storage operation.
    #[error("fatal_durability_uncertain")]
    FatalUncertain,
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
    retired: bool,
    identity_durable: bool,
    allocated: u64,
    published: u64,
    in_flight: BTreeMap<u64, Arc<Descriptor>>,
    accepted: BTreeMap<u64, Vec<String>>,
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
    resources_seen: BTreeMap<String, usize>,
    // Visibility evidence is retained only while a shared resource has live owners.
    resources_published: BTreeSet<String>,
}

pub(crate) type PublishedViews = BTreeMap<String, (Option<String>, u64, Vec<(u64, u64)>)>;
type EntryCleanup = Arc<dyn Fn(&str, u64) + Send + Sync>;
type ReplayCleanup = Arc<dyn Fn(&str) + Send + Sync>;

struct Shared {
    entry_cleanup: OnceLock<EntryCleanup>,
    replay_cleanup: OnceLock<ReplayCleanup>,
    registry: Mutex<Registry>,
    worker: OnceLock<thread::Thread>,
    stopping: AtomicBool,
    changed: Notify,
    db: Weak<redb::Database>,
    path: PathBuf,
    #[cfg(test)]
    snapshot_hook: Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
}

/// Store-owned resolver and synchronized published view. Not restored as live state.
pub struct PublicationCore {
    shared: Arc<Shared>,
    worker: Mutex<Option<JoinHandle<()>>>,
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

impl std::fmt::Debug for PublicationCore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PublicationCore").finish_non_exhaustive()
    }
}

impl PublicationCore {
    pub(crate) fn install_cleanup(&self, entry: EntryCleanup, replay: ReplayCleanup) {
        let _ = self.shared.entry_cleanup.set(entry);
        let _ = self.shared.replay_cleanup.set(replay);
    }

    pub(crate) fn register(
        &self,
        target: &str,
        incarnation: &str,
        issued: u64,
    ) -> Result<(), NodeCoreError> {
        let mut registry = lock(&self.shared);
        if self.shared.stopping.load(Ordering::Acquire) {
            return Err(NodeCoreError::Publication(PublicationRefusal::StoreClosed));
        }
        if registry
            .inboxes
            .range(Key { target: target.into(), incarnation: String::new() }..)
            .next()
            .filter(|(key, _)| key.target == target)
            .is_some_and(|(key, inbox)| inbox.retired || key.incarnation != incarnation)
        {
            return Err(NodeCoreError::Publication(PublicationRefusal::IncarnationMismatch));
        }
        let inbox = registry
            .inboxes
            .entry(Key { target: target.into(), incarnation: incarnation.into() })
            .or_default();
        inbox.identity_durable = true;
        inbox.allocated = inbox.allocated.max(issued);
        if inbox.in_flight.is_empty() {
            inbox.published = inbox.allocated;
        }
        Ok(())
    }

    pub(crate) fn current_incarnation(&self, target: &str) -> Option<String> {
        lock(&self.shared)
            .inboxes
            .range(Key { target: target.into(), incarnation: String::new() }..)
            .next()
            .filter(|(key, _)| key.target == target)
            .map(|(key, _)| key.incarnation.clone())
    }

    pub(crate) fn provisional_incarnation(
        &self,
        target: &str,
        candidate: String,
    ) -> Result<String, NodeCoreError> {
        let mut registry = lock(&self.shared);
        if let Some((key, inbox)) = registry
            .inboxes
            .range(Key { target: target.into(), incarnation: String::new() }..)
            .next()
            .filter(|(key, _)| key.target == target)
        {
            if inbox.retired {
                return Err(NodeCoreError::Publication(PublicationRefusal::IncarnationMismatch));
            }
            return Ok(key.incarnation.clone());
        }
        registry.inboxes.insert(
            Key { target: target.into(), incarnation: candidate.clone() },
            Inbox::default(),
        );
        Ok(candidate)
    }

    pub(crate) fn with_views<T>(&self, f: impl FnOnce(&PublishedViews) -> T) -> T {
        let registry = lock(&self.shared);
        let views = registry
            .inboxes
            .iter()
            .filter(|(_, inbox)| !inbox.retired)
            .map(|(key, inbox)| {
                (
                    key.target.clone(),
                    (
                        inbox.identity_durable.then(|| key.incarnation.clone()),
                        inbox.published,
                        inbox
                            .aborted
                            .iter()
                            .filter(|(start, _)| **start <= inbox.published)
                            .map(|(&a, &b)| (a, b.min(inbox.published)))
                            .collect(),
                    ),
                )
            })
            .collect();
        f(&views)
    }

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
        if self.shared.stopping.load(Ordering::Acquire) {
            return Err(PublicationRefusal::StoreClosed);
        }
        let _gate = crate::fatal_durability::publication()
            .map_err(|_| PublicationRefusal::FatalUncertain)?;
        let mut needed = BTreeMap::<Key, usize>::new();
        for request in requests {
            let key =
                Key { target: request.target.into(), incarnation: request.incarnation.into() };
            *needed.entry(key).or_default() += 1;
        }
        for (key, count) in &needed {
            let inbox = registry.inboxes.get(key).ok_or(PublicationRefusal::IncarnationMismatch)?;
            if inbox.retired {
                return Err(PublicationRefusal::IncarnationMismatch);
            }
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
                registry.resources_seen.entry(resource.clone()).or_default();
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

    pub(crate) fn mark_resource_if_new(&self, resource: &str, held: impl FnOnce() -> bool) -> bool {
        // Preserve registry -> replay-shard lock order used by abort cleanup.
        let mut registry = lock(&self.shared);
        if held() {
            return false;
        }
        *registry.resources_seen.entry(resource.into()).or_default() += 1;
        true
    }

    #[cfg(test)]
    pub(crate) fn mark_resource(&self, resource: &str) {
        *lock(&self.shared).resources_seen.entry(resource.into()).or_default() += 1;
    }
    pub(crate) fn complete_unassigned(&self, resources: &[String]) {
        let mut registry = lock(&self.shared);
        for resource in resources {
            if registry.resources.contains_key(resource)
                || registry.resources_seen.contains_key(resource)
            {
                registry.resources_published.insert(resource.clone());
            }
        }
    }

    pub(crate) fn release_unallocated(&self, resources: &[String]) {
        let mut registry = lock(&self.shared);
        for resource in resources {
            if let Some(count) = registry.resources_seen.get_mut(resource) {
                *count = count.saturating_sub(1);
            }
            if !registry.resources.contains_key(resource)
                && registry.resources_seen.get(resource).is_none_or(|count| *count == 0)
            {
                registry.resources_seen.remove(resource);
                registry.resources_published.remove(resource);
            }
        }
    }

    pub(crate) fn resource_visible(&self, resource: &str) -> bool {
        let registry = lock(&self.shared);
        !registry.resources_seen.contains_key(resource)
            || registry.resources_published.contains(resource)
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
        crate::fatal_durability::check().ok()?;
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
        if crate::fatal_durability::check().is_err() {
            return;
        }
        self.descriptor.state.store(PersistenceState::AcceptedDurable as u8, Ordering::Release);
        #[cfg(any(test, feature = "durability-test-hooks"))]
        if crate::durability_test_hooks::notify(&self.shared.path, "accepted_assignment", true)
            .is_err()
        {
            crate::fatal_durability::fence(false);
            return;
        }
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
            crate::fatal_durability::fence(false);
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
    if aborted && let Some(cleanup) = shared.entry_cleanup.get() {
        cleanup(&descriptor.key.target, descriptor.seq);
    }
    let mut registry = lock(shared);
    let Ok(publication_gate) = crate::fatal_durability::publication() else { return };
    if aborted {
        for resource in &descriptor.resources {
            release_resource(
                shared,
                &mut registry,
                resource,
                &descriptor.key,
                descriptor.seq,
                false,
            );
        }
    }
    let mut published = Vec::new();
    if let Some(inbox) = registry.inboxes.get_mut(&descriptor.key) {
        inbox.identity_durable = true;
        if aborted {
            coalesce(&mut inbox.aborted, descriptor.seq, descriptor.seq);
        } else {
            inbox.accepted.insert(descriptor.seq, descriptor.resources.clone());
        }
        inbox.reservations -= 1;
        inbox.in_flight.remove(&descriptor.seq);
        inbox.published =
            inbox.in_flight.first_key_value().map_or(inbox.allocated, |(&seq, _)| seq - 1);
        while inbox.accepted.first_key_value().is_some_and(|(&seq, _)| seq <= inbox.published) {
            if let Some(entry) = inbox.accepted.pop_first() {
                published.push(entry);
            }
        }
    }
    for (seq, resources) in published {
        for resource in resources {
            release_resource(shared, &mut registry, &resource, &descriptor.key, seq, true);
        }
    }
    drop(registry);
    drop(publication_gate);
    shared.changed.notify_waiters();
}

fn release_resource(
    shared: &Shared,
    registry: &mut Registry,
    resource: &str,
    key: &Key,
    seq: u64,
    accepted: bool,
) {
    if let Some(owners) = registry.resources.get_mut(resource) {
        owners.remove(&(key.clone(), seq));
        if accepted {
            registry.resources_published.insert(resource.into());
        }
        if owners.is_empty() {
            registry.resources.remove(resource);
            let published = registry.resources_published.contains(resource);
            if registry.resources_seen.get(resource).is_none_or(|count| *count == 0) {
                registry.resources_seen.remove(resource);
                registry.resources_published.remove(resource);
            }
            if !accepted
                && !published
                && let Some(cleanup) = shared.replay_cleanup.get()
            {
                cleanup(resource);
            }
        }
    }
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
        if crate::fatal_durability::check().is_err() {
            return;
        }
        let (stopping, descriptors): (_, Vec<_>) = {
            let registry = lock(shared);
            let stopping = shared.stopping.load(Ordering::Acquire);
            let descriptors = registry
                .inboxes
                .values()
                .flat_map(|inbox| inbox.in_flight.values().cloned())
                .collect();
            (stopping, descriptors)
        };
        #[cfg(test)]
        {
            let hook = shared
                .snapshot_hook
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone();
            if let Some(hook) = hook {
                hook();
            }
        }
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
                let _ = error;
                crate::fatal_durability::fence(true);
                return;
            }
            for descriptor in claimed {
                descriptor.state.store(PersistenceState::AbortedDurable as u8, Ordering::Release);
                finish(shared, &descriptor, true);
            }
        }
        let _metrics = diagnostics(shared, Instant::now());
        if stopping {
            if lock(shared).inboxes.values().any(|inbox| !inbox.in_flight.is_empty()) {
                crate::fatal_durability::fence(false);
                return;
            }
            return;
        }
        thread::park_timeout(Duration::from_secs(1));
    }
}

impl PublicationCore {
    /// Retire a fixture target through the same registry barrier as deletion.
    /// # Errors
    /// Returns an error while assignments still own the target.
    #[cfg(any(test, feature = "durability-test-hooks"))]
    pub fn retire_fixture_target(&self, target: &str) -> Result<(), NodeCoreError> {
        self.retire_target(target)?.commit();
        Ok(())
    }

    pub(crate) fn shutdown(&self) {
        {
            let _registry = lock(&self.shared);
            self.shared.stopping.store(true, Ordering::Release);
        }
        if let Some(worker) = self.shared.worker.get() {
            worker.unpark();
        }
        let worker = self.worker.lock().unwrap_or_else(std::sync::PoisonError::into_inner).take();
        if let Some(worker) = worker {
            let _result = worker.join();
        }
    }
}
impl Drop for PublicationCore {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// Explicit storage modes for cross-crate durability fixtures (0=redb, 1=WAL, 2=pipeline WAL).
/// # Errors
/// Returns invalid fixture mode or storage initialization errors.
#[cfg(any(test, feature = "durability-test-hooks"))]
pub fn open_durability_fixture(
    root: &std::path::Path,
    mode: u8,
) -> Result<crate::RouterRedbStore, NodeCoreError> {
    if mode > 2 {
        return Err(error("invalid durability fixture mode"));
    }
    crate::router_store::incarnation::test_store(root, mode, 1024 * 1024)
}

/// A deletion starts only once every assigned write/resolver has settled. Holding
/// this gate through the atomic deletion prevents a late reservation/checkpoint.
pub(crate) struct TargetRetirement {
    shared: Arc<Shared>,
    target: String,
    committed: bool,
}
impl PublicationCore {
    pub(crate) fn retire_target(&self, target: &str) -> Result<TargetRetirement, NodeCoreError> {
        let mut registry = lock(&self.shared);
        if registry
            .inboxes
            .iter()
            .any(|(key, inbox)| key.target == target && !inbox.in_flight.is_empty())
        {
            return Err(NodeCoreError::Publication(PublicationRefusal::CapacityRetryAfter {
                retry_after_ms: 1000,
            }));
        }
        for (key, inbox) in &mut registry.inboxes {
            if key.target == target {
                inbox.retired = true;
            }
        }
        Ok(TargetRetirement {
            shared: Arc::clone(&self.shared),
            target: target.into(),
            committed: false,
        })
    }
}
impl TargetRetirement {
    pub(crate) fn commit(mut self) {
        let mut registry = lock(&self.shared);
        for (key, inbox) in &mut registry.inboxes {
            if key.target == self.target {
                inbox.aborted.clear();
            }
        }
        registry.resources.retain(|_, owners| {
            owners.retain(|(key, _)| key.target != self.target);
            !owners.is_empty()
        });
        self.committed = true;
    }
}
impl Drop for TargetRetirement {
    fn drop(&mut self) {
        if !self.committed {
            for (key, inbox) in &mut lock(&self.shared).inboxes {
                if key.target == self.target {
                    inbox.retired = false;
                }
            }
        }
    }
}
