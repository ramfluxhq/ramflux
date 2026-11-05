// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Bounded request attachment before replay admission. The original request owns
//! persistence; dropping a waiter never changes its descriptor or any other waiter.
use super::{SenderAssignment, content_digest};
use crate::{NodeCoreError, RouterRedbStore};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex, Weak},
};
use tokio::sync::{Notify, OwnedSemaphorePermit};

#[derive(Default)]
pub(crate) struct Registry(Mutex<BTreeMap<String, Arc<Slot>>>);
#[derive(Clone)]
enum Resolution {
    Pending,
    Accepted(SenderAssignment),
    Aborted,
}
struct Slot {
    digest: String,
    retain_until: i64,
    permit: Mutex<Option<OwnedSemaphorePermit>>,
    result: Mutex<Resolution>,
    changed: Notify,
}
/// Admission result after sender authentication, before touching replay state.
pub enum RetryAdmission {
    Owner(RetryOwner),
    Waiting(RetryWaiter),
    Accepted(ResolvedRetry),
}
/// Original request ownership. A non-write drop releases only this identity.
pub struct RetryOwner {
    registry: Weak<Registry>,
    key: String,
    slot: Arc<Slot>,
    bound: Arc<std::sync::atomic::AtomicBool>,
}
/// Cancellation-safe bounded waiter; no assignment or replay reservation ownership.
pub struct RetryWaiter {
    slot: Arc<Slot>,
    permit: OwnedSemaphorePermit,
}
/// A resolved retry retains ingress admission through its original publication gate.
pub struct ResolvedRetry {
    pub(crate) assignment: SenderAssignment,
    pub(crate) permit: OwnedSemaphorePermit,
}
impl std::ops::Deref for ResolvedRetry {
    type Target = SenderAssignment;
    fn deref(&self) -> &Self::Target {
        &self.assignment
    }
}
impl RetryWaiter {
    /// Original admission's retention horizon. Attaching a waiter never refreshes it.
    #[must_use]
    pub fn retain_until(&self) -> i64 {
        self.slot.retain_until
    }

    /// Blocking compatibility adapter for native/TCP store threads.
    /// # Errors
    /// Returns runtime creation or the original typed non-write refusal.
    pub fn resolved_blocking(self) -> Result<ResolvedRetry, NodeCoreError> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .map_err(super::incarnation::error)?;
        runtime.block_on(self.resolved())
    }
    /// Await the original persistence disposition without holding any router lock.
    /// # Errors
    /// Returns `aborted_retry_safe` after the original request proves non-write.
    pub async fn resolved(self) -> Result<ResolvedRetry, NodeCoreError> {
        loop {
            let notified = self.slot.changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            match self.slot.result.lock().map_err(super::incarnation::error)?.clone() {
                Resolution::Pending => {}
                Resolution::Accepted(assignment) => {
                    return Ok(ResolvedRetry { assignment, permit: self.permit });
                }
                Resolution::Aborted => {
                    return Err(super::SenderRetryRefusal::AbortedRetrySafe.into());
                }
            }
            notified.await;
        }
    }
}
#[derive(Clone)]
pub(crate) struct RetryAbort {
    registry: Weak<Registry>,
    key: String,
    slot: Arc<Slot>,
    target: String,
    bound: Arc<std::sync::atomic::AtomicBool>,
}
impl RetryAbort {
    pub(crate) fn bind(&self, target: &str) -> bool {
        if self.target != target {
            return false;
        }
        self.bound
            .compare_exchange(
                false,
                true,
                std::sync::atomic::Ordering::AcqRel,
                std::sync::atomic::Ordering::Acquire,
            )
            .is_ok()
    }
    pub(crate) fn aborted(&self) {
        finish(&self.registry, &self.key, &self.slot, None);
    }
}
impl RetryOwner {
    /// Bind ownership to the allocator's scope before checking the replay guard.
    /// # Errors
    /// Returns an error outside a publication preparation scope.
    pub fn bind(&self, target: &str) -> Result<(), NodeCoreError> {
        crate::router_store::publication::operation::bind_retry(RetryAbort {
            registry: self.registry.clone(),
            key: self.key.clone(),
            slot: Arc::clone(&self.slot),
            target: target.into(),
            bound: Arc::clone(&self.bound),
        })
    }

    /// Install the original durable result before releasing the registration.
    /// Persistent lookup and waiter attachment share the registry lock.
    pub fn accepted(self, assignment: SenderAssignment) {
        if let Some(permit) =
            self.slot.permit.lock().unwrap_or_else(std::sync::PoisonError::into_inner).take()
        {
            crate::router_store::publication::operation::retain_retry_admission(permit);
        }
        self.finish(Some(assignment));
    }
    fn finish(&self, assignment: Option<SenderAssignment>) {
        finish(&self.registry, &self.key, &self.slot, assignment);
    }
}
fn finish(
    owner: &Weak<Registry>,
    key: &str,
    slot: &Arc<Slot>,
    assignment: Option<SenderAssignment>,
) {
    if let Some(registry) = owner.upgrade() {
        let mut entries = registry.0.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut result = slot.result.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if matches!(*result, Resolution::Pending) {
            *result = assignment.map_or(Resolution::Aborted, Resolution::Accepted);
            if entries.get(key).is_some_and(|current| Arc::ptr_eq(current, slot)) {
                entries.remove(key);
            }
            slot.permit.lock().unwrap_or_else(std::sync::PoisonError::into_inner).take();
            slot.changed.notify_waiters();
        }
    }
}

impl Drop for RetryOwner {
    fn drop(&mut self) {
        if !self.bound.load(std::sync::atomic::Ordering::Acquire) {
            self.finish(None);
        }
    }
}
impl RouterRedbStore {
    /// Register an authenticated original or attach an identical retry before the
    /// tentative replay reservation. Every attachment consumes ingress admission.
    /// # Errors
    /// Returns capacity, storage or immutable-content conflict refusals.
    pub fn admit_sender_retry(
        &self,
        source: &ramflux_crypto::RootQualifiedDeviceRef,
        envelope: &ramflux_protocol::Envelope,
        now: i64,
    ) -> Result<RetryAdmission, NodeCoreError> {
        let permit = Arc::clone(&self.submission_admission).try_acquire_owned().map_err(|_| {
            NodeCoreError::Publication(crate::publication::PublicationRefusal::CapacityRetryAfter {
                retry_after_ms: 1000,
            })
        })?;
        let digest = content_digest(envelope)?;
        let key = crate::envelope_replay_tuple_key(source, envelope);
        let mut entries = self.sender_retries.0.lock().map_err(super::incarnation::error)?;
        if let Some(slot) = entries.get(&key) {
            if slot.digest != digest {
                return Err(super::SenderRetryRefusal::IdempotencyConflict.into());
            }
            let waiter = RetryWaiter { slot: Arc::clone(slot), permit };
            drop(entries);
            #[cfg(any(test, feature = "durability-test-hooks"))]
            crate::durability_test_hooks::notify(&self.path, "retry_attached", true)
                .map_err(super::incarnation::error)?;
            return Ok(RetryAdmission::Waiting(waiter));
        }
        if let Some(assignment) = self.sender_assignment(source.root_commitment(), envelope, now)? {
            return Ok(RetryAdmission::Accepted(ResolvedRetry { assignment, permit }));
        }
        let slot = Arc::new(Slot {
            digest,
            retain_until: crate::inbox_retain_until(envelope, now),
            permit: Mutex::new(Some(permit)),
            result: Mutex::new(Resolution::Pending),
            changed: Notify::new(),
        });
        entries.insert(key.clone(), Arc::clone(&slot));
        Ok(RetryAdmission::Owner(RetryOwner {
            registry: Arc::downgrade(&self.sender_retries),
            key,
            slot,
            bound: Arc::default(),
        }))
    }
}

#[cfg(any(test, feature = "durability-test-hooks"))]
impl RouterRedbStore {
    /// Number of unresolved originals; terminal slots never retain history.
    #[must_use]
    pub fn sender_retry_registry_size(&self) -> usize {
        self.sender_retries.0.lock().unwrap_or_else(std::sync::PoisonError::into_inner).len()
    }
}
