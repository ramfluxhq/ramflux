// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! A synchronous preparation scope owns guards until its store operation has
//! finished. The returned operation awaits publication without retaining locks.
use super::{AssignmentGuard, PublicationCore, PublicationWrite};
use crate::{InboxEntry, NodeCoreError};
use std::{cell::RefCell, collections::BTreeSet, sync::Arc};

#[derive(Default)]
struct Scope {
    guards: Vec<AssignmentGuard>,
    resources: Vec<String>,
    core: Option<Arc<PublicationCore>>,
    assigned: BTreeSet<(String, u64)>,
}
thread_local! {
    static CURRENT: RefCell<Option<Scope>> = const { RefCell::new(None) };
}
struct Reset;
impl Drop for Reset {
    fn drop(&mut self) {
        CURRENT.with(|current| {
            current.borrow_mut().take();
        });
    }
}

/// A completed store operation whose response still belongs behind the prefix gate.
pub struct PublishedOperation<T> {
    value: T,
    guards: Vec<AssignmentGuard>,
}
impl<T> PublishedOperation<T> {
    /// Asynchronously await every assigned target. Cancellation cannot undo a
    /// durable acceptance; guards only signal the store-owned resolver on Drop.
    pub async fn published(self) -> T {
        for guard in &self.guards {
            if let Some(shared) = guard.shared.upgrade() {
                loop {
                    let notified = shared.changed.notified();
                    tokio::pin!(notified);
                    notified.as_mut().enable();
                    let ready = {
                        let registry = super::lock(&shared);
                        registry
                            .inboxes
                            .get(&guard.descriptor.key)
                            .is_some_and(|inbox| inbox.published >= guard.sequence())
                    };
                    if ready && crate::fatal_durability::check().is_ok() {
                        break;
                    }
                    notified.await;
                }
            }
        }
        self.value
    }
    /// Compatibility adapter for callers already running on blocking/store threads.
    /// # Errors
    /// Returns runtime creation errors.
    pub fn published_blocking(self) -> Result<T, NodeCoreError> {
        if self.guards.iter().all(|guard| {
            guard.shared.upgrade().is_none_or(|shared| {
                let registry = super::lock(&shared);
                crate::fatal_durability::check().is_ok()
                    && registry
                        .inboxes
                        .get(&guard.descriptor.key)
                        .is_some_and(|inbox| inbox.published >= guard.sequence())
            })
        }) {
            return Ok(self.value);
        }
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .map_err(|error| NodeCoreError::Redb(error.to_string()))?;
        Ok(runtime.block_on(self.published()))
    }
}

/// Run one non-async preparation and storage operation on its blocking thread.
/// A panic or early return drops all pre-write guards; no scope crosses an await.
/// # Errors
/// Refuses nested scopes, which would obscure assignment ownership.
pub fn capture<T>(f: impl FnOnce() -> T) -> Result<PublishedOperation<T>, NodeCoreError> {
    CURRENT.with(|current| {
        let mut current = current.borrow_mut();
        if current.is_some() {
            return Err(NodeCoreError::Redb("nested publication scope".into()));
        }
        *current = Some(Scope::default());
        Ok(())
    })?;
    let reset = Reset;
    let value = f();
    let scope = CURRENT.with(|current| current.borrow_mut().take()).unwrap_or_default();
    drop(reset);
    for guard in &scope.guards {
        guard.definite_non_write();
    }
    Ok(PublishedOperation { value, guards: scope.guards })
}

pub(crate) fn replay_resource(core: Option<&Arc<PublicationCore>>, key: &str) {
    CURRENT.with(|current| {
        if let Some(scope) = current.borrow_mut().as_mut() {
            if let Some(core) = core {
                core.mark_resource(key);
                scope.core = Some(Arc::clone(core));
            }
            scope.resources.push(key.into());
        }
    });
}

pub(crate) fn reserve_targets(
    core: &Arc<PublicationCore>,
    targets: &[(String, String)],
) -> Result<(), NodeCoreError> {
    CURRENT.with(|current| {
        let mut current = current.borrow_mut();
        let scope = current
            .as_mut()
            .ok_or_else(|| NodeCoreError::Redb("fanout requires publication scope".into()))?;
        let requests = targets
            .iter()
            .map(|(target, id)| super::AssignmentReservation {
                target,
                incarnation: id,
                resources: &scope.resources,
            })
            .collect::<Vec<_>>();
        let guards = core
            .reserve_batch(&requests)
            .map_err(|error| NodeCoreError::Redb(error.to_string()))?;
        scope.guards.extend(guards);
        Ok(())
    })
}

pub(crate) fn allocate(
    core: &Arc<PublicationCore>,
    target: &str,
    id: &str,
) -> Result<u64, NodeCoreError> {
    CURRENT.with(|current| {
        let mut current = current.borrow_mut();
        let scope = current
            .as_mut()
            .ok_or_else(|| NodeCoreError::Redb("allocation requires publication scope".into()))?;
        if let Some(guard) = scope.guards.iter().find(|guard| {
            guard.descriptor.key.target == target
                && !scope.assigned.contains(&(target.into(), guard.sequence()))
        }) {
            let sequence = guard.sequence();
            scope.assigned.insert((target.into(), sequence));
            return Ok(sequence);
        }
        let guard = core
            .reserve(target, id, &scope.resources)
            .map_err(|error| NodeCoreError::Redb(error.to_string()))?;
        let sequence = guard.sequence();
        scope.assigned.insert((target.into(), sequence));
        scope.guards.push(guard);
        Ok(sequence)
    })
}

pub(crate) fn hand_off(entries: &[&InboxEntry]) -> Result<Vec<PublicationWrite>, NodeCoreError> {
    CURRENT.with(|current| {
        let current = current.borrow();
        let Some(scope) = current.as_ref() else {
            return Ok(Vec::new());
        };
        scope
            .guards
            .iter()
            .filter(|guard| {
                entries.iter().any(|entry| {
                    entry.target_delivery_id == guard.descriptor.key.target
                        && entry.inbox_seq == guard.sequence()
                })
            })
            .map(|guard| {
                guard
                    .hand_off()
                    .ok_or_else(|| NodeCoreError::Redb("assignment hand-off lost".into()))
            })
            .collect()
    })
}

pub(crate) fn complete_unassigned() {
    CURRENT.with(|current| {
        if let Some(scope) = current.borrow().as_ref()
            && scope.guards.is_empty()
            && let Some(core) = &scope.core
        {
            core.complete_unassigned(&scope.resources);
        }
    });
}
