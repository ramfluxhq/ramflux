// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Same-thread local rebase scope over the shared all-worker generation fence.
use super::Connection;
use crate::{StorageError, account_writer::AccountWriter};
use rusqlite::Error;
use std::{
    cell::RefCell,
    sync::{
        Arc, Weak,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
thread_local! {
    static CURRENT: RefCell<Option<Permit>> = const { RefCell::new(None) };
}
#[derive(Clone)]
pub(super) struct Permit {
    owner: Weak<AccountWriter>,
    epoch: u64,
    deadline: Instant,
    retired: Arc<AtomicBool>,
    active: Arc<AtomicBool>,
}
fn busy() -> Error {
    Error::SqliteFailure(rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_BUSY), None)
}
impl Permit {
    pub(super) fn require_live(&self, epoch: u64) -> rusqlite::Result<()> {
        if self.epoch != epoch
            || self.retired.load(Ordering::Acquire)
            || !self.active.load(Ordering::Acquire)
        {
            return Err(Error::InvalidQuery);
        }
        if Instant::now() >= self.deadline {
            return Err(busy());
        }
        Ok(())
    }
    pub(super) fn retire(&self) {
        self.retired.store(true, Ordering::Release);
    }
}
pub(super) fn current(owner: &Arc<AccountWriter>) -> rusqlite::Result<Option<Permit>> {
    CURRENT.with(|slot| {
        let slot = slot.try_borrow().map_err(|_| Error::InvalidQuery)?;
        match slot.as_ref().filter(|scope| scope.owner.ptr_eq(&Arc::downgrade(owner))) {
            Some(scope) => {
                scope.require_live(scope.epoch)?;
                Ok(Some(scope.clone()))
            }
            None => Ok(None),
        }
    })
}
pub(crate) fn require_deadline() -> Result<(), StorageError> {
    CURRENT.with(|slot| {
        let slot = slot.try_borrow().map_err(|_| StorageError::PairingField("Busy"))?;
        if slot.as_ref().is_some_and(|scope| Instant::now() >= scope.deadline) {
            return Err(StorageError::PairingField("Busy"));
        }
        Ok(())
    })
}
struct Scope<'a> {
    selected: &'a mut u64,
    next: u64,
    permit: Permit,
}
impl Drop for Scope<'_> {
    fn drop(&mut self) {
        self.permit.active.store(false, Ordering::Release);
        // Even an uncertain selection or unwinding test cannot leave old workers live.
        if self.permit.retired.load(Ordering::Acquire) {
            *self.selected = self.next;
        }
        CURRENT.with(|slot| {
            if let Ok(mut slot) = slot.try_borrow_mut() {
                slot.take();
            }
        });
    }
}
impl Connection {
    pub(crate) fn with_generation_rebase<T, E>(
        &self,
        duration: Duration,
        action: impl FnOnce() -> Result<T, E>,
    ) -> Result<T, E>
    where
        E: From<StorageError>,
    {
        let owner = self
            .inner
            .account_writer
            .clone()
            .ok_or_else(|| E::from(StorageError::AuthorizationRejected))?;
        let mut selected = owner
            .generation
            .try_write()
            .map_err(|_| E::from(StorageError::PairingField("Busy")))?;
        let epoch = self.inner.account_generation;
        if *selected != epoch
            || !self.dispatch(|db| Ok(db.is_autocommit())).map_err(StorageError::from)?
        {
            return Err(StorageError::AuthorizationRejected.into());
        }
        let next =
            selected.checked_add(1).ok_or_else(|| E::from(StorageError::AuthorizationRejected))?;
        let permit = Permit {
            owner: Arc::downgrade(&owner),
            epoch,
            deadline: Instant::now() + duration,
            retired: Arc::new(AtomicBool::new(false)),
            active: Arc::new(AtomicBool::new(true)),
        };
        CURRENT.with(|slot| -> Result<(), E> {
            let mut slot =
                slot.try_borrow_mut().map_err(|_| E::from(StorageError::PairingField("Busy")))?;
            if slot.is_some() {
                return Err(StorageError::PairingField("Busy").into());
            }
            *slot = Some(permit.clone());
            Ok(())
        })?;
        let scope = Scope { selected: &mut selected, next, permit };
        let result = action();
        if !scope.permit.retired.load(Ordering::Acquire) && Instant::now() >= scope.permit.deadline
        {
            return Err(StorageError::PairingField("Busy").into());
        }
        result
    }
}

impl crate::AccountDb {
    /// Run only the fourth local target rebase under the shared all-writer fence.
    /// Local work must recheck its guards between bounded steps; no async/network work
    /// belongs here. A deadline refusal releases the fence without selecting a generation.
    /// # Errors
    /// Refuses another generation owner, changed selection, lost unlock or the ten-second cap.
    pub fn with_full_transfer_install_fence<T, E>(
        &self,
        action: impl FnOnce() -> Result<T, E>,
    ) -> Result<T, E>
    where
        E: From<StorageError>,
    {
        self.full_local_unlock_guard()?.require_unlocked()?;
        self.connection.with_generation_rebase(Duration::from_secs(10), action)
    }
}

#[cfg(test)]
mod tests;
