// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Test-only observation of actual contention on the real admission mutex.
#[cfg(not(test))]
pub(super) type StateMutex = std::sync::Mutex<super::State>;

#[cfg(test)]
pub(super) struct StateMutex {
    inner: std::sync::Mutex<super::State>,
    observer: std::sync::Mutex<Option<std::sync::mpsc::Sender<()>>>,
}
#[cfg(test)]
impl StateMutex {
    pub(super) fn new(state: super::State) -> Self {
        Self { inner: std::sync::Mutex::new(state), observer: std::sync::Mutex::new(None) }
    }
    pub(super) fn observe_contention(&self, entered: std::sync::mpsc::Sender<()>) {
        *self.observer.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = Some(entered);
    }
    pub(super) fn try_lock(
        &self,
    ) -> std::sync::TryLockResult<std::sync::MutexGuard<'_, super::State>> {
        self.inner.try_lock()
    }
    pub(super) fn lock(&self) -> std::sync::LockResult<std::sync::MutexGuard<'_, super::State>> {
        match self.try_lock() {
            Ok(guard) => Ok(guard),
            Err(std::sync::TryLockError::Poisoned(error)) => Err(error),
            Err(std::sync::TryLockError::WouldBlock) => {
                let observer =
                    self.observer.lock().unwrap_or_else(std::sync::PoisonError::into_inner).take();
                if let Some(entered) = observer {
                    let _ = entered.send(());
                }
                self.inner.lock()
            }
        }
    }
}
