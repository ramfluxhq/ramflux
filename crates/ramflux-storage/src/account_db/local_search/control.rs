// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Shared cancellation is atomic and never waits behind the SQLite worker queue.
use super::{MAX_VM_STEPS, SearchError, SearchResult, VM_CALLBACK_STEPS};
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use std::time::{Duration, Instant};

#[derive(Clone)]
pub struct SearchControl {
    cancelled: Arc<AtomicBool>,
    steps: Arc<AtomicUsize>,
    deadline: Instant,
}
impl SearchControl {
    #[must_use]
    pub fn new() -> Self {
        let now = Instant::now();
        Self {
            cancelled: Arc::new(AtomicBool::new(false)),
            steps: Arc::new(AtomicUsize::new(0)),
            deadline: now.checked_add(Duration::from_millis(100)).unwrap_or(now),
        }
    }
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }
    /// # Errors
    /// Distinguishes cancellation from the cooperative execution/work deadline.
    pub fn check(&self) -> SearchResult<()> {
        if self.cancelled.load(Ordering::Acquire) {
            return Err(SearchError::Cancelled);
        }
        if Instant::now() >= self.deadline || self.steps.load(Ordering::Acquire) >= MAX_VM_STEPS {
            return Err(SearchError::Deadline);
        }
        Ok(())
    }
    pub(crate) fn vm_interrupt(&self) -> bool {
        self.steps.fetch_add(
            usize::try_from(VM_CALLBACK_STEPS).unwrap_or(MAX_VM_STEPS),
            Ordering::AcqRel,
        );
        self.check().is_err()
    }
    #[must_use]
    pub fn vm_steps(&self) -> usize {
        self.steps.load(Ordering::Acquire)
    }
}
impl Default for SearchControl {
    fn default() -> Self {
        Self::new()
    }
}
