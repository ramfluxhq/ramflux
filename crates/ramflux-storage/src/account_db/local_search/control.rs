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
    #[cfg(test)]
    clock: Option<Arc<dyn Fn() -> Instant + Send + Sync>>,
}
impl SearchControl {
    #[must_use]
    pub fn new() -> Self {
        Self::starting_at(Instant::now())
    }
    fn starting_at(now: Instant) -> Self {
        Self {
            cancelled: Arc::new(AtomicBool::new(false)),
            steps: Arc::new(AtomicUsize::new(0)),
            deadline: now.checked_add(Duration::from_millis(100)).unwrap_or(now),
            #[cfg(test)]
            clock: None,
        }
    }
    #[cfg(test)]
    #[must_use]
    pub(super) fn with_clock(clock: Arc<dyn Fn() -> Instant + Send + Sync>) -> Self {
        let mut control = Self::starting_at(clock());
        control.clock = Some(clock);
        control
    }
    fn clock_now(&self) -> Instant {
        #[cfg(test)]
        if let Some(clock) = self.clock.as_ref() {
            return clock();
        }
        Instant::now()
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
        if self.clock_now() >= self.deadline || self.steps.load(Ordering::Acquire) >= MAX_VM_STEPS {
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicU64;

    #[test]
    fn local_search_control_pins_deadline_and_vm_limits() -> Result<(), Box<dyn std::error::Error>>
    {
        let base = Instant::now();
        let elapsed = Arc::new(AtomicU64::new(0));
        let selected = Arc::clone(&elapsed);
        let clock: Arc<dyn Fn() -> Instant + Send + Sync> = Arc::new(move || {
            base.checked_add(Duration::from_millis(selected.load(Ordering::Acquire)))
                .unwrap_or(base)
        });
        let control = SearchControl::with_clock(Arc::clone(&clock));
        assert!(control.check().is_ok(), "fresh work must be admitted");
        elapsed.store(99, Ordering::Release);
        assert!(control.check().is_ok(), "the declared deadline must not fire before 100 ms");
        elapsed.store(100, Ordering::Release);
        assert!(matches!(control.check(), Err(SearchError::Deadline)), "100 ms must stop work");
        control.cancel();
        assert!(
            matches!(control.check(), Err(SearchError::Cancelled)),
            "explicit cancellation wins"
        );

        elapsed.store(0, Ordering::Release);
        let control = SearchControl::with_clock(clock);
        let steps = usize::try_from(VM_CALLBACK_STEPS)?;
        assert!(
            steps > 0 && steps <= 1000,
            "VM admission checks must occur at least every 1000 steps"
        );
        let callbacks = 2_000_000_usize.div_ceil(steps);
        for _ in 1..callbacks {
            assert!(!control.vm_interrupt(), "VM work below the ceiling must remain admitted");
        }
        assert!(
            control.vm_interrupt(),
            "two million VM steps must stop work even with frozen time"
        );
        assert!(
            (2_000_000..2_001_000).contains(&control.vm_steps()),
            "VM interruption must respect the declared ceiling and callback granularity"
        );
        Ok(())
    }
}
