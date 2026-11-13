// SPDX-License-Identifier: BSD-3-Clause
use crate::CardError;
use std::{
    cell::RefCell,
    rc::Rc,
    sync::atomic::{AtomicUsize, Ordering},
    time::Duration,
};
use web_time::Instant;

pub(crate) const HEAP: usize = 32 * 1024 * 1024;
pub(crate) const STACK: usize = 256 * 1024;
const EVALUATION: Duration = Duration::from_millis(50);
const CUMULATIVE: Duration = Duration::from_millis(100);
const MAX_ADMISSIONS: usize = 128;
const MAX_RESIDENT_VMS: usize = 2;
const WINDOW: Duration = Duration::from_secs(1);
static RESIDENT: AtomicUsize = AtomicUsize::new(0);

pub(crate) struct Resident;
impl Resident {
    pub(crate) fn acquire() -> Result<Self, CardError> {
        RESIDENT
            .try_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                (n < MAX_RESIDENT_VMS).then_some(n + 1)
            })
            .map_err(|_| CardError::Limit("resident VMs"))?;
        Ok(Self)
    }
}
impl Drop for Resident {
    fn drop(&mut self) {
        RESIDENT.fetch_sub(1, Ordering::AcqRel);
    }
}
/// Retain recent durations for a rolling second, including evaluations that fail.
/// A maximum of 128 admissions also bounds bookkeeping for sub-clock operations.
pub(crate) struct Budget {
    recent: std::collections::VecDeque<(Instant, Duration)>,
    start: Instant,
    remaining: Duration,
    pub(crate) exhausted: bool,
}
impl Budget {
    pub(crate) fn new() -> Rc<RefCell<Self>> {
        Rc::new(RefCell::new(Self {
            recent: std::collections::VecDeque::default(),
            start: Instant::now(),
            remaining: EVALUATION,
            exhausted: false,
        }))
    }
    pub(crate) fn begin(&mut self) -> Result<(), CardError> {
        let now = Instant::now();
        while self.recent.front().is_some_and(|(end, _)| now.duration_since(*end) >= WINDOW) {
            self.recent.pop_front();
        }
        let spent: Duration = self.recent.iter().map(|(_, time)| *time).sum();
        if spent >= CUMULATIVE || self.recent.len() >= MAX_ADMISSIONS {
            return Err(CardError::Budget);
        }
        self.start = now;
        self.remaining = EVALUATION.min(CUMULATIVE.saturating_sub(spent));
        self.exhausted = false;
        Ok(())
    }
    pub(crate) fn interrupted(&mut self) -> bool {
        self.exhausted |= self.start.elapsed() >= self.remaining;
        self.exhausted
    }
    pub(crate) fn finish(&mut self) -> Result<(), CardError> {
        self.interrupted();
        self.recent.push_back((Instant::now(), self.start.elapsed()));
        if self.exhausted { Err(CardError::Budget) } else { Ok(()) }
    }
}

#[cfg(test)]
impl Budget {
    pub(crate) fn deny_for_test(&mut self) {
        self.recent.clear();
        for _ in 0..MAX_ADMISSIONS {
            self.recent.push_back((Instant::now(), Duration::ZERO));
        }
    }
    pub(crate) fn reset_for_test(&mut self) {
        self.recent.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rolling_budget_accounts_failed_work_and_bounds_admission() {
        let budget = Budget::new();
        let mut budget = budget.borrow_mut();
        budget.recent.push_back((Instant::now(), CUMULATIVE));
        assert!(
            matches!(budget.begin(), Err(CardError::Budget)),
            "recent work must exhaust cumulative allowance"
        );
        budget.recent.clear();
        budget.recent.push_back((
            Instant::now().checked_sub(WINDOW).expect("test: monotonic history"),
            CUMULATIVE,
        ));
        assert!(budget.begin().is_ok(), "expired work must leave the rolling window");
        budget.start = Instant::now().checked_sub(EVALUATION).expect("test: monotonic evaluation");
        assert!(
            matches!(budget.finish(), Err(CardError::Budget)),
            "overrun must be charged even if engine evaluation fails"
        );
        assert_eq!(budget.recent.len(), 1, "failed work must remain in accounting");
        budget.recent.clear();
        for _ in 0..MAX_ADMISSIONS {
            budget.recent.push_back((Instant::now(), Duration::ZERO));
        }
        assert!(budget.begin().is_err(), "sub-clock calls must not grow bookkeeping without bound");
    }
}
