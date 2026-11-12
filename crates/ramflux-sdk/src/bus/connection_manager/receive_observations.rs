// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Process-owned receive observations. Counts include requests that fail on the wire.

use std::sync::{
    Mutex,
    atomic::{AtomicU64, Ordering},
};

#[derive(Clone, Debug, Default, serde::Serialize)]
pub(crate) struct Observation {
    pub deliver_frames: u64,
    pub resume_requests: u64,
    /// Point fetches for bodies omitted from Resume pages.
    pub page_fetches: u64,
    /// Catch-up passes started, including a pass later interrupted by process death.
    pub catch_up_passes: u64,
    /// Largest successful ACK sequence for the observed inbox incarnation in this process.
    pub last_acked_seq: u64,
}

#[derive(Default)]
pub(crate) struct Counters {
    deliver_frames: AtomicU64,
    resume_requests: AtomicU64,
    page_fetches: AtomicU64,
    catch_up_passes: AtomicU64,
    last_ack: Mutex<(String, u64)>,
    #[cfg(any(test, feature = "itest-memory-vault"))]
    committed_items: AtomicU64,
}

impl Counters {
    pub(crate) fn deliver(&self) {
        self.deliver_frames.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn resume(&self) {
        self.resume_requests.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn fetch(&self) {
        self.page_fetches.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn catch_up(&self) {
        self.catch_up_passes.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn acked(&self, incarnation: &str, sequence: u64) {
        let mut ack = self.last_ack.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if ack.0 != incarnation {
            incarnation.clone_into(&mut ack.0);
            ack.1 = 0;
        }
        ack.1 = ack.1.max(sequence);
    }

    pub(crate) fn acked_for(&self, incarnation: Option<&str>) -> u64 {
        let ack = self.last_ack.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if incarnation == Some(ack.0.as_str()) { ack.1 } else { 0 }
    }

    pub(crate) fn snapshot(&self) -> Observation {
        Observation {
            deliver_frames: self.deliver_frames.load(Ordering::Relaxed),
            resume_requests: self.resume_requests.load(Ordering::Relaxed),
            page_fetches: self.page_fetches.load(Ordering::Relaxed),
            catch_up_passes: self.catch_up_passes.load(Ordering::Relaxed),
            last_acked_seq: self
                .last_ack
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .1,
        }
    }

    /// Default builds contain neither the environment lookup nor the abort path.
    #[cfg(any(test, feature = "itest-memory-vault"))]
    pub(crate) fn committed(&self, before: u64, cursor: u64) {
        if cursor <= before {
            return;
        }
        let count = self.committed_items.fetch_add(1, Ordering::Relaxed) + 1;
        let threshold = std::env::var("RAMFLUX_TEST_CRASH_AFTER_COMMITS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok());
        if threshold == Some(count) {
            eprintln!(
                "RECEIVE_CRASH commits={count} cursor={cursor} last_acked_seq={}",
                self.snapshot().last_acked_seq
            );
            std::process::abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Counters;

    #[test]
    fn counters_move_independently_and_ack_high_water_never_regresses() {
        let counters = Counters::default();
        let zero = counters.snapshot();
        assert_eq!(zero.deliver_frames, 0);
        assert_eq!(zero.resume_requests, 0);
        assert_eq!(zero.page_fetches, 0);
        assert_eq!(zero.catch_up_passes, 0);
        assert_eq!(zero.last_acked_seq, 0);
        counters.deliver();
        assert_eq!(counters.snapshot().deliver_frames, 1);
        assert_eq!(counters.snapshot().resume_requests, 0);
        counters.resume();
        assert_eq!(counters.snapshot().resume_requests, 1);
        assert_eq!(counters.snapshot().page_fetches, 0);
        counters.fetch();
        assert_eq!(counters.snapshot().page_fetches, 1);
        assert_eq!(counters.snapshot().catch_up_passes, 0);
        counters.catch_up();
        assert_eq!(counters.snapshot().catch_up_passes, 1);
        assert_eq!(counters.snapshot().last_acked_seq, 0);
        counters.acked("epoch-a", 9);
        counters.acked("epoch-a", 3);
        assert_eq!(counters.snapshot().last_acked_seq, 9);
        assert_eq!(counters.acked_for(Some("epoch-a")), 9);
        assert_eq!(counters.acked_for(Some("epoch-b")), 0);
        counters.acked("epoch-b", 1);
        assert_eq!(counters.acked_for(Some("epoch-b")), 1);
    }
}
