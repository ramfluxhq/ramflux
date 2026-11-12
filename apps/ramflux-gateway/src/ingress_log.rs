// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Fixed-cardinality ingress counters with at most one aggregate warning per interval.
use std::sync::{
    Mutex, OnceLock,
    atomic::{AtomicU64, Ordering},
};
use std::time::{Duration, Instant};

const SUMMARY_INTERVAL: Duration = Duration::from_secs(30);

#[derive(Clone, Copy)]
pub(crate) enum Event {
    Failure,
    NoChannelBinding,
    LegacyMigration,
}

#[derive(Clone, Copy, Debug, serde::Serialize)]
pub(crate) struct Counts {
    pub failures: u64,
    pub no_channel_binding: u64,
    pub legacy_migrations: u64,
}

#[derive(Default)]
struct Counters {
    totals: [AtomicU64; 3],
    last_summary: Mutex<Option<Instant>>,
}

impl Counters {
    fn snapshot(&self) -> Counts {
        Counts {
            failures: self.totals[0].load(Ordering::Relaxed),
            no_channel_binding: self.totals[1].load(Ordering::Relaxed),
            legacy_migrations: self.totals[2].load(Ordering::Relaxed),
        }
    }
    fn record_at(&self, event: Event, now: Instant) -> Option<Counts> {
        self.totals[event as usize].fetch_add(1, Ordering::Relaxed);
        let Ok(mut last) = self.last_summary.try_lock() else { return None };
        if last.is_some_and(|last| now.saturating_duration_since(last) < SUMMARY_INTERVAL) {
            return None;
        }
        *last = Some(now);
        Some(self.snapshot())
    }
}

fn counters() -> &'static Counters {
    static COUNTERS: OnceLock<Counters> = OnceLock::new();
    COUNTERS.get_or_init(Counters::default)
}

#[cfg(any(test, feature = "itest-http"))]
pub(crate) fn snapshot() -> Counts {
    counters().snapshot()
}

pub(crate) fn record(event: Event) {
    if let Some(counts) = counters().record_at(event, Instant::now()) {
        tracing::warn!(
            failures = counts.failures,
            no_channel_binding = counts.no_channel_binding,
            legacy_migrations = counts.legacy_migrations,
            "gateway ingress aggregate summary"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ingress_summary_is_rate_limited_and_counts_every_event() {
        let counters = Counters::default();
        let now = Instant::now();
        assert!(counters.record_at(Event::Failure, now).is_some());
        for _ in 0..100 {
            assert!(counters.record_at(Event::Failure, now).is_none());
        }
        assert!(
            counters.record_at(Event::NoChannelBinding, now + Duration::from_secs(29)).is_none()
        );
        let counts = counters.record_at(Event::LegacyMigration, now + SUMMARY_INTERVAL);
        assert!(matches!(
            counts,
            Some(Counts { failures: 101, no_channel_binding: 1, legacy_migrations: 1 })
        ));
    }
}
