// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Bound retry traffic across socket reconnects, including validated authentication races.
use std::time::Duration;
#[derive(Default)]
pub(super) struct ReconnectBackoff {
    failures: u32,
}
impl ReconnectBackoff {
    pub(super) fn failed(&mut self, attempt_duration: Duration) -> Duration {
        // A long-lived attempt already spaces traffic by at least the maximum retry interval.
        if attempt_duration >= Duration::from_secs(60) {
            self.failures = 0;
        }
        self.failures = self.failures.saturating_add(1);
        Duration::from_secs((1_u64 << self.failures.saturating_sub(1).min(6)).min(60))
    }
    pub(super) const fn failures(&self) -> u32 {
        self.failures
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn repeated_reconnect_failures_back_off_from_one_to_sixty_seconds() {
        let mut backoff = ReconnectBackoff::default();
        for (failures, seconds) in (1..).zip([1, 2, 4, 8, 16, 32, 60, 60, 60]) {
            assert_eq!(backoff.failed(Duration::ZERO), Duration::from_secs(seconds));
            assert_eq!(backoff.failures(), failures);
        }
    }
    #[test]
    fn a_sustained_connection_restores_the_initial_reconnect_delay() {
        let mut backoff = ReconnectBackoff::default();
        for _ in 0..10 {
            backoff.failed(Duration::from_secs(1));
        }
        assert_eq!(backoff.failed(Duration::from_secs(60)), Duration::from_secs(1));
        assert_eq!(backoff.failures(), 1);
    }
}
