// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![allow(clippy::missing_errors_doc)]
#![allow(clippy::wildcard_imports)]
use crate::prelude::*;

/// Pins the wall clock of the current test thread until dropped, so signed bytes are
/// deterministic.
#[cfg(test)]
pub(crate) struct FixedClock;

#[cfg(test)]
impl FixedClock {
    pub(crate) fn set(now: i64) -> Self {
        test_clock::set_frozen(Some(now));
        Self
    }
}

#[cfg(test)]
impl Drop for FixedClock {
    fn drop(&mut self) {
        test_clock::set_frozen(None);
    }
}

pub(crate) fn now_unix_timestamp() -> i64 {
    #[cfg(test)]
    if let Some(frozen) = test_clock::frozen() {
        return frozen;
    }
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| i64::try_from(duration.as_secs()).unwrap_or(i64::MAX))
}

/// Per-thread frozen clock so timing-sensitive tests do not depend on wall-clock progress.
#[cfg(test)]
pub(crate) mod test_clock {
    use std::cell::Cell;

    thread_local! {
        static FROZEN: Cell<Option<i64>> = const { Cell::new(None) };
    }

    pub(crate) fn frozen() -> Option<i64> {
        FROZEN.with(Cell::get)
    }

    /// Pins (or clears) this thread's clock; used by `FixedClock`.
    pub(crate) fn set_frozen(value: Option<i64>) {
        FROZEN.with(|cell| cell.set(value));
    }

    /// Freezes this thread's clock at the current time until the guard drops.
    pub(crate) struct FrozenClock;

    impl FrozenClock {
        pub(crate) fn freeze() -> Self {
            FROZEN.with(|cell| cell.set(None));
            FROZEN.with(|cell| cell.set(Some(super::now_unix_timestamp())));
            Self
        }
    }

    impl Drop for FrozenClock {
        fn drop(&mut self) {
            FROZEN.with(|cell| cell.set(None));
        }
    }
}
