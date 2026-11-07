// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![allow(clippy::missing_errors_doc)]
#![allow(clippy::wildcard_imports)]
use crate::prelude::*;

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
