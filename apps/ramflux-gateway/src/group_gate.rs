// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Per-source counters of the anonymous group sessions (MLS-SPEC r1.2 2.1, O3). The counters
//! live in this process's memory only: they are never written to a store, a row, a log line or a
//! trace, and no session ever sees another session's counter. (The device pre-auth gate is not
//! used for group sessions because its admission checkpoint persists buckets keyed by source.)
use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock, PoisonError};
use std::time::Instant;

/// Length of one counting window.
const WINDOW_MS: u64 = 60_000;
/// Group sessions one source may open per window (beta default, TBD-MEAS).
const OPENS_PER_WINDOW: u32 = 240;
/// Group ops one source may send per window (beta default, TBD-MEAS).
const OPS_PER_WINDOW: u32 = 1_200;
/// Live group sessions one source may hold (beta default, TBD-MEAS).
const LIVE_MAX: u32 = 256;
/// Sources counted at once; at the bound a new source is refused until an old one is idle.
const SOURCES_MAX: usize = 65_536;

#[derive(Default)]
struct Counter {
    window_start_ms: u64,
    opens: u32,
    ops: u32,
    live: u32,
}

impl Counter {
    fn roll(&mut self, now_ms: u64) {
        if now_ms.saturating_sub(self.window_start_ms) >= WINDOW_MS {
            self.window_start_ms = now_ms;
            self.opens = 0;
            self.ops = 0;
        }
    }

    fn idle(&self, now_ms: u64) -> bool {
        self.live == 0 && now_ms.saturating_sub(self.window_start_ms) >= WINDOW_MS
    }
}

/// The counters of every source, keyed by the transport source key.
#[derive(Default)]
pub(crate) struct SourceGate {
    sources: Mutex<HashMap<String, Counter>>,
}

/// One live group session of a source; dropping it frees the live slot.
pub(crate) struct SourceGuard {
    gate: Arc<SourceGate>,
    source: String,
}

impl SourceGate {
    /// Counts one new session; the refusal is the status token for the client.
    pub(crate) fn begin(
        self: &Arc<Self>,
        source: &str,
        now_ms: u64,
    ) -> Result<SourceGuard, &'static str> {
        let mut sources = self.sources.lock().unwrap_or_else(PoisonError::into_inner);
        if sources.len() >= SOURCES_MAX && !sources.contains_key(source) {
            sources.retain(|_, counter| !counter.idle(now_ms));
            if sources.len() >= SOURCES_MAX {
                return Err("busy");
            }
        }
        let counter = sources.entry(source.to_owned()).or_default();
        counter.roll(now_ms);
        if counter.live >= LIVE_MAX || counter.opens >= OPENS_PER_WINDOW {
            return Err("rate_limited");
        }
        counter.live += 1;
        counter.opens += 1;
        Ok(SourceGuard { gate: Arc::clone(self), source: source.to_owned() })
    }

    fn release(&self, source: &str) {
        let mut sources = self.sources.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(counter) = sources.get_mut(source) {
            counter.live = counter.live.saturating_sub(1);
        }
    }

    fn op(&self, source: &str, now_ms: u64) -> bool {
        let mut sources = self.sources.lock().unwrap_or_else(PoisonError::into_inner);
        let Some(counter) = sources.get_mut(source) else {
            return false;
        };
        counter.roll(now_ms);
        if counter.ops >= OPS_PER_WINDOW {
            return false;
        }
        counter.ops += 1;
        true
    }
}

impl SourceGuard {
    /// Counts one op of this session; `false` when the source is over its window.
    pub(crate) fn allow_op(&self, now_ms: u64) -> bool {
        self.gate.op(&self.source, now_ms)
    }
}

impl Drop for SourceGuard {
    fn drop(&mut self) {
        self.gate.release(&self.source);
    }
}

/// The process-wide gate.
pub(crate) fn gate() -> &'static Arc<SourceGate> {
    static GATE: OnceLock<Arc<SourceGate>> = OnceLock::new();
    GATE.get_or_init(Arc::default)
}

/// Milliseconds on a process-local monotonic clock (never a wall-clock time of a session).
pub(crate) fn now_ms() -> u64 {
    static START: OnceLock<Instant> = OnceLock::new();
    u64::try_from(START.get_or_init(Instant::now).elapsed().as_millis()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opens_ops_and_live_sessions_are_counted_per_source_in_memory() {
        let gate = Arc::new(SourceGate::default());
        let mut held = Vec::new();
        // Opens reset each window; live sessions do not. The live cap can sit
        // above the open cap, so fill it across as many windows as that takes.
        let mut now = 0_u64;
        let windows = LIVE_MAX.div_ceil(OPENS_PER_WINDOW);
        for window in 0..windows {
            now = u64::from(window).saturating_mul(WINDOW_MS);
            let already = u32::try_from(held.len()).expect("test: held count fits");
            let batch = LIVE_MAX.saturating_sub(already).min(OPENS_PER_WINDOW);
            for _ in 0..batch {
                held.push(gate.begin("a", now).expect("test: below the live bound"));
            }
        }
        assert_eq!(
            u32::try_from(held.len()).expect("test: held count fits"),
            LIVE_MAX,
            "test: the live bound is reachable across open windows"
        );
        assert_eq!(gate.begin("a", now).err(), Some("rate_limited"), "test: at the live bound");
        assert!(gate.begin("b", now).is_ok(), "another source is not affected");
        held.truncate(1);
        let first = held.pop().expect("test: one guard left");
        let in_window = now.saturating_add(1);
        for _ in 0..OPS_PER_WINDOW {
            assert!(first.allow_op(in_window), "test: below the ops bound");
        }
        assert!(!first.allow_op(now.saturating_add(2)), "ops over the window");
        assert!(
            first.allow_op(now.saturating_add(WINDOW_MS).saturating_add(1)),
            "the window rolled"
        );
    }

    #[test]
    fn a_dropped_session_frees_its_slot_and_idle_sources_are_forgotten() {
        let gate = Arc::new(SourceGate::default());
        let guard = gate.begin("a", 0).expect("test: first session");
        drop(guard);
        let lock = gate.sources.lock().expect("test: lock");
        assert_eq!(lock.get("a").map(|counter| counter.live), Some(0));
        drop(lock);
        for index in 0..SOURCES_MAX {
            drop(gate.begin(&format!("s{index}"), 0));
        }
        assert_eq!(gate.begin("new", 1).err(), Some("busy"), "no idle source yet");
        assert!(gate.begin("new", WINDOW_MS + 1).is_ok(), "idle sources are purged");
    }

    #[test]
    fn opens_per_window_are_bounded() {
        let gate = Arc::new(SourceGate::default());
        for _ in 0..OPENS_PER_WINDOW {
            drop(gate.begin("a", 5).expect("test: below the open bound"));
        }
        assert_eq!(gate.begin("a", 6).err(), Some("rate_limited"));
        assert!(gate.begin("a", WINDOW_MS + 6).is_ok());
    }
}
