// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Dormant Connected catch-up and anchored safety sweep (S6b P23).
//!
//! Live `connection_manager::receive::run` keeps the 250 ms–5 s tick until P24
//! activation. Tests drive this planner with a logical millisecond clock.

use std::sync::OnceLock;
use std::time::Duration;

/// Push safety-sweep interval parsed once at process start.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SweepSetting {
    pub push_secs: u64,
    pub deprecated_ignored: bool,
}

/// Push uses [`SweepSetting::push_secs`]; compat is always 5 s.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SweepMode {
    Push,
    Compat,
}

/// One Resume-class catch-up the planner may emit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ResumeKind {
    Connected,
    Sweep,
    Resync,
}

/// Live-session snapshot the planner reads. Probe/gap/retry stay on the planner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct View {
    pub live: bool,
    pub generation: u64,
    pub resync: bool,
}

/// Logical-clock catch-up / sweep planner. `now_ms` is never wall time.
pub(crate) struct Planner {
    interval_ms: u64,
    seen_generation: Option<u64>,
    last_completed_ms: Option<u64>,
    pub held_probe: bool,
    pub held_gap: bool,
    pub held_retry: bool,
}

impl SweepSetting {
    pub const DEFAULT_PUSH_SECS: u64 = 900;
    pub const COMPAT_SECS: u64 = 5;
    pub const CATCH_UP_MS: u64 = 100;
    pub const MIN_SECS: u64 = 60;
    pub const MAX_SECS: u64 = 3600;

    /// Pure parser: clamp 60..=3600, default 900. Deprecated vars never change the value.
    #[must_use]
    pub(crate) fn parse(
        sweep_secs: Option<&str>,
        deprecated_min_ms: Option<&str>,
        deprecated_max_ms: Option<&str>,
    ) -> Self {
        let push_secs = sweep_secs
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(Self::DEFAULT_PUSH_SECS)
            .clamp(Self::MIN_SECS, Self::MAX_SECS);
        Self {
            push_secs,
            deprecated_ignored: deprecated_min_ms.is_some() || deprecated_max_ms.is_some(),
        }
    }

    /// Process-start snapshot. Warns once when deprecated env vars are present.
    #[must_use]
    pub(crate) fn from_process() -> Self {
        static SETTING: OnceLock<SweepSetting> = OnceLock::new();
        SETTING
            .get_or_init(|| {
                let parsed = Self::parse(
                    std::env::var("RAMFLUX_SESSION_SAFETY_SWEEP_SECS").ok().as_deref(),
                    std::env::var("RAMFLUX_SYNC_MIN_MS").ok().as_deref(),
                    std::env::var("RAMFLUX_SYNC_MAX_MS").ok().as_deref(),
                );
                if parsed.deprecated_ignored {
                    tracing::warn!(
                        "RAMFLUX_SYNC_MIN_MS/RAMFLUX_SYNC_MAX_MS have no effect; use RAMFLUX_SESSION_SAFETY_SWEEP_SECS"
                    );
                }
                parsed
            })
            .clone()
    }

    #[must_use]
    pub(crate) fn interval(&self, mode: SweepMode) -> Duration {
        let secs = match mode {
            SweepMode::Push => self.push_secs,
            SweepMode::Compat => Self::COMPAT_SECS,
        };
        Duration::from_secs(secs)
    }
}

impl Planner {
    #[must_use]
    pub(crate) fn new(setting: &SweepSetting, mode: SweepMode) -> Self {
        Self {
            interval_ms: setting.interval(mode).as_millis().try_into().unwrap_or(u64::MAX),
            seen_generation: None,
            last_completed_ms: None,
            held_probe: false,
            held_gap: false,
            held_retry: false,
        }
    }

    /// Connected catch-up is immediate (the 100 ms bound is the test frame).
    #[must_use]
    pub(crate) fn decide(&self, now_ms: u64, view: View) -> Option<ResumeKind> {
        if !view.live {
            return None;
        }
        if self.connected_catch_up(view) {
            return Some(ResumeKind::Connected);
        }
        if view.resync {
            return Some(ResumeKind::Resync);
        }
        if let Some(done) = self.last_completed_ms
            && now_ms.saturating_sub(done) >= self.interval_ms
        {
            return Some(ResumeKind::Sweep);
        }
        None
    }

    /// Initial Connected catch-up. Removing this trigger zeroes the 100 ms Resume count.
    #[must_use]
    fn connected_catch_up(&self, view: View) -> bool {
        self.seen_generation != Some(view.generation)
    }

    pub(crate) fn note_generation(&mut self, generation: u64) {
        self.seen_generation = Some(generation);
    }

    /// Successful catch-up (not backpressure-stopped) anchors the idle sweep.
    pub(crate) fn note_completed(&mut self, now_ms: u64, backpressure: bool) {
        if !backpressure {
            self.last_completed_ms = Some(now_ms);
        }
    }

    /// Next sweep deadline in planner milliseconds, if a catch-up has completed.
    #[must_use]
    pub(crate) fn wake_at_ms(&self, now_ms: u64) -> Option<u64> {
        let done = self.last_completed_ms?;
        Some(done.saturating_add(self.interval_ms).max(now_ms))
    }
}
