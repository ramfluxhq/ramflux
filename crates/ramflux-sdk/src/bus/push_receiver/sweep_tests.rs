// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Named P23 scheduler cells. Logical clock only; no wall-clock waits.
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use super::sweep::{Planner, ResumeKind, SweepMode, SweepSetting, View};
use std::sync::OnceLock;

fn live(generation: u64) -> View {
    View { live: true, generation, resync: false }
}

/// Decide, then report a successful pass (the live loop's `finish` call).
fn fire(planner: &mut Planner, now_ms: u64, generation: u64) -> Option<ResumeKind> {
    let kind = planner.decide(now_ms, live(generation))?;
    planner.finish(now_ms, now_ms, generation, true, false);
    Some(kind)
}

/// Decide, then report a failed pass that finished at `finished_ms`.
fn fail(planner: &mut Planner, now_ms: u64, finished_ms: u64, view: View) -> Option<ResumeKind> {
    let kind = planner.decide(now_ms, view)?;
    planner.finish(now_ms, finished_ms, view.generation, false, false);
    Some(kind)
}

fn default_push() -> Planner {
    Planner::new(&SweepSetting::parse(None, None, None), SweepMode::Push)
}

/// Default 900 s; clamp 60..=3600; deprecated vars one warning flag and no effect.
#[test]
fn sweep_setting() {
    let default = SweepSetting::parse(None, None, None);
    assert_eq!(default.push_secs, 900);
    assert!(!default.deprecated_ignored);
    assert_eq!(SweepSetting::parse(Some("60"), None, None).push_secs, 60);
    assert_eq!(SweepSetting::parse(Some("59"), None, None).push_secs, 60);
    assert_eq!(SweepSetting::parse(Some("3600"), None, None).push_secs, 3600);
    assert_eq!(SweepSetting::parse(Some("3601"), None, None).push_secs, 3600);
    assert_eq!(SweepSetting::parse(Some("abc"), None, None).push_secs, 900);
    let deprecated = SweepSetting::parse(None, Some("250"), Some("5000"));
    assert!(deprecated.deprecated_ignored);
    assert_eq!(deprecated.push_secs, 900);
    assert_eq!(SweepSetting::parse(Some("120"), Some("1"), None).push_secs, 120);
    let once = OnceLock::new();
    let warnings = WarnLog::default();
    tracing::subscriber::with_default(warnings.clone(), || {
        deprecated.emit_deprecated_warning(&once);
        deprecated.emit_deprecated_warning(&once);
    });
    let logs = warnings.0.lock().unwrap();
    assert_eq!(logs.len(), 1, "deprecated env warns once: {logs:?}");
    assert!(logs[0].contains("RAMFLUX_SESSION_SAFETY_SWEEP_SECS"), "{logs:?}");
    assert_eq!(SweepSetting::parse(Some(" 120"), None, None).push_secs, 120);
    assert_eq!(SweepSetting::parse(Some("120 "), None, None).push_secs, 120);
    assert_eq!(SweepSetting::parse(Some(" 0 "), None, None).push_secs, 60);
    assert_eq!(SweepSetting::parse(Some("99999999999999999999"), None, None).push_secs, 3600);
    assert_eq!(SweepSetting::parse(Some("18446744073709551616"), None, None).push_secs, 3600);
    assert_eq!(SweepSetting::parse(Some("   "), None, None).push_secs, 900);
    assert_eq!(SweepSetting::parse(Some("-5"), None, None).push_secs, 900);
    let mut premature = Planner::new(&default, SweepMode::Push);
    assert_eq!(fire(&mut premature, 0, 1), Some(ResumeKind::Connected));
    assert_eq!(premature.decide(60_000, live(1)), None, "default 60s would Resume here");
    let mut compat = Planner::new(&default, SweepMode::Compat);
    assert_eq!(fire(&mut compat, 0, 1), Some(ResumeKind::Connected));
    assert_eq!(compat.decide(5_000, live(1)), Some(ResumeKind::Sweep));
}

/// One initial Resume within 100 ms; none until 900 s; probe/gap/retry held.
#[test]
fn connected_and_sweep() {
    let mut planner = default_push();
    let mut resumes = Vec::new();
    if let Some(kind) = fire(&mut planner, 0, 1) {
        resumes.push((0_u64, kind));
    }
    planner.held_probe = true;
    planner.held_gap = true;
    planner.held_retry = true;
    let in_100ms = resumes.iter().filter(|(at, _)| *at <= SweepSetting::CATCH_UP_MS).count();
    assert_eq!(in_100ms, 1, "Connected catch-up Resume within 100ms");
    assert_eq!(planner.decide(SweepSetting::CATCH_UP_MS, live(1)), None);
    assert_eq!(planner.decide(899_999, live(1)), None);
    assert_eq!(resumes.len(), 1);
    assert_eq!(planner.decide(900_000, live(1)), Some(ResumeKind::Sweep));
    assert!(planner.held_probe && planner.held_gap && planner.held_retry);
}

/// Initial catch-up then idle: no Resume in the old 5 s poll window (P25 completes Deliver).
#[test]
fn push_without_polling() {
    let mut planner = default_push();
    assert_eq!(fire(&mut planner, 0, 1), Some(ResumeKind::Connected));
    for idle_ms in [1_000, 5_000, 10_000, 30_000, 899_999] {
        assert_eq!(
            planner.decide(idle_ms, live(1)),
            None,
            "idle Resume at {idle_ms} ms; old 5s schedule would have ticked"
        );
    }
}

/// Connected failure is not marked handled: retried after the 250 ms backoff, never parked.
#[test]
fn connected_and_sweep_retries_failed_connected() {
    let mut planner = default_push();
    assert_eq!(fail(&mut planner, 0, 0, live(1)), Some(ResumeKind::Connected));
    assert_eq!(planner.wake_at_ms(0), Some(250), "failed Connected must not park");
    assert_eq!(planner.decide(249, live(1)), None, "no re-fire inside backoff");
    assert_eq!(fire(&mut planner, 250, 1), Some(ResumeKind::Connected));
    assert_eq!(planner.decide(251, live(1)), None, "success marks the generation handled");
}

/// Repeated Connected failures double the backoff, capped at 5 s.
#[test]
fn connected_and_sweep_backoff_doubles_and_caps() {
    let mut planner = default_push();
    let mut now = 0_u64;
    let mut gaps = Vec::new();
    for _ in 0..7 {
        assert_eq!(fail(&mut planner, now, now, live(1)), Some(ResumeKind::Connected));
        let next = planner.wake_at_ms(now).expect("retry scheduled");
        gaps.push(next - now);
        now = next;
    }
    assert_eq!(gaps, vec![250, 500, 1_000, 2_000, 4_000, 5_000, 5_000]);
}

/// Failed idle Sweep does not re-fire immediately; the next attempt waits the backoff.
#[test]
fn connected_and_sweep_failed_sweep_backs_off() {
    let mut planner = default_push();
    assert_eq!(fire(&mut planner, 0, 1), Some(ResumeKind::Connected));
    assert_eq!(fail(&mut planner, 900_000, 900_000, live(1)), Some(ResumeKind::Sweep));
    assert_eq!(planner.decide(900_000, live(1)), None, "no immediate re-fire");
    assert!(planner.wake_at_ms(900_000).is_some_and(|at| at >= 900_250));
    assert_eq!(planner.decide(900_249, live(1)), None);
    assert_eq!(planner.decide(900_250, live(1)), Some(ResumeKind::Sweep));
}

/// Failed Resync keeps the resync flag set but waits the backoff before re-firing.
#[test]
fn connected_and_sweep_failed_resync_backs_off() {
    let mut planner = default_push();
    assert_eq!(fire(&mut planner, 0, 1), Some(ResumeKind::Connected));
    let resync = View { live: true, generation: 1, resync: true };
    assert_eq!(fail(&mut planner, 1_000, 1_000, resync), Some(ResumeKind::Resync));
    assert_eq!(planner.decide(1_000, resync), None, "no immediate re-fire");
    assert_eq!(planner.wake_at_ms(1_000), Some(1_250));
    assert_eq!(planner.decide(1_249, resync), None);
    assert_eq!(planner.decide(1_250, resync), Some(ResumeKind::Resync));
}

/// A reconnect during backoff fires Connected immediately and starts backoff at 250 ms.
#[test]
fn connected_and_sweep_resets_backoff_on_generation_change() {
    let mut planner = default_push();
    assert_eq!(fail(&mut planner, 0, 0, live(1)), Some(ResumeKind::Connected));
    assert_eq!(planner.decide(100, live(1)), None, "same generation honours backoff");
    assert_eq!(
        planner.decide(100, live(2)),
        Some(ResumeKind::Connected),
        "new generation ignores leftover backoff"
    );
    assert_eq!(fail(&mut planner, 100, 100, live(2)), Some(ResumeKind::Connected));
    assert_eq!(
        planner.wake_at_ms(100),
        Some(350),
        "first fail on the new generation starts at 250"
    );
    assert_eq!(planner.decide(349, live(2)), None);
    assert_eq!(planner.decide(350, live(2)), Some(ResumeKind::Connected));
}

/// A paused success does not anchor the idle sweep.
#[test]
fn connected_and_sweep_paused_does_not_anchor() {
    let mut planner = default_push();
    assert_eq!(planner.decide(0, live(1)), Some(ResumeKind::Connected));
    planner.finish(0, 40, 1, true, true);
    assert_eq!(planner.decide(40, live(1)), None, "generation is handled");
    assert_eq!(planner.decide(900_000, live(1)), None, "paused pass does not start the 900s sweep");
}

#[derive(Clone, Default)]
struct WarnLog(std::sync::Arc<std::sync::Mutex<Vec<String>>>);

impl tracing::Subscriber for WarnLog {
    fn enabled(&self, metadata: &tracing::Metadata<'_>) -> bool {
        *metadata.level() == tracing::Level::WARN
    }
    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }
    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
    fn event(&self, event: &tracing::Event<'_>) {
        struct Fields(String);
        impl tracing::field::Visit for Fields {
            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                use std::fmt::Write;
                let _ = write!(self.0, "{field}={value:?} ");
            }
            fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
                use std::fmt::Write;
                let _ = write!(self.0, "{field}={value} ");
            }
        }
        let mut fields = Fields(String::new());
        event.record(&mut fields);
        self.0.lock().unwrap().push(format!("{} {}", event.metadata().name(), fields.0));
    }
    fn enter(&self, _: &tracing::span::Id) {}
    fn exit(&self, _: &tracing::span::Id) {}
}
