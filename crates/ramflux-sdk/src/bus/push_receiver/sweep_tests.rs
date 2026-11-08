// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Named P23 scheduler cells. Logical clock only; no wall-clock waits.
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use super::sweep::{Planner, ResumeKind, SweepMode, SweepSetting, View};

fn live(generation: u64) -> View {
    View { live: true, generation, resync: false }
}

fn fire(planner: &mut Planner, now_ms: u64, generation: u64) -> Option<ResumeKind> {
    let kind = planner.decide(now_ms, live(generation))?;
    match kind {
        ResumeKind::Connected => {
            planner.note_generation(generation);
            planner.note_completed(now_ms, false);
        }
        ResumeKind::Sweep | ResumeKind::Resync => planner.note_completed(now_ms, false),
    }
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
