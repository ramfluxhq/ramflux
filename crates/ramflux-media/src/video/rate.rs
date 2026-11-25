// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Video rate control (V2.1): the V0 ladder and the target bitrate it drives
//! from feedback samples.
//!
//! Rules (V0, thresholds are unmeasured assumptions until QA):
//! - every 1 s, a sample with loss above 5%, delay growth above 100 ms or a
//!   local queue above 100 ms halves the target and steps the rung down;
//! - ten consecutive clean seconds (loss below 2%, queue below 50 ms) permit one
//!   rung up, never above the negotiated maximum;
//! - feedback older than 1 s steps down; older than 3 s pauses video;
//! - below the Low rung for 3 s pauses video.
//!
//! A pause is sticky until [`RateController::resume`], which the caller invokes
//! only after its own consent, lease and keyframe checks. Feedback never grants
//! authority.

use std::time::{Duration, Instant};

/// Evaluation period.
pub const TICK: Duration = Duration::from_secs(1);
/// Clean seconds needed before one rung up.
pub const CLEAN_SECONDS: u32 = 10;
/// Silence before a downshift.
pub const STALE_DOWNSHIFT: Duration = Duration::from_secs(1);
/// Silence before video pauses.
pub const STALE_PAUSE: Duration = Duration::from_secs(3);
/// Time below the Low rung before video pauses.
pub const LOW_PAUSE: Duration = Duration::from_secs(3);

/// One rung of the V0 ladder.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Rung {
    /// 320×180, 15 fps, 192 kbit/s.
    Low,
    /// 640×360, 24 fps, 450 kbit/s.
    Start,
    /// 960×540, 24 fps, 900 kbit/s.
    Medium,
    /// 1280×720, 30 fps, 1,500 kbit/s.
    High,
}

impl Rung {
    /// Every rung, lowest first.
    pub const ALL: [Rung; 4] = [Rung::Low, Rung::Start, Rung::Medium, Rung::High];

    /// Target video bitrate of the rung, bits per second.
    #[must_use]
    pub fn target_bps(self) -> u32 {
        match self {
            Rung::Low => 192_000,
            Rung::Start => 450_000,
            Rung::Medium => 900_000,
            Rung::High => 1_500_000,
        }
    }

    /// Landscape coded size of the rung (portrait transposes it).
    #[must_use]
    pub fn dimensions(self) -> (u32, u32) {
        match self {
            Rung::Low => (320, 180),
            Rung::Start => (640, 360),
            Rung::Medium => (960, 540),
            Rung::High => (1280, 720),
        }
    }

    /// Frame-rate ceiling of the rung.
    #[must_use]
    pub fn max_fps(self) -> u32 {
        match self {
            Rung::Low => 15,
            Rung::Start | Rung::Medium => 24,
            Rung::High => 30,
        }
    }

    /// The rung one step below, if any.
    #[must_use]
    pub fn below(self) -> Option<Rung> {
        match self {
            Rung::Low => None,
            Rung::Start => Some(Rung::Low),
            Rung::Medium => Some(Rung::Start),
            Rung::High => Some(Rung::Medium),
        }
    }

    /// The rung one step above, if any.
    #[must_use]
    pub fn above(self) -> Option<Rung> {
        match self {
            Rung::Low => Some(Rung::Start),
            Rung::Start => Some(Rung::Medium),
            Rung::Medium => Some(Rung::High),
            Rung::High => None,
        }
    }

    /// The highest rung whose target does not exceed `bps`, if any.
    #[must_use]
    pub fn for_target(bps: u32) -> Option<Rung> {
        Rung::ALL.iter().rev().copied().find(|rung| rung.target_bps() <= bps)
    }
}

/// What the rate controller learned from one feedback report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sample {
    /// Loss in per mille of the window (missing over expected).
    pub loss_per_mille: u32,
    /// Relative delay growth in microseconds (positive is growth).
    pub delay_growth_us: i64,
    /// Local send or encoder queue in milliseconds.
    pub queue_ms: u32,
}

/// Where video stands after the last evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Sending at the current rung.
    Active,
    /// Paused: stale feedback, the Low rung starved, or a fence.
    Paused,
}

/// The endpoint's video rate, driven by [`Sample`]s and a clock.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RateController {
    max: Rung,
    rung: Rung,
    target_bps: u32,
    mode: Mode,
    latest: Option<Sample>,
    last_report: Option<Instant>,
    last_tick: Option<Instant>,
    clean_ticks: u32,
    below_low_since: Option<Instant>,
}

impl RateController {
    /// Starts at the Start rung (or the maximum, if lower) under `max`.
    #[must_use]
    pub fn new(max: Rung) -> Self {
        let rung = Rung::Start.min(max);
        Self {
            max,
            rung,
            target_bps: rung.target_bps(),
            mode: Mode::Active,
            latest: None,
            last_report: None,
            last_tick: None,
            clean_ticks: 0,
            below_low_since: None,
        }
    }

    /// The current rung.
    #[must_use]
    pub fn rung(&self) -> Rung {
        self.rung
    }

    /// The current target bitrate, bits per second.
    #[must_use]
    pub fn target_bps(&self) -> u32 {
        self.target_bps
    }

    /// Active or paused.
    #[must_use]
    pub fn mode(&self) -> Mode {
        self.mode
    }

    /// Records a feedback sample received at `now`.
    pub fn on_report(&mut self, now: Instant, sample: Sample) {
        self.latest = Some(sample);
        self.last_report = Some(now);
    }

    /// Evaluates the rules when a full [`TICK`] has passed since the last evaluation.
    pub fn tick(&mut self, now: Instant) {
        let due = self.last_tick.is_none_or(|last| now.saturating_duration_since(last) >= TICK);
        if !due {
            return;
        }
        self.last_tick = Some(now);
        let silence = self.last_report.map(|at| now.saturating_duration_since(at));
        match silence {
            None => {}
            Some(age) if age >= STALE_PAUSE => self.pause(),
            Some(age) if age >= STALE_DOWNSHIFT => {
                self.clean_ticks = 0;
                self.step_down();
            }
            Some(_) => self.evaluate_sample(),
        }
        self.track_low(now);
    }

    fn evaluate_sample(&mut self) {
        let Some(sample) = self.latest else { return };
        let congested =
            sample.loss_per_mille > 50 || sample.delay_growth_us > 100_000 || sample.queue_ms > 100;
        let clean = sample.loss_per_mille < 20 && sample.queue_ms < 50;
        if congested {
            self.clean_ticks = 0;
            self.target_bps /= 2;
            self.step_down();
        } else if clean {
            self.clean_ticks = self.clean_ticks.saturating_add(1);
            if self.clean_ticks >= CLEAN_SECONDS {
                self.clean_ticks = 0;
                self.step_up();
            }
        } else {
            self.clean_ticks = 0;
        }
    }

    /// One rung down (Low stays at Low: the target may still fall below it,
    /// which [`Self::track_low`] turns into a pause).
    fn step_down(&mut self) {
        self.rung = self.rung.below().unwrap_or(self.rung);
        self.target_bps = self.target_bps.min(self.rung.target_bps());
    }

    fn step_up(&mut self) {
        if let Some(higher) = self.rung.above().filter(|rung| *rung <= self.max) {
            self.rung = higher;
            self.target_bps = higher.target_bps();
        }
    }

    fn pause(&mut self) {
        self.mode = Mode::Paused;
    }

    fn track_low(&mut self, now: Instant) {
        if self.rung == Rung::Low && self.target_bps < Rung::Low.target_bps() {
            let since = *self.below_low_since.get_or_insert(now);
            if now.saturating_duration_since(since) >= LOW_PAUSE {
                self.pause();
            }
        } else {
            self.below_low_since = None;
        }
    }

    /// Leaves the paused mode at the Low rung. The caller checks consent,
    /// lease, generation and keyframe state before calling this.
    pub fn resume(&mut self) {
        self.mode = Mode::Active;
        self.rung = Rung::Low;
        self.target_bps = Rung::Low.target_bps();
        self.clean_ticks = 0;
        self.below_low_since = None;
    }
}
