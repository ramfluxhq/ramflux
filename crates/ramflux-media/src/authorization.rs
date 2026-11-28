// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Worker-side authority fence. Closing it waits for the last send or render.

use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

/// Public, credential-free reason why media cannot run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GateReason {
    AudioInactive,
    CallNotActive,
    GatewayHold,
    LeaseUnavailable,
    Locked,
    Terminal,
    ResyncRequired,
}

/// A snapshot of the admission fence, never a grant supplied by a host.
#[derive(Clone, Copy, Debug)]
pub struct GateSnapshot {
    pub reason: Option<GateReason>,
    pub generation: u64,
    pub audio_active: bool,
    pub retired: bool,
}

pub(crate) struct State {
    reason: Option<GateReason>,
    pub generation: u64,
    audio_active: bool,
    /// Video authority: independent of `audio_active`, cleared when the gate closes for a new reason.
    video_active: bool,
    deadline: Option<Instant>,
    pub retired: bool,
}

impl State {
    /// Lease and retirement check shared by both tracks.
    fn live(&mut self) -> bool {
        if self.retired {
            return false;
        }
        if self.deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            self.close(Some(GateReason::LeaseUnavailable));
            self.retired = true;
        }
        !self.retired && self.reason.is_none()
    }

    pub fn admitted(&mut self) -> bool {
        self.live() && self.audio_active
    }

    /// Video admission: its own activation, same lease and reason fence.
    pub fn admitted_video(&mut self) -> bool {
        self.live() && self.video_active
    }

    fn close(&mut self, reason: Option<GateReason>) {
        if self.reason != reason || self.audio_active {
            if let Some(next) = self.generation.checked_add(1) {
                self.generation = next;
            } else {
                self.retired = true;
            }
            self.audio_active = false;
        }
        if self.reason != reason {
            self.video_active = false;
        }
        self.reason = reason;
    }
}

pub(crate) struct Authorization(Mutex<State>);

impl Authorization {
    pub fn new(lease: Option<Duration>) -> Self {
        Self(Mutex::new(State {
            reason: None,
            generation: 1,
            audio_active: lease.is_none(),
            video_active: false,
            deadline: lease.and_then(|lease| Instant::now().checked_add(lease)),
            retired: false,
        }))
    }

    pub fn lock(&self) -> MutexGuard<'_, State> {
        self.0.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    pub fn update(&self, reason: Option<GateReason>, lease: Duration, renewed: bool) {
        let mut state = self.lock();
        if state.retired {
            return;
        }
        // Expiry cannot be undone by a late renewal. The SDK must retire the call.
        if state.deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            state.close(Some(GateReason::LeaseUnavailable));
            state.retired = true;
            return;
        }
        if state.reason != reason {
            state.close(reason);
        }
        let Some(next) = Instant::now().checked_add(lease) else {
            state.close(Some(GateReason::LeaseUnavailable));
            state.retired = true;
            return;
        };
        state.deadline =
            Some(if renewed { next } else { state.deadline.map_or(next, |old| old.min(next)) });
    }

    pub fn activate(&self, active: bool) -> bool {
        let mut state = self.lock();
        let _ = state.admitted();
        if active && (state.retired || state.reason.is_some()) {
            return false;
        }
        if active {
            state.audio_active = true;
        } else {
            let reason = state.reason;
            state.close(reason);
        }
        true
    }

    /// Sets video authority. Refused once the gate is closed or retired. A
    /// video change never bumps the generation or touches audio.
    pub fn activate_video(&self, active: bool) -> bool {
        let mut state = self.lock();
        let _ = state.live();
        if active && (state.retired || state.reason.is_some()) {
            return false;
        }
        state.video_active = active;
        true
    }

    pub fn retire(&self, reason: GateReason) {
        let mut state = self.lock();
        state.close(Some(reason));
        state.retired = true;
    }

    pub fn snapshot(&self) -> GateSnapshot {
        let mut state = self.lock();
        let _ = state.admitted();
        GateSnapshot {
            reason: state.reason.or((!state.audio_active).then_some(GateReason::AudioInactive)),
            generation: state.generation,
            audio_active: state.audio_active,
            retired: state.retired,
        }
    }
}
