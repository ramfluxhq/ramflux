// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Independent ACK progress and bounded retry parking for prepared sibling targets.
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub(super) struct Target {
    device: String,
    attempts: u32,
    next_at: i64,
    acknowledged: bool,
}

impl Target {
    pub(super) fn new(device: String, attempts: u32, next_at: i64) -> Self {
        Self { device, attempts, next_at, acknowledged: false }
    }
    pub(super) fn due(&self, now: i64) -> bool {
        !self.finished() && self.next_at <= now
    }
    pub(super) fn finished(&self) -> bool {
        self.acknowledged || self.attempts >= 10
    }
    pub(super) fn acknowledged(&self) -> bool {
        self.acknowledged
    }
    pub(super) fn charge(&mut self, now: i64) {
        if self.due(now) {
            self.attempts += 1;
            self.next_at = now.saturating_add((1_i64 << self.attempts.min(6)).min(60));
        }
    }
    pub(super) fn park_after_attempt(&mut self, now: i64) {
        if !self.acknowledged {
            self.next_at = now.saturating_add((1_i64 << self.attempts.min(6)).min(60));
        }
    }
    pub(super) fn confirm(&mut self, delivered: &[String]) {
        self.acknowledged |= delivered.iter().any(|device| device == &self.device);
    }
}
