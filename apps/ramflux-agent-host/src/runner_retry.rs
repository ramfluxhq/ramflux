// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! An owner decision stays here until its POST succeeds or the approval expires.
//! A rate-limited preflight does not drop the frame.

use crate::{AgentBus, AgentHost, EngineProvider, Error, Result};
use ramflux_sdk::LocalBusFrame;
use std::time::{Duration, Instant};

pub(crate) struct HeldOwner {
    not_before: Instant,
    frame: LocalBusFrame,
}

const HELD_CAP: usize = 8;

impl<E: EngineProvider> AgentHost<E> {
    pub fn hold_owner(&mut self, frame: LocalBusFrame, retry_after_ms: u64) {
        if !approval_still_open(&frame) {
            return;
        }
        let delay = Duration::from_millis(retry_after_ms.min(120_000));
        let not_before = Instant::now() + delay;
        if let Some(existing) =
            self.held_owner.iter_mut().find(|held| held.frame.frame_id == frame.frame_id)
        {
            existing.not_before = not_before;
            existing.frame = frame;
            return;
        }
        if self.held_owner.len() >= HELD_CAP {
            eprintln!("agent host owner decision retry queue is full");
            return;
        }
        self.held_owner.push(HeldOwner { not_before, frame });
    }

    /// # Errors
    /// Returns when the host must stop. A failed or rate-limited POST keeps the frame.
    pub(crate) async fn flush_held_owner(&mut self, bus: &mut impl AgentBus) -> Result<()> {
        for frame in self.take_due() {
            match crate::runner_run_approval::forward(bus, &mut self.engine, &frame).await {
                Ok(()) => {}
                Err(error) if error.stops_host() => {
                    self.hold_owner(frame, 3_000);
                    return Err(error);
                }
                Err(Error::RateLimited { retry_after_ms }) => {
                    self.hold_owner(frame, retry_after_ms);
                }
                Err(error) => {
                    eprintln!("prx approval forward deferred: {error}");
                    self.hold_owner(frame, 3_000);
                }
            }
        }
        Ok(())
    }

    /// Posts due decisions while the agent bus is down. A successful POST consumes the frame.
    ///
    /// # Errors
    /// Returns when the host must stop. Any other POST failure keeps the frame.
    pub async fn flush_held_posts(&mut self) -> Result<()> {
        for frame in self.take_due() {
            match self.post_owner_decision(&frame).await {
                Ok(()) => {}
                Err(error) if error.stops_host() => {
                    self.hold_owner(frame, 3_000);
                    return Err(error);
                }
                Err(Error::RateLimited { retry_after_ms }) => {
                    self.hold_owner(frame, retry_after_ms);
                }
                Err(_) => {
                    self.hold_owner(frame, 3_000);
                }
            }
        }
        Ok(())
    }

    fn take_due(&mut self) -> Vec<LocalBusFrame> {
        let now = Instant::now();
        let mut waiting = Vec::new();
        let mut due = Vec::new();
        for held in std::mem::take(&mut self.held_owner) {
            if held.not_before > now {
                waiting.push(held);
            } else if approval_still_open(&held.frame) {
                due.push(held.frame);
            }
        }
        self.held_owner = waiting;
        due
    }
}

fn approval_still_open(frame: &LocalBusFrame) -> bool {
    let Some(raw) = frame.body.get("expires_at").and_then(serde_json::Value::as_str) else {
        return true;
    };
    if raw.is_empty() {
        return true;
    }
    let Ok(expires) =
        time::OffsetDateTime::parse(raw, &time::format_description::well_known::Rfc3339)
    else {
        return true;
    };
    time::OffsetDateTime::now_utc() < expires
}
