// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Identifies the assignee device and revision that opened the current intervention.
use super::{TaskHistory, invalid};
use crate::SdkError;
use ramflux_protocol::NeedsMe;
impl TaskHistory {
    pub(crate) fn intervention_source(
        &self,
        step: &str,
        target: &NeedsMe,
    ) -> Result<(String, u64), SdkError> {
        let mut state = self.checkpoint.as_ref().map(|c| c.state.clone()).unwrap_or_default();
        let mut opening = self
            .checkpoint
            .as_ref()
            .and_then(|c| c.openings.get(step))
            .filter(|(_, _, saved)| saved == target)
            .map(|(device, revision, _)| (device.clone(), *revision));
        for accepted in &self.events {
            let previous = state
                .task()
                .and_then(|t| t.steps.iter().find(|s| s.id == step))
                .and_then(|s| s.needs_me.clone());
            let event = accepted.carrier.verify(&accepted.public_key)?;
            let task = state
                .apply(&event, &accepted.carrier.signer(&accepted.public_key, &event))
                .map_err(|e| invalid(e.to_string()))?;
            let current =
                task.steps.iter().find(|s| s.id == step).and_then(|s| s.needs_me.as_ref());
            if current == Some(target) {
                if previous.as_ref() != Some(target) {
                    opening = Some((accepted.carrier.device_id.clone(), task.version));
                }
            } else {
                opening = None;
            }
        }
        opening.ok_or_else(|| invalid("task intervention has no authenticated opening"))
    }
}
