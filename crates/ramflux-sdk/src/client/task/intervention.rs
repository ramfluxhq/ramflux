// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Identifies the assignee device and revision that opened the current intervention.
use super::{TaskHistory, invalid};
use crate::SdkError;
use ramflux_protocol::{NeedsMe, TaskState};
impl TaskHistory {
    pub(super) fn intervention_source(
        &self,
        step: &str,
        target: &NeedsMe,
    ) -> Result<(String, u64), SdkError> {
        let mut state = TaskState::default();
        let mut opening = None;
        for accepted in &self.events {
            let previous = state
                .task()
                .and_then(|t| t.steps.iter().find(|s| s.id == step))
                .and_then(|s| s.needs_me.clone());
            let event = accepted.carrier.verify(&accepted.public_key)?;
            let task = state
                .apply(&event, &accepted.carrier.signer(&accepted.public_key, &event)?)
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
