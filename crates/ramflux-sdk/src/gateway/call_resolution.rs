// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Decisions belong to pending operations, never to a session-wide media slot.

use crate::SdkError;
use ramflux_protocol::{CallResolution, CallSubmitContext};
use std::collections::BTreeMap;
use tokio::time::Instant;

const SESSION_PENDING_LIMIT: usize = 64;
const CALL_PENDING_LIMIT: usize = 8;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum CallOperationAction {
    Invite,
    Ringing,
    Answer,
    Continue,
    Reject,
    End,
}

impl CallOperationAction {
    pub(crate) fn from_control(control: &ramflux_protocol::CallControl) -> Self {
        use ramflux_protocol::CallAction;
        match &control.body {
            CallAction::Invite { .. } => Self::Invite,
            CallAction::Ringing => Self::Ringing,
            CallAction::Answer { .. } => Self::Answer,
            CallAction::Ack { .. }
            | CallAction::Ready { .. }
            | CallAction::Rekey { .. }
            | CallAction::RekeyAck { .. } => Self::Continue,
            CallAction::Reject | CallAction::Busy | CallAction::AnsweredElsewhere => Self::Reject,
            CallAction::Hangup | CallAction::Timeout | CallAction::Failed => Self::End,
        }
    }
}

#[derive(Default)]
pub(crate) struct PendingCalls {
    entries: BTreeMap<CallSubmitContext, Pending>,
}

struct Pending {
    deadline: Instant,
    decision: Option<CallResolution>,
    conflict: bool,
}

/// Returned through the courier; the account writer must still recheck its `LiveCall`.
#[derive(Clone)]
pub(crate) struct CallSubmitOutcome {
    pub(crate) context: CallSubmitContext,
    pub(crate) decision: CallResolution,
    pub(crate) action: CallOperationAction,
    pub(crate) deadline: Instant,
}

impl CallSubmitOutcome {
    pub(crate) fn permits_media(&self) -> bool {
        use ramflux_protocol::CallResolutionState as State;
        Instant::now() < self.deadline
            && self.context == self.decision.context
            && self.decision.consistent()
            && self.decision.media_allowed
            && match self.action {
                CallOperationAction::Invite | CallOperationAction::Ringing => {
                    matches!(self.decision.state, State::Ringing | State::Answered)
                }
                CallOperationAction::Answer | CallOperationAction::Continue => {
                    self.decision.state == State::Answered
                }
                CallOperationAction::Reject | CallOperationAction::End => false,
            }
    }
}

fn refused(reason: &str) -> SdkError {
    SdkError::GatewaySessionRejected(reason.to_owned())
}

impl PendingCalls {
    pub(crate) fn install(
        &mut self,
        context: CallSubmitContext,
        deadline: Instant,
    ) -> Result<(), SdkError> {
        context.validate()?;
        self.entries.retain(|_, entry| entry.deadline > Instant::now());
        if self.entries.contains_key(&context)
            || self.entries.len() >= SESSION_PENDING_LIMIT
            || self.entries.keys().filter(|k| k.start_digest == context.start_digest).count()
                >= CALL_PENDING_LIMIT
        {
            return Err(refused("call_resolution_capacity"));
        }
        self.entries.insert(context, Pending { deadline, decision: None, conflict: false });
        Ok(())
    }

    pub(crate) fn observe(&mut self, resolution: CallResolution) {
        let Some(pending) = self.entries.get_mut(&resolution.context) else { return };
        if pending.deadline <= Instant::now() {
            return;
        }
        if !resolution.consistent()
            || pending.decision.as_ref().is_some_and(|prior| prior != &resolution)
        {
            pending.conflict = true;
        } else {
            pending.decision = Some(resolution);
        }
    }

    pub(crate) fn decision(
        &self,
        context: &CallSubmitContext,
    ) -> Result<Option<CallResolution>, SdkError> {
        let pending =
            self.entries.get(context).ok_or_else(|| refused("call_resolution_retired"))?;
        if pending.conflict {
            return Err(refused("call_resolution_conflict"));
        }
        if pending.deadline <= Instant::now() {
            return Err(refused("call_resolution_timeout"));
        }
        Ok(pending.decision.clone())
    }

    pub(crate) fn retire(&mut self, context: &CallSubmitContext) {
        self.entries.remove(context);
    }
}

#[cfg(test)]
mod tests;
