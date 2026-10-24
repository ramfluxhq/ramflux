// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Wire limits and typed task rejection reasons.
use super::{TASK_EVENT_SCHEMA, TaskEvent, TaskEventBody, TaskStatus, TaskStep};
use crate::{ProtocolError, canonical_json_bytes, domain, signed_bytes};
use std::collections::BTreeSet;
pub const MAX_TASK_STEPS: usize = 64;
pub const MAX_TASK_TITLE_CHARS: usize = 256;
pub const MAX_TASK_TEXT_CHARS: usize = 16_384;
pub const MAX_TASK_EVENT_BYTES: usize = 65_536;
/// Largest exactly representable interoperable JSON integer.
pub const MAX_TASK_VERSION: u64 = 9_007_199_254_740_991;

/// Why a human receipt no longer matches its observed intervention.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TaskDecisionChange {
    Closed,
    TargetChanged,
    NewerThanObserved,
}

#[derive(Debug, thiserror::Error)]
pub enum TaskReject {
    #[error("unsupported task schema or schema version")]
    InvalidSchema,
    #[error("incorrect task signing domain")]
    InvalidDomain,
    #[error("invalid or oversized field: {0}")]
    InvalidField(&'static str),
    #[error("task event exceeds the canonical byte limit")]
    EventTooLarge,
    #[error("too many task steps")]
    TooManySteps,
    #[error("duplicate step identifier")]
    DuplicateStep,
    #[error("needs_me state and target disagree")]
    NeedsMeMismatch,
    #[error("more than one task intervention is open")]
    MultipleNeedsMe,
    #[error("invalid task revision")]
    InvalidVersion,
    #[error("expected task revision {expected}, received {actual}")]
    StaleVersion { expected: u64, actual: u64 },
    #[error("task signing identity or key differs from the authorized participant")]
    WrongSigner,
    #[error("task signature verification failed")]
    InvalidSignature,
    #[error("only a human may make this decision")]
    HumanRequired,
    #[error("only an automated participant may propose a task")]
    AgentRequired,
    #[error("task already exists")]
    AlreadyExists,
    #[error("task does not exist")]
    NotFound,
    #[error("event belongs to another task or conversation")]
    ContextMismatch,
    #[error("terminal task cannot change")]
    Terminal,
    #[error("illegal task or step transition")]
    IllegalTransition,
    #[error("assignee cannot resolve or replace an open human decision")]
    HumanDecisionPending,
    #[error("human decision does not match the current step and intervention")]
    DecisionMismatch,
    #[error("stale decision for step {step_id}: {change:?}")]
    StaleDecision { step_id: String, change: TaskDecisionChange },
    #[error("human decision or single-use approval was already consumed")]
    DecisionReplay,
    #[error("protocol encoding failed: {0}")]
    Protocol(#[from] ProtocolError),
}

pub(super) fn field(value: &str, name: &'static str, max: usize) -> Result<(), TaskReject> {
    if value.trim().is_empty()
        || value.chars().count() > max
        || !crate::text_safety::single_line_is_safe(value)
    {
        Err(TaskReject::InvalidField(name))
    } else {
        Ok(())
    }
}
pub(super) fn free_text(value: &str, name: &'static str) -> Result<(), TaskReject> {
    if value.trim().is_empty()
        || value.chars().count() > MAX_TASK_TEXT_CHARS
        || !crate::text_safety::free_text_is_safe(value)
    {
        Err(TaskReject::InvalidField(name))
    } else {
        Ok(())
    }
}
pub(super) fn steps(values: &[TaskStep]) -> Result<(), TaskReject> {
    if values.len() > MAX_TASK_STEPS {
        return Err(TaskReject::TooManySteps);
    }
    let mut ids = BTreeSet::new();
    let mut pending = 0;
    for step in values {
        field(&step.id, "step.id", 256)?;
        field(&step.title, "step.title", MAX_TASK_TITLE_CHARS)?;
        if !ids.insert(&step.id) {
            return Err(TaskReject::DuplicateStep);
        }
        if (step.state == TaskStatus::NeedsMe) != step.needs_me.is_some() {
            return Err(TaskReject::NeedsMeMismatch);
        }
        if let Some(target) = &step.needs_me {
            field(target.target_id(), "needs_me.target", 256)?;
            pending += 1;
        }
    }
    if pending > 1 {
        return Err(TaskReject::MultipleNeedsMe);
    }
    Ok(())
}
impl TaskEvent {
    /// Validates framing, scalar-count limits, intervention shape and total JCS size.
    /// # Errors
    /// Returns a typed reject for malformed framing, payload limits, or critical extensions.
    pub fn validate(&self) -> Result<(), TaskReject> {
        if self.fields().schema != TASK_EVENT_SCHEMA || self.fields().version != 1 {
            return Err(TaskReject::InvalidSchema);
        }
        if self.fields().domain != domain::TASK_EVENT {
            return Err(TaskReject::InvalidDomain);
        }
        field(&self.fields().conversation_id, "conversation_id", 256)?;
        field(self.fields().event.task_id(), "task_id", 256)?;
        field(&self.fields().signed.signing_key_id, "signing_key_id", 256)?;
        if !(1..=MAX_TASK_VERSION).contains(&self.fields().event.version()) {
            return Err(TaskReject::InvalidVersion);
        }
        match &self.fields().event {
            TaskEventBody::Start(v) => {
                if v.conversation_id != self.fields().conversation_id {
                    return Err(TaskReject::ContextMismatch);
                }
                field(&v.requester, "requester", 256)?;
                field(&v.assignee, "assignee", 256)?;
                free_text(&v.text, "text")?;
                if let Some(text) = &v.constraints {
                    free_text(text, "constraints")?;
                }
            }
            TaskEventBody::Proposal(v) => {
                if v.conversation_id != self.fields().conversation_id {
                    return Err(TaskReject::ContextMismatch);
                }
                field(&v.proposer, "proposer", 256)?;
                field(&v.assignee, "assignee", 256)?;
                field(&v.title, "title", MAX_TASK_TITLE_CHARS)?;
                steps(&v.steps)?;
            }
            TaskEventBody::Update(v) => {
                steps(&v.steps)?;
                if let Some(summary) = &v.result_summary {
                    free_text(summary, "result_summary")?;
                    if summary.chars().count() > 4096 {
                        return Err(TaskReject::InvalidField("result_summary"));
                    }
                }
                if let Some(reference) = &v.result_ref {
                    field(reference, "result_ref", 256)?;
                }
            }
            TaskEventBody::Resolve(v) => {
                field(&v.step_id, "step_id", 256)?;
                field(v.target.target_id(), "needs_me.target", 256)?;
                field(&v.decision_id, "decision_id", 256)?;
            }
            TaskEventBody::Accept(_) | TaskEventBody::Decline(_) | TaskEventBody::Cancel(_) => {}
        }
        if canonical_json_bytes(self)?.len() > MAX_TASK_EVENT_BYTES {
            return Err(TaskReject::EventTooLarge);
        }
        signed_bytes(self)?;
        Ok(())
    }
}
