// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Plain-text task event summaries for text-only clients.
use super::{TaskDecision, TaskEvent, TaskEventBody, TaskStatus, TaskStep};
impl TaskEvent {
    /// Deterministic quoted display after verification against the caller-pinned signing key.
    #[must_use]
    pub fn fallback_text(&self) -> String {
        self.fallback_text_with_actor_kind(false)
    }
    /// Renders the caller-verified actor-kind status without changing signed event bytes.
    #[must_use]
    pub fn fallback_text_with_actor_kind(&self, actor_kind_verified: bool) -> String {
        let actor = if actor_kind_verified { "" } else { " (actor kind unverified)" };
        let id = self.event().task_id();
        let lines = match self.event() {
            TaskEventBody::Start(v) => {
                let mut lines = vec![format!("Task {id} requested for {}: {}", v.assignee, v.text)];
                if let Some(c) = &v.constraints {
                    lines.push(format!("Constraints: {c}"));
                }
                lines
            }
            TaskEventBody::Proposal(v) => {
                let mut lines = vec![format!(
                    "Task {id} proposed by {} for {} (awaiting acceptance): {}",
                    v.proposer, v.assignee, v.title
                )];
                lines.extend(step_lines(&v.steps));
                lines
            }
            TaskEventBody::Accept(_) => vec![format!("Task {id} accepted{actor}")],
            TaskEventBody::Decline(_) => {
                vec![format!("Task {id} declined{actor}")]
            }
            TaskEventBody::Cancel(_) => vec![format!("Task {id} cancelled by its requester")],
            TaskEventBody::Update(v) => {
                let mut lines = vec![format!("Task {id}: {}", status(v.state))];
                lines.extend(step_lines(&v.steps));
                if let Some(reference) = &v.result_ref {
                    lines.push(format!("Result: {reference}"));
                }
                lines
            }
            TaskEventBody::Resolve(v) => vec![format!(
                "Task {id}: decision{actor} {} for step {} at {} (decision {})",
                match v.decision {
                    TaskDecision::Resume => "resume",
                    TaskDecision::Deny => "deny",
                },
                v.step_id,
                v.target.target_id(),
                v.decision_id
            )],
        };
        crate::text_safety::render_text_fallback(
            &self.signed().signing_key_id,
            self.event().kind(),
            &lines.join("\n"),
        )
    }
}
fn step_lines(steps: &[TaskStep]) -> Vec<String> {
    steps
        .iter()
        .map(|step| match &step.needs_me {
            Some(target) => format!(
                "{}: {} ({}) — needs decision at {}",
                step.id,
                step.title,
                status(step.state),
                target.target_id()
            ),
            None => format!("{}: {} ({})", step.id, step.title, status(step.state)),
        })
        .collect()
}
const fn status(value: TaskStatus) -> &'static str {
    match value {
        TaskStatus::Proposed => "proposed",
        TaskStatus::Running => "running",
        TaskStatus::NeedsMe => "needs_me",
        TaskStatus::Done => "done",
        TaskStatus::Failed => "failed",
        TaskStatus::Cancelled => "cancelled",
    }
}
