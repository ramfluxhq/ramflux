// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Plain-text task event summaries for text-only clients.
use super::{TaskDecision, TaskEvent, TaskEventBody, TaskStatus, TaskStep};
impl TaskEvent {
    /// Deterministic plain-text derivation; control characters cannot become terminal escapes.
    #[must_use]
    pub fn fallback_text(&self) -> String {
        let id = self.event.task_id();
        let lines = match &self.event {
            TaskEventBody::Start(v) => {
                let mut lines = vec![format!("Task {id} requested for {}: {}", v.assignee, v.text)];
                if let Some(c) = &v.constraints {
                    lines.push(format!("Constraints: {c}"));
                }
                lines
            }
            TaskEventBody::Proposal(v) => {
                let mut lines = vec![format!(
                    "Task {id} proposed by {} for {} (awaiting human acceptance): {}",
                    v.proposer, v.assignee, v.title
                )];
                lines.extend(step_lines(&v.steps));
                lines
            }
            TaskEventBody::Accept(_) => vec![format!("Task {id} accepted by a human")],
            TaskEventBody::Decline(_) => vec![format!("Task {id} declined by a human")],
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
                "Task {id}: human decision {} for step {} at {} (decision {})",
                match v.decision {
                    TaskDecision::Resume => "resume",
                    TaskDecision::Deny => "deny",
                },
                v.step_id,
                v.target.target_id(),
                v.decision_id
            )],
        };
        lines
            .join("\n")
            .chars()
            .map(|c| if c.is_control() && c != '\n' { ' ' } else { c })
            .collect()
    }
}
fn step_lines(steps: &[TaskStep]) -> Vec<String> {
    steps
        .iter()
        .map(|step| match &step.needs_me {
            Some(target) => format!(
                "{}: {} ({}) — needs human decision at {}",
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
