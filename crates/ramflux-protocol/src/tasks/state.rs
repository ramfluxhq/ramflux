// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Atomic pure task lifecycle and human decision authority.
use super::{
    MAX_TASK_VERSION, NeedsMe, TaskDecision, TaskEvent, TaskEventBody, TaskReject, TaskResolve,
    TaskSigner, TaskStatus, TaskStep,
};
use crate::ActorType;
use std::collections::{BTreeMap, BTreeSet};

/// Read-only snapshot; a proposal is provisional until `accepted` is true.
#[derive(Clone, Debug, serde::Serialize, PartialEq, Eq)]
pub struct Task {
    pub task_id: String,
    pub conversation_id: String,
    pub requester: Option<String>,
    pub proposer: Option<String>,
    pub assignee: String,
    pub title: String,
    pub text: Option<String>,
    pub constraints: Option<String>,
    pub version: u64,
    pub state: TaskStatus,
    pub steps: Vec<TaskStep>,
    pub result_ref: Option<String>,
    pub accepted: bool,
}
/// One task's verified state. Rejected events leave every field unchanged.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TaskState {
    task: Option<Task>,
    decisions: BTreeSet<String>,
    approvals: BTreeSet<String>,
    pending_since: BTreeMap<String, u64>,
}
impl TaskState {
    #[must_use]
    pub const fn task(&self) -> Option<&Task> {
        self.task.as_ref()
    }
    /// Verifies a signed event and applies it atomically to this task.
    ///
    /// The signer comes from the caller's authenticated identity, role and conversation ACL.
    /// A Resolve is a receipt of an already-verified external human decision, not a tool grant.
    /// # Errors
    /// Rejects invalid signatures, authority, context, revision, limits or transitions.
    pub fn apply(
        &mut self,
        event: &TaskEvent,
        signer: &TaskSigner<'_>,
    ) -> Result<&Task, TaskReject> {
        event.verify(signer)?;
        let mut next = self.clone();
        next.reduce(event, signer)?;
        *self = next;
        self.task.as_ref().ok_or(TaskReject::NotFound)
    }
    fn reduce(&mut self, event: &TaskEvent, signer: &TaskSigner<'_>) -> Result<(), TaskReject> {
        if matches!(event.event(), TaskEventBody::Start(_) | TaskEventBody::Proposal(_)) {
            if self.task.is_some() {
                return Err(TaskReject::AlreadyExists);
            }
            return self.initialize(event, signer);
        }
        let task = self.task.as_mut().ok_or(TaskReject::NotFound)?;
        if task.task_id != event.event().task_id()
            || task.conversation_id != event.conversation_id()
        {
            return Err(TaskReject::ContextMismatch);
        }
        if task.state.is_terminal() {
            return Err(TaskReject::Terminal);
        }
        let expected = task
            .version
            .checked_add(1)
            .filter(|n| *n <= MAX_TASK_VERSION)
            .ok_or(TaskReject::InvalidVersion)?;
        if let Some(base) = event.event().base_revision() {
            if base > task.version {
                return Err(TaskReject::StaleVersion { expected: task.version, actual: base });
            }
        } else if event.event().version() != expected {
            return Err(TaskReject::StaleVersion { expected, actual: event.event().version() });
        }
        match event.event() {
            TaskEventBody::Accept(_) | TaskEventBody::Decline(_) => {
                human(signer)?;
                if task.state != TaskStatus::Proposed {
                    return Err(TaskReject::IllegalTransition);
                }
                if task.proposer.as_deref() == Some(signer.principal_id) {
                    return Err(TaskReject::WrongSigner);
                }
                task.requester = Some(signer.principal_id.to_owned());
                task.accepted = matches!(event.event(), TaskEventBody::Accept(_));
                task.state =
                    if task.accepted { TaskStatus::Running } else { TaskStatus::Cancelled };
                if !task.accepted {
                    cancel_unfinished(&mut task.steps);
                }
            }
            TaskEventBody::Cancel(_) => {
                requester(task, signer)?;
                task.state = TaskStatus::Cancelled;
                cancel_unfinished(&mut task.steps);
            }
            TaskEventBody::Update(update) => {
                if signer.principal_id != task.assignee {
                    return Err(TaskReject::WrongSigner);
                }
                if !task.accepted {
                    return Err(TaskReject::IllegalTransition);
                }
                update_task(task, update, &self.approvals)?;
            }
            TaskEventBody::Resolve(resolution) => {
                requester(task, signer)?;
                if self.decisions.contains(&resolution.decision_id) {
                    return Err(TaskReject::DecisionReplay);
                }
                validate_resolution(task, resolution, &self.pending_since)?;
                resolve(task, resolution)?;
                self.decisions.insert(resolution.decision_id.clone());
                if let NeedsMe::Approval { grant_id } = &resolution.target {
                    self.approvals.insert(grant_id.clone());
                }
            }
            TaskEventBody::Start(_) | TaskEventBody::Proposal(_) => {
                return Err(TaskReject::AlreadyExists);
            }
        }
        self.pending_since
            .retain(|id, _| task.steps.iter().any(|s| &s.id == id && s.needs_me.is_some()));
        for step in task.steps.iter().filter(|s| s.needs_me.is_some()) {
            self.pending_since.entry(step.id.clone()).or_insert(expected);
        }
        task.version = expected;
        Ok(())
    }
    fn initialize(&mut self, event: &TaskEvent, signer: &TaskSigner<'_>) -> Result<(), TaskReject> {
        let task = match event.event() {
            TaskEventBody::Start(v) => {
                human(signer)?;
                if signer.principal_id != v.requester {
                    return Err(TaskReject::WrongSigner);
                }
                Task {
                    task_id: v.task_id.clone(),
                    conversation_id: v.conversation_id.clone(),
                    requester: Some(v.requester.clone()),
                    proposer: None,
                    assignee: v.assignee.clone(),
                    title: v
                        .text
                        .trim()
                        .lines()
                        .next()
                        .unwrap_or_default()
                        .chars()
                        .take(256)
                        .collect(),
                    text: Some(v.text.clone()),
                    constraints: v.constraints.clone(),
                    version: 1,
                    state: TaskStatus::Running,
                    steps: Vec::new(),
                    result_ref: None,
                    accepted: true,
                }
            }
            TaskEventBody::Proposal(v) => {
                if !matches!(signer.actor_type, ActorType::Bot | ActorType::Workflow) {
                    return Err(TaskReject::AgentRequired);
                }
                if signer.principal_id != v.proposer {
                    return Err(TaskReject::WrongSigner);
                }
                if v.steps.iter().any(|s| s.state != TaskStatus::Proposed) {
                    return Err(TaskReject::IllegalTransition);
                }
                Task {
                    task_id: v.task_id.clone(),
                    conversation_id: v.conversation_id.clone(),
                    requester: None,
                    proposer: Some(v.proposer.clone()),
                    assignee: v.assignee.clone(),
                    title: v.title.clone(),
                    text: None,
                    constraints: None,
                    version: 1,
                    state: TaskStatus::Proposed,
                    steps: v.steps.clone(),
                    result_ref: None,
                    accepted: false,
                }
            }
            _ => return Err(TaskReject::NotFound),
        };
        self.task = Some(task);
        Ok(())
    }
}
fn human(signer: &TaskSigner<'_>) -> Result<(), TaskReject> {
    if signer.actor_type == ActorType::Human { Ok(()) } else { Err(TaskReject::HumanRequired) }
}
fn requester(task: &Task, signer: &TaskSigner<'_>) -> Result<(), TaskReject> {
    human(signer)?;
    if task.requester.as_deref() != Some(signer.principal_id) {
        return Err(TaskReject::WrongSigner);
    }
    Ok(())
}
fn cancel_unfinished(steps: &mut [TaskStep]) {
    for step in steps {
        if !step.state.is_terminal() {
            step.state = TaskStatus::Cancelled;
        }
        step.needs_me = None;
    }
}
fn update_task(
    task: &mut Task,
    update: &super::TaskUpdate,
    approvals: &BTreeSet<String>,
) -> Result<(), TaskReject> {
    if !matches!(
        update.state,
        TaskStatus::Running | TaskStatus::NeedsMe | TaskStatus::Done | TaskStatus::Failed
    ) {
        return Err(TaskReject::IllegalTransition);
    }
    let pending = update.steps.iter().find(|s| s.needs_me.is_some());
    if (update.state == TaskStatus::NeedsMe) != pending.is_some() {
        return Err(TaskReject::NeedsMeMismatch);
    }
    for old in &task.steps {
        let new =
            update.steps.iter().find(|s| s.id == old.id).ok_or(if old.needs_me.is_some() {
                TaskReject::HumanDecisionPending
            } else {
                TaskReject::IllegalTransition
            })?;
        if old.needs_me.is_some() && old != new {
            return Err(TaskReject::HumanDecisionPending);
        }
        if old.state.is_terminal() && old != new {
            return Err(TaskReject::IllegalTransition);
        }
        if old.state == TaskStatus::Running && new.state == TaskStatus::Proposed {
            return Err(TaskReject::IllegalTransition);
        }
    }
    if let Some(NeedsMe::Approval { grant_id }) = pending.and_then(|s| s.needs_me.as_ref())
        && approvals.contains(grant_id)
    {
        return Err(TaskReject::DecisionReplay);
    }
    if update.state == TaskStatus::Done && update.steps.iter().any(|s| s.state != TaskStatus::Done)
    {
        return Err(TaskReject::IllegalTransition);
    }
    if update.state == TaskStatus::Failed && update.steps.iter().any(|s| !s.state.is_terminal()) {
        return Err(TaskReject::IllegalTransition);
    }
    if update.result_ref.is_some() && !update.state.is_terminal() {
        return Err(TaskReject::IllegalTransition);
    }
    task.state = update.state;
    task.steps.clone_from(&update.steps);
    task.result_ref.clone_from(&update.result_ref);
    Ok(())
}
fn validate_resolution(
    task: &Task,
    decision: &TaskResolve,
    pending_since: &BTreeMap<String, u64>,
) -> Result<(), TaskReject> {
    let step =
        task.steps.iter().find(|s| s.id == decision.step_id).ok_or(TaskReject::DecisionMismatch)?;
    let change = if step.needs_me.is_none() {
        Some(super::TaskDecisionChange::Closed)
    } else if step.needs_me.as_ref() != Some(&decision.target) {
        Some(super::TaskDecisionChange::TargetChanged)
    } else if pending_since
        .get(&decision.step_id)
        .is_none_or(|opened| decision.base_revision < *opened)
    {
        Some(super::TaskDecisionChange::NewerThanObserved)
    } else {
        None
    };
    if let Some(change) = change {
        return Err(TaskReject::StaleDecision { step_id: decision.step_id.clone(), change });
    }
    Ok(())
}
fn resolve(task: &mut Task, decision: &TaskResolve) -> Result<(), TaskReject> {
    if task.state != TaskStatus::NeedsMe {
        return Err(TaskReject::DecisionMismatch);
    }
    let step = task
        .steps
        .iter_mut()
        .find(|s| s.id == decision.step_id && s.needs_me.as_ref() == Some(&decision.target))
        .ok_or(TaskReject::DecisionMismatch)?;
    step.needs_me = None;
    if decision.decision == TaskDecision::Resume {
        step.state = TaskStatus::Running;
        task.state = TaskStatus::Running;
    } else {
        step.state = TaskStatus::Failed;
        cancel_unfinished(&mut task.steps);
        task.state = TaskStatus::Failed;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{SignatureAlg, SignedFields, encode_base64url, signed_bytes};
    use ed25519_dalek::{Signer, SigningKey};
    #[test]
    fn maximum_safe_revision_cannot_advance_or_mutate_state()
    -> Result<(), Box<dyn std::error::Error>> {
        let key = SigningKey::from_bytes(&[1; 32]);
        let public = encode_base64url(key.verifying_key().to_bytes());
        let signer = TaskSigner {
            principal_id: "human",
            actor_type: ActorType::Human,
            signing_key_id: "key",
            public_key_base64url: &public,
        };
        let start = TaskEvent::new(
            "chat".to_owned(),
            TaskEventBody::Start(super::super::TaskStart {
                task_id: "task".to_owned(),
                conversation_id: "chat".to_owned(),
                requester: "human".to_owned(),
                assignee: "human".to_owned(),
                text: "work".to_owned(),
                constraints: None,
            }),
            SignedFields {
                signing_key_id: "key".to_owned(),
                signature_alg: SignatureAlg::Ed25519,
                signature: String::new(),
            },
        )?;
        let start = start
            .clone()
            .with_signature(encode_base64url(key.sign(&signed_bytes(&start)?).to_bytes()))?;
        let mut state = TaskState::default();
        state.apply(&start, &signer)?;
        state.task.as_mut().ok_or("task")?.version = MAX_TASK_VERSION;
        let before = state.clone();
        let event = TaskEvent::new(
            "chat".into(),
            TaskEventBody::Cancel(super::super::TaskCancel {
                task_id: "task".into(),
                base_revision: MAX_TASK_VERSION,
            }),
            start.signed().clone(),
        )?;
        let event = event
            .clone()
            .with_signature(encode_base64url(key.sign(&signed_bytes(&event)?).to_bytes()))?;
        assert!(matches!(state.apply(&event, &signer), Err(TaskReject::InvalidVersion)));
        assert_eq!(state, before);
        Ok(())
    }
}
