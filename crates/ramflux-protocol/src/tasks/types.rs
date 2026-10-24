// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Declarative task payloads and exactly-one intervention references.
use serde::{Deserialize, Serialize};

/// Lifecycle shared by tasks and their steps.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TaskStatus {
    Proposed,
    Running,
    NeedsMe,
    Done,
    Failed,
    Cancelled,
}
impl TaskStatus {
    /// Whether further work is forbidden.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Done | Self::Failed | Self::Cancelled)
    }
}

/// Exactly one existing approval grant or declarative surface, never both.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum NeedsMe {
    Approval { grant_id: String },
    Choice { surface_id: String },
    Input { surface_id: String },
}
impl NeedsMe {
    /// Opaque identifier resolved through the existing grant or surface flow.
    #[must_use]
    pub fn target_id(&self) -> &str {
        match self {
            Self::Approval { grant_id } => grant_id,
            Self::Choice { surface_id } | Self::Input { surface_id } => surface_id,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TaskStep {
    pub id: String,
    pub title: String,
    pub state: TaskStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub needs_me: Option<NeedsMe>,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TaskStart {
    pub task_id: String,
    pub conversation_id: String,
    pub requester: String,
    pub assignee: String,
    pub text: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub constraints: Option<String>,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TaskProposal {
    pub task_id: String,
    pub conversation_id: String,
    pub proposer: String,
    pub assignee: String,
    pub title: String,
    pub steps: Vec<TaskStep>,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TaskAccept {
    pub task_id: String,
    pub version: u64,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TaskDecline {
    pub task_id: String,
    pub version: u64,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TaskUpdate {
    pub task_id: String,
    pub version: u64,
    pub state: TaskStatus,
    pub steps: Vec<TaskStep>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result_summary: Option<String>,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TaskCancel {
    pub task_id: String,
    pub base_revision: u64,
}

/// Result of the existing human decision flow; this receipt grants no tool capability.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TaskDecision {
    Resume,
    Deny,
}

/// Human-signed receipt linking a task intervention to an existing grant/surface decision.
/// The caller must verify that external decision before applying this receipt. Its id is
/// single-use within this task; cross-task grant consumption remains in the grant subsystem.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TaskResolve {
    pub task_id: String,
    pub base_revision: u64,
    pub step_id: String,
    pub target: NeedsMe,
    pub decision_id: String,
    pub decision: TaskDecision,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "type", content = "body", rename_all = "snake_case", deny_unknown_fields)]
pub enum TaskEventBody {
    Start(TaskStart),
    Proposal(TaskProposal),
    Accept(TaskAccept),
    Decline(TaskDecline),
    Update(TaskUpdate),
    Cancel(TaskCancel),
    Resolve(TaskResolve),
}
impl TaskEventBody {
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Start(_) => "start",
            Self::Proposal(_) => "proposal",
            Self::Accept(_) => "accept",
            Self::Decline(_) => "decline",
            Self::Update(_) => "update",
            Self::Cancel(_) => "cancel",
            Self::Resolve(_) => "resolve",
        }
    }
    #[must_use]
    pub const fn base_revision(&self) -> Option<u64> {
        match self {
            Self::Cancel(v) => Some(v.base_revision),
            Self::Resolve(v) => Some(v.base_revision),
            _ => None,
        }
    }
    #[must_use]
    pub fn task_id(&self) -> &str {
        match self {
            Self::Start(v) => &v.task_id,
            Self::Proposal(v) => &v.task_id,
            Self::Accept(v) => &v.task_id,
            Self::Decline(v) => &v.task_id,
            Self::Update(v) => &v.task_id,
            Self::Cancel(v) => &v.task_id,
            Self::Resolve(v) => &v.task_id,
        }
    }
    /// Ordered event revision, or the observed base revision for Cancel/Resolve.
    /// The resulting projection revision is assigned atomically by `TaskState`.
    #[must_use]
    pub const fn version(&self) -> u64 {
        match self {
            Self::Start(_) | Self::Proposal(_) => 1,
            Self::Accept(v) => v.version,
            Self::Decline(v) => v.version,
            Self::Update(v) => v.version,
            Self::Cancel(v) => v.base_revision,
            Self::Resolve(v) => v.base_revision,
        }
    }
}
