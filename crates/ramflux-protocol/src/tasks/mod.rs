// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Signed task lifecycle inside encrypted conversation messages. Identity, actor role,
//! conversation membership and external grant/surface decision verification belong to the
//! caller's trust boundary. This module verifies signatures and pure lifecycle authority;
//! applying a resolution never mints an MCP grant or executes a surface action.
mod event;
mod fallback;
mod state;
mod types;
mod validation;
pub use event::{TASK_EVENT_SCHEMA, TaskEvent, TaskSigner};
pub use state::{Task, TaskState};
pub use types::*;
pub use validation::{
    MAX_TASK_EVENT_BYTES, MAX_TASK_STEPS, MAX_TASK_TEXT_CHARS, MAX_TASK_TITLE_CHARS,
    MAX_TASK_VERSION, TaskDecisionChange, TaskReject,
};

/// The change made to an account's task read model.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskChangeKind {
    Updated,
    Compacted,
    Removed,
}
