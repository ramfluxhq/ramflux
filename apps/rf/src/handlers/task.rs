// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! `rf task` drivers. Each subcommand sends one existing `task.*` bus method and prints
//! the same `{ok, method, body}` JSON as `rf conversation`. A bus refusal keeps its code,
//! is printed, and fails the process.

use super::conversation_ops::commit_write;
use super::{LocalBusClient, PathBuf, RfError, TaskAction, TaskBodyFile, TaskCommand};
use ramflux_sdk::LocalBusFrame;
use serde_json::{Value, json};
use std::io::Read;
use std::sync::atomic::{AtomicU64, Ordering};

/// Upper bound for a typed task body file; the bus frame budget is far larger than any task.
const TASK_BODY_MAX_BYTES: u64 = 262_144;

pub(crate) async fn handle_task(socket: PathBuf, command: TaskCommand) -> Result<(), RfError> {
    let (account, method, body) = match command.action {
        TaskAction::List(list) => (
            list.account,
            "task.list",
            json!({
                "conversation_id": list.conversation,
                "state": list.state,
                "cursor": list.cursor,
                "limit": list.limit,
            }),
        ),
        TaskAction::Get(get) => (
            get.account,
            "task.get",
            json!({"task_id": get.task_id, "conversation_id": get.conversation}),
        ),
        TaskAction::Propose(file) => (file.account.clone(), "task.propose", body_file(&file)?),
        TaskAction::Start(file) => (file.account.clone(), "task.start", body_file(&file)?),
        TaskAction::Update(file) => (file.account.clone(), "task.update", body_file(&file)?),
        TaskAction::Resolve(file) => (file.account.clone(), "task.resolve", body_file(&file)?),
        TaskAction::Accept(versioned) => {
            let body = versioned_body(
                &versioned.task_id,
                versioned.conversation,
                "version",
                versioned.version,
            );
            (versioned.account, "task.accept", body)
        }
        TaskAction::Decline(versioned) => {
            let body = versioned_body(
                &versioned.task_id,
                versioned.conversation,
                "version",
                versioned.version,
            );
            (versioned.account, "task.decline", body)
        }
        TaskAction::Cancel(cancel) => {
            let body = versioned_body(
                &cancel.task_id,
                cancel.conversation,
                "base_revision",
                cancel.base_revision,
            );
            (cancel.account, "task.cancel", body)
        }
    };
    let bus = LocalBusClient::connect(socket).await?;
    let frame = LocalBusFrame::request(request_id(), Some(account), "task", method, body);
    let response = bus.request_frame_response(frame).await?;
    commit_write(method, &response)
}

fn versioned_body(task_id: &str, conversation: Option<String>, key: &str, value: u64) -> Value {
    let mut body = json!({"task_id": task_id, key: value});
    if let (Some(conversation), Some(object)) = (conversation, body.as_object_mut()) {
        object.insert("conversation_id".into(), json!(conversation));
    }
    body
}

/// Reads a typed JSON object with a hard byte cap. The bus validates the fields.
fn body_file(file: &TaskBodyFile) -> Result<Value, RfError> {
    let mut raw = Vec::new();
    std::fs::File::open(&file.body_file)?
        .take(TASK_BODY_MAX_BYTES.saturating_add(1))
        .read_to_end(&mut raw)?;
    if u64::try_from(raw.len()).unwrap_or(u64::MAX) > TASK_BODY_MAX_BYTES {
        return Err(RfError::Message("task body file exceeds 256 KiB".into()));
    }
    let value: Value = serde_json::from_slice(&raw)?;
    if !value.is_object() {
        return Err(RfError::Message("task body file must contain a JSON object".into()));
    }
    Ok(value)
}

fn request_id() -> String {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    format!("rf-task-{}", NEXT.fetch_add(1, Ordering::Relaxed))
}
