// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Resolve an approval sheet against the SDK's own task request.
//! Card `requestRef` and `taskBinding` are hints. They never become the decision ids.
use crate::{RamfluxClient, SdkError, TaskApprovalBinding};
use ramflux_protocol::NeedsMe;
use ramflux_protocol::a2ui::TaskBinding;
use serde_json::Value;

pub(super) struct Found {
    pub request_ref: String,
    pub task_binding: TaskBinding,
}

struct Pending {
    approval_id: String,
    grant_id: String,
    binding: TaskApprovalBinding,
}

pub(super) struct Hint<'a> {
    pub author: &'a str,
    pub conversation: &'a str,
    pub request_ref: &'a str,
    pub task: Option<&'a TaskBinding>,
}

pub(super) fn lookup(client: &RamfluxClient, hint: &Hint<'_>) -> Result<Option<Found>, SdkError> {
    let mut chosen: Option<Pending> = None;
    for value in client.task_remote_approvals()? {
        let Some(row) = pending_row(&value, hint) else {
            continue;
        };
        if chosen.is_some() {
            return Ok(None);
        }
        chosen = Some(row);
    }
    let Some(row) = chosen else {
        return Ok(None);
    };
    confirm_current(client, row)
}

fn pending_row(value: &Value, hint: &Hint<'_>) -> Option<Pending> {
    let approval_id = value.get("approval_id")?.as_str()?;
    let decision_id = value.get("decision_id")?.as_str()?;
    let grant_id = value.get("grant_id")?.as_str()?;
    let conversation = value.get("conversation_id")?.as_str()?;
    let binding: TaskApprovalBinding =
        serde_json::from_value(value.get("task_binding")?.clone()).ok()?;
    if !owned(&binding, hint.author, hint.conversation, conversation) {
        return None;
    }
    if !hint_hits(hint.request_ref, approval_id, decision_id, grant_id) {
        return None;
    }
    if !task_hits(hint.task, &binding) {
        return None;
    }
    Some(Pending { approval_id: approval_id.to_owned(), grant_id: grant_id.to_owned(), binding })
}

fn owned(binding: &TaskApprovalBinding, author: &str, conversation: &str, row: &str) -> bool {
    binding.assignee == author && binding.conversation_id == conversation && row == conversation
}

fn hint_hits(hint: &str, approval_id: &str, decision_id: &str, grant_id: &str) -> bool {
    !hint.is_empty() && (hint == approval_id || hint == decision_id || hint == grant_id)
}

fn task_hits(hint: Option<&TaskBinding>, binding: &TaskApprovalBinding) -> bool {
    hint.is_none_or(|task| task.task_id == binding.task_id && task.step_id == binding.step_id)
}

fn confirm_current(client: &RamfluxClient, row: Pending) -> Result<Option<Found>, SdkError> {
    let target = NeedsMe::Approval { grant_id: row.grant_id };
    let fresh = client.task_approval_binding(
        &row.binding.conversation_id,
        &row.binding.task_id,
        &row.binding.step_id,
        &target,
    );
    match fresh {
        Ok(fresh) if fresh == row.binding => Ok(Some(Found {
            request_ref: row.approval_id,
            task_binding: TaskBinding {
                task_id: row.binding.task_id,
                step_id: row.binding.step_id,
            },
        })),
        Ok(_) => Ok(None),
        Err(error) => closed(error),
    }
}

fn closed(error: SdkError) -> Result<Option<Found>, SdkError> {
    match error {
        SdkError::TaskRefused { .. } | SdkError::InboundPending(_) | SdkError::LocalBus(_) => {
            Ok(None)
        }
        other => Err(other),
    }
}
