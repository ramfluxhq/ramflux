// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Resolve an approval sheet against the SDK's own task request.
//! Card `requestRef` and `taskBinding` are hints. They never become the decision ids.
use crate::{RamfluxClient, SdkError, TaskApprovalBinding};
use ramflux_card::{ApprovalFacts, ApprovalScope};
use ramflux_protocol::NeedsMe;
use ramflux_protocol::a2ui::{TaskBinding, validate_identifier};
use serde_json::Value;
use std::collections::BTreeMap;

pub(super) struct Found {
    pub request_ref: String,
    pub task_binding: TaskBinding,
    pub facts: Option<ApprovalFacts>,
}

struct Pending {
    approval_id: String,
    grant_id: String,
    binding: TaskApprovalBinding,
    value: Value,
}

const FACT_SCAN: usize = 8;

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
    Some(Pending {
        approval_id: approval_id.to_owned(),
        grant_id: grant_id.to_owned(),
        binding,
        value: value.clone(),
    })
}

pub(super) fn verified_facts(
    client: &RamfluxClient,
    spec: &ramflux_card::CardSpec,
) -> Result<BTreeMap<String, ApprovalFacts>, SdkError> {
    let mut out = BTreeMap::new();
    for hint in component_hints(&spec.snapshot) {
        let found = lookup(
            client,
            &Hint {
                author: &spec.author_principal_id,
                conversation: &spec.conversation_id,
                request_ref: &hint.request_ref,
                task: hint.task.as_ref(),
            },
        )?;
        let Some(found) = found else {
            continue;
        };
        let Some(facts) = found.facts.and_then(|facts| scrub(facts, &hint.explanation)) else {
            continue;
        };
        out.insert(hint.request_ref, facts);
        if out.len() >= FACT_SCAN {
            break;
        }
    }
    Ok(out)
}

struct ComponentHint {
    request_ref: String,
    task: Option<TaskBinding>,
    explanation: String,
}

fn component_hints(snapshot: &ramflux_protocol::a2ui::SurfaceSnapshot) -> Vec<ComponentHint> {
    let mut out = Vec::new();
    for component in &snapshot.components {
        if out.len() >= FACT_SCAN {
            break;
        }
        if component.get("component").and_then(Value::as_str) != Some("Approval") {
            continue;
        }
        let Some(request_ref) = component.get("requestRef").and_then(Value::as_str) else {
            continue;
        };
        if request_ref.is_empty() {
            continue;
        }
        let task = component
            .get("taskBinding")
            .and_then(|value| serde_json::from_value(value.clone()).ok());
        let explanation =
            component.get("explanation").and_then(Value::as_str).unwrap_or("").to_owned();
        out.push(ComponentHint { request_ref: request_ref.to_owned(), task, explanation });
    }
    out
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
        Ok(fresh) if fresh == row.binding => {
            let facts = facts_of(&row.value, &row.binding);
            Ok(Some(Found {
                request_ref: row.approval_id,
                task_binding: TaskBinding {
                    task_id: row.binding.task_id,
                    step_id: row.binding.step_id,
                },
                facts,
            }))
        }
        Ok(_) => Ok(None),
        Err(error) => closed(error),
    }
}

fn facts_of(value: &Value, binding: &TaskApprovalBinding) -> Option<ApprovalFacts> {
    if binding.requester.is_empty() || binding.requester.len() > 256 {
        return None;
    }
    let mut scope = Vec::new();
    push_scope(&mut scope, "conversation", &binding.conversation_id);
    push_scope(&mut scope, "task", &binding.task_id);
    push_scope(&mut scope, "step", &binding.step_id);
    if let Some(tool_scope) = value.get("tool_scope").and_then(Value::as_str) {
        push_scope(&mut scope, "tool_scope", tool_scope);
    }
    if let Some(grant) = value.get("grant_id").and_then(Value::as_str) {
        push_scope(&mut scope, "grant", grant);
    }
    if scope.is_empty() {
        return None;
    }
    let action = value
        .get("tool_name")
        .and_then(Value::as_str)
        .filter(|name| identifier(name))
        .map(str::to_owned);
    let risk = value
        .get("risk_level")
        .and_then(Value::as_str)
        .filter(|name| identifier(name))
        .map(str::to_owned);
    let expires_at =
        value.get("expires_at").and_then(Value::as_i64).filter(|deadline| *deadline > 0);
    Some(ApprovalFacts { requester: binding.requester.clone(), action, scope, expires_at, risk })
}

fn push_scope(scope: &mut Vec<ApprovalScope>, name: &str, value: &str) {
    if scope.len() >= FACT_SCAN || !scope_value(value) {
        return;
    }
    scope.push(ApprovalScope { name: name.to_owned(), value: value.to_owned() });
}

fn scope_value(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty() && bytes.len() <= 128 && bytes.iter().all(u8::is_ascii_graphic)
}

fn identifier(value: &str) -> bool {
    validate_identifier(value).is_ok()
}

fn scrub(mut facts: ApprovalFacts, explanation: &str) -> Option<ApprovalFacts> {
    if !explanation.is_empty() && facts.requester == explanation {
        return None;
    }
    if facts.action.as_deref() == Some(explanation) && !explanation.is_empty() {
        facts.action = None;
    }
    if facts.risk.as_deref() == Some(explanation) && !explanation.is_empty() {
        facts.risk = None;
    }
    if !explanation.is_empty() {
        facts.scope.retain(|row| row.value != explanation);
    }
    if facts.scope.is_empty() {
        return None;
    }
    Some(facts)
}

fn closed(error: SdkError) -> Result<Option<Found>, SdkError> {
    match error {
        SdkError::TaskRefused { .. } | SdkError::InboundPending(_) | SdkError::LocalBus(_) => {
            Ok(None)
        }
        other => Err(other),
    }
}
