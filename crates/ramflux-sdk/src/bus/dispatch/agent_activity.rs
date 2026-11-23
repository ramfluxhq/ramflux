// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Local bus methods for live agent progress and a single-tap run approval.
//! The host publishes. The owner's client decides. The first stored decision wins.

use crate::client::agent_activity::{self, approval_expired};
use crate::prelude::*;
use serde_json::{Value, json};

pub(crate) fn dispatch(
    request: &LocalBusFrame,
    state: &mut LocalBusDaemonState,
) -> Result<LocalBusDispatchResult, SdkError> {
    match request.method.as_str() {
        "agent.progress" => progress(request, state),
        "agent.approval.publish" => publish(request, state),
        "agent.approval.decide" => decide(request, state),
        "agent.approval.list" => list(request, state),
        other => Err(SdkError::LocalBus(format!("unsupported local bus method: {other}"))),
    }
}

fn client<'a>(
    request: &LocalBusFrame,
    state: &'a mut LocalBusDaemonState,
) -> Result<&'a RamfluxClient, SdkError> {
    Ok(&local_bus_account_mut(state, request_account_id(request)?)?.client)
}

fn progress(
    request: &LocalBusFrame,
    state: &mut LocalBusDaemonState,
) -> Result<LocalBusDispatchResult, SdkError> {
    let client = client(request, state)?;
    let body = &request.body;
    let kind = required(body, "kind")?;
    if !matches!(kind, "typing" | "delta" | "tool" | "gap" | "final") {
        return Err(field_invalid("kind"));
    }
    if kind == "delta" && body.get("child_run_id").and_then(Value::as_str).is_some() {
        return Ok(local_bus_ok(json!({"ignored": true})));
    }
    if kind == "typing"
        && body.get("state").and_then(Value::as_str).is_some_and(|state| state != "thinking")
    {
        return Ok(local_bus_ok(json!({"ignored": true})));
    }
    let run_id = required(body, "run_id")?;
    let idx = body.get("idx").and_then(Value::as_u64).ok_or_else(|| field_invalid("idx"))?;
    let conversation_id = required(body, "conversation_id")?;
    let mut record = json!({
        "conversation_id": conversation_id,
        "session": optional(body, "session").unwrap_or(conversation_id),
        "agent": optional(body, "agent").unwrap_or(""),
        "run_id": run_id,
        "idx": idx,
        "kind": kind,
        "source": "prx",
    });
    copy_text(&mut record, body, "text", 4096)?;
    copy_label(&mut record, body, "tool");
    copy_label(&mut record, body, "phase");
    copy_label(&mut record, body, "cause");
    copy_label(&mut record, body, "child_run_id");
    if kind == "typing" {
        record["state"] = json!("thinking");
    }
    let slot = idx % u64::from(MAX_SLOTS);
    let state_kind = format!("agent-progress/{run_id}/{kind}/{slot}");
    stored(client, &state_kind, record)?;
    Ok(local_bus_ok(json!({"run_id": run_id, "idx": idx, "kind": kind})))
}

fn publish(
    request: &LocalBusFrame,
    state: &mut LocalBusDaemonState,
) -> Result<LocalBusDispatchResult, SdkError> {
    let client = client(request, state)?;
    let record = approval_record(&request.body, "prx")?;
    let id = required(&record, "approval_id")?;
    let state_kind = format!("agent-approval/{id}");
    stored(client, &state_kind, record.clone())?;
    Ok(local_bus_ok(record))
}

fn decide(
    request: &LocalBusFrame,
    state: &mut LocalBusDaemonState,
) -> Result<LocalBusDispatchResult, SdkError> {
    let client = client(request, state)?;
    let id = required(&request.body, "approval_id")?;
    let decision = required(&request.body, "decision")?;
    if decision != "approved" && decision != "denied" {
        return Err(field_invalid("decision"));
    }
    let state_kind = format!("agent-approval/{id}");
    let Some(existing) = client.account_db()?.load_actor_state::<Value>(&state_kind)? else {
        return Err(refused("approval_unknown", id, None, None));
    };
    if let Some(expires_at) = existing.get("expires_at").and_then(Value::as_str)
        && approval_expired(expires_at, crate::time::now_unix_timestamp()) == Some(true)
    {
        return Err(refused(
            "approval_expired",
            id,
            existing.get("decision").and_then(Value::as_str),
            Some("expired"),
        ));
    }
    if existing.get("status").and_then(Value::as_str) == Some("decided") {
        let stored = existing.get("decision").and_then(Value::as_str);
        if stored == Some(decision) {
            return Ok(local_bus_ok(existing));
        }
        return Err(refused(
            "approval_decided",
            id,
            stored,
            existing.get("cause").and_then(Value::as_str),
        ));
    }
    let mut record = existing;
    record["status"] = json!("decided");
    record["decision"] = json!(decision);
    record["source"] = json!("owner");
    record.as_object_mut().ok_or_else(|| field_invalid("record"))?.remove("cause");
    stored(client, &state_kind, record.clone())?;
    Ok(local_bus_ok(record))
}

fn list(
    request: &LocalBusFrame,
    state: &mut LocalBusDaemonState,
) -> Result<LocalBusDispatchResult, SdkError> {
    let client = client(request, state)?;
    let mut approvals = Vec::new();
    for key in client.account_db()?.actor_state_keys("agent-approval/")? {
        if approvals.len() >= 256 {
            break;
        }
        let Some(row) = client.account_db()?.load_actor_state::<Value>(&key)? else {
            continue;
        };
        if row.get("status").and_then(Value::as_str) == Some("pending") {
            approvals.push(row);
        }
    }
    Ok(local_bus_ok(json!({"approvals": approvals})))
}

fn stored(client: &RamfluxClient, state_kind: &str, record: Value) -> Result<(), SdkError> {
    if let Some(stored) = agent_activity::commit(client, state_kind, record)? {
        let _ = agent_activity::fan_out(client, state_kind, &stored);
    }
    Ok(())
}

fn approval_record(body: &Value, source: &str) -> Result<Value, SdkError> {
    if body.get("source").and_then(Value::as_str) != Some(source) {
        return Err(field_invalid("source"));
    }
    let status = required(body, "status")?;
    if status != "pending" && status != "decided" && status != "unknown" {
        return Err(field_invalid("status"));
    }
    let decision = optional(body, "decision");
    if status == "decided" && decision != Some("approved") && decision != Some("denied") {
        return Err(field_invalid("decision"));
    }
    let approval_id = required(body, "approval_id")?;
    let conversation_id = required(body, "conversation_id")?;
    let mut record = json!({
        "approval_id": approval_id,
        "conversation_id": conversation_id,
        "session": optional(body, "session").unwrap_or(conversation_id),
        "agent": optional(body, "agent").unwrap_or(""),
        "status": status,
        "source": source,
        "tool": preview_text(body, "tool", 128)?,
        "preview": preview_text(body, "preview", 512)?,
        "expires_at": expiry_text(body)?,
    });
    if let Some(run_id) = optional(body, "run_id") {
        record["run_id"] = json!(run_id);
    }
    if let Some(decision) = decision {
        record["decision"] = json!(decision);
    }
    if let Some(cause) = optional(body, "cause") {
        record["cause"] = json!(cause);
    }
    Ok(record)
}

fn copy_text(record: &mut Value, body: &Value, key: &str, max: usize) -> Result<(), SdkError> {
    let Some(text) = body.get(key).and_then(Value::as_str) else {
        return Ok(());
    };
    if text
        .chars()
        .any(|character| !matches!(character, '\n' | '\r' | '\t') && character.is_control())
    {
        return Err(field_invalid(key));
    }
    record[key] = json!(cap_bytes(text, max));
    Ok(())
}

fn copy_label(record: &mut Value, body: &Value, key: &str) {
    if let Some(text) = optional(body, key) {
        record[key] = json!(text);
    }
}

fn preview_text(body: &Value, key: &str, max: usize) -> Result<String, SdkError> {
    let Some(text) = body.get(key).and_then(Value::as_str) else {
        return Ok(String::new());
    };
    if text.chars().any(char::is_control) {
        return Err(field_invalid(key));
    }
    Ok(cap_bytes(text, max))
}

fn expiry_text(body: &Value) -> Result<String, SdkError> {
    let Some(text) = body.get("expires_at").and_then(Value::as_str) else {
        return Ok(String::new());
    };
    if text.is_empty() {
        return Ok(String::new());
    }
    let legal = text.len() <= 40
        && text.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b':' | b'T' | b'Z' | b'+' | b'.')
        });
    if legal { Ok(text.to_owned()) } else { Err(field_invalid("expires_at")) }
}

fn required<'a>(body: &'a Value, key: &str) -> Result<&'a str, SdkError> {
    optional(body, key).ok_or_else(|| field_invalid(key))
}

fn optional<'a>(body: &'a Value, key: &str) -> Option<&'a str> {
    body.get(key).and_then(Value::as_str).filter(|text| id_ok(text))
}

fn id_ok(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= 512
        && text
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}

fn cap_bytes(text: &str, max: usize) -> String {
    if text.len() <= max {
        return text.to_owned();
    }
    let mut end = max;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    text.get(..end).unwrap_or("").to_owned()
}

fn field_invalid(key: &str) -> SdkError {
    SdkError::LocalBusRefused {
        code: "field_invalid".into(),
        message: "field_invalid".into(),
        body: Box::new(json!({"reason_code":"field_invalid","details":{"cause":key}})),
    }
}

fn refused(code: &str, approval_id: &str, decision: Option<&str>, cause: Option<&str>) -> SdkError {
    SdkError::LocalBusRefused {
        code: code.into(),
        message: code.into(),
        body: Box::new(json!({
            "reason_code": code,
            "details": {"approval_id": approval_id, "decision": decision, "cause": cause}
        })),
    }
}

const MAX_SLOTS: u16 = 128;
