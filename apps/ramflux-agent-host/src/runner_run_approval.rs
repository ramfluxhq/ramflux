// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Forwards one owner decision to PRX, then publishes the receipt.
//! A `prx` event is not posted again. `409` does not overwrite the winner.

use crate::engine::RunApprovalPost;
use crate::{AgentBus, EngineProvider, Error, Result};
use ramflux_sdk::LocalBusFrame;
use serde_json::{Value, json};

/// # Errors
/// Returns [`Error::Bus`] when the POST or the receipt publish cannot reach its peer.
pub(crate) async fn forward<E: EngineProvider>(
    bus: &mut impl AgentBus,
    engine: &mut E,
    event: &LocalBusFrame,
) -> Result<()> {
    if event.method != "agent.approval" {
        return Ok(());
    }
    if event.body.get("source").and_then(Value::as_str) != Some("owner") {
        return Ok(());
    }
    if event.body.get("status").and_then(Value::as_str) != Some("decided") {
        return Ok(());
    }
    let Some(approval_id) = text(&event.body, "approval_id") else { return Ok(()) };
    let Some(session) = text(&event.body, "session") else { return Ok(()) };
    let Some(decision) = text(&event.body, "decision") else { return Ok(()) };
    if decision != "approved" && decision != "denied" || !path_id(session) || !path_id(approval_id)
    {
        eprintln!("prx approval forward skipped");
        return Ok(());
    }
    let posted = engine.post_run_approval(session, approval_id, decision).await?;
    apply_post(bus, &event.body, &posted).await
}

async fn apply_post(
    bus: &mut impl AgentBus,
    record: &Value,
    posted: &RunApprovalPost,
) -> Result<()> {
    match posted.code.as_deref() {
        None => publish(bus, record, &posted.decision, None, &posted.run_id).await,
        Some("approval_expired") => {
            let cause = posted.cause.as_deref().unwrap_or("expired");
            publish(bus, record, "denied", Some(cause), &posted.run_id).await
        }
        Some("approval_unknown") => {
            eprintln!("prx approval unknown");
            Ok(())
        }
        Some("approval_decided") => {
            eprintln!("prx approval already decided");
            Ok(())
        }
        Some("approval_run_mismatch") => {
            eprintln!("prx approval run mismatch");
            Ok(())
        }
        Some(_) => {
            eprintln!("prx approval refused");
            Ok(())
        }
    }
}

async fn publish(
    bus: &mut impl AgentBus,
    record: &Value,
    decision: &str,
    cause: Option<&str>,
    run_id: &str,
) -> Result<()> {
    let Some(body) = receipt(record, decision, cause, run_id) else {
        eprintln!("prx approval receipt skipped");
        return Ok(());
    };
    match bus.request("agent.approval.publish", body, None).await {
        Ok(_) => Ok(()),
        Err(error) if retry(&error) => Err(error),
        Err(_) => {
            eprintln!("prx approval receipt was refused");
            Ok(())
        }
    }
}

fn receipt(record: &Value, decision: &str, cause: Option<&str>, run_id: &str) -> Option<Value> {
    let approval_id = text(record, "approval_id")?;
    let session = text(record, "session")?;
    let conversation = text(record, "conversation_id").unwrap_or(session);
    if !path_id(approval_id) || !path_id(session) || !path_id(conversation) {
        return None;
    }
    let mut body = json!({
        "source": "prx",
        "status": "decided",
        "decision": decision,
        "approval_id": approval_id,
        "conversation_id": conversation,
        "session": session,
        "tool": label(text(record, "tool").unwrap_or("")),
        "preview": preview(text(record, "preview").unwrap_or("")),
        "expires_at": expiry(text(record, "expires_at").unwrap_or("")),
    });
    if let Some(agent) = text(record, "agent") {
        put_id(&mut body, "agent", agent);
    }
    let run = if path_id(run_id) {
        Some(run_id)
    } else {
        text(record, "run_id").filter(|id| path_id(id))
    };
    if let Some(run) = run {
        body["run_id"] = json!(run);
    }
    if let Some(cause) = cause.filter(|value| path_id(value)) {
        body["cause"] = json!(cause);
    }
    Some(body)
}

fn put_id(body: &mut Value, key: &str, value: &str) {
    if path_id(value) {
        body[key] = json!(value);
    }
}

fn text<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value.get(key).and_then(Value::as_str)
}

fn label(value: &str) -> String {
    if path_id(value) { value.to_owned() } else { String::new() }
}

fn preview(value: &str) -> String {
    if value.chars().any(char::is_control) { String::new() } else { cap(value, 512) }
}

fn expiry(value: &str) -> String {
    let legal = value.len() <= 40
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b':' | b'T' | b'Z' | b'+' | b'.')
        });
    if value.is_empty() || legal { value.to_owned() } else { String::new() }
}

fn path_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 512
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}

fn cap(text: &str, max: usize) -> String {
    if text.len() <= max {
        return text.to_owned();
    }
    let mut end = max;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    text.get(..end).unwrap_or("").to_owned()
}

const fn retry(error: &Error) -> bool {
    error.stops_host() || matches!(error, Error::Bus | Error::Resync)
}
