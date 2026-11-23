// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! One mirror change decoded from a snapshot row or a journal event.
//! Unknown payload keys are ignored. A required key with the wrong type is a protocol error.

use crate::error::{PrxError, protocol};
use serde_json::Value;

/// What the host writes into its local mirror.
#[derive(Clone, PartialEq, Eq)]
pub enum MirrorOp {
    /// A session inventory row, including a child session when `child` is set.
    Session {
        session_key: String,
        agent: String,
        incarnation: String,
        channel: Option<String>,
        created_at: Option<String>,
        child: bool,
        deleted: bool,
        /// Set on a `cron:` or `xin:` session. The id inside `metadata`.
        job_id: Option<String>,
        /// Store version from `metadata.job_version`.
        job_version: Option<u64>,
    },
    /// Agent configuration metadata. No prompt text.
    Agent {
        name: String,
        incarnation: String,
        revision: Option<String>,
        enabled: bool,
        deleted: bool,
    },
    /// A user or assistant turn.
    Turn(TurnCopy),
    /// `turn.started`. The following `turn.appended` carries the text.
    Started { run_id: String, session: String, agent: String },
    /// `turn.failed`, including `reason: prx_restart`.
    Failed {
        run_id: Option<String>,
        session: String,
        agent: String,
        reason: String,
        retryable: bool,
    },
    /// `turn.cancelled`.
    Cancelled { run_id: Option<String>, session: String, agent: String },
    /// A tombstoned message. The host deletes its local copy.
    DeleteMessage { message_id: String },
    /// A history erase or an agent purge. The host deletes matching local copies.
    Erase(EraseCopy),
    /// A run-approval row. Pending and decided share one shape.
    Approval(ApprovalCopy),
    /// A kind this client does not store. The cursor still advances.
    Skip,
}

/// One approval the owner can see. `preview` is the redacted summary, at most 512 bytes.
#[derive(Clone, PartialEq, Eq)]
pub struct ApprovalCopy {
    /// PRX approval id (`call.{run}.{digest}`).
    pub approval_id: String,
    /// PRX session key.
    pub session: String,
    /// Agent name.
    pub agent: String,
    /// Run id when the header or payload carried one.
    pub run_id: Option<String>,
    /// Tool name. Empty when the payload omitted it.
    pub tool: String,
    /// Redacted argument preview.
    pub preview: String,
    /// RFC3339 expiry. Empty when the payload omitted it.
    pub expires_at: String,
    /// `pending` or `decided`.
    pub status: String,
    /// `approved` or `denied` once decided.
    pub decision: Option<String>,
    /// Denial cause when PRX sent one.
    pub cause: Option<String>,
}

/// One stored turn. The body is the only place message text lives.
#[derive(Clone, PartialEq, Eq)]
pub struct TurnCopy {
    /// Stable message id from the history route.
    pub message_id: String,
    /// PRX session key.
    pub session: String,
    /// Agent name, or `main`.
    pub agent: String,
    /// Agent incarnation. Empty when the payload has none.
    pub incarnation: String,
    /// `user`, `assistant`, or empty for an oversized marker.
    pub role: String,
    /// Run id when the journal header carried one.
    pub run_id: Option<String>,
    /// Caller message id when the admission row carried one.
    pub client_message_id: Option<String>,
    /// Text, a deletion, or an oversized marker.
    pub body: TurnBody,
}

/// The part of a turn the mirror keeps.
#[derive(Clone, PartialEq, Eq)]
pub enum TurnBody {
    /// Message text. `final_reply` is the authoritative assistant final.
    Text { content: String, final_reply: bool },
    /// The source was removed. The host deletes `message_id`.
    Deleted,
    /// The payload was replaced by `{message_id, oversized, bytes}`.
    Oversized { bytes: u64 },
}

/// One erase receipt. `session: None` deletes every local copy of `agent`.
#[derive(Clone, PartialEq, Eq)]
pub struct EraseCopy {
    /// Deduplication key. Purge events share one id across incarnations.
    pub erase_id: String,
    /// Agent whose copies are removed.
    pub agent: String,
    /// Incarnation stamp. Empty when the payload has none.
    pub incarnation: String,
    /// Set for a session history erase. Absent for an agent purge.
    pub session: Option<String>,
}

pub(super) fn op_from_snapshot(
    kind: &str,
    key: &str,
    payload: &Value,
) -> Result<MirrorOp, PrxError> {
    check_payload(payload)?;
    match kind {
        "session" => session_op(key, payload, false),
        "child_session" => session_op(key, payload, true),
        "agent" => agent_op(key, payload),
        "erase_receipt" => erase_op(payload),
        "turn" => turn_op(payload, "", "", "", None),
        "approval" => approval_op(true, "", "", None, payload),
        _ => Ok(MirrorOp::Skip),
    }
}

pub(super) fn op_from_kind(
    kind: &str,
    session: &str,
    agent: &str,
    incarnation: &str,
    run_id: Option<String>,
    payload: &Value,
) -> Result<MirrorOp, PrxError> {
    check_payload(payload)?;
    match kind {
        "session.upsert" => session_op(session, payload, false),
        "child_session.upsert" => session_op(session, payload, true),
        "agent.config_changed" => agent_op(agent, payload),
        "history.erased" => erase_op(payload),
        "turn.appended" => turn_op(payload, session, agent, incarnation, run_id),
        "turn.deleted" => deleted_message(payload),
        "turn.started" => started_op(payload, session, agent, run_id),
        "turn.failed" => failed_op(payload, session, agent, run_id),
        "turn.cancelled" => cancelled_op(session, agent, run_id, payload),
        "approval.pending" => approval_op(true, session, agent, run_id, payload),
        "approval.decided" => approval_op(false, session, agent, run_id, payload),
        _ => Ok(MirrorOp::Skip),
    }
}

fn approval_op(
    pending: bool,
    session: &str,
    agent: &str,
    run_id: Option<String>,
    payload: &Value,
) -> Result<MirrorOp, PrxError> {
    let approval_id = req_id(payload, "approval_id")?;
    let decision = if pending {
        None
    } else {
        let decision = req_id(payload, "decision")?;
        if decision != "approved" && decision != "denied" {
            return Err(protocol("sync payload field is invalid"));
        }
        Some(decision)
    };
    Ok(MirrorOp::Approval(ApprovalCopy {
        approval_id,
        session: approval_session(payload, session)?,
        agent: approval_agent(payload, agent)?,
        run_id: opt_id(payload, "run_id")?.or(run_id),
        tool: bounded_text(payload, "tool", 128)?,
        preview: bounded_text(payload, "summary", 512)?,
        expires_at: bounded_text(payload, "expires_at", 64)?,
        status: if pending { "pending" } else { "decided" }.to_owned(),
        decision,
        cause: opt_cause(payload)?,
    }))
}

fn approval_session(payload: &Value, fallback: &str) -> Result<String, PrxError> {
    if let Some(value) = opt_id(payload, "session_key")? {
        return Ok(value);
    }
    if let Some(value) = opt_id(payload, "session")? {
        return Ok(value);
    }
    Ok(if nonempty(fallback) { fallback.to_owned() } else { String::new() })
}

fn approval_agent(payload: &Value, fallback: &str) -> Result<String, PrxError> {
    let agent = opt_label(payload, "agent")?;
    if agent.is_empty() { Ok(fallback.to_owned()) } else { Ok(agent) }
}

fn bounded_text(payload: &Value, key: &str, max: usize) -> Result<String, PrxError> {
    let Some(text) = loose_str(payload, key)? else {
        return Ok(String::new());
    };
    if text.len() <= max {
        return Ok(text);
    }
    let mut end = max;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    Ok(text.get(..end).unwrap_or("").to_owned())
}

fn loose_str(payload: &Value, key: &str) -> Result<Option<String>, PrxError> {
    match payload.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(text)) if text.len() <= 8192 && !text.chars().any(char::is_control) => {
            Ok(Some(text.clone()))
        }
        Some(Value::String(_)) => Err(protocol("sync payload field is invalid")),
        Some(_) => Err(protocol("sync payload field has the wrong type")),
    }
}

fn opt_cause(payload: &Value) -> Result<Option<String>, PrxError> {
    match opt_id(payload, "cause")? {
        Some(cause) if cause.len() > 64 => Err(protocol("sync payload field is invalid")),
        other => Ok(other),
    }
}

fn check_payload(payload: &Value) -> Result<(), PrxError> {
    match payload.as_object() {
        Some(map) if map.len() <= 64 => Ok(()),
        Some(_) => Err(protocol("sync payload is too wide")),
        None => Err(protocol("sync payload is not an object")),
    }
}

fn session_op(key: &str, payload: &Value, child: bool) -> Result<MirrorOp, PrxError> {
    let session_key = if nonempty(key) { key.to_owned() } else { req_id(payload, "session_key")? };
    let created_at = match opt_id(payload, "created_at")? {
        Some(value) => Some(value),
        None => opt_id(payload, "started_at")?,
    };
    let channel = opt_id(payload, "channel")?;
    let (job_id, job_version) = job_meta(payload, channel.as_deref(), &session_key)?;
    Ok(MirrorOp::Session {
        session_key,
        agent: opt_label(payload, "agent")?,
        incarnation: opt_label(payload, "incarnation")?,
        channel,
        created_at,
        child,
        deleted: flag(payload, "deleted")?.unwrap_or(false),
        job_id,
        job_version,
    })
}

fn job_meta(
    payload: &Value,
    channel: Option<&str>,
    session_key: &str,
) -> Result<(Option<String>, Option<u64>), PrxError> {
    let Some(prefix) = channel.filter(|value| *value == "cron" || *value == "xin") else {
        return Ok((None, None));
    };
    let Some(meta) = payload.get("metadata").and_then(Value::as_object) else {
        return Err(protocol("sync payload field is missing"));
    };
    let job_id = match meta.get("job_id") {
        Some(Value::String(text)) if job_id_ok(text) => text.clone(),
        _ => return Err(protocol("sync payload field is invalid")),
    };
    if session_key != format!("{prefix}:{job_id}") {
        return Err(protocol("sync payload field is invalid"));
    }
    let job_version = match meta.get("job_version") {
        Some(value) => value.as_u64().ok_or(protocol("sync payload field has the wrong type"))?,
        None => return Err(protocol("sync payload field is missing")),
    };
    Ok((Some(job_id), Some(job_version)))
}

fn job_id_ok(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value.bytes().all(|byte| byte.is_ascii_hexdigit() || byte == b'-')
}

fn agent_op(key: &str, payload: &Value) -> Result<MirrorOp, PrxError> {
    let name = if nonempty(key) { key.to_owned() } else { req_id(payload, "agent")? };
    Ok(MirrorOp::Agent {
        name,
        incarnation: opt_label(payload, "incarnation")?,
        revision: opt_id(payload, "revision")?,
        enabled: flag(payload, "enabled")?.unwrap_or(true),
        deleted: flag(payload, "deleted")?.unwrap_or(false),
    })
}

fn turn_op(
    payload: &Value,
    session: &str,
    agent: &str,
    incarnation: &str,
    run_id: Option<String>,
) -> Result<MirrorOp, PrxError> {
    if flag(payload, "deleted")? == Some(true) {
        return deleted_message(payload);
    }
    let message_id = req_id(payload, "message_id")?;
    let session = required_label(payload, "session_key", session)?;
    let agent = required_label(payload, "agent", agent)?;
    let incarnation = required_label(payload, "incarnation", incarnation)?;
    let run_id = opt_id(payload, "run_id")?.or(run_id);
    let client_message_id = opt_id(payload, "client_message_id")?;
    if flag(payload, "oversized")? == Some(true) {
        let bytes = payload
            .get("bytes")
            .and_then(Value::as_u64)
            .ok_or(protocol("sync payload field is missing"))?;
        return Ok(MirrorOp::Turn(TurnCopy {
            message_id,
            session,
            agent,
            incarnation,
            role: String::new(),
            run_id,
            client_message_id,
            body: TurnBody::Oversized { bytes },
        }));
    }
    let role = req_id(payload, "role")?;
    if role.len() > 32 {
        return Err(protocol("sync payload field is invalid"));
    }
    let content = match payload.get("content") {
        Some(Value::String(text)) => text.clone(),
        Some(_) => return Err(protocol("sync payload field has the wrong type")),
        None => return Err(protocol("sync payload field is missing")),
    };
    let final_reply = flag(payload, "final")?.ok_or(protocol("sync payload field is missing"))?;
    Ok(MirrorOp::Turn(TurnCopy {
        message_id,
        session,
        agent,
        incarnation,
        role,
        run_id,
        client_message_id,
        body: TurnBody::Text { content, final_reply },
    }))
}

fn deleted_message(payload: &Value) -> Result<MirrorOp, PrxError> {
    Ok(MirrorOp::DeleteMessage { message_id: req_id(payload, "message_id")? })
}

fn started_op(
    payload: &Value,
    session: &str,
    agent: &str,
    run_id: Option<String>,
) -> Result<MirrorOp, PrxError> {
    let run_id =
        opt_id(payload, "run_id")?.or(run_id).ok_or(protocol("sync payload field is missing"))?;
    Ok(MirrorOp::Started {
        run_id,
        session: required_label(payload, "session_key", session)?,
        agent: required_label(payload, "agent", agent)?,
    })
}

fn failed_op(
    payload: &Value,
    session: &str,
    agent: &str,
    run_id: Option<String>,
) -> Result<MirrorOp, PrxError> {
    let reason = req_id(payload, "reason")?;
    if reason.len() > 64 {
        return Err(protocol("sync payload field is invalid"));
    }
    Ok(MirrorOp::Failed {
        run_id: opt_id(payload, "run_id")?.or(run_id),
        session: required_label(payload, "session_key", session)?,
        agent: required_label(payload, "agent", agent)?,
        reason,
        retryable: flag(payload, "retryable")?.ok_or(protocol("sync payload field is missing"))?,
    })
}

fn cancelled_op(
    session: &str,
    agent: &str,
    run_id: Option<String>,
    payload: &Value,
) -> Result<MirrorOp, PrxError> {
    Ok(MirrorOp::Cancelled {
        run_id: opt_id(payload, "run_id")?.or(run_id),
        session: required_label(payload, "session_key", session)?,
        agent: required_label(payload, "agent", agent)?,
    })
}

fn erase_op(payload: &Value) -> Result<MirrorOp, PrxError> {
    Ok(MirrorOp::Erase(EraseCopy {
        erase_id: req_id(payload, "erase_id")?,
        agent: req_id(payload, "agent")?,
        incarnation: opt_label(payload, "incarnation")?,
        session: scope_session(payload)?,
    }))
}

fn scope_session(payload: &Value) -> Result<Option<String>, PrxError> {
    match payload.get("scope") {
        Some(Value::String(scope)) if scope == "agent" => Ok(None),
        Some(Value::String(_)) => Err(protocol("sync payload field is invalid")),
        Some(Value::Object(scope)) => match scope.get("session") {
            None | Some(Value::Null) => Ok(None),
            Some(Value::String(text)) if text.is_empty() => Ok(None),
            Some(Value::String(text)) if label_ok(text) => Ok(Some(text.clone())),
            Some(Value::String(_)) => Err(protocol("sync payload field is invalid")),
            Some(_) => Err(protocol("sync payload field has the wrong type")),
        },
        Some(Value::Null) | None => opt_id(payload, "session_key"),
        Some(_) => Err(protocol("sync payload field has the wrong type")),
    }
}

fn required_label(payload: &Value, key: &str, fallback: &str) -> Result<String, PrxError> {
    match opt_id(payload, key)? {
        Some(value) => Ok(value),
        None if nonempty(fallback) => Ok(fallback.to_owned()),
        None => Err(protocol("sync payload field is missing")),
    }
}

fn req_id(payload: &Value, key: &str) -> Result<String, PrxError> {
    opt_id(payload, key)?.ok_or(protocol("sync payload field is missing"))
}

fn opt_id(payload: &Value, key: &str) -> Result<Option<String>, PrxError> {
    match opt_str(payload, key)? {
        Some(text) if text.is_empty() => Ok(None),
        other => Ok(other),
    }
}

fn opt_label(payload: &Value, key: &str) -> Result<String, PrxError> {
    Ok(opt_str(payload, key)?.unwrap_or_default())
}

fn opt_str(payload: &Value, key: &str) -> Result<Option<String>, PrxError> {
    match payload.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(text)) if label_ok(text) => Ok(Some(text.clone())),
        Some(Value::String(_)) => Err(protocol("sync payload field is invalid")),
        Some(_) => Err(protocol("sync payload field has the wrong type")),
    }
}

fn flag(payload: &Value, key: &str) -> Result<Option<bool>, PrxError> {
    match payload.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Bool(bit)) => Ok(Some(*bit)),
        Some(_) => Err(protocol("sync payload field has the wrong type")),
    }
}

fn nonempty(value: &str) -> bool {
    !value.is_empty() && label_ok(value)
}

fn label_ok(value: &str) -> bool {
    value.len() <= 512 && !value.chars().any(char::is_control)
}
