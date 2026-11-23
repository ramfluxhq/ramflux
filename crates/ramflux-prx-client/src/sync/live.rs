// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Ephemeral `stream` and `stream_gap` frames. They are not journaled and not acked.
//! Reasoning text is never copied. A child delta and a non-thinking typing state are ignored.

use super::frame::ServerFrame;
use serde_json::Value;

const TEXT_CAP: usize = 4096;

/// One live frame the host can publish. Malformed frames stay [`ServerFrame::Ignored`].
#[derive(Clone, PartialEq, Eq)]
pub struct LiveNotice {
    /// PRX session key. For an rf chat this is the conversation id.
    pub session: String,
    /// Agent name, or empty when the frame omitted it.
    pub agent: String,
    /// Run the frame names. A child frame still carries its own run id.
    pub run_id: String,
    /// Set when the frame is part of a child run. The host groups under this id.
    pub root_run_id: Option<String>,
    /// Set for a child frame, including a process-child denial.
    pub child_run_id: Option<String>,
    /// Per-run index. Zero for a gap, which has no index.
    pub idx: u64,
    /// What the owner may see.
    pub body: LiveBody,
}

/// Owner-visible live state. Reasoning text has no variant.
#[derive(Clone, PartialEq, Eq)]
pub enum LiveBody {
    /// `typing` with `state: thinking` only.
    Typing,
    /// Live assistant text. Not the authoritative final.
    Delta(String),
    /// One tool phase. `denied` and `expired` never invent `started`.
    Tool { tool: String, phase: String, cause: Option<String> },
    /// The daemon dropped earlier frames for this run.
    Gap,
}

pub(super) fn decode_stream(value: &Value) -> ServerFrame {
    match stream_notice(value) {
        Some(notice) => ServerFrame::Live(notice),
        None => ServerFrame::Ignored,
    }
}

pub(super) fn decode_gap(value: &Value) -> ServerFrame {
    let Some(run_id) = text(value, "run_id") else {
        return ServerFrame::Ignored;
    };
    if !id_ok(&run_id) {
        return ServerFrame::Ignored;
    }
    ServerFrame::Live(LiveNotice {
        session: text(value, "session").unwrap_or_default(),
        agent: text(value, "agent").unwrap_or_default(),
        run_id,
        root_run_id: None,
        child_run_id: None,
        idx: 0,
        body: LiveBody::Gap,
    })
}

fn stream_notice(value: &Value) -> Option<LiveNotice> {
    if value.get("type").and_then(Value::as_str) != Some("stream") {
        return None;
    }
    let idx = value.get("idx").and_then(Value::as_u64)?;
    let run_id = text(value, "run_id").filter(|id| id_ok(id))?;
    let kind = text(value, "kind")?;
    let parent = text(value, "parent_run_id").filter(|id| id_ok(id));
    let child_field = text(value, "child_run_id").filter(|id| id_ok(id));
    let body = match kind.as_str() {
        "typing" => typing_body(value)?,
        "delta" if parent.is_some() => return None,
        "delta" => LiveBody::Delta(cap_bytes(&text(value, "text")?, TEXT_CAP)),
        "tool_status" => tool_body(value, child_field.as_deref())?,
        _ => return None,
    };
    let child_run_id = child_field.or_else(|| parent.as_ref().map(|_| run_id.clone()));
    Some(LiveNotice {
        session: text(value, "session").unwrap_or_default(),
        agent: text(value, "agent").unwrap_or_default(),
        run_id,
        root_run_id: text(value, "root_run_id").filter(|id| id_ok(id)),
        child_run_id,
        idx,
        body,
    })
}

fn typing_body(value: &Value) -> Option<LiveBody> {
    if text(value, "state").as_deref() == Some("thinking") { Some(LiveBody::Typing) } else { None }
}

fn tool_body(value: &Value, child_run_id: Option<&str>) -> Option<LiveBody> {
    let phase = text(value, "phase")?;
    if !matches!(
        phase.as_str(),
        "started" | "succeeded" | "failed" | "denied" | "cancelled" | "awaiting_approval"
    ) {
        return None;
    }
    let tool = text(value, "tool").unwrap_or_default();
    if tool.len() > 128 || tool.chars().any(char::is_control) {
        return None;
    }
    let mut cause = text(value, "cause").filter(|cause| cause.len() <= 64);
    if phase == "denied" && cause.is_none() && child_run_id.is_some() {
        cause = Some("no_resolver".to_owned());
    }
    Some(LiveBody::Tool { tool, phase, cause })
}

fn text(value: &Value, key: &str) -> Option<String> {
    value.get(key).and_then(Value::as_str).map(str::to_owned)
}

fn id_ok(value: &str) -> bool {
    !value.is_empty() && value.len() <= 512 && !value.chars().any(char::is_control)
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
