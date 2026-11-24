// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Host-facing session results. Dispatch success is not author acceptance.
use serde_json::{Value, json};

pub(super) struct View<'a> {
    pub result: &'a str,
    pub allowed: bool,
    pub session: Option<u64>,
    pub fallback: &'a str,
    pub reason: Option<&'a str>,
    pub batch: Option<Value>,
    pub host_request: Option<Value>,
    pub submit: Option<Value>,
    pub draft_conflict: bool,
    pub action_outcome: Option<Value>,
}

pub(super) fn view(view: View<'_>) -> Value {
    let mut body = json!({
        "result": view.result,
        "render_allowed": view.allowed,
        "fallback_text": view.fallback,
    });
    let Some(object) = body.as_object_mut() else {
        return body;
    };
    if let Some(session) = view.session {
        object.insert("session".into(), json!(session));
    }
    if let Some(reason) = view.reason {
        object.insert("reason".into(), json!(reason));
    }
    if view.allowed {
        if let Some(batch) = view.batch {
            object.insert("batch".into(), batch);
        }
        if let Some(host_request) = view.host_request {
            object.insert("host_request".into(), host_request);
        }
        if let Some(submit) = view.submit {
            object.insert("submit".into(), submit);
        }
    }
    if view.draft_conflict {
        object.insert("draft_conflict".into(), json!(true));
    }
    if let Some(outcome) = view.action_outcome {
        object.insert("action_outcome".into(), outcome);
    }
    body
}

pub(super) fn refused(reason: &str, fallback: &str) -> Value {
    view(View {
        result: "refused",
        allowed: false,
        session: None,
        fallback,
        reason: Some(reason),
        batch: None,
        host_request: None,
        submit: None,
        draft_conflict: false,
        action_outcome: None,
    })
}

pub(super) struct Shown<'a> {
    pub result: &'a str,
    pub session: u64,
    pub fallback: &'a str,
    pub batch: Option<Value>,
    pub host_request: Option<Value>,
    pub submit: Option<Value>,
    pub draft_conflict: bool,
    pub action_outcome: Option<Value>,
}

pub(super) fn shown(fields: Shown<'_>) -> Value {
    view(View {
        result: fields.result,
        allowed: true,
        session: Some(fields.session),
        fallback: fields.fallback,
        reason: None,
        batch: fields.batch,
        host_request: fields.host_request,
        submit: fields.submit,
        draft_conflict: fields.draft_conflict,
        action_outcome: fields.action_outcome,
    })
}

pub(super) fn stale(session: u64, fallback: &str) -> Value {
    view(View {
        result: "stale_dropped",
        allowed: true,
        session: Some(session),
        fallback,
        reason: Some("card_session_stale"),
        batch: None,
        host_request: None,
        submit: None,
        draft_conflict: false,
        action_outcome: None,
    })
}

pub(super) fn submitted(
    session: u64,
    message_id: &str,
    surface_version: u64,
    surface_hash: &str,
    fallback: &str,
) -> Value {
    view(View {
        result: "submitted",
        allowed: true,
        session: Some(session),
        fallback,
        reason: None,
        batch: None,
        host_request: None,
        submit: Some(json!({
            "message_id": message_id,
            "surface_version": surface_version,
            "surface_hash": surface_hash,
            "delivery_state": "submitted",
        })),
        draft_conflict: false,
        action_outcome: Some(action_outcome("accepted", None, None)),
    })
}

pub(super) fn stopped(
    session: u64,
    fallback: &str,
    status: &str,
    reason: &str,
    replacement: Option<&str>,
    batch: Option<Value>,
) -> Value {
    let result = if status == "superseded" { "superseded" } else { "refused" };
    view(View {
        result,
        allowed: true,
        session: Some(session),
        fallback,
        reason: Some(reason),
        batch,
        host_request: None,
        submit: None,
        draft_conflict: false,
        action_outcome: Some(action_outcome(status, Some(reason), replacement)),
    })
}

pub(super) fn action_outcome(
    status: &str,
    reason: Option<&str>,
    replacement: Option<&str>,
) -> Value {
    let mut body = json!({ "status": status });
    let Some(object) = body.as_object_mut() else {
        return body;
    };
    if let Some(reason) = reason {
        object.insert("reason".into(), json!(reason));
    }
    if let Some(replacement) = replacement {
        object.insert("replacement_ref".into(), json!(replacement));
    }
    body
}

#[cfg(feature = "card-runtime")]
pub(super) fn batch_value(batch: &ramflux_card::MutationBatch) -> Result<Value, crate::SdkError> {
    let mut value = serde_json::to_value(batch)?;
    scrub_image_urls(&mut value);
    Ok(value)
}

#[cfg(feature = "card-runtime")]
fn scrub_image_urls(value: &mut Value) {
    let Some(object) = value.as_object_mut() else {
        return;
    };
    if object.get("kind").and_then(Value::as_str) == Some("image") {
        object.insert("attachment".into(), json!({"retrieval": "native_callback"}));
    }
    if object.get("kind").and_then(Value::as_str) == Some("Image")
        && let Some(attrs) = object.get_mut("attrs")
    {
        scrub_url_strings(attrs);
    }
    for child in object.values_mut() {
        match child {
            Value::Array(items) => {
                for item in items {
                    scrub_image_urls(item);
                }
            }
            Value::Object(_) => scrub_image_urls(child),
            _ => {}
        }
    }
}

#[cfg(feature = "card-runtime")]
fn scrub_url_strings(value: &mut Value) {
    match value {
        Value::String(text) if is_url(text) => text.clear(),
        Value::Array(items) => {
            for item in items {
                scrub_url_strings(item);
            }
        }
        Value::Object(map) => {
            for child in map.values_mut() {
                scrub_url_strings(child);
            }
        }
        _ => {}
    }
}

#[cfg(feature = "card-runtime")]
fn is_url(text: &str) -> bool {
    let trimmed = text.trim();
    let head = trimmed.get(..8).unwrap_or(trimmed);
    let lower = head.to_ascii_lowercase();
    lower.starts_with("https://")
        || lower.starts_with("http://")
        || trimmed.to_ascii_lowercase().starts_with("data:")
}
