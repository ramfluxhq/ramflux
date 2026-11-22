// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Stable JSON for conversation and typing commands.
//! A daemon error frame keeps its code, message and details unchanged.

use ramflux_sdk::{LocalBusFrame, LocalBusFrameKind};
use serde_json::{Value, json};

#[must_use]
pub(crate) fn outcome(method: &str, response: &LocalBusFrame) -> Value {
    let refused = response.kind == LocalBusFrameKind::Error || response.ok == Some(false);
    if !refused {
        return json!({"ok": true, "method": method, "body": response.body});
    }
    let (code, message, details) = match response.error.as_ref() {
        Some(error) => {
            let details =
                error.details.as_ref().map_or(Value::Null, |value| value.as_ref().clone());
            (error.code.as_str(), error.message.as_str(), details)
        }
        None => ("internal", "", Value::Null),
    };
    json!({
        "ok": false,
        "method": method,
        "error": {"code": code, "message": message, "details": details},
        "body": response.body,
    })
}

/// Why a `conversation.send` outcome is not a delivered send: a refusal frame, or a reply whose
/// delivery state is not `submitted` (every target failed or only some were reached).
#[must_use]
pub(crate) fn send_failure(value: &Value) -> Option<String> {
    if value.get("ok").and_then(Value::as_bool) != Some(true) {
        let code = value.pointer("/error/code").and_then(Value::as_str).unwrap_or("internal");
        let message = value.pointer("/error/message").and_then(Value::as_str).unwrap_or("");
        return Some(format!("{code}: {message}"));
    }
    let state = value.pointer("/body/delivery_state").and_then(Value::as_str).unwrap_or("unknown");
    if state == "submitted" {
        return None;
    }
    let failed = value
        .pointer("/body/deliveries")
        .and_then(Value::as_array)
        .map(|rows| {
            rows.iter()
                .filter(|row| row.get("state").and_then(Value::as_str) != Some("submitted"))
                .filter_map(|row| row.get("error_code").and_then(Value::as_str))
                .collect::<Vec<_>>()
                .join(",")
        })
        .unwrap_or_default();
    Some(format!("delivery {state}: {failed}"))
}

#[must_use]
pub(crate) fn local_refusal(method: &str, code: &str, message: &str) -> Value {
    json!({
        "ok": false,
        "method": method,
        "error": {"code": code, "message": message, "details": Value::Null},
        "body": Value::Null,
    })
}

struct Presented {
    value: Value,
    refusal: Option<(String, String)>,
}

/// JSON for a task or surface write. A daemon error frame keeps its code. A surface
/// write whose body says `accepted: false` becomes the same refusal shape, with the
/// specific reject name when the renderer recorded one.
fn presented(method: &str, response: &LocalBusFrame) -> Presented {
    let mut value = outcome(method, response);
    if value.get("ok").and_then(Value::as_bool) == Some(true)
        && matches!(method, "surface.send" | "surface.action")
        && let Some((code, message)) = surface_action_refusal(&value["body"])
    {
        let body = value["body"].clone();
        value = json!({
            "ok": false,
            "method": method,
            "error": {"code": code, "message": message, "details": body},
            "body": body,
        });
    }
    let refusal = if value.get("ok").and_then(Value::as_bool) == Some(false) {
        Some((
            value["error"]["code"].as_str().unwrap_or("internal").to_owned(),
            value["error"]["message"].as_str().unwrap_or("").to_owned(),
        ))
    } else {
        None
    };
    Presented { value, refusal }
}

/// Prints the structured outcome. A refusal stays on stdout and also fails the process,
/// so a shell with `set -e` cannot continue after it.
pub(crate) fn commit_write(method: &str, response: &LocalBusFrame) -> Result<(), crate::RfError> {
    let presented = presented(method, response);
    crate::utils::print_json(&presented.value)?;
    if let Some((code, message)) = presented.refusal {
        return Err(crate::RfError::Message(format!("{code}: {message}")));
    }
    Ok(())
}

fn surface_action_refusal(body: &Value) -> Option<(String, String)> {
    if body.get("accepted").and_then(Value::as_bool) != Some(false) {
        return None;
    }
    let specific = body.pointer("/renderer_error/reject/reject").and_then(Value::as_str);
    let reason = body.get("reason_code").and_then(Value::as_str);
    let code = specific.or(reason).unwrap_or("surface_refused").to_owned();
    let message = body
        .get("fallback_text")
        .and_then(Value::as_str)
        .filter(|text| !text.is_empty())
        .unwrap_or("surface action refused")
        .to_owned();
    Some((code, message))
}

#[cfg(test)]
mod tests {
    use super::{local_refusal, outcome, presented};
    use ramflux_sdk::{LocalBusErrorBody, LocalBusFrame, LocalBusFrameKind};
    use serde_json::{Value, json};

    #[test]
    fn success_json_keeps_the_bus_body() {
        let mut frame = LocalBusFrame::request(
            "req",
            Some("alice".to_owned()),
            "conversation",
            "conversation.send",
            json!({"message_id": "m1", "delivery_state": "submitted"}),
        );
        frame.kind = LocalBusFrameKind::Response;
        frame.ok = Some(true);
        let value = outcome("conversation.send", &frame);
        assert_eq!(value["ok"], true, "test: a response frame is ok");
        assert_eq!(value["body"]["message_id"], "m1", "test: the bus body is copied");
        assert!(value.get("error").is_none(), "test: success JSON has no error object");
    }

    #[test]
    fn local_typing_refusal_uses_the_existing_invalid_argument_name() {
        let value = local_refusal(
            "message.submit",
            "invalid_argument",
            "typing operation_id must be 16 to 64 bytes",
        );
        assert_eq!(value["ok"], false, "test: a local refusal is not ok");
        assert_eq!(
            value["error"]["code"], "invalid_argument",
            "test: local typing refusal uses invalid_argument"
        );
        assert_eq!(
            value["error"]["details"],
            serde_json::Value::Null,
            "test: a local refusal has null details"
        );
    }

    #[test]
    fn daemon_error_frame_keeps_its_code_and_is_a_process_refusal() {
        let mut frame = LocalBusFrame::request(
            "req",
            Some("alice".to_owned()),
            "task",
            "task.propose",
            json!({}),
        );
        frame.kind = LocalBusFrameKind::Error;
        frame.ok = Some(false);
        frame.error = Some(LocalBusErrorBody {
            details: None,
            reason_code: None,
            code: "invalid_request".to_owned(),
            message: "task proposal requires a headless AI account".to_owned(),
            retry_after_ms: None,
            cause: None,
        });
        frame.body = json!({"kept": true});
        let shown = presented("task.propose", &frame);
        assert_eq!(shown.value["ok"], false, "test: a daemon error is not ok");
        assert_eq!(
            shown.value["error"]["code"], "invalid_request",
            "test: the bus code is preserved"
        );
        assert_eq!(shown.value["body"]["kept"], true, "test: the error body is preserved");
        let Some((code, message)) = shown.refusal else {
            panic!("test: a daemon error must refuse the process");
        };
        assert_eq!(code, "invalid_request", "test: stderr carries the typed code");
        assert!(message.contains("headless AI"), "test: stderr carries the daemon message");
    }

    #[test]
    fn rejected_surface_action_becomes_a_typed_refusal() {
        let mut frame = LocalBusFrame::request(
            "req",
            Some("bob".to_owned()),
            "surface",
            "surface.action",
            json!({}),
        );
        frame.kind = LocalBusFrameKind::Response;
        frame.ok = Some(true);
        frame.body = json!({
            "accepted": false,
            "fallback_text": "[Surface rejected]",
            "reason_code": "invalid_request",
            "renderer_error": {"code": "renderer_error", "reject": {"reject": "unknown_action"}}
        });
        let shown = presented("surface.action", &frame);
        assert_eq!(shown.value["ok"], false, "test: a rejected action is not ok");
        assert_eq!(
            shown.value["error"]["code"], "unknown_action",
            "test: the specific reject is the typed code"
        );
        assert_eq!(
            shown.value["body"]["accepted"], false,
            "test: the bus body stays on the refusal"
        );
        let Some((code, _)) = shown.refusal else {
            panic!("test: a rejected action must refuse the process");
        };
        assert_eq!(code, "unknown_action", "test: stderr names unknown_action");
    }

    #[test]
    fn accepted_surface_write_and_absent_task_body_stay_successful() {
        let mut frame = LocalBusFrame::request(
            "req",
            Some("alice".to_owned()),
            "surface",
            "surface.send",
            json!({}),
        );
        frame.kind = LocalBusFrameKind::Response;
        frame.ok = Some(true);
        frame.body = json!({"accepted": true, "delivery_state": "submitted"});
        let shown = presented("surface.send", &frame);
        assert!(shown.refusal.is_none(), "test: an accepted surface write exits 0");
        assert_eq!(shown.value["ok"], true, "test: accepted JSON stays ok");

        frame.method = "task.get".to_owned();
        frame.body = Value::Null;
        let absent = presented("task.get", &frame);
        assert!(absent.refusal.is_none(), "test: an absent task read exits 0");
        assert_eq!(absent.value["ok"], true, "test: an absent task is ok");
        assert!(absent.value["body"].is_null(), "test: an absent task body is null");
    }
}
