// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Stable JSON for conversation and typing commands.
//! A daemon error frame keeps its code, message and details unchanged.

use ramflux_sdk::{LocalBusFrame, LocalBusFrameKind};
use serde_json::{Value, json};

#[must_use]
pub(super) fn outcome(method: &str, response: &LocalBusFrame) -> Value {
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

#[must_use]
pub(crate) fn local_refusal(method: &str, code: &str, message: &str) -> Value {
    json!({
        "ok": false,
        "method": method,
        "error": {"code": code, "message": message, "details": Value::Null},
        "body": Value::Null,
    })
}

#[cfg(test)]
mod tests {
    use super::{local_refusal, outcome};
    use ramflux_sdk::{LocalBusErrorBody, LocalBusFrame, LocalBusFrameKind};
    use serde_json::json;

    fn error_frame(
        code: &str,
        message: &str,
        details: serde_json::Value,
        body: serde_json::Value,
    ) -> LocalBusFrame {
        let mut frame = LocalBusFrame::request(
            "req",
            Some("alice".to_owned()),
            "conversation",
            "conversation.edit",
            body,
        );
        frame.kind = LocalBusFrameKind::Error;
        frame.ok = Some(false);
        frame.error = Some(LocalBusErrorBody {
            details: Some(Box::new(details)),
            reason_code: None,
            code: code.to_owned(),
            message: message.to_owned(),
            retry_after_ms: None,
            cause: None,
        });
        frame
    }

    #[test]
    fn edit_conflict_refusal_json_keeps_typed_details() {
        let details = json!({"target": "m1", "expected": 1, "received": 2});
        let body = json!({
            "code": 7,
            "name": "edit_conflict",
            "message": "revision conflict",
            "details": details,
        });
        let frame = error_frame("edit_conflict", "revision conflict", details, body);
        let value = outcome("conversation.edit", &frame);
        assert_eq!(value["ok"], false);
        assert_eq!(value["method"], "conversation.edit");
        assert_eq!(value["error"]["code"], "edit_conflict");
        assert_eq!(value["error"]["message"], "revision conflict");
        assert_eq!(value["error"]["details"]["target"], "m1");
        assert_eq!(value["error"]["details"]["expected"], 1);
        assert_eq!(value["error"]["details"]["received"], 2);
        assert_eq!(value["body"]["name"], "edit_conflict");
        assert_eq!(value["body"]["details"]["received"], 2);
    }

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
        assert_eq!(value["ok"], true);
        assert_eq!(value["body"]["message_id"], "m1");
        assert!(value.get("error").is_none());
    }

    #[test]
    fn local_typing_refusal_uses_the_existing_invalid_argument_name() {
        let value = local_refusal(
            "message.submit",
            "invalid_argument",
            "typing operation_id must be 16 to 64 bytes",
        );
        assert_eq!(value["ok"], false);
        assert_eq!(value["error"]["code"], "invalid_argument");
        assert_eq!(value["error"]["details"], serde_json::Value::Null);
    }
}
