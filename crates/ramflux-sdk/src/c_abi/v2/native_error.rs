// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Typed native error projection at SDK envelope fields; business objects are never scanned.
use crate::bindings::ErrorDetails;
use serde::Serialize;
use serde_json::Value;
#[derive(Serialize)]
#[serde(untagged)]
enum Code {
    Number(i64),
    Name(String),
}
#[derive(Serialize)]
#[serde(untagged)]
enum Details {
    Generated(ErrorDetails),
    Retryable { retryable: bool },
}
#[derive(Serialize)]
struct NativeError {
    code: Code,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    details: Details,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    retry_after_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    state: Option<&'static str>,
}
fn token(value: &Value) -> Option<String> {
    let s = value.as_str()?;
    (!s.is_empty() && s.len() <= 128 && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_'))
        .then(|| s.into())
}
fn details(value: &Value, code: &Code) -> Details {
    let value = value.get("details").unwrap_or(&Value::Null);
    let name = match code {
        Code::Name(name) => name.as_str(),
        Code::Number(6) => "resync_required",
        Code::Number(7) => "edit_conflict",
        Code::Number(4) => "storage_capacity",
        Code::Number(_) => "",
    };
    let number = |key: &str| value.get(key).and_then(Value::as_u64);
    match name {
        "resync_required" | "ResyncRequired" => {
            if let (Some(cursor), Some(floor), Some(head)) =
                (number("cursor"), number("floor"), number("head"))
            {
                return Details::Generated(ErrorDetails::ResyncRequired { cursor, floor, head });
            }
        }
        "edit_conflict" | "EditConflict" => {
            if let (Some(target), Some(expected), Some(received)) = (
                value.get("target").and_then(Value::as_str),
                number("expected"),
                number("received"),
            ) {
                return Details::Generated(ErrorDetails::EditConflict {
                    target: target.into(),
                    expected,
                    received,
                });
            }
        }
        "storage_capacity" | "StorageCapacity" => {
            if let (Some(scope), Some(source)) =
                (value.get("scope").and_then(token), value.get("source").and_then(token))
            {
                return Details::Generated(ErrorDetails::StorageCapacity { scope, source });
            }
        }
        _ => {}
    }
    if let Some(retryable) = value.get("retryable").and_then(Value::as_bool) {
        return Details::Retryable { retryable };
    }
    Details::Generated(ErrorDetails::Empty {})
}
fn project(value: &mut Value) {
    let code = value
        .get("code")
        .and_then(Value::as_i64)
        .map(Code::Number)
        .or_else(|| value.get("code").and_then(token).map(Code::Name))
        .unwrap_or(Code::Number(16));
    let error = NativeError {
        details: details(value, &code),
        code,
        name: value.get("name").and_then(token),
        reason_code: value.get("reason_code").and_then(token),
        retry_after_ms: value.get("retry_after_ms").and_then(Value::as_u64),
        state: (value.get("state").and_then(Value::as_str) == Some("error")).then_some("error"),
    };
    let replacement =
        serde_json::to_value(error).unwrap_or_else(|_| serde_json::json!({"code":16}));
    let mut old = std::mem::replace(value, replacement);
    crate::bus::inprocess::erase_value(&mut old);
}
fn field(value: &mut Value, name: &str) {
    if let Some(value) = value.get_mut(name)
        && !value.is_null()
    {
        project(value);
    }
}
fn receipt(value: &mut Value) {
    if let Some(map) = value.as_object_mut()
        && map.get("last_error").is_some_and(|v| !v.is_null())
    {
        if let Some(mut old) = map.insert("last_error".into(), Value::Null) {
            crate::bus::inprocess::erase_value(&mut old);
        }
        map.insert("last_error_code".into(), serde_json::json!(16));
    }
}
pub(super) fn frame(value: &mut Value) {
    let method = value.get("method").and_then(Value::as_str).unwrap_or("").to_owned();
    let error = value.get("kind").and_then(Value::as_str) == Some("error");
    field(value, "error");
    if error {
        field(value, "body");
    }
    if value.get("protocol").and_then(Value::as_str) == Some("ramflux.local_bus.custody.v1")
        && value.get("result").and_then(|v| v.get("state")).and_then(Value::as_str) == Some("error")
    {
        field(value, "result");
    }
    if let Some(body) = value.get_mut("body") {
        match method.as_str() {
            "conversation.edit"
            | "conversation.react"
            | "conversation.reply"
            | "conversation.delete" => {
                if let Some(deliveries) = body.get_mut("deliveries").and_then(Value::as_array_mut) {
                    for delivery in deliveries {
                        field(delivery, "error");
                    }
                }
            }
            "object.put.status"
            | "object.fetch"
            | "object.put.finish"
            | "object.put"
            | "object.transfer.status"
            | "object.transfer.resume" => {
                receipt(body);
                for name in ["receipt", "transfer", "terminal"] {
                    if let Some(v) = body.get_mut(name) {
                        receipt(v);
                    }
                }
            }
            "object.directory" => {
                if let Some(rows) = body.get_mut("objects").and_then(Value::as_array_mut) {
                    for row in rows {
                        receipt(row);
                    }
                }
            }
            "mcp.tool.failed" => field(body, "error"),
            _ => {}
        }
    }
}
pub(super) fn completion(value: &mut Value) {
    // The root is the ABI completion schema, never an application payload.
    if let Some(map) = value.as_object_mut() {
        if let Some(mut old) = map.remove("message") {
            crate::bus::inprocess::erase_value(&mut old);
        }
        if let Some(response) = map.get_mut("response") {
            frame(response);
        }
    }
}
