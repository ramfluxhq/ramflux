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
    reason: String,
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
        "edit_conflict" => {
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
    if let Some(pairing) = value.get("pairing").and_then(token) {
        return Details::Generated(ErrorDetails::Pairing { pairing });
    }
    if let Some(reason) = value.get("reason").and_then(token) {
        return Details::Generated(ErrorDetails::Reason { reason });
    }
    if let Some(retryable) = value.get("retryable").and_then(Value::as_bool) {
        return Details::Retryable { retryable };
    }
    Details::Generated(ErrorDetails::Empty {})
}
fn retry_ms(value: &Value) -> Option<u64> {
    value.get("retry_after_ms").and_then(Value::as_u64).or_else(|| {
        value
            .get("retry_after_secs")
            .and_then(Value::as_i64)
            .map(|secs| u64::try_from(secs).map_or(0, |wait| wait.saturating_mul(1_000)))
    })
}
fn project(value: &mut Value) {
    let code = value
        .get("code")
        .and_then(Value::as_i64)
        .map(Code::Number)
        .or_else(|| value.get("code").and_then(token).map(Code::Name))
        .unwrap_or(Code::Number(16));
    let name = value.get("name").and_then(token).unwrap_or_else(|| match &code {
        Code::Name(name) => name.clone(),
        Code::Number(code) => status_name(*code).to_owned(),
    });
    let reason = reason(value).unwrap_or_else(|| default_reason(&name));
    let error = NativeError {
        details: details(value, &code),
        code,
        name: Some(name),
        reason: reason.clone(),
        reason_code: Some(reason),
        retry_after_ms: retry_ms(value),
        state: (value.get("state").and_then(Value::as_str) == Some("error")).then_some("error"),
    };
    let replacement =
        serde_json::to_value(error).unwrap_or_else(|_| serde_json::json!({"code":16,"name":"Internal","reason":"internal_error","reason_code":"internal_error"}));
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
        if let Some(code) = map.get("code").and_then(Value::as_i64).filter(|code| *code != 0) {
            let nested = map.get("response").and_then(|response| {
                response
                    .get("error")
                    .filter(|v| !v.is_null())
                    .or_else(|| {
                        response
                            .get("result")
                            .filter(|v| v.get("state").and_then(Value::as_str) == Some("error"))
                    })
                    .or_else(|| {
                        response.get("body").filter(|_| {
                            response.get("kind").and_then(Value::as_str) == Some("error")
                        })
                    })
            });
            let name = nested
                .and_then(|e| e.get("name"))
                .and_then(token)
                .or_else(|| map.get("name").and_then(token))
                .unwrap_or_else(|| status_name(code).into());
            let reason = nested
                .and_then(reason)
                .or_else(|| map.get("reason_code").and_then(token))
                .or_else(|| map.get("reason").and_then(token))
                .unwrap_or_else(|| default_reason(&name));
            map.insert("name".into(), Value::String(name));
            map.insert("reason".into(), Value::String(reason.clone()));
            map.insert("reason_code".into(), Value::String(reason));
        }
    }
}

fn reason(value: &Value) -> Option<String> {
    value
        .get("reason_code")
        .and_then(token)
        .or_else(|| value.get("reason").and_then(token))
        .or_else(|| value.pointer("/details/reason").and_then(token))
        .or_else(|| value.get("directory").and_then(token))
}
fn default_reason(name: &str) -> String {
    match name {
        "InvalidArgument" | "ValidationFailed" => "invalid_argument".into(),
        "Internal" => "internal_error".into(),
        "Cancelled" => "cancelled".into(),
        _ => name.into(),
    }
}
pub(super) fn status_name(code: i64) -> &'static str {
    match code {
        0 => "Ok",
        1 => "InvalidArgument",
        2 => "InvalidCanonicalJson",
        3 => "UnsupportedVersion",
        4 => "CapabilityRejected",
        5 => "AuthFailed",
        6 => "DeviceRevoked",
        7 => "CryptoFailed",
        8 => "StorageFailed",
        9 => "TransportUnavailable",
        10 => "Timeout",
        11 => "ReplayRejected",
        12 => "PermissionDenied",
        13 => "McpGrantRejected",
        14 => "ObjectTransferFailed",
        15 => "RateLimited",
        17 => "PanicAborted",
        18 => "AccountBusy",
        19 => "ObjectErased",
        20 => "ObjectIdentityConflict",
        21 => "ObjectOwnershipUnverified",
        22 => "CustodyForkFenced",
        23 => "SchemaResetRequired",
        24 => "Pending",
        25 => "Cancelled",
        26 => "Closed",
        27 => "ResyncRequired",
        28 => "PairingRefused",
        29 => "PairingStale",
        30 => "Suspended",
        31 => "VaultLocked",
        _ => "Internal",
    }
}
