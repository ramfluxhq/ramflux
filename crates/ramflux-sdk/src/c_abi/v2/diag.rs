// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Process-level diagnostic calls (C-7): init before any account, typed host records,
//! flush and the verbose window. Never fails the app; errors come back only as return codes.
//! `flush` waits at most five seconds: call it off the UI thread.
use super::super::{CAbiError, RamfluxErrorCode};
use super::exports::call;
use crate::diag::events;
use crate::diag::logging::{self, fields};
use serde_json::{Map, Value};

const MAX_CONFIG_BYTES: usize = 16 * 1024;
const MAX_RECORD_BYTES: usize = 2048;
const VERBOSE_WINDOW_MS: u64 = 24 * 60 * 60 * 1000;

/// Process-level sink handle held by `ramflux_v2_diag_init`.
static PROCESS_SINK: std::sync::LazyLock<
    std::sync::Mutex<Option<std::sync::Arc<crate::diag::logging::Session>>>,
> = std::sync::LazyLock::new(|| std::sync::Mutex::new(None));

fn invalid(message: &'static str) -> CAbiError {
    CAbiError::new(RamfluxErrorCode::InvalidArgument, message)
}

fn bytes<'a>(ptr: *const u8, len: usize, max: usize) -> Result<&'a [u8], CAbiError> {
    if ptr.is_null() || len == 0 || len > max {
        return Err(invalid("diag bytes"));
    }
    // SAFETY: the host supplies `len` readable bytes for the duration of this call.
    Ok(unsafe { std::slice::from_raw_parts(ptr, len) })
}

/// Starts the process sink. The config carries the C-1 keys plus `dir`, the data root
/// that holds `diag/`. Idempotent for the same policy.
#[unsafe(no_mangle)]
#[must_use]
pub extern "C" fn ramflux_v2_diag_init(config_json: *const u8, len: usize) -> i32 {
    call(|| {
        let mut value: Value = serde_json::from_slice(bytes(config_json, len, MAX_CONFIG_BYTES)?)
            .map_err(|_| invalid("diag config"))?;
        let object = value.as_object_mut().ok_or_else(|| invalid("diag config"))?;
        let dir = object
            .remove("dir")
            .and_then(|item| item.as_str().map(str::to_owned))
            .ok_or_else(|| invalid("diag dir"))?;
        let config: crate::diag::DiagnosticConfig =
            serde_json::from_value(value).map_err(|_| invalid("diag config"))?;
        let root = super::data_root::validate(&dir)?;
        let session = crate::diag::start(&root, config)
            .map_err(|error| super::super::map_sdk_error(&error))?;
        // The process keeps its sink open until exit; dropping this handle would stop the writer.
        if let Ok(mut slot) = PROCESS_SINK.lock() {
            *slot = Some(session);
        }
        Ok(())
    })
}

/// A host record, validated against the registry before anything is written.
struct HostRecord {
    layer: String,
    level: String,
    component: String,
    event: String,
    cid: Option<String>,
    fields: Map<String, Value>,
    err: Option<Value>,
}

fn token_field(object: &Map<String, Value>, key: &str) -> Option<String> {
    let text = object.get(key)?.as_str()?;
    fields::token(text).then(|| text.to_owned())
}

fn host_error(value: &Value) -> Option<Value> {
    for (key, item) in value.as_object()? {
        let accepted = match (key.as_str(), item) {
            ("code", Value::Number(_)) | ("retryable", Value::Bool(_)) => true,
            ("name" | "reason" | "variant", Value::String(text)) => fields::token(text),
            ("effect", Value::String(text)) => {
                matches!(text.as_str(), "none" | "unknown" | "committed")
            }
            _ => false,
        };
        if !accepted {
            return None;
        }
    }
    Some(value.clone())
}

fn host_record(value: &Value) -> Option<HostRecord> {
    let object = value.as_object()?;
    if object
        .keys()
        .any(|key| !matches!(key.as_str(), "lv" | "ly" | "c" | "e" | "cid" | "f" | "err"))
    {
        return None;
    }
    let level = object.get("lv")?.as_str()?;
    if !matches!(level, "E" | "W" | "I" | "D" | "T") {
        return None;
    }
    let layer = object.get("ly")?.as_str()?;
    if !matches!(layer, "ui" | "bridge") {
        return None;
    }
    let cid = match object.get("cid") {
        None => None,
        Some(Value::String(text)) if events::valid_cid(text) => Some(text.clone()),
        Some(_) => return None,
    };
    let fields = match object.get("f") {
        None => Map::new(),
        Some(item) => fields::host_fields(item)?,
    };
    let err = match object.get("err") {
        None => None,
        Some(item) => Some(host_error(item)?),
    };
    Some(HostRecord {
        layer: layer.to_owned(),
        level: level.to_owned(),
        component: token_field(object, "c")?,
        event: token_field(object, "e")?,
        cid,
        fields,
        err,
    })
}

/// Writes one host record (`ui` or `bridge` layer) through the sink. With no sink open the
/// record is dropped and the call succeeds: diagnostics never fail the application.
#[unsafe(no_mangle)]
#[must_use]
pub extern "C" fn ramflux_v2_diag_write(record_json: *const u8, len: usize) -> i32 {
    call(|| {
        let value: Value = serde_json::from_slice(bytes(record_json, len, MAX_RECORD_BYTES)?)
            .map_err(|_| invalid("diag record"))?;
        let Some(record) = host_record(&value) else {
            if let Some(session) = logging::active() {
                session.note_rejected(1);
            }
            return Err(invalid("diag record"));
        };
        if let Some(session) = logging::active() {
            session.write(logging::Record {
                layer: &record.layer,
                level: &record.level,
                component: &record.component,
                event: &record.event,
                cid: record.cid.as_deref(),
                fields: Value::Object(record.fields),
                error: record.err,
            });
        }
        Ok(())
    })
}

/// Flushes the process sink to disk. Blocks at most five seconds (see `Session::flush`).
#[unsafe(no_mangle)]
#[must_use]
pub extern "C" fn ramflux_v2_diag_flush() -> i32 {
    call(|| {
        events::flush();
        Ok(())
    })
}

/// Sets the verbose window. `debug` and `trace` need `until_ms` within the next 24 hours;
/// `error`, `warn` and `info` return to the configured level.
#[unsafe(no_mangle)]
#[must_use]
pub extern "C" fn ramflux_v2_diag_set_level(level: *const std::ffi::c_char, until_ms: u64) -> i32 {
    call(|| {
        if level.is_null() {
            return Err(invalid("diag level"));
        }
        // SAFETY: the host passes a NUL-terminated string that stays valid for this call.
        let text = unsafe { std::ffi::CStr::from_ptr(level) }
            .to_str()
            .map_err(|_| invalid("diag level"))?;
        let Some(session) = logging::active() else { return Ok(()) };
        match text {
            "debug" | "trace" => {
                let now = logging::now_ms();
                if until_ms <= now || until_ms > now.saturating_add(VERBOSE_WINDOW_MS) {
                    return Err(invalid("diag window"));
                }
                let verbose =
                    if text == "debug" { tracing::Level::DEBUG } else { tracing::Level::TRACE };
                session.set_level_override(verbose, Some(until_ms));
            }
            "error" | "warn" | "info" => session.set_level_override(tracing::Level::INFO, None),
            _ => return Err(invalid("diag level")),
        }
        Ok(())
    })
}
