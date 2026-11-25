// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Write-time allow-list; Display text and unknown fields never enter the file.
use serde_json::{Map, Value, json};
use tracing::field::{Field, Visit};

/// Field registry (DIAGNOSTIC-LOGGING-01 6.3). Shipped as `ramflux_diag_fields.json`.
/// Types: `count` (unsigned or signed integer), `bool`, `token` (`[A-Za-z0-9_.]{1,48}`),
/// `hash:<class>` (keyed hash made by the SDK, never by a host; the value is `h:` + 10 hex).
/// `suppressed` is the count of refused-call lines withheld by the 60-second rate rule.
pub(crate) const REGISTRY: &[(&str, &str)] = &[
    ("active", "bool"),
    ("applied", "count"),
    ("attempt", "count"),
    ("build_class", "token"),
    ("bytes", "count"),
    ("check", "token"),
    ("code", "count"),
    ("count", "count"),
    ("cursor", "count"),
    ("cursor_after", "count"),
    ("cursor_before", "count"),
    ("dead_lettered", "count"),
    ("deferred", "count"),
    ("delay_ms", "count"),
    ("device_class", "token"),
    ("duration_ms", "count"),
    ("effect", "token"),
    ("error_code", "token"),
    ("fetched", "count"),
    ("floor", "count"),
    ("generation", "count"),
    ("head", "count"),
    ("held", "count"),
    ("inbox_seq", "count"),
    ("kind", "token"),
    ("known_contact", "bool"),
    ("level", "token"),
    ("method", "token"),
    ("name", "token"),
    ("object_kind", "token"),
    ("objects_failed", "count"),
    ("objects_total", "count"),
    ("objects_verified", "count"),
    ("outcome", "token"),
    ("paused", "bool"),
    ("passes", "count"),
    ("phase", "token"),
    ("process", "token"),
    ("reason", "token"),
    ("reason_code", "token"),
    ("request_counter", "count"),
    ("resumed", "bool"),
    ("result", "token"),
    ("retry_after_ms", "count"),
    ("retryable", "bool"),
    ("stage", "token"),
    ("state", "token"),
    ("stale", "bool"),
    ("stop_reason", "token"),
    ("suppressed", "count"),
    ("targets", "count"),
    ("thread", "token"),
    ("transport", "token"),
    ("variant", "token"),
    ("account_id", "hash:account"),
    ("conversation_id", "hash:conversation"),
    ("contact_id", "hash:contact"),
    ("device_id", "hash:device"),
    ("envelope_id", "hash:envelope"),
    ("group_id", "hash:group"),
    ("message_id", "hash:message"),
    ("node_address", "hash:node"),
    ("node_id", "hash:node"),
    ("object_hash", "hash:object"),
    ("object_id", "hash:object"),
    ("operation_id", "hash:operation"),
    ("principal_id", "hash:principal"),
    ("session_id", "hash:session"),
    ("source_device_id", "hash:device"),
    ("source_principal_id", "hash:principal"),
    ("target_delivery_id", "hash:delivery"),
    ("username", "hash:username"),
];

/// The registered type of `key`, if the key may appear in a record.
pub(crate) fn registered(key: &str) -> Option<&'static str> {
    REGISTRY.iter().find(|(name, _)| *name == key).map(|(_, kind)| *kind)
}

/// Token rule shared by the event names, the component names, the variant and reason names
/// (Rust identifiers such as `NetworkingPending`) and the host record fields.
pub(crate) fn token(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= 48
        && text.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.'))
}

/// A hash-class value: exactly the `h:` + 10 lowercase hex form the SDK hasher produces.
pub(crate) fn hashed(text: &str) -> bool {
    text.strip_prefix("h:").is_some_and(|hex| {
        hex.len() == 10 && hex.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

/// Whether one SDK-built field may be written: the key is registered and the value has its type.
fn accepted(key: &str, item: &Value) -> bool {
    match (registered(key), item) {
        (Some("count"), Value::Number(number)) => number.is_u64() || number.is_i64(),
        (Some("bool"), Value::Bool(_)) => true,
        (Some("token"), Value::String(text)) => token(text),
        (Some(kind), Value::String(text)) if kind.starts_with("hash:") => hashed(text),
        _ => false,
    }
}

/// Keeps only registered keys with values of their registered type. Returns the kept object and
/// the number of refused keys (counted as `diag.rejected`). Raw identifiers are refused here:
/// a hash-class key only passes when its value already has the hashed form.
pub(crate) fn sanitize(fields: Value) -> (Value, u64) {
    let Value::Object(map) = fields else { return (json!({}), 0) };
    let mut kept = Map::new();
    let mut refused = 0_u64;
    for (key, item) in map {
        if accepted(&key, &item) {
            kept.insert(key, item);
        } else {
            refused = refused.saturating_add(1);
        }
    }
    (Value::Object(kept), refused)
}

/// Checks a host record's `f` object: registered keys with count, bool or token values only.
/// Hashes are never accepted from a host; the SDK hashes identifiers itself.
#[cfg(feature = "c-abi")]
pub(crate) fn host_fields(value: &Value) -> Option<Map<String, Value>> {
    let object = value.as_object()?;
    let mut out = Map::new();
    for (key, item) in object {
        let accepted = match (registered(key)?, item) {
            ("count", Value::Number(number)) => number.is_u64() || number.is_i64(),
            ("bool", Value::Bool(_)) => true,
            ("token", Value::String(text)) => token(text),
            _ => false,
        };
        if !accepted {
            return None;
        }
        out.insert(key.clone(), item.clone());
    }
    Some(out)
}

pub(super) struct Visitor<'a> {
    key: &'a [u8; 32],
    pub(super) fields: Map<String, Value>,
}
impl<'a> Visitor<'a> {
    pub(super) fn new(key: &'a [u8; 32]) -> Self {
        Self { key, fields: Map::new() }
    }
    pub(super) fn event(line: Option<u32>) -> String {
        format!("trace.{}", line.unwrap_or(0))
    }
    fn insert(&mut self, field: &Field, value: Value) {
        if self.fields.len() < 24 {
            self.fields.insert(field.name().into(), value);
        }
    }
    fn number(&mut self, field: &Field, value: Value) {
        if registered(field.name()) == Some("count") {
            self.insert(field, value);
        }
    }
    fn text(&mut self, field: &Field, value: &str) {
        match registered(field.name()) {
            Some(kind) if kind.starts_with("hash:") => {
                let class = kind.trim_start_matches("hash:");
                if let Ok(hash) =
                    ramflux_crypto::diagnostic_short_hash(self.key, class, value.as_bytes())
                {
                    self.insert(field, json!(hash));
                }
            }
            Some("token") if token(value) => self.insert(field, json!(value)),
            Some("token") => self.insert(field, json!(format!("[text:{}]", value.len()))),
            _ => {}
        }
    }
}
impl Visit for Visitor<'_> {
    fn record_u64(&mut self, field: &Field, value: u64) {
        self.number(field, json!(value));
    }
    fn record_i64(&mut self, field: &Field, value: i64) {
        self.number(field, json!(value));
    }
    fn record_bool(&mut self, field: &Field, value: bool) {
        if registered(field.name()) == Some("bool") {
            self.insert(field, json!(value));
        }
    }
    fn record_str(&mut self, field: &Field, value: &str) {
        self.text(field, value);
    }
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        struct Bounded {
            text: String,
            total: usize,
        }
        impl std::fmt::Write for Bounded {
            fn write_str(&mut self, text: &str) -> std::fmt::Result {
                self.total = self.total.saturating_add(text.len());
                for c in text.chars() {
                    if self.text.len() + c.len_utf8() > 512 {
                        break;
                    }
                    self.text.push(c);
                }
                Ok(())
            }
        }
        let mut buffer = Bounded { text: String::new(), total: 0 };
        let _ = std::fmt::write(&mut buffer, format_args!("{value:?}"));
        if buffer.total <= 512 {
            self.text(
                field,
                buffer
                    .text
                    .strip_prefix('"')
                    .and_then(|v| v.strip_suffix('"'))
                    .unwrap_or(&buffer.text),
            );
        } else {
            self.insert(field, json!(format!("[text:{}]", buffer.total)));
        }
        zeroize::Zeroize::zeroize(&mut buffer.text);
    }
}
