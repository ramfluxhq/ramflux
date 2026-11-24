// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Write-time allow-list; Display text and unknown fields never enter the file.
use serde_json::{Map, Value, json};
use tracing::field::{Field, Visit};

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
        if matches!(
            field.name(),
            "code"
                | "count"
                | "inbox_seq"
                | "cursor"
                | "head"
                | "floor"
                | "generation"
                | "attempt"
                | "retry_after_ms"
                | "duration_ms"
                | "elapsed_ms"
                | "fetched"
                | "applied"
                | "held"
                | "deferred"
                | "dead_lettered"
                | "cursor_before"
                | "cursor_after"
                | "bytes"
                | "line"
                | "passes"
                | "request_counter"
        ) {
            self.insert(field, value);
        }
    }
    fn text(&mut self, field: &Field, value: &str) {
        let class = match field.name() {
            "account_id" => Some("account"),
            "principal_id" | "source_principal_id" => Some("principal"),
            "device_id" | "source_device_id" => Some("device"),
            "conversation_id" => Some("conversation"),
            "group_id" => Some("group"),
            "contact_id" => Some("contact"),
            "username" => Some("username"),
            "message_id" => Some("message"),
            "envelope_id" => Some("envelope"),
            "object_id" | "object_hash" | "attachment_id" => Some("object"),
            "operation_id" => Some("operation"),
            "node_id" | "node_address" => Some("node"),
            "session_id" => Some("session"),
            "target_delivery_id" => Some("delivery"),
            _ => None,
        };
        if let Some(class) = class {
            if let Ok(hash) =
                ramflux_crypto::diagnostic_short_hash(self.key, class, value.as_bytes())
            {
                self.insert(field, json!(hash));
            }
        } else if matches!(
            field.name(),
            "phase"
                | "event"
                | "reason"
                | "reason_code"
                | "error_code"
                | "name"
                | "variant"
                | "state"
                | "stage"
                | "kind"
                | "outcome"
                | "method"
                | "effect"
                | "transport"
                | "stop_reason"
                | "check"
                | "object_kind"
                | "phase"
                | "event"
        ) && !value.is_empty()
            && value.len() <= 128
            && value.bytes().all(|v| v.is_ascii_alphanumeric() || matches!(v, b'_' | b'.'))
        {
            self.insert(field, json!(value));
        } else if field.name() != "message" {
            self.insert(field, json!(format!("[text:{}]", value.len())));
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
        if matches!(field.name(), "retryable" | "resumed" | "known_contact" | "stale" | "applied") {
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
