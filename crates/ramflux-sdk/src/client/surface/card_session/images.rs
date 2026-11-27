// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Image slots leave the SDK as an object selector. The host reads the bytes through the
//! object APIs (`object.fetch`, then `object.get*`); this module does no network work.
use crate::RamfluxClient;
use serde_json::{Value, json};

const MAX_IMAGE_BYTES: u64 = 8 * 1024 * 1024;
const MAX_DEPTH: usize = 64;

/// Replace the `attachment` selector of every `kind:"image"` host slot in `value`.
pub(super) fn resolve(client: &RamfluxClient, conversation: &str, value: &mut Value) {
    visit(client, conversation, value, 0);
}

fn visit(client: &RamfluxClient, conversation: &str, value: &mut Value, depth: usize) {
    if depth > MAX_DEPTH {
        return;
    }
    match value {
        Value::Object(map) => {
            if map.get("kind").and_then(Value::as_str) == Some("image")
                && let Some(selector) = map.get("attachment")
            {
                let resolved = lookup(client, conversation, selector).unwrap_or_else(unavailable);
                map.insert("attachment".into(), resolved);
                return;
            }
            for child in map.values_mut() {
                visit(client, conversation, child, depth + 1);
            }
        }
        Value::Array(items) => {
            for item in items {
                visit(client, conversation, item, depth + 1);
            }
        }
        _ => {}
    }
}

fn unavailable() -> Value {
    json!({"retrieval": "unavailable", "reason": "card_image_unavailable"})
}

/// `None` for every refusal; the host never learns which check failed.
fn lookup(client: &RamfluxClient, conversation: &str, selector: &Value) -> Option<Value> {
    let object = selector.get("object_id")?.as_str()?;
    let digest = selector.get("manifest_digest")?.as_str()?;
    if !client.surface_attachment_in_conversation(object, digest, conversation).ok()? {
        return None;
    }
    if client.account_db().ok()?.object_is_tombstoned(object).ok()? {
        return None;
    }
    let row = crate::bus::read_model::row(client, "object", object).ok()?;
    if row.get("conversation_id").and_then(Value::as_str) != Some(conversation) {
        return None;
    }
    if row.get("manifest_hash").and_then(Value::as_str).is_some_and(|hash| hash != digest) {
        return None;
    }
    let size = row.get("size").filter(|size| !size.is_null());
    if let Some(size) = size
        && size.as_u64().is_none_or(|bytes| bytes > MAX_IMAGE_BYTES)
    {
        return None;
    }
    let transfer_state = row.get("transfer_state").and_then(Value::as_str).unwrap_or("not_fetched");
    Some(json!({
        "retrieval": "object",
        "object_id": object,
        "manifest_digest": digest,
        "transfer_state": transfer_state,
        "size": size.cloned().unwrap_or(Value::Null),
        "mime": row.get("mime").cloned().unwrap_or(Value::Null),
    }))
}
