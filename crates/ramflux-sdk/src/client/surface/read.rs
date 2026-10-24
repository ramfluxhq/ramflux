// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Explicit surface content reads and safe metadata/fallback projections.
use super::{invalid, key};
use crate::{RamfluxClient, SdkError};
use serde_json::{Value, json};
impl RamfluxClient {
    pub(crate) fn surface_get(
        &self,
        id: &str,
        history_after: u64,
        action_id: Option<&str>,
    ) -> Result<Value, SdkError> {
        let Some(reference) = self.resolve_surface_reference(id, None, None)? else {
            return Ok(Value::Null);
        };
        self.surface_get_ref(&reference, history_after, action_id)
    }
    pub(crate) fn surface_get_ref(
        &self,
        reference: &str,
        history_after: u64,
        action_id: Option<&str>,
    ) -> Result<Value, SdkError> {
        let id = reference;
        let db = self.account_db()?;
        let Some(mut view) = db.client_record("surface", id)? else {
            return Ok(Value::Null);
        };
        if let Some((record, state)) = self.surface_state_ref(id)? {
            view["snapshot"] = serde_json::to_value(state.content())?;
            view["author_device_id"] = json!(record.author_device_id);
            view["streams"] = json!(state.stream_states());
            view["created_at"] = json!(record.created_at);
            view["posted_at"] = json!(record.created_at);
            view["updated_at"] = json!(record.updated_at);
        } else {
            view["snapshot"] = Value::Null;
        }
        if let (Some(author), Some(text)) =
            (view["author_principal_id"].as_str(), view["fallback_text"].as_str())
        {
            let rendered = super::fallback::render(author, text);
            view["fallback_text"] = json!(rendered);
        }
        let prefix = key("history", id) + "/";
        let first = db
            .surface_history_page::<Value>(&prefix, &prefix, 1)?
            .into_iter()
            .next()
            .and_then(|v| v["version"].as_u64());
        view["history_first_version"] = json!(first);
        view["history_truncated"] = json!(first.is_some_and(|v| v > 1));
        let mut history: Vec<Value> =
            db.surface_history_page(&prefix, &format!("{prefix}{history_after:020}"), 101)?;
        let more = history.len() > 100;
        history.truncate(100);
        view["history_next_version"] = if more {
            history.last().and_then(|v| v.get("version")).cloned().unwrap_or(Value::Null)
        } else {
            Value::Null
        };
        // Event bytes remain private at rest; the public history reports version/hash only.
        view["hash_history"] = json!(
            history
                .iter()
                .map(|v| json!({"version":v["version"],"surface_hash":v["surface_hash"]}))
                .collect::<Vec<_>>()
        );
        let actions_prefix = key("actions", id) + "/";
        let mut actions: Vec<Value> = if let Some(action) = action_id {
            if action.is_empty() || action.len() > 128 {
                return Err(invalid("invalid action cursor"));
            }
            db.load_actor_state::<Value>(&format!("{actions_prefix}{action}"))?
                .into_iter()
                .collect()
        } else {
            db.surface_history_page::<Value>(&actions_prefix, &actions_prefix, 100)?
        };
        view["action_missing"] = json!(action_id.is_some() && actions.is_empty());
        for action in &mut actions {
            action["action_receipt_id"] = action["id"].clone();
            action["receipt_verified"] = json!(!action["attestation"].is_null());
            if let Some(wire) = action["carrier"]["wire_base64"].as_str() {
                let raw = ramflux_protocol::decode_base64url(wire)
                    .map_err(|_| invalid("stored surface action wire invalid"))?;
                let parsed = ramflux_protocol::A2uiSurfaceAction::from_wire_bytes(&raw)?;
                action["task_binding"] = serde_json::to_value(parsed.task_binding())?;
            }
            if let Some(row) = action.as_object_mut() {
                row.remove("attestation");
            }
            if let Some(mut carrier) = action.as_object_mut().and_then(|row| row.remove("carrier"))
            {
                action["wire_base64"] = carrier["wire_base64"].take();
                action["signature"] = carrier["signature"].take();
            }
        }
        view["action_receipt_id"] = view["last_action_id"].clone();
        view["actions"] = json!(actions);
        if serde_json::to_vec(&view)?.len() > 512 * 1024 {
            return Err(invalid("surface response budget exceeded; select one action"));
        }
        Ok(view)
    }
    pub(crate) fn surface_list(
        &self,
        conversation: &str,
        after: &str,
        limit: u32,
    ) -> Result<Value, SdkError> {
        if !(1..=100).contains(&limit) {
            return Err(invalid("surface list limit must be 1..=100"));
        }
        let db = self.account_db()?;
        let mut cursor = after.to_owned();
        let mut rows = Vec::new();
        // Read bounded pages, with a finite scan budget even when most surfaces are elsewhere.
        for _ in 0..100 {
            let ids = db.client_directory_ids("surface", &cursor, 100)?;
            if ids.is_empty() {
                return Ok(json!({"surfaces":rows,"next_cursor":null}));
            }
            for id in &ids {
                cursor.clone_from(id);
                if let Some(view) = db.client_record("surface", id)?
                    && view["conversation_id"] == conversation
                {
                    rows.push(surface_metadata(&view));
                    if serde_json::to_vec(&rows)?.len() > 512 * 1024 {
                        return Err(invalid("surface list exceeds response budget"));
                    }
                    if rows.len() == limit as usize {
                        return Ok(json!({"surfaces":rows,"next_cursor":cursor}));
                    }
                }
            }
            if ids.len() < 100 {
                return Ok(json!({"surfaces":rows,"next_cursor":null}));
            }
        }
        Ok(json!({"surfaces":rows,"next_cursor":cursor}))
    }
    pub(crate) fn surface_message_fallback(
        &self,
        message: &str,
    ) -> Result<Option<(String, String)>, SdkError> {
        let db = self.account_db()?;
        let Some(reference) = db.load_actor_state::<Value>(&key("message", message))? else {
            return Ok(None);
        };
        let id = reference["surface_id"]
            .as_str()
            .ok_or_else(|| invalid("surface message binding absent"))?;
        let current = if let Some(reference) = reference["surface_ref"].as_str() {
            db.client_record("surface", reference)?
        } else {
            None
        };
        if reference["accepted"] == true
            && let Some(view) = &current
            && let (Some(author), Some(text)) =
                (view["author_principal_id"].as_str(), view["fallback_text"].as_str())
        {
            return Ok(Some((id.to_owned(), super::fallback::render(author, text))));
        }
        if reference["accepted"] == true {
            return Ok(Some((id.to_owned(), "[Surface unavailable]".into())));
        }
        // Rejected receipts contain only fixed local text.
        Ok(Some((
            id.to_owned(),
            reference["fallback_text"].as_str().unwrap_or("[Surface unavailable]").to_owned(),
        )))
    }
}
pub(crate) fn surface_metadata(view: &Value) -> Value {
    let mut out = serde_json::Map::new();
    for field in [
        "surface_id",
        "surface_ref",
        "removed",
        "streams",
        "created_at",
        "posted_at",
        "updated_at",
        "message_id",
        "sender_device_id",
        "envelope_id",
        "conversation_id",
        "author_principal_id",
        "version",
        "surface_hash",
        "delivery_devices",
        "own_device_copy_state",
        "closed",
        "out_of_sync",
        "executor_device_id",
        "is_action_executor",
        "renderer_error",
        "reason_code",
        "last_action_id",
        "last_action_message_id",
    ] {
        if let Some(value) = view.get(field) {
            out.insert(field.into(), value.clone());
        }
    }
    Value::Object(out)
}
