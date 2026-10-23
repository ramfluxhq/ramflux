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
        let db = self.account_db()?;
        let Some(mut view) = db.client_record("surface", id)? else {
            return Ok(Value::Null);
        };
        if let Some((record, state)) = self.surface_state(id)? {
            view["snapshot"] = serde_json::to_value(state.content())?;
            view["author_device_id"] = json!(record.author_device_id);
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
        view["actions"] = if let Some(action) = action_id {
            if action.is_empty() || action.len() > 128 {
                return Err(invalid("invalid action cursor"));
            }
            json!(
                db.load_actor_state::<Value>(&format!("{actions_prefix}{action}"))?
                    .into_iter()
                    .collect::<Vec<_>>()
            )
        } else {
            json!(db.surface_history_page::<Value>(&actions_prefix, &actions_prefix, 100)?)
        };
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
        let current = db.client_record("surface", id)?;
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
        "conversation_id",
        "author_principal_id",
        "version",
        "surface_hash",
        "closed",
        "renderer_error",
        "last_action_id",
        "last_action_message_id",
    ] {
        if let Some(value) = view.get(field) {
            out.insert(field.into(), value.clone());
        }
    }
    Value::Object(out)
}
