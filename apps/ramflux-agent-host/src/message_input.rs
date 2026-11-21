// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Exact durable read-model lookup before engine input and before output delivery.
use crate::{AgentBus, Error, Result};
use serde_json::{Value, json};

pub(crate) async fn read(
    bus: &mut impl AgentBus,
    conversation: &str,
    id: &str,
) -> Result<Option<Value>> {
    let detail = bus
        .request("message.list", json!({"conversation_id":conversation,"message_id":id}), None)
        .await?;
    if detail["schema"] != ramflux_sdk::typed_read_model::READ_MODEL_SCHEMA {
        return Err(Error::MalformedField("message schema"));
    }
    let message = detail
        .get("message")
        .filter(|row| row.is_object())
        .ok_or(Error::MalformedField("message"))?;
    if message["id"] != id || message["conversation_id"] != conversation {
        return Err(Error::MalformedField("message identity"));
    }
    if message["state"] != "content" || message["kind"] != "message" || message["is_own"] != false {
        return Ok(None);
    }
    crate::participant::field(&message["author"], "account_anchor")?;
    crate::participant::field(&message["author"], "device_id")?;
    if message["text"].as_str().is_none_or(|text| text.len() > crate::config::MAX_TEXT_BYTES) {
        return Ok(None);
    }
    Ok(Some(message.clone()))
}
