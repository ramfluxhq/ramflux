// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
//! Revalidate current rfd projections before reading content and immediately before sending.
use crate::{AgentBus, Checkpoint, Error, Result};
use serde_json::{Value, json};

pub(crate) async fn directory(
    bus: &mut impl AgentBus,
    method: &str,
    field: &str,
    max: usize,
) -> Result<Vec<Value>> {
    let mut rows = Vec::new();
    let mut cursor = Value::Null;
    let mut pages = 0usize;
    let mut bytes = 0usize;
    loop {
        pages += 1;
        if pages > max + 1 {
            return Err(Error::Limit);
        }
        let page = bus.request(method, json!({"limit":100,"cursor":cursor}), None).await?;
        bytes = bytes.saturating_add(serde_json::to_vec(&page).map_err(|_| Error::Bus)?.len());
        if bytes > 1_048_576 {
            return Err(Error::Limit);
        }
        let next = page["next_cursor"].clone();
        let batch = page[field].as_array().ok_or(Error::Bus)?;
        if rows.len().saturating_add(batch.len()) > max {
            return Err(Error::Limit);
        }
        rows.extend(batch.iter().cloned());
        if next.is_null() {
            return Ok(rows);
        }
        if next == cursor || next.as_str().is_none_or(|s| s.len() > 4096) {
            return Err(Error::Bus);
        }
        cursor = next;
    }
}
pub(crate) async fn identity(
    bus: &mut impl AgentBus,
    state: &mut Checkpoint,
    account: &str,
) -> Result<()> {
    let status = bus.request("account.status", json!({}), None).await?;
    if status["client_mode"] != "headless_ai" || status["local_device_authorized"] != true {
        return Err(Error::Unauthorized);
    }
    let principal = field(&status, "principal_id")?;
    let devices = bus.request("device.list", json!({}), None).await?;
    let device = field(&devices, "local_device_id")?;
    if devices["principal_id"] != principal || !contains(&devices["devices"], "device_id", device) {
        return Err(Error::Unauthorized);
    }
    let identities = directory(bus, "identity.directory", "identities", 1024).await?;
    let own = identities
        .iter()
        .find(|v| v["principal_id"] == principal && v["is_self"] == true)
        .ok_or(Error::Unauthorized)?;
    if own["kind"] != "headless_ai" {
        return Err(Error::Unauthorized);
    }
    if !state.account_id.is_empty()
        && (state.account_id != account
            || state.principal_id != principal
            || state.device_id != device)
    {
        return Err(Error::Unauthorized);
    }
    state.account_id = account.into();
    state.principal_id = principal.into();
    state.device_id = device.into();
    Ok(())
}
pub(crate) async fn conversation(
    bus: &mut impl AgentBus,
    state: &Checkpoint,
    id: &str,
    max: usize,
) -> Result<Option<Value>> {
    let rows = directory(bus, "conversation.directory", "conversations", max).await?;
    let Some(row) = rows.into_iter().find(|r| r["id"] == id) else {
        return Ok(None);
    };
    if row["removed"] == true || row["deleted"] == true {
        return Ok(None);
    }
    if let Some(group) = row["group_id"].as_str() {
        let membership = bus.request("group.members", json!({"group_id":group}), None).await?;
        if membership["deleted"] == true
            || !array_has(&membership["members"], &state.device_id)
                && !array_has(&membership["members"], &state.principal_id)
        {
            return Ok(None);
        }
    } else if row["kind"] != "direct" || !array_has(&row["participants"], &state.principal_id) {
        return Ok(None);
    }
    Ok(Some(row))
}
pub(crate) fn array_has(value: &Value, id: &str) -> bool {
    value.as_array().is_some_and(|values| values.iter().any(|v| v == id))
}
fn contains(value: &Value, key: &str, id: &str) -> bool {
    value.as_array().is_some_and(|values| values.iter().any(|v| v[key] == id))
}
pub(crate) fn field<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty() && s.len() <= 1024)
        .ok_or(Error::Bus)
}

pub(crate) async fn reply_body(
    bus: &mut impl AgentBus,
    state: &Checkpoint,
    conversation: &Value,
    message: &Value,
    text: &str,
    index: usize,
) -> Result<(String, String, Value)> {
    let conversation_id = field(conversation, "id")?;
    let input_id = field(message, "message_id")?;
    let operation = ramflux_protocol::hash_base64url(
        "ramflux.agent.reply.v1",
        &ramflux_protocol::canonical_json_bytes(&(
            &state.account_id,
            conversation_id,
            input_id,
            index,
        ))
        .map_err(|_| Error::Bus)?,
    );
    let message_id = format!("agent-{operation}");
    let mut body = json!({"conversation_id":conversation_id,"message_id":message_id,"sender_id":state.device_id,"encrypted_body_base64":"","plaintext_body_base64":ramflux_protocol::encode_base64url(text.as_bytes())});
    let method = if let Some(group) = conversation["group_id"].as_str() {
        body["group_id"] = json!(group);
        "group.send"
    } else {
        let sender = field(message, "sender_id")?;
        let peers = directory(bus, "identity.directory", "identities", 1024).await?;
        let peer =
            peers.iter().find(|peer| peer["principal_id"] == sender).ok_or(Error::Unauthorized)?;
        let principal = field(peer, "principal_id")?;
        if principal == state.principal_id || !array_has(&conversation["participants"], principal) {
            return Err(Error::Unauthorized);
        }
        let device = peer["devices"]
            .as_array()
            .and_then(|devices| {
                devices
                    .iter()
                    .filter(|device| {
                        device["revoked"] != true
                            && device["status"] != "revoked"
                            && device["device_id"].as_str().is_some()
                            && device["target_delivery_id"].as_str().is_some()
                    })
                    .min_by_key(|device| device["device_id"].as_str())
            })
            .ok_or(Error::Unauthorized)?;
        body["recipient_device_id"] = json!(field(device, "device_id")?);
        body["recipient_principal_commitment"] = json!(field(peer, "contact_identity_commitment")?);
        body["target_delivery_id"] = json!(field(device, "target_delivery_id")?);
        body["source_principal_id"] = json!(state.principal_id);
        body["envelope_id"] = json!(format!("agent-env-{operation}"));
        // Freeze this timestamp in the prepared checkpoint so retries reuse the same intent.
        // A delayed input must not inherit an expired gateway delivery timestamp.
        body["created_at"] = json!(crate::bus::now_ms() / 1000);
        body["ttl"] = json!(300);
        "message.submit"
    };
    Ok((method.into(), operation, body))
}
