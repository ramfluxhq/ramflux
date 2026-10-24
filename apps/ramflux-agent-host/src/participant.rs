// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
//! Revalidate current rfd projections before reading content and immediately before sending.
use crate::{AgentBus, Checkpoint, Error, Result};
use serde_json::{Value, json};

async fn directory_find(
    bus: &mut impl AgentBus,
    method: &str,
    field: &str,
    matches: impl Fn(&Value) -> bool,
) -> Result<Option<Value>> {
    let mut cursor = Value::Null;
    let mut seen = std::collections::BTreeSet::new();
    loop {
        let page = bus.request(method, json!({"limit":100,"cursor":cursor}), None).await?;
        let batch = page[field].as_array().ok_or(Error::State)?;
        if batch.len() > 100
            || serde_json::to_vec(&page).map_err(|_| Error::State)?.len() > 1_048_576
        {
            return Err(Error::Limit);
        }
        if let Some(row) = batch.iter().find(|row| matches(row)) {
            return Ok(Some(row.clone()));
        }
        let next = page["next_cursor"].clone();
        if next.is_null() {
            return Ok(None);
        }
        let key = next.as_str().filter(|s| !s.is_empty() && s.len() <= 4096).ok_or(Error::State)?;
        if seen.len() >= 10_000 || !seen.insert(key.to_owned()) {
            return Err(Error::Limit);
        }
        cursor = next;
    }
}
pub(crate) async fn snapshot(bus: &mut impl AgentBus, method: &str, field: &str) -> Result<()> {
    directory_find(bus, method, field, |_| false).await?;
    Ok(())
}
pub(crate) async fn identity(
    bus: &mut impl AgentBus,
    state: &mut Checkpoint,
    account: &str,
) -> Result<()> {
    let status = bus.request("account.status", json!({}), None).await?;
    if status["client_mode"] != "headless_ai" || status["local_device_authorized"] != true {
        return Err(Error::IdentityLost);
    }
    let principal = field(&status, "principal_id")?;
    let devices = bus.request("device.list", json!({}), None).await?;
    let device = field(&devices, "local_device_id")?;
    if devices["principal_id"] != principal || !contains(&devices["devices"], "device_id", device) {
        return Err(Error::IdentityLost);
    }
    let own = directory_find(bus, "identity.directory", "identities", |v| {
        v["principal_id"] == principal && v["is_self"] == true
    })
    .await?
    .ok_or(Error::IdentityLost)?;
    if own["kind"] != "headless_ai" {
        return Err(Error::IdentityLost);
    }
    if !state.account_id.is_empty()
        && (state.account_id != account
            || state.principal_id != principal
            || state.device_id != device)
    {
        return Err(Error::IdentityLost);
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
    _max: usize,
) -> Result<Option<Value>> {
    let Some(row) =
        directory_find(bus, "conversation.directory", "conversations", |r| r["id"] == id).await?
    else {
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

pub(crate) async fn reply_outputs(
    bus: &mut impl AgentBus,
    state: &Checkpoint,
    conversation: &Value,
    message: &Value,
    text: &str,
    index: usize,
) -> Result<Vec<crate::checkpoint::Output>> {
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
    if let Some(group) = conversation["group_id"].as_str() {
        body["group_id"] = json!(group);
        Ok(vec![crate::checkpoint::Output {
            method: "group.send".into(),
            operation_id: operation,
            body,
        }])
    } else {
        let sender = field(message, "sender_id")?;
        let peer = directory_find(bus, "identity.directory", "identities", |peer| {
            peer["principal_id"] == sender
        })
        .await?
        .ok_or(Error::SurfaceRefused(ramflux_sdk::SurfaceRefusalCode::NotFound))?;
        let principal = field(&peer, "principal_id")?;
        if principal == state.principal_id || !array_has(&conversation["participants"], principal) {
            return Err(Error::Unauthorized);
        }
        let devices = peer["devices"]
            .as_array()
            .ok_or(Error::SurfaceRefused(ramflux_sdk::SurfaceRefusalCode::NotFound))?;
        let mut active = devices
            .iter()
            .filter(|device| device["revoked"] != true && device["status"] != "revoked")
            .collect::<Vec<_>>();
        active.sort_by_key(|device| device["device_id"].as_str());
        if active.is_empty() {
            return Err(Error::SurfaceRefused(ramflux_sdk::SurfaceRefusalCode::NotFound));
        }
        if active.len() > 96 {
            return Err(Error::Limit);
        }
        let created_at = crate::bus::now_ms() / 1000;
        let mut outputs = Vec::with_capacity(active.len());
        for device in active {
            let mut body = body.clone();
            let device_id = field(device, "device_id")
                .map_err(|_| Error::SurfaceRefused(ramflux_sdk::SurfaceRefusalCode::NotFound))?;
            let delivery_id = field(device, "target_delivery_id")
                .map_err(|_| Error::SurfaceRefused(ramflux_sdk::SurfaceRefusalCode::NotFound))?;
            let operation_id = ramflux_protocol::hash_base64url(
                "ramflux.agent.reply.device.v1",
                &ramflux_protocol::canonical_json_bytes(&(&operation, device_id))
                    .map_err(|_| Error::State)?,
            );
            body["recipient_device_id"] = json!(device_id);
            body["recipient_principal_commitment"] =
                json!(field(&peer, "contact_identity_commitment")?);
            body["target_delivery_id"] = json!(delivery_id);
            body["source_principal_id"] = json!(state.principal_id);
            body["envelope_id"] = json!(format!("agent-env-{operation_id}"));
            // Freeze this timestamp in the prepared checkpoint so retries reuse the same intent.
            // A delayed input must not inherit an expired gateway delivery timestamp.
            body["created_at"] = json!(created_at);
            body["ttl"] = json!(300);
            outputs.push(crate::checkpoint::Output {
                method: "message.submit".into(),
                operation_id,
                body,
            });
        }
        Ok(outputs)
    }
}
