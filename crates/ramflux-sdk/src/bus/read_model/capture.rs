// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Persist verified public identity/route/context metadata at actor write boundaries.

use crate::prelude::*;
use serde_json::{Value, json};

pub(crate) fn initialize(account: &LocalBusAccountState) -> Result<(), SdkError> {
    let db = account.client.account_db()?;
    let config = &account.gateway_config;
    db.persist_client_record(
        "self",
        "account",
        &json!({"principal_id":config.principal_id,"device_id":config.device_id}),
    )?;
    if db.client_record("identity", &config.principal_id)?.is_none() {
        let public_key = account.client.device_branch.as_ref().map(|branch| {
            ramflux_protocol::encode_base64url(branch.signing_key.verifying_key().to_bytes())
        });
        db.persist_client_record("identity",&config.principal_id,&json!({"id":config.principal_id,"principal_id":config.principal_id,"display_name":null,"kind":null,"is_self":true,"contact_identity_commitment":account.principal_commitment,"devices":[{"id":config.device_id,"device_id":config.device_id,"label":null,"last_seen":null,"target_delivery_id":config.target_delivery_id,"signing_public_key":public_key}],"safety_number":null}))?;
    }
    let path = local_bus_account_manifest_path(
        account.client.account_index()?.root(),
        &db.local_account_id,
    );
    if let Some(manifest) = super::super::sync_status::optional_manifest(&path)
        && let Some(mut value) = db.client_record("identity", &config.principal_id)?
    {
        value["display_name"] = json!(manifest.label);
        let verified = account.client.verified_principal_kind(&config.principal_id)?;
        value["kind_verified"] = json!(verified.is_some());
        value["kind"] = if let Some(kind) = verified {
            json!(kind)
        } else {
            json!(manifest.kind.unwrap_or_else(|| {
                if manifest.client_mode == LocalBusClientMode::HeadlessAi {
                    "headless_ai".to_owned()
                } else {
                    "human".to_owned()
                }
            }))
        };
        db.persist_client_record("identity", &config.principal_id, &value)?;
    }
    let mut device = db.client_record("device", &config.device_id)?.unwrap_or_else(|| json!({}));
    device["principal_id"] = json!(config.principal_id);
    db.persist_client_record("device", &config.device_id, &device)?;
    Ok(())
}

pub(crate) fn capture(
    account: &LocalBusAccountState,
    request: &LocalBusFrame,
    response: &Value,
) -> Result<(), SdkError> {
    let db = account.client.account_db()?;
    let body = &request.body;
    let own = &account.gateway_config.principal_id;
    if request.method == "account.create" {
        let root = account.client.account_index()?.root();
        let path = local_bus_account_manifest_path(root, &db.local_account_id);
        let mut manifest = read_local_bus_account_manifest(&path)?;
        let metadata: LocalBusAccountCreateRequest = serde_json::from_value(body.clone())?;
        if metadata.label.is_some() {
            manifest.label = metadata.label;
        }
        write_local_bus_account_manifest(root, &manifest)?;
    }
    if matches!(request.method.as_str(), "contact.safety_number" | "contact.verify")
        && let Some(commitment) =
            response.get("contact_identity_commitment").and_then(Value::as_str)
        && let Some(peer) = db.client_record("commitment", commitment)?
        && let Some(id) = peer.get("principal_id").and_then(Value::as_str)
        && let Some(mut value) = db.client_record("identity", id)?
    {
        value["safety_number"] = response.get("safety_number").cloned().unwrap_or(Value::Null);
        db.persist_client_record("identity", id, &value)?;
    }
    if request.method == "message.submit" {
        let id = required(body, "conversation_id")?;
        let peer = body
            .get("recipient_device_id")
            .and_then(Value::as_str)
            .map(|device| db.client_record("device", device))
            .transpose()?
            .flatten();
        let principal =
            peer.as_ref().and_then(|peer| peer.get("principal_id")).and_then(Value::as_str);
        let participants = std::iter::once(own.as_str())
            .chain(principal)
            .collect::<std::collections::BTreeSet<_>>();
        let commitment = body
            .get("recipient_principal_commitment")
            .filter(|v| !v.is_null())
            .cloned()
            .or_else(|| peer.as_ref().and_then(|p| p.get("principal_commitment")).cloned());
        db.persist_client_record("conversation",id,&json!({"kind":"direct","title":body.get("title"),"participants":participants,"group_id":null,"direct_route":{"recipient_principal_commitment":commitment,"recipient_device_ids":body.get("recipient_device_id").map(|id|vec![id.clone()]).unwrap_or_default(),"target_delivery_id":body.get("target_delivery_id"),"federation":body.get("federation")}}))?;
        if let Some(attachments) = body.get("attachments").and_then(Value::as_array) {
            for attachment in attachments {
                let attachment: LocalBusMessageAttachmentInput =
                    serde_json::from_value(attachment.clone())?;
                object_metadata(
                    db,
                    &attachment.object_id,
                    &serde_json::to_value(&attachment)?,
                    own,
                    Some(body),
                )?;
            }
        }
    }
    capture_group(account, request)?;
    if request.method.starts_with("object.put")
        && let Some(id) = body.get("object_id").and_then(Value::as_str)
    {
        object_metadata(db, id, body, own, None)?;
    }
    if matches!(request.method.as_str(), "object.get" | "object.get.begin")
        && let Some(id) = body.get("object_id").and_then(Value::as_str)
    {
        let mut value = db.client_record("object", id)?.unwrap_or_else(|| json!({}));
        if let Some(len) = response.get("total_len") {
            value["size"] = len.clone();
        }
        db.persist_client_record("object", id, &value)?;
    }
    Ok(())
}

#[derive(serde::Deserialize)]
struct ObjectMetadata {
    name: Option<String>,
    mime: Option<String>,
    relay_endpoint: Option<String>,
}

fn object_metadata(
    db: &AccountDb,
    id: &str,
    body: &Value,
    own: &str,
    message: Option<&Value>,
) -> Result<(), SdkError> {
    let mut value = db
        .client_record("object", id)?
        .unwrap_or_else(|| json!({"direction":"outgoing","owner":own}));
    let metadata: ObjectMetadata = serde_json::from_value(body.clone())?;
    for (field, text) in [
        ("name", metadata.name),
        ("mime", metadata.mime),
        ("relay_endpoint", metadata.relay_endpoint),
    ] {
        if let Some(text) = text {
            if text.len() > 1024 {
                return Err(SdkError::LocalBus(format!("{field} exceeds 1024 bytes")));
            }
            value[field] = json!(text);
        }
    }
    if let Some(encoded) = body.get("plaintext_base64").and_then(Value::as_str) {
        // Successful dispatch has already validated this base64url payload.
        value["size"] = json!(encoded.trim_end_matches('=').len() * 3 / 4);
    } else if let Some(len) = body.get("total_len") {
        value["size"] = len.clone();
    }
    if let Some(message) = message {
        value["conversation_id"] = message["conversation_id"].clone();
        value["message_id"] = message["message_id"].clone();
    }
    db.persist_client_record("object", id, &value)?;
    Ok(())
}
fn required<'a>(value: &'a Value, key: &str) -> Result<&'a str, SdkError> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| SdkError::LocalBus(format!("missing {key}")))
}

pub(crate) fn capture_mcp_event(
    account: &LocalBusAccountState,
    request: &LocalBusFrame,
    event_type: &str,
    body: &mut Value,
) -> Result<(), SdkError> {
    let db = account.client.account_db()?;
    if let Some(id) = body.get("approval_id").and_then(Value::as_str).map(str::to_owned) {
        let previous = db.client_record("approval", &id)?.unwrap_or_else(|| json!({}));
        for field in ["conversation_id", "context_id"] {
            body[field] = request
                .body
                .get(field)
                .cloned()
                .or_else(|| previous.get(field).cloned())
                .unwrap_or(Value::Null);
        }
        let mut record = body.clone();
        record["id"] = json!(id);
        if event_type != "mcp.approval.request"
            && record.get("status").and_then(Value::as_str) == Some("pending")
        {
            record["status"] = json!(event_type);
        }
        db.persist_client_record("approval", &id, &record)?;
    }
    Ok(())
}

fn capture_group(account: &LocalBusAccountState, request: &LocalBusFrame) -> Result<(), SdkError> {
    let db = account.client.account_db()?;
    let body = &request.body;
    if matches!(
        request.method.as_str(),
        "group.send" | "group.receive" | "group.read" | "group.create"
    ) && body.get("conversation_id").is_some()
    {
        let group = required(body, "group_id")?;
        let conversation = required(body, "conversation_id")?;
        let members = account.client.group_state(group)?.members;
        let mut principals = std::collections::BTreeSet::new();
        for device in members {
            if let Some(peer) = db.client_record("device", &device)?
                && let Some(principal) = peer.get("principal_id").and_then(Value::as_str)
            {
                principals.insert(principal.to_owned());
            }
        }
        let old = db.client_record("group", group)?.unwrap_or_else(|| json!({}));
        let mut links = old
            .get("conversation_ids")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect::<std::collections::BTreeSet<_>>();
        if let Some(id) = old.get("conversation_id").and_then(Value::as_str) {
            links.insert(id.to_owned());
        }
        links.insert(conversation.to_owned());
        let single = if links.len() == 1 { Some(conversation) } else { None };
        db.persist_client_record(
            "group",
            group,
            &json!({"conversation_id":single,"conversation_ids":links}),
        )?;
        db.persist_client_record("conversation",conversation,&json!({"kind":"group","group_id":group,"title":body.get("title"),"participants":principals,"direct_route":null}))?;
    }
    Ok(())
}
