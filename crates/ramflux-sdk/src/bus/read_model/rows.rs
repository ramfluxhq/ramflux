// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Whitelisted client rows; no object payload, nonce, key or resume token is serialized.

use crate::prelude::*;
use serde_json::{Value, json};

pub(crate) fn row(client: &RamfluxClient, directory: &str, id: &str) -> Result<Value, SdkError> {
    let db = client.account_db()?;
    let own = db.client_record("self", "account")?.unwrap_or_else(|| json!({}));
    let mut saved = db.client_record(directory, id)?.unwrap_or_else(|| json!({}));
    match directory {
        "identity" => {
            saved["id"] = json!(id);
            saved["principal_commitment"] =
                saved.get("contact_identity_commitment").cloned().unwrap_or(Value::Null);
            for field in [
                "principal_id",
                "display_name",
                "kind",
                "contact_identity_commitment",
                "safety_number",
            ] {
                if saved.get(field).is_none() {
                    saved[field] = Value::Null;
                }
            }
            if saved.get("devices").is_none() {
                saved["devices"] = json!([]);
            }
            let commitment =
                saved.get("contact_identity_commitment").and_then(Value::as_str).unwrap_or("");
            let verification = db.contact_verification(commitment)?;
            saved["safety_state"] = json!(verification.map_or("unverified".to_owned(), |record| {
                if record.verification_state == "verified"
                    && saved.get("device_set_hash").and_then(Value::as_str)
                        != Some(record.verified_device_set_hash.as_str())
                {
                    "verification_stale".to_owned()
                } else {
                    record.verification_state
                }
            }));
            saved["kind_asserted"] = json!(client.root_asserted_principal_kind(id)?.is_some());
            saved["kind_verified"] = json!(client.verified_principal_kind(id)?.is_some());
            if let Some(kind) = client.root_asserted_principal_kind(id)? {
                saved["kind"] = json!(kind);
                if saved["safety_state"] == "verified" && saved["kind_verified"] == false {
                    saved["safety_state"] = json!("verification_stale");
                }
            }
            // Gateway-fetched safety material is persisted by the verified contact path.
            let contact = client.contact_entry(id)?;
            for field in
                ["reachable", "verified", "kind_asserted", "root_commitment", "root_source", "node"]
            {
                saved[field] = contact[field].clone();
            }
            saved["pair_recovery"] = json!(client.pair_recovery_metadata(id)?);
            saved["safety_number_available"] =
                json!(saved.get("safety_number").is_some_and(|number| !number.is_null()));
            Ok(saved)
        }
        "conversation" => conversation(client, id, &own, &saved),
        "object" => {
            let mut object = db.client_object_metadata(id)?;
            for field in [
                "name",
                "size",
                "mime",
                "direction",
                "owner",
                "conversation_id",
                "message_id",
                "relay_endpoint",
                "manifest_hash",
            ] {
                if let Some(value) = saved.get(field).filter(|value| !value.is_null()) {
                    object[field] = value.clone();
                } else if object.get(field).is_none() {
                    object[field] = Value::Null;
                }
            }
            object["transfer"] = db.client_object_transfer(id)?.unwrap_or(Value::Null);
            if let Some(operation) = db.object_operation(id)? {
                object["transfer_state"] = json!(operation.state);
            }
            if let Some(fetch) = client.received_attachment_status(id)? {
                object["transfer_state"] = fetch["transfer_state"].clone();
                object["last_error"] = fetch["last_error"].clone();
                object["operation_id"] = fetch["operation_id"].clone();
            }
            Ok(object)
        }
        "group" => {
            let mut group = serde_json::to_value(client.group_state(id)?)?;
            group["id"] = json!(id);
            group["safety_changes"] =
                saved.get("safety_changes").cloned().unwrap_or_else(|| json!([]));
            group["safety_change"] = saved.get("safety_change").cloned().unwrap_or(Value::Null);
            group["member_routes"] = json!(super::super::group_delivery::directory(client, id)?);
            group["conversation_id"] = saved.get("conversation_id").cloned().unwrap_or(Value::Null);
            group["conversation_ids"] =
                saved.get("conversation_ids").cloned().unwrap_or_else(|| json!([]));
            Ok(group)
        }
        "server" => Ok(
            json!({"id":id,"reachable":saved.get("reachable").cloned().unwrap_or(Value::Null),"last_check":saved.get("last_check").cloned().unwrap_or(Value::Null),"health_source":saved.get("health_source").cloned().unwrap_or(json!("not_checked"))}),
        ),
        "approval" => Ok(saved),
        _ => Err(SdkError::LocalBus("unknown directory".to_owned())),
    }
}

fn conversation(
    client: &RamfluxClient,
    id: &str,
    own: &Value,
    saved: &Value,
) -> Result<Value, SdkError> {
    let db = client.account_db()?;
    let device = own.get("device_id").and_then(Value::as_str).unwrap_or("");
    let mut value = db.client_conversation_metadata(id, device)?;
    for field in ["kind", "title", "participants", "group_id", "direct_route"] {
        value[field] = saved.get(field).cloned().unwrap_or(Value::Null);
    }
    value["self_principal_id"] = own.get("principal_id").cloned().unwrap_or(Value::Null);
    if let Some(commitment) =
        value.pointer("/direct_route/recipient_principal_commitment").and_then(Value::as_str)
        && let Some(peer) = db.client_record("commitment", commitment)?
        && let Some(principal) = peer.get("principal_id").and_then(Value::as_str)
        && let Some(identity) = db.client_record("identity", principal)?
        && let Some(devices) = identity.get("devices").and_then(Value::as_array)
    {
        let selected =
            value.pointer("/direct_route/recipient_device_ids/0").and_then(Value::as_str);
        if let Some(device) = devices
            .iter()
            .find(|device| device.get("device_id").and_then(Value::as_str) == selected)
        {
            value["direct_route"]["target_delivery_id"] = device["target_delivery_id"].clone();
        } else {
            value["direct_route"] = Value::Null;
        }
    }
    if let Some(group) = value.get("group_id").and_then(Value::as_str) {
        let routes = super::super::group_delivery::directory(client, group)?;
        let mut participants = std::collections::BTreeSet::new();
        for member in client.group_state(group)?.members {
            if let Some(peer) = db.client_record("device", &member)?
                && let Some(id) = peer.get("principal_id").and_then(Value::as_str)
            {
                participants.insert(id.to_owned());
            }
        }
        value["participants"] = json!(participants);
        value["member_routes"] = json!(routes);
    }
    if value["participants"].is_null() {
        let mut participants = std::collections::BTreeSet::new();
        if let Some(id) = own.get("principal_id").and_then(Value::as_str) {
            participants.insert(id.to_owned());
        }
        for sender in db.client_conversation_senders(id)? {
            if let Some(identity) = db.client_record("device", &sender)?
                && let Some(principal) = identity.get("principal_id").and_then(Value::as_str)
            {
                participants.insert(principal.to_owned());
            }
        }
        value["participants"] = json!(participants);
    }
    Ok(value)
}
