// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Surface carriers use the ordinary synchronous message and group delivery adapters.
use crate::client::surface::{Carrier, PayloadKind};
use crate::prelude::*;
use serde_json::{Value, json};
use std::collections::BTreeMap;
fn invalid(message: &str) -> SdkError {
    SdkError::LocalBus(message.into())
}

pub(crate) async fn send(
    account: &mut LocalBusAccountState,
    carrier: &Carrier,
) -> Result<Value, SdkError> {
    let bytes = carrier.bytes()?;
    crate::client::surface::check_delivery_size(bytes.len())?;
    let thread = account
        .client
        .account_db()?
        .client_record("conversation", &carrier.conversation_id)?
        .ok_or_else(|| invalid("surface conversation absent"))?;
    let group = thread["group_id"].as_str();
    let group_epoch = group
        .map(|group| account.client.group_state(group).map(|state| state.group_epoch))
        .transpose()?;
    if let Some(group) = group {
        let request = LocalBusFrame::request(
            "surface-group",
            None,
            "ramflux.sdk.v1",
            "group.send",
            json!({
                "group_id":group,"conversation_id":carrier.conversation_id,
                "message_id":carrier.message_id,"sender_id":carrier.sender_device_id,
                "plaintext_body_base64":ramflux_protocol::encode_base64url(&bytes),"encrypted_body_base64":""
            }),
        );
        super::group::dispatch_group_send_request(&request, account).await?;
    } else {
        let peers = peer_commitments(account, carrier, &thread)?;
        for (root, principal) in peers {
            let engine = account.take_live_engine().await?;
            let manifest = account
                .client
                .cache_verified_device_manifest(&engine.config, &root, "surface_peer")
                .await;
            account.put_engine(engine);
            let manifest = manifest?;
            if manifest.devices.is_empty() {
                return Err(invalid("surface peer has no active verified devices"));
            }
            if principal.as_ref().is_some_and(|principal| *principal != manifest.principal_id) {
                return Err(invalid("surface peer root principal changed"));
            }
            for device in manifest.devices {
                let body: LocalBusMessageSubmitRequest = serde_json::from_value(json!({
                    "conversation_id":carrier.conversation_id,"message_id":carrier.message_id,
                    "envelope_id":crate::new_surface_message_id()?,"source_principal_id":carrier.sender_principal_id,
                    "sender_id":carrier.sender_device_id,"recipient_device_id":device.device_id,
                    "recipient_principal_commitment":root,"target_delivery_id":device.target_delivery_id,
                    "plaintext_body_base64":ramflux_protocol::encode_base64url(&bytes),"encrypted_body_base64":"",
                    "created_at":now_unix_timestamp(),"ttl":600
                }))?;
                super::message::submit_message(account, body).await?;
            }
        }
    }
    let client = &account.client;
    let result = client.account_db()?.surface_transaction(|| {
        let result = client
            .project_surface_message(
                &carrier.conversation_id,
                &carrier.message_id,
                crate::client::surface::SurfaceSender {
                    principal: &carrier.sender_principal_id,
                    device: &carrier.sender_device_id,
                    envelope_id: &carrier.message_id,
                    expires_at: None,
                    group_epoch,
                },
                &bytes,
                true,
            )?
            .ok_or_else(|| invalid("surface projection absent"))?;
        if result.accepted {
            client.retain_authored_surface(carrier)?;
            client.account_db()?.replace_surface_message_content(
                &carrier.conversation_id,
                &carrier.message_id,
                result.fallback_text.as_bytes(),
            )?;
        }
        Ok::<_, SdkError>(result)
    })?;
    let mut response = serde_json::to_value(result)?;
    response["surface_id"] = json!(carrier.surface_id);
    response["surface_ref"] = json!(carrier.surface_reference()?);
    response["message_id"] = json!(carrier.message_id);
    response["delivery_state"] = json!("submitted");
    Ok(response)
}

fn peer_commitments(
    account: &LocalBusAccountState,
    carrier: &Carrier,
    thread: &Value,
) -> Result<BTreeMap<String, Option<String>>, SdkError> {
    let client = &account.client;
    let local = client.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
    let mut peers = BTreeMap::new();
    if let Some(group) = thread["group_id"].as_str() {
        if !client.surface_group_device_allowed(group, &local.device_id)? {
            return Err(invalid("surface sender has no group membership"));
        }
        if carrier.payload_kind == PayloadKind::Action {
            let identity = client
                .account_db()?
                .client_record("identity", &carrier.author_principal_id)?
                .ok_or_else(|| invalid("surface author identity unavailable"))?;
            let commitment = identity["contact_identity_commitment"]
                .as_str()
                .ok_or_else(|| invalid("surface author root missing"))?;
            peers.insert(commitment.into(), Some(carrier.author_principal_id.clone()));
        } else {
            for row in super::super::group_delivery::directory(client, group)? {
                if row["member_id"] == local.device_id || row["principal_id"] == local.principal_id
                {
                    continue;
                }
                let commitment = row["member_principal_commitment"]
                    .as_str()
                    .ok_or_else(|| invalid("group member root unavailable"))?;
                if commitment != account.principal_commitment {
                    peers
                        .insert(commitment.into(), row["principal_id"].as_str().map(str::to_owned));
                }
            }
        }
    } else {
        let participants = thread["participants"]
            .as_array()
            .ok_or_else(|| invalid("surface direct participants absent"))?;
        if thread["kind"] != "direct" || !participants.iter().any(|p| p == &local.principal_id) {
            return Err(invalid("surface direct membership mismatch"));
        }
        let ids = if carrier.payload_kind == PayloadKind::Action {
            vec![carrier.author_principal_id.as_str()]
        } else {
            participants
                .iter()
                .filter_map(Value::as_str)
                .filter(|p| *p != local.principal_id)
                .collect()
        };
        if ids.len() != 1 {
            return Err(invalid("surface direct peer is ambiguous"));
        }
        for id in ids {
            let identity = client
                .account_db()?
                .client_record("identity", id)?
                .ok_or_else(|| invalid("surface peer identity missing"))?;
            peers.insert(
                identity["contact_identity_commitment"]
                    .as_str()
                    .ok_or_else(|| invalid("surface peer root missing"))?
                    .into(),
                Some(id.into()),
            );
        }
    }
    Ok(peers)
}

#[cfg(test)]
#[path = "surface_text_fixture.rs"]
mod fixture;
#[cfg(test)]
#[path = "surface_text_tests.rs"]
mod tests;
