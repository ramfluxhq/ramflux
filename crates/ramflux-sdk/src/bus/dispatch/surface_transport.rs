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
    if let Err(error) = crate::client::surface::check_delivery_size(bytes.len()) {
        account.client.surface_outgoing_too_large(carrier)?;
        return Err(error);
    }
    let thread = account
        .client
        .account_db()?
        .client_record("conversation", &carrier.conversation_id)?
        .ok_or_else(|| invalid("surface conversation absent"))?;
    let group = thread["group_id"].as_str();
    let group_epoch = group
        .map(|group| account.client.group_state(group).map(|state| state.group_epoch))
        .transpose()?;
    let outcome = account.client.stage_surface_outgoing(carrier, group_epoch)?;
    if !outcome.accepted {
        return Ok(serde_json::to_value(outcome)?);
    }
    let sent: Result<(), SdkError> = async {
    if let Some(group) = group {
        let request = LocalBusFrame::request(
            "surface-group",
            None,
            "ramflux.sdk.v1",
            "group.send",
            json!({
                "group_id":group,"conversation_id":carrier.conversation_id,
                "message_id":RamfluxClient::surface_timeline_id(carrier)?,"sender_id":carrier.sender_device_id,
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
                    "conversation_id":carrier.conversation_id,"message_id":RamfluxClient::surface_timeline_id(carrier)?,
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
        Ok(())
    }.await;
    if let Err(error) = sent {
        account.client.set_surface_outgoing_state(carrier, "failed")?;
        return Err(error);
    }
    if let Err(error) = super::super::device_history::push(account).await {
        account.client.set_surface_outgoing_state(carrier, "failed")?;
        return Err(error);
    }
    account.client.set_surface_outgoing_state(carrier, "submitted")?;
    let mut response = serde_json::to_value(outcome)?;
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
    let local = account.client.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
    let participants = thread["participants"]
        .as_array()
        .ok_or_else(|| invalid("surface direct participants absent"))?;
    if thread["kind"] != "direct" || !participants.iter().any(|id| id == &local.principal_id) {
        return Err(invalid("surface direct membership mismatch"));
    }
    let peers = if carrier.payload_kind == PayloadKind::Action {
        vec![carrier.author_principal_id.as_str()]
    } else {
        participants
            .iter()
            .filter_map(Value::as_str)
            .filter(|id| *id != local.principal_id)
            .collect()
    };
    if peers.len() != 1 {
        return Err(invalid("surface direct peer is ambiguous"));
    }
    let mut roots = BTreeMap::new();
    for peer in peers {
        let identity = account
            .client
            .account_db()?
            .client_record("identity", peer)?
            .ok_or_else(|| invalid("surface peer identity missing"))?;
        let root = identity["contact_identity_commitment"]
            .as_str()
            .ok_or_else(|| invalid("surface peer root missing"))?;
        roots.insert(root.into(), Some(peer.into()));
    }
    Ok(roots)
}

#[cfg(test)]
#[path = "surface_text_fixture.rs"]
mod fixture;
#[cfg(test)]
#[path = "surface_text_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "surface_dm_tests.rs"]
mod dm_tests;
