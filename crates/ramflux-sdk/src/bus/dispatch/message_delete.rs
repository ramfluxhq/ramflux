// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Local erasure stays offline; EVERYONE uses one generated Delete across native recipients.
use super::daemon::local_bus_ok;
use crate::bus::daemon::LocalBusDispatchResult;
use crate::bus::protocol::{LocalBusFrame, LocalBusGroupSendRequest, LocalBusMessageDeleteRequest};
use crate::bus::state::LocalBusAccountState;
use crate::{GatewayDirectMessage, RamfluxClient, SdkError};
use ramflux_protocol::message as g;
use serde_json::json;

const MAX_RECIPIENTS: usize = 4096;

fn refused(reason: &str) -> SdkError {
    SdkError::GeneratedRefused {
        code: crate::GeneratedRefusalCode::Content,
        reason: format!("message.delete: {reason}"),
    }
}

pub(super) async fn dispatch(
    request: &LocalBusFrame,
    account: &mut LocalBusAccountState,
) -> Result<LocalBusDispatchResult, SdkError> {
    let body: LocalBusMessageDeleteRequest = serde_json::from_value(request.body.clone())?;
    if body.tombstone_id.is_some() {
        return Err(refused(
            "caller-selected tombstones are retired; use operation_id for retries",
        ));
    }
    if body.operation_id.as_ref().is_some_and(|id| id.is_empty() || id.len() > 256) {
        return Err(refused("operation_id must be 1..256 bytes"));
    }
    match body.delete_scope.as_str() {
        "local" => return local(account, &body),
        "everyone" => {}
        _ => return Err(refused("scope must be local or everyone")),
    }
    let draft = account.client.authored_delete_draft(
        &body.conversation_id,
        &body.message_id,
        body.operation_id.as_deref(),
    )?;
    let (event, count) = if let Some(group) = draft.original.group_id.as_ref() {
        let send = LocalBusGroupSendRequest {
            content: Some(draft.content),
            group_id: group.clone(),
            conversation_id: body.conversation_id.clone(),
            message_id: draft.operation,
            sender_id: account.gateway_config.device_id.clone(),
            encrypted_body_base64: String::new(),
            plaintext_body_base64: None,
            envelope_id: None,
            source_principal_id: None,
            target_delivery_id: None,
            federation: None,
            ttl: Some(account.client.content_ttl()?),
        };
        let mut routed = request.clone();
        routed.method = "group.send".into();
        routed.body = serde_json::to_value(send)?;
        let result = Box::pin(super::group::dispatch_group_send_request(&routed, account)).await?;
        let event = result.response_body["message_id"]
            .as_str()
            .ok_or_else(|| refused("group Delete event identifier missing"))?
            .to_owned();
        let count = result.response_body["submitted"].as_array().map_or(0, Vec::len)
            + result.response_body["federated_submitted"].as_array().map_or(0, Vec::len);
        (event, count)
    } else {
        send_direct(account, &body.conversation_id, &draft.operation, &draft.content).await?
    };
    let identity = ramflux_protocol::decode_base64url(&event)
        .map_err(|_| refused("Delete event identifier invalid"))?;
    let tombstone = g::identity::delete_tombstone(&identity)
        .map_err(|_| refused("Delete event identifier invalid"))?;
    Ok(local_bus_ok(json!({
        "conversation_id":body.conversation_id, "message_id":body.message_id,
        "delete_scope":"everyone", "delete_event_id":event,
        "tombstone_id":ramflux_protocol::encode_base64url(tombstone),
        "submitted_recipients":count,
    })))
}

fn local(
    account: &LocalBusAccountState,
    body: &LocalBusMessageDeleteRequest,
) -> Result<LocalBusDispatchResult, SdkError> {
    let db = account.client.account_db()?;
    let (tombstone, erased, bytes) = db.write_transaction(|| {
        let preview = super::object_erasure::preview(db, &body.message_id)?;
        let tombstone = if db.message_is_deleted(&body.message_id)?
            && let Some(old) =
                db.message_tombstone_for_message(&body.conversation_id, &body.message_id)?
        {
            old
        } else {
            account.client.delete_direct_message(
                &body.conversation_id,
                &body.message_id,
                "local",
                &ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?),
            )?
        };
        let (erased, bytes) = super::object_erasure::confirm(db, &preview)?;
        Ok::<_, SdkError>((tombstone, erased, bytes))
    })?;
    let mut response = json!({
        "conversation_id":tombstone.conversation_id,
        "message_id":tombstone.message_id,
        "delete_scope":tombstone.delete_scope,
        "tombstone_id":tombstone.tombstone_id,
    });
    super::object_erasure::attach(&mut response, erased, bytes);
    Ok(local_bus_ok(response))
}

fn direct_peer(client: &RamfluxClient, conversation: &str) -> Result<String, SdkError> {
    let own = client.own_account_anchor()?;
    let context = client
        .account_db()?
        .client_record("conversation", conversation)?
        .ok_or_else(|| refused("qualified direct conversation missing"))?;
    let roots = context["participant_roots"]
        .as_array()
        .ok_or_else(|| refused("immutable direct roots missing"))?;
    let [first, second] = roots.as_slice() else {
        return Err(refused("direct roots are ambiguous"));
    };
    let (Some(first), Some(second)) = (first.as_str(), second.as_str()) else {
        return Err(refused("direct roots are invalid"));
    };
    let peer = if first == own && second != own {
        second
    } else if second == own && first != own {
        first
    } else {
        return Err(refused("direct roots do not name the local account and one peer"));
    };
    if g::dm_scope::derive(&own, peer).map_err(|_| refused("invalid direct roots"))? != conversation
    {
        return Err(refused("direct conversation differs from its immutable roots"));
    }
    Ok(peer.into())
}

async fn send_direct(
    account: &mut LocalBusAccountState,
    conversation: &str,
    operation: &str,
    content: &g::Content,
) -> Result<(String, usize), SdkError> {
    let peer = direct_peer(&account.client, conversation)?;
    let mut engine = account.session_client().await?;
    let result = async {
        let manifest = account
            .client
            .cache_verified_device_manifest(&engine.config, &peer, "generated-delete")
            .await?;
        if manifest.devices.is_empty() || manifest.devices.len() > MAX_RECIPIENTS {
            return Err(refused("verified recipient cohort is empty or exceeds budget"));
        }
        let count = manifest.devices.len();
        let mut event = None;
        for device in manifest.devices {
            let message = GatewayDirectMessage {
                conversation_id: conversation.into(),
                message_id: operation.into(),
                envelope_id: ramflux_protocol::hash_base64url(
                    "ramflux.message.delete-transport.v1",
                    &ramflux_protocol::canonical_json_bytes(&(
                        operation,
                        &peer,
                        &device.device_id,
                        &device.target_delivery_id,
                    ))?,
                ),
                source_principal_id: engine.config.principal_id.clone(),
                sender_id: engine.config.device_id.clone(),
                recipient_device_id: Some(device.device_id),
                recipient_principal_commitment: Some(peer.clone()),
                target_delivery_id: device.target_delivery_id,
                encrypted_body: Vec::new(),
                created_at: crate::time::now_unix_timestamp(),
                ttl: account.client.content_ttl()?,
            };
            let (id, _) = account
                .client
                .send_generated_content_via_gateway(&mut engine, message, content)
                .await?;
            if event.as_ref().is_some_and(|old| old != &id) {
                return Err(SdkError::ReplayMismatch);
            }
            event = Some(id);
        }
        Ok((event.ok_or_else(|| refused("Delete recipient missing"))?, count))
    }
    .await;
    account.apply_session_metadata(engine);
    result
}
