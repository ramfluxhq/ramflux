// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Resolve current SDK routes for the explicit generated conversation carrier.
use super::conversation_mutation::Prepared;
use crate::bindings::{AdapterError, GeneratedErrorCode as Code};
use crate::prelude::*;
use serde_json::json;

pub(super) async fn send(
    account: &mut LocalBusAccountState,
    prepared: &Prepared,
) -> Result<LocalBusDispatchResult, SdkError> {
    let identity = &prepared.identity;
    let event = ramflux_protocol::encode_base64url(&identity.id);
    let routes = routes(account, prepared).await?;
    if routes.is_empty() {
        return Err(AdapterError::new(
            Code::NotConnected,
            "no verified recipient route is available",
        )
        .into());
    }
    let recipients = routes
        .iter()
        .map(|route| {
            let root = route
                .member_principal_commitment
                .as_deref()
                .ok_or(SdkError::IdentityRootMissing)?;
            Ok::<_, SdkError>(
                account
                    .client
                    .device_identity_for_root(root, &route.member_id)?
                    .storage_key()
                    .to_owned(),
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut deliveries = Vec::new();
    for route in routes {
        let target = route.member_id.clone();
        let key = route_key(&route)?;
        let accepted = super::conversation_journal::load(&account.client, &prepared.journal_key)?
            .is_some_and(|receipt| receipt.accepted.contains(&key));
        let outcome = if accepted {
            Ok(())
        } else {
            submit(account, prepared, &event, &recipients, route).await
        };
        deliveries.push(match outcome {
            Ok(()) => json!({"target":target,"state":"submitted"}),
            Err(error) => {
                json!({"target":target,"state":"failed","error":AdapterError::from_sdk(&error)})
            }
        });
    }
    let submitted = deliveries.iter().all(|delivery| delivery["state"] == "submitted");
    Ok(local_bus_ok(
        json!({"event_id":event,"message_id":event,"conversation_id":identity.conversation_id,
        "delivery_state": if submitted {"submitted"} else {"failed"},"deliveries":deliveries}),
    ))
}

async fn routes(
    account: &mut LocalBusAccountState,
    prepared: &Prepared,
) -> Result<Vec<LocalBusGroupMemberRoute>, SdkError> {
    let identity = &prepared.identity;
    if let Some(group) = identity.group_id.as_deref() {
        account
            .client
            .assert_shared_group_send_capacity(group, &account.gateway_config.device_id)?;
        let body = LocalBusGroupSendRequest {
            group_id: group.into(),
            conversation_id: identity.conversation_id.clone(),
            message_id: ramflux_protocol::encode_base64url(&identity.id),
            sender_id: account.gateway_config.device_id.clone(),
            encrypted_body_base64: String::new(),
            plaintext_body_base64: None,
            envelope_id: None,
            source_principal_id: None,
            target_delivery_id: None,
            federation: None,
            ttl: Some(account.client.content_ttl()?),
        };
        return super::super::group_delivery::resolve_current(account, &body).await;
    }
    let thread = account
        .client
        .account_db()?
        .client_record("conversation", &identity.conversation_id)?
        .ok_or_else(|| AdapterError::new(Code::TargetNotFound, "conversation absent"))?;
    let principal = account
        .client
        .device_branch
        .as_ref()
        .ok_or(SdkError::IdentityRootMissing)?
        .principal_id
        .clone();
    let (peer, root) = super::conversation_send::peer_root(account, &thread, &principal)?;
    let engine = account.session_client().await?;
    let manifest = account
        .client
        .cache_verified_device_manifest(engine.config(), &root, "conversation_peer")
        .await;
    account.apply_session_metadata(engine);
    let manifest = manifest?;
    if manifest.principal_id != peer || manifest.devices.is_empty() || manifest.devices.len() > 64 {
        return Err(
            AdapterError::new(Code::NotAuthorized, "conversation peer manifest mismatch").into()
        );
    }
    Ok(manifest
        .devices
        .into_iter()
        .map(|device| LocalBusGroupMemberRoute {
            member_id: device.device_id,
            member_principal_commitment: Some(root.clone()),
            device_signing_public_key: None,
            target_delivery_id: Some(device.target_delivery_id),
            federation: None,
        })
        .collect())
}

async fn submit(
    account: &mut LocalBusAccountState,
    prepared: &Prepared,
    event: &str,
    recipients: &[String],
    route: LocalBusGroupMemberRoute,
) -> Result<(), SdkError> {
    if route.federation.is_some() {
        return Err(AdapterError::new(
            Code::NotConnected,
            "the SDK generated carrier requires a local gateway route",
        )
        .into());
    }
    let target_key = route_key(&route)?;
    let source = account.client.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
    let message = GatewayDirectMessage {
        conversation_id: prepared.identity.conversation_id.clone(),
        message_id: event.into(),
        envelope_id: ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?),
        source_principal_id: source.principal_id.clone(),
        sender_id: source.device_id.clone(),
        recipient_device_id: Some(route.member_id),
        recipient_principal_commitment: route.member_principal_commitment,
        target_delivery_id: route.target_delivery_id.ok_or_else(|| {
            AdapterError::new(Code::NotConnected, "recipient delivery route absent")
        })?,
        encrypted_body: Vec::new(),
        created_at: now_unix_timestamp(),
        ttl: account.client.content_ttl()?,
    };
    let mut engine = account.session_client().await?;
    let reconcile = || reconcile_accepted(&account.client, prepared, &target_key);
    let outcome = account
        .client
        .submit_conversation_event(
            &mut engine,
            crate::client::routed::ConversationEvent {
                message,
                exact: &prepared.exact,
                wire: &prepared.wire,
                recipients,
                reconcile: Some(&reconcile),
            },
        )
        .await;
    account.apply_session_metadata(engine);
    outcome.map(|_| ())
}

fn route_key(route: &LocalBusGroupMemberRoute) -> Result<String, SdkError> {
    Ok(ramflux_crypto::blake3_256_base64url(
        "ramflux.conversation.delivery.v1",
        &ramflux_protocol::canonical_json_bytes(&(
            &route.member_principal_commitment,
            &route.member_id,
        ))?,
    ))
}

pub(crate) fn reconcile_accepted(
    client: &RamfluxClient,
    prepared: &Prepared,
    target_key: &str,
) -> Result<(), SdkError> {
    let mut receipt = super::conversation_journal::load(client, &prepared.journal_key)?
        .ok_or_else(|| AdapterError::new(Code::Internal, "missing receipt"))?;
    receipt.accepted.insert(target_key.to_owned());
    super::conversation_journal::save(client, &prepared.journal_key, &receipt)?;
    let private = prepared.journal_key.replace("conversation-operation/", "conversation-intent/");
    // Only the currently accepted event's payload is reattached after edit retirement.
    // A later edit/delete retires it normally; the content-free receipt survives.
    let (_, content) = RamfluxClient::decode_generated_inner(&prepared.exact)?;
    let target = match content.value.as_ref() {
        Some(ramflux_protocol::message::content::Value::Edit(v)) => v.target.as_ref(),
        Some(ramflux_protocol::message::content::Value::Delete(v)) => v.targets.first(),
        Some(ramflux_protocol::message::content::Value::Reaction(v)) => v.target.as_ref(),
        Some(ramflux_protocol::message::content::Value::Message(v)) => v.reply_to.as_ref(),
        _ => None,
    }
    .ok_or_else(|| AdapterError::new(Code::Internal, "missing mutation target"))?;
    let target = ramflux_protocol::encode_base64url(&target.id);
    if !client.account_db()?.message_is_deleted(&target)? {
        client.account_db()?.persist_message_actor_state(&target, &private, prepared)?;
    }
    Ok(())
}
