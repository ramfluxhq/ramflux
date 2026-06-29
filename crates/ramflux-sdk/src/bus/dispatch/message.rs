// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![allow(clippy::missing_errors_doc)]
#![allow(clippy::wildcard_imports)]
use crate::prelude::*;

pub(crate) async fn dispatch_message_bus_request(
    request: &LocalBusFrame,
    state: &mut LocalBusDaemonState,
    connection: &LocalBusConnectionState,
) -> Result<LocalBusDispatchResult, SdkError> {
    match request.method.as_str() {
        "message.submit" => Box::pin(dispatch_message_submit_request(request, state)).await,
        "message.receive" => dispatch_message_receive_request(request, state, connection).await,
        "message.ack" => {
            let account_id = request_account_id(request)?;
            let body: LocalBusMessageAckRequest = serde_json::from_value(request.body.clone())?;
            let account = local_bus_account_mut(state, account_id)?;
            let mut engine = account.take_live_engine().await?;
            let result = account
                .client
                .ack_gateway_delivery(
                    &mut engine,
                    &body.envelope_id,
                    &body.receiver_device_id,
                    body.received_at,
                )
                .await;
            account.put_engine(engine);
            let cursor = result?;
            account.mark_acked(&body.envelope_id);
            Ok(local_bus_ok(serde_json::to_value(cursor)?))
        }
        "message.delete" => {
            let account_id = request_account_id(request)?;
            let account = local_bus_account(state, account_id)?;
            dispatch_message_delete(request, account)
        }
        "message.receipt.delivered" => {
            let account_id = request_account_id(request)?;
            let account = local_bus_account_mut(state, account_id)?;
            dispatch_message_receipt_delivered(request, account).await
        }
        "message.receipt.read" => {
            let account_id = request_account_id(request)?;
            let account = local_bus_account_mut(state, account_id)?;
            dispatch_message_receipt_read(request, account).await
        }
        "message.list" | "message.read" => {
            let account_id = request_account_id(request)?;
            let body: LocalBusConversationRequest = serde_json::from_value(request.body.clone())?;
            let account = local_bus_account(state, account_id)?;
            let messages = account.client.direct_messages(&body.conversation_id)?;
            let rejected = account.client.rejected_inbox(&body.conversation_id)?;
            Ok(local_bus_ok(serde_json::json!({
                "messages": messages,
                "rejected": rejected,
            })))
        }
        "conversation.list" => {
            let account_id = request_account_id(request)?;
            let account = local_bus_account(state, account_id)?;
            let conversations = account.client.conversation_list()?;
            Ok(local_bus_ok(serde_json::json!({ "conversations": conversations })))
        }
        "conversation.disappearing.set" => {
            let account_id = request_account_id(request)?;
            let account = local_bus_account(state, account_id)?;
            dispatch_conversation_disappearing_set(request, account)
        }
        "conversation.disappearing.expire" => {
            let account_id = request_account_id(request)?;
            let account = local_bus_account(state, account_id)?;
            dispatch_conversation_disappearing_expire(request, account)
        }
        "conversation.mute" => {
            let account_id = request_account_id(request)?;
            let account = local_bus_account(state, account_id)?;
            dispatch_conversation_mute(request, account)
        }
        other => Err(SdkError::LocalBus(format!("unsupported local bus method: {other}"))),
    }
}

async fn dispatch_message_submit_request(
    request: &LocalBusFrame,
    state: &mut LocalBusDaemonState,
) -> Result<LocalBusDispatchResult, SdkError> {
    let account_id = request_account_id(request)?;
    let body: LocalBusMessageSubmitRequest = serde_json::from_value(request.body.clone())?;
    let account = local_bus_account_mut(state, account_id)?;
    let entry = if let Some(plaintext) = body.plaintext_body()? {
        if !body.attachments.is_empty() {
            if body.federation.is_some() {
                return Err(SdkError::LocalBus(
                    "DM attachments over federation are not supported in this release".to_owned(),
                ));
            }
            let mut engine = account.take_live_engine().await?;
            if let Some(device_id) = body.recipient_device_id.as_deref() {
                account
                    .client
                    .resolve_target_principal_commitment(
                        &engine.config,
                        body.recipient_principal_commitment.as_deref(),
                        device_id,
                    )
                    .await?;
            }
            let message = body.clone().into_gateway_message_with_body(Vec::new());
            let result = account
                .client
                .send_plaintext_direct_message_with_attachments_via_gateway(
                    &mut engine,
                    message,
                    &plaintext,
                    &body.attachments,
                )
                .await;
            account.put_engine(engine);
            result?
        } else if let Some(federation) = body.federation.clone() {
            let recipient_principal_commitment = body.recipient_principal_commitment.clone();
            let message = body.into_gateway_message_with_body(Vec::new());
            let engine = account.take_live_engine().await?;
            if let Some(device_id) = message.recipient_device_id.as_deref() {
                federated_manifest_gate(
                    &account.client,
                    &federation,
                    recipient_principal_commitment.as_deref(),
                    device_id,
                )?;
            }
            let response = account.client.send_plaintext_federated_direct_message(
                &engine,
                message,
                &plaintext,
                &federation,
            );
            account.put_engine(engine);
            let response = response?;
            return Ok(local_bus_ok(serde_json::to_value(response)?));
        } else {
            let mut engine = account.take_live_engine().await?;
            if let Some(device_id) = body.recipient_device_id.as_deref() {
                account
                    .client
                    .resolve_target_principal_commitment(
                        &engine.config,
                        body.recipient_principal_commitment.as_deref(),
                        device_id,
                    )
                    .await?;
            }
            let result = account
                .client
                .send_plaintext_direct_message_via_gateway(
                    &mut engine,
                    body.into_gateway_message_with_body(Vec::new()),
                    &plaintext,
                )
                .await;
            account.put_engine(engine);
            result?
        }
    } else {
        let recipient_principal_commitment = body.recipient_principal_commitment.clone();
        let message = body.into_gateway_message()?;
        let mut engine = account.take_live_engine().await?;
        if let Some(device_id) = message.recipient_device_id.as_deref() {
            account
                .client
                .resolve_target_principal_commitment(
                    &engine.config,
                    recipient_principal_commitment.as_deref(),
                    device_id,
                )
                .await?;
        }
        let result = account.client.send_direct_message_via_gateway(&mut engine, message).await;
        account.put_engine(engine);
        result?
    };
    Ok(local_bus_ok(serde_json::to_value(entry)?))
}

/// Cross-node manifest gate for federated direct messages (C2 §5).
///
/// The recipient lives on a remote home node, so the sender's local gateway/device directory cannot
/// serve the manifest. Resolve and verify it directly from the recipient home node's federation HTTP
/// surface — the same base the federated send already uses for the recipient prekey fetch. The
/// manifest is self-authenticating against the expected commitment, so a lying remote node can only
/// fail closed. The gate runs before send, fail-closed.
fn federated_manifest_gate(
    client: &RamfluxClient,
    federation: &LocalBusFederationRoute,
    recipient_principal_commitment: Option<&str>,
    device_id: &str,
) -> Result<(), SdkError> {
    let manifest_url = federation.recipient_prekey_url.as_deref().ok_or_else(|| {
        SdkError::LocalBus(
            "federated direct messages require a recipient home-node url (--recipient-prekey-url) to verify the remote device manifest"
                .to_owned(),
        )
    })?;
    client.resolve_federated_target_principal_commitment(
        manifest_url,
        recipient_principal_commitment,
        device_id,
    )?;
    Ok(())
}

fn dispatch_message_delete(
    request: &LocalBusFrame,
    account: &LocalBusAccountState,
) -> Result<LocalBusDispatchResult, SdkError> {
    let body: LocalBusMessageDeleteRequest = serde_json::from_value(request.body.clone())?;
    let tombstone_id = body
        .tombstone_id
        .unwrap_or_else(|| format!("tombstone:{}:{}", body.conversation_id, body.message_id));
    let tombstone = account.client.delete_direct_message(
        &body.conversation_id,
        &body.message_id,
        &body.delete_scope,
        &tombstone_id,
    )?;
    Ok(local_bus_ok(serde_json::json!({
        "tombstone_id": tombstone.tombstone_id,
        "conversation_id": tombstone.conversation_id,
        "message_id": tombstone.message_id,
        "delete_scope": tombstone.delete_scope,
    })))
}

async fn dispatch_message_receipt_delivered(
    request: &LocalBusFrame,
    account: &mut LocalBusAccountState,
) -> Result<LocalBusDispatchResult, SdkError> {
    let body: LocalBusMessageReceiptDeliveredRequest =
        serde_json::from_value(request.body.clone())?;
    let delivered_at = body.delivered_at.unwrap_or_else(now_unix_timestamp);
    let ttl_seconds = body.ttl_seconds.unwrap_or(300);
    let receipt = account.client.mark_delivered(
        &body.conversation_id,
        &body.receiver_device_id,
        &body.message_id,
        delivered_at,
        ttl_seconds,
    )?;
    let mut response = serde_json::json!({
        "conversation_id": receipt.conversation_id,
        "receiver_device_id": receipt.receiver_device_id,
        "delivered_through_message_id": receipt.delivered_through_message_id,
        "delivered_at": receipt.delivered_at,
        "ttl_seconds": receipt.ttl_seconds,
        "scope": "local_projection",
    });
    if let (Some(recipient_device_id), Some(target_delivery_id)) =
        (body.recipient_device_id, body.target_delivery_id)
    {
        let mut engine = account.take_live_engine().await?;
        let receipt_id = format!(
            "receipt:delivered:{}:{}:{}",
            body.conversation_id, body.message_id, body.receiver_device_id
        );
        let event = SdkReceiptEventEnvelope {
            schema: "ramflux.sdk.receipt_event.v1".to_owned(),
            version: 1,
            receipt_id: receipt_id.clone(),
            event_seq: u64::try_from(delivered_at).unwrap_or(0),
            nonce: receipt_id.clone(),
            reader_device_id: body.receiver_device_id.clone(),
            event: SdkReceiptEventBody::Delivered {
                conversation_id: body.conversation_id.clone(),
                message_id: body.message_id.clone(),
                delivered_at,
                receiver_device_id: body.receiver_device_id.clone(),
                scope: "e2ee_private".to_owned(),
                ttl_seconds: u32::try_from(ttl_seconds).unwrap_or(u32::MAX),
            },
        };
        let message = receipt_gateway_message(
            account,
            &body.conversation_id,
            &receipt_visible_envelope_id(&receipt_id),
            &recipient_device_id,
            &target_delivery_id,
            delivered_at,
        );
        let entry =
            account.client.send_receipt_event_via_gateway(&mut engine, message, event).await;
        account.put_engine(engine);
        response["scope"] = serde_json::Value::String("network_e2ee".to_owned());
        response["entry"] = serde_json::to_value(entry?)?;
    }
    Ok(local_bus_ok(response))
}

async fn dispatch_message_receipt_read(
    request: &LocalBusFrame,
    account: &mut LocalBusAccountState,
) -> Result<LocalBusDispatchResult, SdkError> {
    let body: LocalBusMessageReceiptReadRequest = serde_json::from_value(request.body.clone())?;
    let read_at = body.read_at.unwrap_or_else(now_unix_timestamp);
    account.client.mark_read(&body.conversation_id, &body.reader_id, &body.message_id)?;
    let mut response = serde_json::json!({
        "conversation_id": body.conversation_id,
        "reader_id": body.reader_id,
        "read_through_message_id": body.message_id,
        "scope": "local_projection",
    });
    if let (Some(recipient_device_id), Some(target_delivery_id)) =
        (body.recipient_device_id.clone(), body.target_delivery_id.clone())
    {
        let mut engine = account.take_live_engine().await?;
        let receipt_id =
            format!("receipt:read:{}:{}:{}", body.conversation_id, body.message_id, body.reader_id);
        let event = SdkReceiptEventEnvelope {
            schema: "ramflux.sdk.receipt_event.v1".to_owned(),
            version: 1,
            receipt_id: receipt_id.clone(),
            event_seq: u64::try_from(read_at).unwrap_or(0),
            nonce: receipt_id.clone(),
            reader_device_id: body.reader_id.clone(),
            event: SdkReceiptEventBody::ReadPrivate {
                conversation_id: body.conversation_id.clone(),
                message_id: body.message_id.clone(),
                reader_identity: body.reader_id.clone(),
                read_at,
                own_device_scope: "e2ee_private".to_owned(),
            },
        };
        let message = receipt_gateway_message(
            account,
            &body.conversation_id,
            &receipt_visible_envelope_id(&receipt_id),
            &recipient_device_id,
            &target_delivery_id,
            read_at,
        );
        let entry =
            account.client.send_receipt_event_via_gateway(&mut engine, message, event).await;
        account.put_engine(engine);
        response["scope"] = serde_json::Value::String("network_e2ee".to_owned());
        response["entry"] = serde_json::to_value(entry?)?;
    }
    Ok(local_bus_ok(response))
}

fn receipt_gateway_message(
    account: &LocalBusAccountState,
    conversation_id: &str,
    receipt_id: &str,
    recipient_device_id: &str,
    target_delivery_id: &str,
    created_at: i64,
) -> GatewayDirectMessage {
    GatewayDirectMessage {
        conversation_id: conversation_id.to_owned(),
        message_id: receipt_id.to_owned(),
        envelope_id: receipt_id.to_owned(),
        source_principal_id: account.gateway_config.principal_id.clone(),
        sender_id: account.gateway_config.device_id.clone(),
        recipient_device_id: Some(recipient_device_id.to_owned()),
        target_delivery_id: target_delivery_id.to_owned(),
        encrypted_body: Vec::new(),
        created_at,
        ttl: 300,
    }
}

fn receipt_visible_envelope_id(receipt_id: &str) -> String {
    format!(
        "receipt_evt_{}",
        ramflux_crypto::blake3_256_base64url(
            "ramflux.receipt.visible_id.v1",
            receipt_id.as_bytes()
        )
    )
}

fn dispatch_conversation_disappearing_set(
    request: &LocalBusFrame,
    account: &LocalBusAccountState,
) -> Result<LocalBusDispatchResult, SdkError> {
    let body: LocalBusConversationDisappearingSetRequest =
        serde_json::from_value(request.body.clone())?;
    let policy = account.client.set_disappearing_policy(
        &body.conversation_id,
        body.ttl_secs,
        &body.countdown_mode,
        &body.scope,
        body.updated_at.unwrap_or_else(now_unix_timestamp),
    )?;
    Ok(local_bus_ok(serde_json::json!({
        "conversation_id": policy.conversation_id,
        "ttl_secs": policy.timer_seconds,
        "countdown_mode": policy.countdown_mode,
        "scope": policy.scope,
        "updated_at": policy.updated_at,
    })))
}

fn dispatch_conversation_disappearing_expire(
    request: &LocalBusFrame,
    account: &LocalBusAccountState,
) -> Result<LocalBusDispatchResult, SdkError> {
    let body: LocalBusConversationDisappearingExpireRequest =
        serde_json::from_value(request.body.clone())?;
    let tombstones = account.client.expire_disappearing_messages(
        &body.conversation_id,
        body.now.unwrap_or_else(now_unix_timestamp),
    )?;
    let tombstones = tombstones
        .into_iter()
        .map(|tombstone| {
            serde_json::json!({
                "tombstone_id": tombstone.tombstone_id,
                "conversation_id": tombstone.conversation_id,
                "message_id": tombstone.message_id,
                "delete_scope": tombstone.delete_scope,
            })
        })
        .collect::<Vec<_>>();
    Ok(local_bus_ok(serde_json::json!({ "tombstones": tombstones })))
}

fn dispatch_conversation_mute(
    request: &LocalBusFrame,
    account: &LocalBusAccountState,
) -> Result<LocalBusDispatchResult, SdkError> {
    let body: LocalBusConversationMuteRequest = serde_json::from_value(request.body.clone())?;
    if body.unmute {
        account.client.unmute_conversation(&body.conversation_id)?;
    } else {
        account
            .client
            .mute_conversation(&body.conversation_id, body.mute_until.unwrap_or(i64::MAX))?;
    }
    let state = account.client.conversation_list_state(&body.conversation_id)?;
    Ok(local_bus_ok(serde_json::json!({
        "conversation_id": state.conversation_id,
        "archived": state.archived,
        "pin_order": state.pin_order,
        "mute_until": state.mute_until,
        "hidden_at": state.hidden_at,
        "cleared_at": state.cleared_at,
    })))
}

pub(crate) async fn dispatch_message_receive_request(
    request: &LocalBusFrame,
    state: &mut LocalBusDaemonState,
    _connection: &LocalBusConnectionState,
) -> Result<LocalBusDispatchResult, SdkError> {
    let account_id = request_account_id(request)?;
    let body: LocalBusMessageReceiveRequest = serde_json::from_value(request.body.clone())?;
    let account = local_bus_account_mut(state, account_id)?;
    let mut engine = account.take_live_engine().await?;
    let receive_result = async {
        let plaintext = if let Some(conversation_id) = body.conversation_id.as_deref() {
            account
                .client
                .receive_gateway_plaintext_deliveries(
                    &mut engine,
                    body.limit,
                    conversation_id,
                    body.auto_fetch_attachments,
                    body.relay_service_key_base64.clone(),
                )
                .await?
        } else {
            Vec::new()
        };
        let entries = if body.conversation_id.is_none() && plaintext.is_empty() {
            account.client.receive_gateway_deliveries(&mut engine, body.limit).await?
        } else {
            plaintext.iter().map(|delivery| delivery.entry.clone()).collect()
        };
        Ok::<_, SdkError>((plaintext, entries))
    }
    .await;
    account.put_engine(engine);
    let (plaintext, entries) = receive_result?;
    let fresh = account.merge_deliveries(entries);
    let event = if fresh.is_empty() {
        None
    } else {
        Some(local_bus_event(
            request,
            account_id,
            "gateway",
            "gateway.deliver",
            serde_json::json!({ "entries": fresh }),
        ))
    };
    Ok(LocalBusDispatchResult {
        response_body: serde_json::json!({
            "entries": account.pending_page(body.limit),
            "decrypted_messages": plaintext,
        }),
        event,
    })
}
