// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![allow(clippy::missing_errors_doc)]
#![allow(clippy::wildcard_imports)]
use crate::prelude::*;

struct ResolvedMessageRecipient {
    principal_id: Option<String>,
    principal_commitment: String,
}

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
            account.mark_acked(&body.envelope_id)?;
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
        "message.franking_evidence" => {
            let account_id = request_account_id(request)?;
            let body: LocalBusMessageFrankingEvidenceRequest =
                serde_json::from_value(request.body.clone())?;
            let account = local_bus_account(state, account_id)?;
            let evidence = account.client.selected_franking_evidence_for_direct_message(
                &body.conversation_id,
                &body.message_id,
            )?;
            Ok(local_bus_ok(serde_json::to_value(evidence)?))
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
    submit_message(account, body).await
}

pub(super) async fn submit_message(
    account: &mut LocalBusAccountState,
    body: LocalBusMessageSubmitRequest,
) -> Result<LocalBusDispatchResult, SdkError> {
    if let Some(plaintext) = body.plaintext_body()?
        && crate::client::surface::Carrier::decode(&plaintext)?.is_some()
    {
        crate::client::surface::check_delivery_size(plaintext.len())?;
    }
    let entry = if let Some(plaintext) = body.plaintext_body()? {
        if !body.attachments.is_empty() {
            if body.federation.is_some() {
                return Err(SdkError::LocalBus(
                    "DM attachments over federation are not supported in this release".to_owned(),
                ));
            }
            let mut engine = account.take_live_engine().await?;
            let recipient = resolve_local_message_recipient_principal_commitment(
                account,
                &engine.config,
                body.recipient_principal_commitment.as_deref(),
                body.recipient_device_id.as_deref(),
            )
            .await?;
            require_message_submit_friend_link_accepted(account, &recipient)?;
            // Acquire the pool clone only after the (pool-independent) recipient/friend pre-checks
            // pass; the account keeps its own Arc regardless of how this request ends.
            let pool = account.relay_quic_pool()?;
            let message = body.clone().into_gateway_message_with_body(Vec::new());
            let result = account
                .client
                .send_plaintext_direct_message_with_attachments_via_gateway(
                    &mut engine,
                    &pool,
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
            let recipient = resolve_federated_message_recipient_principal_commitment(
                &account.client,
                &federation,
                recipient_principal_commitment.as_deref(),
                message.recipient_device_id.as_deref(),
            )?;
            require_message_submit_friend_link_accepted(account, &recipient)?;
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
            let recipient = resolve_local_message_recipient_principal_commitment(
                account,
                &engine.config,
                body.recipient_principal_commitment.as_deref(),
                body.recipient_device_id.as_deref(),
            )
            .await?;
            require_message_submit_friend_link_accepted(account, &recipient)?;
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
        let recipient = resolve_local_message_recipient_principal_commitment(
            account,
            &engine.config,
            recipient_principal_commitment.as_deref(),
            message.recipient_device_id.as_deref(),
        )
        .await?;
        require_message_submit_friend_link_accepted(account, &recipient)?;
        let result = account.client.send_direct_message_via_gateway(&mut engine, message).await;
        account.put_engine(engine);
        result?
    };
    Ok(local_bus_ok(serde_json::to_value(entry)?))
}

async fn resolve_local_message_recipient_principal_commitment(
    account: &LocalBusAccountState,
    gateway: &GatewaySessionConfig,
    explicit_principal_commitment: Option<&str>,
    recipient_device_id: Option<&str>,
) -> Result<ResolvedMessageRecipient, SdkError> {
    if let Some(device_id) = recipient_device_id {
        let principal_commitment = account
            .client
            .resolve_target_principal_commitment(gateway, explicit_principal_commitment, device_id)
            .await?;
        let raw = if explicit_principal_commitment.is_none() {
            crate::client::identity_authority::device_namespace::wire_device_id(device_id)?
        } else {
            device_id.to_owned()
        };
        let device = account
            .client
            .assert_manifest_active_device_cached(
                gateway,
                &principal_commitment,
                &raw,
                "message_submit_friend_gate",
            )
            .await?;
        return Ok(ResolvedMessageRecipient {
            principal_id: Some(device.principal_id),
            principal_commitment,
        });
    }
    explicit_principal_commitment
        .filter(|commitment| !commitment.is_empty())
        .map(|commitment| ResolvedMessageRecipient {
            principal_id: None,
            principal_commitment: commitment.to_owned(),
        })
        .ok_or_else(|| {
            SdkError::LocalBus(
                "message.submit requires recipient_device_id or recipient_principal_commitment to verify friend_link".to_owned(),
            )
        })
}

fn resolve_federated_message_recipient_principal_commitment(
    client: &RamfluxClient,
    federation: &LocalBusFederationRoute,
    recipient_principal_commitment: Option<&str>,
    recipient_device_id: Option<&str>,
) -> Result<ResolvedMessageRecipient, SdkError> {
    if let Some(device_id) = recipient_device_id {
        return federated_manifest_gate(
            client,
            federation,
            recipient_principal_commitment,
            device_id,
        );
    }
    recipient_principal_commitment
        .filter(|commitment| !commitment.is_empty())
        .map(|commitment| ResolvedMessageRecipient {
            principal_id: None,
            principal_commitment: commitment.to_owned(),
        })
        .ok_or_else(|| {
            SdkError::LocalBus(
                "federated direct messages require recipient_device_id or recipient_principal_commitment to verify friend_link".to_owned(),
            )
        })
}

fn require_message_submit_friend_link_accepted(
    account: &LocalBusAccountState,
    recipient: &ResolvedMessageRecipient,
) -> Result<(), SdkError> {
    account.client.require_accepted_friend_link_for_dm_send(
        &account.gateway_config.principal_id,
        &account.principal_commitment,
        recipient.principal_id.as_deref(),
        &recipient.principal_commitment,
    )
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
) -> Result<ResolvedMessageRecipient, SdkError> {
    let manifest_url = federation.recipient_prekey_url.as_deref().ok_or_else(|| {
        SdkError::LocalBus(
            "federated direct messages require a recipient home-node url (--recipient-prekey-url) to verify the remote device manifest"
                .to_owned(),
        )
    })?;
    let principal_commitment = client.resolve_federated_target_principal_commitment(
        manifest_url,
        recipient_principal_commitment,
        device_id,
    )?;
    let device = client.assert_manifest_active_device_from_url(
        manifest_url,
        &principal_commitment,
        device_id,
        "message_submit_friend_gate",
    )?;
    Ok(ResolvedMessageRecipient { principal_id: Some(device.principal_id), principal_commitment })
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
    if let Some(status) = account.client.delivery_receipt_status(
        &body.conversation_id,
        &body.message_id,
        &body.receiver_device_id,
    )? && matches!(status["state"].as_str(), Some("pending" | "sent" | "failed"))
    {
        return Ok(local_bus_ok(
            serde_json::json!({"conversation_id":body.conversation_id,"receiver_device_id":body.receiver_device_id,"delivered_through_message_id":body.message_id,"delivered_at":status["delivered_at"],"ttl_seconds":300,"scope":if status["state"]=="sent" {"network_e2ee"} else {"daemon_queue"},"already_sent":status["state"]=="sent","delivery_receipt_state":status["state"]}),
        ));
    }
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
        )?;
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
        )?;
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
) -> Result<GatewayDirectMessage, SdkError> {
    let reference = if ramflux_protocol::parse_qualified_device_id(recipient_device_id)?.is_some() {
        recipient_device_id.to_owned()
    } else {
        let thread = account
            .client
            .account_db()?
            .client_record("conversation", conversation_id)?
            .ok_or_else(|| {
            SdkError::InboundPending("receipt conversation root unavailable".into())
        })?;
        if let Some(group) = thread["group_id"].as_str() {
            account.client.group_device_reference(group, recipient_device_id)?
        } else {
            let local =
                account.client.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
            let root = thread
                .pointer("/direct_route/recipient_principal_commitment")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned);
            let own_conversation = thread["participants"].as_array().is_some_and(|ids| {
                !ids.is_empty() && ids.iter().all(|id| id == &local.principal_id)
            });
            let root = if own_conversation {
                ramflux_crypto::identity_root_commitment(
                    &account
                        .client
                        .identity_root
                        .as_ref()
                        .ok_or(SdkError::IdentityRootMissing)?
                        .signing_key
                        .verifying_key(),
                )
            } else if let Some(root) = root {
                root
            } else {
                let participants = thread["participants"].as_array().ok_or_else(|| {
                    SdkError::InboundPending("receipt peer root unavailable".into())
                })?;
                let peers: Vec<_> = participants
                    .iter()
                    .filter_map(serde_json::Value::as_str)
                    .filter(|id| *id != local.principal_id)
                    .collect();
                if peers.len() != 1 {
                    return Err(SdkError::InboundPending("receipt peer root is ambiguous".into()));
                }
                account
                    .client
                    .account_db()?
                    .client_record("identity", peers[0])?
                    .and_then(|identity| {
                        identity["contact_identity_commitment"].as_str().map(str::to_owned)
                    })
                    .ok_or_else(|| {
                        SdkError::InboundPending("receipt peer root unavailable".into())
                    })?
            };
            ramflux_protocol::qualified_device_id(&root, recipient_device_id)?
        }
    };
    let root = account.client.device_root(&reference)?;
    let raw = crate::client::identity_authority::device_namespace::wire_device_id(&reference)?;
    Ok(GatewayDirectMessage {
        conversation_id: conversation_id.to_owned(),
        message_id: receipt_id.to_owned(),
        envelope_id: receipt_id.to_owned(),
        source_principal_id: account.gateway_config.principal_id.clone(),
        sender_id: account.gateway_config.device_id.clone(),
        recipient_device_id: Some(raw),
        recipient_principal_commitment: Some(root),
        target_delivery_id: target_delivery_id.to_owned(),
        encrypted_body: Vec::new(),
        created_at,
        ttl: 300,
    })
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
    let before = account
        .pending_deliveries
        .iter()
        .map(|entry| entry.envelope.envelope_id.clone())
        .collect::<BTreeSet<_>>();
    super::super::sync_driver::run(account).await?;
    receive_bound_legacy(account, &body).await?;
    if body.auto_fetch_attachments {
        super::super::attachment_scheduler::fetch_for_page(
            account,
            body.conversation_id.as_deref(),
            body.limit,
        )
        .await?;
    }
    let mut plaintext = Vec::new();
    for entry in &account.pending_deliveries {
        if plaintext.len() >= body.limit.min(64) {
            break;
        }
        let Some((conversation, _)) = account.client.committed_direct_context(entry)? else {
            continue;
        };
        if body.conversation_id.as_deref().is_some_and(|requested| requested != conversation) {
            continue;
        }
        if let Some(mut delivery) =
            account.client.plaintext_projection_delivery(&conversation, entry)?
        {
            if body.auto_fetch_attachments {
                delivery.attachments = compat_attachments(&account.client, &delivery.message_id)?;
            }
            if let Some((_, fallback)) =
                account.client.surface_message_fallback(&delivery.message_id)?
            {
                delivery.plaintext_body_base64 =
                    ramflux_protocol::encode_base64url(fallback.as_bytes());
            }
            plaintext.push(delivery);
        }
    }
    let fresh = account
        .pending_deliveries
        .iter()
        .filter(|entry| !before.contains(&entry.envelope.envelope_id))
        .cloned()
        .collect::<Vec<_>>();
    let event = (!fresh.is_empty()).then(|| {
        local_bus_event(
            request,
            account_id,
            "gateway",
            "gateway.deliver",
            serde_json::json!({"entries":fresh}),
        )
    });
    Ok(LocalBusDispatchResult {
        response_body: serde_json::json!({"entries":account.pending_page(body.limit),"decrypted_messages":plaintext}),
        event,
    })
}

async fn receive_bound_legacy(
    account: &mut LocalBusAccountState,
    body: &LocalBusMessageReceiveRequest,
) -> Result<(), SdkError> {
    let held = account
        .client
        .account_db()?
        .unrouted_entries()?
        .into_iter()
        .map(|bytes| serde_json::from_slice::<GatewayInboxEntry>(&bytes))
        .collect::<Result<Vec<_>, _>>()?;
    let Some(conversation) = body.conversation_id.as_deref() else {
        account.merge_deliveries(held)?;
        return Ok(());
    };
    if held.is_empty() {
        return Ok(());
    }
    let pool = account.relay_quic_pool()?;
    let mut engine = account.take_live_engine().await?;
    let result = async {
        for entry in held {
            if account.client.legacy_routing_binding(&engine.config.device_id, &entry)?.as_deref()
                != Some(conversation)
            {
                continue;
            }
            account
                .client
                .receive_legacy_entry(
                    &mut engine,
                    &pool,
                    entry.clone(),
                    crate::client::dm::LegacyReceive {
                        conversation_id: conversation,
                        auto_fetch_attachments: body.auto_fetch_attachments,
                        relay_service_key_base64: body.relay_service_key_base64.clone(),
                    },
                )
                .await?;
            let device = engine.config.device_id.clone();
            account
                .client
                .ack_gateway_delivery(
                    &mut engine,
                    &entry.envelope.envelope_id,
                    &device,
                    now_unix_timestamp(),
                )
                .await?;
            account
                .client
                .account_db()?
                .remove_unrouted(&account.client.inbox_admission_key(&entry)?)?;
            account.client.account_db()?.remove_unrouted(&entry.envelope.envelope_id)?;
            account.merge_deliveries(vec![entry])?;
        }
        Ok::<(), SdkError>(())
    }
    .await;
    account.put_engine(engine);
    result
}

fn compat_attachments(
    client: &RamfluxClient,
    message: &str,
) -> Result<Vec<SdkDmAttachmentImportResult>, SdkError> {
    let mut attachments = Vec::new();
    for id in client.account_db()?.client_message_object_ids(message)? {
        let Some(object) = client.object_store_object(&id)?.filter(|object| !object.tombstoned)
        else {
            continue;
        };
        let plaintext = client.decrypt_object(&id)?;
        attachments.push(SdkDmAttachmentImportResult {
            object_id: id,
            manifest_hash: object.manifest_hash,
            plaintext_hash: object.plaintext_hash,
            plaintext_base64: ramflux_protocol::encode_base64url(&plaintext),
            imported: true,
        });
    }
    Ok(attachments)
}

#[cfg(test)]
mod root_tests {
    use super::*;
    #[test]
    fn receipts_use_the_conversation_root_despite_equal_device_names() -> Result<(), SdkError> {
        let root = std::env::temp_dir().join(format!(
            "rf-receipt-root-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos())
        ));
        let mut client = RamfluxClient::new();
        client.create_identity_root("alice", [1; 32]);
        client.create_device_branch("alice", "phone", 1, [2; 32]);
        client.open_account_index(&root)?;
        client.create_account("alice", "alice")?;
        client.unlock_account("alice", b"receipt-fixture")?;
        let db = client.account_db()?;
        for (principal, commitment) in [("bob", "bob-root"), ("mallory", "mallory-root")] {
            db.persist_client_record("device", "shared", &serde_json::json!({"device_id":"shared", "principal_id":principal, "principal_commitment":commitment}))?;
            db.persist_client_record(
                "identity",
                principal,
                &serde_json::json!({"contact_identity_commitment":commitment}),
            )?;
        }
        db.persist_client_record(
            "conversation",
            "direct",
            &serde_json::json!({"participants":["alice", "bob"]}),
        )?;
        let config = GatewaySessionConfig::quic(GatewayQuicEndpointConfig {
            bind_addr: "127.0.0.1:0".parse().map_err(|e| SdkError::LocalBus(format!("{e}")))?,
            gateway_addr: "127.0.0.1:1".parse().map_err(|e| SdkError::LocalBus(format!("{e}")))?,
            server_name: "fixture".into(),
            ca_cert: root.join("ca.pem"),
            principal_id: "alice".into(),
            device_id: "phone".into(),
            target_delivery_id: "alice".into(),
            prekey_http_url: None,
        });
        let account = LocalBusAccountState::disconnected(client, config, "alice-root".into());
        let receipt =
            receipt_gateway_message(&account, "direct", "receipt", "shared", "target", 1)?;
        assert_eq!(receipt.recipient_principal_commitment.as_deref(), Some("bob-root"));
        assert_eq!(receipt.recipient_device_id.as_deref(), Some("shared"));
        account.client.account_db()?.persist_client_record(
            "conversation",
            "self",
            &serde_json::json!({"kind":"direct","participants":["alice","alice"]}),
        )?;
        let own_root = ramflux_crypto::identity_root_commitment(
            &account
                .client
                .identity_root
                .as_ref()
                .ok_or(SdkError::IdentityRootMissing)?
                .signing_key
                .verifying_key(),
        );
        let sibling =
            receipt_gateway_message(&account, "self", "own-receipt", "shared", "own-target", 1)?;
        assert_eq!(sibling.recipient_principal_commitment.as_deref(), Some(own_root.as_str()));
        assert_eq!(sibling.recipient_device_id.as_deref(), Some("shared"));
        assert!(
            receipt_gateway_message(&account, "unknown", "receipt", "shared", "target", 1).is_err()
        );
        drop(account);
        std::fs::remove_dir_all(root)?;
        Ok(())
    }
}
