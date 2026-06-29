// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![allow(clippy::missing_errors_doc)]
#![allow(clippy::wildcard_imports)]
use crate::prelude::*;

#[allow(clippy::too_many_lines)]
pub(crate) async fn dispatch_group_bus_request(
    request: &LocalBusFrame,
    state: &mut LocalBusDaemonState,
) -> Result<LocalBusDispatchResult, SdkError> {
    let account_id = request_account_id(request)?;
    match request.method.as_str() {
        "group.create" => {
            let account = local_bus_account_mut(state, account_id)?;
            let body: LocalBusGroupCreateRequest = serde_json::from_value(request.body.clone())?;
            let group = account.client.create_group(&body.group_id, &body.creator_id)?;
            if let Some(public_key) = body.creator_signing_public_key.as_ref() {
                account.client.account_db()?.persist_group_member_device_key(
                    &body.group_id,
                    &body.creator_id,
                    public_key,
                )?;
            }
            if body.creator_target_delivery_id.is_some()
                || body.creator_signing_public_key.is_some()
            {
                let creator_principal_commitment =
                    if body.creator_id == account.gateway_config.device_id {
                        Some(account.principal_commitment.clone())
                    } else {
                        None
                    };
                account.client.persist_group_member_route(
                    &body.group_id,
                    &LocalBusGroupMemberRoute {
                        member_id: body.creator_id.clone(),
                        member_principal_commitment: creator_principal_commitment,
                        device_signing_public_key: body.creator_signing_public_key.clone(),
                        target_delivery_id: body.creator_target_delivery_id.clone(),
                        federation: None,
                    },
                )?;
            }
            Ok(local_bus_ok(serde_json::to_value(group)?))
        }
        "group.member.add" => {
            let account = local_bus_account_mut(state, account_id)?;
            Box::pin(dispatch_group_member_add_request(request, account)).await
        }
        "group.member.remove" => {
            let account = local_bus_account_mut(state, account_id)?;
            dispatch_group_member_remove_request(request, account).await
        }
        "group.role.set" => {
            let account = local_bus_account_mut(state, account_id)?;
            Box::pin(dispatch_group_role_set_request(request, account)).await
        }
        "group.member.kick" => {
            let account = local_bus_account_mut(state, account_id)?;
            Box::pin(dispatch_group_member_kick_request(request, account)).await
        }
        "group.member.ban" => {
            let account = local_bus_account_mut(state, account_id)?;
            Box::pin(dispatch_group_member_ban_request(request, account)).await
        }
        "group.invite.create" => {
            let account = local_bus_account_mut(state, account_id)?;
            Box::pin(dispatch_group_invite_create_request(request, account)).await
        }
        "group.invite.accept" => {
            let account = local_bus_account_mut(state, account_id)?;
            Box::pin(dispatch_group_invite_accept_request(request, account)).await
        }
        "group.message.delete" => {
            let account = local_bus_account_mut(state, account_id)?;
            Box::pin(dispatch_group_message_delete_request(request, account)).await
        }
        "group.members" => {
            let account = local_bus_account(state, account_id)?;
            let body: LocalBusGroupRequest = serde_json::from_value(request.body.clone())?;
            Ok(local_bus_ok(serde_json::to_value(account.client.group_state(&body.group_id)?)?))
        }
        "group.list" => {
            let account = local_bus_account(state, account_id)?;
            let groups = account.client.groups()?;
            Ok(local_bus_ok(serde_json::json!({ "groups": groups })))
        }
        "group.send" => {
            let account = local_bus_account_mut(state, account_id)?;
            Box::pin(dispatch_group_send_request(request, account)).await
        }
        "group.read" | "group.receive" => {
            let account = local_bus_account_mut(state, account_id)?;
            dispatch_group_receive_request(request, account).await
        }
        "group.sender_key.export" => {
            let account = local_bus_account(state, account_id)?;
            let body: LocalBusGroupSenderKeyExportRequest =
                serde_json::from_value(request.body.clone())?;
            let distribution = account
                .client
                .export_group_sender_key_distribution(&body.group_id, &body.sender_id)?;
            Ok(local_bus_ok(serde_json::json!({
                "distribution_base64": ramflux_protocol::encode_base64url(&distribution),
            })))
        }
        "group.sender_key.import" => {
            let account = local_bus_account(state, account_id)?;
            let body: LocalBusGroupSenderKeyImportRequest =
                serde_json::from_value(request.body.clone())?;
            let distribution = ramflux_protocol::decode_base64url(&body.distribution_base64)
                .map_err(|error| {
                    SdkError::LocalBus(format!("invalid sender key distribution: {error}"))
                })?;
            let (distribution, pending) =
                account.client.import_group_sender_key_distribution_inner(&distribution, true)?;
            let mut value = serde_json::to_value(distribution)?;
            let imported_group_id = value["group_id"]
                .as_str()
                .ok_or_else(|| SdkError::LocalBus("missing imported group_id".to_owned()))?
                .to_owned();
            value["pending_undecrypted_count"] = serde_json::json!(
                account.client.account_db()?.group_pending_undecrypted_count(&imported_group_id)?
            );
            value["decrypted_messages"] = serde_json::Value::Array(
                pending
                    .into_iter()
                    .map(|message| {
                        group_plaintext_json(
                            &message.conversation_id,
                            &message.group_id,
                            &message.message_id,
                            &message.plaintext,
                        )
                    })
                    .collect(),
            );
            Ok(local_bus_ok(value))
        }
        other => Err(SdkError::LocalBus(format!("unsupported local bus method: {other}"))),
    }
}

async fn dispatch_group_member_add_request(
    request: &LocalBusFrame,
    account: &mut LocalBusAccountState,
) -> Result<LocalBusDispatchResult, SdkError> {
    let body: LocalBusGroupMemberAddRequest = serde_json::from_value(request.body.clone())?;
    let group = account.client.add_group_member(&body.group_id, &body.member_id, &body.role)?;
    let member_principal_commitment =
        resolve_group_member_principal_commitment(account, &body).await?;
    let route = LocalBusGroupMemberRoute {
        member_id: body.member_id.clone(),
        member_principal_commitment,
        device_signing_public_key: body.member_signing_public_key.clone(),
        target_delivery_id: body.target_delivery_id.clone(),
        federation: body.federation.clone(),
    };
    account.client.persist_group_member_route(&body.group_id, &route)?;
    let onboard_event = create_group_member_onboard_event_for_authorized_local_actor(
        account, &group, &body, &route,
    )?;
    let distribution = if route.target_delivery_id.is_some() || route.federation.is_some() {
        dispatch_group_sender_key_distribution(
            account,
            &body.group_id,
            route,
            onboard_event.as_ref(),
        )
        .await?
    } else {
        None
    };
    let mut redistributions = Vec::new();
    for route in account.client.group_member_routes(&body.group_id)? {
        if route.member_id == body.member_id {
            continue;
        }
        if let Some(redistribution) =
            dispatch_group_sender_key_distribution(account, &body.group_id, route, None).await?
        {
            redistributions.push(redistribution);
        }
    }
    let mut value = serde_json::to_value(group)?;
    value["sender_key_distribution"] = serde_json::to_value(distribution)?;
    value["sender_key_redistribution"] = serde_json::Value::Array(redistributions);
    Ok(local_bus_ok(value))
}

fn create_group_member_onboard_event_for_authorized_local_actor(
    account: &LocalBusAccountState,
    group: &GroupState,
    body: &LocalBusGroupMemberAddRequest,
    route: &LocalBusGroupMemberRoute,
) -> Result<Option<ramflux_protocol::GroupEvent>, SdkError> {
    if route.target_delivery_id.is_none() && route.federation.is_none() {
        return Ok(None);
    }
    let actor_device_id = account
        .client
        .device_branch
        .as_ref()
        .ok_or(SdkError::IdentityRootMissing)?
        .device_id
        .clone();
    let Some(actor_role) = group.roles.get(&actor_device_id) else {
        return Ok(None);
    };
    if actor_role != "owner" && actor_role != "admin" {
        return Ok(None);
    }
    Ok(Some(account.client.create_signed_group_member_join_event(
        &body.group_id,
        &actor_device_id,
        &body.member_id,
        &body.role,
        &account.principal_commitment,
    )?))
}

async fn resolve_group_member_principal_commitment(
    account: &mut LocalBusAccountState,
    body: &LocalBusGroupMemberAddRequest,
) -> Result<Option<String>, SdkError> {
    if body.member_principal_commitment.is_none()
        && body.target_delivery_id.is_none()
        && body.federation.is_none()
    {
        return Ok(None);
    }
    let engine = account.take_live_engine().await?;
    let commitment = account
        .client
        .resolve_target_principal_commitment(
            &engine.config,
            body.member_principal_commitment.as_deref(),
            &body.member_id,
        )
        .await;
    account.put_engine(engine);
    Ok(Some(commitment?))
}

async fn dispatch_group_role_set_request(
    request: &LocalBusFrame,
    account: &mut LocalBusAccountState,
) -> Result<LocalBusDispatchResult, SdkError> {
    let body: LocalBusGroupRoleSetRequest = serde_json::from_value(request.body.clone())?;
    let (event, group) = account.client.create_signed_group_role_change(
        &body.group_id,
        &body.actor_id,
        &body.member_id,
        &body.role,
    )?;
    Box::pin(dispatch_group_control_response(
        account,
        &body.group_id,
        &body.actor_id,
        event,
        group,
        false,
    ))
    .await
}

async fn dispatch_group_member_kick_request(
    request: &LocalBusFrame,
    account: &mut LocalBusAccountState,
) -> Result<LocalBusDispatchResult, SdkError> {
    let body: LocalBusGroupMemberKickRequest = serde_json::from_value(request.body.clone())?;
    let reason = body.reason.as_deref().unwrap_or("kick");
    let (event, group) = account.client.create_signed_group_member_kick(
        &body.group_id,
        &body.actor_id,
        &body.member_id,
        reason,
    )?;
    Box::pin(dispatch_group_control_response(
        account,
        &body.group_id,
        &body.actor_id,
        event,
        group,
        true,
    ))
    .await
}

async fn dispatch_group_member_ban_request(
    request: &LocalBusFrame,
    account: &mut LocalBusAccountState,
) -> Result<LocalBusDispatchResult, SdkError> {
    let body: LocalBusGroupMemberBanRequest = serde_json::from_value(request.body.clone())?;
    let reason = body.reason.as_deref().unwrap_or("ban");
    let (event, group) = account.client.create_signed_group_member_ban(
        &body.group_id,
        &body.actor_id,
        &body.member_id,
        reason,
    )?;
    Box::pin(dispatch_group_control_response(
        account,
        &body.group_id,
        &body.actor_id,
        event,
        group,
        true,
    ))
    .await
}

async fn dispatch_group_message_delete_request(
    request: &LocalBusFrame,
    account: &mut LocalBusAccountState,
) -> Result<LocalBusDispatchResult, SdkError> {
    let body: LocalBusGroupMessageDeleteRequest = serde_json::from_value(request.body.clone())?;
    let reason = body.reason.as_deref().unwrap_or("delete");
    let (event, group) = account.client.create_signed_group_message_delete(
        &body.group_id,
        &body.actor_id,
        &body.message_id,
        &body.delete_scope,
        reason,
    )?;
    Box::pin(dispatch_group_control_response(
        account,
        &body.group_id,
        &body.actor_id,
        event,
        group,
        false,
    ))
    .await
}

async fn dispatch_group_invite_create_request(
    request: &LocalBusFrame,
    account: &mut LocalBusAccountState,
) -> Result<LocalBusDispatchResult, SdkError> {
    let body: LocalBusGroupInviteCreateRequest = serde_json::from_value(request.body.clone())?;
    let reason = body.reason.as_deref().unwrap_or("invite");
    let (event, group) = account.client.create_signed_group_member_invite(
        &body.group_id,
        &body.actor_id,
        &body.invitee_id,
        &body.invitee_signing_public_key,
        &body.role,
        body.expires_at,
        reason,
    )?;
    let invitee_route = LocalBusGroupMemberRoute {
        member_id: body.invitee_id.clone(),
        member_principal_commitment: body.invitee_principal_commitment.clone(),
        device_signing_public_key: Some(body.invitee_signing_public_key),
        target_delivery_id: Some(body.target_delivery_id),
        federation: body.federation,
    };
    account.client.persist_group_member_route(&body.group_id, &invitee_route)?;
    let mut response = Box::pin(dispatch_group_control_response(
        account,
        &body.group_id,
        &body.actor_id,
        event.clone(),
        group,
        false,
    ))
    .await?;
    let payload = SdkGroupControlEnvelope {
        schema: "ramflux.sdk.group_control.v1".to_owned(),
        version: 1,
        event: event.clone(),
    };
    let target_delivery_id = invitee_route
        .target_delivery_id
        .clone()
        .ok_or_else(|| SdkError::LocalBus("missing invitee target delivery id".to_owned()))?;
    let invitee_delivery = dispatch_group_control_delivery(
        account,
        GroupControlDelivery {
            group_id: &body.group_id,
            actor_id: &body.actor_id,
            route: invitee_route,
            target_delivery_id,
            event_id: &event.event_id,
            payload_bytes: &serde_json::to_vec(&payload)?,
        },
    )
    .await?;
    response.response_body["invitee_submitted"] = invitee_delivery;
    Ok(response)
}

async fn dispatch_group_invite_accept_request(
    request: &LocalBusFrame,
    account: &mut LocalBusAccountState,
) -> Result<LocalBusDispatchResult, SdkError> {
    let body: LocalBusGroupInviteAcceptRequest = serde_json::from_value(request.body.clone())?;
    let (event, group) = account.client.create_signed_group_member_accept(
        &body.group_id,
        &body.actor_id,
        &body.invite_id,
    )?;
    if body.target_delivery_id.is_some() || body.federation.is_some() {
        account.client.persist_group_member_route(
            &body.group_id,
            &LocalBusGroupMemberRoute {
                member_id: body.actor_id.clone(),
                member_principal_commitment: body.member_principal_commitment.clone(),
                device_signing_public_key: None,
                target_delivery_id: body.target_delivery_id.clone(),
                federation: body.federation.clone(),
            },
        )?;
    }
    let mut response = Box::pin(dispatch_group_control_response(
        account,
        &body.group_id,
        &body.actor_id,
        event,
        group,
        false,
    ))
    .await?;
    let mut sender_key_distribution = Vec::new();
    for route in account.client.group_member_routes(&body.group_id)? {
        if route.member_id == body.actor_id {
            continue;
        }
        if let Some(distribution) =
            dispatch_group_sender_key_distribution(account, &body.group_id, route, None).await?
        {
            sender_key_distribution.push(distribution);
        }
    }
    response.response_body["sender_key_distribution"] =
        serde_json::Value::Array(sender_key_distribution);
    Ok(response)
}

async fn dispatch_group_control_response(
    account: &mut LocalBusAccountState,
    group_id: &str,
    actor_id: &str,
    event: ramflux_protocol::GroupEvent,
    group: GroupState,
    redistribute_actor_key: bool,
) -> Result<LocalBusDispatchResult, SdkError> {
    let payload = SdkGroupControlEnvelope {
        schema: "ramflux.sdk.group_control.v1".to_owned(),
        version: 1,
        event: event.clone(),
    };
    let payload_bytes = serde_json::to_vec(&payload)?;
    let mut submitted = Vec::new();
    let mut federated_submitted = Vec::new();
    let mut sender_key_distribution = Vec::new();
    for route in account.client.group_member_routes(group_id)? {
        if route.member_id == actor_id {
            continue;
        }
        if redistribute_actor_key
            && let Some(distribution) =
                dispatch_group_sender_key_distribution(account, group_id, route.clone(), None)
                    .await?
        {
            sender_key_distribution.push(distribution);
        }
        let Some(target_delivery_id) = route.target_delivery_id.clone() else {
            continue;
        };
        let value = dispatch_group_control_delivery(
            account,
            GroupControlDelivery {
                group_id,
                actor_id,
                route,
                target_delivery_id,
                event_id: &event.event_id,
                payload_bytes: &payload_bytes,
            },
        )
        .await?;
        if value.get("federated").and_then(serde_json::Value::as_bool) == Some(true) {
            federated_submitted.push(value);
        } else {
            submitted.push(value);
        }
    }
    let mut response = serde_json::to_value(group)?;
    response["control_event"] = serde_json::to_value(event)?;
    response["submitted"] = serde_json::Value::Array(submitted);
    response["federated_submitted"] = serde_json::Value::Array(federated_submitted);
    response["sender_key_distribution"] = serde_json::Value::Array(sender_key_distribution);
    Ok(local_bus_ok(response))
}

struct GroupControlDelivery<'a> {
    group_id: &'a str,
    actor_id: &'a str,
    route: LocalBusGroupMemberRoute,
    target_delivery_id: String,
    event_id: &'a str,
    payload_bytes: &'a [u8],
}

async fn dispatch_group_control_delivery(
    account: &mut LocalBusAccountState,
    delivery: GroupControlDelivery<'_>,
) -> Result<serde_json::Value, SdkError> {
    let mut engine = account.take_live_engine().await?;
    let result = async {
        let conversation_id = group_sender_key_distribution_conversation_id(
            delivery.group_id,
            delivery.actor_id,
            &delivery.route.member_id,
        );
        let delivery_id_hash = ramflux_crypto::blake3_256_base64url(
            "ramflux.sdk.group_control.delivery_id.v1",
            format!("{}:{}", delivery.event_id, delivery.route.member_id).as_bytes(),
        );
        let delivery_message_id = format!("group.control.delivery:{delivery_id_hash}");
        let message = GatewayDirectMessage {
            conversation_id,
            message_id: delivery_message_id.clone(),
            envelope_id: delivery_message_id,
            source_principal_id: engine.config.principal_id.clone(),
            sender_id: delivery.actor_id.to_owned(),
            recipient_device_id: Some(delivery.route.member_id.clone()),
            target_delivery_id: delivery.target_delivery_id,
            encrypted_body: Vec::new(),
            created_at: now_unix_timestamp(),
            ttl: 3_600,
        };
        if let Some(federation) = delivery.route.federation.as_ref() {
            let response = account.client.send_plaintext_federated_direct_message(
                &engine,
                message,
                delivery.payload_bytes,
                federation,
            )?;
            let mut value = serde_json::to_value(response)?;
            value["federated"] = serde_json::Value::Bool(true);
            Ok(value)
        } else {
            let entry = account
                .client
                .send_plaintext_direct_message_via_gateway(
                    &mut engine,
                    message,
                    delivery.payload_bytes,
                )
                .await?;
            let mut value = serde_json::to_value(entry)?;
            value["federated"] = serde_json::Value::Bool(false);
            Ok(value)
        }
    }
    .await;
    account.put_engine(engine);
    result
}

async fn dispatch_group_member_remove_request(
    request: &LocalBusFrame,
    account: &mut LocalBusAccountState,
) -> Result<LocalBusDispatchResult, SdkError> {
    let body: LocalBusGroupMemberRemoveRequest = serde_json::from_value(request.body.clone())?;
    let group =
        account.client.remove_group_member(&body.group_id, &body.actor_id, &body.member_id)?;
    let mut distributions = Vec::new();
    for route in account.client.group_member_routes(&body.group_id)? {
        if route.member_id == body.actor_id {
            continue;
        }
        if let Some(distribution) =
            dispatch_group_sender_key_distribution(account, &body.group_id, route, None).await?
        {
            distributions.push(distribution);
        }
    }
    let mut value = serde_json::to_value(group)?;
    value["sender_key_distribution"] = serde_json::Value::Array(distributions);
    Ok(local_bus_ok(value))
}

#[allow(clippy::too_many_lines)]
pub(crate) async fn dispatch_group_send_request(
    request: &LocalBusFrame,
    account: &mut LocalBusAccountState,
) -> Result<LocalBusDispatchResult, SdkError> {
    let body: LocalBusGroupSendRequest = serde_json::from_value(request.body.clone())?;
    let plaintext_body_base64 =
        body.plaintext_body_base64.as_deref().unwrap_or(&body.encrypted_body_base64);
    let plaintext_body = ramflux_protocol::decode_base64url(plaintext_body_base64)
        .map_err(|error| SdkError::LocalBus(format!("invalid group body: {error}")))?;
    let encrypted_body =
        account.client.encrypt_group_message(&body.group_id, &body.sender_id, &plaintext_body)?;
    let mut response = serde_json::json!({
        "group_id": body.group_id,
        "conversation_id": body.conversation_id,
        "message_id": body.message_id,
    });
    let existing_message = account.client.direct_message_by_id(&body.message_id)?;
    if let Some(existing_message) = existing_message {
        if existing_message.encrypted_body != encrypted_body {
            return Err(SdkError::LocalBus(format!(
                "group message id collision for {}",
                body.message_id
            )));
        }
    } else {
        account.client.send_direct_message(
            &body.conversation_id,
            &body.message_id,
            &body.sender_id,
            &encrypted_body,
        )?;
    }
    if let (Some(envelope_id), Some(source_principal_id), Some(target_delivery_id)) = (
        body.envelope_id.clone(),
        body.source_principal_id.clone(),
        body.target_delivery_id.clone(),
    ) {
        let created_at = now_unix_timestamp();
        let message = GatewayDirectMessage {
            conversation_id: body.conversation_id,
            message_id: body.message_id,
            envelope_id,
            source_principal_id,
            sender_id: body.sender_id,
            recipient_device_id: None,
            target_delivery_id,
            encrypted_body,
            created_at,
            ttl: body.ttl.unwrap_or(3_600),
        };
        if let Some(federation) = body.federation.as_ref() {
            let engine = account.take_live_engine().await?;
            let forwarded =
                account.client.forward_federated_gateway_message(&engine, &message, federation);
            account.put_engine(engine);
            response["federated_submitted"] = serde_json::to_value(forwarded?)?;
        } else {
            let mut engine = account.take_live_engine().await?;
            let entry =
                account.client.submit_direct_message_via_gateway(&mut engine, message).await;
            account.put_engine(engine);
            response["submitted"] = serde_json::to_value(entry?)?;
        }
    } else {
        let routes = account.client.group_member_routes(&body.group_id)?;
        let mut sender_key_distribution = Vec::new();
        for route in routes.iter().cloned() {
            if route.member_id == body.sender_id {
                continue;
            }
            if let Some(distribution) =
                dispatch_group_sender_key_distribution(account, &body.group_id, route, None).await?
            {
                sender_key_distribution.push(distribution);
            }
        }
        let mut local = Vec::new();
        let mut federated = Vec::new();
        for (index, route) in routes.into_iter().enumerate() {
            if route.member_id == body.sender_id {
                continue;
            }
            let Some(target_delivery_id) = route.target_delivery_id.clone() else {
                continue;
            };
            let created_at = now_unix_timestamp();
            let message = GatewayDirectMessage {
                conversation_id: body.conversation_id.clone(),
                message_id: body.message_id.clone(),
                envelope_id: format!("{}:{index}", body.message_id),
                source_principal_id: body.source_principal_id.clone().unwrap_or_default(),
                sender_id: body.sender_id.clone(),
                recipient_device_id: Some(route.member_id.clone()),
                target_delivery_id,
                encrypted_body: encrypted_body.clone(),
                created_at,
                ttl: body.ttl.unwrap_or(3_600),
            };
            if let Some(federation) = route.federation.as_ref() {
                let engine = account.take_live_engine().await?;
                let forwarded =
                    account.client.forward_federated_gateway_message(&engine, &message, federation);
                account.put_engine(engine);
                federated.push(serde_json::to_value(forwarded?)?);
            } else {
                let mut engine = account.take_live_engine().await?;
                let entry =
                    account.client.submit_direct_message_via_gateway(&mut engine, message).await;
                account.put_engine(engine);
                local.push(serde_json::to_value(entry?)?);
            }
        }
        response["submitted"] = serde_json::Value::Array(local);
        response["federated_submitted"] = serde_json::Value::Array(federated);
        response["sender_key_distribution"] = serde_json::Value::Array(sender_key_distribution);
    }
    Ok(local_bus_ok(response))
}

pub(crate) async fn dispatch_group_sender_key_distribution(
    account: &mut LocalBusAccountState,
    group_id: &str,
    route: LocalBusGroupMemberRoute,
    membership_event: Option<&ramflux_protocol::GroupEvent>,
) -> Result<Option<serde_json::Value>, SdkError> {
    let mut engine = account.take_live_engine().await?;
    let result = async {
        let sender_id = engine.config.device_id.clone();
        let recipient_device_id = route.member_id.as_str();
        if sender_id == recipient_device_id {
            return Ok(None);
        }
        let _member_principal_commitment = account
            .client
            .resolve_target_principal_commitment(
                &engine.config,
                route.member_principal_commitment.as_deref(),
                recipient_device_id,
            )
            .await?;
        let distribution =
            account.client.export_group_sender_key_distribution(group_id, &sender_id)?;
        let decoded_distribution: SdkGroupSenderKeyDistribution =
            serde_json::from_slice(&distribution)?;
        let envelope_id = format!(
            "group.sender_key.distribution:{group_id}:{sender_id}:{recipient_device_id}:epoch{}",
            decoded_distribution.group_key_epoch
        );
        if account.client.direct_message_by_id(&envelope_id)?.is_some() {
            return Ok(Some(serde_json::json!({
                "message_id": envelope_id,
                "recipient_device_id": recipient_device_id,
                "already_submitted": true,
            })));
        }
        let prekey = if let Some(federation) = route.federation.as_ref() {
            let prekey_url = federation.recipient_prekey_url.as_deref().ok_or_else(|| {
                SdkError::LocalBus(
                    "recipient_prekey_url is required for federated group sender-key recipients"
                        .to_owned(),
                )
            })?;
            sdk_fetch_prekey_bundle(prekey_url, recipient_device_id)?
        } else {
            engine.fetch_prekey_bundle(recipient_device_id).await?
        };
        let target_delivery_id =
            route.target_delivery_id.clone().or(prekey.target_delivery_id).ok_or_else(|| {
                SdkError::LocalBus(format!(
                    "missing target delivery id for group sender-key recipient {recipient_device_id}"
                ))
            })?;
        let conversation_id = group_sender_key_distribution_conversation_id(
            group_id,
            &sender_id,
            recipient_device_id,
        );
        let payload = SdkGroupSenderKeyDistributionEnvelope {
            schema: "ramflux.sdk.group_sender_key.distribution_envelope.v1".to_owned(),
            version: 1,
            membership_event_base64: membership_event
                .map(serde_json::to_vec)
                .transpose()?
                .map(|bytes| ramflux_protocol::encode_base64url(&bytes)),
            distribution_base64: ramflux_protocol::encode_base64url(&distribution),
        };
        let message = GatewayDirectMessage {
            conversation_id,
            message_id: envelope_id.clone(),
            envelope_id,
            source_principal_id: engine.config.principal_id.clone(),
            sender_id: sender_id.clone(),
            recipient_device_id: Some(recipient_device_id.to_owned()),
            target_delivery_id,
            encrypted_body: Vec::new(),
            created_at: now_unix_timestamp(),
            ttl: 3_600,
        };
        if let Some(federation) = route.federation.as_ref() {
            let response = account.client.send_plaintext_federated_direct_message(
                &engine,
                message,
                &serde_json::to_vec(&payload)?,
                federation,
            )?;
            Ok(Some(serde_json::to_value(response)?))
        } else {
            let entry = account.client.send_plaintext_direct_message_via_gateway(
                &mut engine,
                message,
                &serde_json::to_vec(&payload)?,
            )
            .await?;
            Ok(Some(serde_json::to_value(entry)?))
        }
    }
    .await;
    account.put_engine(engine);
    result
}

#[allow(clippy::too_many_lines)]
pub(crate) async fn dispatch_group_receive_request(
    request: &LocalBusFrame,
    account: &mut LocalBusAccountState,
) -> Result<LocalBusDispatchResult, SdkError> {
    let body: LocalBusGroupReceiveRequest = serde_json::from_value(request.body.clone())?;
    let mut engine = account.take_live_engine().await?;
    let receive_result = async {
        let after_inbox_seq = account.client.gateway_receive_cursor(engine.target_delivery_id())?;
        let mut entries = engine.resume_after(after_inbox_seq, body.limit).await?;
        entries.retain(|entry| entry.inbox_seq > after_inbox_seq);
        entries.sort_by_key(|entry| entry.inbox_seq);
        let mut gateway_entries = Vec::new();
        let mut decrypted = Vec::new();
        let mut sender_key_distributions = Vec::new();
        let mut message_entries = Vec::new();
        let mut imported_sender_keys = Vec::new();
        for entry in entries {
            if group_entry_is_sender_key_message(&entry)? {
                message_entries.push(entry);
                continue;
            }
            let message_id = entry.envelope.envelope_id.clone();
            match account
                .client
                .append_group_gateway_delivery_for_recipient_with_gateway(
                    &engine.config,
                    &body.conversation_id,
                    &body.group_id,
                    &message_id,
                    &entry,
                    engine.config.device_id.as_str(),
                )
                .await?
            {
                GroupGatewayDeliveryResult::SenderKeyDistribution(distribution) => {
                    account.client.persist_gateway_receive_cursor(
                        engine.target_delivery_id(),
                        entry.inbox_seq,
                    )?;
                    imported_sender_keys
                        .push((distribution.group_id.clone(), distribution.group_key_epoch));
                    gateway_entries.push(entry);
                    sender_key_distributions.push(serde_json::to_value(distribution)?);
                }
                GroupGatewayDeliveryResult::Message(plaintext) => {
                    account.client.persist_gateway_receive_cursor(
                        engine.target_delivery_id(),
                        entry.inbox_seq,
                    )?;
                    gateway_entries.push(entry);
                    if !plaintext.is_empty() {
                        decrypted.push(serde_json::json!({
                            "conversation_id": body.conversation_id,
                            "group_id": body.group_id,
                            "message_id": message_id,
                            "plaintext_body_base64": ramflux_protocol::encode_base64url(&plaintext),
                            "body_utf8": String::from_utf8_lossy(&plaintext),
                        }));
                    }
                }
            }
        }
        for entry in message_entries {
            let message_id = entry.envelope.envelope_id.clone();
            if let GroupGatewayDeliveryResult::Message(plaintext) = account
                .client
                .append_group_gateway_delivery_for_recipient_with_gateway(
                    &engine.config,
                    &body.conversation_id,
                    &body.group_id,
                    &message_id,
                    &entry,
                    engine.config.device_id.as_str(),
                )
                .await?
            {
                account
                    .client
                    .persist_gateway_receive_cursor(engine.target_delivery_id(), entry.inbox_seq)?;
                gateway_entries.push(entry);
                if !plaintext.is_empty() {
                    decrypted.push(group_plaintext_json(
                        &body.conversation_id,
                        &body.group_id,
                        &message_id,
                        &plaintext,
                    ));
                }
            }
        }
        for (group_id, group_key_epoch) in imported_sender_keys {
            for pending in
                account.client.retry_pending_group_messages(&group_id, group_key_epoch)?
            {
                decrypted.push(group_plaintext_json(
                    &pending.conversation_id,
                    &pending.group_id,
                    &pending.message_id,
                    &pending.plaintext,
                ));
            }
        }
        Ok::<_, SdkError>((gateway_entries, decrypted, sender_key_distributions))
    }
    .await;
    account.put_engine(engine);
    let (gateway_entries, decrypted, sender_key_distributions) = receive_result?;
    Ok(local_bus_ok(serde_json::json!({
        "gateway_entries": gateway_entries,
        "sender_key_distributions": sender_key_distributions,
        "decrypted_messages": decrypted,
        "pending_undecrypted_count": account.client.account_db()?.group_pending_undecrypted_count(&body.group_id)?,
        "messages": account.client.direct_messages(&body.conversation_id)?,
    })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddr};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_root(test_name: &str) -> PathBuf {
        let nanos =
            SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |duration| duration.as_nanos());
        std::env::temp_dir().join(format!("ramflux-sdk-dispatch-group-{test_name}-{nanos}"))
    }

    fn gateway_config(principal: &str, device: &str, target: &str) -> GatewaySessionConfig {
        GatewaySessionConfig::auto(GatewayQuicEndpointConfig {
            bind_addr: SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
            gateway_addr: SocketAddr::from((Ipv4Addr::LOCALHOST, 1)),
            server_name: "localhost".to_owned(),
            ca_cert: PathBuf::from("ca.pem"),
            principal_id: principal.to_owned(),
            device_id: device.to_owned(),
            target_delivery_id: target.to_owned(),
            prekey_http_url: None,
        })
    }

    fn account_state(
        test_name: &str,
        account_id: &str,
        principal: &str,
        device: &str,
        seed: [u8; 32],
    ) -> Result<LocalBusAccountState, SdkError> {
        let mut client = RamfluxClient::new();
        client.create_identity_root(principal, [0x31; 32]);
        let branch = client.create_device_branch(principal, device, 1, seed);
        client.open_account_index(temp_root(test_name))?;
        client.create_account(account_id, principal)?;
        client.unlock_account(account_id, b"dispatch-group-test")?;
        Ok(LocalBusAccountState::disconnected(
            client,
            gateway_config(principal, device, &format!("target_{device}"))
                .with_device_branch(branch),
            principal.to_owned(),
        ))
    }

    fn member_add_body(group_id: &str, member_id: &str) -> LocalBusGroupMemberAddRequest {
        LocalBusGroupMemberAddRequest {
            group_id: group_id.to_owned(),
            member_id: member_id.to_owned(),
            role: "member".to_owned(),
            member_signing_public_key: Some(format!("{member_id}_key")),
            member_principal_commitment: Some(format!("{member_id}_commitment")),
            target_delivery_id: Some(format!("target_{member_id}")),
            federation: None,
        }
    }

    #[test]
    fn dispatch_onboard_event_skips_signed_role_local_seed_for_non_admin_signer()
    -> Result<(), SdkError> {
        let bob = account_state(
            "bob_s44_seed",
            "bob_s44_account",
            "principal_bob",
            "bob_device_s44",
            [0x44; 32],
        )?;
        bob.client.create_group("group_s44", "alice_device_s44")?;
        let body = member_add_body("group_s44", "bob_device_s44");
        let group = bob.client.add_group_member(&body.group_id, &body.member_id, &body.role)?;
        let route = LocalBusGroupMemberRoute {
            member_id: body.member_id.clone(),
            member_principal_commitment: body.member_principal_commitment.clone(),
            device_signing_public_key: body.member_signing_public_key.clone(),
            target_delivery_id: body.target_delivery_id.clone(),
            federation: body.federation.clone(),
        };

        assert_eq!(group.roles.get("alice_device_s44").map(String::as_str), Some("owner"));
        assert_eq!(group.roles.get("bob_device_s44").map(String::as_str), Some("member"));
        let event = create_group_member_onboard_event_for_authorized_local_actor(
            &bob, &group, &body, &route,
        )?;
        assert!(event.is_none());
        Ok(())
    }

    #[test]
    fn dispatch_onboard_event_owner_can_sign_multiple_direct_adds() -> Result<(), SdkError> {
        let alice = account_state(
            "alice_s44_seed",
            "alice_s44_account",
            "principal_alice",
            "alice_device_s44",
            [0x42; 32],
        )?;
        alice.client.create_group("group_s44", "alice_device_s44")?;

        let bob_body = member_add_body("group_s44", "bob_device_s44");
        let bob_group = alice.client.add_group_member(
            &bob_body.group_id,
            &bob_body.member_id,
            &bob_body.role,
        )?;
        let bob_route = LocalBusGroupMemberRoute {
            member_id: bob_body.member_id.clone(),
            member_principal_commitment: bob_body.member_principal_commitment.clone(),
            device_signing_public_key: bob_body.member_signing_public_key.clone(),
            target_delivery_id: bob_body.target_delivery_id.clone(),
            federation: bob_body.federation.clone(),
        };
        let bob_event = create_group_member_onboard_event_for_authorized_local_actor(
            &alice, &bob_group, &bob_body, &bob_route,
        )?;
        assert!(bob_event.is_some());

        let carol_body = member_add_body("group_s44", "carol_device_s44");
        let carol_group = alice.client.add_group_member(
            &carol_body.group_id,
            &carol_body.member_id,
            &carol_body.role,
        )?;
        let carol_route = LocalBusGroupMemberRoute {
            member_id: carol_body.member_id.clone(),
            member_principal_commitment: carol_body.member_principal_commitment.clone(),
            device_signing_public_key: carol_body.member_signing_public_key.clone(),
            target_delivery_id: carol_body.target_delivery_id.clone(),
            federation: carol_body.federation.clone(),
        };
        let carol_event = create_group_member_onboard_event_for_authorized_local_actor(
            &alice,
            &carol_group,
            &carol_body,
            &carol_route,
        )?;
        assert!(carol_event.is_some());
        Ok(())
    }
}
