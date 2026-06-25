#![allow(clippy::missing_errors_doc)]
#![allow(clippy::wildcard_imports)]
use crate::prelude::*;

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
            Ok(local_bus_ok(serde_json::to_value(group)?))
        }
        "group.member.add" => {
            let account = local_bus_account_mut(state, account_id)?;
            dispatch_group_member_add_request(request, account).await
        }
        "group.member.remove" => {
            let account = local_bus_account_mut(state, account_id)?;
            dispatch_group_member_remove_request(request, account).await
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
            dispatch_group_send_request(request, account).await
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
    let route = LocalBusGroupMemberRoute {
        member_id: body.member_id.clone(),
        target_delivery_id: body.target_delivery_id.clone(),
        federation: body.federation.clone(),
    };
    account.client.persist_group_member_route(&body.group_id, &route)?;
    let distribution =
        dispatch_group_sender_key_distribution(account, &body.group_id, route).await?;
    let mut redistributions = Vec::new();
    for route in account.client.group_member_routes(&body.group_id)? {
        if route.member_id == body.member_id {
            continue;
        }
        if let Some(redistribution) =
            dispatch_group_sender_key_distribution(account, &body.group_id, route).await?
        {
            redistributions.push(redistribution);
        }
    }
    let mut value = serde_json::to_value(group)?;
    value["sender_key_distribution"] = serde_json::to_value(distribution)?;
    value["sender_key_redistribution"] = serde_json::Value::Array(redistributions);
    Ok(local_bus_ok(value))
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
            dispatch_group_sender_key_distribution(account, &body.group_id, route).await?
        {
            distributions.push(distribution);
        }
    }
    let mut value = serde_json::to_value(group)?;
    value["sender_key_distribution"] = serde_json::Value::Array(distributions);
    Ok(local_bus_ok(value))
}

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
    account.client.send_direct_message(
        &body.conversation_id,
        &body.message_id,
        &body.sender_id,
        &encrypted_body,
    )?;
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
    }
    Ok(local_bus_ok(response))
}

pub(crate) async fn dispatch_group_sender_key_distribution(
    account: &mut LocalBusAccountState,
    group_id: &str,
    route: LocalBusGroupMemberRoute,
) -> Result<Option<serde_json::Value>, SdkError> {
    let mut engine = account.take_live_engine().await?;
    let result = async {
        let sender_id = engine.config.device_id.clone();
        let recipient_device_id = route.member_id.as_str();
        if sender_id == recipient_device_id {
            return Ok(None);
        }
        let distribution =
            account.client.export_group_sender_key_distribution(group_id, &sender_id)?;
        let decoded_distribution: SdkGroupSenderKeyDistribution =
            serde_json::from_slice(&distribution)?;
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
        let envelope_id = format!(
            "group.sender_key.distribution:{group_id}:{sender_id}:{recipient_device_id}:epoch{}",
            decoded_distribution.group_key_epoch
        );
        let payload = SdkGroupSenderKeyDistributionEnvelope {
            schema: "ramflux.sdk.group_sender_key.distribution_envelope.v1".to_owned(),
            version: 1,
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
            match account.client.append_group_gateway_delivery_for_recipient(
                &body.conversation_id,
                &body.group_id,
                &message_id,
                &entry,
                engine.config.device_id.as_str(),
            )? {
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
            if let GroupGatewayDeliveryResult::Message(plaintext) =
                account.client.append_group_gateway_delivery_for_recipient(
                    &body.conversation_id,
                    &body.group_id,
                    &message_id,
                    &entry,
                    engine.config.device_id.as_str(),
                )?
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
