#![allow(clippy::missing_errors_doc)]
#![allow(clippy::wildcard_imports)]
use crate::prelude::*;

pub(crate) async fn dispatch_message_bus_request(
    request: &LocalBusFrame,
    state: &mut LocalBusDaemonState,
    connection: &LocalBusConnectionState,
) -> Result<LocalBusDispatchResult, SdkError> {
    match request.method.as_str() {
        "message.submit" => dispatch_message_submit_request(request, state).await,
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
            let account = local_bus_account(state, account_id)?;
            dispatch_message_receipt_delivered(request, account)
        }
        "message.receipt.read" => {
            let account_id = request_account_id(request)?;
            let account = local_bus_account(state, account_id)?;
            dispatch_message_receipt_read(request, account)
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
        if let Some(federation) = body.federation.clone() {
            let message = body.into_gateway_message_with_body(Vec::new());
            let engine = account.take_live_engine().await?;
            let response = account.client.send_plaintext_federated_direct_message(
                &engine,
                message,
                &plaintext,
                &federation,
            );
            account.put_engine(engine);
            let response = response?;
            return Ok(local_bus_ok(serde_json::to_value(response)?));
        }
        let mut engine = account.take_live_engine().await?;
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
    } else {
        let message = body.into_gateway_message()?;
        let mut engine = account.take_live_engine().await?;
        let result = account.client.send_direct_message_via_gateway(&mut engine, message).await;
        account.put_engine(engine);
        result?
    };
    Ok(local_bus_ok(serde_json::to_value(entry)?))
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

fn dispatch_message_receipt_delivered(
    request: &LocalBusFrame,
    account: &LocalBusAccountState,
) -> Result<LocalBusDispatchResult, SdkError> {
    let body: LocalBusMessageReceiptDeliveredRequest =
        serde_json::from_value(request.body.clone())?;
    let receipt = account.client.mark_delivered(
        &body.conversation_id,
        &body.receiver_device_id,
        &body.message_id,
        body.delivered_at.unwrap_or_else(now_unix_timestamp),
        body.ttl_seconds.unwrap_or(300),
    )?;
    Ok(local_bus_ok(serde_json::json!({
        "conversation_id": receipt.conversation_id,
        "receiver_device_id": receipt.receiver_device_id,
        "delivered_through_message_id": receipt.delivered_through_message_id,
        "delivered_at": receipt.delivered_at,
        "ttl_seconds": receipt.ttl_seconds,
        "scope": "local_projection",
    })))
}

fn dispatch_message_receipt_read(
    request: &LocalBusFrame,
    account: &LocalBusAccountState,
) -> Result<LocalBusDispatchResult, SdkError> {
    let body: LocalBusMessageReceiptReadRequest = serde_json::from_value(request.body.clone())?;
    account.client.mark_read(&body.conversation_id, &body.reader_id, &body.message_id)?;
    Ok(local_bus_ok(serde_json::json!({
        "conversation_id": body.conversation_id,
        "reader_id": body.reader_id,
        "read_through_message_id": body.message_id,
        "scope": "local_projection",
    })))
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
                .receive_gateway_plaintext_deliveries(&mut engine, body.limit, conversation_id)
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
