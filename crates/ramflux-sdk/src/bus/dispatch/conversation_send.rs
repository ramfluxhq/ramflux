// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Conversation intent resolves authenticated routes before using the ordinary SDK send paths.
use crate::prelude::*;
use serde::Deserialize;
use serde_json::{Value, json};
use zeroize::Zeroize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Intent {
    conversation_id: String,
    text: String,
    #[serde(default)]
    attachments: Vec<LocalBusMessageAttachmentInput>,
}
impl Drop for Intent {
    fn drop(&mut self) {
        self.text.zeroize();
    }
}
fn invalid(message: &str) -> SdkError {
    SdkError::LocalBus(message.into())
}

pub(super) async fn send(
    request: &LocalBusFrame,
    state: &mut LocalBusDaemonState,
) -> Result<LocalBusDispatchResult, SdkError> {
    let account = local_bus_account_mut(state, request_account_id(request)?)?;
    send_account(request, account).await
}

pub(in crate::bus) async fn send_account(
    request: &LocalBusFrame,
    account: &mut LocalBusAccountState,
) -> Result<LocalBusDispatchResult, SdkError> {
    let intent: Intent = serde_json::from_value(request.body.clone())?;
    if intent.text.len() > 64 * 1024 || (intent.text.is_empty() && intent.attachments.is_empty()) {
        return Err(invalid("conversation text must contain 1 to 65536 bytes or attachments"));
    }
    let account_id = request_account_id(request)?;
    let operation = request
        .operation_id
        .as_deref()
        .filter(|key| !key.is_empty() && key.len() <= 256)
        .ok_or_else(|| invalid("conversation.send requires operation_id"))?;
    let message_id = ramflux_crypto::blake3_256_base64url(
        "ramflux.conversation.send.v1",
        &ramflux_protocol::canonical_json_bytes(&(account_id, operation))?,
    );
    let thread = account
        .client
        .account_db()?
        .client_record("conversation", &intent.conversation_id)?
        .ok_or_else(|| invalid("conversation absent"))?;
    let local = account.client.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
    let principal = local.principal_id.clone();
    let sender = local.device_id.clone();
    let message_id = if let Some(group) = thread.get("group_id").and_then(Value::as_str) {
        account.client.qualify_outgoing_group_message(group, &message_id)?.0
    } else {
        message_id
    };
    let deliveries = if let Some(group) = thread.get("group_id").and_then(Value::as_str) {
        if !intent.attachments.is_empty() {
            return Err(invalid("group attachments are unsupported"));
        }
        send_group(account, &intent, &message_id, &sender, group).await?
    } else {
        send_direct(account, &intent, &message_id, &principal, &sender, &thread).await?
    };
    let submitted =
        deliveries.iter().all(|delivery| delivery.get("state") == Some(&json!("submitted")));
    Ok(local_bus_ok(json!({"message_id":message_id,"conversation_id":intent.conversation_id,
        "delivery_state":if submitted {"submitted"} else {"failed"},"deliveries":deliveries})))
}

async fn send_group(
    account: &mut LocalBusAccountState,
    intent: &Intent,
    message: &str,
    sender: &str,
    group: &str,
) -> Result<Vec<Value>, SdkError> {
    let request = LocalBusFrame::request(
        "conversation-send-group",
        None,
        "group",
        "group.send",
        json!({"group_id":group,"conversation_id":intent.conversation_id,"message_id":message,
            "sender_id":sender,"plaintext_body_base64":ramflux_protocol::encode_base64url(intent.text.as_bytes()),
            "encrypted_body_base64":""}),
    );
    let outcome = super::group::dispatch_group_send_request(&request, account).await;
    Ok(vec![delivery(group, outcome)])
}

fn peer_root(
    account: &LocalBusAccountState,
    thread: &Value,
    principal: &str,
) -> Result<(String, String), SdkError> {
    let participants = thread
        .get("participants")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("direct participants absent"))?;
    if thread.get("kind").and_then(Value::as_str) != Some("direct")
        || participants.len() != 2
        || !participants.iter().any(|id| id.as_str() == Some(principal))
    {
        return Err(invalid("direct conversation membership mismatch"));
    }
    let peer = participants
        .iter()
        .filter_map(Value::as_str)
        .find(|id| *id != principal)
        .ok_or_else(|| invalid("direct peer absent"))?;
    let identity = account
        .client
        .account_db()?
        .client_record("identity", peer)?
        .ok_or_else(|| invalid("direct peer identity absent"))?;
    let root = identity
        .get("contact_identity_commitment")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("direct peer commitment absent"))?;
    Ok((peer.into(), root.into()))
}

async fn send_direct(
    account: &mut LocalBusAccountState,
    intent: &Intent,
    message: &str,
    principal: &str,
    sender: &str,
    thread: &Value,
) -> Result<Vec<Value>, SdkError> {
    let (peer, root) = peer_root(account, thread, principal)?;
    let engine = account.session_client().await?;
    let manifest = account
        .client
        .cache_verified_device_manifest(engine.config(), &root, "conversation_peer")
        .await;
    account.apply_session_metadata(engine);
    let manifest = manifest?;
    if manifest.principal_id != peer || manifest.devices.is_empty() || manifest.devices.len() > 64 {
        return Err(invalid("direct peer manifest mismatch or capacity exceeded"));
    }
    let mut deliveries = Vec::new();
    for device in manifest.devices {
        let envelope = ramflux_crypto::blake3_256_base64url(
            "ramflux.conversation.envelope.v1",
            &ramflux_protocol::canonical_json_bytes(&(message, &root, &device.device_id))?,
        );
        let body: LocalBusMessageSubmitRequest = serde_json::from_value(json!({
            "conversation_id":intent.conversation_id,"message_id":message,"envelope_id":envelope,
            "source_principal_id":principal,"sender_id":sender,"recipient_device_id":device.device_id,
            "recipient_principal_commitment":root,"target_delivery_id":device.target_delivery_id,
            "plaintext_body_base64":ramflux_protocol::encode_base64url(intent.text.as_bytes()),
            "encrypted_body_base64":"","created_at":now_unix_timestamp(),
            "ttl":account.client.content_ttl()?,"attachments":intent.attachments}))?;
        let outcome = super::message::submit_conversation_message(account, body).await;
        deliveries.push(delivery(&device.device_id, outcome));
    }
    Ok(deliveries)
}

fn delivery(target: &str, result: Result<LocalBusDispatchResult, SdkError>) -> Value {
    match result {
        Ok(_) => json!({"target":target,"state":"submitted"}),
        Err(error) => {
            json!({"target":target,"state":"failed", "error_code":super::super::io::local_bus_error_code(&error)})
        }
    }
}
