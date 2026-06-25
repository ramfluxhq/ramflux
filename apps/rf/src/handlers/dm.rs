#![allow(unused_imports)]
#![allow(clippy::wildcard_imports)]
use super::*;

pub(crate) async fn handle_dm(socket: PathBuf, command: DmCommand) -> Result<(), RfError> {
    let mut bus = LocalBusClient::connect(socket).await?;
    match command.action {
        DmAction::Send(send) => {
            let federation = rf_federation_route(&send)?;
            let request = LocalBusMessageSubmitRequest {
                conversation_id: send.conversation,
                message_id: send.message,
                envelope_id: send.envelope,
                source_principal_id: send.source_principal,
                sender_id: send.sender,
                recipient_device_id: send.recipient_device,
                target_delivery_id: send.target,
                encrypted_body_base64: String::new(),
                plaintext_body_base64: Some(ramflux_protocol::encode_base64url(
                    send.body.as_bytes(),
                )),
                created_at: rf_now_unix_timestamp(),
                ttl: send
                    .ttl
                    .min(u32::try_from(ramflux_protocol::REPLAY_WINDOW_SECONDS).unwrap_or(300)),
                federation,
            };
            print_json(
                &bus.request(Some(send.account), "message", "message.submit", &request).await?,
            )
        }
        DmAction::List(selector) | DmAction::Read(selector) => {
            let request = LocalBusConversationRequest { conversation_id: selector.conversation };
            let received = bus
                .request(
                    Some(selector.account.clone()),
                    "message",
                    "message.receive",
                    &serde_json::json!({
                        "limit": 100,
                        "conversation_id": request.conversation_id,
                    }),
                )
                .await?;
            let mut value =
                bus.request(Some(selector.account), "message", "message.read", &request).await?;
            value["gateway_entries"] = received
                .get("entries")
                .cloned()
                .unwrap_or_else(|| serde_json::Value::Array(Vec::new()));
            value["decrypted_messages"] = received
                .get("decrypted_messages")
                .cloned()
                .unwrap_or_else(|| serde_json::Value::Array(Vec::new()));
            print_json(&with_message_plaintext(value))
        }
        DmAction::Ack(ack) => {
            let envelope_id = rf_dm_ack_envelope_id(&ack)?;
            let request = LocalBusMessageAckRequest {
                envelope_id,
                receiver_device_id: ack.receiver_device,
                received_at: ack.received_at.unwrap_or_else(rf_now_unix_timestamp),
            };
            print_json(&bus.request(Some(ack.account), "message", "message.ack", &request).await?)
        }
        DmAction::Delete(delete) => {
            let request = LocalBusMessageDeleteRequest {
                conversation_id: delete.conversation,
                message_id: delete.message,
                delete_scope: delete.scope,
                tombstone_id: delete.tombstone,
            };
            print_json(
                &bus.request(Some(delete.account), "message", "message.delete", &request).await?,
            )
        }
        DmAction::Receipt(command) => handle_dm_receipt(&mut bus, command).await,
        DmAction::Disappearing(command) => handle_dm_disappearing(&mut bus, command).await,
        DmAction::Mute(mute) => handle_dm_mute(&mut bus, mute).await,
    }
}

async fn handle_dm_receipt(
    bus: &mut LocalBusClient,
    command: DmReceiptCommand,
) -> Result<(), RfError> {
    match command.action {
        DmReceiptAction::Delivered(delivered) => {
            let request = LocalBusMessageReceiptDeliveredRequest {
                conversation_id: delivered.conversation,
                message_id: delivered.message,
                receiver_device_id: delivered.receiver_device,
                delivered_at: delivered.delivered_at,
                ttl_seconds: Some(delivered.ttl_secs),
            };
            print_json(
                &bus.request(
                    Some(delivered.account),
                    "message",
                    "message.receipt.delivered",
                    &request,
                )
                .await?,
            )
        }
        DmReceiptAction::Read(read) => {
            let request = LocalBusMessageReceiptReadRequest {
                conversation_id: read.conversation,
                message_id: read.message,
                reader_id: read.reader,
            };
            print_json(
                &bus.request(Some(read.account), "message", "message.receipt.read", &request)
                    .await?,
            )
        }
    }
}

async fn handle_dm_disappearing(
    bus: &mut LocalBusClient,
    command: DmDisappearingCommand,
) -> Result<(), RfError> {
    match command.action {
        DmDisappearingAction::Set(set) => {
            let request = LocalBusConversationDisappearingSetRequest {
                conversation_id: set.conversation,
                ttl_secs: set.ttl_secs,
                countdown_mode: "on_send".to_owned(),
                scope: "own_devices".to_owned(),
                updated_at: Some(rf_now_unix_timestamp()),
            };
            print_json(
                &bus.request(
                    Some(set.account),
                    "conversation",
                    "conversation.disappearing.set",
                    &request,
                )
                .await?,
            )
        }
        DmDisappearingAction::Expire(expire) => {
            let request = LocalBusConversationDisappearingExpireRequest {
                conversation_id: expire.conversation,
                now: expire.now,
            };
            print_json(
                &bus.request(
                    Some(expire.account),
                    "conversation",
                    "conversation.disappearing.expire",
                    &request,
                )
                .await?,
            )
        }
    }
}

async fn handle_dm_mute(bus: &mut LocalBusClient, mute: DmMute) -> Result<(), RfError> {
    let request = LocalBusConversationMuteRequest {
        conversation_id: mute.conversation,
        mute_until: mute.mute_until,
        unmute: mute.unmute,
    };
    print_json(
        &bus.request(Some(mute.account), "conversation", "conversation.mute", &request).await?,
    )
}

fn rf_dm_ack_envelope_id(ack: &DmAck) -> Result<String, RfError> {
    match (&ack.envelope, &ack.message) {
        (Some(envelope), Some(message)) if envelope != message => Err(RfError::Message(
            "--message and --envelope must match when both are provided for dm ack".to_owned(),
        )),
        (Some(envelope), _) => Ok(envelope.clone()),
        (_, Some(message)) => Ok(message.clone()),
        (None, None) => {
            let conversation = &ack.conversation;
            Err(RfError::Message(format!(
                "dm ack for conversation {conversation} requires --envelope or --message"
            )))
        }
    }
}

pub(crate) fn rf_federation_route(
    send: &DmSend,
) -> Result<Option<LocalBusFederationRoute>, RfError> {
    match (&send.federation_url, &send.source_node, &send.target_node, &send.recipient_prekey_url) {
        (None, None, None, None) => Ok(None),
        (Some(federation_url), Some(source_node), Some(target_node), recipient_prekey_url) => {
            Ok(Some(LocalBusFederationRoute {
                federation_url: federation_url.clone(),
                source_node_id: source_node.clone(),
                target_node_id: target_node.clone(),
                required_capability: send.federation_capability.clone(),
                admin_token: send.federation_admin_token.clone(),
                recipient_prekey_url: recipient_prekey_url.clone(),
            }))
        }
        _ => Err(RfError::Message(
            "federated dm send requires --federation-url, --source-node, --target-node, and optional --recipient-prekey-url only with that route".to_owned(),
        )),
    }
}
