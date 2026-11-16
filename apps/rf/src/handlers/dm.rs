// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![allow(unused_imports)]
#![allow(clippy::wildcard_imports)]
use super::*;

#[path = "dm/unified.rs"]
pub(crate) mod unified;
#[path = "dm/wait.rs"]
mod wait;

pub(crate) async fn handle_dm(socket: PathBuf, command: DmCommand) -> Result<(), RfError> {
    if let DmAction::Send(send) = &command.action {
        super::attachment::refuse_retired(
            send.relay_url.is_some(),
            send.attachment_chunk_size.is_some(),
        )?;
        if !send.attach.is_empty() && !send.media_ref.is_empty() {
            return Err(RfError::Message("content".into()));
        }
    }
    let mut bus = LocalBusClient::connect(socket).await?;
    match command.action {
        DmAction::Send(send) if !send.attach.is_empty() => {
            super::attachment::send_dm(&mut bus, send).await
        }
        DmAction::Send(send) => {
            let federation = rf_federation_route(&send)?;
            let content = crate::utils::media_content(&send.body, &send.media_ref)?;
            let request = LocalBusMessageSubmitRequest {
                content: Some(content),
                conversation_id: send.conversation,
                message_id: send.message,
                envelope_id: send.envelope,
                source_principal_id: send.source_principal,
                sender_id: send.sender,
                recipient_device_id: send.recipient_device,
                recipient_principal_commitment: send.recipient_principal_commitment,
                target_delivery_id: send.target,
                encrypted_body_base64: String::new(),
                plaintext_body_base64: None,
                created_at: rf_now_unix_timestamp(),
                ttl: send
                    .ttl
                    .min(u32::try_from(ramflux_protocol::REPLAY_WINDOW_SECONDS).unwrap_or(300)),
                attachments: Vec::new(),
                federation,
            };
            print_json(
                &bus.request(
                    Some(send.account),
                    "message",
                    "message.submit",
                    serde_json::to_value(request)?,
                )
                .await?,
            )
        }
        DmAction::List(selector) => handle_dm_list(&mut bus, selector).await,
        DmAction::Read(read) => handle_dm_read(&mut bus, read).await,
        DmAction::Ack(ack) => {
            let request = rf_dm_ack_request(&ack)?;
            print_json(
                &bus.request(
                    Some(ack.account),
                    "message",
                    "message.ack",
                    serde_json::to_value(request)?,
                )
                .await?,
            )
        }
        DmAction::Delete(delete) => {
            let request = LocalBusMessageDeleteRequest {
                conversation_id: delete.conversation,
                message_id: delete.message,
                delete_scope: delete.scope,
                tombstone_id: None,
                operation_id: delete.operation_id,
            };
            print_json(
                &bus.request(
                    Some(delete.account),
                    "message",
                    "message.delete",
                    serde_json::to_value(request)?,
                )
                .await?,
            )
        }
        DmAction::Receipt(command) => handle_dm_receipt(&mut bus, command).await,
        DmAction::Disappearing(command) => handle_dm_disappearing(&mut bus, command).await,
        DmAction::Mute(mute) => handle_dm_mute(&mut bus, mute).await,
    }
}

async fn handle_dm_list(
    bus: &mut LocalBusClient,
    selector: ConversationSelector,
) -> Result<(), RfError> {
    let query = unified::Query {
        account: selector.account,
        conversation: selector.conversation,
        limit: selector.limit,
        before: selector.before,
        after_seq: selector.after_seq,
        message: selector.message,
    };
    unified::print(bus, &query, false).await
}

async fn handle_dm_read(bus: &mut LocalBusClient, read: DmRead) -> Result<(), RfError> {
    let query = unified::Query {
        account: read.account,
        conversation: read.conversation,
        limit: read.limit,
        before: read.before,
        after_seq: read.after_seq,
        message: read.message,
    };
    let value = wait::receive(std::time::Duration::from_secs(read.wait), async || {
        unified::read(bus, &query, true).await
    })
    .await?;
    print_json(&value)
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
                recipient_device_id: delivered.recipient_device,
                target_delivery_id: delivered.target,
                delivered_at: delivered.delivered_at,
                ttl_seconds: Some(delivered.ttl_secs),
            };
            print_json(
                &bus.request(
                    Some(delivered.account),
                    "message",
                    "message.receipt.delivered",
                    serde_json::to_value(request)?,
                )
                .await?,
            )
        }
        DmReceiptAction::Read(read) => {
            let request = LocalBusMessageReceiptReadRequest {
                conversation_id: read.conversation,
                message_id: read.message,
                reader_id: read.reader,
                recipient_device_id: read.recipient_device,
                target_delivery_id: read.target,
                read_at: read.read_at,
            };
            print_json(
                &bus.request(
                    Some(read.account),
                    "message",
                    "message.receipt.read",
                    serde_json::to_value(request)?,
                )
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
                    serde_json::to_value(request)?,
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
                    serde_json::to_value(request)?,
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
        &bus.request(
            Some(mute.account),
            "conversation",
            "conversation.mute",
            serde_json::to_value(request)?,
        )
        .await?,
    )
}

fn rf_dm_ack_request(ack: &DmAck) -> Result<LocalBusMessageAckRequest, RfError> {
    Ok(LocalBusMessageAckRequest {
        envelope_id: rf_dm_ack_envelope_id(ack)?,
        receiver_device_id: ack.receiver_device.clone(),
        received_at: ack.received_at.unwrap_or_else(rf_now_unix_timestamp),
        inbox_seq: ack.inbox_seq,
    })
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

#[cfg(test)]
mod tests {
    use clap::Parser;

    #[test]
    fn retired_dm_flags_are_unknown_arguments() -> Result<(), Box<dyn std::error::Error>> {
        let args = [
            "rf",
            "dm",
            "delete",
            "--account",
            "account",
            "--conversation",
            "conversation",
            "--message",
            "operation",
            "--tombstone",
            "old-id",
        ];
        let error = crate::cli::Cli::try_parse_from(args).err().ok_or("retired flag accepted")?;
        assert_eq!(error.kind(), clap::error::ErrorKind::UnknownArgument);
        Ok(())
    }
}
