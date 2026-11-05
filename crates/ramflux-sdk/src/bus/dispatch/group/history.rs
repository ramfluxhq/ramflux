// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Stored group history, without receive work or network authority refresh.
use crate::client::identity_authority::HeadUse;
use crate::prelude::*;
use serde_json::{Value, json};

pub(crate) fn read(client: &RamfluxClient, request: &LocalBusFrame) -> Result<Value, SdkError> {
    let mut body: LocalBusGroupReceiveRequest = serde_json::from_value(request.body.clone())?;
    body.conversation_id =
        crate::bus::group_conversation::resolve(client, &body.group_id, &body.conversation_id)?;
    let metadata = match client.shared_group_metadata(&body.group_id)? {
        Some(value) => value,
        None => serde_json::to_value(client.group_state(&body.group_id)?)?,
    };
    let db = client.account_db()?;
    let state = db.shared_group_state(&body.group_id)?;
    let mut messages = Vec::new();
    let mut decrypted = Vec::new();
    if body.limit == 0 {
        return Ok(json!({"group_id":body.group_id,"conversation_id":body.conversation_id,
            "metadata":metadata,"messages":[],"decrypted_messages":[]}));
    }
    for message in client.direct_messages(&body.conversation_id)? {
        if message.deleted {
            continue;
        }
        let Some(content) = db.message_content(&message.message_id)? else {
            continue;
        };
        if let Some(state) = &state {
            let identity = if let Some(owner) = db.load_actor_state::<String>(&format!(
                "routed/message-owner/{}",
                message.message_id
            ))? {
                client.device_identity(&owner)?
            } else {
                let mut members = state
                    .view()
                    .members
                    .iter()
                    .filter(|member| member.identity.device_id == message.sender_id);
                let member = members.next().ok_or_else(|| {
                    SdkError::InboundRejected("stored sender authority absent".into())
                })?;
                if members.next().is_some() {
                    return Err(SdkError::InboundRejected(
                        "ambiguous stored sender authority".into(),
                    ));
                }
                client.device_identity_for_root(
                    &member.identity.root_commitment,
                    &member.identity.device_id,
                )?
            };
            client.trusted_device(HeadUse::HistoricalRead, &identity)?;
        }
        decrypted.push(super::group_plaintext_json(
            &body.conversation_id,
            &body.group_id,
            &message.message_id,
            &content,
        ));
        messages.push(message);
        if messages.len() >= body.limit {
            break;
        }
    }
    Ok(json!({"group_id":body.group_id,"conversation_id":body.conversation_id,
        "metadata":metadata,"messages":messages,"decrypted_messages":decrypted}))
}
