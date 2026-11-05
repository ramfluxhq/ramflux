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
        let verification = match state.as_ref() {
            Some(state) => sender_verification(client, state, &message)?,
            None => SenderVerification::Unknown,
        };
        let mut plaintext = super::group_plaintext_json(
            &body.conversation_id,
            &body.group_id,
            &message.message_id,
            &content,
        );
        plaintext["sender_verification"] = serde_json::to_value(verification)?;
        let mut message = serde_json::to_value(message)?;
        message["sender_verification"] = serde_json::to_value(verification)?;
        decrypted.push(plaintext);
        messages.push(message);
        if messages.len() >= body.limit {
            break;
        }
    }
    Ok(json!({"group_id":body.group_id,"conversation_id":body.conversation_id,
        "metadata":metadata,"messages":messages,"decrypted_messages":decrypted}))
}

/// This describes current cached sender authority, not a new admission decision.
#[derive(Clone, Copy, serde::Serialize)]
#[serde(rename_all = "snake_case")]
enum SenderVerification {
    Verified,
    Unverified,
    Unknown,
}

fn sender_verification(
    client: &RamfluxClient,
    state: &ramflux_crypto::VerifiedGroupState,
    message: &ramflux_storage::DirectMessageRecord,
) -> Result<SenderVerification, SdkError> {
    match verify_sender(client, state, message) {
        Ok(()) => Ok(SenderVerification::Verified),
        Err(SdkError::InboundPending(_) | SdkError::IdentityRootMissing) => {
            Ok(SenderVerification::Unknown)
        }
        Err(
            SdkError::InboundRejected(_)
            | SdkError::Crypto(_)
            | SdkError::Protocol(_)
            | SdkError::CustodyExpired
            | SdkError::CustodyForkFenced
            | SdkError::CustodyModeDowngrade
            | SdkError::SignatureVerificationFailed(_),
        ) => Ok(SenderVerification::Unverified),
        Err(error) => Err(error),
    }
}

fn verify_sender(
    client: &RamfluxClient,
    state: &ramflux_crypto::VerifiedGroupState,
    message: &ramflux_storage::DirectMessageRecord,
) -> Result<(), SdkError> {
    let identity = if let Some(owner) = client
        .account_db()?
        .load_actor_state::<String>(&format!("routed/message-owner/{}", message.message_id))?
    {
        client.device_identity(&owner)?
    } else {
        // A raw device name alone cannot identify a sibling's root. Preserve the
        // stored row as unknown instead of guessing authority from another member.
        let mut members = state
            .view()
            .members
            .iter()
            .filter(|member| member.identity.device_id == message.sender_id);
        let member = members
            .next()
            .ok_or_else(|| SdkError::InboundPending("stored sender authority absent".into()))?;
        if members.next().is_some() {
            return Err(SdkError::InboundPending("ambiguous stored sender authority".into()));
        }
        client.device_identity_for_root(
            &member.identity.root_commitment,
            &member.identity.device_id,
        )?
    };
    client.trusted_device(HeadUse::HistoricalRead, &identity)?;
    Ok(())
}
