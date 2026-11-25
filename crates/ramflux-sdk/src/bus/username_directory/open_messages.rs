// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Durable open-send intents. Destination cost admission must activate before transport.
use crate::{
    SdkError,
    prelude::{LocalBusAccountState, LocalBusDispatchResult, LocalBusFrame, local_bus_ok},
};
use ramflux_protocol::{
    account_reach::{ReachMode, ReplyPermission},
    username_directory as w,
};
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Start {
    pub name: String,
    pub text: zeroize::Zeroizing<String>,
    pub operation_id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Reply {
    pub request_id: String,
    pub text: zeroize::Zeroizing<String>,
    pub operation_id: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Intent {
    operation_id: String,
    peer_root: String,
    principal_id: String,
    conversation_id: String,
    message_id: String,
    text: zeroize::Zeroizing<String>,
    placement: String,
    permission: Option<ReplyPermission>,
}

pub(super) fn validate(text: &str, operation: &str) -> Result<(), SdkError> {
    if text.is_empty()
        || text.len() > 65536
        || operation.is_empty()
        || operation.len() > 256
        || operation.chars().any(char::is_control)
    {
        return Err(w::DirectoryCode::InvalidProfile.into());
    }
    Ok(())
}

pub(super) fn prepare_reply(
    account: &LocalBusAccountState,
    request: &LocalBusFrame,
) -> Result<(w::NativeUsernameAction, Reply), SdkError> {
    let body: Reply = serde_json::from_value(request.body.clone())?;
    validate(&body.text, &body.operation_id)?;
    let row = account
        .client
        .account_db()?
        .select_inbound_contact_request("request_id", &body.request_id)?
        .ok_or(crate::ContactReason::RequestNotFound)?;
    if row.state != "pending" || row.expires_at <= crate::prelude::now_unix_timestamp() {
        return Err(crate::ContactReason::RequestClosed.into());
    }
    let conversation_id = ramflux_protocol::message::dm_scope::derive(
        &row.contact_identity_commitment,
        &account.principal_commitment,
    )
    .map_err(|_| w::DirectoryCode::OwnershipMismatch)?;
    Ok((
        w::NativeUsernameAction::ReplyAuthorize {
            peer_root: row.contact_identity_commitment,
            conversation_id,
            operation_id: body.operation_id.clone(),
        },
        body,
    ))
}

pub(super) fn start(
    account: &LocalBusAccountState,
    resolved: &crate::username_directory::ResolvedUsername,
    input: Start,
) -> Result<LocalBusDispatchResult, SdkError> {
    if resolved.root_commitment == account.principal_commitment {
        return Err(crate::ContactReason::SelfContact.into());
    }
    resolved.pin_for_add(account.client.account_db()?)?;
    let mode = resolved
        .reach
        .as_ref()
        .map(|row| row.policy.body.mode)
        .ok_or(w::DirectoryCode::DirectoryUnavailable)?;
    let conversation = ramflux_protocol::message::dm_scope::derive(
        &account.principal_commitment,
        &resolved.root_commitment,
    )
    .map_err(|_| w::DirectoryCode::OwnershipMismatch)?;
    enqueue(
        account,
        Intent {
            message_id: message_id(&account.principal_commitment, &input.operation_id)?,
            conversation_id: conversation,
            peer_root: resolved.root_commitment.clone(),
            principal_id: resolved.principal_id.clone(),
            text: input.text,
            operation_id: input.operation_id,
            placement: if mode == ReachMode::Open { "direct" } else { "requests" }.into(),
            permission: None,
        },
    )
}

pub(super) fn reply(
    account: &LocalBusAccountState,
    input: Reply,
    result: crate::username_directory::UsernameNetworkReply,
) -> Result<LocalBusDispatchResult, SdkError> {
    let w::NativeUsernameReply::ReplyAuthorized { permission } = result.reply else {
        return Err(w::DirectoryCode::DirectoryUnavailable.into());
    };
    if permission.expires_at <= crate::custody::network_now()? {
        return Err(SdkError::LocalBus("reply permission expired".into()));
    }
    let row = account
        .client
        .account_db()?
        .select_inbound_contact_request("request_id", &input.request_id)?
        .ok_or(crate::ContactReason::RequestNotFound)?;
    if row.state != "pending"
        || permission.owner_root != account.principal_commitment
        || permission.peer_root != row.contact_identity_commitment
    {
        return Err(crate::ContactReason::RequestClosed.into());
    }
    enqueue(
        account,
        Intent {
            message_id: message_id(&account.principal_commitment, &input.operation_id)?,
            conversation_id: permission.conversation_id.clone(),
            peer_root: permission.peer_root.clone(),
            principal_id: row.principal_id,
            operation_id: input.operation_id,
            text: input.text,
            placement: "requests".into(),
            permission: Some(permission),
        },
    )
}

fn message_id(root: &str, operation: &str) -> Result<String, SdkError> {
    Ok(ramflux_protocol::hash_base64url(
        "ramflux.open_message.intent.v1",
        &ramflux_protocol::canonical_json_bytes(&(root, operation))?,
    ))
}

fn enqueue(
    account: &LocalBusAccountState,
    intent: Intent,
) -> Result<LocalBusDispatchResult, SdkError> {
    let db = account.client.account_db()?;
    let key = format!("reach/outbox/{}", intent.message_id);
    for peer in [&intent.peer_root, &intent.principal_id] {
        if db.friend_link_for_peer(peer)?.is_some_and(|link| link.blocked) {
            return Err(crate::ContactReason::RequestClosed.into());
        }
    }
    let intent = db.write_transaction(|| {
        if let Some(old) = db.load_actor_state::<Intent>(&key)? {
            if old.peer_root != intent.peer_root
                || old.text != intent.text
                || old.operation_id != intent.operation_id
                || old.conversation_id != intent.conversation_id
            {
                return Err(SdkError::ReplayMismatch);
            }
            return Ok(old);
        }
        db.bind_message_container_reference(&intent.message_id, &key)?;
        db.persist_actor_state(&key, &intent)?;
        Ok::<_, SdkError>(intent)
    })?;
    Ok(local_bus_ok(
        serde_json::json!({"conversation_id":intent.conversation_id,"message_id":intent.message_id,"placement":intent.placement,"state":"pending"}),
    ))
}
