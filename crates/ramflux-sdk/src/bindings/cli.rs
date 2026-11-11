// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! CLI adapter: construct generated `MessageRequest` / `MessageUpdate` from rf fields.

use super::{invalid, round_trip_request, round_trip_update};
use crate::SdkError;
use ramflux_protocol::message as g;

/// Build a text send request from CLI send fields.
///
/// # Errors
/// Returns an error when required ids or body content are empty.
pub fn send_text(
    request_id: &str,
    account_id: &str,
    conversation_id: &str,
    text: &str,
    operation_id: &[u8],
) -> Result<g::MessageRequest, SdkError> {
    let request = g::MessageRequest {
        request_id: request_id.to_string(),
        account_id: account_id.to_string(),
        action: Some(g::message_request::Action::Send(g::SendMessage {
            conversation_id: conversation_id.to_string(),
            content: Some(g::Content {
                value: Some(g::content::Value::Message(g::Message {
                    text: text.to_string(),
                    ..Default::default()
                })),
            }),
            operation_id: operation_id.to_vec(),
            reply_to: None,
        })),
    };
    round_trip_request(&request)
}

/// Conversation id and text body from a generated send request.
///
/// # Errors
/// Returns an error when the request is not a text send.
pub fn send_payload(request: &g::MessageRequest) -> Result<(String, String), SdkError> {
    let Some(g::message_request::Action::Send(send)) = request.action.as_ref() else {
        return Err(invalid("generated request is not a send"));
    };
    let Some(g::content::Value::Message(message)) =
        send.content.as_ref().and_then(|content| content.value.as_ref())
    else {
        return Err(invalid("generated send requires message content"));
    };
    Ok((send.conversation_id.clone(), message.text.clone()))
}

/// Build a delete request from CLI delete fields.
///
/// # Errors
/// Returns an error when ids are empty.
pub fn delete_message(
    request_id: &str,
    account_id: &str,
    conversation_id: &str,
    message_id: &[u8],
    everyone: bool,
    tombstone_id: Option<&[u8]>,
) -> Result<g::MessageRequest, SdkError> {
    let request = g::MessageRequest {
        request_id: request_id.to_string(),
        account_id: account_id.to_string(),
        action: Some(g::message_request::Action::Delete(g::Delete {
            targets: vec![g::MessageRef {
                id: message_id.to_vec(),
                conversation_id: conversation_id.to_string(),
                author_anchor: String::new(),
            }],
            scope: if everyone {
                g::DeleteScope::Everyone as i32
            } else {
                g::DeleteScope::Local as i32
            },
            tombstone_id: tombstone_id.unwrap_or(&[]).to_vec(),
            native_group_authorization: Vec::new(),
        })),
    };
    round_trip_request(&request)
}

/// Target conversation and message id from a generated delete request.
///
/// # Errors
/// Returns an error when the request is not a delete with one target.
pub fn delete_payload(request: &g::MessageRequest) -> Result<(String, Vec<u8>), SdkError> {
    let Some(g::message_request::Action::Delete(delete)) = request.action.as_ref() else {
        return Err(invalid("generated request is not a delete"));
    };
    let Some(target) = delete.targets.first() else {
        return Err(invalid("generated delete requires a target"));
    };
    Ok((target.conversation_id.clone(), target.id.clone()))
}

/// Build a `MessageUpdate` identity used by CLI surface resync.
///
/// # Errors
/// Returns an error when account or event id is empty.
pub fn identity_update(
    account_id: &str,
    journal_sequence: u64,
    event_id: &[u8],
) -> Result<g::MessageUpdate, SdkError> {
    if event_id.is_empty() {
        return Err(invalid("generated update requires an event id"));
    }
    let update = g::MessageUpdate {
        account_id: account_id.to_string(),
        journal_sequence,
        identity: Some(g::EventIdentity {
            id: event_id.to_vec(),
            conversation_id: String::new(),
            author: None,
            device_sequence: 0,
            hlc: 0,
            group_id: None,
            group_epoch: None,
        }),
        state: Some(g::message_update::State::Unsupported(g::UnsupportedView {
            layer: ramflux_protocol::message::registry::COMPILED_LAYER,
            kind: 0,
            ..Default::default()
        })),
    };
    round_trip_update(&update)
}

/// Event id from a generated update identity.
///
/// # Errors
/// Returns an error when identity is missing.
pub fn identity_event_id(update: &g::MessageUpdate) -> Result<Vec<u8>, SdkError> {
    update
        .identity
        .as_ref()
        .map(|identity| identity.id.clone())
        .filter(|id| !id.is_empty())
        .ok_or_else(|| invalid("generated update requires identity.id"))
}
