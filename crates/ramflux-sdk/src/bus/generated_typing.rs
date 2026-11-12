// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! This branch precedes durable mutation lookup/reservation and response/event capture.
use super::{
    actor::{AccountCommand, ActorResponse},
    state::LocalBusDaemonState,
};
use crate::prelude::local_bus_account_mut;
use crate::{
    SdkError,
    bindings::{AdapterError, GeneratedErrorCode},
};
use ramflux_protocol::message as g;

/// Scheduling only; strict generated validation still runs before any effect.
/// Malformed Typing-shaped local requests must not trigger a network bootstrap either.
pub(super) fn is_request(method: &str, body: &serde_json::Value) -> bool {
    method == "message.submit"
        && (body.get("typing").is_some() || body.pointer("/send/content/typing").is_some())
}

pub(super) fn is_transient(method: &str, body: &serde_json::Value) -> bool {
    method == "message.focus" || is_request(method, body)
}

pub(super) async fn execute(
    state: &mut LocalBusDaemonState,
    account_id: &str,
    command: &AccountCommand,
) -> Result<Option<ActorResponse>, SdkError> {
    if !crate::client::target_selection::schema_v1_selected() {
        if is_transient(&command.request.method, &command.request.body) {
            return Err(AdapterError::new(
                GeneratedErrorCode::PeerUpgradeRequired,
                "Typing requires schema generation 1",
            )
            .into());
        }
        return Ok(None);
    }
    if command.request.method == "message.focus" {
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Focus {
            conversation_id: Option<String>,
        }
        let focus: Focus = serde_json::from_value(command.request.body.clone())?;
        let account = local_bus_account_mut(state, account_id)?;
        let previous = account.client.set_typing_focus(focus.conversation_id.as_deref())?;
        if let Some(previous) = previous {
            let request = g::MessageRequest {
                request_id: command.request.request_id.clone(),
                account_id: account_id.into(),
                action: Some(g::message_request::Action::Send(g::SendMessage {
                    conversation_id: previous,
                    operation_id: ramflux_crypto::random_32()?.to_vec(),
                    reply_to: None,
                    content: Some(g::Content {
                        value: Some(g::content::Value::Typing(g::Typing {
                            active: false,
                            expires_at: 0,
                        })),
                    }),
                })),
            };
            // Best effort clear; never reconnect, queue or retry a blur notification.
            if let Some(engine) = account.engine.as_mut() {
                let _ = account.client.send_generated_typing_request(engine, &request).await;
            }
        }
        return Ok(Some(ActorResponse {
            body: serde_json::Value::Null,
            events: Vec::new(),
            nodes: None,
        }));
    }
    if command.request.method != "message.submit" {
        return Ok(None);
    }
    let request = crate::bindings::decode_message_request(&command.request.body)?;
    let Some(g::message_request::Action::Send(send)) = request.action.as_ref() else {
        return Ok(None);
    };
    if !matches!(
        send.content.as_ref().and_then(|content| content.value.as_ref()),
        Some(g::content::Value::Typing(_))
    ) {
        return Ok(None);
    }
    if request.account_id != account_id {
        return Err(AdapterError::new(
            GeneratedErrorCode::InvalidArgument,
            "typing account mismatch",
        )
        .into());
    }
    let account = local_bus_account_mut(state, account_id)?;
    let engine = account.engine.as_mut().ok_or_else(|| {
        AdapterError::new(
            GeneratedErrorCode::EphemeralUnavailable,
            "typing requires a live ephemeral host",
        )
    })?;
    // Borrow in place: cancellation never removes the live account engine. No resume
    // metadata, response or journal capture belongs to this transient request.
    let update = account.client.send_generated_typing_request(engine, &request).await?;
    Ok(Some(ActorResponse {
        body: crate::bindings::encode_message_update(&update)?,
        events: Vec::new(),
        nodes: None,
    }))
}
