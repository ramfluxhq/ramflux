// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Typed transient local-bus framing, independent of journal publication.
use super::{AdapterError, GeneratedErrorCode};
use crate::{LocalBusFrame, LocalBusFrameKind, SdkError};
use prost::Message as _;
use ramflux_protocol::message as g;

/// Encode a Typing update as a lossy `message.transient` event with sequence zero.
/// It has no RPC correlation, durable operation key, cursor or replay source.
/// # Errors
/// Refuses non-Typing state, nonzero sequence, malformed transient identity or frame overflow.
pub fn transient_message_frame(update: &g::MessageUpdate) -> Result<LocalBusFrame, SdkError> {
    let invalid = || {
        AdapterError::new(GeneratedErrorCode::InvalidArgument, "invalid transient Typing update")
    };
    let Some(g::message_update::State::Content(content)) = update.state.as_ref() else {
        return Err(invalid().into());
    };
    let Some(g::content::Value::Typing(typing)) = content.value.as_ref() else {
        return Err(invalid().into());
    };
    let identity = update.identity.as_ref().ok_or_else(invalid)?;
    if update.journal_sequence != 0
        || identity.id.len() != 32
        || identity.device_sequence != 0
        || identity.hlc != 0
        || identity.conversation_id.is_empty()
        || identity.group_id.is_some()
        || identity.group_epoch.is_some()
        || identity.author.as_ref().is_none_or(|author| {
            author.account_anchor.is_empty()
                || author.device_id.is_empty()
                || author.device_epoch == 0
        })
        || typing.expires_at == 0
        || typing.expires_at.checked_mul(1000).is_none()
    {
        return Err(invalid().into());
    }
    let body = super::encode_message_update(update)?;
    let mut frame = LocalBusFrame::request(
        "",
        Some(update.account_id.clone()),
        "message",
        g::TRANSIENT_TOPIC,
        body,
    );
    frame.kind = LocalBusFrameKind::Event;
    frame.seq = Some(0);
    // Local event locator, not a wire message identity or an authority proof. Include the
    // complete typed metadata so intentional nonce reuse cannot collide across scopes.
    frame.frame_id =
        format!("transient_{}", ramflux_protocol::encode_base64url(update.encode_to_vec()));
    if ramflux_protocol::canonical_json_bytes(&frame)?.len()
        > crate::bus::io::MAX_LOCAL_BUS_FRAME_BYTES
    {
        return Err(AdapterError::new(
            GeneratedErrorCode::PayloadTooLarge,
            "transient frame exceeds bus limit",
        )
        .into());
    }
    Ok(frame)
}
