// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Dormant generated Message/Service/Forward/Receipt Inner conversion.
//! This module neither sends a carrier nor admits a stored event.
use crate::{RamfluxClient, SdkError};
use prost::Message as _;
use ramflux_protocol::message as g;
use ramflux_protocol::message::registry::{self, COMPILED_LAYER};
use ramflux_protocol::message::validation::{self, ScanOutcome};

/// Shared device sequence and HLC for Message and Service on one conversation.
#[derive(Clone, Debug)]
pub struct GeneratedEventStream {
    conversation_id: String,
    author: g::QualifiedDevice,
    group_id: Option<String>,
    group_epoch: Option<u64>,
    device_sequence: u64,
    hlc: u64,
}

impl GeneratedEventStream {
    /// Start a per-device stream. Sequence and HLC begin at zero and increment together.
    #[must_use]
    pub fn new(conversation_id: impl Into<String>, author: g::QualifiedDevice) -> Self {
        Self {
            conversation_id: conversation_id.into(),
            author,
            group_id: None,
            group_epoch: None,
            device_sequence: 0,
            hlc: 0,
        }
    }

    /// Attach group identity shared by every event on this stream.
    #[must_use]
    pub fn with_group(mut self, group_id: impl Into<String>, epoch: u64) -> Self {
        self.group_id = Some(group_id.into());
        self.group_epoch = Some(epoch);
        self
    }

    /// Allocate the next source-qualified identity on this stream.
    /// # Errors
    /// Refuses an empty event id.
    pub fn next(&mut self, event_id: Vec<u8>) -> Result<g::EventIdentity, SdkError> {
        if event_id.is_empty() {
            return Err(invalid("generated event id must be source-qualified"));
        }
        self.device_sequence = self.device_sequence.saturating_add(1);
        self.hlc = self.hlc.saturating_add(1);
        Ok(g::EventIdentity {
            id: event_id,
            conversation_id: self.conversation_id.clone(),
            author: Some(self.author.clone()),
            device_sequence: self.device_sequence,
            hlc: self.hlc,
            group_id: self.group_id.clone(),
            group_epoch: self.group_epoch,
        })
    }
}

impl RamfluxClient {
    /// Encode generated Inner bytes. Additive candidate API; does not send or persist.
    /// # Errors
    /// Rejects empty identity, invalid content, noncanonical wire, or the Inner byte cap.
    pub fn encode_generated_inner(
        identity: g::EventIdentity,
        content: &g::Content,
    ) -> Result<Vec<u8>, SdkError> {
        if identity.id.is_empty() {
            return Err(invalid("generated event id must be source-qualified"));
        }
        validation::validate_content(content).map_err(content_error)?;
        let (kind, body) = registry::encode_body(content).map_err(content_error)?;
        let inner = g::Inner { layer: COMPILED_LAYER, kind, identity: Some(identity), body };
        let bytes = inner.encode_to_vec();
        check_wire(&bytes)?;
        Ok(bytes)
    }

    /// Encode a Message body on a shared event stream.
    /// # Errors
    /// Same as [`Self::encode_generated_inner`].
    pub fn encode_generated_message(
        stream: &mut GeneratedEventStream,
        event_id: Vec<u8>,
        message: g::Message,
    ) -> Result<Vec<u8>, SdkError> {
        let identity = stream.next(event_id)?;
        Self::encode_generated_inner(
            identity,
            &g::Content { value: Some(g::content::Value::Message(message)) },
        )
    }

    /// Encode a Service body on the same stream as Message (T13).
    /// # Errors
    /// Same as [`Self::encode_generated_inner`].
    pub fn encode_generated_service(
        stream: &mut GeneratedEventStream,
        event_id: Vec<u8>,
        service: g::Service,
    ) -> Result<Vec<u8>, SdkError> {
        let identity = stream.next(event_id)?;
        Self::encode_generated_inner(
            identity,
            &g::Content { value: Some(g::content::Value::Service(service)) },
        )
    }

    /// Encode a user Receipt body. Distinct from transport ACK (T13).
    /// # Errors
    /// Same as [`Self::encode_generated_inner`].
    pub fn encode_generated_receipt(
        stream: &mut GeneratedEventStream,
        event_id: Vec<u8>,
        receipt: g::Receipt,
    ) -> Result<Vec<u8>, SdkError> {
        let identity = stream.next(event_id)?;
        Self::encode_generated_inner(
            identity,
            &g::Content { value: Some(g::content::Value::Receipt(receipt)) },
        )
    }

    /// Decode canonical generated Inner bytes. No effect is committed.
    /// # Errors
    /// Rejects noncanonical bytes, missing identity, or invalid content.
    pub fn decode_generated_inner(
        bytes: &[u8],
    ) -> Result<(g::EventIdentity, g::Content), SdkError> {
        check_wire(bytes)?;
        let inner = g::Inner::decode(bytes).map_err(|_| invalid("invalid generated inner"))?;
        let identity = inner.identity.ok_or_else(|| invalid("generated inner identity missing"))?;
        if identity.id.is_empty() {
            return Err(invalid("generated event id must be source-qualified"));
        }
        let content =
            registry::decode_body(inner.kind, &inner.body, inner.layer).map_err(content_error)?;
        Ok((identity, content))
    }
}

fn check_wire(bytes: &[u8]) -> Result<(), SdkError> {
    if bytes.len() > validation::MAX_INNER_BYTES {
        return Err(invalid("generated inner exceeds the byte cap"));
    }
    let scanned =
        validation::scan_inner(bytes).map_err(|_| invalid("noncanonical generated inner"))?;
    if scanned.outcome != ScanOutcome::Supported {
        return Err(invalid("unsupported generated inner"));
    }
    Ok(())
}

fn content_error(error: validation::ValidationError) -> SdkError {
    invalid(error.to_string())
}

fn invalid(message: impl Into<String>) -> SdkError {
    SdkError::LocalBus(message.into())
}

#[cfg(test)]
mod tests;
