// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Typed egress builders with durable-retry-friendly, unpredictable logical message identifiers.
use crate::SdkError;
use ramflux_protocol::{EventFrame, SurfaceAction};
use serde::Serialize;

/// Creates a fresh 128-bit random surface message id. Persist it before sending and reuse it
/// unchanged for retries of the same logical operation.
/// # Errors
/// Returns an OS entropy failure.
pub fn new_surface_message_id() -> Result<String, SdkError> {
    let bytes = ramflux_crypto::random_32()?;
    Ok(ramflux_protocol::encode_base64url(&bytes[..16]))
}
/// A local-bus surface request, constructed from typed local intent or an already validated action.
/// Serialization is for output; remote events/actions must still enter from their original bytes.
#[derive(Clone, Serialize)]
pub struct SurfaceSendRequest {
    pub conversation_id: String,
    pub message_id: String,
    pub wire_base64: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub author_principal_id: Option<String>,
}
impl SurfaceSendRequest {
    /// Encodes a locally authored typed command and assigns one fresh logical message id.
    /// # Errors
    /// Rejects invalid I-JSON values or an entropy failure.
    pub fn event(frame: &EventFrame) -> Result<Self, SdkError> {
        let wire = frame.wire_bytes()?;
        Ok(Self {
            conversation_id: frame.conversation_id.clone(),
            message_id: new_surface_message_id()?,
            wire_base64: ramflux_protocol::encode_base64url(wire),
            author_principal_id: None,
        })
    }
    /// Encode an RPC frame for the `surface.send` transport method.
    /// # Errors
    /// Refuses invalid framing, bounds or an entropy failure.
    pub fn rpc(
        author: Option<&str>,
        frame: &ramflux_protocol::RpcFrame,
        kind: ramflux_protocol::RpcKind,
    ) -> Result<Self, SdkError> {
        Ok(Self {
            conversation_id: frame.conversation_id.clone(),
            message_id: new_surface_message_id()?,
            wire_base64: ramflux_protocol::encode_base64url(frame.wire_bytes(kind)?),
            author_principal_id: author.map(str::to_owned),
        })
    }
    /// Preserves the exact validated action wire bytes and selects the intended author namespace.
    /// # Errors
    /// Rejects invalid original action bytes or an entropy failure.
    pub fn action(author_principal_id: &str, wire: &[u8]) -> Result<Self, SdkError> {
        let action = SurfaceAction::from_wire_bytes(wire)?;
        Ok(Self {
            conversation_id: action.conversation_id().into(),
            message_id: new_surface_message_id()?,
            wire_base64: ramflux_protocol::encode_base64url(wire),
            author_principal_id: Some(author_principal_id.into()),
        })
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn builder_message_identifiers_have_128_random_bits_and_actions_keep_original_bytes()
    -> Result<(), Box<dyn std::error::Error>> {
        let first = super::new_surface_message_id()?;
        let second = super::new_surface_message_id()?;
        assert_ne!(first, second);
        assert_eq!(ramflux_protocol::decode_base64url(&first)?.len(), 16);
        let wire = include_bytes!(
            "../../ramflux-protocol/fixtures/protocol/v1/a2ui_surface/submit.action.json"
        )
        .to_vec();
        let request = super::SurfaceSendRequest::action("author", &wire)?;
        assert_eq!(ramflux_protocol::decode_base64url(&request.wire_base64)?, wire);
        assert_eq!(request.author_principal_id.as_deref(), Some("author"));
        Ok(())
    }
}
