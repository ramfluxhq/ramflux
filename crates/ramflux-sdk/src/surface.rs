// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Typed egress builders with durable-retry-friendly, unpredictable logical message identifiers.
use crate::SdkError;
use ramflux_protocol::{A2uiConversationCommand, A2uiSurfaceAction};
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
    pub fn event(
        conversation_id: &str,
        version: u64,
        command: &A2uiConversationCommand,
    ) -> Result<Self, SdkError> {
        let wire =
            ramflux_protocol::encode_a2ui_conversation_event(conversation_id, version, command)?;
        Ok(Self {
            conversation_id: conversation_id.into(),
            message_id: new_surface_message_id()?,
            wire_base64: ramflux_protocol::encode_base64url(wire),
            author_principal_id: None,
        })
    }
    /// Preserves the exact validated action wire bytes and selects the intended author namespace.
    /// # Errors
    /// Rejects invalid original action bytes or an entropy failure.
    pub fn action(author_principal_id: &str, wire: &[u8]) -> Result<Self, SdkError> {
        let action = A2uiSurfaceAction::from_wire_bytes(wire)?;
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
        let values = serde_json::json!({});
        let wire = serde_json::to_vec(
            &serde_json::json!({"schema":"ramflux.a2ui.action.v2","conversationId":"c","surfaceId":"s","version":1,"surfaceHash":"h","actionId":"choose","values":values,"argsHash":ramflux_protocol::surface_args_hash(&values)?}),
        )?;
        let request = super::SurfaceSendRequest::action("author", &wire)?;
        assert_eq!(ramflux_protocol::decode_base64url(&request.wire_base64)?, wire);
        assert_eq!(request.author_principal_id.as_deref(), Some("author"));
        Ok(())
    }
}
