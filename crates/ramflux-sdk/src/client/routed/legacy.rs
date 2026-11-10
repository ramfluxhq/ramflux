// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Legacy routing accepts only an existing exact device-pair and ratchet-session binding.
use super::{
    GatewayInboxEntry, RamfluxClient, SdkDmEncryptedEnvelope, SdkError, dm_device_id_hash,
};
impl RamfluxClient {
    pub(crate) async fn authorize_bound_legacy(
        &self,
        gateway: &crate::GatewaySessionConfig,
        entry: &GatewayInboxEntry,
        conversation: &str,
    ) -> Result<(), SdkError> {
        self.require_legacy_routing_binding(&gateway.device_id, entry, conversation)?;
        self.ensure_inbound_device(gateway, entry).await
    }

    /// Sync half of `authorize_bound_legacy`: the exact device/session/conversation binding,
    /// including the v2-blocks-legacy guard. Shared by the live DM path and the W1 DM paths.
    /// It does not run `ensure_inbound_device`; async callers must do that separately.
    pub(crate) fn require_legacy_routing_binding(
        &self,
        local: &str,
        entry: &GatewayInboxEntry,
        conversation: &str,
    ) -> Result<(), SdkError> {
        if self.legacy_routing_binding(local, entry)?.as_deref() != Some(conversation) {
            return Err(SdkError::InboundRejected(
                "legacy delivery has no matching device/session/conversation binding".to_owned(),
            ));
        }
        Ok(())
    }

    pub(crate) fn legacy_routing_binding(
        &self,
        local: &str,
        entry: &GatewayInboxEntry,
    ) -> Result<Option<String>, SdkError> {
        if self.v2_blocks_legacy(&self.inbound_device_reference(entry)?)? {
            return Ok(None);
        }
        let bytes = ramflux_protocol::decode_base64url(&entry.envelope.encrypted_payload)
            .map_err(|_| SdkError::LocalBus("invalid envelope encoding".to_owned()))?;
        let Ok(envelope) = serde_json::from_slice::<SdkDmEncryptedEnvelope>(&bytes) else {
            return Ok(None);
        };
        if envelope.version != 1 || envelope.schema != "ramflux.sdk.dm_x3dh_envelope.v1" {
            // Group and other v1 payloads JSON-parse as this type via shared
            // ciphertext fields. They are not a DM binding.
            return Ok(None);
        }
        let mut binding = None;
        for conversation in self.conversation_list()? {
            if let Ok(session) = self.load_dm_session(&conversation.conversation_id, "recv") {
                if session.session_id != envelope.ciphertext.session_id {
                    continue;
                }
                let sender = dm_device_id_hash(&entry.envelope.source_device_id);
                let recipient = dm_device_id_hash(local);
                if (session.sender_device_id_hash == sender
                    && session.recipient_device_id_hash == recipient)
                    || (session.sender_device_id_hash == recipient
                        && session.recipient_device_id_hash == sender)
                {
                    if binding.is_some() {
                        return Ok(None);
                    }
                    binding = Some(conversation.conversation_id);
                }
            }
        }
        Ok(binding)
    }
}
