// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Legacy routing accepts only an existing exact device-pair and ratchet-session binding.
use super::{
    GatewayInboxEntry, RamfluxClient, SdkDmEncryptedEnvelope, SdkError, dm_device_id_hash,
};
impl RamfluxClient {
    pub(crate) fn legacy_routing_binding(
        &self,
        local: &str,
        entry: &GatewayInboxEntry,
    ) -> Result<Option<String>, SdkError> {
        let bytes = ramflux_protocol::decode_base64url(&entry.envelope.encrypted_payload)
            .map_err(|_| SdkError::LocalBus("invalid envelope encoding".to_owned()))?;
        let Ok(envelope) = serde_json::from_slice::<SdkDmEncryptedEnvelope>(&bytes) else {
            return Ok(None);
        };
        if envelope.version != 1 {
            return Err(SdkError::LocalBus("invalid routed envelope".to_owned()));
        }
        let mut binding = None;
        for conversation in self.conversation_list()? {
            if let Ok(session) = self.load_dm_session(&conversation.conversation_id, "recv") {
                if session.session_id != envelope.ciphertext.session_id {
                    continue;
                }
                let snapshot = serde_json::to_value(session.snapshot())?;
                let sender =
                    serde_json::to_value(dm_device_id_hash(&entry.envelope.source_device_id))?;
                let recipient = serde_json::to_value(dm_device_id_hash(local))?;
                if (snapshot["sender_device_id_hash"] == sender
                    && snapshot["recipient_device_id_hash"] == recipient)
                    || (snapshot["sender_device_id_hash"] == recipient
                        && snapshot["recipient_device_id_hash"] == sender)
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
