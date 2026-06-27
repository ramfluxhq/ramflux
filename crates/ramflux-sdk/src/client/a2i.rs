// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![allow(clippy::missing_errors_doc)]
#![allow(clippy::wildcard_imports)]
use crate::prelude::*;

impl RamfluxClient {
    pub async fn send_a2i_control_event_via_gateway(
        &self,
        engine: &mut GatewaySessionEngine,
        event: &A2iControlEvent,
        target_delivery_id: Option<String>,
    ) -> Result<GatewayInboxEntry, SdkError> {
        let prekey = engine.fetch_prekey_bundle(&event.target_device_id).await?;
        let target_delivery_id =
            target_delivery_id.or(prekey.target_delivery_id).ok_or_else(|| {
                SdkError::LocalBus(format!(
                    "missing target delivery id for A2I target device {}",
                    event.target_device_id
                ))
            })?;
        let conversation_id =
            a2i_control_conversation_id(&event.source_device_id, &event.target_device_id);
        let message = GatewayDirectMessage {
            conversation_id,
            message_id: event.event_id.clone(),
            envelope_id: format!("a2i:{}", event.event_id),
            source_principal_id: engine.config.principal_id.clone(),
            sender_id: event.source_device_id.clone(),
            recipient_device_id: Some(event.target_device_id.clone()),
            target_delivery_id,
            encrypted_body: Vec::new(),
            created_at: event.created_at,
            ttl: 3_600,
        };
        self.send_plaintext_direct_message_via_gateway(engine, message, &serde_json::to_vec(event)?)
            .await
    }

    /// # Errors
    /// Returns an error when SDK-owned DM encryption, local projection persistence, envelope
    pub async fn receive_a2i_control_events(
        &self,
        engine: &mut GatewaySessionEngine,
        limit: usize,
    ) -> Result<Vec<A2iControlEvent>, SdkError> {
        let after_inbox_seq = self.gateway_receive_cursor(engine.target_delivery_id())?;
        let mut entries = engine.resume_after(after_inbox_seq, limit).await?;
        entries.retain(|entry| entry.inbox_seq > after_inbox_seq);
        entries.sort_by_key(|entry| entry.inbox_seq);
        let mut events = Vec::new();
        for entry in entries {
            self.append_gateway_delivery(&entry)?;
            let conversation_id = a2i_control_conversation_id(
                &entry.envelope.source_device_id,
                &engine.config.device_id,
            );
            let ciphertext_bytes =
                ramflux_protocol::decode_base64url(&entry.envelope.encrypted_payload).map_err(
                    |error| SdkError::LocalBus(format!("invalid A2I encrypted payload: {error}")),
                )?;
            let envelope: SdkDmEncryptedEnvelope = serde_json::from_slice(&ciphertext_bytes)?;
            let mut session =
                self.load_or_create_recv_dm_session(&conversation_id, envelope.x3dh.as_ref())?;
            let body =
                session.decrypt(&envelope.ciphertext, dm_associated_data(&conversation_id))?;
            let event: A2iControlEvent = serde_json::from_slice(&body)?;
            self.persist_dm_session(
                &conversation_id,
                &entry.envelope.envelope_id,
                "recv",
                &session,
            )?;
            self.persist_gateway_receive_cursor(engine.target_delivery_id(), entry.inbox_seq)?;
            events.push(event);
        }
        Ok(events)
    }
}
