// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Explicit ordinary attachment authorization on independently paired native owners.
use super::AccountSessionHarness;
use crate::{GatewayDirectMessage, LocalBusMessageAttachmentInput, SdkError};
const MESSAGE: &str = "paired-ordinary-media-message";
const OBJECT: &str = "paired-ordinary-media-object";
const MAX_BYTES: usize = 65_536;
impl AccountSessionHarness {
    /// Authorize an ordinary encrypted attachment upload and message to the named sibling.
    /// # Errors
    /// Refuses oversized fixture input, native/session errors or failed authenticated upload.
    pub async fn send_pairing_media(
        &mut self,
        sibling: &str,
        body: &[u8],
        media: &[u8],
    ) -> Result<(), SdkError> {
        if media.len() > MAX_BYTES || body.len() > MAX_BYTES {
            return Err(SdkError::PairingCode("TransferCapacity"));
        }
        let mut engine = self.session()?;
        let account = self
            .runtime
            .state
            .accounts
            .get_mut(&self.runtime.id)
            .ok_or(SdkError::AccountDbNotUnlocked)?;
        let identity = account.client.owned_device_identity()?;
        let options = account
            .client
            .relay_transfer_options(None, None, None)?
            .ok_or(SdkError::NetworkingPending)?;
        let pool = account.relay_quic_pool()?;
        let message = GatewayDirectMessage {
            conversation_id: "paired-ordinary-media-thread".into(),
            message_id: MESSAGE.into(),
            envelope_id: MESSAGE.into(),
            source_principal_id: account.gateway_config.principal_id.clone(),
            sender_id: identity.device_id().into(),
            recipient_device_id: Some(sibling.into()),
            recipient_principal_commitment: Some(identity.root_commitment().into()),
            target_delivery_id: ramflux_protocol::qualified_device_id(
                identity.root_commitment(),
                sibling,
            )?,
            encrypted_body: Vec::new(),
            created_at: crate::time::now_unix_timestamp(),
            ttl: account.client.content_ttl()?,
        };
        let attachment = LocalBusMessageAttachmentInput {
            name: Some("paired-media.bin".into()),
            mime: Some("application/octet-stream".into()),
            object_id: OBJECT.into(),
            plaintext_base64: ramflux_protocol::encode_base64url(media),
            chunk_size: MAX_BYTES,
            relay_endpoint: options.relay_endpoint,
            owner_home_node_id: options.relay_owner_home_node_id,
            relay_audience_node_id: options.relay_audience_node_id,
            relay_service_key_base64: None,
        };
        let result =
            Box::pin(account.client.send_plaintext_direct_message_with_attachments_via_gateway(
                &mut engine,
                &pool,
                message,
                body,
                &[attachment],
            ))
            .await;
        account.apply_session_metadata(engine);
        result.map(|_| ())
    }

    /// Fetch and decrypt the received ordinary attachment using this device's own branch.
    /// # Errors
    /// Returns receipt, grant, proof, remote fetch, decryption or plaintext mismatch errors.
    pub async fn fetch_pairing_media(&mut self, expected: &[u8]) -> Result<(), SdkError> {
        if expected.len() > MAX_BYTES {
            return Err(SdkError::PairingCode("TransferCapacity"));
        }
        let mut engine = self.session()?;
        let account = self
            .runtime
            .state
            .accounts
            .get_mut(&self.runtime.id)
            .ok_or(SdkError::AccountDbNotUnlocked)?;
        let pool = account.relay_quic_pool()?;
        let result = Box::pin(account.client.fetch_received_attachment(
            &mut engine,
            &pool,
            OBJECT,
            "paired-ordinary-media-fetch",
        ))
        .await;
        account.apply_session_metadata(engine);
        result?;
        let actual = zeroize::Zeroizing::new(account.client.decrypt_object(OBJECT)?);
        if actual.as_slice() != expected {
            return Err(SdkError::InboundRejected("paired media plaintext mismatch".into()));
        }
        Ok(())
    }
}
