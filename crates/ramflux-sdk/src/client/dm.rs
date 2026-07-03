// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![allow(clippy::missing_errors_doc)]
#![allow(clippy::wildcard_imports)]
use crate::prelude::*;

impl RamfluxClient {
    pub fn send_direct_message(
        &self,
        conversation_id: &str,
        message_id: &str,
        sender_id: &str,
        encrypted_body: &[u8],
    ) -> Result<(), SdkError> {
        Ok(self.account_db()?.send_direct_message(
            conversation_id,
            message_id,
            sender_id,
            encrypted_body,
        )?)
    }

    /// # Errors
    /// Returns an error when validation, serialization, storage, or state checks fail.
    pub fn send_direct_message_with_metadata(
        &self,
        conversation_id: &str,
        message_id: &str,
        sender_id: &str,
        encrypted_body: &[u8],
        metadata: &MessageMetadata,
    ) -> Result<(), SdkError> {
        Ok(self.account_db()?.send_direct_message_with_metadata(
            conversation_id,
            message_id,
            sender_id,
            encrypted_body,
            metadata,
        )?)
    }

    /// # Errors
    /// Returns an error when local projection write or gateway submit fails.
    pub async fn send_direct_message_via_gateway(
        &self,
        engine: &mut GatewaySessionEngine,
        message: GatewayDirectMessage,
    ) -> Result<GatewayInboxEntry, SdkError> {
        self.send_direct_message(
            &message.conversation_id,
            &message.message_id,
            &message.sender_id,
            &message.encrypted_body,
        )?;
        let envelope = gateway_direct_message_envelope(&engine.config, &message, None)?;
        engine.submit_envelope(envelope).await
    }

    /// # Errors
    /// Returns an error when the gateway rejects or cannot deliver the envelope.
    pub async fn submit_direct_message_via_gateway(
        &self,
        engine: &mut GatewaySessionEngine,
        message: GatewayDirectMessage,
    ) -> Result<GatewayInboxEntry, SdkError> {
        let envelope = gateway_direct_message_envelope(&engine.config, &message, None)?;
        engine.submit_envelope(envelope).await
    }

    /// # Errors
    /// Returns an error when SDK-owned DM encryption, local projection write, or gateway submit
    /// fails.
    pub async fn send_plaintext_direct_message_via_gateway(
        &self,
        engine: &mut GatewaySessionEngine,
        message: GatewayDirectMessage,
        plaintext: &[u8],
    ) -> Result<GatewayInboxEntry, SdkError> {
        self.send_plaintext_direct_message_via_gateway_inner(engine, message, plaintext, true).await
    }

    pub(crate) async fn send_plaintext_direct_message_without_franking(
        &self,
        engine: &mut GatewaySessionEngine,
        message: GatewayDirectMessage,
        plaintext: &[u8],
    ) -> Result<GatewayInboxEntry, SdkError> {
        self.send_plaintext_direct_message_via_gateway_inner(engine, message, plaintext, false)
            .await
    }

    async fn send_plaintext_direct_message_via_gateway_inner(
        &self,
        engine: &mut GatewaySessionEngine,
        mut message: GatewayDirectMessage,
        plaintext: &[u8],
        include_franking_ext: bool,
    ) -> Result<GatewayInboxEntry, SdkError> {
        let conversation_id = message.conversation_id.clone();
        let (mut session, x3dh) = self.load_or_create_send_dm_session(engine, &message).await?;
        let ciphertext = session.encrypt(plaintext, dm_associated_data(&conversation_id))?;
        let franking =
            include_franking_ext.then(|| SdkDmFrankingMetadata::from_ciphertext(&ciphertext));
        message.encrypted_body = serde_json::to_vec(&SdkDmEncryptedEnvelope {
            schema: "ramflux.sdk.dm_x3dh_envelope.v1".to_owned(),
            version: 1,
            x3dh,
            ciphertext,
        })?;
        self.send_direct_message(
            &message.conversation_id,
            &message.message_id,
            &message.sender_id,
            &message.encrypted_body,
        )?;
        let envelope =
            gateway_direct_message_envelope(&engine.config, &message, franking.as_ref())?;
        let entry = engine.submit_envelope(envelope).await?;
        self.persist_dm_session(&conversation_id, &entry.envelope.envelope_id, "send", &session)?;
        Ok(entry)
    }

    /// # Errors
    /// Returns an error when attachment encryption/upload, DM encryption, or gateway submit fails.
    pub async fn send_plaintext_direct_message_with_attachments_via_gateway(
        &mut self,
        engine: &mut GatewaySessionEngine,
        message: GatewayDirectMessage,
        plaintext: &[u8],
        attachments: &[LocalBusMessageAttachmentInput],
    ) -> Result<GatewayInboxEntry, SdkError> {
        self.send_plaintext_direct_message_with_attachments_via_gateway_inner(
            engine,
            message,
            plaintext,
            attachments,
            true,
        )
        .await
    }

    async fn send_plaintext_direct_message_with_attachments_via_gateway_inner(
        &mut self,
        engine: &mut GatewaySessionEngine,
        message: GatewayDirectMessage,
        plaintext: &[u8],
        attachments: &[LocalBusMessageAttachmentInput],
        include_franking_ext: bool,
    ) -> Result<GatewayInboxEntry, SdkError> {
        let mut refs = Vec::with_capacity(attachments.len());
        for attachment in attachments {
            let attachment_plaintext = ramflux_protocol::decode_base64url(
                &attachment.plaintext_base64,
            )
            .map_err(|error| SdkError::LocalBus(format!("invalid attachment body: {error}")))?;
            refs.push(
                self.dm_attachment_ref_for_recipient(
                    engine,
                    &message,
                    attachment,
                    &attachment_plaintext,
                )
                .await?,
            );
        }
        let envelope = SdkDmAttachmentEnvelope {
            schema: "ramflux.sdk.dm_attachment_envelope.v1".to_owned(),
            version: 1,
            body_base64: ramflux_protocol::encode_base64url(plaintext),
            attachments: refs,
        };
        let envelope_plaintext = serde_json::to_vec(&envelope)?;
        self.send_plaintext_direct_message_via_gateway_inner(
            engine,
            message,
            &envelope_plaintext,
            include_franking_ext,
        )
        .await
    }

    /// # Errors
    /// Returns an error when receipt serialization, encryption, local projection, or gateway
    /// delivery fails.
    pub(crate) async fn send_receipt_event_via_gateway(
        &self,
        engine: &mut GatewaySessionEngine,
        mut message: GatewayDirectMessage,
        envelope: SdkReceiptEventEnvelope,
    ) -> Result<GatewayInboxEntry, SdkError> {
        let conversation_id = message.conversation_id.clone();
        let (mut session, x3dh) = self.load_or_create_send_dm_session(engine, &message).await?;
        let plaintext = serde_json::to_vec(&envelope)?;
        let ciphertext = session.encrypt(&plaintext, dm_associated_data(&conversation_id))?;
        message.encrypted_body = serde_json::to_vec(&SdkDmEncryptedEnvelope {
            schema: "ramflux.sdk.dm_x3dh_envelope.v1".to_owned(),
            version: 1,
            x3dh,
            ciphertext,
        })?;
        let entry = self.submit_direct_message_via_gateway(engine, message).await?;
        self.persist_dm_session(&conversation_id, &entry.envelope.envelope_id, "send", &session)?;
        Ok(entry)
    }

    /// # Errors
    /// Returns an error when the target device prekey cannot be fetched, the A2I control event
    pub async fn receive_gateway_deliveries(
        &self,
        engine: &mut GatewaySessionEngine,
        limit: usize,
    ) -> Result<Vec<GatewayInboxEntry>, SdkError> {
        let after_inbox_seq = self.gateway_cursor(engine.target_delivery_id())?;
        let entries = engine.resume_after(after_inbox_seq, limit).await?;
        for entry in &entries {
            self.append_gateway_delivery(entry)?;
        }
        Ok(entries)
    }

    /// # Errors
    /// Returns an error when resume fails, the opaque delivery cannot be appended locally, or SDK
    /// DM decryption fails.
    pub async fn receive_gateway_plaintext_deliveries(
        &mut self,
        engine: &mut GatewaySessionEngine,
        limit: usize,
        conversation_id: &str,
        auto_fetch_attachments: bool,
        relay_service_key_base64: Option<String>,
    ) -> Result<Vec<GatewayPlaintextDelivery>, SdkError> {
        let after_inbox_seq = self.gateway_receive_cursor(engine.target_delivery_id())?;
        let mut entries = engine.resume_after(after_inbox_seq, limit).await?;
        entries.retain(|entry| entry.inbox_seq > after_inbox_seq);
        entries.sort_by_key(|entry| entry.inbox_seq);
        let mut plaintext = Vec::new();
        for entry in entries {
            self.append_gateway_delivery(&entry)?;
            if self.plaintext_projection_delivery(conversation_id, &entry)?.is_some() {
                self.persist_gateway_receive_cursor(engine.target_delivery_id(), entry.inbox_seq)?;
                continue;
            }
            let ciphertext_bytes = ramflux_protocol::decode_base64url(
                &entry.envelope.encrypted_payload,
            )
            .map_err(|error| SdkError::LocalBus(format!("invalid encrypted payload: {error}")))?;
            let envelope: SdkDmEncryptedEnvelope = serde_json::from_slice(&ciphertext_bytes)?;
            let mut session =
                self.load_or_create_recv_dm_session(conversation_id, envelope.x3dh.as_ref())?;
            let decrypted = session.decrypt_with_franking_keys(
                &envelope.ciphertext,
                dm_associated_data(conversation_id),
            )?;
            let body = decrypted.plaintext.clone();
            self.persist_dm_session(
                conversation_id,
                &entry.envelope.envelope_id,
                "recv",
                &session,
            )?;
            self.apply_contact_event_plaintext(&body)?;
            if self
                .apply_receipt_event_plaintext(&body, &entry.envelope.source_device_id)?
                .is_some()
            {
                self.persist_gateway_receive_cursor(engine.target_delivery_id(), entry.inbox_seq)?;
                continue;
            }
            if let Some(reason) =
                self.friend_rejection_reason(&entry.envelope.source_principal_id)?
            {
                self.account_db()?.reject_inbox_message(
                    conversation_id,
                    &entry.envelope.envelope_id,
                    &entry.envelope.source_principal_id,
                    &reason,
                    now_unix_timestamp(),
                )?;
                self.persist_gateway_receive_cursor(engine.target_delivery_id(), entry.inbox_seq)?;
                continue;
            }
            let (projection_body, attachment_refs) = decode_dm_attachment_body(&body)?;
            let metadata = franking_report_metadata_for_delivery(
                conversation_id,
                &entry,
                &envelope,
                &decrypted,
            )?;
            let mut attachments = Vec::new();
            if auto_fetch_attachments {
                for attachment in &attachment_refs {
                    attachments.push(self.import_dm_attachment_from_relay(
                        attachment,
                        relay_service_key_base64.clone(),
                    )?);
                }
            }
            self.append_plaintext_projection_once(
                conversation_id,
                &entry,
                &projection_body,
                metadata.as_ref(),
            )?;
            self.persist_gateway_receive_cursor(engine.target_delivery_id(), entry.inbox_seq)?;
            plaintext.push(GatewayPlaintextDelivery {
                conversation_id: conversation_id.to_owned(),
                message_id: entry.envelope.envelope_id.clone(),
                sender_id: entry.envelope.source_principal_id.clone(),
                plaintext_body_base64: ramflux_protocol::encode_base64url(&projection_body),
                attachments,
                entry,
            });
        }
        Ok(plaintext)
    }

    /// # Errors
    /// Returns an error when the message is missing, has no stored franking report metadata, or
    /// the stored plaintext cannot be represented as the selected evidence string.
    pub fn selected_franking_evidence_for_direct_message(
        &self,
        conversation_id: &str,
        message_id: &str,
    ) -> Result<SdkSelectedFrankingEvidence, SdkError> {
        let message = self
            .direct_message_by_id(message_id)?
            .ok_or_else(|| SdkError::LocalBus(format!("message not found: {message_id}")))?;
        if message.conversation_id != conversation_id {
            return Err(SdkError::LocalBus(format!(
                "message {message_id} is not in conversation {conversation_id}"
            )));
        }
        let Some(franking) = message.metadata.franking_report else {
            return Err(SdkError::LocalBus(format!(
                "message has no stored franking evidence: {message_id}"
            )));
        };
        let plaintext = ramflux_protocol::decode_base64url(&franking.plaintext_base64)
            .map_err(|error| SdkError::LocalBus(format!("invalid stored plaintext: {error}")))?;
        let plaintext_excerpt = String::from_utf8(plaintext).map_err(|error| {
            SdkError::LocalBus(format!("stored plaintext is not UTF-8 evidence: {error}"))
        })?;
        Ok(SdkSelectedFrankingEvidence {
            evidence_kind: SdkFrankingEvidenceKind::ReceiverAttestedDm,
            node_id: franking.node_id,
            envelope_id: franking.envelope_id,
            plaintext_excerpt,
            opening_key: franking.opening_key,
            commitment_key: franking.commitment_key,
            sender_device_id_hash: franking.sender_device_id_hash,
            msg_event_id: franking.msg_event_id,
            canonical_header_bytes: franking.canonical_header_bytes,
            associated_data: franking.associated_data,
            ciphertext: franking.ciphertext,
            header_hash: franking.header_hash,
            associated_data_hash: franking.associated_data_hash,
            ciphertext_hash: franking.ciphertext_hash,
            franking_commitment: franking.franking_commitment,
            commitment: franking.commitment,
            franking_tag: franking.franking_tag,
            franking_timestamp: franking.franking_timestamp,
            group_header_signature: None,
        })
    }

    /// # Errors
    /// Returns an error when the gateway resume fails or an A2I control envelope cannot be
    fn plaintext_projection_delivery(
        &self,
        conversation_id: &str,
        entry: &GatewayInboxEntry,
    ) -> Result<Option<GatewayPlaintextDelivery>, SdkError> {
        let message_id = &entry.envelope.envelope_id;
        let Some(message) = self
            .direct_messages(conversation_id)?
            .into_iter()
            .find(|message| message.message_id == *message_id)
        else {
            return Ok(None);
        };
        Ok(Some(GatewayPlaintextDelivery {
            entry: entry.clone(),
            conversation_id: conversation_id.to_owned(),
            message_id: message.message_id,
            sender_id: message.sender_id,
            plaintext_body_base64: ramflux_protocol::encode_base64url(&message.encrypted_body),
            attachments: Vec::new(),
        }))
    }

    /// # Errors
    /// Returns an error when the gateway ack fails or the durable cursor cannot be persisted.
    pub async fn ack_gateway_delivery(
        &self,
        engine: &mut GatewaySessionEngine,
        envelope_id: &str,
        receiver_device_id: &str,
        received_at: i64,
    ) -> Result<GatewayCursor, SdkError> {
        let ack = gateway_ack(envelope_id, receiver_device_id, received_at)?;
        let cursor = engine.ack(ack).await?;
        self.persist_gateway_cursor(&cursor.target_delivery_id, cursor.inbox_seq)?;
        Ok(cursor)
    }

    /// # Errors
    fn append_plaintext_projection_once(
        &self,
        conversation_id: &str,
        entry: &GatewayInboxEntry,
        plaintext: &[u8],
        metadata: Option<&MessageMetadata>,
    ) -> Result<(), SdkError> {
        let message_id = &entry.envelope.envelope_id;
        if self
            .direct_messages(conversation_id)?
            .iter()
            .any(|message| message.message_id == *message_id)
        {
            return Ok(());
        }
        if let Some(metadata) = metadata {
            self.send_direct_message_with_metadata(
                conversation_id,
                message_id,
                &entry.envelope.source_principal_id,
                plaintext,
                metadata,
            )
        } else {
            self.send_direct_message(
                conversation_id,
                message_id,
                &entry.envelope.source_principal_id,
                plaintext,
            )
        }
    }

    fn apply_receipt_event_plaintext(
        &self,
        body: &[u8],
        authenticated_source_device_id: &str,
    ) -> Result<Option<SdkReceiptEventEnvelope>, SdkError> {
        let Ok(envelope) = serde_json::from_slice::<SdkReceiptEventEnvelope>(body) else {
            return Ok(None);
        };
        if envelope.schema != "ramflux.sdk.receipt_event.v1" {
            return Ok(None);
        }
        if envelope.reader_device_id != authenticated_source_device_id {
            return Err(SdkError::LocalBus(format!(
                "receipt reader_device_id mismatch: claimed {}, authenticated {}",
                envelope.reader_device_id, authenticated_source_device_id
            )));
        }
        let inserted = match &envelope.event {
            SdkReceiptEventBody::Delivered {
                conversation_id,
                message_id,
                delivered_at,
                receiver_device_id,
                ttl_seconds,
                ..
            } => {
                if receiver_device_id != authenticated_source_device_id {
                    return Err(SdkError::LocalBus(format!(
                        "receipt receiver_device_id mismatch: claimed {receiver_device_id}, authenticated {authenticated_source_device_id}"
                    )));
                }
                let inserted = self.account_db()?.record_receipt_event_once(ReceiptEventWrite {
                    receipt_id: &envelope.receipt_id,
                    conversation_id,
                    message_id,
                    receipt_type: "delivered",
                    actor_device_id: receiver_device_id,
                    created_at: *delivered_at,
                })?;
                if inserted {
                    self.mark_delivered(
                        conversation_id,
                        receiver_device_id,
                        message_id,
                        *delivered_at,
                        i64::from(*ttl_seconds),
                    )?;
                }
                inserted
            }
            SdkReceiptEventBody::ReadPrivate {
                conversation_id,
                message_id,
                reader_identity,
                read_at,
                ..
            } => {
                if reader_identity != authenticated_source_device_id {
                    return Err(SdkError::LocalBus(format!(
                        "receipt reader identity mismatch: claimed {reader_identity}, authenticated {authenticated_source_device_id}"
                    )));
                }
                let inserted = self.account_db()?.record_receipt_event_once(ReceiptEventWrite {
                    receipt_id: &envelope.receipt_id,
                    conversation_id,
                    message_id,
                    receipt_type: "read",
                    actor_device_id: reader_identity,
                    created_at: *read_at,
                })?;
                if inserted {
                    self.mark_read(conversation_id, reader_identity, message_id)?;
                }
                inserted
            }
            SdkReceiptEventBody::ReadPublic { .. } => {
                return Err(SdkError::LocalBus(
                    "public read receipts are not accepted on the E2EE receipt path".to_owned(),
                ));
            }
        };
        let _ = inserted;
        Ok(Some(envelope))
    }
}

fn franking_report_metadata_for_delivery(
    conversation_id: &str,
    entry: &GatewayInboxEntry,
    envelope: &SdkDmEncryptedEnvelope,
    decrypted: &ramflux_crypto::DmDecryptionOutput,
) -> Result<Option<MessageMetadata>, SdkError> {
    let Some(franking_value) = entry.envelope.ext.ext.get("franking") else {
        return Ok(None);
    };
    if franking_value.get("franking_tag").is_none()
        || franking_value.get("node_id").is_none()
        || franking_value.get("accepted_at").is_none()
    {
        return Ok(None);
    }
    let franking: SdkReceivedFrankingMetadata = serde_json::from_value(franking_value.clone())?;
    if franking.sender_device_id_hash
        != ramflux_protocol::encode_base64url(envelope.ciphertext.sender_device_id_hash)
        || franking.message_event_id != envelope.ciphertext.message_event_id
        || franking.commitment != envelope.ciphertext.commitment
        || franking.ciphertext_hash != envelope.ciphertext.ciphertext_hash
    {
        return Err(SdkError::LocalBus(
            "received franking metadata does not match DM ciphertext".to_owned(),
        ));
    }
    let commitment =
        ramflux_crypto::franking_commitment(&ramflux_crypto::FrankingCommitmentInput {
            plaintext: &decrypted.plaintext,
            sender_device_id_hash: &envelope.ciphertext.sender_device_id_hash,
            message_event_id: &envelope.ciphertext.message_event_id,
            canonical_header_bytes: &envelope.ciphertext.canonical_header_bytes,
            associated_data: dm_associated_data(conversation_id),
            ciphertext: &envelope.ciphertext.ciphertext,
            opening_key: &decrypted.opening_key,
            commitment_key: &decrypted.commitment_key,
        });
    Ok(Some(MessageMetadata {
        franking_report: Some(FrankingReportMetadata {
            node_id: franking.node_id,
            envelope_id: entry.envelope.envelope_id.clone(),
            plaintext_base64: ramflux_protocol::encode_base64url(&decrypted.plaintext),
            opening_key: ramflux_protocol::encode_base64url(decrypted.opening_key),
            commitment_key: ramflux_protocol::encode_base64url(decrypted.commitment_key),
            sender_device_id_hash: franking.sender_device_id_hash,
            msg_event_id: franking.message_event_id,
            canonical_header_bytes: ramflux_protocol::encode_base64url(
                &envelope.ciphertext.canonical_header_bytes,
            ),
            associated_data: ramflux_protocol::encode_base64url(dm_associated_data(
                conversation_id,
            )),
            ciphertext: ramflux_protocol::encode_base64url(&envelope.ciphertext.ciphertext),
            header_hash: commitment.header_hash,
            associated_data_hash: commitment.associated_data_hash,
            ciphertext_hash: commitment.ciphertext_hash,
            franking_commitment: commitment.franking_commitment,
            commitment: commitment.commitment,
            franking_tag: franking.franking_tag,
            franking_timestamp: franking.accepted_at,
        }),
        ..MessageMetadata::default()
    }))
}

fn decode_dm_attachment_body(body: &[u8]) -> Result<(Vec<u8>, Vec<SdkDmAttachmentRef>), SdkError> {
    let Ok(envelope) = serde_json::from_slice::<SdkDmAttachmentEnvelope>(body) else {
        return Ok((body.to_vec(), Vec::new()));
    };
    if envelope.schema != "ramflux.sdk.dm_attachment_envelope.v1" {
        return Ok((body.to_vec(), Vec::new()));
    }
    let body = ramflux_protocol::decode_base64url(&envelope.body_base64)
        .map_err(|error| SdkError::LocalBus(format!("invalid DM attachment body: {error}")))?;
    Ok((body, envelope.attachments))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_root(test_name: &str) -> PathBuf {
        let nanos =
            SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |duration| duration.as_nanos());
        std::env::temp_dir()
            .join(format!("ramflux-sdk-dm-{test_name}-{}-{nanos}", std::process::id()))
    }

    fn test_client(test_name: &str) -> Result<(PathBuf, RamfluxClient), SdkError> {
        let root = temp_root(test_name);
        let mut client = RamfluxClient::new();
        client.open_account_index(&root)?;
        client.create_account("acct", "principal")?;
        client.unlock_account("acct", b"test-secret")?;
        Ok((root, client))
    }

    #[test]
    fn selected_franking_evidence_is_built_from_stored_message_metadata() -> Result<(), SdkError> {
        let (root, client) = test_client("franking-evidence")?;
        let metadata = MessageMetadata {
            franking_report: Some(FrankingReportMetadata {
                node_id: "localhost".to_owned(),
                envelope_id: "env_report".to_owned(),
                plaintext_base64: ramflux_protocol::encode_base64url(b"selected report text"),
                opening_key: "opening".to_owned(),
                commitment_key: "commitment-key".to_owned(),
                sender_device_id_hash: "sender-hash".to_owned(),
                msg_event_id: "msg-event".to_owned(),
                canonical_header_bytes: "header".to_owned(),
                associated_data: "ad".to_owned(),
                ciphertext: "ciphertext".to_owned(),
                header_hash: "header-hash".to_owned(),
                associated_data_hash: "ad-hash".to_owned(),
                ciphertext_hash: "ciphertext-hash".to_owned(),
                franking_commitment: "franking-commitment".to_owned(),
                commitment: "commitment".to_owned(),
                franking_tag: "node-tag".to_owned(),
                franking_timestamp: 1_760_001_234_567,
            }),
            ..MessageMetadata::default()
        };
        client.send_direct_message_with_metadata(
            "conv_report",
            "msg_report",
            "alice",
            b"selected report text",
            &metadata,
        )?;

        let evidence =
            client.selected_franking_evidence_for_direct_message("conv_report", "msg_report")?;
        assert_eq!(evidence.evidence_kind, SdkFrankingEvidenceKind::ReceiverAttestedDm);
        assert_eq!(evidence.node_id, "localhost");
        assert_eq!(evidence.envelope_id, "env_report");
        assert_eq!(evidence.plaintext_excerpt, "selected report text");
        assert_eq!(evidence.franking_tag, "node-tag");
        assert_eq!(evidence.franking_timestamp, 1_760_001_234_567);

        let _ = std::fs::remove_dir_all(root);
        Ok(())
    }
}
