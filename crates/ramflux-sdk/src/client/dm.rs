// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![allow(clippy::missing_errors_doc)]
#![allow(clippy::wildcard_imports)]
use crate::prelude::*;
pub(crate) struct LegacyReceive<'a> {
    pub conversation_id: &'a str,
    pub auto_fetch_attachments: bool,
    pub relay_service_key_base64: Option<String>,
}

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
        self.send_plaintext_direct_message_via_gateway_inner(
            engine,
            message,
            plaintext,
            true,
            crate::client::routed::Route::direct(),
        )
        .await
    }

    pub(crate) async fn send_plaintext_direct_message_without_franking(
        &self,
        engine: &mut GatewaySessionEngine,
        message: GatewayDirectMessage,
        plaintext: &[u8],
        route: crate::client::routed::Route,
    ) -> Result<GatewayInboxEntry, SdkError> {
        self.send_plaintext_direct_message_via_gateway_inner(
            engine, message, plaintext, false, route,
        )
        .await
    }

    async fn send_plaintext_direct_message_via_gateway_inner(
        &self,
        engine: &mut GatewaySessionEngine,
        mut message: GatewayDirectMessage,
        plaintext: &[u8],
        include_franking_ext: bool,
        route: crate::client::routed::Route,
    ) -> Result<GatewayInboxEntry, SdkError> {
        self.resolve_message_recipient(&engine.config, &mut message).await?;
        let attachments = route.attachments;
        let own_history_control = matches!(route.kind, crate::client::routed::Kind::Control)
            && serde_json::from_slice::<serde_json::Value>(plaintext)
                .is_ok_and(|value| value["schema"] == "ramflux.sdk.own_device_sync.v1");
        let sealed = self.seal_routed_as(engine, &message, plaintext, route).await?;
        let franking = include_franking_ext
            .then(|| SdkDmFrankingMetadata::from_ciphertext(&sealed.ciphertext));
        message.encrypted_body = serde_json::to_vec(&sealed)?;
        // History replication controls must not become history messages themselves.
        if !own_history_control {
            if let Some(carrier) = crate::client::surface::Carrier::decode(plaintext)? {
                self.journal_surface_frame(&message, &carrier, &message.encrypted_body)?;
            } else {
                self.send_direct_message(
                    &message.conversation_id,
                    &message.message_id,
                    &message.sender_id,
                    &message.encrypted_body,
                )?;
                let content = zeroize::Zeroizing::new(if attachments {
                    crate::client::dm::decode_dm_attachment_body(plaintext)?.0
                } else {
                    plaintext.to_vec()
                });
                self.account_db()?.store_message_content(
                    &message.conversation_id,
                    &message.message_id,
                    &content,
                )?;
            }
        }
        let envelope =
            gateway_direct_message_envelope(&engine.config, &message, franking.as_ref())?;
        // Persist the advanced send ratchet before the remote submit. A process death after the
        // gateway accepts the envelope must never reopen the pre-send chain state and reuse the
        // same message key for a later message. If submit fails, skipping one send key is safe;
        // reusing it is not.

        #[cfg(feature = "itest-rfd-fault")]
        crate::itest_rfd_fault::barrier(crate::itest_rfd_fault::Mode::DmSend).await?;
        let entry = engine.submit_envelope(envelope).await?;
        Ok(entry)
    }

    /// # Errors
    /// Returns an error when attachment encryption/upload, DM encryption, or gateway submit fails.
    pub async fn send_plaintext_direct_message_with_attachments_via_gateway(
        &mut self,
        engine: &mut GatewaySessionEngine,
        pool: &ramflux_transport::RelayQuicPool,
        message: GatewayDirectMessage,
        plaintext: &[u8],
        attachments: &[LocalBusMessageAttachmentInput],
    ) -> Result<GatewayInboxEntry, SdkError> {
        self.send_plaintext_direct_message_with_attachments_via_gateway_inner(
            engine,
            pool,
            message,
            plaintext,
            attachments,
            true,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn send_plaintext_direct_message_with_attachments_via_gateway_inner(
        &mut self,
        engine: &mut GatewaySessionEngine,
        pool: &ramflux_transport::RelayQuicPool,
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
                    pool,
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
            crate::client::routed::Route::attachments(),
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
        let plaintext = serde_json::to_vec(&envelope)?;
        let sealed = self
            .seal_routed_as(engine, &message, &plaintext, crate::client::routed::Route::receipt())
            .await?;
        message.encrypted_body = serde_json::to_vec(&sealed)?;
        let gateway_envelope = gateway_direct_message_envelope(&engine.config, &message, None)?;
        let entry = engine.submit_envelope(gateway_envelope).await?;
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
    #[allow(clippy::too_many_lines)]
    #[allow(clippy::too_many_arguments)]
    pub async fn receive_gateway_plaintext_deliveries(
        &mut self,
        engine: &mut GatewaySessionEngine,
        pool: &ramflux_transport::RelayQuicPool,
        limit: usize,
        conversation_id: &str,
        auto_fetch_attachments: bool,
        relay_service_key_base64: Option<String>,
    ) -> Result<Vec<GatewayPlaintextDelivery>, SdkError> {
        let after_inbox_seq = self.gateway_receive_cursor(engine.target_delivery_id())?;
        let mut entries = engine.resume_after(after_inbox_seq, limit).await?;
        entries.retain(|entry| entry.inbox_seq > after_inbox_seq);
        for bytes in self.account_db()?.unrouted_entries()? {
            let entry: GatewayInboxEntry = serde_json::from_slice(&bytes)?;
            if !entries.iter().any(|e| e.envelope.envelope_id == entry.envelope.envelope_id) {
                entries.push(entry);
            }
        }
        entries.sort_by_key(|entry| entry.inbox_seq);
        let mut plaintext = Vec::new();
        for entry in entries {
            if crate::client::routed::decode(&entry.envelope).is_ok() {
                let delivery: crate::client::routed::Delivery =
                    self.apply_routed_entry(engine, pool, &entry, auto_fetch_attachments).await?;
                self.persist_gateway_receive_cursor(engine.target_delivery_id(), entry.inbox_seq)?;
                if delivery.routing.conversation_id == conversation_id
                    && let Some(message) = delivery.plaintext
                {
                    plaintext.push(message);
                }
                continue;
            }
            let legacy_key = self.inbox_admission_key(&entry)?;
            let legacy_id = entry.envelope.envelope_id.clone();
            if let Some(delivery) = self
                .receive_legacy_entry(
                    engine,
                    pool,
                    entry,
                    LegacyReceive {
                        conversation_id,
                        auto_fetch_attachments,
                        relay_service_key_base64: relay_service_key_base64.clone(),
                    },
                )
                .await?
            {
                plaintext.push(delivery);
            }
            self.account_db()?.remove_unrouted(&legacy_key)?;
            self.account_db()?.remove_unrouted(&legacy_id)?;
        }
        Ok(plaintext)
    }

    fn catch_up_legacy_cursor(
        &self,
        conversation_id: &str,
        entry: &GatewayInboxEntry,
        target: &str,
    ) -> Result<bool, SdkError> {
        if self.legacy_receive_checkpoint_current(conversation_id, entry)? {
            self.persist_legacy_committed(entry, conversation_id)?;
            self.persist_gateway_receive_cursor(target, entry.inbox_seq)?;
            return Ok(true);
        }
        Ok(false)
    }

    pub(crate) async fn receive_legacy_entry(
        &mut self,
        engine: &mut GatewaySessionEngine,
        pool: &ramflux_transport::RelayQuicPool,
        entry: GatewayInboxEntry,
        options: LegacyReceive<'_>,
    ) -> Result<Option<GatewayPlaintextDelivery>, SdkError> {
        self.authorize_bound_legacy(&engine.config, &entry, options.conversation_id).await?;

        let conversation_id = options.conversation_id;
        let terminal = self.legacy_committed_key(&entry)?;
        if self.account_db()?.load_actor_state::<String>(&terminal)?.as_deref()
            == Some(conversation_id)
        {
            return self.plaintext_projection_delivery(conversation_id, &entry);
        }
        self.append_gateway_delivery(&entry)?;
        if self.catch_up_legacy_cursor(conversation_id, &entry, engine.target_delivery_id())? {
            return Ok(None);
        }
        let (envelope, session, decrypted) = self.decrypt_legacy_entry(conversation_id, &entry)?;
        let body = decrypted.plaintext.clone();
        // T21-A2a: the advanced recv session (ratchet) is NOT persisted here. It is committed
        // only once this inbox entry reaches its success terminal state, immediately before the
        // receive cursor advances. If any downstream step fails, the local `session` is dropped
        // so the persisted ratchet snapshot and cursor stay unchanged and the same ciphertext
        // can be re-decrypted on a later `dm read`.
        if let Err(error) = self.project_legacy_contact_control(&entry, &body) {
            if !matches!(error, SdkError::InboundRejected(_)) {
                return Err(error);
            }
            self.quarantine_legacy_control(
                &entry,
                conversation_id,
                engine.target_delivery_id(),
                &session,
            )?;
            return Ok(None);
        }
        if self
            .apply_receipt_event_plaintext(
                &body,
                &self.authenticated_device_identity(&entry)?,
                conversation_id,
            )?
            .is_some()
        {
            // Receipt applied: commit the advanced recv ratchet, then the cursor.
            self.commit_legacy_receive(
                conversation_id,
                &entry,
                engine.target_delivery_id(),
                &session,
            )?;
            return Ok(None);
        }
        if self.reject_legacy_peer(
            conversation_id,
            &entry,
            engine.target_delivery_id(),
            &session,
        )? {
            return Ok(None);
        }
        let (projection_body, attachment_refs) = decode_dm_attachment_body(&body)?;
        let metadata = franking_report_metadata_for_delivery(
            conversation_id,
            &entry,
            &envelope,
            &decrypted,
            None,
        )?;
        let attachments = self
            .import_legacy_attachments(
                engine,
                pool,
                &attachment_refs,
                options.auto_fetch_attachments,
                options.relay_service_key_base64,
            )
            .await?;
        self.append_plaintext_projection_once(
            conversation_id,
            &entry.envelope.envelope_id,
            &entry,
            &projection_body,
            metadata.as_ref(),
        )?;
        if self.account_db()?.client_record("conversation", conversation_id)?.is_none() {
            self.account_db()?.persist_client_record("conversation",conversation_id,&serde_json::json!({
                    "kind":"direct","title":null,"group_id":null,"participants":[engine.config.principal_id,entry.envelope.source_principal_id],"direct_route":null
                }))?;
        }
        self.persist_legacy_attachment_references(&attachment_refs, &entry, conversation_id)?;
        // Every attachment was imported, ACKed, and projected: only now do we commit the
        // advanced recv ratchet, then advance the cursor. A failed attachment import/ACK above
        // returns before this point, leaving the persisted ratchet snapshot and cursor intact so
        // the same ciphertext can be re-decrypted and re-ACKed by a later `dm read`.
        self.persist_dm_session(conversation_id, &entry.envelope.envelope_id, "recv", &session)?;
        #[cfg(feature = "itest-rfd-fault")]
        crate::itest_rfd_fault::barrier(crate::itest_rfd_fault::Mode::DmRecv).await?;
        self.account_db()?.persist_actor_state(&terminal, &conversation_id)?;
        self.persist_gateway_receive_cursor(engine.target_delivery_id(), entry.inbox_seq)?;
        Ok(Some(GatewayPlaintextDelivery {
            conversation_id: conversation_id.to_owned(),
            message_id: entry.envelope.envelope_id.clone(),
            sender_id: entry.envelope.source_principal_id.clone(),
            plaintext_body_base64: ramflux_protocol::encode_base64url(&projection_body),
            attachments,
            entry,
        }))
    }

    fn persist_legacy_attachment_references(
        &self,
        attachment_refs: &[SdkDmAttachmentRef],
        entry: &GatewayInboxEntry,
        conversation_id: &str,
    ) -> Result<(), SdkError> {
        for attachment in attachment_refs {
            self.persist_received_attachment_reference(
                attachment,
                &entry.envelope.source_principal_id,
                conversation_id,
                &entry.envelope.envelope_id,
            )?;
        }
        Ok(())
    }

    fn decrypt_legacy_entry(
        &self,
        conversation_id: &str,
        entry: &GatewayInboxEntry,
    ) -> Result<
        (SdkDmEncryptedEnvelope, ramflux_crypto::DmSession, ramflux_crypto::DmDecryptionOutput),
        SdkError,
    > {
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
        Ok((envelope, session, decrypted))
    }

    fn legacy_receive_checkpoint_current(
        &self,
        conversation: &str,
        entry: &GatewayInboxEntry,
    ) -> Result<bool, SdkError> {
        // The persisted ratchet checkpoint, not a partial plaintext projection, permits cursor catch-up.
        let projected = self.plaintext_projection_delivery(conversation, entry)?.is_some();
        let committed =
            self.recv_session_checkpoint_at(conversation, &entry.envelope.envelope_id)?;
        Ok(matches!(
            receive_terminal_recovery(projected, committed),
            ReceiveTerminalDecision::CursorCatchUp
        ))
    }
    fn reject_legacy_peer(
        &self,
        conversation: &str,
        entry: &GatewayInboxEntry,
        target: &str,
        session: &ramflux_crypto::DmSession,
    ) -> Result<bool, SdkError> {
        if let Some(reason) = self.friend_rejection_reason(&entry.envelope.source_principal_id)? {
            self.account_db()?.reject_inbox_message(
                conversation,
                &entry.envelope.envelope_id,
                &entry.envelope.source_principal_id,
                &reason,
                now_unix_timestamp(),
            )?;
            // Rejection recorded: commit the advanced recv ratchet, then the cursor.
            self.commit_legacy_receive(conversation, entry, target, session)?;
            return Ok(true);
        }
        Ok(false)
    }
    fn quarantine_legacy_control(
        &self,
        entry: &GatewayInboxEntry,
        conversation: &str,
        target: &str,
        session: &ramflux_crypto::DmSession,
    ) -> Result<(), SdkError> {
        let key = self.legacy_committed_key(entry)?;
        let db = self.account_db()?;
        db.write_transaction(|| {
            db.dead_letter_inbox(&key,&serde_json::to_vec(entry)?,&serde_json::json!({"envelope_id":entry.envelope.envelope_id,"error_code":"legacy_control_rejected"}),now_unix_timestamp())?;
            self.commit_legacy_receive(conversation,entry,target,session)?;
            db.remove_unrouted(&key)?;
            db.remove_unrouted(&entry.envelope.envelope_id)?;
            Ok::<_,SdkError>(())
        })
    }
    fn commit_legacy_receive(
        &self,
        conversation: &str,
        entry: &GatewayInboxEntry,
        target: &str,
        session: &ramflux_crypto::DmSession,
    ) -> Result<(), SdkError> {
        self.account_db()?.write_transaction(|| -> Result<(), SdkError> {
            self.persist_dm_session(conversation, &entry.envelope.envelope_id, "recv", session)?;
            self.persist_legacy_committed(entry, conversation)?;
            self.persist_gateway_receive_cursor(target, entry.inbox_seq)
        })
    }

    async fn import_legacy_attachments(
        &mut self,
        engine: &mut GatewaySessionEngine,
        pool: &ramflux_transport::RelayQuicPool,
        attachment_refs: &[SdkDmAttachmentRef],
        auto_fetch_attachments: bool,
        relay_service_key_base64: Option<String>,
    ) -> Result<Vec<SdkDmAttachmentImportResult>, SdkError> {
        let mut attachments = Vec::new();
        if auto_fetch_attachments {
            for attachment in attachment_refs {
                attachments.push(
                    self.import_dm_attachment_from_relay_via_gateway(
                        engine,
                        pool,
                        attachment,
                        relay_service_key_base64.clone(),
                    )
                    .await?,
                );
            }
        }
        Ok(attachments)
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
    pub(crate) fn plaintext_projection_delivery(
        &self,
        conversation_id: &str,
        entry: &GatewayInboxEntry,
    ) -> Result<Option<GatewayPlaintextDelivery>, SdkError> {
        let route = self.committed_routing(entry)?;
        let message_id =
            route.as_ref().map_or(&entry.envelope.envelope_id, |route| &route.message_id);
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

    /// Acknowledge one exact delivery under the account's authenticated device identity.
    /// # Errors
    /// Rejects a foreign mailbox/engine identity, or a failed ACK/cursor commit.
    pub async fn ack_gateway_entry(
        &self,
        engine: &mut GatewaySessionEngine,
        entry: &GatewayInboxEntry,
        received_at: i64,
    ) -> Result<GatewayCursor, SdkError> {
        let receiver = self.owned_device_identity()?;
        if engine.config.source_identity.as_ref() != Some(&receiver)
            || entry.target_delivery_id != engine.target_delivery_id()
        {
            return Err(SdkError::InboundRejected("ACK mailbox identity mismatch".into()));
        }
        let mut ack = gateway_ack(&entry.envelope.envelope_id, &receiver, received_at);
        ack.ext.ext.insert("inbox_seq".into(), serde_json::json!(entry.inbox_seq));
        let cursor = engine.ack(ack).await?;
        self.persist_gateway_cursor(&cursor.target_delivery_id, cursor.inbox_seq)?;
        Ok(cursor)
    }

    /// # Errors
    /// Returns an error when the gateway ack fails or the durable cursor cannot be persisted.
    pub async fn ack_gateway_delivery(
        &self,
        engine: &mut GatewaySessionEngine,
        envelope_id: &str,
        receiver: &ramflux_crypto::RootQualifiedDeviceRef,
        received_at: i64,
    ) -> Result<GatewayCursor, SdkError> {
        if self.owned_device_identity()? != *receiver
            || engine.config.source_identity.as_ref() != Some(receiver)
        {
            return Err(SdkError::InboundRejected("ACK receiver context mismatch".into()));
        }
        let ack = gateway_ack(envelope_id, receiver, received_at);
        let cursor = engine.ack(ack).await?;
        self.persist_gateway_cursor(&cursor.target_delivery_id, cursor.inbox_seq)?;
        Ok(cursor)
    }

    /// # Errors
    pub(crate) fn append_plaintext_projection_once(
        &self,
        conversation_id: &str,
        message_id: &str,
        entry: &GatewayInboxEntry,
        plaintext: &[u8],
        metadata: Option<&MessageMetadata>,
    ) -> Result<(), SdkError> {
        self.account_db()?.write_transaction(|| {
            self.account_db()?.store_message_content(conversation_id, message_id, plaintext)?;
            if self
                .direct_messages(conversation_id)?
                .iter()
                .any(|message| message.message_id == message_id)
            {
                self.stage_delivery_receipt(conversation_id, message_id, entry)?;
                return Ok(());
            }
            // A held message may be accepted days later; reception/consent must not rewrite
            // its authenticated send time in the ordinary conversation projection.
            self.account_db()?.send_direct_message_at_with_metadata(
                ramflux_storage::DirectMessageWrite {
                    conversation_id,
                    message_id,
                    sender_id: &entry.envelope.source_principal_id,
                    encrypted_body: plaintext,
                    metadata: &metadata.cloned().unwrap_or_default(),
                    created_at: entry.envelope.created_at,
                },
            )?;
            self.stage_delivery_receipt(conversation_id, message_id, entry)?;
            Ok(())
        })
    }

    pub(crate) fn apply_receipt_event_plaintext(
        &self,
        body: &[u8],
        source: &ramflux_crypto::RootQualifiedDeviceRef,
        authenticated_conversation: &str,
    ) -> Result<Option<SdkReceiptEventEnvelope>, SdkError> {
        let Ok(mut envelope) = serde_json::from_slice::<SdkReceiptEventEnvelope>(body) else {
            return Ok(None);
        };
        if envelope.schema != "ramflux.sdk.receipt_event.v1" {
            return Ok(None);
        }
        let raw_device = source.device_id();
        let conversation = match &envelope.event {
            SdkReceiptEventBody::Delivered { conversation_id, .. }
            | SdkReceiptEventBody::ReadPrivate { conversation_id, .. }
            | SdkReceiptEventBody::ReadPublic { conversation_id, .. } => conversation_id,
        };
        if conversation != authenticated_conversation {
            return Err(SdkError::InboundRejected(
                "receipt conversation differs from authenticated route".into(),
            ));
        }
        if envelope.reader_device_id != raw_device {
            return Err(SdkError::LocalBus(format!(
                "receipt reader_device_id mismatch: claimed {}, authenticated {}",
                envelope.reader_device_id, raw_device
            )));
        }
        if let SdkReceiptEventBody::Delivered { message_id, .. } = &mut envelope.event {
            *message_id = self.resolve_delivery_receipt_message(
                source,
                authenticated_conversation,
                message_id,
            )?;
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
                if receiver_device_id != raw_device {
                    return Err(SdkError::LocalBus(format!(
                        "receipt receiver_device_id mismatch: claimed {receiver_device_id}, authenticated {raw_device}"
                    )));
                }
                let inserted = self.account_db()?.record_receipt_event_once(ReceiptEventWrite {
                    receipt_id: &envelope.receipt_id,
                    conversation_id,
                    message_id,
                    receipt_type: "delivered",
                    actor: source,
                    created_at: *delivered_at,
                })?;
                if inserted {
                    self.mark_delivered(
                        conversation_id,
                        source,
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
                if reader_identity != raw_device {
                    return Err(SdkError::LocalBus(format!(
                        "receipt reader identity mismatch: claimed {reader_identity}, authenticated {raw_device}"
                    )));
                }
                let inserted = self.account_db()?.record_receipt_event_once(ReceiptEventWrite {
                    receipt_id: &envelope.receipt_id,
                    conversation_id,
                    message_id,
                    receipt_type: "read",
                    actor: source,
                    created_at: *read_at,
                })?;
                if inserted {
                    self.mark_read(conversation_id, source, message_id)?;
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

pub(crate) fn franking_report_metadata_for_delivery(
    conversation_id: &str,
    entry: &GatewayInboxEntry,
    envelope: &SdkDmEncryptedEnvelope,
    decrypted: &ramflux_crypto::DmDecryptionOutput,
    aad_override: Option<&[u8]>,
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
    let aad = aad_override.unwrap_or_else(|| dm_associated_data(conversation_id));
    let commitment =
        ramflux_crypto::franking_commitment(&ramflux_crypto::FrankingCommitmentInput {
            plaintext: &decrypted.plaintext,
            sender_device_id_hash: &envelope.ciphertext.sender_device_id_hash,
            message_event_id: &envelope.ciphertext.message_event_id,
            canonical_header_bytes: &envelope.ciphertext.canonical_header_bytes,
            associated_data: aad,
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
            associated_data: ramflux_protocol::encode_base64url(aad),
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

pub(crate) fn decode_dm_attachment_body(
    body: &[u8],
) -> Result<(Vec<u8>, Vec<SdkDmAttachmentRef>), SdkError> {
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

    // ---- T24-B1a: client DB crash-resume invariants (evidence-first) ----

    fn reopen_client(root: &std::path::Path) -> Result<RamfluxClient, SdkError> {
        let mut client = RamfluxClient::new();
        client.open_account_index(root)?;
        client.unlock_account("acct", b"test-secret")?;
        Ok(client)
    }

    fn seed_session(tag: u8) -> Result<ramflux_crypto::DmSession, SdkError> {
        Ok(ramflux_crypto::DmSession::initiator([tag; 32], [2; 32], [3; 32], [4; 32])?)
    }

    // B1b conflict proof: replaying the same deterministic event id with a DIFFERENT ratchet
    // snapshot must fail closed and preserve the original event. Byte-identical replay is covered
    // by the storage-level idempotency regression.
    #[test]
    fn dm_session_reappend_with_changed_snapshot_is_rejected_fail_closed() -> Result<(), SdkError> {
        let (root, client) = test_client("b1a-event-replay")?;
        let first = seed_session(1)?;
        client.persist_dm_session("conv_x", "env_1", "recv", &first)?;
        assert!(client.recv_session_checkpoint_at("conv_x", "env_1")?);

        // Resume re-persists the same coordinates (a different in-memory session value, same id).
        let replay = seed_session(9)?;
        let redo = client.persist_dm_session("conv_x", "env_1", "recv", &replay);
        assert!(
            matches!(
                redo,
                Err(SdkError::Storage(ramflux_storage::StorageError::EventIdConflict(ref event_id)))
                    if event_id == &dm_session_event_id("conv_x", "recv", "env_1")
            ),
            "same event id with a changed snapshot must fail closed; got {redo:?}"
        );

        // The originally-committed row must be unchanged (checkpoint still points at env_1).
        assert!(client.recv_session_checkpoint_at("conv_x", "env_1")?);

        let _ = std::fs::remove_dir_all(root);
        Ok(())
    }

    // B1a DM-reopen proof: a persisted recv session snapshot + gateway receive cursor survive a
    // full client drop/reopen keyed by the same account secret, and the recovery decision honors
    // the recv-session checkpoint (not projection presence).
    #[test]
    fn dm_recv_session_and_cursor_survive_client_reopen() -> Result<(), SdkError> {
        let (root, client) = test_client("b1a-dm-reopen")?;
        let mut session = seed_session(1)?;
        // advance the receive ratchet a few steps so a non-zero counter must round-trip
        session.receive_counter = 7;
        client.persist_dm_session("conv_r", "env_r", "recv", &session)?;
        client.persist_gateway_receive_cursor("target_r", 42)?;
        drop(client);

        let restored = reopen_client(&root)?;
        let loaded = restored.load_dm_session("conv_r", "recv")?;
        assert_eq!(loaded.receive_counter, 7, "recv ratchet counter must persist across reopen");
        assert_eq!(loaded.session_id, session.session_id, "session identity must persist");
        assert_eq!(
            restored.gateway_receive_cursor("target_r")?,
            42,
            "gateway receive cursor must persist across reopen"
        );

        // Recovery-decision boundary against the durable checkpoint.
        assert!(restored.recv_session_checkpoint_at("conv_r", "env_r")?);
        assert!(!restored.recv_session_checkpoint_at("conv_r", "env_other")?);
        assert_eq!(
            crate::dm::receive_terminal_recovery(true, true),
            crate::dm::ReceiveTerminalDecision::CursorCatchUp
        );
        assert_eq!(
            crate::dm::receive_terminal_recovery(true, false),
            crate::dm::ReceiveTerminalDecision::Decrypt,
            "projection present but checkpoint not current must still re-decrypt"
        );

        let _ = std::fs::remove_dir_all(root);
        Ok(())
    }

    // B1a send-window mechanism: a client reopen reloads the PERSISTED send counter, not an
    // in-flight advance that was never persisted. Production send paths now persist the advance
    // before remote submit; this test keeps the underlying crash invariant pinned.
    #[test]
    fn send_session_reopen_reloads_persisted_counter_not_inflight_advance() -> Result<(), SdkError>
    {
        let (root, client) = test_client("b1a-send-window")?;
        let mut session = seed_session(1)?;
        let _ = session.encrypt(b"m0", b"ad")?; // send_counter 0 -> 1
        let persisted_counter = session.send_counter;
        client.persist_dm_session("conv_s", "env_s0", "send", &session)?;
        // "submitted but not persisted" next message advances the in-memory counter only.
        let _ = session.encrypt(b"m1", b"ad")?; // -> 2, never persisted
        assert_eq!(session.send_counter, persisted_counter + 1);
        drop(client);

        let restored = reopen_client(&root)?;
        let reloaded = restored.load_dm_session("conv_s", "send")?;
        assert_eq!(
            reloaded.send_counter, persisted_counter,
            "reopen must reload the persisted counter, not the un-persisted in-flight advance"
        );

        let _ = std::fs::remove_dir_all(root);
        Ok(())
    }

    // B1a send-window mechanism (crypto layer): encryption at a given counter is deterministic
    // — the nonce is counter-derived, not fresh-random. Therefore reloading an old counter (part 1)
    // and re-encrypting a DIFFERENT plaintext reuses the SAME nonce, an AEAD key/nonce-reuse hazard.
    // This is the mechanism; the production send path cannot be driven end-to-end without a live
    // gateway (see report §Stop / B1b seam recommendation).
    #[test]
    fn dm_encrypt_at_reloaded_counter_reuses_nonce_across_different_plaintext()
    -> Result<(), SdkError> {
        let (root, client) = test_client("b1a-nonce-reuse")?;
        let session = seed_session(1)?; // send_counter 0
        client.persist_dm_session("conv_n", "env_n0", "send", &session)?;
        drop(client);

        // Two independent reloads of the SAME persisted counter re-encrypt different plaintexts.
        let restored = reopen_client(&root)?;
        let mut a = restored.load_dm_session("conv_n", "send")?;
        let mut b = restored.load_dm_session("conv_n", "send")?;
        assert_eq!(a.send_counter, b.send_counter, "both reloads start at the same counter");
        let ca = a.encrypt(b"first-plaintext", b"ad")?;
        let cb = b.encrypt(b"second-DIFFERENT-plaintext", b"ad")?;

        assert_eq!(ca.counter, cb.counter, "both encrypt at the reloaded counter");
        assert_eq!(
            ca.nonce, cb.nonce,
            "nonce is counter-derived, so an unpersisted/reloaded counter would reuse \
             the nonce across different plaintext (AEAD catastrophe)"
        );
        assert_ne!(ca.ciphertext, cb.ciphertext, "different plaintext under the reused nonce");

        let _ = std::fs::remove_dir_all(root);
        Ok(())
    }
}
