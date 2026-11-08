// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Legacy receive preserves terminal checkpoints while carrying attachment admission.
use super::*;

pub(crate) struct LegacyDmMessage {
    pub projection_body: Vec<u8>,
    pub metadata: Option<MessageMetadata>,
    pub import_refs: Vec<SdkDmAttachmentRef>,
}

pub(crate) enum LegacyDmPrepared {
    Finished,
    Message(Box<LegacyDmMessage>),
}

pub(crate) struct LegacyDmDecrypt<'a> {
    pub conversation: &'a str,
    pub entry: &'a GatewayInboxEntry,
    pub target: &'a str,
    pub session: &'a ramflux_crypto::DmSession,
    pub envelope: &'a SdkDmEncryptedEnvelope,
    pub decrypted: &'a ramflux_crypto::DmDecryptionOutput,
    pub consume_erased: bool,
    pub persist_cursor: bool,
}

impl RamfluxClient {
    pub(crate) async fn receive_legacy_entry(
        &mut self,
        engine: &mut impl GatewaySessionAccess,
        pool: &ramflux_transport::RelayQuicPool,
        entry: GatewayInboxEntry,
        options: LegacyReceive<'_>,
    ) -> Result<Option<GatewayPlaintextDelivery>, SdkError> {
        self.receive_legacy_entry_mode(engine, pool, entry, options, true).await
    }

    #[cfg_attr(not(test), expect(dead_code, reason = "compatibility registration entrypoint"))]
    pub(in crate::client) fn prepare_legacy_attachment_imports(
        &self,
        refs: &[SdkDmAttachmentRef],
        sender: &str,
        conversation: &str,
        message: &str,
    ) -> Result<(), SdkError> {
        self.prepare_legacy_attachment_imports_mode(refs, sender, conversation, message, false)
            .map(|_| ())
    }

    async fn receive_legacy_entry_mode(
        &mut self,
        engine: &mut impl GatewaySessionAccess,
        pool: &ramflux_transport::RelayQuicPool,
        entry: GatewayInboxEntry,
        options: LegacyReceive<'_>,
        consume_erased: bool,
    ) -> Result<Option<GatewayPlaintextDelivery>, SdkError> {
        self.authorize_bound_legacy(engine.config(), &entry, options.conversation_id).await?;

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
        // T21-A2a: the advanced recv session (ratchet) is NOT persisted here. It is committed
        // only once this inbox entry reaches its success terminal state, immediately before the
        // receive cursor advances. If any downstream step fails, the local `session` is dropped
        // so the persisted ratchet snapshot and cursor stay unchanged and the same ciphertext
        // can be re-decrypted on a later `dm read`.
        let prepared = self.prepare_legacy_dm_after_decrypt(&LegacyDmDecrypt {
            conversation: conversation_id,
            entry: &entry,
            target: engine.target_delivery_id(),
            session: &session,
            envelope: &envelope,
            decrypted: &decrypted,
            consume_erased,
            persist_cursor: true,
        })?;
        let LegacyDmPrepared::Message(prepared) = prepared else {
            return Ok(None);
        };
        let LegacyDmMessage { projection_body, metadata, import_refs } = *prepared;
        let attachments = self
            .import_legacy_attachments(engine, pool, &import_refs, options, consume_erased)
            .await?;
        self.persist_legacy_dm_projection(
            conversation_id,
            &entry,
            &projection_body,
            metadata.as_ref(),
            &engine.config().principal_id,
        )?;
        // Attachment processing reached success: only now do we commit the
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

    pub(crate) fn prepare_legacy_dm_after_decrypt(
        &self,
        input: &LegacyDmDecrypt<'_>,
    ) -> Result<LegacyDmPrepared, SdkError> {
        let body = &input.decrypted.plaintext;
        if self.reject_legacy_control(input)? {
            return Ok(LegacyDmPrepared::Finished);
        }
        if self
            .apply_receipt_event_plaintext(
                body,
                &self.authenticated_device_identity(HeadUse::NewAuthorization, input.entry)?,
                input.conversation,
            )?
            .is_some()
        {
            self.commit_legacy_terminal(
                input.conversation,
                input.entry,
                input.target,
                input.session,
                input.persist_cursor,
            )?;
            return Ok(LegacyDmPrepared::Finished);
        }
        if self.reject_legacy_peer(
            input.conversation,
            input.entry,
            input.target,
            input.session,
            input.persist_cursor,
        )? {
            return Ok(LegacyDmPrepared::Finished);
        }
        let (projection_body, attachment_refs) = decode_dm_attachment_body(body)?;
        let metadata = franking_report_metadata_for_delivery(
            input.conversation,
            input.entry,
            input.envelope,
            input.decrypted,
            None,
        )?;
        let admitted = self.prepare_legacy_attachment_imports_mode(
            &attachment_refs,
            &input.entry.envelope.source_principal_id,
            input.conversation,
            &input.entry.envelope.envelope_id,
            input.consume_erased,
        )?;
        Ok(LegacyDmPrepared::Message(Box::new(LegacyDmMessage {
            projection_body,
            metadata,
            import_refs: if input.consume_erased { admitted } else { attachment_refs },
        })))
    }

    pub(crate) fn persist_legacy_dm_projection(
        &self,
        conversation: &str,
        entry: &GatewayInboxEntry,
        projection_body: &[u8],
        metadata: Option<&MessageMetadata>,
        principal_id: &str,
    ) -> Result<(), SdkError> {
        self.append_plaintext_projection_once(
            conversation,
            &entry.envelope.envelope_id,
            entry,
            projection_body,
            metadata,
        )?;
        if self.account_db()?.client_record("conversation", conversation)?.is_none() {
            self.account_db()?.persist_client_record(
                "conversation",
                conversation,
                &serde_json::json!({
                    "kind": "direct",
                    "title": null,
                    "group_id": null,
                    "participants": [principal_id, entry.envelope.source_principal_id],
                    "direct_route": null
                }),
            )?;
        }
        Ok(())
    }

    fn reject_legacy_control(&self, input: &LegacyDmDecrypt<'_>) -> Result<bool, SdkError> {
        match self.project_legacy_contact_control(input.entry, &input.decrypted.plaintext) {
            Ok(()) => Ok(false),
            Err(SdkError::InboundRejected(_)) => {
                self.quarantine_legacy_control(
                    input.entry,
                    input.conversation,
                    input.target,
                    input.session,
                    input.persist_cursor,
                )?;
                Ok(true)
            }
            Err(error) => Err(error),
        }
    }

    fn prepare_legacy_attachment_imports_mode(
        &self,
        attachment_refs: &[SdkDmAttachmentRef],
        sender: &str,
        conversation_id: &str,
        message_id: &str,
        consume_erased: bool,
    ) -> Result<Vec<SdkDmAttachmentRef>, SdkError> {
        let mut admitted = Vec::new();
        for attachment in attachment_refs {
            let result = self.persist_received_attachment_reference(
                attachment,
                sender,
                conversation_id,
                message_id,
            );
            #[cfg(test)]
            super::super::routed::observe_legacy_registration(&result);
            match result {
                Ok(()) => admitted.push(attachment.clone()),
                Err(SdkError::ObjectErased) if consume_erased => {}
                Err(error) => return Err(error),
            }
        }
        Ok(admitted)
    }

    async fn import_legacy_attachments(
        &mut self,
        engine: &mut impl GatewaySessionAccess,
        pool: &ramflux_transport::RelayQuicPool,
        attachment_refs: &[SdkDmAttachmentRef],
        options: LegacyReceive<'_>,
        consume_erased: bool,
    ) -> Result<Vec<SdkDmAttachmentImportResult>, SdkError> {
        let mut attachments = Vec::new();
        if options.auto_fetch_attachments {
            for attachment in attachment_refs {
                #[cfg(test)]
                crate::client::routed::observe_legacy_import(self, attachment)?;
                match self
                    .import_dm_attachment_from_relay_via_gateway(
                        engine,
                        pool,
                        attachment,
                        options.relay_service_key_base64.clone(),
                    )
                    .await
                {
                    Ok(imported) => attachments.push(imported),
                    Err(SdkError::ObjectErased) if consume_erased => {}
                    Err(error) => return Err(error),
                }
            }
        }
        Ok(attachments)
    }
}
