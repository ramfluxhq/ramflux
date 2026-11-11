// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Transient pair encryption. Only ratchet metadata persists; Typing never enters W0/W1 or history.
use super::{
    CandidateAadBinding, GatewayDirectMessage, GatewayInboxEntry, GatewaySessionAccess, HeadUse,
    Kind, RamfluxClient, Routing, SdkDmEncryptedEnvelope, SdkError, SealedRouted,
    associated_data_bound, associated_data_from_outer, decode, invalid,
    refuse_received_outer_fields, report,
};
use crate::GatewayServerFrame;
use crate::bindings::{AdapterError, GeneratedErrorCode};
use ramflux_protocol::message as g;

impl RamfluxClient {
    /// Seal generated Typing on the S6c ephemeral channel, without durable send/retry state.
    /// # Errors
    /// Refuses unsupported capability, lifetime, source authority, size and crypto failures.
    pub fn prepare_typing_delivery(
        &self,
        engine: &mut impl GatewaySessionAccess,
        message: &GatewayDirectMessage,
        active: bool,
    ) -> Result<ramflux_protocol::Envelope, SdkError> {
        let (source, remote) = self.typing_sender_target(engine, message, active)?;
        let expires = message
            .created_at
            .checked_add(i64::from(message.ttl))
            .and_then(|at| u64::try_from(at).ok())
            .ok_or_else(|| invalid("typing deadline overflow"))?;
        let inner = self.encode_typing_inner(message, &source, active, expires)?;
        let (mut session, header, bundle) = self
            .sendable_pair(&source, &remote)?
            .ok_or_else(|| typing_unavailable("typing requires an established pair session"))?;
        if header.is_some()
            || !self
                .account_db()?
                .load_actor_state::<bool>(&format!("dm-pair/confirmed/{}", session.session_id))?
                .unwrap_or(false)
        {
            return Err(typing_unavailable("typing cannot bootstrap or confirm a pair session"));
        }
        let seals_key = format!("dm-pair/ephemeral-seals/{}", session.session_id);
        if self.account_db()?.load_actor_state::<u16>(&seals_key)?.unwrap_or(0) >= 256 {
            return Err(typing_unavailable("typing pair session seal budget exhausted"));
        }
        let report = report::assemble_report_with_policy(
            self,
            message,
            &session,
            &inner,
            &remote,
            &report::ReportPolicy {
                local_device_id: &engine.config().device_id,
                mode: "ephemeral",
                priority: ramflux_protocol::Priority::Low,
            },
        )?;
        let aad = associated_data_bound(
            &message.envelope_id,
            &engine.config().device_id,
            remote.device_id(),
            &bundle,
            CandidateAadBinding {
                delivery_mode: "ephemeral",
                collapse_tag: report.collapse_tag,
                report_commitment: Some(report.report_commitment),
            },
        )?;
        let ciphertext = session.encrypt(report.framed.as_bytes(), &aad)?;
        let sealed = SealedRouted {
            packet: SdkDmEncryptedEnvelope {
                source_principal_commitment: Some(source.root_commitment().into()),
                schema: "ramflux.sdk.dm_x3dh_envelope.v2".into(),
                version: 2,
                x3dh: header,
                ciphertext,
                collapse_tag: Some(ramflux_protocol::encode_base64url(report.collapse_tag)),
                report_commitment: Some(ramflux_protocol::encode_base64url(
                    report.report_commitment,
                )),
            },
            committed_a0: Some(report.a0_bytes),
            metadata_commitment: None,
        };
        let mut message = message.clone();
        let envelope = crate::dm::gateway_ephemeral_envelope_from_sealed(
            engine.config(),
            &mut message,
            sealed,
        )?;
        Self::check_typing_frame(&envelope, expires)?;
        self.account_db()?.write_transaction(|| {
            let count = self.account_db()?.load_actor_state::<u16>(&seals_key)?.unwrap_or(0);
            if count >= 256 {
                return Err(typing_unavailable("typing pair session seal budget exhausted"));
            }
            self.account_db()?.persist_actor_state(&seals_key, &(count + 1))?;
            self.persist_pair(&source, &remote, &bundle, &session)
        })?;
        self.finish_pair_retirement()?;
        Ok(envelope)
    }

    fn typing_sender_target(
        &self,
        engine: &impl GatewaySessionAccess,
        message: &GatewayDirectMessage,
        active: bool,
    ) -> Result<
        (ramflux_crypto::RootQualifiedDeviceRef, ramflux_crypto::RootQualifiedDeviceRef),
        SdkError,
    > {
        use ramflux_protocol::ephemeral::GATEWAY_EPHEMERAL_CAPABILITY;
        if !crate::client::target_selection::schema_v1_selected() {
            return Err(AdapterError::new(
                GeneratedErrorCode::PeerUpgradeRequired,
                "typing requires schema generation 1",
            )
            .into());
        }
        if !engine
            .config()
            .capability_scope
            .iter()
            .any(|scope| scope == GATEWAY_EPHEMERAL_CAPABILITY)
        {
            return Err(typing_unavailable("typing requires negotiated ephemeral mode"));
        }
        if message.ttl != if active { 5 } else { 1 } {
            return Err(AdapterError::new(
                GeneratedErrorCode::InvalidArgument,
                "typing TTL must be 5 (active) or 1 (clear)",
            )
            .into());
        }
        let source = self.owned_device_identity()?;
        let recipient = Self::qualified_recipient(message)?;
        let remote = self.device_identity(&recipient).map_err(|error| match error {
            SdkError::InboundPending(_) => {
                typing_unavailable("typing requires cached recipient authority")
            }
            other => other,
        })?;
        if remote.root_commitment() == source.root_commitment()
            || !self.friend_link_peer_is_accepted(remote.root_commitment())?
        {
            return Err(AdapterError::new(
                GeneratedErrorCode::NotAuthorized,
                "typing recipient requires accepted root consent",
            )
            .into());
        }
        Ok((source, remote))
    }

    fn check_typing_frame(
        envelope: &ramflux_protocol::Envelope,
        expires: u64,
    ) -> Result<(), SdkError> {
        let frame = GatewayServerFrame::Ephemeral {
            envelope: envelope.clone(),
            expires_at_ms: expires
                .checked_mul(1000)
                .ok_or_else(|| invalid("typing deadline overflow"))?,
        };
        if ramflux_protocol::canonical_json_bytes(&frame)?.len() > 32_768 {
            return Err(invalid("typing exceeds ephemeral frame cap"));
        }
        Ok(())
    }

    fn encode_typing_inner(
        &self,
        message: &GatewayDirectMessage,
        source: &ramflux_crypto::RootQualifiedDeviceRef,
        active: bool,
        expires_at: u64,
    ) -> Result<Vec<u8>, SdkError> {
        let identity = g::EventIdentity {
            id: ramflux_crypto::random_32()?.to_vec(),
            conversation_id: message.conversation_id.clone(),
            author: Some(g::QualifiedDevice {
                account_anchor: source.root_commitment().into(),
                device_id: source.device_id().into(),
                device_epoch: self
                    .device_branch
                    .as_ref()
                    .ok_or(SdkError::IdentityRootMissing)?
                    .device_epoch,
            }),
            ..Default::default()
        };
        Self::encode_generated_inner(
            identity,
            &g::Content {
                value: Some(g::content::Value::Typing(g::Typing { active, expires_at })),
            },
        )
    }

    pub(crate) fn typing_conversation_before_decrypt(
        &self,
        envelope: &ramflux_protocol::Envelope,
    ) -> Result<Option<String>, SdkError> {
        let packet = decode(envelope)?;
        if packet.x3dh.is_some() {
            return Ok(None);
        }
        let Some(tag) = envelope.collapse_tag.as_deref() else {
            return Ok(None);
        };
        Ok(self.account_db()?.load_actor_state(&format!(
            "dm-pair/collapse-scope/{}/{tag}",
            packet.ciphertext.session_id
        ))?)
    }

    pub(crate) fn open_typing_delivery(
        &self,
        envelope: &ramflux_protocol::Envelope,
        local: &str,
    ) -> Result<(g::EventIdentity, g::Typing), SdkError> {
        let entry = GatewayInboxEntry {
            forwarded: false,
            inbox_seq: 0,
            target_delivery_id: envelope.target_delivery_id.clone(),
            envelope: envelope.clone(),
        };
        self.authenticated_envelope_sender(HeadUse::NewAuthorization, &entry)?;
        refuse_received_outer_fields(envelope)?;
        let conversation = self
            .typing_conversation_before_decrypt(envelope)?
            .ok_or_else(|| invalid("typing requires an established conversation scope"))?;
        let packet = decode(envelope)?;
        report::refuse_payload_outer_mismatch(envelope, &packet)?;
        if packet.x3dh.is_some() {
            return Err(invalid("typing cannot bootstrap a receive session"));
        }
        let local_device = self.local_device_identity(local)?;
        let remote = self.authenticated_device_identity(HeadUse::NewAuthorization, &entry)?;
        if remote.root_commitment() == local_device.root_commitment() {
            return Err(invalid("typing cannot target own devices"));
        }
        let (mut session, bundle) =
            self.recv_pair_session(&local_device, &remote, &envelope.envelope_id, &packet)?;
        report::refuse_direct_candidate_opening(envelope, &session, &Kind::Direct)?;
        let aad = associated_data_from_outer(envelope, &envelope.source_device_id, local, &bundle)?;
        let decrypted =
            zeroize::Zeroizing::new(session.decrypt_with_franking_keys(&packet.ciphertext, &aad)?);
        let inner = report::opened_inner_plaintext(envelope, &decrypted.plaintext)?;
        let (identity, content) = Self::decode_generated_inner(&inner)?;
        if identity.author.as_ref().is_none_or(|author| {
            author.account_anchor != remote.root_commitment()
                || author.device_id != remote.device_id()
        }) || identity.conversation_id != conversation
            || identity.group_id.is_some()
            || identity.group_epoch.is_some()
            || identity.device_sequence != 0
            || identity.id.len() != 32
            || identity.conversation_id.is_empty()
            || !self
                .accepted_contact_source(remote.root_commitment(), &envelope.source_principal_id)?
        {
            return Err(SdkError::InboundRejected("typing source is not authorized".into()));
        }
        let route = Routing {
            kind: Kind::Direct,
            conversation_id: identity.conversation_id.clone(),
            group_id: None,
            message_id: envelope.envelope_id.clone(),
            group_message_id: None,
            attachments: false,
        };
        self.confirm_routed_context(&route, &entry)?;
        let Some(g::content::Value::Typing(typing)) = content.value else {
            return Err(SdkError::InboundRejected("ephemeral content is not known Typing".into()));
        };
        let deadline = envelope
            .created_at
            .checked_add(i64::from(envelope.ttl))
            .and_then(|at| u64::try_from(at).ok())
            .ok_or_else(|| invalid("typing deadline overflow"))?;
        if typing.expires_at != deadline || envelope.ttl != if typing.active { 5 } else { 1 } {
            return Err(SdkError::InboundRejected(
                "typing interval exceeds signed lifetime".into(),
            ));
        }
        self.account_db()?
            .write_transaction(|| self.persist_pair(&local_device, &remote, &bundle, &session))?;
        self.finish_pair_retirement()?;
        Ok((identity, typing))
    }
}

fn typing_unavailable(reason: &str) -> SdkError {
    AdapterError::new(GeneratedErrorCode::EphemeralUnavailable, reason).into()
}
