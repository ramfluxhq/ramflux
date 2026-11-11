// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Transient pair encryption. Only ratchet metadata persists; Typing never enters W0/W1 or history.
use super::{RamfluxClient, GatewaySessionAccess, GatewayDirectMessage, SdkError, invalid,
    report, associated_data_bound, CandidateAadBinding, SealedRouted, SdkDmEncryptedEnvelope,
    GatewayInboxEntry, HeadUse, refuse_received_outer_fields, decode, Kind, associated_data_from_outer, Routing};
use crate::GatewayServerFrame;
use ramflux_protocol::message as g;

impl RamfluxClient {
    /// Seal generated Typing on the S6c ephemeral channel, without durable send/retry state.
    /// # Errors
    /// Refuses unsupported capability, lifetime, source authority, size and crypto failures.
    pub async fn prepare_typing_delivery(
        &self,
        engine: &mut impl GatewaySessionAccess,
        message: &GatewayDirectMessage,
        active: bool,
    ) -> Result<ramflux_protocol::Envelope, SdkError> {
        use ramflux_protocol::ephemeral::GATEWAY_EPHEMERAL_CAPABILITY;
        if !crate::client::target_selection::schema_v1_selected()
            || !engine.config().capability_scope.iter().any(|scope| scope == GATEWAY_EPHEMERAL_CAPABILITY)
            || !(1..=5).contains(&message.ttl)
        {
            return Err(SdkError::InboundRejected("typing requires negotiated ephemeral mode and TTL 1..5".into()));
        }
        let source = self.owned_device_identity()?;
        let recipient = Self::qualified_recipient(message)?;
        let remote = self.device_identity(&recipient)?;
        if remote.root_commitment() != source.root_commitment()
            && !self.friend_link_peer_is_accepted(remote.root_commitment())?
        { return Err(SdkError::InboundRejected("typing recipient requires accepted root consent".into())); }
        let expires = message.created_at.checked_add(i64::from(message.ttl))
            .and_then(|at| u64::try_from(at).ok()).ok_or_else(|| invalid("typing deadline overflow"))?;
        let inner = self.encode_typing_inner(message, &source, active, expires)?;
        let (mut session, header, bundle) = self.send_pair_session(engine, message).await?;
        let bootstrap = header.is_some();
        let report = report::assemble_report_with_policy(self, message, &session, &inner, &remote,
            &report::ReportPolicy { local_device_id: &engine.config().device_id, mode: "ephemeral", priority: ramflux_protocol::Priority::Low })?;
        let aad = associated_data_bound(&message.envelope_id, &engine.config().device_id,
            remote.device_id(), &bundle, CandidateAadBinding {
                delivery_mode: "ephemeral", collapse_tag: report.collapse_tag,
                report_commitment: Some(report.report_commitment),
            })?;
        let ciphertext = session.encrypt(report.framed.as_bytes(), &aad)?;
        let sealed = SealedRouted { packet: SdkDmEncryptedEnvelope {
            source_principal_commitment: Some(source.root_commitment().into()),
            schema: "ramflux.sdk.dm_x3dh_envelope.v2".into(), version: 2, x3dh: header,
            ciphertext, collapse_tag: Some(ramflux_protocol::encode_base64url(report.collapse_tag)),
            report_commitment: Some(ramflux_protocol::encode_base64url(report.report_commitment)),
        }, committed_a0: Some(report.a0_bytes) };
        let mut message = message.clone();
        let envelope = crate::dm::gateway_ephemeral_envelope_from_sealed(engine.config(), &mut message, sealed)?;
        let frame = GatewayServerFrame::Ephemeral { envelope: envelope.clone(), expires_at_ms: expires.checked_mul(1000).ok_or_else(|| invalid("typing deadline overflow"))? };
        if ramflux_protocol::canonical_json_bytes(&frame)?.len() > 32_768 {
            return Err(invalid("typing exceeds ephemeral frame cap"));
        }
        self.account_db()?.write_transaction(|| {
            if bootstrap {
                self.account_db()?.persist_actor_state(&format!("dm-pair/local/{}", session.session_id), &true)?;
            }
            self.persist_pair(&source, &remote, &bundle, &session)
        })?;
        self.finish_pair_retirement()?;
        Ok(envelope)
    }

    fn encode_typing_inner(
        &self,
        message: &GatewayDirectMessage,
        source: &ramflux_crypto::RootQualifiedDeviceRef,
        active: bool,
        expires_at: u64,
    ) -> Result<Vec<u8>, SdkError> {
        let identity = g::EventIdentity {
            id: ramflux_crypto::random_32()?.to_vec(), conversation_id: message.conversation_id.clone(),
            author: Some(g::QualifiedDevice {
                account_anchor: source.root_commitment().into(), device_id: source.device_id().into(),
                device_epoch: self.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?.device_epoch,
            }), ..Default::default()
        };
        Self::encode_generated_inner(identity, &g::Content {
            value: Some(g::content::Value::Typing(g::Typing { active, expires_at })),
        })
    }

    pub(crate) fn open_typing_delivery(
        &self,
        envelope: &ramflux_protocol::Envelope,
        local: &str,
    ) -> Result<(g::EventIdentity, g::Typing), SdkError> {
        let entry = GatewayInboxEntry { forwarded: false, inbox_seq: 0,
            target_delivery_id: envelope.target_delivery_id.clone(), envelope: envelope.clone() };
        self.authenticated_envelope_sender(HeadUse::NewAuthorization, &entry)?;
        refuse_received_outer_fields(envelope)?;
        let packet = decode(envelope)?;
        report::refuse_payload_outer_mismatch(envelope, &packet)?;
        let local_device = self.local_device_identity(local)?;
        let remote = self.authenticated_device_identity(HeadUse::NewAuthorization, &entry)?;
        let (mut session, bundle) = self.recv_pair_session(&local_device, &remote, &envelope.envelope_id, &packet)?;
        report::refuse_direct_candidate_opening(envelope, &session, &Kind::Direct)?;
        let aad = associated_data_from_outer(envelope, &envelope.source_device_id, local, &bundle)?;
        let decrypted = zeroize::Zeroizing::new(session.decrypt_with_franking_keys(&packet.ciphertext, &aad)?);
        let inner = report::opened_inner_plaintext(envelope, &decrypted.plaintext)?;
        let (identity, content) = Self::decode_generated_inner(&inner)?;
        if identity.author.as_ref().is_none_or(|author| {
            author.account_anchor != remote.root_commitment() || author.device_id != remote.device_id()
        }) || identity.conversation_id.is_empty()
            || !self.accepted_contact_source(remote.root_commitment(), &envelope.source_principal_id)?
        { return Err(SdkError::InboundRejected("typing source is not authorized".into())); }
        let route = Routing { kind: Kind::Direct, conversation_id: identity.conversation_id.clone(),
            group_id: None, message_id: envelope.envelope_id.clone(), group_message_id: None, attachments: false };
        self.confirm_routed_context(&route, &entry)?;
        let Some(g::content::Value::Typing(typing)) = content.value else {
            return Err(SdkError::InboundRejected("ephemeral content is not known Typing".into()));
        };
        let deadline = envelope.created_at.checked_add(i64::from(envelope.ttl))
            .and_then(|at| u64::try_from(at).ok()).ok_or_else(|| invalid("typing deadline overflow"))?;
        if typing.expires_at > deadline || typing.expires_at < u64::try_from(envelope.created_at).map_err(|_| invalid("typing start before epoch"))? {
            return Err(SdkError::InboundRejected("typing interval exceeds signed lifetime".into()));
        }
        self.account_db()?.write_transaction(|| {
            self.commit_bootstrap_sequence(&local_device, &remote, packet.x3dh.as_ref(), &session.session_id)?;
            self.persist_pair(&local_device, &remote, &bundle, &session)
        })?;
        self.finish_pair_retirement()?;
        Ok((identity, typing))
    }
}
