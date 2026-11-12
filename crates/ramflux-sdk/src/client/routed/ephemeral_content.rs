// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! S10a endpoint admission after the transport's authenticated ciphertext handoff.
use super::{
    GatewayInboxEntry, HeadUse, Kind, Opened, RamfluxClient, Routing, SdkError,
    associated_data_from_outer, decode, invalid, refuse_received_outer_fields, report,
};
use prost::Message as _;
use ramflux_protocol::message::{
    self as g,
    validation::{self, ScanOutcome},
};

pub(crate) enum EphemeralContent {
    Typing(g::EventIdentity, g::Typing),
    Unsupported,
    NonTyping,
}
impl RamfluxClient {
    pub(crate) fn open_ephemeral_delivery(
        &self,
        envelope: &ramflux_protocol::Envelope,
        local: &str,
    ) -> Result<EphemeralContent, SdkError> {
        let result = self.account_db()?.write_transaction(|| {
            let entry = GatewayInboxEntry {
                forwarded: false,
                inbox_seq: 0,
                target_delivery_id: envelope.target_delivery_id.clone(),
                envelope: envelope.clone(),
            };
            let opened = self.open_ephemeral_inner(&entry, local)?;
            let result = self.admit_ephemeral_inner(&opened, &entry)?;
            self.persist_pair(
                &opened.local_device,
                &opened.remote_device,
                &opened.bundle_hash,
                &opened.session,
            )?;
            Ok::<_, SdkError>(result)
        })?;
        Ok(result)
    }

    fn open_ephemeral_inner(
        &self,
        entry: &GatewayInboxEntry,
        local: &str,
    ) -> Result<Opened, SdkError> {
        let envelope = &entry.envelope;
        if envelope.delivery_mode.as_deref() != Some("ephemeral") {
            return Err(invalid("ephemeral endpoint requires ephemeral mode"));
        }
        self.authenticated_envelope_sender(HeadUse::NewAuthorization, entry)?;
        refuse_received_outer_fields(envelope)?;
        let conversation = self
            .typing_conversation_before_decrypt(envelope)?
            .ok_or_else(|| invalid("ephemeral input requires an established scope"))?;
        let packet = decode(envelope)?;
        report::refuse_payload_outer_mismatch(envelope, &packet)?;
        if packet.x3dh.is_some() {
            return Err(invalid("ephemeral input cannot bootstrap"));
        }
        let local_device = self.local_device_identity(local)?;
        let remote_device = self.authenticated_device_identity(HeadUse::NewAuthorization, entry)?;
        if remote_device.root_commitment() == local_device.root_commitment()
            || !self.friend_link_peer_is_accepted(remote_device.root_commitment())?
        {
            return Err(invalid("ephemeral source requires accepted peer consent"));
        }
        let (mut session, bundle_hash) =
            self.recv_pair_session(&local_device, &remote_device, &envelope.envelope_id, &packet)?;
        report::refuse_direct_candidate_opening(envelope, &session, &Kind::Direct)?;
        let aad =
            associated_data_from_outer(envelope, &envelope.source_device_id, local, &bundle_hash)?;
        let decrypted =
            zeroize::Zeroizing::new(session.decrypt_with_franking_keys(&packet.ciphertext, &aad)?);
        let body = report::opened_inner_plaintext(envelope, &decrypted.plaintext)?;
        let decoded = g::Inner::decode(body.as_slice()).ok();
        let identity = decoded.as_ref().and_then(|inner| inner.identity.as_ref());
        if let Some(identity) = identity {
            self.check_ephemeral_identity(
                identity,
                &remote_device,
                &conversation,
                decoded.as_ref().ok_or_else(|| invalid("ephemeral Inner missing"))?.kind,
            )?;
        }
        let message_id = identity.map_or_else(
            || format!("unclassified/{}/{}", remote_device.storage_key(), envelope.envelope_id),
            |identity| ramflux_protocol::encode_base64url(&identity.id),
        );
        let routing = Routing {
            kind: Kind::Direct,
            conversation_id: conversation,
            group_id: None,
            message_id,
            group_message_id: None,
            attachments: false,
        };
        self.confirm_routed_context(&routing, entry)?;
        if !self.raw_reparse_scope_allowed(&remote_device, &routing.conversation_id)? {
            return Err(invalid("ephemeral direct root binding conflict"));
        }
        Ok(Opened { routing, body, decrypted, session, bundle_hash, local_device, remote_device })
    }

    fn check_ephemeral_identity(
        &self,
        identity: &g::EventIdentity,
        remote: &ramflux_crypto::RootQualifiedDeviceRef,
        conversation: &str,
        kind: u32,
    ) -> Result<(), SdkError> {
        let epoch = self
            .account_db()?
            .client_device_record(remote)?
            .and_then(|record| record["device_epoch"].as_u64());
        if identity.author.as_ref().is_none_or(|author| {
            author.account_anchor != remote.root_commitment()
                || author.device_id != remote.device_id()
                || Some(author.device_epoch) != epoch
        }) || identity.conversation_id != conversation
            || identity.group_id.is_some()
            || identity.group_epoch.is_some()
            || identity.id.len() != 32
            || (kind != 7 && g::identity::verify(identity).is_err())
        {
            return Err(invalid("ephemeral identity conflicts with authenticated source/scope"));
        }
        Ok(())
    }

    fn admit_ephemeral_inner(
        &self,
        opened: &Opened,
        entry: &GatewayInboxEntry,
    ) -> Result<EphemeralContent, SdkError> {
        let scanned = validation::scan_inner(&opened.body)
            .map_err(|_| invalid("malformed ephemeral Inner"))?;
        if scanned.outcome == ScanOutcome::Unsupported {
            if scanned.kind == 7 {
                return Ok(EphemeralContent::NonTyping);
            }
            self.retain_ephemeral_unknown(opened, entry, &scanned)?;
            return Ok(EphemeralContent::Unsupported);
        }
        let (identity, content) = Self::decode_generated_inner(&opened.body)?;
        let Some(g::content::Value::Typing(typing)) = content.value else {
            return Ok(EphemeralContent::NonTyping);
        };
        let deadline = entry
            .envelope
            .created_at
            .checked_add(i64::from(entry.envelope.ttl))
            .and_then(|at| u64::try_from(at).ok())
            .ok_or_else(|| invalid("ephemeral deadline overflow"))?;
        if identity.device_sequence != 0
            || typing.expires_at != deadline
            || entry.envelope.ttl != if typing.active { 5 } else { 1 }
        {
            return Err(invalid("typing interval or sequence exceeds signed policy"));
        }
        Ok(EphemeralContent::Typing(identity, typing))
    }

    fn retain_ephemeral_unknown(
        &self,
        opened: &Opened,
        entry: &GatewayInboxEntry,
        scanned: &validation::ScannedInner<'_>,
    ) -> Result<(), SdkError> {
        let source = &opened.remote_device;
        let target = match scanned.kind {
            3 => g::Edit::decode(scanned.body).ok().and_then(|edit| edit.target),
            5 => g::Reaction::decode(scanned.body).ok().and_then(|reaction| reaction.target),
            _ => None,
        };
        if target.as_ref().is_some_and(|target| {
            target.id.len() != 32 || target.conversation_id != opened.routing.conversation_id
        }) {
            return Err(invalid("ephemeral mutation target binding mismatch"));
        }
        let origin = self
            .capture_retained_origin(opened, entry)?
            .ok_or_else(|| invalid("ephemeral Unsupported requires original source evidence"))?;
        let proof_id = origin.copy_id()?;
        // Private receive locator only: never a durable transport receipt or ACK key.
        let copy_id = format!(
            "ephemeral/{}/{}/{}",
            source.storage_key(),
            entry.envelope.envelope_id,
            entry.envelope.payload_hash
        );
        let provenance = super::generated_receive::Provenance {
            source: source.storage_key().into(),
            conversation: opened.routing.conversation_id.clone(),
            message: opened.routing.message_id.clone(),
            envelope_id: entry.envelope.envelope_id.clone(),
            payload_hash: entry.envelope.payload_hash.clone(),
            expires_at: entry
                .envelope
                .created_at
                .checked_add(i64::from(entry.envelope.ttl))
                .ok_or_else(|| invalid("ephemeral deadline overflow"))?,
            original_mode: "ephemeral".into(),
            source_epoch: self
                .account_db()?
                .client_device_record(source)?
                .and_then(|record| record["device_epoch"].as_u64())
                .ok_or_else(|| invalid("ephemeral epoch missing"))?,
            original_route: serde_json::to_string(&opened.routing)?,
            outer_receipt_key: copy_id.clone(),
            source_evidence_copy: Some(proof_id.clone()),
            received_erasure_generation: self.account_db()?.privacy_erasure_generation()?,
        };
        self.retain_raw_origin_copy(
            &opened.routing.message_id,
            source.root_commitment(),
            &proof_id,
            &origin,
            target.as_ref(),
        )?;
        self.account_db()?.put_unsupported_raw_copy(ramflux_storage::RawInnerCopyWrite {
            owner_id: &opened.routing.message_id,
            verified_source_anchor: source.root_commitment(),
            copy_id: &copy_id,
            kind: ramflux_storage::RawInnerCopyKind::OuterInner,
            bytes: scanned.exact_inner,
            bounded_metadata: &serde_json::to_vec(&provenance)?,
        })?;
        if let Some(target) = target {
            self.account_db()?
                .bind_raw_inner_copy(&copy_id, &ramflux_protocol::encode_base64url(target.id))?;
        }
        Ok(())
    }
}
