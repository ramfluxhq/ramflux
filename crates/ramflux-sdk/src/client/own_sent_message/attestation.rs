// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Private own-root attestation, kept separate from a peer's first-hand origin evidence.
use crate::client::raw_inner_origin::RetainedOrigin;
use crate::client::routed::Opened;
use crate::{GatewayInboxEntry, RamfluxClient, SdkError};
use prost::Message as _;
use ramflux_protocol::message::{self as g, original_header::EvidenceError};
use zeroize::Zeroize as _;

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OwnSentAttestation {
    exact_outer_inner: Vec<u8>,
    origin: RetainedOrigin,
}
impl Drop for OwnSentAttestation {
    fn drop(&mut self) {
        self.exact_outer_inner.zeroize();
        self.origin.reported_inner.zeroize();
        self.origin.evidence.report_opening.zeroize();
        self.origin.evidence.group_plaintext.zeroize();
        self.origin.evidence.group_opening.zeroize();
    }
}

impl OwnSentAttestation {
    pub(super) fn enclosing_copy(&self) -> Result<g::OwnMessageCopy, SdkError> {
        let inner = g::Inner::decode(self.exact_outer_inner.as_slice())
            .map_err(|_| EvidenceError::OriginCommitmentMismatch)?;
        let control = g::Control::decode(inner.body.as_slice())
            .map_err(|_| EvidenceError::OriginCommitmentMismatch)?;
        match control.payload {
            Some(g::control::Payload::OwnMessageCopy(copy)) => Ok(copy),
            _ => Err(EvidenceError::OriginCommitmentMismatch.into()),
        }
    }

    pub(crate) fn verify(
        &self,
        exact_nested: &[u8],
        own_root: &str,
    ) -> Result<g::OwnSentMessage, SdkError> {
        let bad = EvidenceError::OriginCommitmentMismatch;
        let scanned = g::validation::scan_inner(&self.exact_outer_inner).map_err(|_| bad)?;
        let outer = g::Inner::decode(self.exact_outer_inner.as_slice()).map_err(|_| bad)?;
        let identity = outer.identity.as_ref().ok_or(bad)?;
        if scanned.kind != 8
            || identity.group_id.is_some()
            || identity.device_sequence & (1 << 63) == 0
        {
            return Err(bad.into());
        }
        // This verifies C against the enclosing own-copy, never against the nested Message.
        let verified = self.origin.verify(identity, &self.exact_outer_inner)?;
        if verified.author.root != own_root
            || verified.outer.delivery_mode.as_deref() != Some("durable")
            || verified.outer.delivery_class != ramflux_protocol::DeliveryClass::Message
        {
            return Err(bad.into());
        }
        let control = g::Control::decode(scanned.body).map_err(|_| bad)?;
        let Some(g::control::Payload::OwnMessageCopy(copy)) = control.payload else {
            return Err(bad.into());
        };
        if control.operation != 15
            || copy.source.as_ref() != identity.author.as_ref()
            || copy.target.as_ref().is_none_or(|target| target.account_anchor != own_root)
        {
            return Err(bad.into());
        }
        let Some(g::own_message_copy::Payload::Sent(sent)) = copy.payload else {
            return Err(bad.into());
        };
        if sent.exact_inner != exact_nested
            || sent
                .context
                .as_ref()
                .is_none_or(|context| context.conversation_id != identity.conversation_id)
        {
            return Err(bad.into());
        }
        let nested = g::Inner::decode(exact_nested).map_err(|_| bad)?;
        g::validation::scan_inner(exact_nested).map_err(|_| bad)?;
        let original = nested.identity.as_ref().ok_or(bad)?;
        g::identity::verify(original).map_err(|_| bad)?;
        if original.conversation_id != identity.conversation_id
            || original.device_sequence & (1 << 63) != 0
            || original.author.as_ref().is_none_or(|author| author.account_anchor != own_root)
            || ramflux_protocol::encode_base64url(&original.id) != sent.message_id
            || !matches!(nested.kind, 1 | 3 | 4 | 5)
        {
            return Err(bad.into());
        }
        Ok(sent)
    }
}

impl RamfluxClient {
    pub(crate) fn retain_received_own_sent_attestation(
        &self,
        opened: &Opened,
        entry: &GatewayInboxEntry,
        sent: &g::OwnSentMessage,
    ) -> Result<(), SdkError> {
        let scanned = g::validation::scan_inner(&sent.exact_inner)
            .map_err(|_| EvidenceError::OriginCommitmentMismatch)?;
        if !matches!(scanned.kind, 1 | 3) {
            return Ok(());
        }
        let (identity, owners) = if scanned.kind == 1 {
            let inner = g::Inner::decode(sent.exact_inner.as_slice())
                .map_err(|_| EvidenceError::OriginCommitmentMismatch)?;
            let identity = inner.identity.ok_or(EvidenceError::OriginCommitmentMismatch)?;
            let owners = vec![ramflux_protocol::encode_base64url(&identity.id)];
            (identity, owners)
        } else {
            let (identity, content) = Self::decode_generated_inner(&sent.exact_inner)?;
            let owners = super::generated::own_sent_erasure_owners(&identity, &content)?;
            (identity, owners)
        };
        let proof = self.capture_own_sent_attestation(opened, entry, sent)?;
        for owner in owners {
            self.persist_own_sent_attestation(&owner, &proof)?;
            if scanned.outcome != g::validation::ScanOutcome::Supported && scanned.kind == 1 {
                self.retain_unsupported_own_sent_view(&owner, &identity, sent, &proof)?;
            }
        }
        Ok(())
    }

    pub(crate) fn capture_own_sent_attestation(
        &self,
        opened: &Opened,
        entry: &GatewayInboxEntry,
        sent: &g::OwnSentMessage,
    ) -> Result<OwnSentAttestation, SdkError> {
        let origin = self
            .capture_retained_origin(opened, entry)?
            .ok_or(EvidenceError::OriginEvidenceMissing)?;
        let attestation = OwnSentAttestation { exact_outer_inner: opened.body.to_vec(), origin };
        let verified = attestation.verify(&sent.exact_inner, &self.own_account_anchor()?)?;
        if verified != *sent {
            return Err(EvidenceError::OriginCommitmentMismatch.into());
        }
        Ok(attestation)
    }

    pub(crate) fn persist_own_sent_attestation(
        &self,
        owner: &str,
        proof: &OwnSentAttestation,
    ) -> Result<(), SdkError> {
        let db = self.account_db()?;
        let sent = proof.verify(
            &{
                let outer = g::Inner::decode(proof.exact_outer_inner.as_slice())
                    .map_err(|_| EvidenceError::OriginCommitmentMismatch)?;
                let control = g::Control::decode(outer.body.as_slice())
                    .map_err(|_| EvidenceError::OriginCommitmentMismatch)?;
                let Some(g::control::Payload::OwnMessageCopy(copy)) = control.payload else {
                    return Err(EvidenceError::OriginCommitmentMismatch.into());
                };
                let Some(g::own_message_copy::Payload::Sent(sent)) = copy.payload else {
                    return Err(EvidenceError::OriginCommitmentMismatch.into());
                };
                sent.exact_inner
            },
            &self.own_account_anchor()?,
        )?;
        let inner = g::Inner::decode(sent.exact_inner.as_slice())
            .map_err(|_| EvidenceError::OriginCommitmentMismatch)?;
        // Only plaintext Message/Edit attestations contain the message body needed by
        // this private owner. Deletes settle without retaining an enclosing body copy.
        if !matches!(inner.kind, 1 | 3)
            || db.message_is_deleted(owner)?
            || self.generated_edit_reference_erased(&sent.exact_inner)?
        {
            return Ok(());
        }
        if inner.kind == 1
            && db
                .load_actor_state::<bool>(&format!("routed/report-opening-retired/{owner}"))?
                .unwrap_or(false)
        {
            return Ok(());
        }
        let identity = inner.identity.as_ref().ok_or(EvidenceError::OriginCommitmentMismatch)?;
        let owns = if inner.kind == 1 {
            ramflux_protocol::encode_base64url(&identity.id) == owner
        } else {
            let content = g::registry::decode_body(inner.kind, &inner.body, inner.layer)
                .map_err(|_| EvidenceError::OriginCommitmentMismatch)?;
            super::generated::own_sent_erasure_owners(identity, &content)?
                .iter()
                .any(|id| id == owner)
        };
        if !owns {
            return Err(EvidenceError::OriginCommitmentMismatch.into());
        }
        let encoded = zeroize::Zeroizing::new(serde_json::to_vec(proof)?);
        if encoded.len() > 4 * 1024 * 1024 {
            return Err(EvidenceError::OriginCommitmentMismatch.into());
        }
        let key = format!(
            "routed/own-sent-attestation/{owner}/{}",
            ramflux_protocol::encode_base64url(&identity.id)
        );
        db.put_unsupported_raw_copy(ramflux_storage::RawInnerCopyWrite {
            owner_id: owner,
            verified_source_anchor: &self.own_account_anchor()?,
            copy_id: &key,
            kind: ramflux_storage::RawInnerCopyKind::SourceEvidence,
            bytes: &encoded,
            bounded_metadata: &[],
        })?;
        db.persist_message_actor_state(owner, &key, proof)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::native_test_support::{Fixture, TestResult};
    use crate::client::routed::{Kind, Routing};
    use serde_json::json;

    async fn fixture() -> TestResult<(Fixture, OwnSentAttestation, g::OwnSentMessage)> {
        let own = Fixture::new("native-own-attestation").await?;
        let original = own.client.allocate_generated_identity("proof-conversation", 1000, false)?;
        let exact_inner = RamfluxClient::encode_generated_inner(
            original.clone(),
            &g::Content {
                value: Some(g::content::Value::Message(g::Message {
                    text: "private original body".into(),
                    ..Default::default()
                })),
            },
        )?;
        let sent = g::OwnSentMessage {
            envelope_id: "original-envelope".into(),
            message_id: ramflux_protocol::encode_base64url(&original.id),
            sender_id: "original label".into(),
            exact_inner,
            context: Some(g::OwnContext {
                conversation_id: original.conversation_id.clone(),
                participants: vec![own.manifest.principal_id.clone(), "peer".into()],
                ..Default::default()
            }),
            ..Default::default()
        };
        let now = crate::custody::network_now()?;
        let identity = own.client.allocate_generated_identity("proof-conversation", 1001, true)?;
        let source = identity.author.clone().ok_or("source")?;
        let exact_outer_inner = RamfluxClient::encode_generated_inner(
            identity.clone(),
            &g::Content {
                value: Some(g::content::Value::Control(g::Control {
                    operation: 15,
                    payload: Some(g::control::Payload::OwnMessageCopy(g::OwnMessageCopy {
                        source: Some(source.clone()),
                        target: Some(g::QualifiedDevice { device_id: "sibling".into(), ..source }),
                        created_at: i64::try_from(now)?,
                        expires_at: i64::try_from(now + 300)?,
                        payload: Some(g::own_message_copy::Payload::Sent(sent.clone())),
                    })),
                })),
            },
        )?;
        let proof = signed_proof(&own, &identity, exact_outer_inner, now)?;
        Ok((own, proof, sent))
    }

    fn signed_proof(
        own: &Fixture,
        identity: &g::EventIdentity,
        exact_outer_inner: Vec<u8>,
        now: u64,
    ) -> TestResult<OwnSentAttestation> {
        let vectors: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../ramflux-protocol/src/sender_transcript_vectors.json"
        ))?;
        let mut outer = vectors["envelope"].clone();
        outer["source_principal_id"] = json!(own.manifest.principal_id);
        outer["source_device_id"] = json!(own.client.owned_device_identity()?.device_id());
        outer["created_at"] = json!(now);
        outer["ttl"] = json!(300);
        outer["delivery_mode"] = json!("durable");
        outer["delivery_class"] = json!("message");
        outer["ext"] = json!({"source_root_commitment":own.client.own_account_anchor()?});
        let envelope: ramflux_protocol::Envelope = serde_json::from_value(outer.clone())?;
        let a0 = g::outer::encode_candidate_report_a0(
            &g::outer::candidate_report_a0_from_envelope(&envelope)?,
        )?;
        let opening = ramflux_crypto::random_32()?;
        outer["report_commitment"] = json!(ramflux_protocol::encode_base64url(
            ramflux_crypto::report_commitment(&opening, &exact_outer_inner, &a0)?
        ));
        outer["signature"] = json!(ramflux_crypto::sign_protocol_object_with_device_branch(
            own.client.device_branch.as_ref().ok_or("branch")?,
            &outer
        )?);
        let evidence = g::HistoryOriginEvidence {
            canonical_sender_envelope: ramflux_protocol::sender_origin_evidence(&outer)?,
            source_authority: Some(g::NativeCustodyManifest {
                canonical: ramflux_protocol::canonical_json_bytes(
                    own.manifest.custody.as_ref().ok_or("custody")?,
                )?,
            }),
            report_opening: opening.to_vec(),
            ..Default::default()
        };
        let proof = OwnSentAttestation {
            exact_outer_inner,
            origin: RetainedOrigin {
                evidence,
                reported_inner: Vec::new(),
                routing: Routing {
                    kind: Kind::Control,
                    conversation_id: identity.conversation_id.clone(),
                    message_id: ramflux_protocol::encode_base64url(&identity.id),
                    group_id: None,
                    group_message_id: None,
                    attachments: false,
                },
            },
        };
        Ok(proof)
    }

    #[tokio::test]
    async fn own_attestation_binds_exact_enclosing_bytes_and_never_becomes_peer_origin()
    -> TestResult {
        let (own, mut proof, sent) = fixture().await?;
        let root = own.client.own_account_anchor()?;
        assert_eq!(proof.verify(&sent.exact_inner, &root)?, sent);
        let retained: serde_json::Value =
            ramflux_protocol::parse_i_json(&proof.origin.evidence.canonical_sender_envelope)?;
        assert!(retained.get("encrypted_payload").is_none(), "body-free signed outer evidence");
        let mut changed = sent.exact_inner.clone();
        changed.push(0x01);
        assert!(proof.verify(&changed, &root).is_err());
        assert!(proof.verify(&sent.exact_inner, "another-root").is_err());
        assert!(
            RamfluxClient::verify_history_message_origin(&g::HistoryItem {
                exact_inner: sent.exact_inner.clone(),
                source_evidence: Some(proof.origin.evidence.clone()),
                ..Default::default()
            })
            .is_err(),
            "own-root outer is not the nested author's original envelope proof"
        );
        let mut outer = g::Inner::decode(proof.exact_outer_inner.as_slice())?;
        let mut control = g::Control::decode(outer.body.as_slice())?;
        let Some(g::control::Payload::OwnMessageCopy(copy)) = control.payload.as_mut() else {
            return Err("copy".into());
        };
        copy.created_at -= 1;
        outer.body = control.encode_to_vec();
        proof.exact_outer_inner = outer.encode_to_vec();
        assert!(
            proof.verify(&sent.exact_inner, &root).is_err(),
            "changed enclosing bytes must fail the retained report commitment"
        );
        Ok(())
    }

    #[tokio::test]
    async fn own_attestation_private_owner_quota_and_edit_retirement_apply() -> TestResult {
        let (own, proof, sent) = fixture().await?;
        let owner = &sent.message_id;
        let db = own.client.account_db()?;
        db.write_transaction(|| own.client.persist_own_sent_attestation(owner, &proof))?;
        let keys = db.message_actor_keys(owner, "routed/own-sent-attestation/")?;
        assert_eq!(keys.len(), 1);
        assert!(db.raw_inner_copy(&keys[0])?.is_some());
        let quota = db.unsupported_raw_quota(Some(&own.client.own_account_anchor()?))?;
        assert_eq!(quota.owners, 1);
        assert!(quota.raw_bytes >= u64::try_from(serde_json::to_vec(&proof)?.len())?);
        assert!(
            db.write_transaction(|| own.client.persist_own_sent_attestation("wrong-owner", &proof))
                .is_err()
        );
        db.write_transaction(|| {
            own.client.retire_generated_edit_payloads("proof-conversation", owner)
        })?;
        assert!(db.raw_inner_copy(&keys[0])?.is_none());
        assert!(!db.actor_state_exists(&keys[0])?);
        db.write_transaction(|| own.client.persist_own_sent_attestation(owner, &proof))?;
        assert!(
            db.raw_inner_copy(&keys[0])?.is_none(),
            "late original cannot resurrect its private proof"
        );
        Ok(())
    }
    fn bind_private_thread(own: &Fixture, sent: &g::OwnSentMessage) -> TestResult {
        let context = sent.context.as_ref().ok_or("context")?;
        own.client.account_db()?.persist_client_record(
            "conversation",
            &context.conversation_id,
            &json!({"kind":"direct", "group_id":null, "participants":context.participants}),
        )?;
        Ok(())
    }

    #[tokio::test]
    async fn own_sent_unsupported_message_keeps_exact_private_evidence_and_settles() -> TestResult {
        let _gate = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
        let (mut own, proof, mut sent) = fixture().await?;
        bind_private_thread(&own, &sent)?;
        let mut nested = g::Inner::decode(sent.exact_inner.as_slice())?;
        nested.body.extend_from_slice(&[0xf8, 0x07, 1]);
        sent.exact_inner = nested.encode_to_vec();
        let identity = nested.identity.as_ref().ok_or("identity")?;
        let mut outer = g::Inner::decode(proof.exact_outer_inner.as_slice())?;
        let mut control = g::Control::decode(outer.body.as_slice())?;
        let Some(g::control::Payload::OwnMessageCopy(copy)) = control.payload.as_mut() else {
            return Err("copy".into());
        };
        copy.payload = Some(g::own_message_copy::Payload::Sent(sent.clone()));
        outer.body = control.encode_to_vec();
        let proof = signed_proof(
            &own,
            outer.identity.as_ref().ok_or("outer identity")?,
            outer.encode_to_vec(),
            crate::custody::network_now()?,
        )?;
        proof.verify(&sent.exact_inner, &own.client.own_account_anchor()?)?;
        own.client.authorize_generated_own_sent(
            &own.client.owned_device_identity()?,
            &identity.conversation_id,
            &sent,
        )?;
        let packet = super::super::SentMessage::from_generated(&sent)?;
        let owner = sent.message_id.clone();
        own.client.account_db()?.write_transaction(|| -> Result<(), SdkError> {
            assert!(own.client.commit_unsupported_own_message(&packet, identity, &sent)?);
            own.client.persist_own_sent_attestation(&owner, &proof)?;
            own.client.retain_unsupported_own_sent_view(&owner, identity, &sent, &proof)?;
            Ok(())
        })?;
        let key = format!("routed/own-sent-attestation/{owner}/{owner}/inner");
        assert_eq!(
            own.client.account_db()?.raw_inner_copy(&key)?.ok_or("raw")?.bytes,
            sent.exact_inner
        );
        assert!(own.client.account_db()?.message_content(&owner)?.is_none());
        assert_eq!(own.client.reparse_raw_inner_page()?.projected, 0);
        assert!(own.client.account_db()?.raw_inner_copy(&key)?.is_some());
        own.client.account_db()?.write_transaction(|| {
            own.client.retire_generated_edit_payloads(&identity.conversation_id, &owner)
        })?;
        assert!(own.client.account_db()?.raw_inner_copy(&key)?.is_none());
        own.client.account_db()?.write_transaction(|| -> Result<(), SdkError> {
            own.client.persist_own_sent_attestation(&owner, &proof)?;
            own.client.retain_unsupported_own_sent_view(&owner, identity, &sent, &proof)
        })?;
        assert!(
            own.client.account_db()?.raw_inner_copy(&key)?.is_none(),
            "late opaque original cannot restore erased body or nonce"
        );
        assert!(own.client.account_db()?.raw_inner_copy(key.trim_end_matches("/inner"))?.is_none());
        Ok(())
    }

    #[tokio::test]
    async fn private_own_message_reparse_uses_own_attestation_and_keeps_peer_origin_separate()
    -> TestResult {
        let _gate = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
        let (mut own, proof, sent) = fixture().await?;
        bind_private_thread(&own, &sent)?;
        let identity = g::Inner::decode(sent.exact_inner.as_slice())?.identity.ok_or("identity")?;
        let owner = sent.message_id.clone();
        // Stage a previous decoder's Unsupported view around genuinely signed native evidence.
        own.client.account_db()?.write_transaction(|| -> Result<(), SdkError> {
            own.client.persist_own_sent_attestation(&owner, &proof)?;
            own.client.retain_unsupported_own_sent_view(&owner, &identity, &sent, &proof)
        })?;
        assert!(own.client.account_db()?.message_content(&owner)?.is_none());
        assert_eq!(own.client.reparse_raw_inner_page()?.projected, 1);
        assert_eq!(
            own.client.account_db()?.message_content(&owner)?,
            Some(sent.exact_inner.clone())
        );
        assert_eq!(own.client.reparse_raw_inner_page()?.projected, 0);
        assert!(
            own.client.export_generated_history_item(&identity.id).is_err(),
            "sibling attestation cannot become peer origin"
        );
        Ok(())
    }
}
