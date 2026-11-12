// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Private first-hand origin material, sharing the audited history authority verifier.
use crate::client::routed::{Opened, Routing};
use crate::{RamfluxClient, SdkError};
use prost::Message as _;
use ramflux_protocol::message::{self as g, original_header::EvidenceError};
use serde::{Deserialize, Serialize};

/// Proves the original signer committed to these bytes; not delivery, freshness or node custody.
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct RetainedOrigin {
    pub evidence: g::HistoryOriginEvidence,
    pub reported_inner: Vec<u8>,
    pub routing: Routing,
}
pub(crate) struct VerifiedOrigin {
    pub author: crate::client::generated_history::Author,
    pub outer: ramflux_protocol::Envelope,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Carrier {
    routing: Routing,
    body_base64: String,
}
impl RetainedOrigin {
    pub(crate) fn copy_id(&self) -> Result<String, SdkError> {
        // Private content address, not a wire identity or an authority grant. Two genuine
        // receipt-time authority snapshots for one envelope must not collide on restore.
        Ok(format!(
            "source/{}",
            ramflux_crypto::blake3_256_base64url(
                "ramflux.sdk.raw-origin-copy.v1",
                &serde_json::to_vec(self)?
            )
        ))
    }

    pub(crate) fn verify(
        &self,
        identity: &g::EventIdentity,
        exact_inner: &[u8],
    ) -> Result<VerifiedOrigin, SdkError> {
        let bad = EvidenceError::OriginCommitmentMismatch;
        let decoded = g::Inner::decode(exact_inner).map_err(|_| bad)?;
        if !self.evidence.group_plaintext.is_empty()
            || !self.evidence.group_opening.is_empty()
            || self.evidence.group_membership.is_some()
            || decoded.identity.as_ref() != Some(identity)
            || self.routing.group_id.is_some()
            || identity.group_id.is_some()
            || identity.group_epoch.is_some()
        {
            return Err(bad.into());
        }
        if decoded.kind != 7 && g::identity::verify(identity).is_err() {
            return Err(bad.into());
        }
        let reported = if self.reported_inner.is_empty() {
            exact_inner
        } else {
            self.reported_inner.as_slice()
        };
        if self.evidence.canonical_sender_envelope.len() > g::original_header::MAX_OUTER_BYTES {
            return Err(bad.into());
        }
        let outer: serde_json::Value =
            ramflux_protocol::parse_i_json(&self.evidence.canonical_sender_envelope)
                .map_err(|_| bad)?;
        if ramflux_protocol::canonical_json_bytes(&outer)?
            != self.evidence.canonical_sender_envelope
        {
            return Err(bad.into());
        }
        let author = crate::client::generated_history::authority(
            &outer,
            self.evidence.source_authority.as_ref().ok_or(EvidenceError::OriginEvidenceMissing)?,
            identity,
        )?;
        let mut a0_outer = outer.clone();
        a0_outer["encrypted_payload"] = serde_json::Value::String(String::new());
        // The placeholder is used for A0/header fields only. Signature verification above
        // uses Evidence mode on the exact body-free signed outer, with no ciphertext key.
        let envelope: ramflux_protocol::Envelope =
            serde_json::from_value(a0_outer).map_err(|_| bad)?;
        let a0 = g::outer::encode_candidate_report_a0(
            &g::outer::candidate_report_a0_from_envelope(&envelope)?,
        )?;
        let opening: [u8; 32] =
            self.evidence.report_opening.as_slice().try_into().map_err(|_| bad)?;
        let commitment: [u8; 32] =
            ramflux_protocol::decode_base64url(envelope.report_commitment.as_deref().ok_or(bad)?)
                .map_err(|_| bad)?
                .try_into()
                .map_err(|_| bad)?;
        ramflux_crypto::verify_report_opening(&opening, reported, &a0, &commitment)
            .map_err(|_| bad)?;
        if reported != exact_inner {
            if ramflux_protocol::schema_profile::ACTIVE_STORAGE_GENERATION >= 1 {
                return Err(bad.into());
            }
            let carrier: Carrier = ramflux_protocol::parse_i_json(reported).map_err(|_| bad)?;
            if carrier.routing != self.routing
                || ramflux_protocol::decode_base64url(&carrier.body_base64).map_err(|_| bad)?
                    != exact_inner
            {
                return Err(bad.into());
            }
        }
        if identity.conversation_id != self.routing.conversation_id {
            return Err(bad.into());
        }
        let issued = u64::try_from(envelope.created_at).map_err(|_| bad)?;
        let expires = issued.checked_add(u64::from(envelope.ttl)).ok_or(bad)?;
        g::original_header::verify_inner_extension(&envelope.ext, exact_inner, issued, expires)?;
        Ok(VerifiedOrigin { author, outer: envelope })
    }
}
impl RamfluxClient {
    pub(crate) fn capture_retained_origin(
        &self,
        opened: &Opened,
        entry: &crate::GatewayInboxEntry,
    ) -> Result<Option<RetainedOrigin>, SdkError> {
        if entry.envelope.schema != g::outer::CANDIDATE_ENVELOPE_SCHEMA
            || opened.routing.group_id.is_some()
        {
            return Ok(None);
        }
        let parsed = ramflux_crypto::parse_report_plaintext(&opened.decrypted.plaintext)?;
        let authority = self
            .current_custody_evidence(
                opened.remote_device.root_commitment(),
                crate::custody::network_now()?,
            )?
            .ok_or(EvidenceError::OriginEvidenceMissing)?;
        let manifest = ramflux_protocol::custody::CustodyManifest {
            publication: authority.publication,
            custodian_publication: authority.custodian_publication,
            devices: Vec::new(),
        };
        Ok(Some(RetainedOrigin {
            evidence: g::HistoryOriginEvidence {
                canonical_sender_envelope: ramflux_protocol::sender_origin_evidence(
                    &entry.envelope,
                )?,
                source_authority: Some(g::NativeCustodyManifest {
                    canonical: ramflux_protocol::canonical_json_bytes(&manifest)?,
                }),
                report_opening: parsed.opening().to_vec(),
                ..Default::default()
            },
            reported_inner: if parsed.inner() == opened.body.as_slice() {
                Vec::new()
            } else {
                parsed.inner().to_vec()
            },
            routing: opened.routing.clone(),
        }))
    }
}

impl RamfluxClient {
    pub(crate) fn retain_raw_origin_copy(
        &self,
        owner: &str,
        source: &str,
        copy_id: &str,
        origin: &RetainedOrigin,
        target: Option<&g::MessageRef>,
    ) -> Result<(), SdkError> {
        let db = self.account_db()?;
        db.put_unsupported_raw_copy(ramflux_storage::RawInnerCopyWrite {
            owner_id: owner,
            verified_source_anchor: source,
            copy_id,
            kind: ramflux_storage::RawInnerCopyKind::SourceEvidence,
            bytes: &serde_json::to_vec(origin)?,
            bounded_metadata: b"source evidence",
        })?;
        if let Some(target) = target {
            db.bind_raw_inner_copy(copy_id, &ramflux_protocol::encode_base64url(&target.id))?;
        }
        Ok(())
    }
}
