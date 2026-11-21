// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Exact retained origin and its immutable verifier; current authorization stays with the caller.
use super::{Author, EvidenceError, Routing, authority, g};
use prost::Message as _;
use serde::{Deserialize, Serialize};

/// Proves the original signer committed to these bytes; not delivery, freshness or node custody.
#[derive(Clone, Serialize, Deserialize)]
pub struct RetainedOrigin {
    pub evidence: g::HistoryOriginEvidence,
    pub reported_inner: Vec<u8>,
    pub routing: Routing,
}
/// Original author/header information; never a live permission or local pin adoption.
pub struct VerifiedOrigin {
    pub author: Author,
    pub outer: ramflux_protocol::Envelope,
}
impl RetainedOrigin {
    /// Compute a private content address over this exact retained proof.
    /// # Errors
    /// Refuses evidence that cannot be serialized. This address grants no authority.
    pub fn copy_id(&self) -> Result<String, serde_json::Error> {
        // Private content address, not a wire identity or an authority grant. Two genuine
        // receipt-time authority snapshots for one envelope must not collide on restore.
        Ok(format!(
            "source/{}",
            crate::blake3_256_base64url(
                "ramflux.sdk.raw-origin-copy.v1",
                &serde_json::to_vec(self)?
            )
        ))
    }

    /// Verify the exact inner against its original signer, commitment and group evidence.
    /// # Errors
    /// Refuses missing, changed, cross-author or invalid native origin evidence.
    pub fn verify(
        &self,
        identity: &g::EventIdentity,
        exact_inner: &[u8],
    ) -> Result<VerifiedOrigin, EvidenceError> {
        let bad = EvidenceError::OriginCommitmentMismatch;
        g::validation::scan_inner(exact_inner).map_err(|_| bad)?;
        if self.evidence.report_opening.len() != 32
            || (identity.group_id.is_some() && self.evidence.group_opening.len() != 64)
        {
            return Err(bad);
        }
        let decoded = g::Inner::decode(exact_inner).map_err(|_| bad)?;
        if decoded.identity.as_ref() != Some(identity) {
            return Err(bad);
        }
        if identity.group_id.is_none()
            && (!self.evidence.group_plaintext.is_empty()
                || !self.evidence.group_opening.is_empty()
                || self.evidence.group_membership.is_some()
                || self.routing.group_id.is_some()
                || identity.group_epoch.is_some())
        {
            return Err(bad);
        }
        if decoded.kind != 7 && g::identity::verify(identity).is_err() {
            return Err(bad);
        }
        let reported = if self.reported_inner.is_empty() {
            exact_inner
        } else {
            self.reported_inner.as_slice()
        };
        if self.evidence.canonical_sender_envelope.len() > g::original_header::MAX_OUTER_BYTES {
            return Err(bad);
        }
        let outer: serde_json::Value =
            ramflux_protocol::parse_i_json(&self.evidence.canonical_sender_envelope)
                .map_err(|_| bad)?;
        if ramflux_protocol::canonical_json_bytes(&outer).map_err(|_| bad)?
            != self.evidence.canonical_sender_envelope
        {
            return Err(bad);
        }
        let author = authority(
            &outer,
            self.evidence.source_authority.as_ref().ok_or(EvidenceError::OriginEvidenceMissing)?,
            identity,
        )?;
        if identity.group_id.is_some() {
            if outer["delivery_mode"].as_str() != Some("durable")
                || outer["delivery_class"].as_str() != Some("message")
            {
                return Err(bad);
            }
            self.verify_group_binding(identity, &decoded, &author)?;
        }
        let mut a0_outer = outer.clone();
        a0_outer["encrypted_payload"] = serde_json::Value::String(String::new());
        // The placeholder is used for A0/header fields only. Signature verification above
        // uses Evidence mode on the exact body-free signed outer, with no ciphertext key.
        let envelope: ramflux_protocol::Envelope =
            serde_json::from_value(a0_outer).map_err(|_| bad)?;
        let a0 = g::outer::encode_candidate_report_a0(
            &g::outer::candidate_report_a0_from_envelope(&envelope).map_err(|_| bad)?,
        )
        .map_err(|_| bad)?;
        let opening: [u8; 32] =
            self.evidence.report_opening.as_slice().try_into().map_err(|_| bad)?;
        let commitment: [u8; 32] =
            ramflux_protocol::decode_base64url(envelope.report_commitment.as_deref().ok_or(bad)?)
                .map_err(|_| bad)?
                .try_into()
                .map_err(|_| bad)?;
        crate::verify_report_opening(&opening, reported, &a0, &commitment).map_err(|_| bad)?;
        if reported != exact_inner {
            return Err(bad);
        }
        if identity.conversation_id != self.routing.conversation_id {
            return Err(bad);
        }
        let issued = u64::try_from(envelope.created_at).map_err(|_| bad)?;
        let expires = issued.checked_add(u64::from(envelope.ttl)).ok_or(bad)?;
        g::original_header::verify_inner_extension(&envelope.ext, exact_inner, issued, expires)?;
        if identity.group_id.is_some() {
            self.verify_group_opening(&decoded)?;
        }
        Ok(VerifiedOrigin { author, outer: envelope })
    }
}

impl Drop for RetainedOrigin {
    fn drop(&mut self) {
        use zeroize::Zeroize as _;
        self.evidence.report_opening.zeroize();
        self.evidence.group_opening.zeroize();
        self.evidence.group_plaintext.zeroize();
        self.reported_inner.zeroize();
    }
}
