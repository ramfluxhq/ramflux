// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Public original-header evidence survives Edit without retaining the retired body.
use super::{Author, EvidenceError, g};
use serde_json::Value;

#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OriginalHeader {
    pub exact_identity: Vec<u8>,
    pub evidence: g::HistoryOriginalMetadataEvidence,
}

/// A verified historical header, never a retired-body or current-membership capability.
pub struct VerifiedOriginalHeader {
    identity: g::EventIdentity,
    author: Author,
}
impl VerifiedOriginalHeader {
    #[must_use]
    pub const fn identity(&self) -> &g::EventIdentity {
        &self.identity
    }
    #[must_use]
    pub const fn author(&self) -> &Author {
        &self.author
    }
    #[must_use]
    pub fn into_author(self) -> Author {
        self.author
    }
    /// Original signed order, independent of receive-time clipping and local cursors.
    /// # Errors
    /// Refuses invalid original order coordinates.
    pub fn order_key(&self) -> Result<g::identity::EventOrder, EvidenceError> {
        g::identity::order_key(&self.identity).map_err(|_| EvidenceError::OriginCommitmentMismatch)
    }
}
impl OriginalHeader {
    /// Compare identity commitments only. This comparison does not authenticate either header.
    /// # Errors
    /// Refuses invalid I-JSON in bounded original metadata envelopes.
    pub fn matches(&self, other: &Self) -> Result<bool, ramflux_protocol::ProtocolError> {
        if self.evidence.canonical_sender_envelope.len() > g::original_header::MAX_OUTER_BYTES
            || other.evidence.canonical_sender_envelope.len() > g::original_header::MAX_OUTER_BYTES
        {
            return Ok(false);
        }
        let left: Value = ramflux_protocol::parse_i_json(&self.evidence.canonical_sender_envelope)?;
        let right: Value =
            ramflux_protocol::parse_i_json(&other.evidence.canonical_sender_envelope)?;
        Ok(self.exact_identity == other.exact_identity
            && self.evidence.layer == other.evidence.layer
            && left["ext"][g::original_header::EXT_KEY]
                == right["ext"][g::original_header::EXT_KEY])
    }

    /// Verify the exact identity/HLC against its original signed metadata and public custody.
    /// No report opening or retired plaintext is required or reconstructed. Group membership
    /// and current mutation authorization remain separate requirements of their owners.
    /// # Errors
    /// Refuses changed identity/order/layer, invalid original signatures/custody, wrong
    /// delivery policy, ciphertext-bearing evidence, malformed commitments and bounds.
    pub fn verify_header(&self) -> Result<VerifiedOriginalHeader, EvidenceError> {
        let bad = EvidenceError::OriginCommitmentMismatch;
        let identity = g::original_header::decode_identity(&self.exact_identity)?;
        if identity.device_sequence & (1 << 63) != 0
            || self.evidence.canonical_sender_envelope.len() > g::original_header::MAX_OUTER_BYTES
            || self.evidence.group_binding.is_some() != self.evidence.group_membership.is_some()
        {
            return Err(bad);
        }
        let outer: Value = ramflux_protocol::parse_i_json(&self.evidence.canonical_sender_envelope)
            .map_err(|_| bad)?;
        if ramflux_protocol::canonical_json_bytes(&outer).map_err(|_| bad)?
            != self.evidence.canonical_sender_envelope
            || outer["schema"].as_str() != Some(g::outer::CANDIDATE_ENVELOPE_SCHEMA)
            || outer["delivery_mode"].as_str() != Some("durable")
            || outer["delivery_class"].as_str() != Some("message")
        {
            return Err(bad);
        }
        let author = super::authority(
            &outer,
            self.evidence.source_authority.as_ref().ok_or(EvidenceError::OriginEvidenceMissing)?,
            &identity,
        )?;
        let issued_at = outer["created_at"].as_u64().ok_or(bad)?;
        let expires_at = issued_at.checked_add(outer["ttl"].as_u64().ok_or(bad)?).ok_or(bad)?;
        let ext = ramflux_protocol::Ext {
            ext: outer["ext"]
                .as_object()
                .ok_or(bad)?
                .iter()
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect(),
        };
        g::original_header::verify_extension(
            &ext,
            1,
            Some(&g::original_header::Header {
                layer: self.evidence.layer,
                kind: 1,
                exact_identity: &self.exact_identity,
                issued_at,
                expires_at,
                group: self.evidence.group_binding.as_ref(),
            }),
        )?;
        Ok(VerifiedOriginalHeader { identity, author })
    }
}
