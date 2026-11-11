// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Shape and original-header checks. Native manifest/signature verification remains mandatory.
use super::{EvidenceError, Header, MAX_OUTER_BYTES, decode_identity, verify_extension};
use crate::message as g;
use prost::Message as _;

/// Parsed original header and carried Edit. This is not a native authority grant.
pub struct EditedHeader {
    pub identity: g::EventIdentity,
    pub edit_identity: g::EventIdentity,
    pub edit: g::Edit,
    pub original_outer: serde_json::Value,
}

/// Check exact retained original identity against its signed outer commitment.
/// # Errors
/// Refuses missing evidence, tags on other kinds, invalid encoding, mismatched headers and bounds.
pub fn check(item: &g::HistoryItem) -> Result<EditedHeader, EvidenceError> {
    let missing = EvidenceError::OriginEvidenceMissing;
    let bad = EvidenceError::OriginCommitmentMismatch;
    let evidence = item.original_metadata_evidence.as_ref().ok_or(missing)?;
    if item.exact_original_identity.is_empty() || item.source_evidence.is_none() {
        return Err(missing);
    }
    let scanned = g::validation::scan_inner(&item.exact_inner).map_err(|_| bad)?;
    if scanned.kind != 3 || item.tombstone.is_some() {
        return Err(bad);
    }
    let content =
        g::registry::decode_body(scanned.kind, scanned.body, scanned.layer).map_err(|_| bad)?;
    let Some(g::content::Value::Edit(edit)) = content.value else {
        return Err(bad);
    };
    let edit_identity =
        g::Inner::decode(item.exact_inner.as_slice()).map_err(|_| bad)?.identity.ok_or(bad)?;
    g::identity::verify(&edit_identity).map_err(|_| bad)?;
    let identity = decode_identity(&item.exact_original_identity)?;
    if evidence.canonical_sender_envelope.len() > MAX_OUTER_BYTES
        || evidence.source_authority.is_none()
    {
        return Err(bad);
    }
    let outer: serde_json::Value =
        crate::parse_i_json(&evidence.canonical_sender_envelope).map_err(|_| bad)?;
    if crate::canonical_json_bytes(&outer).map_err(|_| bad)? != evidence.canonical_sender_envelope {
        return Err(bad);
    }
    // Evidence must have no ciphertext key, including an empty one.
    crate::sender_signed_transcript(&outer, crate::SenderTranscriptMode::Evidence)
        .map_err(|_| bad)?;
    let issued_at = outer["created_at"].as_u64().ok_or(bad)?;
    let expires_at = issued_at.checked_add(outer["ttl"].as_u64().ok_or(bad)?).ok_or(bad)?;
    let ext = crate::Ext { ext: serde_json::from_value(outer["ext"].clone()).map_err(|_| bad)? };
    verify_extension(
        &ext,
        1,
        Some(&Header {
            layer: evidence.layer,
            kind: 1,
            exact_identity: &item.exact_original_identity,
            issued_at,
            expires_at,
            group: evidence.group_binding.as_ref(),
        }),
    )?;
    Ok(EditedHeader { identity, edit_identity, edit, original_outer: outer })
}
