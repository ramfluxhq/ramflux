// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! OV-EDIT-HISTORY: a signed commitment to the original header, never its body.
use super::{EventIdentity, OriginalGroupBinding, identity::lp, registry, validation};
use prost::Message as _;
pub mod edited;

/// Signed outer extension, required exactly on Message outers.
pub const EXT_KEY: &str = "message_metadata_commitment";
/// Bound on retained deterministic `EventIdentity` bytes.
pub const MAX_IDENTITY_BYTES: usize = 1024;
/// Bound on retained body-free original signed outer bytes.
pub const MAX_OUTER_BYTES: usize = 8192;

/// Stable per-item refusal reasons. A failed item grants no retention or projection.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum EvidenceError {
    /// A Message lacks required original evidence.
    #[error("OriginEvidenceMissing")]
    OriginEvidenceMissing,
    /// A commitment, canonical encoding, header or resource bound is invalid.
    #[error("OriginCommitmentMismatch")]
    OriginCommitmentMismatch,
    /// The Edit targets a different original identity or conversation.
    #[error("EditTargetMismatch")]
    EditTargetMismatch,
    /// Independently verified author roots differ.
    #[error("EditAuthorMismatch")]
    EditAuthorMismatch,
    /// Editing retired the original report opening.
    #[error("ReportOpeningRetired")]
    ReportOpeningRetired,
}

/// Original non-secret preimage. No original Message body field belongs here.
pub struct Header<'a> {
    pub layer: u32,
    pub kind: u32,
    pub exact_identity: &'a [u8],
    pub issued_at: u64,
    pub expires_at: u64,
    pub group: Option<&'a OriginalGroupBinding>,
}

/// Decode deterministic identity bytes with no unknown fields or alternate encodings.
/// # Errors
/// Refuses missing, oversized, unsupported, noncanonical or invalid identities.
pub fn decode_identity(bytes: &[u8]) -> Result<EventIdentity, EvidenceError> {
    let bad = EvidenceError::OriginCommitmentMismatch;
    if bytes.is_empty() || bytes.len() > MAX_IDENTITY_BYTES {
        return Err(bad);
    }
    if validation::scan_message("EventIdentity", bytes, registry::COMPILED_LAYER)
        .map_err(|_| bad)?
        != validation::ScanOutcome::Supported
    {
        return Err(bad);
    }
    let identity = EventIdentity::decode(bytes).map_err(|_| bad)?;
    if identity.encode_to_vec() != bytes {
        return Err(bad);
    }
    super::identity::verify(&identity).map_err(|_| bad)?;
    Ok(identity)
}

fn group_bytes(
    identity: &EventIdentity,
    group: Option<&OriginalGroupBinding>,
) -> Result<Vec<u8>, EvidenceError> {
    let bad = EvidenceError::OriginCommitmentMismatch;
    let mut bytes = Vec::new();
    match (identity.group_id.as_deref(), group) {
        (None, None) if identity.group_epoch.is_none() => (),
        (Some(id), Some(group))
            if !id.is_empty()
                && id == group.group_id
                && group.author == identity.author
                && group.key_epoch != 0
                && identity.group_epoch == Some(group.key_epoch)
                && group.group_state_hash.len() == 32 =>
        {
            for field in [
                id.as_bytes().to_vec(),
                group.author.as_ref().ok_or(bad)?.encode_to_vec(),
                group.key_epoch.to_be_bytes().to_vec(),
                group.group_state_hash.clone(),
            ] {
                lp(&mut bytes, &field).map_err(|_| bad)?;
            }
        }
        _ => return Err(bad),
    }
    Ok(bytes)
}

/// Exact LP(domain)-framed BLAKE3 transcript, shared by send, receipt and history.
/// # Errors
/// Refuses any header that cannot be an original durable Message.
pub fn transcript(header: &Header<'_>) -> Result<Vec<u8>, EvidenceError> {
    let bad = EvidenceError::OriginCommitmentMismatch;
    if header.layer == 0 || header.kind != 1 || header.expires_at <= header.issued_at {
        return Err(bad);
    }
    let identity = decode_identity(header.exact_identity)?;
    let group = group_bytes(&identity, header.group)?;
    let mut bytes = Vec::new();
    for field in [
        crate::domain::MESSAGE_ORIGINAL_HEADER.as_bytes(),
        &header.layer.to_be_bytes(),
        &header.kind.to_be_bytes(),
        header.exact_identity,
        &header.issued_at.to_be_bytes(),
        &header.expires_at.to_be_bytes(),
        &group,
    ] {
        lp(&mut bytes, field).map_err(|_| bad)?;
    }
    Ok(bytes)
}

/// Canonical unpadded base64url of the raw 32-byte header digest.
/// # Errors
/// Refuses invalid preimages.
pub fn commitment(header: &Header<'_>) -> Result<String, EvidenceError> {
    Ok(crate::encode_base64url(blake3::hash(&transcript(header)?).as_bytes()))
}

/// Check the required extension after C, before projection or Unsupported retention.
/// # Errors
/// Refuses omission, wrong kind, malformed encoding and any mismatch.
pub fn verify_extension(
    ext: &crate::Ext,
    kind: u32,
    header: Option<&Header<'_>>,
) -> Result<(), EvidenceError> {
    let value = ext.ext.get(EXT_KEY);
    if kind != 1 {
        return if value.is_none() { Ok(()) } else { Err(EvidenceError::OriginCommitmentMismatch) };
    }
    let value = value.ok_or(EvidenceError::OriginEvidenceMissing)?;
    let encoded = value.as_str().ok_or(EvidenceError::OriginCommitmentMismatch)?;
    let raw =
        crate::decode_base64url(encoded).map_err(|_| EvidenceError::OriginCommitmentMismatch)?;
    if raw.len() != 32
        || crate::encode_base64url(&raw) != encoded
        || commitment(header.ok_or(EvidenceError::OriginEvidenceMissing)?)? != encoded
    {
        return Err(EvidenceError::OriginCommitmentMismatch);
    }
    Ok(())
}

/// Borrow the exact deterministic identity field, without dropping unknown fields on decode.
/// # Errors
/// Refuses missing, duplicate, noncanonical and unsupported identities.
pub fn exact_identity(bytes: &[u8]) -> Result<&[u8], EvidenceError> {
    let bad = EvidenceError::OriginCommitmentMismatch;
    let mut input = bytes;
    let mut identity = None;
    while !input.is_empty() {
        let field = super::wire::field(&mut input).map_err(|_| bad)?;
        if field.tag == 3 {
            if field.wire != 2 || identity.is_some() {
                return Err(bad);
            }
            identity = Some(field.bytes);
        }
    }
    let identity = identity.ok_or(bad)?;
    decode_identity(identity)?;
    Ok(identity)
}

/// The sole retained group-wrapper projection. It contains no body commitments or key material.
#[must_use]
pub fn group_binding(group: &super::GroupSealedContent) -> OriginalGroupBinding {
    OriginalGroupBinding {
        group_id: group.group_id.clone(),
        author: group.author.clone(),
        key_epoch: group.key_epoch,
        group_state_hash: group.group_state_hash.clone(),
    }
}

/// Derive a Message outer commitment from the original exact Inner, ignoring all body fields.
/// # Errors
/// Refuses invalid identities, times, wrappers and noncanonical encodings.
pub fn for_inner(
    bytes: &[u8],
    issued_at: u64,
    expires_at: u64,
) -> Result<Option<String>, EvidenceError> {
    let bad = EvidenceError::OriginCommitmentMismatch;
    let scanned = validation::scan_inner(bytes).map_err(|_| bad)?;
    if scanned.kind != 1 {
        return Ok(None);
    }
    let identity = exact_identity(bytes)?;
    let message = super::Message::decode(scanned.body).map_err(|_| bad)?;
    let group = message.sealed_group.as_ref().map(group_binding);
    commitment(&Header {
        layer: scanned.layer,
        kind: scanned.kind,
        exact_identity: identity,
        issued_at,
        expires_at,
        group: group.as_ref(),
    })
    .map(Some)
}

/// Receipt-time presence and equality rule for every known Message outer.
/// # Errors
/// Refuses missing, malformed or mismatching commitments, including a key on another kind.
pub fn verify_inner_extension(
    ext: &crate::Ext,
    bytes: &[u8],
    issued_at: u64,
    expires_at: u64,
) -> Result<(), EvidenceError> {
    let expected = for_inner(bytes, issued_at, expires_at)?;
    match (expected, ext.ext.get(EXT_KEY)) {
        (None, None) => Ok(()),
        (Some(expected), Some(serde_json::Value::String(encoded))) if *encoded == expected => {
            Ok(())
        }
        (Some(_), None) => Err(EvidenceError::OriginEvidenceMissing),
        _ => Err(EvidenceError::OriginCommitmentMismatch),
    }
}

#[cfg(test)]
mod tests;
