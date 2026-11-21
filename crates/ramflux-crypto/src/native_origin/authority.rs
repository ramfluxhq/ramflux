// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Original custody and branch-signature authority, independent of local adoption.
use ramflux_protocol::message::{self as g, original_header::EvidenceError};
use serde_json::Value;

/// Original public author coordinates; native authorization still requires its signed evidence.
pub struct Author {
    pub root: String,
    pub device: crate::RootQualifiedDeviceRef,
}

/// Verify the original author against signed custody and the exact sender transcript.
/// # Errors
/// Refuses malformed evidence, unauthorized authors and invalid original signatures.
pub fn authority(
    outer: &Value,
    manifest: &g::NativeCustodyManifest,
    identity: &g::EventIdentity,
) -> Result<Author, EvidenceError> {
    let bad = EvidenceError::OriginCommitmentMismatch;
    let manifest: ramflux_protocol::custody::CustodyManifest =
        ramflux_protocol::custody::decode(&manifest.canonical, 5 * 1024 * 1024).map_err(|_| bad)?;
    let issued = outer["created_at"].as_u64().ok_or(bad)?;
    let verified = verify_public_authority(
        &manifest.publication,
        manifest.custodian_publication.as_ref(),
        issued,
    )
    .map_err(|_| bad)?;
    let root = &verified.envelope().body.account_anchor;
    let author = identity.author.as_ref().ok_or(bad)?;
    if author.account_anchor != *root
        || outer["source_device_id"].as_str() != Some(author.device_id.as_str())
        || outer["source_principal_id"].as_str()
            != Some(verified.envelope().body.principal_id.as_str())
        || outer["ext"]["source_root_commitment"].as_str() != Some(root.as_str())
    {
        return Err(bad);
    }
    let device = ramflux_protocol::custody::DeviceRef {
        account_anchor: root.clone(),
        device_id: author.device_id.clone(),
        device_epoch: author.device_epoch,
    };
    let certified = verified.authorize(&device, "message", issued).map_err(|_| bad)?;
    if identity.group_id.is_some() {
        verified.authorize(&device, "group", issued).map_err(|_| bad)?;
    }
    ramflux_protocol::verify_sender_signature(
        outer,
        ramflux_protocol::SenderTranscriptMode::Evidence,
        &certified.branch_signing_public_key,
    )
    .map_err(|_| bad)?;
    Ok(Author {
        root: root.clone(),
        device: crate::RootQualifiedDeviceRef::from_custody_record(&verified, &author.device_id)
            .map_err(|_| bad)?,
    })
}

/// Verify immutable publication evidence without reading or adopting any local pins.
/// # Errors
/// Refuses invalid custody chains, signatures, lifetimes or compacted-id commitments.
pub fn verify_public_authority(
    publication: &ramflux_protocol::custody::Publication,
    custodian: Option<&ramflux_protocol::custody::Publication>,
    now: u64,
) -> Result<crate::custody::VerifiedRecord, crate::CryptoError> {
    let human = custodian
        .map(|p| crate::custody::verify_record(&p.record, now, p.compacted_ids.as_deref(), None))
        .transpose()?;
    crate::custody::verify_record(
        &publication.record,
        now,
        publication.compacted_ids.as_deref(),
        human.as_ref(),
    )
}
