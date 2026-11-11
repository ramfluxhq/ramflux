// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Revocation-aware full-data admission. Data grants never authorize publication or sessions.
use crate::{
    CryptoError,
    custody::{VerifiedNodeRecord, VerifiedRecord},
    verify_canonical_signature,
};
use ramflux_protocol::custody::Envelope;
use ramflux_protocol::custody::pairing::{
    PairingWire,
    full_transfer::lease::{DataGrant, DataLease, LeaseRequest, ResumeProof},
};

type Result<T = ()> = std::result::Result<T, CryptoError>;
fn changed() -> CryptoError {
    CryptoError::Pairing("HeadChanged")
}
fn active(
    record: &VerifiedRecord,
    reference: &ramflux_protocol::custody::DeviceRef,
    key: &str,
    now: u64,
) -> Result {
    let cert = record.authorize(reference, "message", now).map_err(|_| changed())?;
    if cert.branch_signing_public_key != key {
        return Err(changed());
    }
    Ok(())
}

/// Verify both original keys against the fresh native owner before J5.
/// A new B can be absent; an existing, reused, removed or revoked ID cannot masquerade as new.
/// # Errors
/// Refuses loss of primary, expired leases, either branch's revocation/key change or reused B.
pub fn verify_full_prepublication_authority(
    grant: &DataGrant,
    current: &VerifiedRecord,
    now: u64,
) -> Result {
    grant.validate()?;
    if grant.expires_at <= now {
        return Err(CryptoError::Pairing("LeaseExpired"));
    }
    let body = &current.envelope().body;
    if body.master_certificate.body.primary_device_ref != grant.source_ref {
        return Err(changed());
    }
    active(current, &grant.source_ref, &grant.branch_keys.source, now)?;
    let destination = &grant.destination_ref;
    if current.revoked_ids().contains(&destination.device_id) {
        return Err(changed());
    }
    if body.devices.iter().any(|d| d.device_id == destination.device_id) {
        active(current, destination, &grant.branch_keys.destination, now)?;
    }
    Ok(())
}

/// A6 DATA-ONLY node relay admission after publication. This never authenticates an
/// endpoint's exact candidate, manifest chain, J6 installation or ordinary authority.
/// # Errors
/// Refuses old roles, removed/revoked refs, changed original branch keys or expired grants.
pub fn verify_full_tail_authority(grant: &DataGrant, current: &VerifiedRecord, now: u64) -> Result {
    grant.validate()?;
    if grant.expires_at <= now {
        return Err(CryptoError::Pairing("LeaseExpired"));
    }
    if current.envelope().body.master_certificate.body.primary_device_ref != grant.destination_ref {
        return Err(changed());
    }
    active(current, &grant.source_ref, &grant.branch_keys.source, now)?;
    active(current, &grant.destination_ref, &grant.branch_keys.destination, now)?;
    Ok(())
}

/// Both endpoints require a full day of remaining data lease before constructing J3.
/// # Errors
/// Refuses expired/short leases and malformed grants before candidate/signing-key creation.
pub fn verify_full_j3_lease_margin(grant: &DataGrant, now: u64) -> Result {
    grant.validate()?;
    if grant.expires_at.checked_sub(now).is_none_or(|remaining| {
        remaining < ramflux_protocol::custody::pairing::full_transfer::MIN_J3_LEASE_SECONDS
    }) {
        return Err(CryptoError::Pairing("LeaseExpired"));
    }
    Ok(())
}

/// Verify both signatures after the caller has checked its saved live original invitation.
/// These signatures alone cannot resurrect an expired invitation or prove local SAS confirmation.
/// # Errors
/// Refuses malformed scope, either missing original branch proof or changed current authority.
pub fn verify_full_lease_request(
    request: &LeaseRequest,
    current: &VerifiedRecord,
    now: u64,
) -> Result {
    request.validate()?;
    verify_full_prepublication_authority(&request.grant, current, now)?;
    if request.grant.expires_at <= now {
        return Err(CryptoError::Pairing("LeaseExpired"));
    }
    for (role, key, signature) in [
        ("initiator", &request.grant.branch_keys.source, &request.source_signature),
        ("responder", &request.grant.branch_keys.destination, &request.destination_signature),
    ] {
        verify_canonical_signature(&request.signing_bytes(role)?, signature, key)
            .map_err(|_| CryptoError::Pairing("WrongContext"))?;
    }
    Ok(())
}

/// Authenticate a data-only node lease against the independently trusted node record.
/// # Errors
/// Refuses expiry, another node, a replacement grant or a bad node signature.
pub fn verify_full_data_lease(
    lease: &Envelope<DataLease>,
    expected: &DataGrant,
    node: &VerifiedNodeRecord,
    now: u64,
) -> Result {
    lease.body.require_live(now)?;
    if lease.signature.len() != 86 {
        return Err(CryptoError::Pairing("WrongContext"));
    }
    let trusted = &node.envelope().body;
    if &lease.body.grant != expected || lease.body.grant.node_id != trusted.node_id {
        return Err(CryptoError::Pairing("WrongContext"));
    }
    verify_canonical_signature(
        &lease.body.signing_bytes()?,
        &lease.signature,
        &trusted.node_signing_public_key,
    )
    .map_err(|_| CryptoError::Pairing("WrongContext"))
}

/// Verify both fresh original-branch possession proofs for one boot-scoped reconnect challenge.
/// Fresh native authority and a still-valid trusted-node lease must be checked on every claim.
/// # Errors
/// Refuses role reflection, stale boot/nonce, key substitution and mismatched fresh epochs.
pub fn verify_full_resume_pair(
    lease: &DataLease,
    source: &Envelope<ResumeProof>,
    destination: &Envelope<ResumeProof>,
    boot_id: &str,
    nonce: &str,
    now: u64,
) -> Result {
    lease.require_live(now)?;
    if source.signature.len() != 86 || destination.signature.len() != 86 {
        return Err(CryptoError::Pairing("WrongContext"));
    }
    source.body.require_peer(&destination.body)?;
    if source.body.role != "initiator"
        || destination.body.role != "responder"
        || source.body.lease_id != lease.lease_id
        || source.body.boot_id != boot_id
        || source.body.nonce != nonce
    {
        return Err(CryptoError::Pairing("WrongContext"));
    }
    for (proof, key) in [
        (source, &lease.grant.branch_keys.source),
        (destination, &lease.grant.branch_keys.destination),
    ] {
        verify_canonical_signature(&proof.body.signing_bytes()?, &proof.signature, key)
            .map_err(|_| CryptoError::Pairing("WrongContext"))?;
    }
    Ok(())
}

/// OVP-01: reconstruct every grant operand from B's own SAS/private bootstrap before signing.
/// # Errors
/// Refuses changed refs/keys/commitment/profile, another pinned node or an invalid expiry.
pub fn verify_full_grant_offer(
    context: &ramflux_protocol::custody::pairing::context_v3::TranscriptV3,
    start: &ramflux_protocol::custody::pairing::full_transfer::relay::StartFull,
    offered: &DataGrant,
    pinned_node_id: &str,
    now: u64,
) -> Result<DataGrant> {
    context.validate()?;
    start.validate()?;
    offered.validate()?;
    let transfer_id = context
        .initiator
        .common
        .transfer_id
        .as_ref()
        .ok_or(CryptoError::Pairing("WrongContext"))?;
    if start.transfer_id != *transfer_id
        || offered.expires_at <= now
        || offered.expires_at
            > now.checked_add(604_800 + 300).ok_or(CryptoError::Pairing("WrongContext"))?
    {
        return Err(CryptoError::Pairing("WrongContext"));
    }
    let expected = DataGrant {
        schema: "ramflux.pairing.full_transfer.data_grant.v1".into(),
        version: 1,
        transfer_id: transfer_id.clone(),
        node_id: pinned_node_id.into(),
        source_ref: context.initiator.device_ref.clone(),
        destination_ref: context.responder.device_ref.clone(),
        branch_keys: ramflux_protocol::custody::pairing::full_transfer::lease::BranchKeys {
            source: context.initiator.branch_key.clone(),
            destination: context.responder.branch_key.clone(),
        },
        opaque_commitment: start.opaque_commitment.clone(),
        expires_at: offered.expires_at,
    };
    if &expected != offered {
        return Err(CryptoError::Pairing("WrongContext"));
    }
    Ok(expected)
}

#[cfg(test)]
mod tests;
