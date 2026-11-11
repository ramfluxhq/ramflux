// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Revocation-aware full-data admission. Data grants never authorize publication or sessions.
use crate::{
    CryptoError,
    custody::{VerifiedNodeRecord, VerifiedRecord},
    verify_canonical_signature,
};
use ramflux_protocol::custody::pairing::{
    PairingWire,
    full_transfer::lease::{DataGrant, DataLease, LeaseRequest, ResumeProof},
};
use ramflux_protocol::custody::{Envelope, object_hash};

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

/// Independently check the exact published candidate and fresh native head for tail continuation.
/// `expected_candidate_hash` comes from the durable publication owner, never a relay hint.
/// # Errors
/// Refuses a different publication, source removal, changed keys or loss of B's primary role.
pub fn verify_full_tail_authority(
    grant: &DataGrant,
    published: &VerifiedRecord,
    expected_candidate_hash: &str,
    current: &VerifiedRecord,
    now: u64,
) -> Result {
    grant.validate()?;
    if grant.expires_at <= now {
        return Err(CryptoError::Pairing("LeaseExpired"));
    }
    if object_hash(published.envelope())? != expected_candidate_hash {
        return Err(changed());
    }
    for (authority, at) in [(published, published.envelope().body.issued_at), (current, now)] {
        if authority.envelope().body.master_certificate.body.primary_device_ref
            != grant.destination_ref
        {
            return Err(changed());
        }
        active(authority, &grant.source_ref, &grant.branch_keys.source, at)?;
        active(authority, &grant.destination_ref, &grant.branch_keys.destination, at)?;
    }
    if current.envelope().body.device_set_epoch < published.envelope().body.device_set_epoch {
        return Err(changed());
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

#[cfg(test)]
mod tests;
