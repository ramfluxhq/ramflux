// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Historical object authentication has no current-authority result or pin side effects.
use super::{CryptoError, Signed, custody, manager, reject, verify, wire};

fn selected(
    proof: &wire::ProvenanceAuthority,
    root: &str,
    head: &str,
    certificate: &str,
    issued_at: u64,
) -> Result<crate::custody::VerifiedRecord, CryptoError> {
    proof.validate()?;
    let tuple = &proof.authority;
    let record = &tuple.publication.record;
    if record.body.account_anchor != root
        || custody::object_hash(record)? != head
        || custody::object_hash(&record.body.master_certificate)? != certificate
        || record.body.issued_at > issued_at
        || record.body.master_certificate.body.issued_at > issued_at
    {
        return Err(reject("historical recipient signer selector or time"));
    }
    if let Some(human) = &tuple.custodian_publication
        && (human.record.body.issued_at > issued_at
            || human.record.body.master_certificate.body.issued_at > issued_at)
    {
        return Err(reject("historical custodian was issued after object"));
    }
    if record.body.master_certificate.body.custody_kind == custody::CustodyKind::LocalHuman
        && !proof.custodian_history.is_empty()
    {
        return Err(reject("unsolicited local historical closure"));
    }
    // Transition closure needs its complete native home evidence. Never treat a list of
    // individually valid publications as proof of an unresolved transition relation.
    if !proof.custodian_history.is_empty() {
        return Err(reject("historical transition reconciliation pending"));
    }
    crate::custody::verify_publication(tuple, issued_at)
}
/// Authenticate only this original policy at its original signing time.
/// # Errors
/// Refuses missing/substituted native history, original role, lease or signature failures.
pub fn verify_historical_policy(
    update: &Signed<wire::ReachPolicy>,
    proof: &wire::ProvenanceAuthority,
) -> Result<(), CryptoError> {
    let b = &update.body;
    b.validate()?;
    let authority = selected(
        proof,
        &b.account_anchor,
        &b.authority_head_hash,
        &b.master_certificate_hash,
        b.issued_at,
    )?;
    manager(
        &authority,
        &b.actor,
        &b.account_anchor,
        &b.authority_head_hash,
        &b.master_certificate_hash,
        b.issued_at,
    )?;
    verify(
        wire::POLICY_DOMAIN,
        update,
        &authority.envelope().body.master_certificate.body.self_signing_public_key,
    )
}
/// Authenticate only this original admission; this never checks or grants present use.
/// # Errors
/// Refuses bad native history, original actor capability and signature/selector substitution.
pub fn verify_historical_admission(
    update: &Signed<wire::Admission>,
    proof: &wire::ProvenanceAuthority,
) -> Result<(), CryptoError> {
    let b = &update.body;
    b.validate()?;
    let authority = selected(
        proof,
        &b.recipient_root,
        &b.authority_head_hash,
        &b.master_certificate_hash,
        b.issued_at,
    )?;
    manager(
        &authority,
        &b.actor,
        &b.recipient_root,
        &b.authority_head_hash,
        &b.master_certificate_hash,
        b.issued_at,
    )?;
    verify(
        wire::ADMISSION_DOMAIN,
        update,
        &authority.envelope().body.master_certificate.body.self_signing_public_key,
    )
}
/// Authenticate a header using its own independently selected signer, never the grant signer.
/// # Errors
/// Refuses missing selectors, invalid historical management role or an altered original header.
pub fn verify_historical_roster_header(
    header: &Signed<wire::GroupRosterHeader>,
    proof: &wire::ProvenanceAuthority,
) -> Result<(), CryptoError> {
    let b = &header.body;
    b.validate()?;
    let authority = selected(
        proof,
        &b.recipient_root,
        &b.authority_head_hash,
        &b.master_certificate_hash,
        b.issued_at,
    )?;
    let cert = &authority.envelope().body.master_certificate.body;
    manager(
        &authority,
        &cert.primary_device_ref,
        &b.recipient_root,
        &b.authority_head_hash,
        &b.master_certificate_hash,
        b.issued_at,
    )?;
    verify(wire::GROUP_ROSTER_DOMAIN, header, &cert.self_signing_public_key)
}
