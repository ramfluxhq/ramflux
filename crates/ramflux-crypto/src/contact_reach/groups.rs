// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Roster headers use the same certified everyday primary authority as group consent.
use super::{
    CryptoError, SelfSigningKey, Signed, SigningKey, VerifiedRecord, custody, manager, reject,
    sign, verify, verify_retained_admission, wire,
};
/// Authenticate derived bookkeeping against the current primary and exact live grant.
/// # Errors
/// Refuses changed grants, stale/revoked primary authority, future headers and bad signatures.
pub fn verify_group_roster(
    roster: &wire::GroupRoster,
    grant: &Signed<wire::Admission>,
    authority: &VerifiedRecord,
    now: u64,
) -> Result<(), CryptoError> {
    roster.validate(grant)?;
    verify_retained_admission(grant, authority, now)?;
    if roster.header.body.master_certificate_hash
        != custody::object_hash(&authority.envelope().body.master_certificate)?
        || roster.header.body.recipient_root != authority.envelope().body.account_anchor
        || roster.header.body.issued_at
            > now.checked_add(60).ok_or_else(|| reject("roster clock overflow"))?
    {
        return Err(reject("roster primary or time mismatch"));
    }
    verify(
        wire::GROUP_ROSTER_DOMAIN,
        &roster.header,
        &authority.envelope().body.master_certificate.body.self_signing_public_key,
    )
}
/// Verify a new roster command against its exact independently current signing context.
/// # Errors
/// Refuses stale signed selectors, backdated authority and all live roster failures.
pub fn verify_group_roster_command(
    roster: &wire::GroupRoster,
    grant: &Signed<wire::Admission>,
    authority: &VerifiedRecord,
    now: u64,
) -> Result<(), CryptoError> {
    if roster.header.body.authority_head_hash != custody::object_hash(authority.envelope())? {
        return Err(reject("roster command current head mismatch"));
    }
    super::original_management_time(
        authority,
        &authority.envelope().body.master_certificate.body.primary_device_ref,
        roster.header.body.issued_at,
    )?;
    verify_group_roster(roster, grant, authority, now)
}
/// Verify every original witness in a group retirement; witness grants authorize nothing.
/// Missing historical signer evidence must stay pending, never become an empty denial.
/// # Errors
/// Refuses altered floors, signatures, header/grant links and unavailable signer authority.
pub fn verify_group_retirement(
    update: &Signed<wire::Admission>,
    floor: &wire::GroupFloor,
    authority: &VerifiedRecord,
    now: u64,
) -> Result<(), CryptoError> {
    floor.validate(update)?;
    verify_retained_admission(update, authority, now)?;
    if let Some(grant) = &floor.grant {
        verify_retained_admission(grant, authority, now)?;
    }
    if let Some(control) = &floor.block_control {
        verify_retained_admission(control, authority, now)?;
    }
    if let Some(header) = &floor.roster_header {
        if header.body.issued_at
            > now.checked_add(60).ok_or_else(|| reject("retirement clock overflow"))?
        {
            return Err(reject("retirement roster header is from the future"));
        }
        verify(
            wire::GROUP_ROSTER_DOMAIN,
            header,
            &authority.envelope().body.master_certificate.body.self_signing_public_key,
        )?;
    }
    Ok(())
}
impl SelfSigningKey {
    /// Sign derived roster bookkeeping only with the account's certified primary management key.
    /// The SDK constructs members from its adopted signed group head before calling this.
    /// # Errors
    /// Refuses malformed headers, unrelated keys and unavailable current primary authority.
    pub fn sign_group_roster_header(
        &self,
        body: wire::GroupRosterHeader,
        authority: &VerifiedRecord,
        now: u64,
    ) -> Result<Signed<wire::GroupRosterHeader>, CryptoError> {
        body.validate()?;
        super::original_management_time(
            authority,
            &authority.envelope().body.master_certificate.body.primary_device_ref,
            body.issued_at,
        )?;
        let cert = &authority.envelope().body.master_certificate.body;
        manager(
            authority,
            &cert.primary_device_ref,
            &body.recipient_root,
            &body.authority_head_hash,
            &body.master_certificate_hash,
            now,
        )?;
        if self.public_key() != cert.self_signing_public_key
            || body.issued_at
                > now.checked_add(60).ok_or_else(|| reject("roster clock overflow"))?
        {
            return Err(reject("roster signer or clock mismatch"));
        }
        sign(wire::GROUP_ROSTER_DOMAIN, body, &SigningKey::from_bytes(&self.vault_seed()))
    }
}
