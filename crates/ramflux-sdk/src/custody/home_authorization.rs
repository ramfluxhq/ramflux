// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! A single purpose-bound management signature, never a generic digest-signing API.
use crate::SdkError;
use ramflux_crypto::{
    DeviceBranch,
    custody::{SelfSigningKey, VerifiedRecord},
};
use ramflux_protocol::{
    custody::{CustodyKind, object_hash},
    home_migration::{Authorization, Refusal, Signed},
};

pub(crate) fn refused(reason: Refusal) -> SdkError {
    SdkError::HomeMigrationRefused(reason)
}
pub(crate) fn unavailable() -> SdkError {
    refused(Refusal::CustodyUserPresenceUnavailable)
}
pub(crate) fn proposal_digest(body: &Authorization) -> Result<String, SdkError> {
    Ok(ramflux_protocol::custody::framed_hash("ramflux.sdk.home_migration.proposal.v1", body)?)
}
#[cfg(target_os = "macos")]
pub(crate) fn now() -> Result<u64, SdkError> {
    Ok(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| unavailable())?
        .as_secs())
}

/// Provider request built only from the SDK's stored, verified pending proposal.
/// It is not deserializable or clonable and grants no reusable management key.
pub struct HomeAuthorizationRequest<'a> {
    local_account_id: &'a str,
    pub(crate) reference: &'a str,
    body: &'a Authorization,
    branch: &'a DeviceBranch,
    authority: &'a VerifiedRecord,
    digest: String,
    pub(crate) requested_at: u64,
}
#[derive(Clone, Copy)]
pub(crate) struct HomeAuthorizationInput<'a, 'd> {
    pub local_account_id: &'a str,
    pub reference: &'a str,
    pub body: &'a Authorization,
    pub branch: &'a DeviceBranch,
    pub authority: &'a VerifiedRecord,
    pub digest: &'d str,
    pub now: u64,
}
impl<'a> HomeAuthorizationRequest<'a> {
    pub(crate) fn new(input: HomeAuthorizationInput<'a, '_>) -> Result<Self, SdkError> {
        let HomeAuthorizationInput {
            local_account_id,
            reference,
            body,
            branch,
            authority,
            digest,
            now,
        } = input;
        let expected = proposal_digest(body)?;
        if digest != expected
            || local_account_id.is_empty()
            || reference.is_empty()
            || reference.len() > 256
            || reference.chars().any(char::is_control)
        {
            return Err(refused(Refusal::CustodyApprovalRequired));
        }
        let request = Self {
            local_account_id,
            reference,
            body,
            branch,
            authority,
            digest: expected,
            requested_at: now,
        };
        request.validate(now)?;
        Ok(request)
    }
    fn validate(&self, now: u64) -> Result<(), SdkError> {
        let now = now.max(self.requested_at);
        let record = self.authority.envelope();
        if record.body.principal_kind != ramflux_protocol::PrincipalKind::Human
            || record.body.master_certificate.body.custody_kind != CustodyKind::LocalHuman
        {
            return Err(refused(Refusal::CustodyApprovalRequired));
        }
        if object_hash(record)? != self.body.authority_record_hash
            || object_hash(&record.body.master_certificate)?
                != self.body.management_certificate_hash
            || record.body.account_anchor != self.body.account_anchor
        {
            return Err(refused(Refusal::AuthorityUpdateRequired));
        }
        if now > self.body.seal_until {
            return Err(refused(Refusal::AdmissionExpired));
        }
        ramflux_crypto::home_migration::authorization_bounds(self.body, now)?;
        self.authority.authorize(&self.body.actor, "register", now)?;
        Ok(())
    }
    #[must_use]
    pub fn proposal_digest(&self) -> &str {
        &self.digest
    }
    #[must_use]
    pub fn primary_reference(&self) -> &str {
        self.reference
    }
    #[must_use]
    pub fn local_account_id(&self) -> &str {
        self.local_account_id
    }
    #[must_use]
    pub fn request_id(&self) -> &str {
        &self.body.migration_id
    }
    #[must_use]
    pub fn destination_fingerprint(&self) -> String {
        ramflux_protocol::hash_hex(
            ramflux_protocol::CLIENT_DISCOVERY_DOMAIN,
            self.body.destination_key.as_bytes(),
        )
    }
    #[must_use]
    pub fn previous_home_hash(&self) -> &str {
        &self.body.previous_home_hash
    }
    #[must_use]
    pub const fn next_home_epoch(&self) -> u64 {
        self.body.next_home_epoch
    }
    #[must_use]
    pub fn expected_primary_public_key(&self) -> &str {
        &self.authority.envelope().body.master_certificate.body.self_signing_public_key
    }
    /// Complete exactly this request after the provider has enforced OS presence.
    /// # Errors
    /// Rejects expired approval, stale authority, another primary and invalid actor keys.
    pub fn sign_once(
        self,
        primary: &SelfSigningKey,
        now: u64,
    ) -> Result<Signed<Authorization>, SdkError> {
        let now = now.max(self.requested_at);
        let current = Self::new(HomeAuthorizationInput {
            local_account_id: self.local_account_id,
            reference: self.reference,
            body: self.body,
            branch: self.branch,
            authority: self.authority,
            digest: &self.digest,
            now,
        })?;
        Ok(primary.sign_home_authorization(
            current.body.clone(),
            current.branch,
            current.authority,
            now,
        )?)
    }
}
