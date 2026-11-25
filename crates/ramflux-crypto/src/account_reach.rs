// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Reach signatures bind a certified primary, exact authority head and monotonic revision.
use crate::{
    CryptoError,
    custody::{SelfSigningKey, VerifiedRecord},
};
use ramflux_protocol::{
    account_reach::{REACH_POLICY_DOMAIN, ReachPolicy, ReachPolicyBody},
    custody::{Envelope, object_hash, signing_bytes},
};

/// Validate a historical policy against the exact authority that signed it.
/// # Errors
/// Refuses malformed revisions, identifiers, substituted authority and invalid signatures.
pub fn verify_reach_policy(
    policy: &ReachPolicy,
    authority: &Envelope<ramflux_protocol::custody::DeviceSet>,
) -> Result<(), CryptoError> {
    let body = &policy.body;
    let certificate = &authority.body.master_certificate;
    let master = crate::verifying_key_from_base64url(&certificate.body.master_public_key)?;
    if crate::identity_root_commitment(&master) != authority.body.account_anchor
        || certificate.body.account_anchor != authority.body.account_anchor
        || certificate.body.principal_id != authority.body.principal_id
    {
        return Err(CryptoError::IdentityAuthority("reach master mismatch"));
    }
    crate::verify_canonical_signature(
        &signing_bytes(ramflux_protocol::domain::CUSTODY_MASTER_CERTIFICATE, &certificate.body)?,
        &certificate.signature,
        &certificate.body.master_public_key,
    )?;
    crate::verify_canonical_signature(
        &signing_bytes(ramflux_protocol::domain::SIGNED_DEVICE_SET_V3, &authority.body)?,
        &authority.signature,
        &certificate.body.self_signing_public_key,
    )?;
    if body.version != 1
        || body.revision == 0
        || body.revision > ramflux_protocol::MAX_SAFE_JSON_INTEGER
        || body.expected_revision.checked_add(1) != Some(body.revision)
        || body.account_anchor != authority.body.account_anchor
        || body.authority_head_hash != object_hash(authority)?
    {
        return Err(CryptoError::IdentityAuthority("reach policy authority or revision mismatch"));
    }
    for value in [&body.home_head_hash, &body.authority_head_hash] {
        let raw = ramflux_protocol::decode_base64url(value)?;
        if raw.len() != 32 || ramflux_protocol::encode_base64url(&raw) != *value {
            return Err(CryptoError::IdentityAuthority("invalid reach identifier"));
        }
    }
    if body.operation_id.is_empty()
        || body.operation_id.len() > 256
        || body.operation_id.chars().any(char::is_control)
    {
        return Err(CryptoError::IdentityAuthority("invalid reach operation"));
    }
    crate::verify_canonical_signature(
        &signing_bytes(REACH_POLICY_DOMAIN, body)?,
        &policy.signature,
        &authority.body.master_certificate.body.self_signing_public_key,
    )
}

impl SelfSigningKey {
    /// Sign an exact policy using the current certified management authority.
    /// # Errors
    /// Refuses unrelated signers, malformed fields and mismatched current authority.
    pub fn sign_reach_policy(
        &self,
        current: &VerifiedRecord,
        body: ReachPolicyBody,
    ) -> Result<ReachPolicy, CryptoError> {
        let authority = current.envelope();
        if self.public_key() != authority.body.master_certificate.body.self_signing_public_key {
            return Err(CryptoError::IdentityAuthority("reach signer mismatch"));
        }
        let policy = Envelope {
            signature: crate::sign_canonical_bytes_with_seed(
                &signing_bytes(REACH_POLICY_DOMAIN, &body)?,
                *self.vault_seed(),
            ),
            body,
        };
        verify_reach_policy(&policy, authority)?;
        Ok(policy)
    }
}
