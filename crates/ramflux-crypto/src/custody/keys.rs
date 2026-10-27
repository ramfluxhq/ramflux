// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Separate offline-master and primary self-signing capabilities.
use super::RecoveryPhrase;
use crate::CryptoError;
use ed25519_dalek::{Signer, SigningKey};
use hkdf::Hkdf;
use ramflux_protocol::{custody, domain, encode_base64url};
use sha2::Sha256;
use std::fmt;
use zeroize::Zeroizing;

/// Ephemeral offline authority. It cannot sign a device set or arbitrary bytes.
pub struct MasterKey(SigningKey);
impl fmt::Debug for MasterKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MasterKey(<redacted>)")
    }
}
impl MasterKey {
    /// Derive the exact master seed with zero salt, entropy IKM and the bare v1 info label.
    /// # Errors
    /// Returns a derivation/provider failure without including recovery material.
    pub fn from_phrase(phrase: &RecoveryPhrase) -> Result<Self, CryptoError> {
        let entropy = phrase.entropy();
        if entropy.len() != 32 {
            return Err(CryptoError::IdentityAuthority("recovery entropy length"));
        }
        let mut seed = Zeroizing::new([0_u8; 32]);
        Hkdf::<Sha256>::new(Some(&[0_u8; 32]), &entropy)
            .expand(domain::CUSTODY_MASTER_SEED.as_bytes(), &mut *seed)
            .map_err(|_| CryptoError::HkdfFailed)?;
        Ok(Self(SigningKey::from_bytes(&seed)))
    }
    #[must_use]
    pub fn public_key(&self) -> String {
        encode_base64url(self.0.verifying_key().to_bytes())
    }
    /// Bind one fresh primary signing key to its certified range.
    /// # Errors
    /// Rejects a mismatched master, malformed certificate or serialization failure.
    pub fn certify(
        &self,
        body: custody::MasterCertificate,
    ) -> Result<custody::Envelope<custody::MasterCertificate>, CryptoError> {
        if body.master_public_key != self.public_key() {
            return Err(CryptoError::IdentityAuthority("master key mismatch"));
        }
        super::validate::master_body(&body)?;
        let bytes = custody::signing_bytes(domain::CUSTODY_MASTER_CERTIFICATE, &body)?;
        let envelope =
            custody::Envelope { body, signature: encode_base64url(self.0.sign(&bytes).to_bytes()) };
        if ramflux_protocol::canonical_json_bytes(&envelope)?.len() > 8192 {
            return Err(CryptoError::IdentityAuthority("master certificate byte budget exceeded"));
        }
        Ok(envelope)
    }
}
/// Primary management authority, kept independently of data/branch credentials.
pub struct SelfSigningKey(SigningKey);
impl fmt::Debug for SelfSigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SelfSigningKey(<redacted>)")
    }
}
impl SelfSigningKey {
    /// Create a fresh random primary key. Storage belongs exclusively to a custody vault provider.
    /// # Errors
    /// Returns a randomness failure.
    pub fn generate() -> Result<Self, CryptoError> {
        let seed = super::random_secret()?;
        Ok(Self(SigningKey::from_bytes(&seed)))
    }
    /// Load a provider-owned zeroizing seed; callers must not persist it in manifests or backups.
    #[must_use]
    pub fn from_vault_seed(seed: &Zeroizing<[u8; 32]>) -> Self {
        Self(SigningKey::from_bytes(seed))
    }
    /// Transfer a zeroizing seed directly to a primary-only vault provider.
    #[must_use]
    pub fn vault_seed(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.0.to_bytes())
    }
    #[must_use]
    pub fn public_key(&self) -> String {
        encode_base64url(self.0.verifying_key().to_bytes())
    }
    pub(crate) fn sign_group_state_bytes(&self, bytes: &[u8]) -> String {
        encode_base64url(self.0.sign(bytes).to_bytes())
    }
    /// Certify branch keys with explicit operation scopes and a bounded lease.
    /// # Errors
    /// Rejects malformed certificate data or canonical serialization failures.
    pub fn certify_branch(
        &self,
        body: custody::BranchCertificate,
    ) -> Result<custody::Envelope<custody::BranchCertificate>, CryptoError> {
        super::validate::branch_body(&body)?;
        let bytes = custody::signing_bytes(domain::CUSTODY_BRANCH_CERTIFICATE, &body)?;
        Ok(custody::Envelope { body, signature: encode_base64url(self.0.sign(&bytes).to_bytes()) })
    }
    /// Sign one exact home move with current primary and branch authority.
    /// The vault/provider must enforce user presence before handing out this key.
    /// # Errors
    /// Rejects a stale/wrong manager, actor mismatch and invalid authorization bounds.
    pub fn sign_home_authorization(
        &self,
        body: ramflux_protocol::home_migration::Authorization,
        actor: &crate::DeviceBranch,
        authority: &super::VerifiedRecord,
        now: u64,
    ) -> Result<
        ramflux_protocol::home_migration::Signed<ramflux_protocol::home_migration::Authorization>,
        CryptoError,
    > {
        let signers = crate::home_migration::authorization_signers(&body, authority, now)?;
        if actor.device_id != body.actor.device_id
            || actor.device_epoch != body.actor.device_epoch
            || actor.principal_id != authority.envelope().body.principal_id
        {
            return Err(super::validate::reject("migration actor ownership mismatch"));
        }
        crate::home_migration::sign_with_keys(body, signers, &[&self.0, &actor.signing_key])
    }

    /// Publish a complete typed device set; never invoke a generic root-signing path.
    /// # Errors
    /// Rejects an unrelated signer, invalid sections, or canonical serialization failures.
    pub fn sign_record(
        &self,
        mut body: custody::DeviceSet,
    ) -> Result<custody::Envelope<custody::DeviceSet>, CryptoError> {
        if body.master_certificate.body.self_signing_public_key != self.public_key() {
            return Err(CryptoError::IdentityAuthority("self-signing key mismatch"));
        }
        body.section_hashes = custody::section_hashes(&body)?;
        super::validate::record_structure(&body)?;
        let bytes = custody::signing_bytes(domain::SIGNED_DEVICE_SET_V3, &body)?;
        let envelope =
            custody::Envelope { body, signature: encode_base64url(self.0.sign(&bytes).to_bytes()) };
        if ramflux_protocol::canonical_json_bytes(&envelope)?.len() > custody::MAX_RECORD_BYTES {
            return Err(CryptoError::IdentityAuthority("custody record byte budget exceeded"));
        }
        Ok(envelope)
    }
}

impl SelfSigningKey {
    /// Approve consent under the current certified management key for this exact sending branch.
    /// Callers must enforce current durable head pins before invoking this operation.
    /// # Errors
    /// Rejects unrelated authority, wrong hashes/endpoints, invalid branch leases and body data.
    pub fn sign_contact_consent(
        &self,
        current: &super::VerifiedRecord,
        body: custody::ContactConsentV2,
        now: u64,
    ) -> Result<custody::Envelope<custody::ContactConsentV2>, CryptoError> {
        super::contact::validate_authority(&body, current, current, &body.sending_device_ref, now)?;
        if self.public_key()
            != current.envelope().body.master_certificate.body.self_signing_public_key
        {
            return Err(super::validate::reject(
                "contact consent requires certified primary signer",
            ));
        }
        let bytes = custody::signing_bytes(domain::CONTACT_REQUEST_V2, &body)?;
        Ok(custody::Envelope {
            body,
            signature: ramflux_protocol::encode_base64url(self.0.sign(&bytes).to_bytes()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn hkdf_seed_matches_the_independent_vector_without_a_production_seed_export()
    -> Result<(), Box<dyn std::error::Error>> {
        let vector: serde_json::Value =
            serde_json::from_str(include_str!("../../tests/fixtures/custody_v3.json"))?;
        let phrase = RecoveryPhrase::from_entropy(&[0; 32])?;
        let key = MasterKey::from_phrase(&phrase)?;
        assert_eq!(hex::encode(key.0.to_bytes()), vector["master_seed_hex"]);
        assert_eq!(key.public_key(), vector["master_public_key"]);
        Ok(())
    }
}
