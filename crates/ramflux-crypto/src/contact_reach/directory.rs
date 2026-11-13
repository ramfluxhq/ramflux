// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Everyday account-certified directory signatures and independently distributed centre pins.
use super::{manager, reject, sign, verify};
use crate::{
    CryptoError,
    custody::{SelfSigningKey, VerifiedRecord},
};
use ed25519_dalek::SigningKey;
use ramflux_protocol::{
    contact_reach::{
        self as reach,
        directory::{
            BINDING_DOMAIN, Binding, CENTRE_ROTATION_DOMAIN, CentreManifest, CentrePin,
            CentreRotation, IndexResolve, NameOperation, OPERATION_DOMAIN, PROFILE_DOMAIN, Profile,
            RESOLVE_DOMAIN,
        },
    },
    custody::{self, Envelope as Signed},
};

/// Pinned centre authority. Only a locally supplied distribution manifest creates it.
#[derive(Clone, Debug)]
pub struct PinnedCentre {
    pin: CentrePin,
}
impl PinnedCentre {
    /// Select an exact build-distributed pin; no response can install a centre key.
    /// # Errors
    /// Refuses missing, ambiguous or malformed pins and non-HTTPS origins.
    pub fn from_manifest(manifest: &CentreManifest, id: &str) -> Result<Self, CryptoError> {
        if manifest.version != 1
            || manifest.centres.len() > 4
            || ramflux_protocol::canonical_json_bytes(manifest)?.len() > 4096
        {
            return Err(reject("invalid centre manifest"));
        }
        let mut seen = std::collections::BTreeSet::new();
        for pin in &manifest.centres {
            crate::verifying_key_from_base64url(&pin.key)?;
            if !seen.insert(&pin.centre_id)
                || pin.epoch == 0
                || pin.epoch > ramflux_protocol::MAX_SAFE_JSON_INTEGER
                || pin.origin != format!("https://{}", pin.centre_id)
            {
                return Err(reject("invalid or duplicated centre pin"));
            }
        }
        let pin = manifest
            .centres
            .iter()
            .find(|p| p.centre_id == id)
            .ok_or_else(|| reject("centre pin required"))?;
        Ok(Self { pin: pin.clone() })
    }
    #[must_use]
    pub fn pin(&self) -> &CentrePin {
        &self.pin
    }
    /// Verify both signatures of a single successor; the caller commits CAS/fork floors.
    /// # Errors
    /// Refuses key substitution, skipped epochs and unproved new-key possession.
    pub fn rotate(&self, rotation: &CentreRotation) -> Result<Self, CryptoError> {
        let b = &rotation.body;
        if b.version != 1
            || b.centre_id != self.pin.centre_id
            || b.origin != self.pin.origin
            || b.old_key != self.pin.key
            || b.expected_epoch != self.pin.epoch
            || b.expected_epoch.checked_add(1) != Some(b.epoch)
            || b.epoch > ramflux_protocol::MAX_SAFE_JSON_INTEGER
            || b.new_key == b.old_key
        {
            return Err(reject("centre rotation pin or epoch mismatch"));
        }
        let bytes = custody::signing_bytes(CENTRE_ROTATION_DOMAIN, b)?;
        crate::verify_canonical_signature(&bytes, &rotation.old_signature, &b.old_key)?;
        crate::verify_canonical_signature(&bytes, &rotation.new_signature, &b.new_key)?;
        Ok(Self {
            pin: CentrePin {
                centre_id: b.centre_id.clone(),
                origin: b.origin.clone(),
                key: b.new_key.clone(),
                epoch: b.epoch,
            },
        })
    }
}

/// Verify a current certified binding, distinct from centre uniqueness/order authority.
/// # Errors
/// Refuses stale home/head/certificate provenance and substituted account signatures.
pub fn verify_binding(
    value: &Signed<Binding>,
    authority: &VerifiedRecord,
    home_hash: &str,
) -> Result<(), CryptoError> {
    value.body.validate()?;
    let b = &value.body;
    let record = authority.envelope();
    if b.account_anchor != record.body.account_anchor
        || b.home_head_hash != home_hash
        || b.authority_head_hash != custody::object_hash(record)?
        || b.master_certificate_hash != custody::object_hash(&record.body.master_certificate)?
        || ramflux_protocol::canonical_json_bytes(value)?.len() > 4096
    {
        return Err(reject("certified username binding authority mismatch"));
    }
    verify(BINDING_DOMAIN, value, &record.body.master_certificate.body.self_signing_public_key)
}
/// Verify a primary-approved name mutation with the currently certified everyday signer.
/// # Errors
/// Refuses old master formats, branch signatures, stale actor/home or malformed action fields.
pub fn verify_operation(
    value: &Signed<NameOperation>,
    authority: &VerifiedRecord,
    home_hash: &str,
    actor: &custody::DeviceRef,
    now: u64,
) -> Result<(), CryptoError> {
    let b = &value.body;
    b.validate()?;
    reach::check_submission_time(b.issued_at, b.expires_at, now)?;
    if &b.actor != actor || b.home_head_hash != home_hash {
        return Err(reject("name session/home mismatch"));
    }
    manager(
        authority,
        actor,
        &b.account_anchor,
        &b.authority_head_hash,
        &b.master_certificate_hash,
        now,
    )?;
    if let Some(binding) = &b.binding {
        verify_binding(binding, authority, home_hash)?;
    }
    if ramflux_protocol::canonical_json_bytes(value)?.len() > 4096 {
        return Err(reject("name operation byte budget"));
    }
    verify(
        OPERATION_DOMAIN,
        value,
        &authority.envelope().body.master_certificate.body.self_signing_public_key,
    )
}
/// Verify a home-served profile without contacting the centre.
/// # Errors
/// Refuses unrelated principals, profile kinds, heads and self-signing keys.
pub fn verify_profile(
    value: &Signed<Profile>,
    authority: &VerifiedRecord,
    home_hash: &str,
) -> Result<(), CryptoError> {
    let b = &value.body;
    b.validate()?;
    let record = authority.envelope();
    let kind = match record.body.principal_kind {
        ramflux_protocol::PrincipalKind::Human => {
            ramflux_protocol::username_directory::ProfileKind::Human
        }
        ramflux_protocol::PrincipalKind::HeadlessAi => {
            ramflux_protocol::username_directory::ProfileKind::HeadlessAi
        }
        ramflux_protocol::PrincipalKind::Bot => {
            ramflux_protocol::username_directory::ProfileKind::Bot
        }
        ramflux_protocol::PrincipalKind::Workflow => {
            return Err(reject("workflow profiles are unsupported"));
        }
    };
    if b.account_anchor != record.body.account_anchor
        || b.principal_id != record.body.principal_id
        || b.kind != kind
        || b.display_name != record.body.profile.display_name
        || b.home_head_hash != home_hash
        || b.authority_head_hash != custody::object_hash(record)?
        || b.master_certificate_hash != custody::object_hash(&record.body.master_certificate)?
        || ramflux_protocol::canonical_json_bytes(value)?.len() > 8192
    {
        return Err(reject("certified profile authority mismatch"));
    }
    verify(PROFILE_DOMAIN, value, &record.body.master_certificate.body.self_signing_public_key)
}

impl SelfSigningKey {
    /// Sign a binding only for the current certified account/home.
    /// # Errors
    /// Refuses invalid binding fields or an unrelated everyday signer.
    pub fn sign_username_binding(
        &self,
        body: Binding,
        authority: &VerifiedRecord,
    ) -> Result<Signed<Binding>, CryptoError> {
        let value = sign(BINDING_DOMAIN, body, &SigningKey::from_bytes(&self.vault_seed()))?;
        verify_binding(&value, authority, &value.body.home_head_hash)?;
        Ok(value)
    }
    /// Sign one explicit name mutation; no recovery/master ceremony is involved.
    /// # Errors
    /// Refuses invalid command fields, unavailable current primary or an unrelated signer.
    pub fn sign_username_operation(
        &self,
        body: NameOperation,
        authority: &VerifiedRecord,
        now: u64,
    ) -> Result<Signed<NameOperation>, CryptoError> {
        let value = sign(OPERATION_DOMAIN, body, &SigningKey::from_bytes(&self.vault_seed()))?;
        verify_operation(&value, authority, &value.body.home_head_hash, &value.body.actor, now)?;
        Ok(value)
    }
    /// Sign a profile independently of username registration and centre availability.
    /// # Errors
    /// Refuses mismatching current account metadata or an unrelated signer.
    pub fn sign_certified_profile(
        &self,
        body: Profile,
        authority: &VerifiedRecord,
    ) -> Result<Signed<Profile>, CryptoError> {
        let value = sign(PROFILE_DOMAIN, body, &SigningKey::from_bytes(&self.vault_seed()))?;
        verify_profile(&value, authority, &value.body.home_head_hash)?;
        Ok(value)
    }
}

/// Verify a fresh exact-name result with the SDK's own centre pin and request nonce.
/// # Errors
/// Refuses substituted names/nonces, expiry and centre key replacement.
pub fn verify_resolve(
    pin: &PinnedCentre,
    value: &Signed<IndexResolve>,
    name: &str,
    nonce: &str,
    now: u64,
) -> Result<(), CryptoError> {
    let b = &value.body;
    if b.version != 2
        || b.centre_id != pin.pin.centre_id
        || b.name != name
        || b.request_nonce != nonce
        || b.epoch == 0
        || b.epoch > ramflux_protocol::MAX_SAFE_JSON_INTEGER
        || b.issued_at.checked_add(60) != Some(b.expires_at)
    {
        return Err(reject("username resolution correlation mismatch"));
    }
    reach::check_submission_time(b.issued_at, b.expires_at, now)?;
    ramflux_protocol::username_directory::validate_username(&b.name)
        .map_err(|_| reject("invalid resolved name"))?;
    verify(RESOLVE_DOMAIN, value, &pin.pin.key)
}
