// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! The same root authority signs both the public profile and its device-set publication.
use crate::{CryptoError, IdentityRoot, identity_binding::invalid};
use ed25519_dalek::{Signer, VerifyingKey};
use ramflux_protocol::{
    PrincipalKind, SignedIdentityProfile, encode_base64url, identity_profile_signing_bytes,
};
/// Signs a bounded NFC public profile with the device-set root signer.
/// # Errors
/// Rejects invalid kind, display text or epoch.
pub fn sign_identity_profile(
    root: &IdentityRoot,
    kind: PrincipalKind,
    display_name: &str,
    epoch: u64,
) -> Result<SignedIdentityProfile, CryptoError> {
    let mut profile = SignedIdentityProfile {
        domain: ramflux_protocol::domain::IDENTITY_PROFILE.into(),
        principal_id: root.principal_id.clone(),
        principal_commitment: crate::identity_root_commitment(&root.signing_key.verifying_key()),
        kind,
        display_name: ramflux_protocol::normalize_profile_display_name(display_name)?,
        epoch,
        signature: String::new(),
    };
    profile.signature = encode_base64url(
        root.signing_key.sign(&identity_profile_signing_bytes(&profile)?).to_bytes(),
    );
    Ok(profile)
}
/// Verifies the root signature; this asserts a principal's claim, not biological humanity.
/// # Errors
/// Rejects unsigned, forged, oversized, unsafe or wrongly bound profiles.
pub fn verify_identity_profile(
    root: &VerifyingKey,
    profile: &SignedIdentityProfile,
) -> Result<(), CryptoError> {
    if root.is_weak() || profile.principal_commitment != crate::identity_root_commitment(root) {
        return Err(invalid("profile root mismatch"));
    }
    crate::identity_binding::identifier(&profile.principal_id)?;
    crate::verify_canonical_signature(
        &identity_profile_signing_bytes(profile)?,
        &profile.signature,
        &encode_base64url(root.to_bytes()),
    )
}
/// A previously accepted profile cannot disappear, roll back or equivocate at the same epoch.
/// # Errors
/// Rejects profile removal or non-monotonic changes.
pub(crate) fn validate_transition(
    old: Option<&SignedIdentityProfile>,
    next: Option<&SignedIdentityProfile>,
) -> Result<(), CryptoError> {
    if let Some(old) = old {
        let next = next.ok_or_else(|| invalid("profile downgrade or omission"))?;
        if next.epoch < old.epoch || next.epoch == old.epoch && next != old {
            return Err(invalid("profile epoch rollback or equivocation"));
        }
    }
    Ok(())
}
