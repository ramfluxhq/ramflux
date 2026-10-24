// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Domain-separated root authorization of exact device signing/agreement keys and kind.
use crate::{
    BranchProofDocument, CryptoError, DeviceBranch, IdentityRoot, verifying_key_from_base64url,
};
use ed25519_dalek::{Signer, VerifyingKey};
use ramflux_protocol::{DeviceKeyBinding, PrincipalKind, decode_base64url, encode_base64url};
use serde::Serialize;
/// Maximum accepted forward clock skew for root authorizations (five minutes).
pub const BRANCH_PROOF_CLOCK_SKEW_SECONDS: i64 = 300;

/// Local root-owned inputs; no key or kind is inferred from a server response.
pub struct BranchAuthorization<'a> {
    pub audience: &'a str,
    pub capability_scope: Vec<String>,
    pub issued_at: i64,
    pub expires_at: i64,
    pub principal_kind: PrincipalKind,
    pub agreement_identity_public_key: [u8; 32],
}
/// Root-sign exact device keys and immutable kind in the existing branch-proof document.
/// # Errors
/// Rejects root/device disagreement, invalid keys, identifiers, times or canonical serialization.
pub fn authorize_device_branch_v2(
    root: &IdentityRoot,
    device: &DeviceBranch,
    request: BranchAuthorization<'_>,
) -> Result<BranchProofDocument, CryptoError> {
    if root.principal_id != device.principal_id {
        return Err(invalid("root principal mismatch"));
    }
    let binding = DeviceKeyBinding {
        version: 2,
        principal_kind: request.principal_kind,
        branch_signing_public_key: encode_base64url(device.signing_key.verifying_key().to_bytes()),
        agreement_identity_public_key: encode_base64url(request.agreement_identity_public_key),
    };
    let proof_id = ramflux_protocol::hash_base64url(
        ramflux_protocol::domain::BRANCH_PROOF_V2,
        &ramflux_protocol::canonical_json_bytes(&(
            encode_base64url(root.signing_key.verifying_key().to_bytes()),
            &device.principal_id,
            &device.device_id,
            device.device_epoch,
            request.audience,
            &request.capability_scope,
            request.issued_at,
            request.expires_at,
            &binding,
        ))?,
    );
    let mut proof = BranchProofDocument {
        proof_id,
        principal_id: device.principal_id.clone(),
        device_id: device.device_id.clone(),
        device_epoch: device.device_epoch,
        audience: request.audience.into(),
        capability_scope: request.capability_scope,
        issued_at: request.issued_at,
        expires_at: request.expires_at,
        signature: String::new(),
        key_binding: Some(binding),
    };
    validate_bound_proof(&proof)?;
    proof.signature =
        encode_base64url(root.signing_key.sign(&branch_proof_signing_bytes(&proof)?).to_bytes());
    Ok(proof)
}
/// Canonical signing bytes for v2, or the exact historical v1 body for read-only legacy state.
/// This function alone does not grant key authority.
/// # Errors
/// Rejects unsupported binding versions, invalid bound fields or serialization errors.
pub fn branch_proof_signing_bytes(proof: &BranchProofDocument) -> Result<Vec<u8>, CryptoError> {
    #[derive(Serialize)]
    struct Body<'a> {
        #[serde(skip_serializing_if = "Option::is_none")]
        domain: Option<&'static str>,
        proof_id: &'a str,
        principal_id: &'a str,
        device_id: &'a str,
        device_epoch: u64,
        audience: &'a str,
        capability_scope: &'a [String],
        issued_at: i64,
        expires_at: i64,
        #[serde(skip_serializing_if = "Option::is_none")]
        key_binding: Option<&'a DeviceKeyBinding>,
    }
    let domain = if proof.key_binding.is_some() {
        validate_bound_proof(proof)?;
        Some(ramflux_protocol::domain::BRANCH_PROOF_V2)
    } else {
        None
    };
    Ok(ramflux_protocol::canonical_json_bytes(&Body {
        domain,
        proof_id: &proof.proof_id,
        principal_id: &proof.principal_id,
        device_id: &proof.device_id,
        device_epoch: proof.device_epoch,
        audience: &proof.audience,
        capability_scope: &proof.capability_scope,
        issued_at: proof.issued_at,
        expires_at: proof.expires_at,
        key_binding: proof.key_binding.as_ref(),
    })?)
}
/// Verify the root signature and compare both advertised keys against its signed binding.
/// # Errors
/// Rejects legacy proofs, substitution, future/expired proofs, wrong kind or missing capability.
pub fn verify_root_bound_branch_proof(
    root: &VerifyingKey,
    proof: &BranchProofDocument,
    expected: &DeviceKeyBinding,
    audience: &str,
    capability: &str,
    now: i64,
) -> Result<(), CryptoError> {
    let binding =
        proof.key_binding.as_ref().ok_or_else(|| invalid("legacy branch proof is read-only"))?;
    if binding != expected
        || proof.issued_at > now.saturating_add(BRANCH_PROOF_CLOCK_SKEW_SECONDS)
        || root.is_weak()
    {
        return Err(invalid("branch key, kind or time mismatch"));
    }
    crate::verify_branch_proof(root, proof, audience, capability, now)
}
pub(super) fn invalid(reason: &'static str) -> CryptoError {
    CryptoError::IdentityAuthority(reason)
}
pub(super) fn identifier(value: &str) -> Result<(), CryptoError> {
    if value.is_empty() || value.len() > 256 || value.chars().any(char::is_control) {
        return Err(invalid("invalid identity identifier"));
    }
    Ok(())
}
pub(super) fn validate_public_keys(
    signing: &str,
    agreement_encoded: &str,
) -> Result<([u8; 32], [u8; 32]), CryptoError> {
    let public = verifying_key_from_base64url(signing)?;
    let raw = decode_base64url(agreement_encoded)?;
    let agreement: [u8; 32] =
        raw.try_into().map_err(|_| invalid("invalid agreement key length"))?;
    let probe = x25519_dalek::StaticSecret::from([0x57; 32]);
    if public.is_weak()
        || !probe.diffie_hellman(&x25519_dalek::PublicKey::from(agreement)).was_contributory()
        || encode_base64url(public.to_bytes()) != signing
        || encode_base64url(agreement) != agreement_encoded
    {
        return Err(invalid("invalid device public key"));
    }
    Ok((public.to_bytes(), agreement))
}
fn validate_bound_proof(proof: &BranchProofDocument) -> Result<(), CryptoError> {
    let binding =
        proof.key_binding.as_ref().ok_or_else(|| invalid("missing branch key binding"))?;
    if binding.version != 2
        || proof.device_epoch == 0
        || proof.device_epoch > ramflux_protocol::MAX_SAFE_JSON_INTEGER
        || proof.issued_at < 0
        || proof.expires_at <= proof.issued_at
        || proof.expires_at
            > i64::try_from(ramflux_protocol::MAX_SAFE_JSON_INTEGER)
                .map_err(|_| invalid("time bound"))?
        || proof.capability_scope.is_empty()
        || proof.capability_scope.len() > 64
    {
        return Err(invalid("invalid bound branch proof"));
    }
    for id in [&proof.proof_id, &proof.principal_id, &proof.device_id, &proof.audience] {
        identifier(id)?;
    }
    for capability in &proof.capability_scope {
        identifier(capability)?;
    }
    validate_public_keys(
        &binding.branch_signing_public_key,
        &binding.agreement_identity_public_key,
    )?;
    Ok(())
}
