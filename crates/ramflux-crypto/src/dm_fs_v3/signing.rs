// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Closed native signing domains and strict public verification.
use super::{NativePrekeyError, branch_binding};
use ed25519_dalek::{Signature, Signer, VerifyingKey};
use ramflux_protocol::{
    dm_fs_v3::{
        NativePrekeyRequest, OwnerPrekeyStatus, OwnerPrekeyUpdate, PrekeyLeaseResult,
        QualifiedBranch, SignedNativeOpk, SignedNativePrekeyBase,
    },
    domain,
};
type Result<T = ()> = std::result::Result<T, NativePrekeyError>;
/// The six native signature roles. Hash roles cannot be used as signature domains.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NativeSignatureDomain {
    /// Canonical `SignedNativePrekeyBase` signing body.
    Base,
    /// Canonical `SignedNativeOpk` signing body.
    Opk,
    /// Canonical `OwnerPrekeyUpdate` signing body.
    OwnerUpdate,
    /// Canonical `NativePrekeyRequest` signing body.
    Request,
    /// Canonical `PrekeyLeaseResult` signing body.
    LeaseResult,
    /// Canonical `OwnerPrekeyStatus` signing body.
    OwnerStatus,
}
impl NativeSignatureDomain {
    /// Exact registered signature domain.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Base => domain::DM_FS_V3_BASE,
            Self::Opk => domain::DM_FS_V3_OPK,
            Self::OwnerUpdate => domain::DM_FS_V3_OWNER_UPDATE,
            Self::Request => domain::DM_FS_V3_REQUEST,
            Self::LeaseResult => domain::DM_FS_V3_LEASE_RESULT,
            Self::OwnerStatus => domain::DM_FS_V3_OWNER_STATUS,
        }
    }
}
/// Scoped signing capability. Implementers must not expose secret material in Debug
/// or serialization. Typed sign helpers validate canonical sizes before invocation.
pub trait NativePrekeySigner {
    /// Public Ed25519 signing key.
    fn public_key(&self) -> [u8; 32];
    /// Sign `domain || NUL || body`; body contains public canonical fields only.
    fn sign(&self, domain: NativeSignatureDomain, body: &[u8]) -> [u8; 64];
}
impl NativePrekeySigner for crate::DeviceBranch {
    fn public_key(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }
    fn sign(&self, domain: NativeSignatureDomain, body: &[u8]) -> [u8; 64] {
        self.signing_key.sign(&signing_preimage(domain, body)).to_bytes()
    }
}
fn signing_preimage(domain: NativeSignatureDomain, body: &[u8]) -> Vec<u8> {
    let mut bytes = domain.as_str().as_bytes().to_vec();
    bytes.push(0);
    bytes.extend_from_slice(body);
    bytes
}
fn verify(
    domain: NativeSignatureDomain,
    body: &[u8],
    signature: &[u8; 64],
    key: &[u8; 32],
) -> Result {
    let key = VerifyingKey::from_bytes(key).map_err(|_| NativePrekeyError::Signature)?;
    key.verify_strict(&signing_preimage(domain, body), &Signature::from_bytes(signature))
        .map_err(|_| NativePrekeyError::Signature)
}
fn signer_matches(signer: &dyn NativePrekeySigner, key: &[u8; 32]) -> Result {
    if signer.public_key() == *key { Ok(()) } else { Err(NativePrekeyError::SignerMismatch) }
}
/// Sign one bounded canonical `SignedNativePrekeyBase` using the supplied scoped capability.
/// # Errors
/// Rejects canonical bounds, wrong signer ownership or inconsistent public bindings.
pub fn sign_base(
    mut value: SignedNativePrekeyBase,
    signer: &dyn NativePrekeySigner,
) -> Result<SignedNativePrekeyBase> {
    signer_matches(signer, &value.branch.signing_key)?;
    value.signature = signer.sign(NativeSignatureDomain::Base, &value.signing_body_bytes()?);
    verify_base(&value)?;
    Ok(value)
}
/// Verify strict signature validity and embedded public bindings only.
/// The caller must establish current branch authority independently.
/// # Errors
/// Rejects malformed canonical data, bad signatures and inconsistent bindings.
pub fn verify_base(value: &SignedNativePrekeyBase) -> Result {
    verify(
        NativeSignatureDomain::Base,
        &value.signing_body_bytes()?,
        &value.signature,
        &value.branch.signing_key,
    )
}
/// Sign one bounded canonical `SignedNativeOpk` using the supplied scoped capability.
/// # Errors
/// Rejects canonical bounds, wrong signer ownership or inconsistent public bindings.
pub fn sign_opk(
    mut value: SignedNativeOpk,
    signer: &dyn NativePrekeySigner,
    branch: &QualifiedBranch,
) -> Result<SignedNativeOpk> {
    signer_matches(signer, &branch.signing_key)?;
    if value.branch_binding != branch_binding(branch)? {
        return Err(NativePrekeyError::Binding);
    }
    value.signature = signer.sign(NativeSignatureDomain::Opk, &value.signing_body_bytes()?);
    verify_opk(&value, branch)?;
    Ok(value)
}
/// Verify strict signature validity and embedded public bindings only.
/// The caller must establish current branch authority independently.
/// # Errors
/// Rejects malformed canonical data, bad signatures and inconsistent bindings.
pub fn verify_opk(value: &SignedNativeOpk, branch: &QualifiedBranch) -> Result {
    if value.branch_binding != branch_binding(branch)? {
        return Err(NativePrekeyError::Binding);
    }
    verify(
        NativeSignatureDomain::Opk,
        &value.signing_body_bytes()?,
        &value.signature,
        &branch.signing_key,
    )
}
/// Sign one bounded canonical `OwnerPrekeyUpdate` using the supplied scoped capability.
/// # Errors
/// Rejects canonical bounds, wrong signer ownership or inconsistent public bindings.
pub fn sign_owner_update(
    mut value: OwnerPrekeyUpdate,
    signer: &dyn NativePrekeySigner,
) -> Result<OwnerPrekeyUpdate> {
    signer_matches(signer, &value.base.branch.signing_key)?;
    value.signature = signer.sign(NativeSignatureDomain::OwnerUpdate, &value.signing_body_bytes()?);
    verify_owner_update(&value)?;
    Ok(value)
}
/// Verify strict signature validity and embedded public bindings only.
/// The caller must establish current branch authority independently.
/// # Errors
/// Rejects malformed canonical data, bad signatures and inconsistent bindings.
pub fn verify_owner_update(value: &OwnerPrekeyUpdate) -> Result {
    let body = value.signing_body_bytes()?;
    verify_base(&value.base)?;
    for opk in &value.additive_opks {
        verify_opk(opk, &value.base.branch)?;
        if opk.generation != value.base.generation {
            return Err(NativePrekeyError::Binding);
        }
    }
    verify(
        NativeSignatureDomain::OwnerUpdate,
        &body,
        &value.signature,
        &value.base.branch.signing_key,
    )
}
/// Sign one bounded canonical `NativePrekeyRequest` using the supplied scoped capability.
/// # Errors
/// Rejects canonical bounds, wrong signer ownership or inconsistent public bindings.
pub fn sign_request(
    mut value: NativePrekeyRequest,
    signer: &dyn NativePrekeySigner,
) -> Result<NativePrekeyRequest> {
    signer_matches(signer, &value.source.signing_key)?;
    value.signature = signer.sign(NativeSignatureDomain::Request, &value.signing_body()?);
    verify_request(&value)?;
    Ok(value)
}
/// Verify strict signature validity and embedded public bindings only.
/// The caller must establish current branch authority independently.
/// # Errors
/// Rejects malformed canonical data, bad signatures and inconsistent bindings.
pub fn verify_request(value: &NativePrekeyRequest) -> Result {
    verify(
        NativeSignatureDomain::Request,
        &value.signing_body()?,
        &value.signature,
        &value.source.signing_key,
    )
}
/// Sign one bounded canonical `PrekeyLeaseResult` using the supplied scoped capability.
/// # Errors
/// Rejects canonical bounds, wrong signer ownership or inconsistent public bindings.
pub fn sign_lease_result(
    mut value: PrekeyLeaseResult,
    signer: &dyn NativePrekeySigner,
) -> Result<PrekeyLeaseResult> {
    value.signature = signer.sign(NativeSignatureDomain::LeaseResult, &value.signing_body_bytes()?);
    verify_lease_result(&value, &signer.public_key())?;
    Ok(value)
}
/// Verify strict signature validity and embedded public bindings only.
/// Node keys must come from the caller's authenticated node context.
/// # Errors
/// Rejects malformed canonical data, bad signatures and inconsistent bindings.
pub fn verify_lease_result(value: &PrekeyLeaseResult, node_key: &[u8; 32]) -> Result {
    verify_base(&value.base)?;
    if value.target != value.base.branch {
        return Err(NativePrekeyError::Binding);
    }
    if let Some(opk) = &value.opk {
        verify_opk(opk, &value.target)?;
        if opk.generation != value.base.generation {
            return Err(NativePrekeyError::Binding);
        }
    }
    verify(
        NativeSignatureDomain::LeaseResult,
        &value.signing_body_bytes()?,
        &value.signature,
        node_key,
    )
}
/// Sign one bounded canonical `OwnerPrekeyStatus` using the supplied scoped capability.
/// # Errors
/// Rejects canonical bounds, wrong signer ownership or inconsistent public bindings.
pub fn sign_owner_status(
    mut value: OwnerPrekeyStatus,
    signer: &dyn NativePrekeySigner,
) -> Result<OwnerPrekeyStatus> {
    value.signature = signer.sign(NativeSignatureDomain::OwnerStatus, &value.signing_body_bytes()?);
    verify_owner_status(&value, &signer.public_key())?;
    Ok(value)
}
/// Verify strict signature validity and embedded public bindings only.
/// Node keys must come from the caller's authenticated node context.
/// # Errors
/// Rejects malformed canonical data, bad signatures and inconsistent bindings.
pub fn verify_owner_status(value: &OwnerPrekeyStatus, node_key: &[u8; 32]) -> Result {
    verify(
        NativeSignatureDomain::OwnerStatus,
        &value.signing_body_bytes()?,
        &value.signature,
        node_key,
    )
}
