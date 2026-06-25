// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use ramflux_protocol::{decode_base64url, encode_base64url};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{CryptoError, blake3_256_base64url, verify_canonical_signature};

#[derive(Clone, Eq, PartialEq)]
pub struct IdentityRoot {
    pub principal_id: String,
    pub root_key_id: String,
    pub signing_key: SigningKey,
}

impl fmt::Debug for IdentityRoot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IdentityRoot")
            .field("principal_id", &self.principal_id)
            .field("root_key_id", &self.root_key_id)
            .field("signing_key", &"<redacted>")
            .finish()
    }
}

impl Zeroize for IdentityRoot {
    fn zeroize(&mut self) {
        self.signing_key = SigningKey::from_bytes(&[0_u8; 32]);
    }
}

impl Drop for IdentityRoot {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for IdentityRoot {}

#[derive(Clone, Eq, PartialEq)]
pub struct DeviceBranch {
    pub principal_id: String,
    pub device_id: String,
    pub device_epoch: u64,
    pub signing_key: SigningKey,
}

impl fmt::Debug for DeviceBranch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeviceBranch")
            .field("principal_id", &self.principal_id)
            .field("device_id", &self.device_id)
            .field("device_epoch", &self.device_epoch)
            .field("signing_key", &"<redacted>")
            .finish()
    }
}

impl Zeroize for DeviceBranch {
    fn zeroize(&mut self) {
        self.signing_key = SigningKey::from_bytes(&[0_u8; 32]);
    }
}

impl Drop for DeviceBranch {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for DeviceBranch {}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BranchProofDocument {
    pub proof_id: String,
    pub principal_id: String,
    pub device_id: String,
    pub device_epoch: u64,
    pub audience: String,
    pub capability_scope: Vec<String>,
    pub issued_at: i64,
    pub expires_at: i64,
    pub signature: String,
}

/// # Errors
/// Returns an error when the public key is not valid base64url or ed25519 bytes.
pub fn verifying_key_from_base64url(value: &str) -> Result<VerifyingKey, CryptoError> {
    let public_key_bytes = decode_base64url(value)?;
    let public_key_array: [u8; 32] = public_key_bytes
        .as_slice()
        .try_into()
        .map_err(|_| CryptoError::InvalidPublicKeyLength(public_key_bytes.len()))?;
    VerifyingKey::from_bytes(&public_key_array).map_err(|_err| CryptoError::VerifyFailed)
}

#[derive(Serialize)]
struct BranchProofSigningBody<'a> {
    proof_id: &'a str,
    principal_id: &'a str,
    device_id: &'a str,
    device_epoch: u64,
    audience: &'a str,
    capability_scope: &'a [String],
    issued_at: i64,
    expires_at: i64,
}

#[must_use]
pub fn create_identity_root(principal_id: &str, seed: [u8; 32]) -> IdentityRoot {
    IdentityRoot {
        principal_id: principal_id.to_owned(),
        root_key_id: format!("root:{principal_id}"),
        signing_key: SigningKey::from_bytes(&seed),
    }
}

#[must_use]
pub fn create_device_branch(
    principal_id: &str,
    device_id: &str,
    device_epoch: u64,
    seed: [u8; 32],
) -> DeviceBranch {
    DeviceBranch {
        principal_id: principal_id.to_owned(),
        device_id: device_id.to_owned(),
        device_epoch,
        signing_key: SigningKey::from_bytes(&seed),
    }
}

/// # Errors
/// Returns an error when validation, serialization, storage, or state checks fail.
pub fn authorize_device_branch(
    root: &IdentityRoot,
    device: &DeviceBranch,
    audience: &str,
    capability_scope: Vec<String>,
    issued_at: i64,
    expires_at: i64,
) -> Result<BranchProofDocument, CryptoError> {
    let proof_id = blake3_256_base64url(
        ramflux_protocol::domain::BRANCH_PROOF,
        format!(
            "{}:{}:{}:{}",
            device.principal_id, device.device_id, device.device_epoch, audience
        )
        .as_bytes(),
    );
    let body = BranchProofSigningBody {
        proof_id: &proof_id,
        principal_id: &device.principal_id,
        device_id: &device.device_id,
        device_epoch: device.device_epoch,
        audience,
        capability_scope: &capability_scope,
        issued_at,
        expires_at,
    };
    let canonical = ramflux_protocol::canonical_json_bytes(&body)?;
    let signature = root.signing_key.sign(&canonical);
    Ok(BranchProofDocument {
        proof_id,
        principal_id: device.principal_id.clone(),
        device_id: device.device_id.clone(),
        device_epoch: device.device_epoch,
        audience: audience.to_owned(),
        capability_scope,
        issued_at,
        expires_at,
        signature: encode_base64url(signature.to_bytes()),
    })
}

/// # Errors
/// Returns an error when validation, serialization, storage, or state checks fail.
pub fn verify_branch_proof(
    root_public_key: &VerifyingKey,
    proof: &BranchProofDocument,
    audience: &str,
    required_capability: &str,
    now: i64,
) -> Result<(), CryptoError> {
    if proof.audience != audience || proof.expires_at < now {
        return Err(CryptoError::VerifyFailed);
    }
    if !proof.capability_scope.iter().any(|capability| capability == required_capability) {
        return Err(CryptoError::VerifyFailed);
    }
    let body = BranchProofSigningBody {
        proof_id: &proof.proof_id,
        principal_id: &proof.principal_id,
        device_id: &proof.device_id,
        device_epoch: proof.device_epoch,
        audience: &proof.audience,
        capability_scope: &proof.capability_scope,
        issued_at: proof.issued_at,
        expires_at: proof.expires_at,
    };
    let canonical = ramflux_protocol::canonical_json_bytes(&body)?;
    verify_canonical_signature(
        &canonical,
        &proof.signature,
        &encode_base64url(root_public_key.to_bytes()),
    )
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DeviceRevocationReplayGuard {
    revoked_devices: BTreeSet<String>,
    seen_proofs: BTreeSet<String>,
}

impl DeviceRevocationReplayGuard {
    #[must_use]
    pub const fn new() -> Self {
        Self { revoked_devices: BTreeSet::new(), seen_proofs: BTreeSet::new() }
    }

    pub fn revoke_device(&mut self, device_id: &str) {
        self.revoked_devices.insert(device_id.to_owned());
    }

    /// # Errors
    /// Returns an error when validation, serialization, storage, or state checks fail.
    pub fn accept_branch_proof(
        &mut self,
        root_public_key: &VerifyingKey,
        proof: &BranchProofDocument,
        audience: &str,
        required_capability: &str,
        now: i64,
    ) -> Result<(), CryptoError> {
        if self.revoked_devices.contains(&proof.device_id) {
            return Err(CryptoError::DeviceRevoked);
        }
        if !self.seen_proofs.insert(proof.proof_id.clone()) {
            return Err(CryptoError::BranchProofReplay);
        }
        verify_branch_proof(root_public_key, proof, audience, required_capability, now)
    }
}
