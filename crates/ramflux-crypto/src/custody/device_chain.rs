// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! V1 device chain: the pure proof that a device key belongs to an account anchor.
//!
//! The chain is `{master certificate envelope, branch certificate envelope}`, at most
//! [`MAX_DEVICE_CHAIN_BYTES`] of canonical JSON. Verification reads no clock, no directory and no
//! fetched input: freshness (lease, revocation, key change) is a local decision of the checking
//! device and never decides the validity of a received commit or Welcome.
use ed25519_dalek::VerifyingKey;
use ramflux_protocol::{
    PrincipalKind,
    custody::{BranchCertificate, Envelope, MasterCertificate, decode, object_hash},
    domain,
};
use serde::{Deserialize, Serialize};

use super::validate;
use crate::CryptoError;

/// Largest encoded device chain.
pub const MAX_DEVICE_CHAIN_BYTES: usize = 4 * 1024;

/// The branch capability a chain must grant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeviceChainCapability {
    /// A `dm` or `self` credential (`message`).
    Message,
    /// A group roster entry (`group`).
    Group,
}

impl DeviceChainCapability {
    fn as_str(self) -> &'static str {
        match self {
            Self::Message => "message",
            Self::Group => "group",
        }
    }
}

/// The two certificates that tie a device signing key to an account anchor.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceChain {
    /// The master certificate of the account.
    pub master: Envelope<MasterCertificate>,
    /// The branch certificate of the device.
    pub branch: Envelope<BranchCertificate>,
}

/// What a valid chain proves.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifiedDeviceChain {
    /// `principal_kind` of the master certificate (the AI marker is its non-human kinds).
    pub principal_kind: PrincipalKind,
}

/// Encode a chain for a credential.
///
/// # Errors
/// Serialization failure, or the encoding exceeds [`MAX_DEVICE_CHAIN_BYTES`].
pub fn encode_device_chain(
    master: &Envelope<MasterCertificate>,
    branch: &Envelope<BranchCertificate>,
) -> Result<Vec<u8>, CryptoError> {
    let bytes = ramflux_protocol::canonical_json_bytes(&DeviceChain {
        master: master.clone(),
        branch: branch.clone(),
    })?;
    if bytes.len() > MAX_DEVICE_CHAIN_BYTES {
        return Err(validate::reject("device chain exceeds its byte budget"));
    }
    Ok(bytes)
}

fn decode_chain(bytes: &[u8]) -> Result<DeviceChain, CryptoError> {
    Ok(decode::<DeviceChain>(bytes, MAX_DEVICE_CHAIN_BYTES)?)
}

/// Read the `principal_kind` of an already admitted chain without verifying it again.
///
/// # Errors
/// The bytes are not a well-formed chain.
pub fn device_chain_principal_kind(bytes: &[u8]) -> Result<PrincipalKind, CryptoError> {
    Ok(decode_chain(bytes)?.master.body.principal_kind)
}

/// Verify a device chain (rule V1). Pure: no clock, no directory, no I/O.
///
/// The master certificate must be valid and its key must commit to `anchor`; the branch
/// certificate must be signed by the master certificate's self-signing key, bound to that master
/// certificate and to `anchor`, name exactly this device id, epoch and signing key, and grant
/// `capability`. The lease window of the branch certificate is deliberately not compared to a
/// clock.
///
/// # Errors
/// [`CryptoError::IdentityAuthority`] or [`CryptoError::VerifyFailed`] for any mismatch.
pub fn verify_device_chain(
    bytes: &[u8],
    anchor: &str,
    device_id: &str,
    device_epoch: u64,
    device_signing_pk: &[u8; 32],
    capability: DeviceChainCapability,
) -> Result<VerifiedDeviceChain, CryptoError> {
    let chain = decode_chain(bytes)?;
    let master = &chain.master.body;
    validate::master_body(master)?;
    validate::signature(
        &validate::key(&master.master_public_key)?,
        domain::CUSTODY_MASTER_CERTIFICATE,
        &chain.master,
    )?;
    if master.account_anchor != anchor {
        return Err(validate::reject("device chain belongs to another account anchor"));
    }
    let branch = &chain.branch.body;
    validate::branch_body(branch)?;
    if branch.account_anchor != anchor
        || branch.master_certificate_hash != object_hash(&chain.master)?
        || branch.principal_kind != master.principal_kind
        || branch.device_id != device_id
        || branch.device_epoch != device_epoch
        || branch.branch_signing_public_key == master.master_public_key
        || branch.branch_signing_public_key == master.self_signing_public_key
    {
        return Err(validate::reject("device chain branch binding mismatch"));
    }
    let branch_key: VerifyingKey = validate::key(&branch.branch_signing_public_key)?;
    if branch_key.as_bytes() != device_signing_pk {
        return Err(validate::reject("device chain key is not the credential device key"));
    }
    if !branch.capabilities.iter().any(|granted| granted == capability.as_str()) {
        return Err(validate::reject("device chain lacks the required capability"));
    }
    validate::signature(
        &validate::key(&master.self_signing_public_key)?,
        domain::CUSTODY_BRANCH_CERTIFICATE,
        &chain.branch,
    )?;
    Ok(VerifiedDeviceChain { principal_kind: master.principal_kind })
}
