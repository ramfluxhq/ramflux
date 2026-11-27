// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! `0xF0D1` device credential.
//!
//! TLS-style encoding `{version = 1, root_vk[32], device_id<V>, device_set_record<V>,
//! device_signing_pk[32], cert_sig[64]}`. `cert_sig` is the device signing key's Ed25519
//! signature over `"rf-mls-leaf-v1" || u16 suite || leaf_signature_key`, which binds the
//! credential to exactly one leaf key.

use ed25519_dalek::{Signature, VerifyingKey};
use openmls::prelude::{Credential, CredentialType};
use ramflux_protocol::domain::{DEVICE_SIGNING_KEY_COMMITMENT, MLS_LEAF_CERT_V1};
use ramflux_protocol::{DeviceSetStatus, SignedDeviceSetRecord};
use tls_codec::{DeserializeBytes, Serialize, VLBytes};

use super::VerifiedMember;
use super::device_sets;
use crate::storage::MlsStorage;
use crate::storage::kv::MlsKv;
use crate::{
    CREDENTIAL_TYPE_DEVICE, CREDENTIAL_VERSION, MAX_CREDENTIAL_BYTES, MLS_SUITE_CODE, MlsError,
};

/// Signs the leaf certificate with the device signing key (the key itself stays in the account).
pub trait DeviceCertSigner: Send + Sync {
    /// Sign `message` with the device signing key.
    ///
    /// # Errors
    /// The key is unavailable or signing failed.
    fn sign_cert(&self, message: &[u8]) -> Result<[u8; 64], MlsError>;
}

/// The own device identity, issued by the account (part 0b).
pub struct DeviceIdentity {
    /// Root verifying key of the principal.
    pub root_vk: [u8; 32],
    /// Own device id inside the signed device set.
    pub device_id: String,
    /// Original I-JSON bytes of the principal's `SignedDeviceSetRecord`.
    pub device_set_record: Vec<u8>,
    /// Device signing public key.
    pub device_signing_pk: [u8; 32],
    /// Signer for the leaf certificate.
    pub signer: Box<dyn DeviceCertSigner>,
}

/// Decoded credential content.
pub(crate) struct DeviceCredential {
    pub(crate) root_vk: [u8; 32],
    pub(crate) device_id: String,
    pub(crate) device_set_record: Vec<u8>,
    pub(crate) device_signing_pk: [u8; 32],
    pub(crate) cert_sig: [u8; 64],
}

fn reject(what: &str) -> MlsError {
    MlsError::CredentialRejected(what.to_owned())
}

/// The bytes the device key signs for a leaf.
#[must_use]
pub fn cert_message(suite: u16, leaf_signature_key: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(MLS_LEAF_CERT_V1.len() + 2 + leaf_signature_key.len());
    message.extend_from_slice(MLS_LEAF_CERT_V1.as_bytes());
    message.extend_from_slice(&suite.to_be_bytes());
    message.extend_from_slice(leaf_signature_key);
    message
}

impl DeviceCredential {
    pub(crate) fn encode(&self) -> Result<Vec<u8>, MlsError> {
        let mut out = vec![CREDENTIAL_VERSION];
        out.extend_from_slice(&self.root_vk);
        out.extend_from_slice(&vl(self.device_id.as_bytes())?);
        out.extend_from_slice(&vl(&self.device_set_record)?);
        out.extend_from_slice(&self.device_signing_pk);
        out.extend_from_slice(&self.cert_sig);
        Ok(out)
    }

    pub(crate) fn decode(content: &[u8]) -> Result<Self, MlsError> {
        let (version, rest) =
            content.split_first().ok_or_else(|| reject("empty device credential"))?;
        if *version != CREDENTIAL_VERSION {
            return Err(reject("device credential version"));
        }
        let (root_vk, rest) = take_array::<32>(rest)?;
        let (device_id, rest) = take_vl(rest)?;
        let (device_set_record, rest) = take_vl(rest)?;
        let (device_signing_pk, rest) = take_array::<32>(rest)?;
        let (cert_sig, rest) = take_array::<64>(rest)?;
        if !rest.is_empty() {
            return Err(reject("trailing bytes in device credential"));
        }
        let device_id =
            String::from_utf8(device_id).map_err(|_| reject("device id is not UTF-8"))?;
        Ok(Self { root_vk, device_id, device_set_record, device_signing_pk, cert_sig })
    }
}

fn vl(bytes: &[u8]) -> Result<Vec<u8>, MlsError> {
    VLBytes::from(bytes.to_vec()).tls_serialize_detached().map_err(MlsError::mls)
}

fn take_vl(input: &[u8]) -> Result<(Vec<u8>, &[u8]), MlsError> {
    let (value, rest) =
        VLBytes::tls_deserialize_bytes(input).map_err(|_| reject("malformed device credential"))?;
    Ok((value.as_slice().to_vec(), rest))
}

fn take_array<const N: usize>(input: &[u8]) -> Result<([u8; N], &[u8]), MlsError> {
    let (head, rest) =
        input.split_at_checked(N).ok_or_else(|| reject("truncated device credential"))?;
    let array: [u8; N] = head.try_into().map_err(|_| reject("truncated device credential"))?;
    Ok((array, rest))
}

/// Build the own credential for a fresh leaf signature key.
///
/// # Errors
/// [`MlsError::DeviceSetTooLarge`] when the encoded credential exceeds the cap (no truncation, no
/// fallback), or the device signer fails.
pub fn issue(
    identity: &DeviceIdentity,
    leaf_signature_key: &[u8; 32],
) -> Result<Credential, MlsError> {
    let cert_sig = identity.signer.sign_cert(&cert_message(MLS_SUITE_CODE, leaf_signature_key))?;
    let content = DeviceCredential {
        root_vk: identity.root_vk,
        device_id: identity.device_id.clone(),
        device_set_record: identity.device_set_record.clone(),
        device_signing_pk: identity.device_signing_pk,
        cert_sig,
    }
    .encode()?;
    if content.len() > MAX_CREDENTIAL_BYTES {
        return Err(MlsError::DeviceSetTooLarge {
            bytes: content.len(),
            max: MAX_CREDENTIAL_BYTES,
        });
    }
    Ok(Credential::new(CredentialType::Other(CREDENTIAL_TYPE_DEVICE), content))
}

/// Verify a received device credential against the leaf signature key and the device-set
/// authority.
pub(crate) fn verify<K: MlsKv>(
    storage: &MlsStorage<'_, K>,
    content: &[u8],
    leaf_signature_key: &[u8; 32],
) -> Result<VerifiedMember, MlsError> {
    let credential = DeviceCredential::decode(content)?;
    let record = SignedDeviceSetRecord::from_wire_bytes(&credential.device_set_record)
        .map_err(|error| reject(&format!("device set record: {error}")))?;
    let root = VerifyingKey::from_bytes(&credential.root_vk).map_err(|_| reject("root key"))?;
    ramflux_crypto::verify_signed_device_set(&root, &record)
        .map_err(|error| reject(&format!("device set signature: {error}")))?;
    let entry = record
        .devices
        .iter()
        .find(|entry| entry.device_id == credential.device_id)
        .ok_or_else(|| reject("device is not in the device set"))?;
    if entry.status != DeviceSetStatus::Active {
        return Err(reject("device is revoked"));
    }
    let signing_key = VerifyingKey::from_bytes(&credential.device_signing_pk)
        .map_err(|_| reject("device signing key"))?;
    if signing_key.is_weak() {
        return Err(reject("weak device signing key"));
    }
    let commitment = ramflux_crypto::blake3_256_base64url(
        DEVICE_SIGNING_KEY_COMMITMENT,
        &credential.device_signing_pk,
    );
    if entry.signing_key_commitment != commitment {
        return Err(reject("device signing key does not match its commitment"));
    }
    let signature = Signature::from_bytes(&credential.cert_sig);
    signing_key
        .verify_strict(&cert_message(MLS_SUITE_CODE, leaf_signature_key), &signature)
        .map_err(|_| reject("leaf certificate signature"))?;
    device_sets::authorize(
        storage,
        &record.principal_commitment,
        &record,
        &credential.device_set_record,
        &credential.device_id,
        &entry.signing_key_commitment,
    )?;
    Ok(VerifiedMember {
        root_commitment: record.principal_commitment.clone(),
        device_id: credential.device_id,
        device_set_epoch: record.device_set_epoch,
        leaf_sig_pk: *leaf_signature_key,
    })
}

/// Read the identity of an already admitted leaf without re-running the authority checks (the
/// leaf was verified when it entered the group; its device may be revoked since).
pub(crate) fn describe(
    content: &[u8],
    leaf_signature_key: &[u8; 32],
) -> Result<VerifiedMember, MlsError> {
    let credential = DeviceCredential::decode(content)?;
    let record = SignedDeviceSetRecord::from_wire_bytes(&credential.device_set_record)
        .map_err(|error| reject(&format!("device set record: {error}")))?;
    Ok(VerifiedMember {
        root_commitment: record.principal_commitment,
        device_id: credential.device_id,
        device_set_epoch: record.device_set_epoch,
        leaf_sig_pk: *leaf_signature_key,
    })
}
