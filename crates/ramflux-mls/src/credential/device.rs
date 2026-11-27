// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! `0xF0D1` device credential, version 2.
//!
//! TLS-style encoding `{version = 2, account_anchor<V>, device_id<V>, device_epoch u64,
//! device_set_epoch u64, device_signing_pk[32], cert_sig[64]}` (about 200 bytes). The device
//! record is not in the credential: it is looked up through the directory-path
//! [`DeviceAuthority`] (`authority.rs`), and every commit decision uses the records the commit
//! carries (the pure path). `cert_sig` is the device (branch) signing key's Ed25519 signature
//! over `MLS_LEAF_CERT_V2 || u16 suite || leaf_signature_key || u16 len || anchor || u16 len ||
//! device_id || u64 device_epoch` (the two variable fields are length-prefixed so the message is
//! unambiguous), which binds the credential to exactly one leaf key and one device.

use ed25519_dalek::{Signature, VerifyingKey};
use openmls::prelude::{Credential, CredentialType};
use ramflux_protocol::custody::DeviceRef;
use ramflux_protocol::decode_base64url;
use ramflux_protocol::domain::{DEVICE_SIGNING_KEY_COMMITMENT, MLS_LEAF_CERT_V2};
use tls_codec::{DeserializeBytes, Serialize, VLBytes};

use super::VerifiedMember;
use super::authority::DeviceAuthority;
use crate::group::unix_now;
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
    /// Account anchor (base64url root commitment).
    pub account_anchor: String,
    /// Own device id inside the signed device set.
    pub device_id: String,
    /// Own device epoch.
    pub device_epoch: u64,
    /// Epoch of the device-set record the credential is built from.
    pub device_set_epoch: u64,
    /// Device (branch) signing public key.
    pub device_signing_pk: [u8; 32],
    /// Signer for the leaf certificate.
    pub signer: Box<dyn DeviceCertSigner>,
}

/// Decoded credential content.
pub(crate) struct DeviceCredential {
    pub(crate) account_anchor: String,
    pub(crate) device_id: String,
    pub(crate) device_epoch: u64,
    pub(crate) device_set_epoch: u64,
    pub(crate) device_signing_pk: [u8; 32],
    pub(crate) cert_sig: [u8; 64],
}

/// The branch capability a device credential needs (the leased `message` capability).
pub(crate) const DEVICE_CAPABILITY: &str = "message";

fn reject(what: &str) -> MlsError {
    MlsError::CredentialRejected(what.to_owned())
}

/// The bytes the device key signs for a leaf.
#[must_use]
pub fn cert_message(
    suite: u16,
    leaf_signature_key: &[u8],
    anchor: &str,
    device_id: &str,
    device_epoch: u64,
) -> Vec<u8> {
    let mut message = Vec::with_capacity(
        MLS_LEAF_CERT_V2.len() + 2 + leaf_signature_key.len() + anchor.len() + device_id.len() + 12,
    );
    message.extend_from_slice(MLS_LEAF_CERT_V2.as_bytes());
    message.extend_from_slice(&suite.to_be_bytes());
    message.extend_from_slice(leaf_signature_key);
    for field in [anchor.as_bytes(), device_id.as_bytes()] {
        let len = u16::try_from(field.len()).unwrap_or(u16::MAX);
        message.extend_from_slice(&len.to_be_bytes());
        message.extend_from_slice(field);
    }
    message.extend_from_slice(&device_epoch.to_be_bytes());
    message
}

impl DeviceCredential {
    pub(crate) fn encode(&self) -> Result<Vec<u8>, MlsError> {
        let mut out = vec![CREDENTIAL_VERSION];
        out.extend_from_slice(&vl(self.account_anchor.as_bytes())?);
        out.extend_from_slice(&vl(self.device_id.as_bytes())?);
        out.extend_from_slice(&self.device_epoch.to_be_bytes());
        out.extend_from_slice(&self.device_set_epoch.to_be_bytes());
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
        let (account_anchor, rest) = take_vl(rest)?;
        let (device_id, rest) = take_vl(rest)?;
        let (device_epoch, rest) = take_array::<8>(rest)?;
        let (device_set_epoch, rest) = take_array::<8>(rest)?;
        let (device_signing_pk, rest) = take_array::<32>(rest)?;
        let (cert_sig, rest) = take_array::<64>(rest)?;
        if !rest.is_empty() {
            return Err(reject("trailing bytes in device credential"));
        }
        let account_anchor =
            String::from_utf8(account_anchor).map_err(|_| reject("anchor is not UTF-8"))?;
        ramflux_crypto::custody::validate_native_account_anchor(&account_anchor)
            .map_err(|_| reject("account anchor"))?;
        let device_id =
            String::from_utf8(device_id).map_err(|_| reject("device id is not UTF-8"))?;
        Ok(Self {
            account_anchor,
            device_id,
            device_epoch: u64::from_be_bytes(device_epoch),
            device_set_epoch: u64::from_be_bytes(device_set_epoch),
            device_signing_pk,
            cert_sig,
        })
    }

    fn member(&self, leaf_signature_key: &[u8; 32]) -> VerifiedMember {
        VerifiedMember {
            root_commitment: self.account_anchor.clone(),
            device_id: self.device_id.clone(),
            device_epoch: self.device_epoch,
            device_set_epoch: self.device_set_epoch,
            device_signing_pk: self.device_signing_pk,
            leaf_sig_pk: *leaf_signature_key,
            kp_hash: None,
            leaf_index: None,
        }
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
    let cert_sig = identity.signer.sign_cert(&cert_message(
        MLS_SUITE_CODE,
        leaf_signature_key,
        &identity.account_anchor,
        &identity.device_id,
        identity.device_epoch,
    ))?;
    let content = DeviceCredential {
        account_anchor: identity.account_anchor.clone(),
        device_id: identity.device_id.clone(),
        device_epoch: identity.device_epoch,
        device_set_epoch: identity.device_set_epoch,
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

/// Verify a received device credential against the leaf signature key: the certificate signature
/// first (pure), then the directory path.
///
/// Directory path: the head of the anchor must be known and at least as new as the credential's
/// `device_set_epoch` (else `authority_needed`: the caller fetches the custody record and
/// retries once); the device entry must be Active and not revoked, its signing-key commitment must
/// match, and its leased `message` branch key must be the credential's device key.
pub(crate) fn verify(
    authority: &dyn DeviceAuthority,
    content: &[u8],
    leaf_signature_key: &[u8; 32],
) -> Result<VerifiedMember, MlsError> {
    let credential = DeviceCredential::decode(content)?;
    let signing_key = VerifyingKey::from_bytes(&credential.device_signing_pk)
        .map_err(|_| reject("device signing key"))?;
    if signing_key.is_weak() {
        return Err(reject("weak device signing key"));
    }
    let signature = Signature::from_bytes(&credential.cert_sig);
    signing_key
        .verify_strict(
            &cert_message(
                MLS_SUITE_CODE,
                leaf_signature_key,
                &credential.account_anchor,
                &credential.device_id,
                credential.device_epoch,
            ),
            &signature,
        )
        .map_err(|_| reject("leaf certificate signature"))?;
    let now = unix_now()?;
    let head = authority
        .current(credential.account_anchor.as_bytes())
        .ok_or_else(|| MlsError::AuthorityNeeded(credential.account_anchor.clone()))?;
    let body = &head.envelope().body;
    if body.account_anchor != credential.account_anchor
        || body.device_set_epoch < credential.device_set_epoch
    {
        return Err(MlsError::AuthorityNeeded(credential.account_anchor.clone()));
    }
    let entry = body
        .devices
        .iter()
        .find(|entry| {
            entry.device_id == credential.device_id && entry.device_epoch == credential.device_epoch
        })
        .ok_or_else(|| reject("device is not in the device set"))?;
    if entry.status != ramflux_protocol::DeviceSetStatus::Active
        || head.revoked_ids().contains(&entry.device_id)
    {
        return Err(reject("device is revoked"));
    }
    let commitment = ramflux_crypto::blake3_256_base64url(
        DEVICE_SIGNING_KEY_COMMITMENT,
        &credential.device_signing_pk,
    );
    if entry.signing_key_commitment != commitment {
        return Err(reject("device signing key does not match its commitment"));
    }
    let reference = DeviceRef {
        account_anchor: body.account_anchor.clone(),
        device_id: entry.device_id.clone(),
        device_epoch: entry.device_epoch,
    };
    let lease = head
        .authorize(&reference, DEVICE_CAPABILITY, now)
        .map_err(|error| reject(&format!("device lease: {error}")))?;
    if decode_base64url(&lease.branch_signing_public_key).ok().as_deref()
        != Some(credential.device_signing_pk.as_slice())
    {
        return Err(reject("device signing key is not the leased branch key"));
    }
    Ok(credential.member(leaf_signature_key))
}

/// Read the identity of an already admitted leaf without re-running the authority checks (the
/// leaf was verified when it entered the group; its device may be revoked since).
pub(crate) fn describe(
    content: &[u8],
    leaf_signature_key: &[u8; 32],
) -> Result<VerifiedMember, MlsError> {
    Ok(DeviceCredential::decode(content)?.member(leaf_signature_key))
}
