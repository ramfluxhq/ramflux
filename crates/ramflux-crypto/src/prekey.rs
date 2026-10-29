// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use ramflux_protocol::encode_base64url;
use serde::{Deserialize, Serialize};
use std::fmt;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{CryptoError, DeviceBranch, random_32, verify_canonical_signature};

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct X25519KeyPair {
    pub secret: StaticSecret,
    #[zeroize(skip)]
    pub public: [u8; 32],
}

impl fmt::Debug for X25519KeyPair {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("X25519KeyPair")
            .field("secret", &"<redacted>")
            .field("public", &self.public)
            .finish()
    }
}

impl X25519KeyPair {
    #[must_use]
    pub fn from_seed(seed: [u8; 32]) -> Self {
        let secret = StaticSecret::from(seed);
        let public = X25519PublicKey::from(&secret).to_bytes();
        Self { secret, public }
    }

    /// # Errors
    /// Returns an error when the operating system CSPRNG cannot provide fresh key material.
    pub fn random() -> Result<Self, CryptoError> {
        Ok(Self::from_seed(random_32()?))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PrekeyBundle {
    #[serde(default = "prekey_schema")]
    pub schema: String,
    #[serde(default)]
    pub identity_commitment: String,
    #[serde(default)]
    pub device_id: String,
    #[serde(default)]
    pub device_epoch: u64,
    #[serde(default)]
    pub device_identity_key_id: String,
    #[serde(default)]
    pub device_identity_ed25519_public: String,
    #[serde(default)]
    pub device_agreement_x25519_public: [u8; 32],
    pub identity_key: [u8; 32],
    pub signed_prekey_id: String,
    #[serde(default)]
    pub signed_prekey_x25519_public: [u8; 32],
    pub signed_prekey: [u8; 32],
    #[serde(default)]
    pub signed_prekey_created_at: i64,
    #[serde(default)]
    pub signed_prekey_expires_at: i64,
    #[serde(default)]
    pub one_time_prekey_ids: Vec<String>,
    #[serde(default)]
    pub one_time_prekey_x25519_public: Vec<[u8; 32]>,
    #[serde(default)]
    pub one_time_prekey_signatures: Vec<String>,
    #[serde(default)]
    pub one_time_prekey_pool_hash: [u8; 32],
    pub one_time_prekey_id: Option<String>,
    pub one_time_prekey: Option<[u8; 32]>,
    #[serde(default)]
    pub one_time_prekey_signature: Option<String>,
    #[serde(default)]
    pub prekey_bundle_counter: u64,
    #[serde(default)]
    pub capability_scope: Vec<String>,
    #[serde(default)]
    pub signature_by_device_identity: String,
    #[serde(default)]
    pub signature_by_lineage: String,
    pub signature: String,
}

/// Returns a public identity and signed-prekey view without any one-time prekey material.
#[must_use]
pub fn signed_prekey_only_bundle(bundle: &PrekeyBundle) -> PrekeyBundle {
    let mut public = bundle.clone();
    public.one_time_prekey_id = None;
    public.one_time_prekey = None;
    public.one_time_prekey_signature = None;
    public.one_time_prekey_ids.clear();
    public.one_time_prekey_x25519_public.clear();
    public.one_time_prekey_signatures.clear();
    public
}

/// Serializes a manifest bundle without disclosing any pooled or leased OPK.
/// # Errors
/// Returns the serializer's output error.
pub fn serialize_signed_prekey_only<S: serde::Serializer>(
    bundle: &PrekeyBundle,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    signed_prekey_only_bundle(bundle).serialize(serializer)
}

#[derive(Serialize)]
struct PrekeyBundleSigningBody<'a> {
    schema: &'a str,
    identity_commitment: &'a str,
    device_id: &'a str,
    device_epoch: u64,
    device_identity_key_id: &'a str,
    device_identity_ed25519_public: &'a str,
    device_agreement_x25519_public: &'a str,
    signed_prekey_id: &'a str,
    signed_prekey_x25519_public: &'a str,
    signed_prekey_created_at: i64,
    signed_prekey_expires_at: i64,
    one_time_prekey_pool_hash: &'a str,
    prekey_bundle_counter: u64,
    capability_scope: &'a [String],
}

#[derive(Serialize)]
struct OneTimePrekeySigningBody<'a> {
    schema: &'a str,
    identity_commitment: &'a str,
    device_id: &'a str,
    device_epoch: u64,
    prekey_bundle_counter: u64,
    one_time_prekey_id: &'a str,
    one_time_prekey_x25519_public: &'a str,
}

/// Rotating signed-prekey and bounded one-time-prekey publication inputs.
pub struct PrekeyBundleOptions<'a> {
    pub signed_prekey_id: &'a str,
    pub signed_prekey: &'a X25519KeyPair,
    pub signed_prekey_created_at: i64,
    pub signed_prekey_expires_at: i64,
    pub one_time_prekeys: &'a [(String, [u8; 32])],
    pub prekey_bundle_counter: u64,
}

/// # Errors
/// Returns an error when the prekey bundle signing body cannot be canonicalized.
pub fn create_prekey_bundle(
    device_branch: &DeviceBranch,
    identity_key: &X25519KeyPair,
    signed_prekey_id: &str,
    signed_prekey: &X25519KeyPair,
    one_time_prekey_id: Option<String>,
    one_time_prekey: Option<[u8; 32]>,
) -> Result<PrekeyBundle, CryptoError> {
    create_prekey_bundle_with_lineage(
        device_branch,
        &device_branch.signing_key,
        identity_key,
        signed_prekey_id,
        signed_prekey,
        one_time_prekey_id,
        one_time_prekey,
    )
}

/// # Errors
/// Returns an error when the canonical prekey bundle body cannot be signed.
#[allow(clippy::too_many_arguments)]
pub fn create_prekey_bundle_with_lineage(
    device_branch: &DeviceBranch,
    lineage_signing_key: &SigningKey,
    identity_key: &X25519KeyPair,
    signed_prekey_id: &str,
    signed_prekey: &X25519KeyPair,
    one_time_prekey_id: Option<String>,
    one_time_prekey: Option<[u8; 32]>,
) -> Result<PrekeyBundle, CryptoError> {
    let one_time_prekeys =
        one_time_prekey_id.clone().zip(one_time_prekey).into_iter().collect::<Vec<_>>();
    let mut bundle = create_rotating_prekey_bundle_with_lineage(
        device_branch,
        lineage_signing_key,
        identity_key,
        &PrekeyBundleOptions {
            signed_prekey_id,
            signed_prekey,
            signed_prekey_created_at: 0,
            signed_prekey_expires_at: 0,
            one_time_prekeys: &one_time_prekeys,
            prekey_bundle_counter: 0,
        },
    )?;
    bundle.one_time_prekey_id = one_time_prekey_id;
    bundle.one_time_prekey = one_time_prekey;
    bundle.one_time_prekey_signature = bundle.one_time_prekey_signatures.first().cloned();
    Ok(bundle)
}

/// Creates a signed bundle with rotation metadata and a bounded public OPK pool.
///
/// # Errors
/// Returns an error when the canonical prekey bundle body cannot be signed.
pub fn create_rotating_prekey_bundle_with_lineage(
    device_branch: &DeviceBranch,
    lineage_signing_key: &SigningKey,
    identity_key: &X25519KeyPair,
    options: &PrekeyBundleOptions<'_>,
) -> Result<PrekeyBundle, CryptoError> {
    let one_time_prekey_ids =
        options.one_time_prekeys.iter().map(|(id, _)| id.clone()).collect::<Vec<_>>();
    let one_time_prekey_public =
        options.one_time_prekeys.iter().map(|(_, key)| *key).collect::<Vec<_>>();
    let one_time_prekey_x25519_public =
        one_time_prekey_public.iter().copied().map(encode_base64url).collect::<Vec<_>>();
    let pool_hash = one_time_prekey_pool_hash(&one_time_prekey_ids, &one_time_prekey_public)?;
    let body = PrekeyBundleSigningBody {
        schema: ramflux_protocol::domain::X3DH_PREKEY_BUNDLE,
        identity_commitment: &device_branch.principal_id,
        device_id: &device_branch.device_id,
        device_epoch: device_branch.device_epoch,
        device_identity_key_id: &format!("device:{}", device_branch.device_id),
        device_identity_ed25519_public: &encode_base64url(
            device_branch.signing_key.verifying_key().to_bytes(),
        ),
        device_agreement_x25519_public: &encode_base64url(identity_key.public),
        signed_prekey_id: options.signed_prekey_id,
        signed_prekey_x25519_public: &encode_base64url(options.signed_prekey.public),
        signed_prekey_created_at: options.signed_prekey_created_at,
        signed_prekey_expires_at: options.signed_prekey_expires_at,
        one_time_prekey_pool_hash: &encode_base64url(pool_hash),
        prekey_bundle_counter: options.prekey_bundle_counter,
        capability_scope: &["dm.x3dh".to_owned()],
    };
    let canonical = ramflux_protocol::canonical_json_bytes(&body)?;
    let signature_by_device_identity =
        encode_base64url(device_branch.signing_key.sign(&canonical).to_bytes());
    let signature_by_lineage = encode_base64url(lineage_signing_key.sign(&canonical).to_bytes());
    let one_time_prekey_signatures = one_time_prekey_ids
        .iter()
        .zip(&one_time_prekey_x25519_public)
        .map(|(id, key)| {
            let body = OneTimePrekeySigningBody {
                schema: ramflux_protocol::domain::X3DH_PREKEY_BUNDLE,
                identity_commitment: &device_branch.principal_id,
                device_id: &device_branch.device_id,
                device_epoch: device_branch.device_epoch,
                prekey_bundle_counter: options.prekey_bundle_counter,
                one_time_prekey_id: id,
                one_time_prekey_x25519_public: key,
            };
            ramflux_protocol::canonical_json_bytes(&body)
                .map(|bytes| encode_base64url(device_branch.signing_key.sign(&bytes).to_bytes()))
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(PrekeyBundle {
        schema: ramflux_protocol::domain::X3DH_PREKEY_BUNDLE.to_owned(),
        identity_commitment: device_branch.principal_id.clone(),
        device_id: device_branch.device_id.clone(),
        device_epoch: device_branch.device_epoch,
        device_identity_key_id: format!("device:{}", device_branch.device_id),
        device_identity_ed25519_public: encode_base64url(
            device_branch.signing_key.verifying_key().to_bytes(),
        ),
        device_agreement_x25519_public: identity_key.public,
        identity_key: identity_key.public,
        signed_prekey_id: options.signed_prekey_id.to_owned(),
        signed_prekey_x25519_public: options.signed_prekey.public,
        signed_prekey: options.signed_prekey.public,
        signed_prekey_created_at: options.signed_prekey_created_at,
        signed_prekey_expires_at: options.signed_prekey_expires_at,
        one_time_prekey_ids,
        one_time_prekey_x25519_public: one_time_prekey_public,
        one_time_prekey_signatures,
        one_time_prekey_pool_hash: pool_hash,
        one_time_prekey_id: None,
        one_time_prekey: None,
        one_time_prekey_signature: None,
        prekey_bundle_counter: options.prekey_bundle_counter,
        capability_scope: vec!["dm.x3dh".to_owned()],
        signature_by_device_identity: signature_by_device_identity.clone(),
        signature_by_lineage,
        signature: signature_by_device_identity,
    })
}

/// # Errors
/// Returns an error when validation, serialization, storage, or state checks fail.
pub fn verify_prekey_bundle(
    device_public_key: &VerifyingKey,
    bundle: &PrekeyBundle,
) -> Result<(), CryptoError> {
    verify_prekey_bundle_with_lineage(device_public_key, device_public_key, bundle)
}

/// # Errors
/// Returns an error when either the device identity signature or lineage signature fails.
pub fn verify_prekey_bundle_with_lineage(
    device_public_key: &VerifyingKey,
    lineage_public_key: &VerifyingKey,
    bundle: &PrekeyBundle,
) -> Result<(), CryptoError> {
    if bundle.identity_key != bundle.device_agreement_x25519_public
        || bundle.signed_prekey != bundle.signed_prekey_x25519_public
        || bundle.one_time_prekey_ids.len() != bundle.one_time_prekey_x25519_public.len()
        || bundle.one_time_prekey_ids.len() != bundle.one_time_prekey_signatures.len()
        || bundle.one_time_prekey_ids.len() > 200
        || bundle.one_time_prekey_ids.iter().collect::<std::collections::BTreeSet<_>>().len()
            != bundle.one_time_prekey_ids.len()
        || ((bundle.signed_prekey_created_at == 0) != (bundle.signed_prekey_expires_at == 0))
        || (bundle.signed_prekey_created_at > 0
            && bundle.signed_prekey_expires_at <= bundle.signed_prekey_created_at)
    {
        return Err(CryptoError::IdentityAuthority("invalid prekey bundle"));
    }
    match (&bundle.one_time_prekey_id, bundle.one_time_prekey) {
        (Some(id), Some(key)) => {
            let signature = bundle.one_time_prekey_signature.as_deref().or_else(|| {
                bundle
                    .one_time_prekey_ids
                    .iter()
                    .position(|candidate| candidate == id)
                    .and_then(|index| bundle.one_time_prekey_signatures.get(index))
                    .map(String::as_str)
            });
            verify_one_time_prekey_signature(device_public_key, bundle, id, key, signature)?;
        }
        (None, None) if bundle.one_time_prekey_signature.is_none() => {}
        _ => return Err(CryptoError::IdentityAuthority("incomplete one-time prekey selection")),
    }
    if !bundle.one_time_prekey_ids.is_empty()
        && one_time_prekey_pool_hash(
            &bundle.one_time_prekey_ids,
            &bundle.one_time_prekey_x25519_public,
        )? != bundle.one_time_prekey_pool_hash
    {
        return Err(CryptoError::IdentityAuthority("one-time prekey pool hash mismatch"));
    }
    for ((id, key), signature) in bundle
        .one_time_prekey_ids
        .iter()
        .zip(&bundle.one_time_prekey_x25519_public)
        .zip(&bundle.one_time_prekey_signatures)
    {
        verify_one_time_prekey_signature(device_public_key, bundle, id, *key, Some(signature))?;
    }
    let body = PrekeyBundleSigningBody {
        schema: &bundle.schema,
        identity_commitment: &bundle.identity_commitment,
        device_id: &bundle.device_id,
        device_epoch: bundle.device_epoch,
        device_identity_key_id: &bundle.device_identity_key_id,
        device_identity_ed25519_public: &bundle.device_identity_ed25519_public,
        device_agreement_x25519_public: &encode_base64url(bundle.device_agreement_x25519_public),
        signed_prekey_id: &bundle.signed_prekey_id,
        signed_prekey_x25519_public: &encode_base64url(bundle.signed_prekey_x25519_public),
        signed_prekey_created_at: bundle.signed_prekey_created_at,
        signed_prekey_expires_at: bundle.signed_prekey_expires_at,
        one_time_prekey_pool_hash: &encode_base64url(bundle.one_time_prekey_pool_hash),
        prekey_bundle_counter: bundle.prekey_bundle_counter,
        capability_scope: &bundle.capability_scope,
    };
    let canonical = ramflux_protocol::canonical_json_bytes(&body)?;
    let device_signature = if bundle.signature_by_device_identity.is_empty() {
        &bundle.signature
    } else {
        &bundle.signature_by_device_identity
    };
    verify_canonical_signature(
        &canonical,
        device_signature,
        &encode_base64url(device_public_key.to_bytes()),
    )?;
    verify_canonical_signature(
        &canonical,
        &bundle.signature_by_lineage,
        &encode_base64url(lineage_public_key.to_bytes()),
    )
}

fn one_time_prekey_pool_hash(ids: &[String], keys: &[[u8; 32]]) -> Result<[u8; 32], CryptoError> {
    let encoded = keys.iter().copied().map(encode_base64url).collect::<Vec<_>>();
    let canonical = ramflux_protocol::canonical_json_bytes(&(ids, encoded))?;
    Ok(crate::blake3_256("ramflux.x3dh.one_time_prekey_pool.v1", &canonical))
}

fn verify_one_time_prekey_signature(
    device_public_key: &VerifyingKey,
    bundle: &PrekeyBundle,
    id: &str,
    key: [u8; 32],
    signature: Option<&str>,
) -> Result<(), CryptoError> {
    let signature = signature
        .ok_or(CryptoError::IdentityAuthority("selected one-time prekey is not signed"))?;
    let body = OneTimePrekeySigningBody {
        schema: &bundle.schema,
        identity_commitment: &bundle.identity_commitment,
        device_id: &bundle.device_id,
        device_epoch: bundle.device_epoch,
        prekey_bundle_counter: bundle.prekey_bundle_counter,
        one_time_prekey_id: id,
        one_time_prekey_x25519_public: &encode_base64url(key),
    };
    let canonical = ramflux_protocol::canonical_json_bytes(&body)?;
    verify_canonical_signature(
        &canonical,
        signature,
        &encode_base64url(device_public_key.to_bytes()),
    )
}

fn prekey_schema() -> String {
    ramflux_protocol::domain::X3DH_PREKEY_BUNDLE.to_owned()
}
