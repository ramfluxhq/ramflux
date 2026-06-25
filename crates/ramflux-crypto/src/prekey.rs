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
    pub one_time_prekey_id: Option<String>,
    pub one_time_prekey: Option<[u8; 32]>,
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
    one_time_prekey_ids: &'a [String],
    one_time_prekey_x25519_public: &'a [String],
    prekey_bundle_counter: u64,
    capability_scope: &'a [String],
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
    let one_time_prekey_ids = one_time_prekey_id.clone().into_iter().collect::<Vec<_>>();
    let one_time_prekey_x25519_public =
        one_time_prekey.iter().copied().map(encode_base64url).collect::<Vec<_>>();
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
        signed_prekey_id,
        signed_prekey_x25519_public: &encode_base64url(signed_prekey.public),
        signed_prekey_created_at: 0,
        signed_prekey_expires_at: 0,
        one_time_prekey_ids: &one_time_prekey_ids,
        one_time_prekey_x25519_public: &one_time_prekey_x25519_public,
        prekey_bundle_counter: 0,
        capability_scope: &["dm.x3dh".to_owned()],
    };
    let canonical = ramflux_protocol::canonical_json_bytes(&body)?;
    let signature_by_device_identity =
        encode_base64url(device_branch.signing_key.sign(&canonical).to_bytes());
    let signature_by_lineage = encode_base64url(lineage_signing_key.sign(&canonical).to_bytes());
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
        signed_prekey_id: signed_prekey_id.to_owned(),
        signed_prekey_x25519_public: signed_prekey.public,
        signed_prekey: signed_prekey.public,
        signed_prekey_created_at: 0,
        signed_prekey_expires_at: 0,
        one_time_prekey_ids,
        one_time_prekey_x25519_public: one_time_prekey.iter().copied().collect(),
        one_time_prekey_id,
        one_time_prekey,
        prekey_bundle_counter: 0,
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
    let one_time_prekey_x25519_public = if bundle.one_time_prekey_x25519_public.is_empty() {
        bundle.one_time_prekey.iter().copied().map(encode_base64url).collect::<Vec<_>>()
    } else {
        bundle
            .one_time_prekey_x25519_public
            .iter()
            .copied()
            .map(encode_base64url)
            .collect::<Vec<_>>()
    };
    let one_time_prekey_ids = if bundle.one_time_prekey_ids.is_empty() {
        bundle.one_time_prekey_id.clone().into_iter().collect::<Vec<_>>()
    } else {
        bundle.one_time_prekey_ids.clone()
    };
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
        one_time_prekey_ids: &one_time_prekey_ids,
        one_time_prekey_x25519_public: &one_time_prekey_x25519_public,
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

fn prekey_schema() -> String {
    ramflux_protocol::domain::X3DH_PREKEY_BUNDLE.to_owned()
}
