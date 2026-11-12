// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Linking a browser: the payload it shows, the code the user compares, and the import of the
//! enrolment bundle a native device exports.
//!
//! Linking always starts on a native device that holds account authority. The browser generates
//! its own keys, shows public data only, and later imports public data only. Nothing here can
//! create an account or approve a device.

use ramflux_protocol::custody::{BranchCertificate, DeviceRef, Envelope, object_hash};
use ramflux_protocol::{canonical_json_bytes, encode_base64url};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::WebError;
use crate::session::WebLinkPins;
use crate::wire::{
    CAPABILITY_WEB_ORIGIN_PREFIX, CAPABILITY_WEB_SECONDARY, is_canonical_listener_url,
    is_serialized_origin, web_origin_capability,
};

const LINK_CODE_TAG: &[u8] = b"ramflux.web_link_code.v1";
/// A bundle is accepted only this long after the payload was shown.
pub const LINK_PICKUP_WINDOW_SECS: u64 = 600;
/// Most capabilities a web certificate may carry.
pub const MAX_WEB_CERTIFICATE_CAPABILITIES: usize = 7;
const ALLOWED_PLAIN_CAPABILITIES: &[&str] = &["call", "group", "message", "register", "sync"];

/// What the browser shows as a QR code and as text. It holds no secret.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LinkPayload {
    pub v: u32,
    pub node_id: String,
    pub origin: String,
    pub listener_url: String,
    pub device_id: String,
    pub branch_signing_public_key: String,
    pub agreement_identity_public_key: String,
    /// Sixteen random bytes, base64url.
    pub link_nonce: String,
    pub created_at: u64,
}

impl LinkPayload {
    /// The six-digit code shown by the browser and compared on the native device.
    ///
    /// # Errors
    /// Returns [`WebError::Encoding`] when canonical serialization fails.
    pub fn link_code(&self) -> Result<String, WebError> {
        let mut hasher = Sha256::new();
        hasher.update(LINK_CODE_TAG);
        hasher.update([0_u8]);
        hasher.update(canonical_json_bytes(self)?);
        let digest = hasher.finalize();
        let head = u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]]);
        Ok(format!("{:06}", head % 1_000_000))
    }
}

/// The enrolment bundle a native device exports after it signed and published the web branch
/// certificate. Public data only.
///
/// OPEN-VALUE: the design fixes what the bundle must let the browser check, not its field names.
/// This shape is the smallest one that carries those facts.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnrolmentBundle {
    pub v: u32,
    pub node_id: String,
    pub node_signing_public_key: String,
    /// The branch certificate issued for this browser.
    pub certificate: Envelope<BranchCertificate>,
    /// Hash of the authority record (the current head) that contains the certificate.
    pub record_hash: String,
    /// The authority record itself, kept for the signature chain check.
    pub authority_record: Value,
}

/// What the browser persists after a successful import.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImportedLink {
    pub pins: WebLinkPins,
    /// Shown as "Linked to account …"; the native device shows the same value.
    pub account_fingerprint: String,
    pub certificate_expires_at: u64,
}

/// Check a bundle against the payload this browser showed and produce the link-time pins.
///
/// # Errors
/// Returns [`WebError::Link`] when the bundle is not for exactly this browser, this origin and
/// this node, lacks the web markers, or arrives outside the pickup window.
pub fn import_bundle(
    payload: &LinkPayload,
    bundle: &EnrolmentBundle,
    now: u64,
) -> Result<ImportedLink, WebError> {
    if payload.v != 1 || bundle.v != 1 {
        return Err(WebError::Link("unsupported link version"));
    }
    if !is_canonical_listener_url(&payload.listener_url) || !is_serialized_origin(&payload.origin) {
        return Err(WebError::Link("payload listener or origin is not canonical"));
    }
    if now < payload.created_at || now - payload.created_at > LINK_PICKUP_WINDOW_SECS {
        return Err(WebError::Link("bundle arrived outside the pickup window"));
    }
    if bundle.node_id != payload.node_id {
        return Err(WebError::Link("bundle is for another node"));
    }
    let certificate = &bundle.certificate.body;
    if certificate.device_id != payload.device_id
        || certificate.branch_signing_public_key != payload.branch_signing_public_key
        || certificate.agreement_identity_public_key != payload.agreement_identity_public_key
    {
        return Err(WebError::Link("certificate is not for this browser's keys"));
    }
    check_web_capabilities(&certificate.capabilities, &payload.origin)?;
    if certificate.not_before > now.saturating_add(300) || certificate.expires_at <= now {
        return Err(WebError::Link("certificate is not valid now"));
    }
    let certificate_hash = object_hash(&bundle.certificate)?;
    let fingerprint = Sha256::digest(certificate.account_anchor.as_bytes());
    Ok(ImportedLink {
        pins: WebLinkPins {
            listener_url: payload.listener_url.clone(),
            origin: payload.origin.clone(),
            node_id: bundle.node_id.clone(),
            node_signing_public_key: bundle.node_signing_public_key.clone(),
            device_ref: DeviceRef {
                account_anchor: certificate.account_anchor.clone(),
                device_id: certificate.device_id.clone(),
                device_epoch: certificate.device_epoch,
            },
            certificate_hash,
            record_hash: bundle.record_hash.clone(),
        },
        account_fingerprint: encode_base64url(&fingerprint[..10]),
        certificate_expires_at: certificate.expires_at,
    })
}

/// The shape of a web certificate: sorted, duplicate-free, both markers for this origin,
/// `message` and `register`, and nothing outside the closed set.
fn check_web_capabilities(capabilities: &[String], origin: &str) -> Result<(), WebError> {
    if capabilities.len() > MAX_WEB_CERTIFICATE_CAPABILITIES
        || !capabilities.windows(2).all(|pair| pair[0] < pair[1])
    {
        return Err(WebError::Link("capabilities are not a sorted set"));
    }
    let own_origin = web_origin_capability(origin);
    let mut origin_markers = 0_usize;
    for capability in capabilities {
        if capability.starts_with(CAPABILITY_WEB_ORIGIN_PREFIX) {
            origin_markers += 1;
            if *capability != own_origin {
                return Err(WebError::Link("certificate is bound to another origin"));
            }
        } else if capability != CAPABILITY_WEB_SECONDARY
            && !ALLOWED_PLAIN_CAPABILITIES.contains(&capability.as_str())
        {
            return Err(WebError::Link("certificate carries an unknown capability"));
        }
    }
    let has = |name: &str| capabilities.iter().any(|capability| capability == name);
    if origin_markers != 1 || !has(CAPABILITY_WEB_SECONDARY) || !has("message") || !has("register") {
        return Err(WebError::Link("certificate is not a web secondary certificate"));
    }
    Ok(())
}

/// The public keys of a freshly generated web device and the secrets that stay in its vault.
pub struct NewWebDevice {
    pub payload: LinkPayload,
    pub secrets: crate::vault_format::VaultSecrets,
}

/// Entropy for a new web device: every value comes from the platform random source.
#[derive(zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct LinkEntropy {
    pub branch_signing_seed: [u8; 32],
    pub agreement_identity_seed: [u8; 32],
    pub database_key: [u8; 32],
    pub device_id: [u8; 16],
    pub link_nonce: [u8; 16],
}

/// Generate this browser's own device keys and the payload it shows. The keys are a branch
/// signing key and an agreement identity key; a browser never generates or receives an account
/// key.
///
/// OPEN-VALUE: the device id format (`web_` plus 16 random bytes in base64url).
///
/// # Errors
/// Returns [`WebError::Link`] when the listener URL or origin is not canonical.
pub fn new_web_device(
    node_id: &str,
    listener_url: &str,
    origin: &str,
    created_at: u64,
    entropy: &LinkEntropy,
) -> Result<NewWebDevice, WebError> {
    if !is_canonical_listener_url(listener_url) || !is_serialized_origin(origin) {
        return Err(WebError::Link("listener or origin is not canonical"));
    }
    let signing = ed25519_dalek::SigningKey::from_bytes(&entropy.branch_signing_seed);
    let agreement = x25519_dalek::StaticSecret::from(entropy.agreement_identity_seed);
    let payload = LinkPayload {
        v: 1,
        node_id: node_id.to_owned(),
        origin: origin.to_owned(),
        listener_url: listener_url.to_owned(),
        device_id: format!("web_{}", encode_base64url(entropy.device_id)),
        branch_signing_public_key: encode_base64url(signing.verifying_key().to_bytes()),
        agreement_identity_public_key: encode_base64url(
            x25519_dalek::PublicKey::from(&agreement).to_bytes(),
        ),
        link_nonce: encode_base64url(entropy.link_nonce),
        created_at,
    };
    let secrets = crate::vault_format::VaultSecrets {
        branch_signing_seed: encode_base64url(entropy.branch_signing_seed),
        agreement_identity_seed: encode_base64url(entropy.agreement_identity_seed),
        database_key: encode_base64url(entropy.database_key),
    };
    Ok(NewWebDevice { payload, secrets })
}

/// Why a linked browser cannot currently authenticate, as shown to the host.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LinkState {
    /// No link exists in this browser.
    NotLinked,
    /// The payload is shown; waiting for the bundle.
    AwaitingBundle,
    Linked,
    /// The node keeps refusing. The usual cause is an authority head that changed while this
    /// browser was offline: it cannot recover alone and needs a fresh bundle or a new link.
    NeedsFreshBundle,
    /// The node expired or revoked this device.
    Unlinked,
    /// Another context of this device holds the session.
    Replaced,
    /// Local state was lost; the old web device should be removed from a native device.
    LocalStateLost,
}

#[cfg(test)]
mod tests {
    use ramflux_protocol::PrincipalKind;

    use super::*;

    const ORIGIN: &str = "https://app.example.org";
    const NOW: u64 = 1_794_500_100;

    fn payload() -> LinkPayload {
        LinkPayload {
            v: 1,
            node_id: "node-a".to_owned(),
            origin: ORIGIN.to_owned(),
            listener_url: "wss://gw.example.org/v1/session".to_owned(),
            device_id: "web-1".to_owned(),
            branch_signing_public_key: encode_base64url([1_u8; 32]),
            agreement_identity_public_key: encode_base64url([2_u8; 32]),
            link_nonce: encode_base64url([3_u8; 16]),
            created_at: NOW - 60,
        }
    }

    fn bundle(capabilities: &[&str]) -> EnrolmentBundle {
        EnrolmentBundle {
            v: 1,
            node_id: "node-a".to_owned(),
            node_signing_public_key: encode_base64url([9_u8; 32]),
            certificate: Envelope {
                body: BranchCertificate {
                    schema: "ramflux.identity.branch_certificate.v1".to_owned(),
                    version: 1,
                    account_anchor: encode_base64url([4_u8; 32]),
                    master_certificate_hash: encode_base64url([5_u8; 32]),
                    device_id: "web-1".to_owned(),
                    device_epoch: 1,
                    principal_kind: PrincipalKind::Human,
                    branch_signing_public_key: encode_base64url([1_u8; 32]),
                    agreement_identity_public_key: encode_base64url([2_u8; 32]),
                    capabilities: capabilities.iter().map(|c| (*c).to_owned()).collect(),
                    not_before: NOW - 30,
                    expires_at: NOW + 2_592_000,
                    cert_id: "cert-1".to_owned(),
                },
                signature: encode_base64url([0_u8; 64]),
            },
            record_hash: encode_base64url([6_u8; 32]),
            authority_record: Value::Null,
        }
    }

    fn web_capabilities() -> Vec<String> {
        vec![
            "message".to_owned(),
            "register".to_owned(),
            web_origin_capability(ORIGIN),
            "web_secondary".to_owned(),
        ]
    }

    #[test]
    fn a_new_web_device_publishes_only_public_keys() {
        let entropy = LinkEntropy {
            branch_signing_seed: [1; 32],
            agreement_identity_seed: [2; 32],
            database_key: [3; 32],
            device_id: [4; 16],
            link_nonce: [5; 16],
        };
        let device = new_web_device("node-a", "wss://gw.example.org/v1/session", ORIGIN, NOW, &entropy);
        let Ok(device) = device else { unreachable!("canonical inputs") };
        let shown = serde_json::to_string(&device.payload).unwrap_or_default();
        assert!(!shown.contains(&device.secrets.branch_signing_seed));
        assert!(!shown.contains(&device.secrets.agreement_identity_seed));
        assert!(!shown.contains(&device.secrets.database_key));
        assert!(device.payload.device_id.starts_with("web_"));
        assert!(new_web_device("node-a", "ws://gw.example.org/v1/session", ORIGIN, NOW, &entropy).is_err());
    }

    #[test]
    fn link_code_is_six_digits_and_changes_with_the_payload() {
        let code = payload().link_code().unwrap_or_default();
        assert_eq!(code.len(), 6);
        assert!(code.bytes().all(|b| b.is_ascii_digit()));
        let mut other = payload();
        other.device_id = "web-2".to_owned();
        assert_ne!(code, other.link_code().unwrap_or_default());
    }

    #[test]
    fn imports_a_bundle_for_exactly_this_browser_and_origin() {
        let capabilities = web_capabilities();
        let refs: Vec<&str> = capabilities.iter().map(String::as_str).collect();
        let imported = import_bundle(&payload(), &bundle(&refs), NOW);
        assert!(imported.is_ok_and(|link| link.pins.device_ref.device_id == "web-1"));
    }

    #[test]
    fn refuses_a_certificate_without_the_web_markers() {
        assert!(import_bundle(&payload(), &bundle(&["message", "register"]), NOW).is_err());
        let other = web_origin_capability("https://other.example.org");
        let caps = ["message", "register", other.as_str(), "web_secondary"];
        assert!(import_bundle(&payload(), &bundle(&caps), NOW).is_err());
    }

    #[test]
    fn refuses_a_certificate_for_other_keys_or_a_late_bundle() {
        let capabilities = web_capabilities();
        let refs: Vec<&str> = capabilities.iter().map(String::as_str).collect();
        let mut other = bundle(&refs);
        other.certificate.body.branch_signing_public_key = encode_base64url([7_u8; 32]);
        assert!(import_bundle(&payload(), &other, NOW).is_err());
        assert!(import_bundle(&payload(), &bundle(&refs), NOW + 601).is_err());
    }
}
