// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Signed service locator: a transport hint bound to the already verified terminal home key.
use super::{
    CheckpointError, Result, canonical,
    config::{validate_node, validate_origin},
    fixed, require,
};
use ed25519_dalek::{Signer, SigningKey};
use ramflux_protocol::username_directory::{self as wire, Wire};
use serde::{Deserialize, Serialize};

pub const HOME_SERVICE_DOMAIN: &str = "ramflux.identity.username_home_service.v1";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HomeServiceAddress {
    pub version: u8,
    pub node: String,
    pub public_key: String,
    pub origin: String,
    pub tls_server_name: String,
    pub ca_cert_pem: String,
    pub issued_at: u64,
    pub expires_at: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedHomeServiceAddress {
    pub body: HomeServiceAddress,
    pub signature: String,
}

impl SignedHomeServiceAddress {
    /// # Errors
    /// Refuses malformed/oversized locator metadata, unrelated keys and expired advertisements.
    pub fn verify(&self, node: &str, key: &str, now: u64) -> Result<()> {
        wire::encode(self)?;
        require(self.body.node == node && self.body.public_key == key, "home_service_identity")?;
        require(self.body.issued_at <= now && now < self.body.expires_at, "home_service_expired")?;
        ramflux_crypto::verify_canonical_signature(
            &signing_bytes(&self.body)?,
            &self.signature,
            key,
        )
        .map_err(|_| CheckpointError::Refused("home_service_signature"))
    }
}

impl Wire for SignedHomeServiceAddress {
    const LIMIT: usize = 4096;
    fn validate(&self) -> std::result::Result<(), wire::CodecError> {
        let fail = |_| wire::CodecError::Field("home_service");
        require(self.body.version == 1, "home_service_version").map_err(fail)?;
        validate_node(&self.body.node).map_err(fail)?;
        validate_node(&self.body.tls_server_name).map_err(fail)?;
        validate_origin(&self.body.origin).map_err(fail)?;
        fixed(&self.body.public_key).map_err(fail)?;
        require(
            self.body.ca_cert_pem.len() <= 2048
                && self.body.ca_cert_pem.is_ascii()
                && self.body.ca_cert_pem.starts_with("-----BEGIN CERTIFICATE-----")
                && self.body.ca_cert_pem.trim_end().ends_with("-----END CERTIFICATE-----"),
            "home_service_ca",
        )
        .map_err(fail)?;
        require(
            self.body.expires_at <= ramflux_protocol::MAX_SAFE_JSON_INTEGER
                && self
                    .body
                    .expires_at
                    .checked_sub(self.body.issued_at)
                    .is_some_and(|n| n > 0 && n <= 86400),
            "home_service_time",
        )
        .map_err(fail)?;
        let signature = ramflux_protocol::decode_base64url(&self.signature)
            .map_err(|_| wire::CodecError::Field("signature"))?;
        require(
            signature.len() == 64
                && ramflux_protocol::encode_base64url(&signature) == self.signature,
            "signature",
        )
        .map_err(fail)?;
        Ok(())
    }
}

/// The existing home node signer publishes no account data in this advertisement.
/// # Errors
/// Refuses malformed fields or an unrelated node signing key.
pub fn sign_home_service(
    key: &SigningKey,
    body: HomeServiceAddress,
) -> Result<SignedHomeServiceAddress> {
    require(
        body.public_key == ramflux_protocol::encode_base64url(key.verifying_key().to_bytes()),
        "home_service_identity",
    )?;
    let signature = ramflux_protocol::encode_base64url(key.sign(&signing_bytes(&body)?).to_bytes());
    let result = SignedHomeServiceAddress { body, signature };
    wire::encode(&result)?;
    Ok(result)
}

fn signing_bytes(body: &HomeServiceAddress) -> Result<Vec<u8>> {
    let mut bytes = HOME_SERVICE_DOMAIN.as_bytes().to_vec();
    bytes.push(0);
    bytes.extend(canonical(body)?);
    Ok(bytes)
}
