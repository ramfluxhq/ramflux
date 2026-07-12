// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Shared v3 object-relay envelope surface (RQ-03).
//!
//! These are the SDK-owned pieces of a v3 object-relay invocation: the owner-signed access grant and
//! owner-authorization proof, and the per-invocation requester proof-of-possession. They live here in
//! `ramflux-protocol` — which both the client SDK and node-core depend on — so the SDK can build and
//! sign a v3 envelope without depending on `ramflux-node-core`.
//!
//! Only the canonical signing-byte derivation lives here (it needs nothing beyond
//! [`crate::canonical_json_bytes`]); the actual Ed25519 signing/verification is the caller's job via
//! `ramflux-crypto`. The wire shapes (field names + `snake_case` capability) are byte-for-byte
//! identical to the node-core relay verifier, so an SDK-built, protocol-signed envelope canonicalizes
//! to the same bytes the relay verifies.

use serde::{Deserialize, Serialize};

use crate::{ProtocolError, canonical_json_bytes};

/// Every v3 grant/proof/PoP payload must carry this version; any other value fails closed at the
/// verifier.
pub const OBJECT_RELAY_V3_PROOF_VERSION: u32 = 3;

/// Canonical schema tags for the SDK-owned v3 payloads.
pub const OBJECT_ACCESS_GRANT_SCHEMA: &str = "ramflux.object_access_grant.v3";
pub const OWNER_AUTHORIZATION_PROOF_SCHEMA: &str = "ramflux.owner_authorization_proof.v3";
pub const REQUESTER_POP_SCHEMA: &str = "ramflux.requester_proof_of_possession.v3";
pub const GATEWAY_ISSUER_CERTIFICATE_SCHEMA: &str = "ramflux.gateway_issuer_certificate.v3";
pub const RELAY_TOKEN_V3_AUDIENCE_RELAY: &str = "ramflux-relay";

/// The relay object operations a v3 invocation may request. `Get`/`Ack` are grant-backed; `Put`/
/// `Tombstone` are owner-session (owner-proof) backed.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ObjectRelayCapability {
    Put,
    Get,
    Ack,
    Tombstone,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RelayAuthorizationKind {
    OwnerGrant,
    OwnerSession,
}

/// Owner-signed authorization that grantee `grantee_device_hash` may Get/Ack an object. Signed by the
/// owner device; grants may only carry Get/Ack capabilities.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ObjectAccessGrant {
    pub schema: String,
    pub version: u32,
    pub object_id: String,
    pub manifest_hash: String,
    pub grantee_device_hash: String,
    pub capabilities: Vec<ObjectRelayCapability>,
    pub issued_at: u64,
    pub expires_at: u64,
    pub owner_signing_key_id: String,
    pub owner_public_key: String,
    pub owner_signature: String,
}

/// Owner-signed proof authorizing a Put/Tombstone. Deliberately carries no `token_id` (it is produced
/// before any token exists); the per-invocation `RequesterProofOfPossession` binds the token frame.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OwnerAuthorizationProof {
    pub schema: String,
    pub version: u32,
    pub capability: ObjectRelayCapability,
    pub object_id: String,
    pub manifest_hash: Option<String>,
    pub chunk_id: Option<String>,
    pub owner_home_node_id: String,
    pub owner_principal_id: String,
    pub owner_device_epoch: u64,
    pub request_nonce: String,
    pub body_hash: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub owner_signing_key_id: String,
    pub owner_public_key: String,
    pub owner_signature: String,
}

/// Per-invocation proof that the caller currently holds the requester device private key. Signed by
/// the requester device at call time and bound to the specific token and request frame.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RequesterProofOfPossession {
    pub schema: String,
    pub version: u32,
    pub token_id: String,
    pub capability: ObjectRelayCapability,
    pub object_id: String,
    pub manifest_hash: String,
    pub chunk_id: String,
    pub request_nonce: String,
    pub body_hash: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub signer_device_id: String,
    pub signer_public_key: String,
    pub signature: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GatewayIssuerCertificate {
    pub schema: String,
    pub version: u32,
    pub cert_id: String,
    pub node_id: String,
    pub gateway_instance_id: String,
    pub attestation_public_key: String,
    pub attestation_key_id: String,
    pub not_before: u64,
    pub not_after: u64,
    pub issued_at: u64,
    pub node_root_signing_key_id: String,
    pub node_root_signature: String,
    pub revoked_at: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RelayTokenV3 {
    pub token_version: u32,
    pub token_id: String,
    pub requester_device_id: String,
    pub requester_device_hash: String,
    pub requester_public_key: String,
    pub requester_device_epoch: u64,
    pub owner_signing_key_id: String,
    pub owner_public_key: String,
    pub owner_home_node_id: String,
    pub owner_principal_id: String,
    pub owner_device_epoch: u64,
    pub issuer_node_id: String,
    pub gateway_instance_id: String,
    pub issuer_certificate_id: String,
    pub attestation_key_id: String,
    pub issuer_certificate: GatewayIssuerCertificate,
    pub audience_service: String,
    pub audience_node_id: String,
    pub relay_instance_id: Option<String>,
    pub object_id: String,
    pub manifest_hash: String,
    pub chunk_id: String,
    pub capabilities: Vec<ObjectRelayCapability>,
    pub authorization_kind: RelayAuthorizationKind,
    pub authorization_binding_hash: String,
    pub delete_after_ack: bool,
    pub issued_at: u64,
    pub expires_at: u64,
    pub nonce: String,
    pub issuer_signature: String,
}

/// Canonical signing bytes for an [`ObjectAccessGrant`]: the canonical JSON of the grant with the
/// signature field cleared. The owner signs these bytes with `ramflux-crypto`.
///
/// # Errors
/// Returns an error when the grant cannot be canonicalized.
pub fn object_access_grant_signing_bytes(
    grant: &ObjectAccessGrant,
) -> Result<Vec<u8>, ProtocolError> {
    let mut canonical = grant.clone();
    canonical.owner_signature.clear();
    canonical_json_bytes(&canonical)
}

/// Canonical signing bytes for an [`OwnerAuthorizationProof`] (signature field cleared).
///
/// # Errors
/// Returns an error when the proof cannot be canonicalized.
pub fn owner_authorization_proof_signing_bytes(
    proof: &OwnerAuthorizationProof,
) -> Result<Vec<u8>, ProtocolError> {
    let mut canonical = proof.clone();
    canonical.owner_signature.clear();
    canonical_json_bytes(&canonical)
}

/// Canonical signing bytes for a [`RequesterProofOfPossession`] (signature field cleared).
///
/// # Errors
/// Returns an error when the `PoP` cannot be canonicalized.
pub fn requester_pop_signing_bytes(
    pop: &RequesterProofOfPossession,
) -> Result<Vec<u8>, ProtocolError> {
    let mut canonical = pop.clone();
    canonical.signature.clear();
    canonical_json_bytes(&canonical)
}

/// Returns canonical certificate bytes with the node-root signature cleared.
///
/// # Errors
/// Returns an error when canonical serialization fails.
pub fn gateway_issuer_certificate_signing_bytes(
    certificate: &GatewayIssuerCertificate,
) -> Result<Vec<u8>, ProtocolError> {
    let mut unsigned = certificate.clone();
    unsigned.node_root_signature.clear();
    canonical_json_bytes(&unsigned)
}

/// Returns canonical token bytes with the issuer signature cleared.
///
/// # Errors
/// Returns an error when canonical serialization fails.
pub fn relay_token_v3_signing_bytes(token: &RelayTokenV3) -> Result<Vec<u8>, ProtocolError> {
    let mut unsigned = token.clone();
    unsigned.issuer_signature.clear();
    canonical_json_bytes(&unsigned)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_grant(capability: ObjectRelayCapability) -> ObjectAccessGrant {
        ObjectAccessGrant {
            schema: OBJECT_ACCESS_GRANT_SCHEMA.to_owned(),
            version: OBJECT_RELAY_V3_PROOF_VERSION,
            object_id: "object_v3".to_owned(),
            manifest_hash: "manifest_v3".to_owned(),
            grantee_device_hash: "grantee_v3".to_owned(),
            capabilities: vec![capability],
            issued_at: 1_000_000,
            expires_at: 1_000_300,
            owner_signing_key_id: "owner_v3".to_owned(),
            owner_public_key: "owner_pk_v3".to_owned(),
            owner_signature: String::new(),
        }
    }

    fn sample_pop(capability: ObjectRelayCapability) -> RequesterProofOfPossession {
        RequesterProofOfPossession {
            schema: REQUESTER_POP_SCHEMA.to_owned(),
            version: OBJECT_RELAY_V3_PROOF_VERSION,
            token_id: "tok_v3".to_owned(),
            capability,
            object_id: "object_v3".to_owned(),
            manifest_hash: "manifest_v3".to_owned(),
            chunk_id: "chunk_v3".to_owned(),
            request_nonce: "nonce_v3".to_owned(),
            body_hash: "body_hash_v3".to_owned(),
            issued_at: 1_000_000,
            expires_at: 1_000_060,
            signer_device_id: "requester_v3".to_owned(),
            signer_public_key: "requester_pk_v3".to_owned(),
            signature: String::new(),
        }
    }

    #[test]
    fn version_and_capability_constants_are_pinned() -> Result<(), ProtocolError> {
        assert_eq!(OBJECT_RELAY_V3_PROOF_VERSION, 3);
        // Capability serializes to its snake_case wire form.
        assert_eq!(serde_json::to_string(&ObjectRelayCapability::Tombstone)?, "\"tombstone\"");
        assert_eq!(serde_json::to_string(&ObjectRelayCapability::Get)?, "\"get\"");
        Ok(())
    }

    #[test]
    fn grant_signing_bytes_excludes_signature_and_is_deterministic() -> Result<(), ProtocolError> {
        let unsigned = sample_grant(ObjectRelayCapability::Get);
        let mut signed = unsigned.clone();
        signed.owner_signature = "a-signature".to_owned();
        // The signature field is not part of the signed bytes, so a signed and unsigned grant that
        // are otherwise identical canonicalize to the same bytes.
        assert_eq!(
            object_access_grant_signing_bytes(&unsigned)?,
            object_access_grant_signing_bytes(&signed)?
        );
        // Deterministic across calls.
        assert_eq!(
            object_access_grant_signing_bytes(&unsigned)?,
            object_access_grant_signing_bytes(&unsigned)?
        );
        Ok(())
    }

    #[test]
    fn grant_signing_bytes_bind_version_and_capability() -> Result<(), ProtocolError> {
        let base = object_access_grant_signing_bytes(&sample_grant(ObjectRelayCapability::Get))?;
        // A different capability changes the signed bytes.
        let other_capability =
            object_access_grant_signing_bytes(&sample_grant(ObjectRelayCapability::Ack))?;
        assert_ne!(base, other_capability, "capability must be bound by the signing bytes");
        // A different version changes the signed bytes.
        let mut bumped = sample_grant(ObjectRelayCapability::Get);
        bumped.version = 2;
        assert_ne!(
            base,
            object_access_grant_signing_bytes(&bumped)?,
            "version must be bound by the signing bytes"
        );
        Ok(())
    }

    #[test]
    fn pop_signing_bytes_exclude_signature_and_bind_capability() -> Result<(), ProtocolError> {
        let unsigned = sample_pop(ObjectRelayCapability::Ack);
        let mut signed = unsigned.clone();
        signed.signature = "a-signature".to_owned();
        assert_eq!(requester_pop_signing_bytes(&unsigned)?, requester_pop_signing_bytes(&signed)?);
        assert_ne!(
            requester_pop_signing_bytes(&sample_pop(ObjectRelayCapability::Ack))?,
            requester_pop_signing_bytes(&sample_pop(ObjectRelayCapability::Get))?,
            "capability must be bound by the PoP signing bytes"
        );
        Ok(())
    }
}
