// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! V3 grants, owner proofs, requester binding, and relay invocation validation.

use super::{
    Deserialize, GatewayIssuerCertificate, NodeCoreError, OBJECT_RELAY_CLOCK_SKEW_LEEWAY_SECONDS,
    OBJECT_RELAY_TOKEN_MAX_TTL_SECONDS, Serialize, gateway_issuer_certificate_binding_hash,
    verify_gateway_issuer_certificate,
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ObjectRelayCapability {
    Put,
    Get,
    Ack,
    Tombstone,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GatewayRelayTokenV3IssueRequest {
    pub signed_request: ramflux_protocol::SignedRequest,
    pub body: RelayTokenV3IssueRequest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GatewayRelayTokenV3IssueResponse {
    pub relay_token: RelayTokenV3,
}

// ===========================================================================================
// RQ-03-V3-T1: object relay v3 proof types + pure verification logic.
//
// This block is NOT wired into any production handler. It defines the asymmetric issuer-attestation
// token (v3), the owner-signed access grant, the owner authorization proof and the per-invocation
// requester proof-of-possession, plus pure verifiers and a capability/proof matrix. The existing v2
// HMAC path (RelayToken/validate_relay_token) is untouched. v3 has no HMAC/shared-key surface.
// ===========================================================================================

pub const OBJECT_RELAY_TOKEN_V3_VERSION: u32 = 3;
pub const OBJECT_ACCESS_GRANT_SCHEMA: &str = "ramflux.object_access_grant.v3";
pub const OWNER_AUTHORIZATION_PROOF_SCHEMA: &str = "ramflux.owner_authorization_proof.v3";
pub const REQUESTER_POP_SCHEMA: &str = "ramflux.requester_proof_of_possession.v3";
pub const RELAY_TOKEN_V3_AUDIENCE_RELAY: &str = "ramflux-relay";
pub(super) const OBJECT_ACCESS_GRANT_BINDING_DOMAIN: &str =
    "ramflux.object_access_grant.binding.v3";
pub(super) const OWNER_AUTHORIZATION_PROOF_BINDING_DOMAIN: &str =
    "ramflux.owner_authorization_proof.binding.v3";

/// Which authorization instrument backs a v3 token. Get/Ack are backed by an owner-signed grant;
/// Put/Tombstone are backed by an authenticated owner session + owner authorization proof.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RelayAuthorizationKind {
    OwnerGrant,
    OwnerSession,
}

/// Owner-signed authorization that grantee `grantee_device_hash` may Get/Ack an object. Signed by
/// the owner device; the relay's chunk-owner binding is the ultimate anchor. Grants may only carry
/// Get/Ack capabilities.
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

/// Owner-signed proof authorizing a Put/Tombstone. Deliberately does NOT contain a `token_id`: it is
/// produced before any token exists, so binding it to a future token id would be circular. The
/// per-invocation `RequesterProofOfPossession` is what binds `token_id`/capability/chunk/nonce/body.
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
/// the requester device at call time and bound to the specific token and request frame, so a leaked
/// bearer token cannot be replayed by a party without the requester key.
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

/// Asymmetric issuer-attestation relay token (v3). Signed by the issuing gateway's attestation key
/// (verified by the relay against a node-root-signed certificate, out of scope for T1). No HMAC/mac
/// field exists; there is no shared-key path.
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
    /// The gateway issuer certificate carried inline with the token/frame. It participates in the
    /// token's canonical bytes, so `issuer_signature` commits to it and a frame cannot swap it. The
    /// relay still verifies this certificate against a pinned node-root key and against the expected
    /// certificate it holds.
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

/// Inputs supplied by an authenticated gateway when issuing an asymmetric v3 relay token.
/// Certificate/root trust verification is performed by the relay verifier; issuance still checks
/// the certificate identity/window and all token binding invariants before signing.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RelayTokenV3IssueRequest {
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
    pub issuer_certificate: GatewayIssuerCertificate,
}

/// Issues an issuer-signed v3 relay token after validating its security bindings.
///
/// This is deliberately independent of gateway session/authentication state. The caller must
/// authenticate the session and provide the issuer private key; this function enforces the token
/// shape, certificate binding, capability/authorization matrix, and bounded TTL.
///
/// # Errors
/// Returns an error when identity fields, certificate binding, TTL, capability matrix, or signing
/// inputs are invalid.
pub fn issue_gateway_relay_token_v3(
    request: &RelayTokenV3IssueRequest,
    issuer_signing_seed: [u8; 32],
    now: u64,
) -> Result<RelayTokenV3, NodeCoreError> {
    require_non_empty(&request.requester_device_id, "requester_device_id")?;
    require_non_empty(&request.requester_device_hash, "requester_device_hash")?;
    require_non_empty(&request.requester_public_key, "requester_public_key")?;
    require_non_empty(&request.owner_signing_key_id, "owner_signing_key_id")?;
    require_non_empty(&request.owner_public_key, "owner_public_key")?;
    require_non_empty(&request.owner_home_node_id, "owner_home_node_id")?;
    require_non_empty(&request.owner_principal_id, "owner_principal_id")?;
    require_non_empty(&request.issuer_node_id, "issuer_node_id")?;
    require_non_empty(&request.gateway_instance_id, "gateway_instance_id")?;
    require_non_empty(&request.audience_node_id, "audience_node_id")?;
    require_non_empty(&request.object_id, "object_id")?;
    require_non_empty(&request.manifest_hash, "manifest_hash")?;
    require_non_empty(&request.chunk_id, "chunk_id")?;
    require_non_empty(&request.authorization_binding_hash, "authorization_binding_hash")?;
    require_non_empty(&request.nonce, "nonce")?;
    if request.issuer_certificate.node_id != request.issuer_node_id
        || request.issuer_certificate.gateway_instance_id != request.gateway_instance_id
    {
        return Err(NodeCoreError::Unauthorized(
            "relay token issuer certificate identity mismatch".to_owned(),
        ));
    }
    if request.issuer_certificate.revoked_at.is_some()
        || now < request.issuer_certificate.not_before
        || now >= request.issuer_certificate.not_after
    {
        return Err(NodeCoreError::TtlExpired { envelope_id: request.object_id.clone() });
    }
    if request.issued_at > now.saturating_add(OBJECT_RELAY_CLOCK_SKEW_LEEWAY_SECONDS)
        || request.expires_at <= now
        || request.expires_at > now.saturating_add(OBJECT_RELAY_TOKEN_MAX_TTL_SECONDS)
        || request.expires_at > request.issuer_certificate.not_after
    {
        return Err(NodeCoreError::TtlExpired { envelope_id: request.chunk_id.clone() });
    }
    if request.capabilities.len() != 1 {
        return Err(NodeCoreError::Unauthorized(
            "relay v3 token must carry exactly one capability".to_owned(),
        ));
    }
    let capability = request.capabilities[0];
    let expected_kind =
        if matches!(capability, ObjectRelayCapability::Get | ObjectRelayCapability::Ack) {
            RelayAuthorizationKind::OwnerGrant
        } else {
            RelayAuthorizationKind::OwnerSession
        };
    if request.authorization_kind != expected_kind {
        return Err(NodeCoreError::Unauthorized(
            "relay v3 authorization kind does not match capability".to_owned(),
        ));
    }
    if request.delete_after_ack && capability != ObjectRelayCapability::Put {
        return Err(NodeCoreError::Unauthorized(
            "delete_after_ack is only permitted on put relay tokens".to_owned(),
        ));
    }
    let mut token = RelayTokenV3 {
        token_version: OBJECT_RELAY_TOKEN_V3_VERSION,
        token_id: format!("v3:{}:{}:{capability:?}", request.chunk_id, request.expires_at),
        requester_device_id: request.requester_device_id.clone(),
        requester_device_hash: request.requester_device_hash.clone(),
        requester_public_key: request.requester_public_key.clone(),
        requester_device_epoch: request.requester_device_epoch,
        owner_signing_key_id: request.owner_signing_key_id.clone(),
        owner_public_key: request.owner_public_key.clone(),
        owner_home_node_id: request.owner_home_node_id.clone(),
        owner_principal_id: request.owner_principal_id.clone(),
        owner_device_epoch: request.owner_device_epoch,
        issuer_node_id: request.issuer_node_id.clone(),
        gateway_instance_id: request.gateway_instance_id.clone(),
        issuer_certificate_id: request.issuer_certificate.cert_id.clone(),
        attestation_key_id: request.issuer_certificate.attestation_key_id.clone(),
        issuer_certificate: request.issuer_certificate.clone(),
        audience_service: RELAY_TOKEN_V3_AUDIENCE_RELAY.to_owned(),
        audience_node_id: request.audience_node_id.clone(),
        relay_instance_id: request.relay_instance_id.clone(),
        object_id: request.object_id.clone(),
        manifest_hash: request.manifest_hash.clone(),
        chunk_id: request.chunk_id.clone(),
        capabilities: request.capabilities.clone(),
        authorization_kind: request.authorization_kind,
        authorization_binding_hash: request.authorization_binding_hash.clone(),
        delete_after_ack: request.delete_after_ack,
        issued_at: request.issued_at,
        expires_at: request.expires_at,
        nonce: request.nonce.clone(),
        issuer_signature: String::new(),
    };
    token.issuer_signature = ramflux_crypto::sign_canonical_bytes_with_seed(
        &relay_token_v3_signing_bytes(&token)?,
        issuer_signing_seed,
    );
    Ok(token)
}

/// All inputs the relay needs to authorize a single v3 invocation. Bundled so the matrix verifier
/// stays a single-argument pure function.
pub struct RelayInvocationV3<'a> {
    pub token: &'a RelayTokenV3,
    pub issuer_public_key: &'a str,
    pub grant: Option<&'a ObjectAccessGrant>,
    pub owner_proof: Option<&'a OwnerAuthorizationProof>,
    pub pop: &'a RequesterProofOfPossession,
    pub expected_audience_node_id: &'a str,
    pub expected_body_hash: &'a str,
    pub capability: ObjectRelayCapability,
    pub now: u64,
}

/// Every v3 grant/proof/PoP payload must carry this version; any other value fails closed.
pub const OBJECT_RELAY_V3_PROOF_VERSION: u32 = 3;

#[must_use]
pub(super) fn is_grant_capability(capability: ObjectRelayCapability) -> bool {
    matches!(capability, ObjectRelayCapability::Get | ObjectRelayCapability::Ack)
}

#[must_use]
pub(super) fn is_owner_session_capability(capability: ObjectRelayCapability) -> bool {
    matches!(capability, ObjectRelayCapability::Put | ObjectRelayCapability::Tombstone)
}

pub(super) fn require_non_empty(value: &str, field: &str) -> Result<(), NodeCoreError> {
    if value.is_empty() {
        return Err(NodeCoreError::Unauthorized(format!("relay v3 {field} must not be empty")));
    }
    Ok(())
}

/// Returns `true` when the capability list has no duplicate entries.
#[must_use]
pub(super) fn capabilities_have_no_duplicates(capabilities: &[ObjectRelayCapability]) -> bool {
    capabilities
        .iter()
        .enumerate()
        .all(|(index, capability)| !capabilities[index + 1..].contains(capability))
}

/// # Errors
/// Returns an error when the grant cannot be canonicalized.
pub fn object_access_grant_signing_bytes(
    grant: &ObjectAccessGrant,
) -> Result<Vec<u8>, NodeCoreError> {
    let mut canonical = grant.clone();
    canonical.owner_signature.clear();
    ramflux_protocol::canonical_json_bytes(&canonical)
        .map_err(|source| NodeCoreError::ItestJson(source.to_string()))
}

/// # Errors
/// Returns an error when the grant cannot be canonicalized. Binds the exact signed grant.
pub fn object_access_grant_binding_hash(
    grant: &ObjectAccessGrant,
) -> Result<String, NodeCoreError> {
    let canonical = ramflux_protocol::canonical_json_bytes(grant)
        .map_err(|source| NodeCoreError::ItestJson(source.to_string()))?;
    Ok(ramflux_crypto::blake3_256_base64url(OBJECT_ACCESS_GRANT_BINDING_DOMAIN, &canonical))
}

/// # Errors
/// Returns an error when the proof cannot be canonicalized.
pub fn owner_authorization_proof_signing_bytes(
    proof: &OwnerAuthorizationProof,
) -> Result<Vec<u8>, NodeCoreError> {
    let mut canonical = proof.clone();
    canonical.owner_signature.clear();
    ramflux_protocol::canonical_json_bytes(&canonical)
        .map_err(|source| NodeCoreError::ItestJson(source.to_string()))
}

/// # Errors
/// Returns an error when the proof cannot be canonicalized. Binds the exact signed proof.
pub fn owner_authorization_proof_binding_hash(
    proof: &OwnerAuthorizationProof,
) -> Result<String, NodeCoreError> {
    let canonical = ramflux_protocol::canonical_json_bytes(proof)
        .map_err(|source| NodeCoreError::ItestJson(source.to_string()))?;
    Ok(ramflux_crypto::blake3_256_base64url(OWNER_AUTHORIZATION_PROOF_BINDING_DOMAIN, &canonical))
}

/// # Errors
/// Returns an error when the `PoP` cannot be canonicalized.
pub fn requester_pop_signing_bytes(
    pop: &RequesterProofOfPossession,
) -> Result<Vec<u8>, NodeCoreError> {
    let mut canonical = pop.clone();
    canonical.signature.clear();
    ramflux_protocol::canonical_json_bytes(&canonical)
        .map_err(|source| NodeCoreError::ItestJson(source.to_string()))
}

/// # Errors
/// Returns an error when the token cannot be canonicalized.
pub fn relay_token_v3_signing_bytes(token: &RelayTokenV3) -> Result<Vec<u8>, NodeCoreError> {
    let mut canonical = token.clone();
    canonical.issuer_signature.clear();
    ramflux_protocol::canonical_json_bytes(&canonical)
        .map_err(|source| NodeCoreError::ItestJson(source.to_string()))
}

pub(super) fn within_ttl(
    issued_at: u64,
    expires_at: u64,
    now: u64,
    envelope_id: &str,
) -> Result<(), NodeCoreError> {
    if issued_at > now.saturating_add(OBJECT_RELAY_CLOCK_SKEW_LEEWAY_SECONDS) || expires_at <= now {
        return Err(NodeCoreError::TtlExpired { envelope_id: envelope_id.to_owned() });
    }
    Ok(())
}

/// # Errors
/// Returns an error when the grant schema, capability set, TTL, or owner signature is invalid.
pub fn verify_object_access_grant(
    grant: &ObjectAccessGrant,
    capability: ObjectRelayCapability,
    now: u64,
) -> Result<(), NodeCoreError> {
    if grant.schema != OBJECT_ACCESS_GRANT_SCHEMA {
        return Err(NodeCoreError::ItestJson("object access grant schema rejected".to_owned()));
    }
    if grant.version != OBJECT_RELAY_V3_PROOF_VERSION {
        return Err(NodeCoreError::ItestJson("object access grant version rejected".to_owned()));
    }
    if !is_grant_capability(capability) {
        return Err(NodeCoreError::Unauthorized(
            "object access grant only authorizes get/ack".to_owned(),
        ));
    }
    if grant.capabilities.is_empty()
        || grant.capabilities.iter().any(|cap| !is_grant_capability(*cap))
        || !capabilities_have_no_duplicates(&grant.capabilities)
    {
        return Err(NodeCoreError::Unauthorized(
            "object access grant capabilities must be a non-empty, duplicate-free subset of get/ack"
                .to_owned(),
        ));
    }
    if !grant.capabilities.contains(&capability) {
        return Err(NodeCoreError::Unauthorized(
            "object access grant does not cover requested capability".to_owned(),
        ));
    }
    require_non_empty(&grant.object_id, "grant object_id")?;
    require_non_empty(&grant.manifest_hash, "grant manifest_hash")?;
    require_non_empty(&grant.grantee_device_hash, "grant grantee_device_hash")?;
    require_non_empty(&grant.owner_signing_key_id, "grant owner_signing_key_id")?;
    require_non_empty(&grant.owner_public_key, "grant owner_public_key")?;
    require_non_empty(&grant.owner_signature, "grant owner_signature")?;
    within_ttl(grant.issued_at, grant.expires_at, now, &grant.object_id)?;
    ramflux_crypto::verify_canonical_signature(
        &object_access_grant_signing_bytes(grant)?,
        &grant.owner_signature,
        &grant.owner_public_key,
    )
    .map_err(|source| NodeCoreError::Unauthorized(source.to_string()))
}

/// # Errors
/// Returns an error when the proof schema, capability, TTL, or owner signature is invalid.
pub fn verify_owner_authorization_proof(
    proof: &OwnerAuthorizationProof,
    capability: ObjectRelayCapability,
    now: u64,
) -> Result<(), NodeCoreError> {
    if proof.schema != OWNER_AUTHORIZATION_PROOF_SCHEMA {
        return Err(NodeCoreError::ItestJson(
            "owner authorization proof schema rejected".to_owned(),
        ));
    }
    if proof.version != OBJECT_RELAY_V3_PROOF_VERSION {
        return Err(NodeCoreError::ItestJson(
            "owner authorization proof version rejected".to_owned(),
        ));
    }
    if !is_owner_session_capability(capability) {
        return Err(NodeCoreError::Unauthorized(
            "owner authorization proof only authorizes put/tombstone".to_owned(),
        ));
    }
    if proof.capability != capability {
        return Err(NodeCoreError::Unauthorized(
            "owner authorization proof capability mismatch".to_owned(),
        ));
    }
    require_non_empty(&proof.object_id, "owner proof object_id")?;
    require_non_empty(&proof.owner_home_node_id, "owner proof owner_home_node_id")?;
    require_non_empty(&proof.owner_principal_id, "owner proof owner_principal_id")?;
    require_non_empty(&proof.request_nonce, "owner proof request_nonce")?;
    require_non_empty(&proof.body_hash, "owner proof body_hash")?;
    require_non_empty(&proof.owner_signing_key_id, "owner proof owner_signing_key_id")?;
    require_non_empty(&proof.owner_public_key, "owner proof owner_public_key")?;
    require_non_empty(&proof.owner_signature, "owner proof owner_signature")?;
    within_ttl(proof.issued_at, proof.expires_at, now, &proof.object_id)?;
    ramflux_crypto::verify_canonical_signature(
        &owner_authorization_proof_signing_bytes(proof)?,
        &proof.owner_signature,
        &proof.owner_public_key,
    )
    .map_err(|source| NodeCoreError::Unauthorized(source.to_string()))
}

/// # Errors
/// Returns an error when the `PoP` schema, TTL, or requester signature is invalid.
pub fn verify_requester_pop(
    pop: &RequesterProofOfPossession,
    signer_public_key: &str,
    now: u64,
) -> Result<(), NodeCoreError> {
    if pop.schema != REQUESTER_POP_SCHEMA {
        return Err(NodeCoreError::ItestJson("requester pop schema rejected".to_owned()));
    }
    if pop.version != OBJECT_RELAY_V3_PROOF_VERSION {
        return Err(NodeCoreError::ItestJson("requester pop version rejected".to_owned()));
    }
    require_non_empty(&pop.token_id, "pop token_id")?;
    require_non_empty(&pop.object_id, "pop object_id")?;
    require_non_empty(&pop.manifest_hash, "pop manifest_hash")?;
    require_non_empty(&pop.chunk_id, "pop chunk_id")?;
    require_non_empty(&pop.request_nonce, "pop request_nonce")?;
    require_non_empty(&pop.body_hash, "pop body_hash")?;
    require_non_empty(&pop.signer_device_id, "pop signer_device_id")?;
    require_non_empty(&pop.signer_public_key, "pop signer_public_key")?;
    require_non_empty(&pop.signature, "pop signature")?;
    within_ttl(pop.issued_at, pop.expires_at, now, &pop.token_id)?;
    ramflux_crypto::verify_canonical_signature(
        &requester_pop_signing_bytes(pop)?,
        &pop.signature,
        signer_public_key,
    )
    .map_err(|source| NodeCoreError::Unauthorized(source.to_string()))
}

/// # Errors
/// Returns an error when the token version, audience, capability, authorization kind, TTL, or issuer
/// signature is invalid. Rejects any non-v3 token (there is no HMAC/shared-key path).
pub fn verify_relay_token_v3(
    token: &RelayTokenV3,
    issuer_public_key: &str,
    capability: ObjectRelayCapability,
    expected_audience_node_id: &str,
    now: u64,
) -> Result<(), NodeCoreError> {
    if token.token_version != OBJECT_RELAY_TOKEN_V3_VERSION {
        return Err(NodeCoreError::Unauthorized(
            "relay token version rejected: v3 issuer-signed token required".to_owned(),
        ));
    }
    if token.audience_service != RELAY_TOKEN_V3_AUDIENCE_RELAY {
        return Err(NodeCoreError::Unauthorized(
            "relay token audience service rejected".to_owned(),
        ));
    }
    if token.audience_node_id != expected_audience_node_id {
        return Err(NodeCoreError::Unauthorized("relay token audience node rejected".to_owned()));
    }
    if token.capabilities.len() != 1
        || !token.capabilities.contains(&capability)
        || !capabilities_have_no_duplicates(&token.capabilities)
    {
        return Err(NodeCoreError::Unauthorized("relay token capability rejected".to_owned()));
    }
    let expected_kind = if is_grant_capability(capability) {
        RelayAuthorizationKind::OwnerGrant
    } else {
        RelayAuthorizationKind::OwnerSession
    };
    if token.authorization_kind != expected_kind {
        return Err(NodeCoreError::Unauthorized(
            "relay token authorization kind mismatch for capability".to_owned(),
        ));
    }
    // A destructive delete-on-ack policy may only ride on a Put token.
    if token.delete_after_ack && capability != ObjectRelayCapability::Put {
        return Err(NodeCoreError::Unauthorized(
            "relay token delete_after_ack is only permitted for put".to_owned(),
        ));
    }
    // Critical identity/key/hash/nonce fields must be present.
    require_non_empty(&token.token_id, "token token_id")?;
    require_non_empty(&token.requester_device_id, "token requester_device_id")?;
    require_non_empty(&token.requester_device_hash, "token requester_device_hash")?;
    require_non_empty(&token.requester_public_key, "token requester_public_key")?;
    require_non_empty(&token.owner_signing_key_id, "token owner_signing_key_id")?;
    require_non_empty(&token.owner_public_key, "token owner_public_key")?;
    require_non_empty(&token.owner_home_node_id, "token owner_home_node_id")?;
    require_non_empty(&token.owner_principal_id, "token owner_principal_id")?;
    require_non_empty(&token.issuer_node_id, "token issuer_node_id")?;
    require_non_empty(&token.gateway_instance_id, "token gateway_instance_id")?;
    require_non_empty(&token.issuer_certificate_id, "token issuer_certificate_id")?;
    require_non_empty(&token.attestation_key_id, "token attestation_key_id")?;
    require_non_empty(&token.audience_node_id, "token audience_node_id")?;
    require_non_empty(&token.object_id, "token object_id")?;
    require_non_empty(&token.manifest_hash, "token manifest_hash")?;
    require_non_empty(&token.chunk_id, "token chunk_id")?;
    require_non_empty(&token.authorization_binding_hash, "token authorization_binding_hash")?;
    require_non_empty(&token.nonce, "token nonce")?;
    if token.expires_at > token.issued_at.saturating_add(OBJECT_RELAY_TOKEN_MAX_TTL_SECONDS) {
        return Err(NodeCoreError::TtlExpired { envelope_id: token.token_id.clone() });
    }
    within_ttl(token.issued_at, token.expires_at, now, &token.token_id)?;
    ramflux_crypto::verify_canonical_signature(
        &relay_token_v3_signing_bytes(token)?,
        &token.issuer_signature,
        issuer_public_key,
    )
    .map_err(|source| NodeCoreError::Unauthorized(source.to_string()))
}

/// Verifies a v3 relay token against the gateway issuer certificate carried inline with it and a
/// pinned node-root public key.
///
/// The token embeds its issuer certificate (`token.issuer_certificate`), which is covered by the
/// token's `issuer_signature`. The relay is also given the certificate it expects (`certificate`,
/// from its trusted provider in a later integration step) and requires the frame-carried certificate
/// to be identical — same canonical bytes and same `cert_id`/`attestation_key_id`/node/instance — so a
/// frame cannot substitute a different (even if separately root-valid) certificate. The embedded
/// certificate is then verified against the pinned node root, its `cert_id`/`attestation_key_id`
/// must match the token's declared references, and finally its attestation key verifies the token's
/// issuer signature.
///
/// # Errors
/// Returns an error when the frame/expected certificate mismatch, the certificate chain, the
/// token/certificate binding, or the token itself fails to verify.
pub fn verify_relay_token_v3_with_certificate(
    token: &RelayTokenV3,
    certificate: &GatewayIssuerCertificate,
    node_root_public_key: &str,
    capability: ObjectRelayCapability,
    expected_audience_node_id: &str,
    now: u64,
) -> Result<(), NodeCoreError> {
    let embedded = &token.issuer_certificate;
    // The frame-carried certificate must be exactly the certificate the relay expects.
    if embedded.cert_id != certificate.cert_id
        || embedded.attestation_key_id != certificate.attestation_key_id
        || embedded.node_id != certificate.node_id
        || embedded.gateway_instance_id != certificate.gateway_instance_id
        || gateway_issuer_certificate_binding_hash(embedded)?
            != gateway_issuer_certificate_binding_hash(certificate)?
    {
        return Err(NodeCoreError::Unauthorized(
            "token issuer certificate does not match the expected certificate".to_owned(),
        ));
    }
    // Verify the embedded certificate against the pinned node root, bound to the token's issuer.
    verify_gateway_issuer_certificate(
        embedded,
        node_root_public_key,
        &token.issuer_node_id,
        &token.gateway_instance_id,
        now,
    )?;
    // The token's declared certificate references must match the embedded certificate.
    if embedded.cert_id != token.issuer_certificate_id {
        return Err(NodeCoreError::Unauthorized(
            "token issuer certificate id does not match embedded certificate".to_owned(),
        ));
    }
    if embedded.attestation_key_id != token.attestation_key_id {
        return Err(NodeCoreError::Unauthorized(
            "token attestation key id does not match embedded certificate".to_owned(),
        ));
    }
    // Finally verify the token issuer signature with the embedded certificate's attestation key.
    verify_relay_token_v3(
        token,
        &embedded.attestation_public_key,
        capability,
        expected_audience_node_id,
        now,
    )
}

pub(super) fn verify_grant_invocation(
    token: &RelayTokenV3,
    grant: Option<&ObjectAccessGrant>,
    owner_proof: Option<&OwnerAuthorizationProof>,
    capability: ObjectRelayCapability,
    now: u64,
) -> Result<(), NodeCoreError> {
    if owner_proof.is_some() {
        return Err(NodeCoreError::Unauthorized(
            "get/ack must not carry an owner authorization proof".to_owned(),
        ));
    }
    let grant = grant.ok_or_else(|| {
        NodeCoreError::Unauthorized("get/ack requires an object access grant".to_owned())
    })?;
    verify_object_access_grant(grant, capability, now)?;
    if grant.owner_signing_key_id != token.owner_signing_key_id
        || grant.owner_public_key != token.owner_public_key
    {
        return Err(NodeCoreError::Unauthorized(
            "grant owner does not match token owner".to_owned(),
        ));
    }
    if grant.grantee_device_hash != token.requester_device_hash {
        return Err(NodeCoreError::Unauthorized(
            "grant grantee does not match token requester".to_owned(),
        ));
    }
    if grant.object_id != token.object_id || grant.manifest_hash != token.manifest_hash {
        return Err(NodeCoreError::Unauthorized("grant object binding mismatch".to_owned()));
    }
    if token.authorization_binding_hash != object_access_grant_binding_hash(grant)? {
        return Err(NodeCoreError::Unauthorized(
            "token authorization binding hash does not match grant".to_owned(),
        ));
    }
    Ok(())
}

pub(super) fn verify_owner_session_invocation(
    token: &RelayTokenV3,
    grant: Option<&ObjectAccessGrant>,
    owner_proof: Option<&OwnerAuthorizationProof>,
    capability: ObjectRelayCapability,
    expected_body_hash: &str,
    now: u64,
) -> Result<(), NodeCoreError> {
    if grant.is_some() {
        return Err(NodeCoreError::Unauthorized(
            "put/tombstone must not carry an object access grant".to_owned(),
        ));
    }
    let proof = owner_proof.ok_or_else(|| {
        NodeCoreError::Unauthorized(
            "put/tombstone requires an owner authorization proof".to_owned(),
        )
    })?;
    verify_owner_authorization_proof(proof, capability, now)?;
    if proof.owner_signing_key_id != token.owner_signing_key_id
        || proof.owner_public_key != token.owner_public_key
    {
        return Err(NodeCoreError::Unauthorized(
            "proof owner does not match token owner".to_owned(),
        ));
    }
    // For owner-session operations the requester is the owner itself.
    if token.requester_device_id != token.owner_signing_key_id
        || token.requester_public_key != token.owner_public_key
    {
        return Err(NodeCoreError::Unauthorized(
            "put/tombstone requester must be the owner device".to_owned(),
        ));
    }
    if proof.object_id != token.object_id
        || proof.owner_home_node_id != token.owner_home_node_id
        || proof.owner_principal_id != token.owner_principal_id
        || proof.owner_device_epoch != token.owner_device_epoch
    {
        return Err(NodeCoreError::Unauthorized("proof owner/object binding mismatch".to_owned()));
    }
    // The proof's manifest must match the token.
    if proof.manifest_hash.as_deref() != Some(token.manifest_hash.as_str()) {
        return Err(NodeCoreError::Unauthorized("proof manifest binding mismatch".to_owned()));
    }
    // Put must bind the exact chunk; Tombstone may be whole-object (None) but a present chunk id
    // must match the token.
    match capability {
        ObjectRelayCapability::Put => {
            if proof.chunk_id.as_deref() != Some(token.chunk_id.as_str()) {
                return Err(NodeCoreError::Unauthorized(
                    "put owner proof must bind the token chunk".to_owned(),
                ));
            }
        }
        ObjectRelayCapability::Tombstone => {
            if let Some(chunk_id) = proof.chunk_id.as_deref()
                && chunk_id != token.chunk_id
            {
                return Err(NodeCoreError::Unauthorized(
                    "tombstone owner proof chunk mismatch".to_owned(),
                ));
            }
        }
        ObjectRelayCapability::Get | ObjectRelayCapability::Ack => {
            return Err(NodeCoreError::Unauthorized(
                "owner authorization proof cannot back get/ack".to_owned(),
            ));
        }
    }
    // The proof binds the request body, mirroring the per-invocation PoP.
    if proof.body_hash != expected_body_hash {
        return Err(NodeCoreError::Unauthorized("proof body hash mismatch".to_owned()));
    }
    if token.authorization_binding_hash != owner_authorization_proof_binding_hash(proof)? {
        return Err(NodeCoreError::Unauthorized(
            "token authorization binding hash does not match owner proof".to_owned(),
        ));
    }
    Ok(())
}

pub(super) fn verify_pop_binding(
    token: &RelayTokenV3,
    pop: &RequesterProofOfPossession,
    capability: ObjectRelayCapability,
    expected_body_hash: &str,
    now: u64,
) -> Result<(), NodeCoreError> {
    // The PoP signature is verified against the gateway-attested requester key on the token, not the
    // PoP's self-declared key; the self-declared key must match to avoid confusion.
    verify_requester_pop(pop, &token.requester_public_key, now)?;
    if pop.signer_device_id != token.requester_device_id
        || pop.signer_public_key != token.requester_public_key
    {
        return Err(NodeCoreError::Unauthorized(
            "pop signer is not the token requester".to_owned(),
        ));
    }
    if pop.token_id != token.token_id {
        return Err(NodeCoreError::Unauthorized("pop is not bound to this token".to_owned()));
    }
    if pop.capability != capability {
        return Err(NodeCoreError::Unauthorized("pop capability mismatch".to_owned()));
    }
    if pop.object_id != token.object_id
        || pop.manifest_hash != token.manifest_hash
        || pop.chunk_id != token.chunk_id
    {
        return Err(NodeCoreError::Unauthorized("pop object binding mismatch".to_owned()));
    }
    if pop.body_hash != expected_body_hash {
        return Err(NodeCoreError::Unauthorized("pop body hash mismatch".to_owned()));
    }
    Ok(())
}

/// Capability/proof matrix verifier for a single v3 invocation. Fails closed on any missing, extra,
/// or wrong-kind proof.
///
/// - Get/Ack require `OwnerGrant` + an `ObjectAccessGrant` (no owner proof) + `RequesterPoP`.
/// - Put/Tombstone require `OwnerSession` + an `OwnerAuthorizationProof` (no grant) + `RequesterPoP`.
/// - Grants may never carry Put/Tombstone; tokens must be v3 (no HMAC/shared-key fallback).
///
/// # Errors
/// Returns an error when the token, the capability/proof matrix, the authorization binding, or the
/// requester proof-of-possession fails to verify.
pub fn verify_relay_invocation_v3(ctx: &RelayInvocationV3<'_>) -> Result<(), NodeCoreError> {
    verify_relay_token_v3(
        ctx.token,
        ctx.issuer_public_key,
        ctx.capability,
        ctx.expected_audience_node_id,
        ctx.now,
    )?;
    if is_grant_capability(ctx.capability) {
        verify_grant_invocation(ctx.token, ctx.grant, ctx.owner_proof, ctx.capability, ctx.now)?;
    } else if is_owner_session_capability(ctx.capability) {
        verify_owner_session_invocation(
            ctx.token,
            ctx.grant,
            ctx.owner_proof,
            ctx.capability,
            ctx.expected_body_hash,
            ctx.now,
        )?;
    } else {
        return Err(NodeCoreError::Unauthorized("unsupported relay capability".to_owned()));
    }
    verify_pop_binding(ctx.token, ctx.pop, ctx.capability, ctx.expected_body_hash, ctx.now)
}
#[cfg(test)]
#[path = "tests/authorization.rs"]
mod tests;
