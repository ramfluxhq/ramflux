// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Gateway certificate issuance, proof of possession, binding, and revocation.

use super::{
    Deserialize, NodeCoreError, OBJECT_RELAY_CLOCK_SKEW_LEEWAY_SECONDS,
    OBJECT_RELAY_TOKEN_AUDIENCE_RELAY, OBJECT_RELAY_TOKEN_ISSUER_GATEWAY,
    OBJECT_RELAY_TOKEN_VERSION, OBJECT_RELAY_V3_PROOF_VERSION, RelayToken, RelayTokenIssueBody,
    Serialize, relay_token_mac, require_non_empty, validate_relay_token_issue_body,
};

/// # Errors
/// Returns an error when the issuance body is invalid or token signing fails.
pub fn issue_gateway_relay_token(
    service_key: &[u8],
    body: &RelayTokenIssueBody,
    now: u64,
) -> Result<RelayToken, NodeCoreError> {
    validate_relay_token_issue_body(body, now)?;
    let mut token = RelayToken {
        token_version: OBJECT_RELAY_TOKEN_VERSION,
        token_id: format!("token:{}:{}:{:?}", body.chunk_id, body.expires_at, body.capability),
        object_id: body.object_id.clone(),
        manifest_hash: body.manifest_hash.clone(),
        chunk_id: body.chunk_id.clone(),
        recipient_device_hash: body.recipient_device_hash.clone(),
        owner_signing_key_id: body.owner_signing_key_id.clone(),
        owner_public_key: body.owner_public_key.clone(),
        issuer_service: OBJECT_RELAY_TOKEN_ISSUER_GATEWAY.to_owned(),
        audience_service: OBJECT_RELAY_TOKEN_AUDIENCE_RELAY.to_owned(),
        capabilities: vec![body.capability],
        delete_after_ack: body.delete_after_ack,
        issued_at: body.issued_at,
        expires_at: body.expires_at,
        nonce: ramflux_protocol::encode_base64url(
            ramflux_crypto::random_32()
                .map_err(|source| NodeCoreError::ItestHttp(source.to_string()))?,
        ),
        mac: String::new(),
    };
    token.mac = relay_token_mac(service_key, &token)?;
    Ok(token)
}
pub const GATEWAY_ISSUER_CERTIFICATE_SCHEMA: &str = "ramflux.gateway_issuer_certificate.v3";
pub const GATEWAY_CERTIFICATE_REQUEST_SCHEMA: &str = "ramflux.gateway_certificate_request.v3";
/// Hard upper bound on an issued certificate's validity window (`not_after - now`). Short-lived
/// certificates keep the revocation/rotation risk window small.
pub const GATEWAY_ISSUER_CERTIFICATE_MAX_TTL_SECONDS: u64 = 6 * 60 * 60;
/// Maximum accepted age of a certificate request's `requested_at` relative to `now`. Bounds how long
/// a captured, validly-signed request stays acceptable; it is a freshness window only and is NOT a
/// persistent nonce replay guard (that lives in the signer integration).
pub const GATEWAY_CERTIFICATE_REQUEST_MAX_AGE_SECONDS: u64 = 300;
pub(super) const GATEWAY_ISSUER_CERTIFICATE_BINDING_DOMAIN: &str =
    "ramflux.gateway_issuer_certificate.binding.v3";

/// Node-root-signed certificate binding a gateway's attestation public key to its node id and
/// instance, with a bounded validity window. The relay verifies this against a pinned node-root
/// public key, then uses `attestation_public_key` to verify a token's `issuer_signature`. Root
/// keyring distribution, rotation, and CRL are out of scope for T2 (the root public key is a pure
/// input here).
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

/// A gateway's request to a node signer for a `GatewayIssuerCertificate`. It is self-signed with the
/// attestation private key (a proof-of-possession), so the node signer knows the requester actually
/// holds the attestation key it wants certified. It deliberately does NOT carry the future `cert_id`
/// (assigned by the signer). Transport-level authentication of the requesting gateway (mTLS + node
/// instance allowlist) is an integration concern, not part of this pure type.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GatewayCertificateRequest {
    pub schema: String,
    pub version: u32,
    pub request_id: String,
    pub node_id: String,
    pub gateway_instance_id: String,
    pub attestation_public_key: String,
    pub attestation_key_id: String,
    pub not_before: u64,
    pub not_after: u64,
    pub requested_at: u64,
    pub request_nonce: String,
    pub request_signature: String,
}

/// A revocation record binding a specific issued certificate by all of its identity fields. Applying
/// it stamps `revoked_at` on the certificate, after which the certificate fails closed. Persistent
/// CRL storage and distribution are out of scope (integration concern).
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GatewayCertificateRevocation {
    pub cert_id: String,
    pub attestation_key_id: String,
    pub node_id: String,
    pub gateway_instance_id: String,
    pub revoked_at: u64,
}

/// # Errors
/// Returns an error when the certificate cannot be canonicalized.
pub fn gateway_issuer_certificate_signing_bytes(
    certificate: &GatewayIssuerCertificate,
) -> Result<Vec<u8>, NodeCoreError> {
    let mut canonical = certificate.clone();
    canonical.node_root_signature.clear();
    ramflux_protocol::canonical_json_bytes(&canonical)
        .map_err(|source| NodeCoreError::ItestJson(source.to_string()))
}

/// # Errors
/// Returns an error when the certificate cannot be canonicalized. Binds the exact signed cert.
pub fn gateway_issuer_certificate_binding_hash(
    certificate: &GatewayIssuerCertificate,
) -> Result<String, NodeCoreError> {
    let canonical = ramflux_protocol::canonical_json_bytes(certificate)
        .map_err(|source| NodeCoreError::ItestJson(source.to_string()))?;
    Ok(ramflux_crypto::blake3_256_base64url(GATEWAY_ISSUER_CERTIFICATE_BINDING_DOMAIN, &canonical))
}

/// # Errors
/// Returns an error when the certificate request cannot be canonicalized.
pub fn gateway_certificate_request_signing_bytes(
    request: &GatewayCertificateRequest,
) -> Result<Vec<u8>, NodeCoreError> {
    let mut canonical = request.clone();
    canonical.request_signature.clear();
    ramflux_protocol::canonical_json_bytes(&canonical)
        .map_err(|source| NodeCoreError::ItestJson(source.to_string()))
}

/// Verifies a gateway issuer certificate against a pinned node-root public key.
///
/// Checks schema/version, required non-empty fields, that the certificate names the expected node
/// and gateway instance, a well-formed and currently-valid validity window
/// (`not_before <= not_after`, `not_before <= now <= not_after` with clock-skew leeway on the lower
/// bound), that the certificate is not revoked (fails closed on `revoked_at`), and the node-root
/// signature. Root keyring/rotation/CRL distribution are out of scope (the root key is a pure
/// input).
///
/// # Errors
/// Returns an error when any of the above checks fail.
pub fn verify_gateway_issuer_certificate(
    certificate: &GatewayIssuerCertificate,
    node_root_public_key: &str,
    expected_node_id: &str,
    expected_gateway_instance_id: &str,
    now: u64,
) -> Result<(), NodeCoreError> {
    if certificate.schema != GATEWAY_ISSUER_CERTIFICATE_SCHEMA {
        return Err(NodeCoreError::ItestJson(
            "gateway issuer certificate schema rejected".to_owned(),
        ));
    }
    if certificate.version != OBJECT_RELAY_V3_PROOF_VERSION {
        return Err(NodeCoreError::ItestJson(
            "gateway issuer certificate version rejected".to_owned(),
        ));
    }
    require_non_empty(&certificate.cert_id, "certificate cert_id")?;
    require_non_empty(&certificate.node_id, "certificate node_id")?;
    require_non_empty(&certificate.gateway_instance_id, "certificate gateway_instance_id")?;
    require_non_empty(&certificate.attestation_public_key, "certificate attestation_public_key")?;
    require_non_empty(&certificate.attestation_key_id, "certificate attestation_key_id")?;
    require_non_empty(
        &certificate.node_root_signing_key_id,
        "certificate node_root_signing_key_id",
    )?;
    require_non_empty(&certificate.node_root_signature, "certificate node_root_signature")?;
    if certificate.node_id != expected_node_id {
        return Err(NodeCoreError::Unauthorized("certificate node id mismatch".to_owned()));
    }
    if certificate.gateway_instance_id != expected_gateway_instance_id {
        return Err(NodeCoreError::Unauthorized(
            "certificate gateway instance mismatch".to_owned(),
        ));
    }
    if certificate.not_before >= certificate.not_after {
        return Err(NodeCoreError::Unauthorized(
            "certificate validity window is empty or inverted".to_owned(),
        ));
    }
    // The certificate must have been issued within its own validity window.
    if certificate.issued_at < certificate.not_before
        || certificate.issued_at > certificate.not_after
    {
        return Err(NodeCoreError::Unauthorized(
            "certificate issued_at is outside its validity window".to_owned(),
        ));
    }
    if now.saturating_add(OBJECT_RELAY_CLOCK_SKEW_LEEWAY_SECONDS) < certificate.not_before
        || now >= certificate.not_after
    {
        return Err(NodeCoreError::TtlExpired { envelope_id: certificate.cert_id.clone() });
    }
    if certificate.revoked_at.is_some_and(|revoked_at| revoked_at <= now) {
        return Err(NodeCoreError::Unauthorized("certificate is revoked".to_owned()));
    }
    ramflux_crypto::verify_canonical_signature(
        &gateway_issuer_certificate_signing_bytes(certificate)?,
        &certificate.node_root_signature,
        node_root_public_key,
    )
    .map_err(|source| NodeCoreError::Unauthorized(source.to_string()))
}

/// Verifies a gateway certificate request: schema/version, required non-empty fields, that it names
/// the expected node and gateway instance, a well-formed and not-yet-expired requested validity
/// window, a fresh `requested_at` (neither in the future beyond clock skew nor older than
/// [`GATEWAY_CERTIFICATE_REQUEST_MAX_AGE_SECONDS`]), and the attestation-key self-signature (proof of
/// possession of the attestation private key). The age bound is a freshness check only; a persistent
/// per-`request_nonce` replay guard, plus node/instance authentication of the requesting gateway
/// (mTLS + allowlist), are integration concerns handled by the signer/caller.
///
/// # Errors
/// Returns an error when any of the above checks fail.
pub fn verify_gateway_certificate_request(
    request: &GatewayCertificateRequest,
    expected_node_id: &str,
    expected_gateway_instance_id: &str,
    now: u64,
) -> Result<(), NodeCoreError> {
    if request.schema != GATEWAY_CERTIFICATE_REQUEST_SCHEMA {
        return Err(NodeCoreError::ItestJson(
            "gateway certificate request schema rejected".to_owned(),
        ));
    }
    if request.version != OBJECT_RELAY_V3_PROOF_VERSION {
        return Err(NodeCoreError::ItestJson(
            "gateway certificate request version rejected".to_owned(),
        ));
    }
    require_non_empty(&request.request_id, "certificate request request_id")?;
    require_non_empty(&request.node_id, "certificate request node_id")?;
    require_non_empty(&request.gateway_instance_id, "certificate request gateway_instance_id")?;
    require_non_empty(
        &request.attestation_public_key,
        "certificate request attestation_public_key",
    )?;
    require_non_empty(&request.attestation_key_id, "certificate request attestation_key_id")?;
    require_non_empty(&request.request_nonce, "certificate request request_nonce")?;
    require_non_empty(&request.request_signature, "certificate request request_signature")?;
    if request.node_id != expected_node_id {
        return Err(NodeCoreError::Unauthorized("certificate request node id mismatch".to_owned()));
    }
    if request.gateway_instance_id != expected_gateway_instance_id {
        return Err(NodeCoreError::Unauthorized(
            "certificate request gateway instance mismatch".to_owned(),
        ));
    }
    if request.not_before >= request.not_after {
        return Err(NodeCoreError::Unauthorized(
            "certificate request validity window is empty or inverted".to_owned(),
        ));
    }
    if request.not_after <= now {
        return Err(NodeCoreError::TtlExpired { envelope_id: request.request_id.clone() });
    }
    // `requested_at` must be neither in the future (beyond clock skew) nor too old. The age bound
    // limits the window in which a captured, validly-signed request stays acceptable; it is a
    // freshness check, not a persistent per-nonce replay guard (that is a signer-integration
    // concern).
    if request.requested_at > now.saturating_add(OBJECT_RELAY_CLOCK_SKEW_LEEWAY_SECONDS)
        || request.requested_at.saturating_add(GATEWAY_CERTIFICATE_REQUEST_MAX_AGE_SECONDS) < now
    {
        return Err(NodeCoreError::TtlExpired { envelope_id: request.request_id.clone() });
    }
    ramflux_crypto::verify_canonical_signature(
        &gateway_certificate_request_signing_bytes(request)?,
        &request.request_signature,
        &request.attestation_public_key,
    )
    .map_err(|source| NodeCoreError::Unauthorized(source.to_string()))
}

/// Issues a node-root-signed `GatewayIssuerCertificate` from a verified certificate request.
///
/// Verifies the request (proof of possession + window) against its own declared node/instance, then
/// enforces the issuance policy: the certificate must be immediately active (`not_before <= now`),
/// currently within its window (`now < not_after`), and bounded by the hard maximum TTL
/// (`not_after <= now + GATEWAY_ISSUER_CERTIFICATE_MAX_TTL_SECONDS`). The issued certificate takes
/// `issued_at = now` (which is inside the window by construction) and is signed by the node root.
/// The resulting certificate verifies under [`verify_gateway_issuer_certificate`].
///
/// # Errors
/// Returns an error when the request fails verification, the issuance-window policy is violated, or
/// signing fails.
pub fn issue_gateway_issuer_certificate(
    request: &GatewayCertificateRequest,
    node_root_signing_key_id: &str,
    node_root_seed: [u8; 32],
    cert_id: &str,
    now: u64,
) -> Result<GatewayIssuerCertificate, NodeCoreError> {
    verify_gateway_certificate_request(
        request,
        &request.node_id,
        &request.gateway_instance_id,
        now,
    )?;
    require_non_empty(cert_id, "issued certificate cert_id")?;
    require_non_empty(node_root_signing_key_id, "issued certificate node_root_signing_key_id")?;
    // The issued certificate must be active now, so `issued_at = now` falls inside the window.
    if request.not_before > now {
        return Err(NodeCoreError::Unauthorized(
            "certificate request not_before is in the future; certificate would not be active"
                .to_owned(),
        ));
    }
    if now >= request.not_after {
        return Err(NodeCoreError::TtlExpired { envelope_id: request.request_id.clone() });
    }
    if request.not_after > now.saturating_add(GATEWAY_ISSUER_CERTIFICATE_MAX_TTL_SECONDS) {
        return Err(NodeCoreError::Unauthorized(
            "certificate request validity window exceeds the maximum allowed TTL".to_owned(),
        ));
    }
    let mut certificate = GatewayIssuerCertificate {
        schema: GATEWAY_ISSUER_CERTIFICATE_SCHEMA.to_owned(),
        version: OBJECT_RELAY_V3_PROOF_VERSION,
        cert_id: cert_id.to_owned(),
        node_id: request.node_id.clone(),
        gateway_instance_id: request.gateway_instance_id.clone(),
        attestation_public_key: request.attestation_public_key.clone(),
        attestation_key_id: request.attestation_key_id.clone(),
        not_before: request.not_before,
        not_after: request.not_after,
        issued_at: now,
        node_root_signing_key_id: node_root_signing_key_id.to_owned(),
        node_root_signature: String::new(),
        revoked_at: None,
    };
    certificate.node_root_signature = ramflux_crypto::sign_canonical_bytes_with_seed(
        &gateway_issuer_certificate_signing_bytes(&certificate)?,
        node_root_seed,
    );
    Ok(certificate)
}

/// Returns `true` when `next` is a valid renewal of `previous`: the same gateway (node id and
/// instance) with a fresh certificate id whose validity does not end earlier than the previous one.
/// The attestation key may be rotated or retained. This is the binding contract only; issuing the
/// renewal still goes through [`issue_gateway_issuer_certificate`].
#[must_use]
pub fn gateway_certificate_is_renewal_of(
    previous: &GatewayIssuerCertificate,
    next: &GatewayIssuerCertificate,
) -> bool {
    next.node_id == previous.node_id
        && next.gateway_instance_id == previous.gateway_instance_id
        && next.cert_id != previous.cert_id
        && next.not_after >= previous.not_after
}

/// Returns `true` when a revocation targets exactly the given certificate (bound by cert id,
/// attestation key id, node id, and gateway instance).
#[must_use]
pub fn gateway_certificate_matches_revocation(
    certificate: &GatewayIssuerCertificate,
    revocation: &GatewayCertificateRevocation,
) -> bool {
    certificate.cert_id == revocation.cert_id
        && certificate.attestation_key_id == revocation.attestation_key_id
        && certificate.node_id == revocation.node_id
        && certificate.gateway_instance_id == revocation.gateway_instance_id
}

/// Applies a revocation to the certificate it targets, returning a copy stamped with `revoked_at`.
/// The revoked certificate then fails closed under [`verify_gateway_issuer_certificate`]. Persistent
/// CRL storage/distribution is an integration concern and is not implemented here.
///
/// # Errors
/// Returns an error when the revocation does not bind to the certificate.
pub fn apply_gateway_certificate_revocation(
    certificate: &GatewayIssuerCertificate,
    revocation: &GatewayCertificateRevocation,
) -> Result<GatewayIssuerCertificate, NodeCoreError> {
    if !gateway_certificate_matches_revocation(certificate, revocation) {
        return Err(NodeCoreError::Unauthorized(
            "revocation does not target this certificate".to_owned(),
        ));
    }
    let mut revoked = certificate.clone();
    revoked.revoked_at = Some(revocation.revoked_at);
    Ok(revoked)
}
#[cfg(test)]
#[path = "tests/certificates.rs"]
mod tests;
