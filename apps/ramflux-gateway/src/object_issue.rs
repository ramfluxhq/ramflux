// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Gateway adapter for v3 relay-token issuance (RQ-03 / T16-B).
//!
//! This is a thin runtime adapter over the pure node-core issuer
//! [`ramflux_node_core::issue_gateway_relay_token_v3`]. All token-shape, certificate-binding,
//! capability/authorization, and TTL validation lives in node-core; this layer only holds the
//! gateway's runtime issuer material (its attestation signing seed and node-root-signed certificate)
//! and forces the gateway's own certificate identity onto every issued token, so a caller cannot
//! supply its own issuer identity. Issuance fails closed when the issuer material is not configured.
//!
//! There is no shared-secret / HMAC fallback: v3 tokens are always issuer-attestation signed.

/// Runtime-held gateway issuer material for v3 relay-token issuance. Constructed at gateway startup
/// from explicit configuration; kept out of `GatewayQuicContext` for now so the (still-optional)
/// issuer material can be threaded in without disturbing the existing context construction sites.
#[allow(dead_code)]
#[derive(Clone)]
pub(crate) struct GatewayV3IssuerConfig {
    /// The gateway attestation private key (32-byte seed) whose public key is bound in `certificate`.
    pub(crate) attestation_seed: [u8; 32],
    /// The node-root-signed certificate that binds this gateway's attestation key to its node/instance.
    pub(crate) certificate: ramflux_node_core::GatewayIssuerCertificate,
}

/// Issues an issuer-attestation-signed v3 relay token for `request`, using the gateway's configured
/// issuer material. Fails closed (`Err`) when the issuer material is absent. The gateway certificate is
/// authoritative: `issuer_node_id`, `gateway_instance_id`, and `issuer_certificate` on the request are
/// overwritten from the configured certificate before delegating to the node-core issuer, which
/// performs all validation.
///
/// # Errors
/// Returns an error when issuance is not configured, or when node-core rejects the request (invalid
/// capability/authorization matrix, certificate binding, TTL, or identity fields).
#[allow(dead_code)]
pub(crate) fn issue_object_relay_token_v3(
    issuer: Option<&GatewayV3IssuerConfig>,
    mut request: ramflux_node_core::RelayTokenV3IssueRequest,
    now: u64,
) -> anyhow::Result<ramflux_node_core::RelayTokenV3> {
    let issuer = issuer.ok_or_else(|| {
        anyhow::anyhow!(
            "gateway v3 relay token issuance is not configured (missing issuer material)"
        )
    })?;
    // The gateway's own certificate is authoritative — the caller cannot supply an issuer identity.
    request.issuer_node_id.clone_from(&issuer.certificate.node_id);
    request.gateway_instance_id.clone_from(&issuer.certificate.gateway_instance_id);
    request.issuer_certificate = issuer.certificate.clone();
    Ok(ramflux_node_core::issue_gateway_relay_token_v3(&request, issuer.attestation_seed, now)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ATTESTATION_SEED: [u8; 32] = [0x33; 32];
    const ROOT_SEED: [u8; 32] = [0x44; 32];
    const NODE_ID: &str = "node-b";
    const GATEWAY_INSTANCE: &str = "gw-b-1";
    const AUDIENCE_NODE: &str = "node-a";

    fn issuer_config(now: u64) -> anyhow::Result<GatewayV3IssuerConfig> {
        let mut certificate = ramflux_node_core::GatewayIssuerCertificate {
            schema: ramflux_node_core::GATEWAY_ISSUER_CERTIFICATE_SCHEMA.to_owned(),
            version: ramflux_node_core::OBJECT_RELAY_V3_PROOF_VERSION,
            cert_id: "cert-b-1".to_owned(),
            node_id: NODE_ID.to_owned(),
            gateway_instance_id: GATEWAY_INSTANCE.to_owned(),
            attestation_public_key: ramflux_crypto::public_key_base64url_from_seed(
                ATTESTATION_SEED,
            ),
            attestation_key_id: "att-b-1".to_owned(),
            not_before: now - 10,
            not_after: now + 3_600,
            issued_at: now - 10,
            node_root_signing_key_id: "node-b#root".to_owned(),
            node_root_signature: String::new(),
            revoked_at: None,
        };
        certificate.node_root_signature = ramflux_crypto::sign_canonical_bytes_with_seed(
            &ramflux_node_core::gateway_issuer_certificate_signing_bytes(&certificate)?,
            ROOT_SEED,
        );
        Ok(GatewayV3IssuerConfig { attestation_seed: ATTESTATION_SEED, certificate })
    }

    fn issue_request(
        now: u64,
        capability: ramflux_node_core::ObjectRelayCapability,
        authorization_kind: ramflux_node_core::RelayAuthorizationKind,
        certificate: ramflux_node_core::GatewayIssuerCertificate,
    ) -> ramflux_node_core::RelayTokenV3IssueRequest {
        ramflux_node_core::RelayTokenV3IssueRequest {
            requester_device_id: "device_b".to_owned(),
            requester_device_hash: "device_b_hash".to_owned(),
            requester_public_key: "device_b_pk".to_owned(),
            requester_device_epoch: 1,
            owner_signing_key_id: "owner_a".to_owned(),
            owner_public_key: "owner_a_pk".to_owned(),
            owner_home_node_id: AUDIENCE_NODE.to_owned(),
            owner_principal_id: "principal_a".to_owned(),
            owner_device_epoch: 1,
            // Deliberately wrong issuer identity: the adapter must overwrite these from the config.
            issuer_node_id: "attacker-node".to_owned(),
            gateway_instance_id: "attacker-instance".to_owned(),
            audience_node_id: AUDIENCE_NODE.to_owned(),
            relay_instance_id: None,
            object_id: "object_v3".to_owned(),
            manifest_hash: "manifest_v3".to_owned(),
            chunk_id: "chunk_v3".to_owned(),
            capabilities: vec![capability],
            authorization_kind,
            authorization_binding_hash: "binding_v3".to_owned(),
            delete_after_ack: false,
            issued_at: now,
            expires_at: now + 120,
            nonce: "nonce_v3".to_owned(),
            issuer_certificate: certificate,
        }
    }

    #[test]
    fn adapter_issues_valid_token_and_forces_gateway_identity() -> anyhow::Result<()> {
        let now = 1_000_000;
        let config = issuer_config(now)?;
        let request = issue_request(
            now,
            ramflux_node_core::ObjectRelayCapability::Get,
            ramflux_node_core::RelayAuthorizationKind::OwnerGrant,
            config.certificate.clone(),
        );
        let token = issue_object_relay_token_v3(Some(&config), request, now)?;
        // The gateway certificate identity is authoritative (the request's attacker identity is gone).
        assert_eq!(token.issuer_node_id, NODE_ID);
        assert_eq!(token.gateway_instance_id, GATEWAY_INSTANCE);
        assert_eq!(token.issuer_certificate_id, "cert-b-1");
        assert!(!token.issuer_signature.is_empty());
        // The issued token verifies against its own certificate chain and the pinned node root.
        ramflux_node_core::verify_relay_token_v3_with_certificate(
            &token,
            &config.certificate,
            &ramflux_crypto::public_key_base64url_from_seed(ROOT_SEED),
            ramflux_node_core::ObjectRelayCapability::Get,
            AUDIENCE_NODE,
            now,
        )?;
        Ok(())
    }

    #[test]
    fn adapter_fails_closed_when_issuer_material_absent() -> anyhow::Result<()> {
        let now = 1_000_000;
        let config = issuer_config(now)?;
        let request = issue_request(
            now,
            ramflux_node_core::ObjectRelayCapability::Get,
            ramflux_node_core::RelayAuthorizationKind::OwnerGrant,
            config.certificate,
        );
        // No configured issuer material -> issuance is refused, never signed.
        assert!(issue_object_relay_token_v3(None, request, now).is_err());
        Ok(())
    }

    #[test]
    fn adapter_rejects_invalid_capability_authorization_matrix() -> anyhow::Result<()> {
        let now = 1_000_000;
        let config = issuer_config(now)?;
        // Get is a grant capability, so an owner-session authorization kind is invalid; node-core
        // rejects it and the adapter propagates the failure (no token is issued).
        let request = issue_request(
            now,
            ramflux_node_core::ObjectRelayCapability::Get,
            ramflux_node_core::RelayAuthorizationKind::OwnerSession,
            config.certificate.clone(),
        );
        assert!(issue_object_relay_token_v3(Some(&config), request, now).is_err());
        Ok(())
    }
}
