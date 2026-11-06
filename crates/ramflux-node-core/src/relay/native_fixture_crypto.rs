// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
//! Shared native-service authenticated test fixtures, excluded from production features.
use crate::{
    FEDERATED_ISSUER_TRUST_SNAPSHOT_SCHEMA, FederatedIssuerTrustSnapshot,
    FederatedIssuerTrustStatus, GATEWAY_ISSUER_CERTIFICATE_SCHEMA, GatewayIssuerCertificate,
    OBJECT_RELAY_TOKEN_V3_VERSION, OBJECT_RELAY_V3_PROOF_VERSION, OWNER_AUTHORIZATION_PROOF_SCHEMA,
    ObjectRelayCapability, OwnerAuthorizationProof, RELAY_TOKEN_V3_AUDIENCE_RELAY,
    REQUESTER_POP_SCHEMA, RelayAuthorizationKind, RelayTokenV3, RequesterProofOfPossession,
    TrustedNodeRootKey, gateway_issuer_certificate_signing_bytes,
    owner_authorization_proof_signing_bytes, relay_token_v3_signing_bytes,
    requester_pop_signing_bytes,
};
use std::collections::BTreeSet;
pub(super) const V3_OWNER_SEED: [u8; 32] = [0x11; 32];
pub(super) const V3_REQUESTER_SEED: [u8; 32] = [0x22; 32];
pub(super) const V3_ISSUER_SEED: [u8; 32] = [0x33; 32];
pub(super) const V3_OWNER_ID: &str = "device_a_owner";
pub(super) const V3_REQUESTER_ID: &str = "device_b_requester";
pub(super) const V3_OBJECT: &str = "object_v3";
pub(super) const V3_MANIFEST: &str = "manifest_v3";
pub(super) const V3_CHUNK: &str = "chunk_v3";
pub(super) const V3_BODY_HASH: &str = "body_hash_v3";
pub(super) const V3_AUDIENCE_NODE: &str = "node-a";
pub(super) const V3_ROOT_SEED: [u8; 32] = [0x44; 32];
pub(super) const V3_ISSUER_NODE: &str = "node-b";
pub(super) const V3_GATEWAY_INSTANCE: &str = "gw-b-1";
pub(super) const V3_CERT_ID: &str = "cert-b-1";
pub(super) const V3_ATTESTATION_KEY_ID: &str = "att-b-1";
pub(super) const V3_ROOT_KEY_ID: &str = "node-b#root";
pub(super) fn v3_pk(seed: [u8; 32]) -> String {
    ramflux_crypto::public_key_base64url_from_seed(seed)
}
pub(super) fn v3_requester_hash() -> String {
    ramflux_crypto::blake3_256_base64url(
        "ramflux.object_relay.recipient_device.v1",
        V3_REQUESTER_ID.as_bytes(),
    )
}
pub(super) fn v3_sign(bytes: &[u8], seed: [u8; 32]) -> String {
    ramflux_crypto::sign_canonical_bytes_with_seed(bytes, seed)
}
pub(super) fn v3_signed_owner_proof(
    now: u64,
    capability: ObjectRelayCapability,
) -> Result<OwnerAuthorizationProof, String> {
    let mut proof = OwnerAuthorizationProof {
        schema: OWNER_AUTHORIZATION_PROOF_SCHEMA.to_owned(),
        version: OBJECT_RELAY_V3_PROOF_VERSION,
        capability,
        object_id: V3_OBJECT.to_owned(),
        manifest_hash: Some(V3_MANIFEST.to_owned()),
        chunk_id: Some(V3_CHUNK.to_owned()),
        owner_home_node_id: V3_AUDIENCE_NODE.to_owned(),
        owner_principal_id: "principal_a".to_owned(),
        owner_device_epoch: 3,
        request_nonce: "owner_proof_nonce_v3".to_owned(),
        body_hash: V3_BODY_HASH.to_owned(),
        issued_at: now,
        expires_at: now + 120,
        owner_signing_key_id: V3_OWNER_ID.to_owned(),
        owner_public_key: v3_pk(V3_OWNER_SEED),
        owner_signature: String::new(),
    };
    proof.owner_signature = v3_sign(
        &owner_authorization_proof_signing_bytes(&proof).map_err(|e| e.to_string())?,
        V3_OWNER_SEED,
    );
    Ok(proof)
}
pub(super) fn v3_resign_token(token: &mut RelayTokenV3) -> Result<(), String> {
    token.issuer_signature =
        v3_sign(&relay_token_v3_signing_bytes(token).map_err(|e| e.to_string())?, V3_ISSUER_SEED);
    Ok(())
}
pub(super) fn v3_grant_token(
    now: u64,
    capability: ObjectRelayCapability,
    binding_hash: String,
) -> Result<RelayTokenV3, String> {
    let mut token = RelayTokenV3 {
        token_version: OBJECT_RELAY_TOKEN_V3_VERSION,
        token_id: "tok_v3_grant".to_owned(),
        requester_device_id: V3_REQUESTER_ID.to_owned(),
        requester_device_hash: v3_requester_hash(),
        requester_public_key: v3_pk(V3_REQUESTER_SEED),
        requester_device_epoch: 7,
        owner_signing_key_id: V3_OWNER_ID.to_owned(),
        owner_public_key: v3_pk(V3_OWNER_SEED),
        owner_home_node_id: V3_AUDIENCE_NODE.to_owned(),
        owner_principal_id: "principal_a".to_owned(),
        owner_device_epoch: 3,
        issuer_node_id: V3_ISSUER_NODE.to_owned(),
        gateway_instance_id: V3_GATEWAY_INSTANCE.to_owned(),
        issuer_certificate_id: V3_CERT_ID.to_owned(),
        attestation_key_id: V3_ATTESTATION_KEY_ID.to_owned(),
        issuer_certificate: v3_certificate(now, |_cert| {})?,
        audience_service: RELAY_TOKEN_V3_AUDIENCE_RELAY.to_owned(),
        audience_node_id: V3_AUDIENCE_NODE.to_owned(),
        relay_instance_id: None,
        object_id: V3_OBJECT.to_owned(),
        manifest_hash: V3_MANIFEST.to_owned(),
        chunk_id: V3_CHUNK.to_owned(),
        capabilities: vec![capability],
        authorization_kind: RelayAuthorizationKind::OwnerGrant,
        authorization_binding_hash: binding_hash,
        delete_after_ack: false,
        issued_at: now,
        expires_at: now + 120,
        nonce: "nonce_tok_v3".to_owned(),
        issuer_signature: String::new(),
    };
    v3_resign_token(&mut token)?;
    Ok(token)
}
pub(super) fn v3_owner_session_token(
    now: u64,
    capability: ObjectRelayCapability,
    binding_hash: String,
) -> Result<RelayTokenV3, String> {
    // Owner-session operations: the requester is the owner device itself.
    let mut token = v3_grant_token(now, capability, binding_hash)?;
    token.authorization_kind = RelayAuthorizationKind::OwnerSession;
    V3_OWNER_ID.clone_into(&mut token.requester_device_id);
    token.requester_device_hash = ramflux_crypto::blake3_256_base64url(
        "ramflux.object_relay.recipient_device.v1",
        V3_OWNER_ID.as_bytes(),
    );
    token.requester_public_key = v3_pk(V3_OWNER_SEED);
    v3_resign_token(&mut token)?;
    Ok(token)
}
pub(super) fn v3_signed_pop(
    token: &RelayTokenV3,
    capability: ObjectRelayCapability,
    signer_seed: [u8; 32],
    now: u64,
) -> Result<RequesterProofOfPossession, String> {
    let mut pop = RequesterProofOfPossession {
        schema: REQUESTER_POP_SCHEMA.to_owned(),
        version: OBJECT_RELAY_V3_PROOF_VERSION,
        token_id: token.token_id.clone(),
        capability,
        object_id: token.object_id.clone(),
        manifest_hash: token.manifest_hash.clone(),
        chunk_id: token.chunk_id.clone(),
        request_nonce: "req_nonce_v3".to_owned(),
        body_hash: V3_BODY_HASH.to_owned(),
        issued_at: now,
        expires_at: now + 60,
        signer_device_id: token.requester_device_id.clone(),
        signer_public_key: token.requester_public_key.clone(),
        signature: String::new(),
    };
    pop.signature =
        v3_sign(&requester_pop_signing_bytes(&pop).map_err(|e| e.to_string())?, signer_seed);
    Ok(pop)
}
pub(super) fn v3_certificate(
    now: u64,
    apply: impl FnOnce(&mut GatewayIssuerCertificate),
) -> Result<GatewayIssuerCertificate, String> {
    let mut cert = GatewayIssuerCertificate {
        schema: GATEWAY_ISSUER_CERTIFICATE_SCHEMA.to_owned(),
        version: OBJECT_RELAY_V3_PROOF_VERSION,
        cert_id: V3_CERT_ID.to_owned(),
        node_id: V3_ISSUER_NODE.to_owned(),
        gateway_instance_id: V3_GATEWAY_INSTANCE.to_owned(),
        attestation_public_key: v3_pk(V3_ISSUER_SEED),
        attestation_key_id: V3_ATTESTATION_KEY_ID.to_owned(),
        not_before: now - 10,
        not_after: now + 3_600,
        issued_at: now - 10,
        node_root_signing_key_id: "node-b#root".to_owned(),
        node_root_signature: String::new(),
        revoked_at: None,
    };
    apply(&mut cert);
    cert.node_root_signature = v3_sign(
        &gateway_issuer_certificate_signing_bytes(&cert).map_err(|e| e.to_string())?,
        V3_ROOT_SEED,
    );
    Ok(cert)
}
pub(super) fn v3_trust_snapshot(
    now: u64,
    apply: impl FnOnce(&mut FederatedIssuerTrustSnapshot),
) -> FederatedIssuerTrustSnapshot {
    let mut snapshot = FederatedIssuerTrustSnapshot {
        schema: FEDERATED_ISSUER_TRUST_SNAPSHOT_SCHEMA.to_owned(),
        version: OBJECT_RELAY_V3_PROOF_VERSION,
        node_id: V3_ISSUER_NODE.to_owned(),
        generation: 5,
        pin_epoch: 3,
        trust_status: FederatedIssuerTrustStatus::Active,
        roots: vec![TrustedNodeRootKey {
            node_id: V3_ISSUER_NODE.to_owned(),
            key_id: V3_ROOT_KEY_ID.to_owned(),
            public_key: v3_pk(V3_ROOT_SEED),
            not_before: now - 100,
            not_after: now + 3_600,
            pin_epoch: 3,
            retired_at: None,
        }],
        revoked_cert_ids: BTreeSet::new(),
        hard_stale_at: now + 300,
    };
    apply(&mut snapshot);
    snapshot
}
