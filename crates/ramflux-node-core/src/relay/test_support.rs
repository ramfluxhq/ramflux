// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::{
    BTreeSet, FEDERATED_ISSUER_TRUST_SNAPSHOT_ENVELOPE_SCHEMA,
    FEDERATED_ISSUER_TRUST_SNAPSHOT_SCHEMA, FEDERATED_TRUST_SNAPSHOT_ENVELOPE_SCHEMA,
    FederatedIssuerTrustSnapshot, FederatedIssuerTrustStatus, FederatedTrustSnapshotEnvelope,
    GATEWAY_CERTIFICATE_REQUEST_SCHEMA, GATEWAY_ISSUER_CERTIFICATE_SCHEMA,
    GatewayCertificateRequest, GatewayIssuerCertificate, NodeCoreError, OBJECT_ACCESS_GRANT_SCHEMA,
    OBJECT_RELAY_TOKEN_AUDIENCE_RELAY, OBJECT_RELAY_TOKEN_ISSUER_GATEWAY,
    OBJECT_RELAY_TOKEN_V3_VERSION, OBJECT_RELAY_TOKEN_VERSION, OBJECT_RELAY_V3_PROOF_VERSION,
    OWNER_AUTHORIZATION_PROOF_SCHEMA, ObjectAccessGrant, ObjectPermissionEnvelope,
    ObjectRelayCapability, OwnerAuthorizationProof, OwnerSessionTombstoneRequest,
    PROVIDER_KEYRING_SCHEMA, PROVIDER_KEYRING_VERSION,
    PROVIDER_SIGNED_TRUST_SNAPSHOT_ENVELOPE_SCHEMA,
    PROVIDER_SIGNED_TRUST_SNAPSHOT_ENVELOPE_VERSION, ProviderKeyEntry, ProviderKeyring,
    ProviderSignedTrustSnapshot, RELAY_TOKEN_V3_AUDIENCE_RELAY, REQUESTER_POP_SCHEMA,
    RelayAuthorizationKind, RelayChunkEntry, RelayChunkStatus, RelayToken, RelayTokenV3,
    RequesterProofOfPossession, SignedFederatedIssuerTrustSnapshot, TrustedNodeRootKey,
    ValidatedProviderKeyring, federated_trust_snapshot_envelope_signing_bytes,
    gateway_certificate_request_signing_bytes, gateway_issuer_certificate_signing_bytes,
    object_access_grant_binding_hash, object_access_grant_signing_bytes,
    object_permission_canonical_bytes, owner_authorization_proof_signing_bytes,
    provider_keyring_signing_bytes, provider_signed_trust_snapshot_signing_bytes, relay_token_mac,
    relay_token_v3_signing_bytes, requester_pop_signing_bytes,
    signed_federated_issuer_trust_snapshot_signing_bytes, verify_provider_keyring,
};

pub(super) fn test_relay_token(
    service_key: &[u8],
    capability: ObjectRelayCapability,
    issued_at: u64,
    expires_at: u64,
) -> Result<RelayToken, String> {
    let mut token = RelayToken {
        token_version: OBJECT_RELAY_TOKEN_VERSION,
        token_id: format!("token_clock_skew_{capability:?}_{issued_at}"),
        object_id: "object_relay_clock_skew".to_owned(),
        manifest_hash: "manifest_relay_clock_skew".to_owned(),
        chunk_id: "chunk_relay_clock_skew".to_owned(),
        recipient_device_hash: "recipient_clock_skew".to_owned(),
        owner_signing_key_id: "owner_fixture_key".to_owned(),
        owner_public_key: ramflux_crypto::fixture_public_key_base64url(),
        issuer_service: OBJECT_RELAY_TOKEN_ISSUER_GATEWAY.to_owned(),
        audience_service: OBJECT_RELAY_TOKEN_AUDIENCE_RELAY.to_owned(),
        capabilities: vec![capability],
        delete_after_ack: false,
        issued_at,
        expires_at,
        nonce: format!("nonce_clock_skew_{issued_at}"),
        mac: String::new(),
    };
    token.mac = relay_token_mac(service_key, &token).map_err(|source| source.to_string())?;
    Ok(token)
}

pub(super) fn test_object_permission(
    capability: ObjectRelayCapability,
    issued_at: u64,
    expires_at: u64,
) -> Result<ObjectPermissionEnvelope, String> {
    let mut permission = ObjectPermissionEnvelope {
        object_id: "object_relay_clock_skew".to_owned(),
        manifest_hash: "manifest_relay_clock_skew".to_owned(),
        grantee_device_hash: "recipient_clock_skew".to_owned(),
        capability,
        issued_at,
        expires_at,
        owner_signing_key_id: "owner_fixture_key".to_owned(),
        owner_public_key: ramflux_crypto::fixture_public_key_base64url(),
        owner_signature: String::new(),
    };
    permission.owner_signature = ramflux_crypto::sign_canonical_bytes(
        &object_permission_canonical_bytes(&permission).map_err(|source| source.to_string())?,
    );
    Ok(permission)
}

// ---- RQ-03-V3-T1 pure-verification tests ----

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

pub(super) fn v3_signed_grant(
    now: u64,
    capabilities: Vec<ObjectRelayCapability>,
) -> Result<ObjectAccessGrant, String> {
    let mut grant = ObjectAccessGrant {
        schema: OBJECT_ACCESS_GRANT_SCHEMA.to_owned(),
        version: OBJECT_RELAY_V3_PROOF_VERSION,
        object_id: V3_OBJECT.to_owned(),
        manifest_hash: V3_MANIFEST.to_owned(),
        grantee_device_hash: v3_requester_hash(),
        capabilities,
        issued_at: now,
        expires_at: now + 300,
        owner_signing_key_id: V3_OWNER_ID.to_owned(),
        owner_public_key: v3_pk(V3_OWNER_SEED),
        owner_signature: String::new(),
    };
    grant.owner_signature = v3_sign(
        &object_access_grant_signing_bytes(&grant).map_err(|e| e.to_string())?,
        V3_OWNER_SEED,
    );
    Ok(grant)
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
    token.requester_device_id = V3_OWNER_ID.to_owned();
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

pub(super) fn v3_resign_owner_proof(
    mut proof: OwnerAuthorizationProof,
) -> Result<OwnerAuthorizationProof, String> {
    proof.owner_signature = v3_sign(
        &owner_authorization_proof_signing_bytes(&proof).map_err(|e| e.to_string())?,
        V3_OWNER_SEED,
    );
    Ok(proof)
}

// ---- RQ-03-V3-T2 certificate-chain tests ----

pub(super) const V3_ROOT_SEED: [u8; 32] = [0x44; 32];
pub(super) const V3_ISSUER_NODE: &str = "node-b";
pub(super) const V3_GATEWAY_INSTANCE: &str = "gw-b-1";
pub(super) const V3_CERT_ID: &str = "cert-b-1";
pub(super) const V3_ATTESTATION_KEY_ID: &str = "att-b-1";

// Builds a node-root-signed certificate whose attestation key is the issuer key used to sign the
// v3 token fixtures, then applies `apply` and (re)signs so overrides yield a valid root
// signature (for semantic-mismatch tests). Fields match the token fixture's issuer identity.
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

pub(super) fn v3_get_token_for_cert(now: u64) -> Result<(RelayTokenV3, ObjectAccessGrant), String> {
    let grant = v3_signed_grant(now, vec![ObjectRelayCapability::Get])?;
    let binding = object_access_grant_binding_hash(&grant).map_err(|e| e.to_string())?;
    let token = v3_grant_token(now, ObjectRelayCapability::Get, binding)?;
    Ok((token, grant))
}

// ---- RQ-03-V3-T3 certificate issuance (request PoP + node-root issuance) tests ----

pub(super) const V3_ROOT_KEY_ID: &str = "node-b#root";

pub(super) fn v3_certificate_request(
    now: u64,
    apply: impl FnOnce(&mut GatewayCertificateRequest),
) -> Result<GatewayCertificateRequest, String> {
    let mut request = GatewayCertificateRequest {
        schema: GATEWAY_CERTIFICATE_REQUEST_SCHEMA.to_owned(),
        version: OBJECT_RELAY_V3_PROOF_VERSION,
        request_id: "req-v3-1".to_owned(),
        node_id: V3_ISSUER_NODE.to_owned(),
        gateway_instance_id: V3_GATEWAY_INSTANCE.to_owned(),
        attestation_public_key: v3_pk(V3_ISSUER_SEED),
        attestation_key_id: V3_ATTESTATION_KEY_ID.to_owned(),
        not_before: now - 10,
        not_after: now + 3_600,
        requested_at: now,
        request_nonce: "req-nonce-v3".to_owned(),
        request_signature: String::new(),
    };
    apply(&mut request);
    request.request_signature = v3_sign(
        &gateway_certificate_request_signing_bytes(&request).map_err(|e| e.to_string())?,
        V3_ISSUER_SEED,
    );
    Ok(request)
}

// ---- RQ-03-V3-T4 federated root trust snapshot tests ----

pub(super) const V3_ROOT_PREV_SEED: [u8; 32] = [0x55; 32];
pub(super) const V3_ROOT_PREV_KEY_ID: &str = "node-b#root-prev";

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

pub(super) const V3_PROVIDER_SEED: [u8; 32] = [0x66; 32];

pub(super) fn v3_signed_snapshot_envelope(
    now: u64,
    apply: impl FnOnce(&mut SignedFederatedIssuerTrustSnapshot),
) -> Result<SignedFederatedIssuerTrustSnapshot, String> {
    let mut envelope = SignedFederatedIssuerTrustSnapshot {
        schema: FEDERATED_ISSUER_TRUST_SNAPSHOT_ENVELOPE_SCHEMA.to_owned(),
        version: OBJECT_RELAY_V3_PROOF_VERSION,
        snapshot: v3_trust_snapshot(now, |_s| {}),
        provider_signing_key_id: "node-b#trust-provider".to_owned(),
        provider_public_key: v3_pk(V3_PROVIDER_SEED),
        issued_at: now,
        expires_at: now + 300,
        signature: String::new(),
    };
    apply(&mut envelope);
    envelope.signature = v3_sign(
        &signed_federated_issuer_trust_snapshot_signing_bytes(&envelope)
            .map_err(|e| e.to_string())?,
        V3_PROVIDER_SEED,
    );
    Ok(envelope)
}

// Builds a Get token whose embedded certificate is signed by `root_seed` under `root_key_id`.
pub(super) fn v3_token_signed_by_root(
    now: u64,
    root_seed: [u8; 32],
    root_key_id: &str,
) -> Result<(RelayTokenV3, GatewayIssuerCertificate), String> {
    let grant = v3_signed_grant(now, vec![ObjectRelayCapability::Get])?;
    let binding = object_access_grant_binding_hash(&grant).map_err(|e| e.to_string())?;
    let mut token = v3_grant_token(now, ObjectRelayCapability::Get, binding)?;
    let mut cert = token.issuer_certificate.clone();
    cert.node_root_signing_key_id = root_key_id.to_owned();
    cert.node_root_signature = v3_sign(
        &gateway_issuer_certificate_signing_bytes(&cert).map_err(|e| e.to_string())?,
        root_seed,
    );
    token.issuer_certificate = cert.clone();
    v3_resign_token(&mut token)?;
    Ok((token, cert))
}

pub(super) fn v3_previous_root(now: u64, retired_at: Option<u64>) -> TrustedNodeRootKey {
    TrustedNodeRootKey {
        node_id: V3_ISSUER_NODE.to_owned(),
        key_id: V3_ROOT_PREV_KEY_ID.to_owned(),
        public_key: v3_pk(V3_ROOT_PREV_SEED),
        not_before: now - 200,
        not_after: now + 3_600,
        pin_epoch: 2,
        retired_at,
    }
}

pub(super) fn signed_trust_snapshot_envelope(
    now: u64,
    seed: [u8; 32],
) -> Result<FederatedTrustSnapshotEnvelope, String> {
    let mut envelope = FederatedTrustSnapshotEnvelope {
        schema: FEDERATED_TRUST_SNAPSHOT_ENVELOPE_SCHEMA.to_owned(),
        version: OBJECT_RELAY_V3_PROOF_VERSION,
        snapshot: v3_trust_snapshot(now, |_snapshot| {}),
        signer_key_id: V3_ROOT_KEY_ID.to_owned(),
        signer_public_key: v3_pk(seed),
        issued_at: now - 1,
        expires_at: now + 300,
        signature: String::new(),
    };
    envelope.signature = ramflux_crypto::sign_canonical_bytes_with_seed(
        &federated_trust_snapshot_envelope_signing_bytes(&envelope)
            .map_err(|error| error.to_string())?,
        seed,
    );
    Ok(envelope)
}

// ---- RQ-03-V3-T14-D: owner-session tombstone core ----

pub(super) fn t14d_tombstone_chunk(owner_public_key: String) -> RelayChunkEntry {
    RelayChunkEntry {
        chunk_id: V3_CHUNK.to_owned(),
        object_id: V3_OBJECT.to_owned(),
        manifest_hash: V3_MANIFEST.to_owned(),
        chunk_index: 0,
        chunk_cipher_hash: "t14d-cipher".to_owned(),
        owner_signing_key_id: V3_OWNER_ID.to_owned(),
        owner_public_key,
        encrypted_chunk: b"t14d-ct".to_vec(),
        stored_at: 0,
        expires_at: 2_000_000,
        delete_after_ack: false,
        acked_by: BTreeSet::new(),
        status: RelayChunkStatus::Available,
    }
}

pub(super) fn t14d_tombstone_request() -> OwnerSessionTombstoneRequest {
    OwnerSessionTombstoneRequest {
        object_id: V3_OBJECT.to_owned(),
        manifest_hash: Some(V3_MANIFEST.to_owned()),
        tombstone_hash: "t14d-ts-hash".to_owned(),
        source_event_id: "t14d-evt".to_owned(),
        signed_at: 999_000,
        expires_at: 1_000_100,
        owner_signing_key_id: V3_OWNER_ID.to_owned(),
        owner_public_key: v3_pk(V3_OWNER_SEED),
    }
}

// ---- T23-A2b2: provider keyring rotation + provider_epoch envelope ----

pub(super) const A2B2_OFFLINE_ROOT_SEED: [u8; 32] = [0x71; 32];
pub(super) const A2B2_K1_SEED: [u8; 32] = [0x72; 32];
pub(super) const A2B2_K2_SEED: [u8; 32] = [0x73; 32];
pub(super) const A2B2_WRONG_SEED: [u8; 32] = [0x74; 32];
pub(super) const A2B2_K1: &str = "prov-k1";
pub(super) const A2B2_K2: &str = "prov-k2";

pub(super) fn a2b2_entry(
    key_id: &str,
    seed: [u8; 32],
    now: u64,
    retired_at: Option<u64>,
    epoch: u64,
) -> ProviderKeyEntry {
    ProviderKeyEntry {
        key_id: key_id.to_owned(),
        public_key: v3_pk(seed),
        not_before: now - 100,
        not_after: now + 3_600,
        retired_at,
        authorized_provider_epoch: epoch,
    }
}

#[allow(clippy::expect_used)]
pub(super) fn a2b2_keyring(
    keyring_epoch: u64,
    keys: Vec<ProviderKeyEntry>,
    apply: impl FnOnce(&mut ProviderKeyring),
) -> ProviderKeyring {
    let mut keyring = ProviderKeyring {
        schema: PROVIDER_KEYRING_SCHEMA.to_owned(),
        version: PROVIDER_KEYRING_VERSION,
        issuer_node_id: V3_ISSUER_NODE.to_owned(),
        keyring_epoch,
        keys,
        keyring_signature: String::new(),
    };
    apply(&mut keyring);
    keyring.keyring_signature = v3_sign(
        &provider_keyring_signing_bytes(&keyring).expect("keyring canonical"),
        A2B2_OFFLINE_ROOT_SEED,
    );
    keyring
}

pub(super) fn a2b2_validate(
    keyring: &ProviderKeyring,
) -> Result<ValidatedProviderKeyring, NodeCoreError> {
    verify_provider_keyring(keyring, &v3_pk(A2B2_OFFLINE_ROOT_SEED), V3_ISSUER_NODE)
}

#[allow(clippy::expect_used)]
pub(super) fn a2b2_envelope(
    now: u64,
    signer_key_id: &str,
    signer_seed: [u8; 32],
    provider_epoch: u64,
    apply: impl FnOnce(&mut ProviderSignedTrustSnapshot),
) -> ProviderSignedTrustSnapshot {
    let mut envelope = ProviderSignedTrustSnapshot {
        schema: PROVIDER_SIGNED_TRUST_SNAPSHOT_ENVELOPE_SCHEMA.to_owned(),
        version: PROVIDER_SIGNED_TRUST_SNAPSHOT_ENVELOPE_VERSION,
        snapshot: v3_trust_snapshot(now, |_s| {}),
        provider_signing_key_id: signer_key_id.to_owned(),
        provider_public_key: v3_pk(signer_seed),
        provider_epoch,
        issued_at: now,
        expires_at: now + 300,
        signature: String::new(),
    };
    apply(&mut envelope);
    envelope.signature = v3_sign(
        &provider_signed_trust_snapshot_signing_bytes(&envelope).expect("envelope canonical"),
        signer_seed,
    );
    envelope
}
