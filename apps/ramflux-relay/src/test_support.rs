// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use ramflux_node_core::ObjectRelayCapability::{Put, Tombstone};
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
#[cfg(feature = "itest-object-v2")]
use std::sync::mpsc;

pub(crate) fn client_quic_request(
    method: &str,
    path: &str,
) -> ramflux_transport::GatewayQuicRequest {
    ramflux_transport::GatewayQuicRequest {
        method: method.to_owned(),
        path: path.to_owned(),
        body: serde_json::Value::Null,
    }
}

// ---- T14-B v3 ingress gate fixtures (valid Get invocation, built via public node-core API) ----

pub(crate) const V3_NOW: u64 = 1_000_000;
pub(crate) const V3_OWNER_SEED: [u8; 32] = [0x11; 32];
pub(crate) const V3_REQUESTER_SEED: [u8; 32] = [0x22; 32];
pub(crate) const V3_ISSUER_SEED: [u8; 32] = [0x33; 32];
pub(crate) const V3_ROOT_SEED: [u8; 32] = [0x44; 32];
pub(crate) const V3_ISSUER_NODE: &str = "node-b";
pub(crate) const V3_AUDIENCE_NODE: &str = "node-a";
pub(crate) const V3_ROOT_KEY_ID: &str = "node-b#root";
pub(crate) const V3_OWNER_ID: &str = "device_a_owner";
pub(crate) const V3_REQUESTER_ID: &str = "device_b_requester";
pub(crate) const V3_OBJECT: &str = "object_v3";
pub(crate) const V3_MANIFEST: &str = "manifest_v3";
pub(crate) const V3_CHUNK: &str = "chunk_v3";
pub(crate) const V3_BODY_HASH: &str = "body_hash_v3";

pub(crate) fn v3_pk(seed: [u8; 32]) -> String {
    ramflux_crypto::public_key_base64url_from_seed(seed)
}

pub(crate) fn v3_sign(bytes: &[u8], seed: [u8; 32]) -> String {
    ramflux_crypto::sign_canonical_bytes_with_seed(bytes, seed)
}

pub(crate) fn v3_requester_hash() -> String {
    ramflux_crypto::blake3_256_base64url(
        "ramflux.object_relay.recipient_device.v1",
        V3_REQUESTER_ID.as_bytes(),
    )
}

pub(crate) fn v3_certificate() -> Result<ramflux_node_core::GatewayIssuerCertificate, String> {
    let mut cert = ramflux_node_core::GatewayIssuerCertificate {
        schema: ramflux_node_core::GATEWAY_ISSUER_CERTIFICATE_SCHEMA.to_owned(),
        version: ramflux_node_core::OBJECT_RELAY_V3_PROOF_VERSION,
        cert_id: "cert-b-1".to_owned(),
        node_id: V3_ISSUER_NODE.to_owned(),
        gateway_instance_id: "gw-b-1".to_owned(),
        attestation_public_key: v3_pk(V3_ISSUER_SEED),
        attestation_key_id: "att-b-1".to_owned(),
        not_before: V3_NOW - 10,
        not_after: V3_NOW + 3_600,
        issued_at: V3_NOW - 10,
        node_root_signing_key_id: V3_ROOT_KEY_ID.to_owned(),
        node_root_signature: String::new(),
        revoked_at: None,
    };
    cert.node_root_signature = v3_sign(
        &ramflux_node_core::gateway_issuer_certificate_signing_bytes(&cert)
            .map_err(|error| error.to_string())?,
        V3_ROOT_SEED,
    );
    Ok(cert)
}

pub(crate) fn v3_signed_grant(
    capabilities: Vec<ramflux_node_core::ObjectRelayCapability>,
) -> Result<ramflux_node_core::ObjectAccessGrant, String> {
    let mut grant = ramflux_node_core::ObjectAccessGrant {
        schema: ramflux_node_core::OBJECT_ACCESS_GRANT_SCHEMA.to_owned(),
        version: ramflux_node_core::OBJECT_RELAY_V3_PROOF_VERSION,
        object_id: V3_OBJECT.to_owned(),
        manifest_hash: V3_MANIFEST.to_owned(),
        grantee_device_hash: v3_requester_hash(),
        capabilities,
        issued_at: V3_NOW,
        expires_at: V3_NOW + 300,
        owner_signing_key_id: V3_OWNER_ID.to_owned(),
        owner_public_key: v3_pk(V3_OWNER_SEED),
        owner_signature: String::new(),
    };
    grant.owner_signature = v3_sign(
        &ramflux_node_core::object_access_grant_signing_bytes(&grant)
            .map_err(|error| error.to_string())?,
        V3_OWNER_SEED,
    );
    Ok(grant)
}

pub(crate) fn v3_token(
    certificate: ramflux_node_core::GatewayIssuerCertificate,
    binding_hash: String,
    capability: ramflux_node_core::ObjectRelayCapability,
) -> Result<ramflux_node_core::RelayTokenV3, String> {
    let mut token = ramflux_node_core::RelayTokenV3 {
        token_version: ramflux_node_core::OBJECT_RELAY_TOKEN_V3_VERSION,
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
        gateway_instance_id: "gw-b-1".to_owned(),
        issuer_certificate_id: "cert-b-1".to_owned(),
        attestation_key_id: "att-b-1".to_owned(),
        issuer_certificate: certificate,
        audience_service: ramflux_node_core::RELAY_TOKEN_V3_AUDIENCE_RELAY.to_owned(),
        audience_node_id: V3_AUDIENCE_NODE.to_owned(),
        relay_instance_id: None,
        object_id: V3_OBJECT.to_owned(),
        manifest_hash: V3_MANIFEST.to_owned(),
        chunk_id: V3_CHUNK.to_owned(),
        capabilities: vec![capability],
        authorization_kind: ramflux_node_core::RelayAuthorizationKind::OwnerGrant,
        authorization_binding_hash: binding_hash,
        delete_after_ack: false,
        issued_at: V3_NOW,
        expires_at: V3_NOW + 120,
        nonce: "nonce_tok_v3".to_owned(),
        issuer_signature: String::new(),
    };
    token.issuer_signature = v3_sign(
        &ramflux_node_core::relay_token_v3_signing_bytes(&token)
            .map_err(|error| error.to_string())?,
        V3_ISSUER_SEED,
    );
    Ok(token)
}

pub(crate) fn v3_signed_pop(
    token: &ramflux_node_core::RelayTokenV3,
    capability: ramflux_node_core::ObjectRelayCapability,
    body_hash: &str,
    signer_seed: [u8; 32],
) -> Result<ramflux_node_core::RequesterProofOfPossession, String> {
    let mut pop = ramflux_node_core::RequesterProofOfPossession {
        schema: ramflux_node_core::REQUESTER_POP_SCHEMA.to_owned(),
        version: ramflux_node_core::OBJECT_RELAY_V3_PROOF_VERSION,
        token_id: token.token_id.clone(),
        capability,
        object_id: token.object_id.clone(),
        manifest_hash: token.manifest_hash.clone(),
        chunk_id: token.chunk_id.clone(),
        request_nonce: "req_nonce_v3".to_owned(),
        body_hash: body_hash.to_owned(),
        issued_at: V3_NOW,
        expires_at: V3_NOW + 60,
        signer_device_id: token.requester_device_id.clone(),
        signer_public_key: token.requester_public_key.clone(),
        signature: String::new(),
    };
    pop.signature = v3_sign(
        &ramflux_node_core::requester_pop_signing_bytes(&pop).map_err(|error| error.to_string())?,
        signer_seed,
    );
    Ok(pop)
}

pub(crate) fn v3_trust_snapshot() -> ramflux_node_core::FederatedIssuerTrustSnapshot {
    ramflux_node_core::FederatedIssuerTrustSnapshot {
        schema: ramflux_node_core::FEDERATED_ISSUER_TRUST_SNAPSHOT_SCHEMA.to_owned(),
        version: ramflux_node_core::OBJECT_RELAY_V3_PROOF_VERSION,
        node_id: V3_ISSUER_NODE.to_owned(),
        generation: 5,
        pin_epoch: 3,
        trust_status: ramflux_node_core::FederatedIssuerTrustStatus::Active,
        roots: vec![ramflux_node_core::TrustedNodeRootKey {
            node_id: V3_ISSUER_NODE.to_owned(),
            key_id: V3_ROOT_KEY_ID.to_owned(),
            public_key: v3_pk(V3_ROOT_SEED),
            not_before: V3_NOW - 100,
            not_after: V3_NOW + 3_600,
            pin_epoch: 3,
            retired_at: None,
        }],
        revoked_cert_ids: BTreeSet::new(),
        hard_stale_at: V3_NOW + 300,
    }
}

/// A cache pinned with the valid trust snapshot for the issuer node.
pub(crate) fn v3_pinned_cache() -> Result<ramflux_node_core::RelayTrustSnapshotCache, String> {
    let mut cache = ramflux_node_core::RelayTrustSnapshotCache::new();
    cache.update(v3_trust_snapshot(), V3_ISSUER_NODE, V3_NOW).map_err(|error| error.to_string())?;
    Ok(cache)
}

/// A complete, correctly-signed v3 ingress envelope body for `capability` (grant covers both Get
/// and Ack so the same fixture serves both). `mutate` can tamper the body before it is serialized
/// (e.g. to smuggle a bogus `snapshot`).
pub(crate) fn v3_envelope_body(
    capability: ramflux_node_core::ObjectRelayCapability,
    mutate: impl FnOnce(&mut serde_json::Map<String, serde_json::Value>),
) -> Result<serde_json::Value, String> {
    let cert = v3_certificate()?;
    let grant = v3_signed_grant(vec![
        ramflux_node_core::ObjectRelayCapability::Get,
        ramflux_node_core::ObjectRelayCapability::Ack,
    ])?;
    let binding = ramflux_node_core::object_access_grant_binding_hash(&grant)
        .map_err(|error| error.to_string())?;
    let token = v3_token(cert.clone(), binding, capability)?;
    let pop = v3_signed_pop(&token, capability, V3_BODY_HASH, V3_REQUESTER_SEED)?;
    let mut body = serde_json::Map::new();
    body.insert(
        "token".to_owned(),
        serde_json::to_value(&token).map_err(|error| error.to_string())?,
    );
    body.insert(
        "certificate".to_owned(),
        serde_json::to_value(&cert).map_err(|error| error.to_string())?,
    );
    body.insert(
        "grant".to_owned(),
        serde_json::to_value(&grant).map_err(|error| error.to_string())?,
    );
    body.insert("pop".to_owned(), serde_json::to_value(&pop).map_err(|error| error.to_string())?);
    body.insert("body_hash".to_owned(), serde_json::Value::String(V3_BODY_HASH.to_owned()));
    body.insert(
        "capability".to_owned(),
        serde_json::to_value(capability).map_err(|error| error.to_string())?,
    );
    mutate(&mut body);
    Ok(serde_json::Value::Object(body))
}

pub(crate) fn client_quic_object_request(
    body: serde_json::Value,
) -> ramflux_transport::GatewayQuicRequest {
    client_quic_object_request_to("/relay/v1/object/get_chunk", body)
}

pub(crate) fn client_quic_object_request_to(
    path: &str,
    body: serde_json::Value,
) -> ramflux_transport::GatewayQuicRequest {
    ramflux_transport::GatewayQuicRequest { method: "POST".to_owned(), path: path.to_owned(), body }
}

/// A stored chunk whose immutable original-owner binding matches the token owner
/// (`V3_OWNER_ID` / `V3_OWNER_SEED`) unless `owner_public_key` is overridden.
pub(crate) fn v3_stored_chunk(
    owner_public_key: String,
    delete_after_ack: bool,
) -> ramflux_node_core::RelayChunkEntry {
    ramflux_node_core::RelayChunkEntry {
        chunk_id: V3_CHUNK.to_owned(),
        object_id: V3_OBJECT.to_owned(),
        manifest_hash: V3_MANIFEST.to_owned(),
        chunk_index: 0,
        // Real canonical cipher hash of the stored ciphertext so the GET read-through integrity
        // check (recompute == stored hash) passes.
        chunk_cipher_hash: ramflux_node_core::object_relay_chunk_cipher_hash(
            V3_MANIFEST,
            0,
            b"ciphertext-v3",
        ),
        owner_signing_key_id: V3_OWNER_ID.to_owned(),
        owner_public_key,
        encrypted_chunk: b"ciphertext-v3".to_vec(),
        stored_at: V3_NOW - 10,
        expires_at: V3_NOW + 300,
        delete_after_ack,
        acked_by: BTreeSet::new(),
        status: ramflux_node_core::RelayChunkStatus::Available,
    }
}

// Seeds a chunk into BOTH the resident meta index and the redb payload table, keeping the
// metadata-only-in-memory invariant (ciphertext lives in redb, read through on demand).
pub(crate) fn v3_state_with(
    store: &ramflux_node_core::RelayRedbStore,
    chunk: ramflux_node_core::RelayChunkEntry,
) -> Result<Arc<Mutex<ramflux_node_core::RelayCacheState>>, String> {
    store.record_relay_chunk_entry(&chunk).map_err(|error| error.to_string())?;
    let mut state = ramflux_node_core::RelayCacheState::new();
    state.put_chunk(chunk).map_err(|error| error.to_string())?;
    Ok(Arc::new(Mutex::new(state)))
}

/// A fresh on-disk relay store at a process-unique temp path (avoids redb "already open" flakes).
pub(crate) fn v3_temp_store() -> Result<Arc<ramflux_node_core::RelayRedbStore>, String> {
    static NEXT_STORE_ID: AtomicU64 = AtomicU64::new(0);
    let id = NEXT_STORE_ID.fetch_add(1, Ordering::Relaxed);
    let path =
        std::env::temp_dir().join(format!("ramflux-relay-t14c-{}-{id}.redb", std::process::id()));
    let store =
        ramflux_node_core::RelayRedbStore::open(&path).map_err(|error| error.to_string())?;
    Ok(Arc::new(store))
}

pub(crate) fn v3_acked_by_count(state: &Arc<Mutex<ramflux_node_core::RelayCacheState>>) -> usize {
    let guard = state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    guard.chunk_entry(V3_CHUNK).map_or(0, |chunk| chunk.acked_by.len())
}

// ---- owner-session (Put) fixtures: the requester is the owner device itself ----

pub(crate) const V3_PUT_INDEX: u32 = 0;
// Must be within the token's own expiry window (`V3_NOW + 120`) and a bounded future value.
pub(crate) const V3_PUT_EXPIRES_AT: u64 = V3_NOW + 100;

pub(crate) fn v3_put_ciphertext() -> Vec<u8> {
    b"put-ciphertext-v3".to_vec()
}

pub(crate) fn v3_put_cipher_hash() -> String {
    ramflux_node_core::object_relay_chunk_cipher_hash(
        V3_MANIFEST,
        V3_PUT_INDEX,
        &v3_put_ciphertext(),
    )
}

pub(crate) fn v3_owner_proof(
    capability: ramflux_node_core::ObjectRelayCapability,
    body_hash: &str,
) -> Result<ramflux_node_core::OwnerAuthorizationProof, String> {
    let mut proof = ramflux_node_core::OwnerAuthorizationProof {
        schema: ramflux_node_core::OWNER_AUTHORIZATION_PROOF_SCHEMA.to_owned(),
        version: ramflux_node_core::OBJECT_RELAY_V3_PROOF_VERSION,
        capability,
        object_id: V3_OBJECT.to_owned(),
        manifest_hash: Some(V3_MANIFEST.to_owned()),
        chunk_id: Some(V3_CHUNK.to_owned()),
        owner_home_node_id: V3_AUDIENCE_NODE.to_owned(),
        owner_principal_id: "principal_a".to_owned(),
        owner_device_epoch: 3,
        request_nonce: "owner_proof_nonce_v3".to_owned(),
        body_hash: body_hash.to_owned(),
        issued_at: V3_NOW,
        expires_at: V3_NOW + 120,
        owner_signing_key_id: V3_OWNER_ID.to_owned(),
        owner_public_key: v3_pk(V3_OWNER_SEED),
        owner_signature: String::new(),
    };
    proof.owner_signature = v3_sign(
        &ramflux_node_core::owner_authorization_proof_signing_bytes(&proof)
            .map_err(|error| error.to_string())?,
        V3_OWNER_SEED,
    );
    Ok(proof)
}

pub(crate) fn v3_owner_session_token(
    certificate: ramflux_node_core::GatewayIssuerCertificate,
    binding_hash: String,
    capability: ramflux_node_core::ObjectRelayCapability,
) -> Result<ramflux_node_core::RelayTokenV3, String> {
    // For owner-session operations the requester IS the owner device.
    let mut token = v3_token(certificate, binding_hash, capability)?;
    token.authorization_kind = ramflux_node_core::RelayAuthorizationKind::OwnerSession;
    token.requester_device_id = V3_OWNER_ID.to_owned();
    token.requester_device_hash = ramflux_crypto::blake3_256_base64url(
        "ramflux.object_relay.recipient_device.v1",
        V3_OWNER_ID.as_bytes(),
    );
    token.requester_public_key = v3_pk(V3_OWNER_SEED);
    token.issuer_signature = v3_sign(
        &ramflux_node_core::relay_token_v3_signing_bytes(&token)
            .map_err(|error| error.to_string())?,
        V3_ISSUER_SEED,
    );
    Ok(token)
}

/// A complete, correctly-signed owner-session Put request body: the auth envelope (owner proof,
/// owner-signed `PoP`) plus the chunk payload, with `body_hash` bound to the ciphertext's cipher
/// hash. `mutate` can tamper the body before it is serialized.
pub(crate) fn v3_put_request_body(
    mutate: impl FnOnce(&mut serde_json::Map<String, serde_json::Value>),
) -> Result<serde_json::Value, String> {
    let cipher_hash = v3_put_cipher_hash();
    let cert = v3_certificate()?;
    let proof = v3_owner_proof(Put, &cipher_hash)?;
    let binding = ramflux_node_core::owner_authorization_proof_binding_hash(&proof)
        .map_err(|error| error.to_string())?;
    let token = v3_owner_session_token(cert.clone(), binding, Put)?;
    let pop = v3_signed_pop(&token, Put, &cipher_hash, V3_OWNER_SEED)?;
    let mut body = serde_json::Map::new();
    body.insert(
        "token".to_owned(),
        serde_json::to_value(&token).map_err(|error| error.to_string())?,
    );
    body.insert(
        "certificate".to_owned(),
        serde_json::to_value(&cert).map_err(|error| error.to_string())?,
    );
    body.insert(
        "owner_proof".to_owned(),
        serde_json::to_value(&proof).map_err(|error| error.to_string())?,
    );
    body.insert("pop".to_owned(), serde_json::to_value(&pop).map_err(|error| error.to_string())?);
    body.insert("body_hash".to_owned(), serde_json::Value::String(cipher_hash.clone()));
    body.insert(
        "capability".to_owned(),
        serde_json::to_value(Put).map_err(|error| error.to_string())?,
    );
    // Chunk payload (flat, alongside the auth envelope).
    body.insert("chunk_index".to_owned(), serde_json::Value::Number(V3_PUT_INDEX.into()));
    body.insert("chunk_cipher_hash".to_owned(), serde_json::Value::String(cipher_hash));
    body.insert(
        "encrypted_chunk".to_owned(),
        serde_json::to_value(v3_put_ciphertext()).map_err(|error| error.to_string())?,
    );
    body.insert("expires_at".to_owned(), serde_json::Value::Number(V3_PUT_EXPIRES_AT.into()));
    body.insert("delete_after_ack".to_owned(), serde_json::Value::Bool(false));
    mutate(&mut body);
    Ok(serde_json::Value::Object(body))
}

pub(crate) fn v3_chunk_snapshot(
    state: &Arc<Mutex<ramflux_node_core::RelayCacheState>>,
) -> Option<ramflux_node_core::RelayChunkMeta> {
    let guard = state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    guard.chunk_entry(V3_CHUNK).cloned()
}

// ---- owner-session (Tombstone) fixtures ----

pub(crate) const V3_TOMBSTONE_HASH: &str = "t14d-relay-tombstone-hash";

/// A complete, correctly-signed owner-session Tombstone request body: the auth envelope (owner
/// proof, owner-signed `PoP`) plus the tombstone metadata, with `body_hash` bound to the
/// `tombstone_hash`. `mutate` can tamper the body before it is serialized.
pub(crate) fn v3_tombstone_request_body(
    mutate: impl FnOnce(&mut serde_json::Map<String, serde_json::Value>),
) -> Result<serde_json::Value, String> {
    let cert = v3_certificate()?;
    let proof = v3_owner_proof(Tombstone, V3_TOMBSTONE_HASH)?;
    let binding = ramflux_node_core::owner_authorization_proof_binding_hash(&proof)
        .map_err(|error| error.to_string())?;
    let token = v3_owner_session_token(cert.clone(), binding, Tombstone)?;
    let pop = v3_signed_pop(&token, Tombstone, V3_TOMBSTONE_HASH, V3_OWNER_SEED)?;
    let mut body = serde_json::Map::new();
    body.insert(
        "token".to_owned(),
        serde_json::to_value(&token).map_err(|error| error.to_string())?,
    );
    body.insert(
        "certificate".to_owned(),
        serde_json::to_value(&cert).map_err(|error| error.to_string())?,
    );
    body.insert(
        "owner_proof".to_owned(),
        serde_json::to_value(&proof).map_err(|error| error.to_string())?,
    );
    body.insert("pop".to_owned(), serde_json::to_value(&pop).map_err(|error| error.to_string())?);
    body.insert("body_hash".to_owned(), serde_json::Value::String(V3_TOMBSTONE_HASH.to_owned()));
    body.insert(
        "capability".to_owned(),
        serde_json::to_value(Tombstone).map_err(|error| error.to_string())?,
    );
    body.insert(
        "tombstone_hash".to_owned(),
        serde_json::Value::String(V3_TOMBSTONE_HASH.to_owned()),
    );
    body.insert("source_event_id".to_owned(), serde_json::Value::String("t14d-evt".to_owned()));
    body.insert("signed_at".to_owned(), serde_json::Value::Number(V3_NOW.into()));
    body.insert("expires_at".to_owned(), serde_json::Value::Number((V3_NOW + 100).into()));
    mutate(&mut body);
    Ok(serde_json::Value::Object(body))
}

pub(crate) fn v3_chunk_status(
    state: &Arc<Mutex<ramflux_node_core::RelayCacheState>>,
) -> Option<ramflux_node_core::RelayChunkStatus> {
    v3_chunk_snapshot(state).map(|chunk| chunk.status)
}

#[cfg(feature = "itest-object-v2")]
pub(crate) fn spawn_retention_blocking_mesh_echo_server(
    server_tls: ramflux_transport::MeshTlsConfig,
    trusted_relay_ca: String,
) -> Result<
    (String, mpsc::Receiver<ramflux_node_core::RetentionRecordRequest>),
    Box<dyn std::error::Error>,
> {
    let server = ramflux_transport::MeshTlsServer::bind("127.0.0.1:0", &server_tls)?;
    let endpoint = server.local_addr()?.to_string();
    let (request_tx, request_rx) = mpsc::channel::<ramflux_node_core::RetentionRecordRequest>();
    std::thread::spawn(move || {
        let result: Result<(), String> = (|| {
            let mut accepted = server
                .accept_authenticated_with_pem_roots(&server_tls, &[trusted_relay_ca])
                .map_err(|source| source.to_string())?
                .stream;
            let request = ramflux_transport::read_mesh_http_request(&mut accepted)
                .map_err(|source| source.to_string())?
                .ok_or_else(|| "missing retention blocking mesh request".to_owned())?;
            if request.method != "POST" || request.path != "/retention/v1/object_relay_ttl" {
                return Err(format!(
                    "unexpected retention blocking mesh request {} {}",
                    request.method, request.path
                ));
            }
            let request: ramflux_node_core::RetentionRecordRequest =
                serde_json::from_slice(&request.body).map_err(|source| source.to_string())?;
            let response = request.record.clone();
            request_tx.send(request).map_err(|source| source.to_string())?;
            ramflux_transport::write_mesh_json_response(&mut accepted, "200 OK", &response)
                .map_err(|source| source.to_string())?;
            ramflux_transport::close_mesh_server_stream(&mut accepted)
                .map_err(|source| source.to_string())
        })();
        if let Err(error) = result {
            tracing::debug!(%error, "relay retention blocking mesh fallback test server stopped");
        }
    });
    Ok((endpoint, request_rx))
}

pub(crate) fn test_config(
    tls: &ramflux_transport::MeshTlsConfig,
    retention_endpoint: &str,
) -> ramflux_node_core::NodeServiceConfig {
    let mut endpoints = BTreeMap::new();
    endpoints.insert("retention".to_owned(), retention_endpoint.to_owned());
    ramflux_node_core::NodeServiceConfig {
        node_id: "node-retention-a".to_owned(),
        service_id: "ramflux-relay".to_owned(),
        redb_path: ":memory:".to_owned(),
        node_service_signing_seed_b64url: None,
        mesh: ramflux_node_core::MeshConfig {
            listen_addr: "127.0.0.1:0".to_owned(),
            ca_cert: tls.ca_cert.to_string_lossy().into_owned(),
            service_cert: tls.service_cert.to_string_lossy().into_owned(),
            service_key: tls.service_key.to_string_lossy().into_owned(),
            allowed_service_ids: BTreeSet::from([
                "ramflux-relay".to_owned(),
                "ramflux-retention".to_owned(),
            ]),
            endpoints,
        },
        gateway: None,
        signaling: None,
        relay: None,
    }
}

#[cfg(feature = "itest-object-v2")]
pub(crate) fn test_relay_chunk_entry() -> ramflux_node_core::RelayChunkEntry {
    ramflux_node_core::RelayChunkEntry {
        chunk_id: "chunk-retention-quic-fallback".to_owned(),
        object_id: "object-retention-quic-fallback".to_owned(),
        manifest_hash: "manifest-hash".to_owned(),
        chunk_index: 0,
        chunk_cipher_hash: "chunk-cipher-hash".to_owned(),
        owner_signing_key_id: "owner-retention-quic-fallback".to_owned(),
        owner_public_key: "owner-public-retention-quic-fallback".to_owned(),
        encrypted_chunk: b"ciphertext".to_vec(),
        stored_at: 1_000,
        expires_at: 1_900,
        delete_after_ack: false,
        acked_by: BTreeSet::new(),
        status: ramflux_node_core::RelayChunkStatus::Available,
    }
}

pub(crate) struct TestPeerCerts {
    pub(crate) tls: ramflux_transport::MeshTlsConfig,
    #[cfg_attr(not(feature = "itest-object-v2"), allow(dead_code))]
    pub(crate) ca_pem: String,
}

pub(crate) fn temp_cert_root(name: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let root =
        std::env::temp_dir().join(format!("ramflux_relay_{name}_{}_{}", std::process::id(), nanos));
    if root.exists() {
        std::fs::remove_dir_all(&root)?;
    }
    std::fs::create_dir_all(&root)?;
    Ok(root)
}

pub(crate) fn issue_test_ca_and_service_cert(
    root: &Path,
    node_id: &str,
    service_id: &str,
) -> Result<TestPeerCerts, Box<dyn std::error::Error>> {
    let dir = root.join(service_id);
    std::fs::create_dir_all(&dir)?;
    let ca_key = dir.join("ca-key.pem");
    let ca_cert = dir.join("ca.pem");
    let service_key = dir.join(format!("{service_id}-key.pem"));
    let service_csr = dir.join(format!("{service_id}.csr"));
    let service_cert = dir.join(format!("{service_id}.pem"));
    let ext = dir.join(format!("{service_id}.ext"));
    run_openssl(&["genpkey", "-algorithm", "ED25519", "-out", path_str(&ca_key)?])?;
    run_openssl(&[
        "req",
        "-x509",
        "-new",
        "-key",
        path_str(&ca_key)?,
        "-out",
        path_str(&ca_cert)?,
        "-days",
        "30",
        "-subj",
        "/CN=Ramflux Relay Retention Mesh Test CA",
    ])?;
    run_openssl(&["genpkey", "-algorithm", "ED25519", "-out", path_str(&service_key)?])?;
    run_openssl(&[
        "req",
        "-new",
        "-key",
        path_str(&service_key)?,
        "-out",
        path_str(&service_csr)?,
        "-subj",
        &format!("/CN={service_id}"),
    ])?;
    std::fs::write(
        &ext,
        format!(
            "subjectAltName = DNS:{service_id}, DNS:localhost, URI:spiffe://{node_id}/{service_id}\nextendedKeyUsage = serverAuth, clientAuth\nkeyUsage = digitalSignature\n"
        ),
    )?;
    run_openssl(&[
        "x509",
        "-req",
        "-in",
        path_str(&service_csr)?,
        "-CA",
        path_str(&ca_cert)?,
        "-CAkey",
        path_str(&ca_key)?,
        "-CAcreateserial",
        "-out",
        path_str(&service_cert)?,
        "-days",
        "30",
        "-extfile",
        path_str(&ext)?,
    ])?;
    Ok(TestPeerCerts {
        tls: ramflux_transport::MeshTlsConfig {
            ca_cert: ca_cert.clone(),
            service_cert,
            service_key,
        },
        ca_pem: std::fs::read_to_string(ca_cert)?,
    })
}

pub(crate) fn run_openssl(args: &[&str]) -> Result<(), Box<dyn std::error::Error>> {
    let status = Command::new("openssl").args(args).status()?;
    if !status.success() {
        return Err(format!("openssl failed with status {status}: {}", args.join(" ")).into());
    }
    Ok(())
}

pub(crate) fn path_str(path: &Path) -> Result<&str, Box<dyn std::error::Error>> {
    path.to_str().ok_or_else(|| format!("non-UTF-8 path {}", path.display()).into())
}

#[cfg(feature = "itest-object-v2")]
pub(crate) fn test_error(message: impl Into<String>) -> Box<dyn std::error::Error> {
    message.into().into()
}
