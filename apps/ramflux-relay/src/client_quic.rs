// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! V3 object request authorization, ownership checks, and operation routing.

use std::sync::{Arc, Mutex};

/// The explicit v3 ingress envelope carried in an object request body. It carries the caller-supplied
/// token/certificate/authorization/`PoP` material and the request `body_hash`/`capability`, but NOT a
/// trust snapshot: the authoritative snapshot is always taken from the relay's pinned trust cache,
/// never from the request body (a body-supplied snapshot would be trivially forgeable). Unknown JSON
/// members are ignored, so a body that additionally smuggles a `snapshot` has no effect.
#[derive(serde::Deserialize)]
pub(crate) struct RelayClientQuicV3Envelope {
    pub(crate) token: ramflux_node_core::RelayTokenV3,
    pub(crate) certificate: ramflux_node_core::GatewayIssuerCertificate,
    #[serde(default)]
    pub(crate) grant: Option<ramflux_node_core::ObjectAccessGrant>,
    #[serde(default)]
    pub(crate) owner_proof: Option<ramflux_node_core::OwnerAuthorizationProof>,
    pub(crate) pop: ramflux_node_core::RequesterProofOfPossession,
    pub(crate) body_hash: String,
    pub(crate) capability: ramflux_node_core::ObjectRelayCapability,
}

/// The chunk payload carried alongside the v3 invocation on a `put_chunk` request. It is NOT trusted
/// on its own: `chunk_cipher_hash` must be the canonical hash of `encrypted_chunk` for the token's
/// manifest/index, and it must equal the invocation's `body_hash` — which both the owner proof and
/// the requester `PoP` sign — so the ciphertext cannot be substituted under a valid invocation.
#[derive(serde::Deserialize)]
pub(crate) struct RelayClientQuicPutPayload {
    pub(crate) chunk_index: u32,
    pub(crate) chunk_cipher_hash: String,
    pub(crate) encrypted_chunk: Vec<u8>,
    pub(crate) expires_at: u64,
    pub(crate) delete_after_ack: bool,
}

/// The tombstone metadata carried alongside the v3 invocation on a `tombstone` request. Its
/// `tombstone_hash` must equal the invocation's `body_hash` (which the owner proof and `PoP` sign), so
/// the tombstone the owner authorized cannot be swapped for a different one. The object and manifest
/// scope are taken from the verified token, never the payload.
#[derive(serde::Deserialize)]
pub(crate) struct RelayClientQuicTombstonePayload {
    pub(crate) tombstone_hash: String,
    pub(crate) source_event_id: String,
    pub(crate) signed_at: u64,
    pub(crate) expires_at: u64,
}

pub(crate) fn relay_client_quic_response(
    status: u16,
    body: serde_json::Value,
) -> ramflux_transport::GatewayQuicResponse {
    ramflux_transport::GatewayQuicResponse { status, body }
}

/// Verifies a client-facing object request as a fully-authenticated v3 invocation and returns the
/// parsed envelope. Fail-closed at every step and — crucially — performs NO store access, so a caller
/// that fails verification can never reach or mutate the data plane:
/// - A body that does not parse as a [`RelayClientQuicV3Envelope`] (including any v2/HMAC wire shape)
///   is rejected `401`.
/// - The route fixes `expected_capability`; a token for a different capability is rejected `403`, so
///   an Ack-scoped token cannot be replayed against the get route (or vice versa).
/// - The authoritative trust snapshot is read from the pinned `trust_cache` keyed by the token's
///   issuer node id — never from the request body. A missing/stale/mismatched pin is rejected `403`.
/// - The token trust-chain ([`ramflux_node_core::verify_relay_token_v3_with_trust_snapshot`]) and the
///   invocation binding ([`ramflux_node_core::verify_relay_invocation_v3`]) must both pass, else `403`.
pub(crate) fn relay_client_quic_verify_invocation(
    request: &ramflux_transport::GatewayQuicRequest,
    trust_cache: &ramflux_node_core::RelayTrustSnapshotCache,
    expected_node_id: &str,
    expected_capability: ramflux_node_core::ObjectRelayCapability,
    now: u64,
) -> Result<RelayClientQuicV3Envelope, ramflux_transport::GatewayQuicResponse> {
    let malformed =
        |reason: String| relay_client_quic_response(401, serde_json::json!({ "error": reason }));
    let unauthorized =
        |reason: String| relay_client_quic_response(403, serde_json::json!({ "error": reason }));

    let envelope: RelayClientQuicV3Envelope = serde_json::from_value(request.body.clone())
        .map_err(|error| malformed(format!("malformed v3 ingress envelope: {error}")))?;

    // The capability is fixed by the route; a mismatch means the caller is presenting a token scoped
    // to a different operation than this endpoint performs.
    if envelope.capability != expected_capability {
        return Err(unauthorized(format!(
            "capability {:?} does not match this endpoint",
            envelope.capability
        )));
    }

    // Authoritative trust snapshot: pinned cache only, keyed by the token's issuer node id. A
    // body-supplied snapshot (or any extra JSON) is ignored, so it can never anchor trust.
    let snapshot = trust_cache
        .current(&envelope.token.issuer_node_id, now)
        .map_err(|error| unauthorized(format!("no pinned trust snapshot for issuer: {error}")))?;

    ramflux_node_core::verify_relay_token_v3_with_trust_snapshot(
        &envelope.token,
        &envelope.certificate,
        snapshot,
        envelope.capability,
        expected_node_id,
        now,
    )
    .map_err(|error| unauthorized(format!("relay token rejected: {error}")))?;

    let invocation = ramflux_node_core::RelayInvocationV3 {
        token: &envelope.token,
        issuer_public_key: &envelope.certificate.attestation_public_key,
        grant: envelope.grant.as_ref(),
        owner_proof: envelope.owner_proof.as_ref(),
        pop: &envelope.pop,
        expected_audience_node_id: expected_node_id,
        expected_body_hash: &envelope.body_hash,
        capability: envelope.capability,
        now,
    };
    ramflux_node_core::verify_relay_invocation_v3(&invocation)
        .map_err(|error| unauthorized(format!("relay invocation rejected: {error}")))?;

    Ok(envelope)
}

/// Enforces the RQ-03 original-owner binding for a verified v3 Get/Ack: the stored chunk's immutable
/// original-owner identity (bound at put time) and its object/manifest must equal the token's owner
/// and object/manifest. The v3 grant proved the token's owner authorized the requester as grantee;
/// this ties that authorization to the chunk actually in the store, closing the "any self-signed
/// grant reads any chunk" gap. A legacy chunk with no owner binding fails closed.
pub(crate) fn relay_chunk_matches_owner_binding(
    chunk: &ramflux_node_core::RelayChunkMeta,
    token: &ramflux_node_core::RelayTokenV3,
) -> bool {
    chunk.has_owner_binding()
        && chunk.owner_signing_key_id == token.owner_signing_key_id
        && chunk.owner_public_key == token.owner_public_key
        && chunk.object_id == token.object_id
        && chunk.manifest_hash == token.manifest_hash
}

/// Verified Get data plane: after full v3 verification, returns the stored chunk that matches the
/// token's chunk id and original-owner binding. Read-only; the store is touched only after
/// verification passes. `404` when the chunk is not available, `403` on an owner/object binding
/// mismatch, `410` when the object is tombstoned.
pub(crate) fn relay_client_quic_object_get(
    request: &ramflux_transport::GatewayQuicRequest,
    trust_cache: &ramflux_node_core::RelayTrustSnapshotCache,
    store: &Arc<ramflux_node_core::RelayRedbStore>,
    state: &Arc<Mutex<ramflux_node_core::RelayCacheState>>,
    expected_node_id: &str,
    now: u64,
) -> ramflux_transport::GatewayQuicResponse {
    let envelope = match relay_client_quic_verify_invocation(
        request,
        trust_cache,
        expected_node_id,
        ramflux_node_core::ObjectRelayCapability::Get,
        now,
    ) {
        Ok(envelope) => envelope,
        Err(response) => return response,
    };

    // Snapshot the resident metadata under the lock (availability + owner-binding + tombstone), then
    // read the ciphertext through redb with a TOCTOU recheck (never serves a stale/tombstoned payload).
    let expected = {
        let guard = state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(meta) = guard.available_meta(&envelope.token.chunk_id, now) else {
            return relay_client_quic_response(
                404,
                serde_json::json!({ "error": "relay chunk not available" }),
            );
        };
        if !relay_chunk_matches_owner_binding(meta, &envelope.token) {
            return relay_client_quic_response(
                403,
                serde_json::json!({ "error": "relay chunk owner/object binding mismatch" }),
            );
        }
        if guard.tombstone(&meta.object_id).is_some() {
            return relay_client_quic_response(
                410,
                serde_json::json!({ "error": "relay object tombstoned" }),
            );
        }
        meta.clone()
    };
    let chunk = match ramflux_node_core::relay_store_read_through(store, state, &expected, now) {
        Ok(chunk) => chunk,
        Err(error) => {
            let status = error.status_code();
            return relay_client_quic_response(
                status,
                serde_json::json!({ "error": format!("relay get read-through failed: {error}") }),
            );
        }
    };
    let get_response = ramflux_node_core::ObjectRelayGetResponse { chunk };
    match serde_json::to_value(get_response) {
        Ok(body) => relay_client_quic_response(200, body),
        Err(error) => relay_client_quic_response(
            500,
            serde_json::json!({ "error": format!("relay get serialization failed: {error}") }),
        ),
    }
}

/// Verified Ack data plane: after full v3 verification, records the requester (grantee) device in the
/// stored chunk's `acked_by` set and applies the owner's stored delete-on-ack policy, then persists.
/// Idempotent: `acked_by` is a set, the delete policy is the owner's stored policy (never the token's),
/// and an already-consumed chunk is never resurrected. `404` when the chunk is missing, `403` on an
/// owner/object binding mismatch.
// itest-only fault seam: fail exactly the first client-facing v3 ACK per relay process when the
// RAMFLUX_RELAY_ITEST_FAIL_FIRST_V3_ACK env is set, so a test can exercise the SDK's persist-then-ACK
// retry path. It fires before any authorization or store/replay mutation, so a failed ACK never
// touches the chunk entry, and once consumed the same relay process acknowledges normally. This is
// compiled only under `itest-http`; a default/release relay build contains neither the symbol, the
// env string, nor the branch.
#[cfg(feature = "itest-http")]
pub(crate) static RELAY_CLIENT_ACK_FAILED_FIRST: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

#[cfg(feature = "itest-http")]
pub(crate) fn relay_client_quic_ack_fail_once() -> bool {
    relay_client_quic_ack_fail_once_with(
        &RELAY_CLIENT_ACK_FAILED_FIRST,
        ramflux_node_core::environment::var("RAMFLUX_RELAY_ITEST_FAIL_FIRST_V3_ACK").as_deref()
            == Ok("1"),
    )
}

#[cfg(feature = "itest-http")]
pub(crate) fn relay_client_quic_ack_fail_once_with(
    failed_first: &std::sync::atomic::AtomicBool,
    enabled: bool,
) -> bool {
    if !enabled {
        return false;
    }
    !failed_first.swap(true, std::sync::atomic::Ordering::SeqCst)
}

pub(crate) fn relay_client_quic_object_ack(
    request: &ramflux_transport::GatewayQuicRequest,
    trust_cache: &ramflux_node_core::RelayTrustSnapshotCache,
    store: &Arc<ramflux_node_core::RelayRedbStore>,
    state: &Arc<Mutex<ramflux_node_core::RelayCacheState>>,
    expected_node_id: &str,
    now: u64,
) -> ramflux_transport::GatewayQuicResponse {
    // Fail closed before any authorization or store/replay mutation on the injected first ACK.
    #[cfg(feature = "itest-http")]
    if relay_client_quic_ack_fail_once() {
        return relay_client_quic_response(
            503,
            serde_json::json!({ "error": "itest fail-first v3 ack seam" }),
        );
    }
    let envelope = match relay_client_quic_verify_invocation(
        request,
        trust_cache,
        expected_node_id,
        ramflux_node_core::ObjectRelayCapability::Ack,
        now,
    ) {
        Ok(envelope) => envelope,
        Err(response) => return response,
    };

    // Plan (owner-binding + acked_by + owner delete policy) + reserve are atomic under one lock inside
    // `relay_store_ack`; then persist-before-publish (payload kept unless the ack consumed the chunk).
    let token = &envelope.token;
    let updated = match ramflux_node_core::relay_store_ack(store, state, |guard| {
        let existing = guard
            .chunk_meta(&token.chunk_id)
            .ok_or(ramflux_node_core::RelayStoreOpError::NotAvailable)?;
        if !relay_chunk_matches_owner_binding(existing, token) {
            return Err(ramflux_node_core::RelayStoreOpError::Unauthorized(
                "relay chunk owner/object binding mismatch".to_owned(),
            ));
        }
        let mut updated = existing.clone();
        updated.acked_by.insert(token.requester_device_hash.clone());
        // Deletion is governed solely by the owner's stored policy, never the token, and a consumed
        // chunk is never brought back to `Available`.
        if updated.delete_after_ack {
            updated.status = ramflux_node_core::RelayChunkStatus::AckedDeleted;
        }
        Ok(updated)
    }) {
        Ok(meta) => meta,
        Err(error) => {
            let status = error.status_code();
            return relay_client_quic_response(
                status,
                serde_json::json!({ "error": format!("relay ack failed: {error}") }),
            );
        }
    };
    let ack_response = ramflux_node_core::ObjectRelayAckResponse {
        chunk_id: updated.chunk_id.clone(),
        status: updated.status,
        acked_by_count: updated.acked_by.len(),
    };
    match serde_json::to_value(ack_response) {
        Ok(body) => relay_client_quic_response(200, body),
        Err(error) => relay_client_quic_response(
            500,
            serde_json::json!({ "error": format!("relay ack serialization failed: {error}") }),
        ),
    }
}

/// Verified owner-session Put data plane: after full v3 verification (owner proof required; requester
/// must be the owner device), stores the carried chunk under the owner's immutable original-owner
/// binding. Mirrors the node-core `put_object_chunk_frame` store invariants:
/// - the carried ciphertext is bound to the signed invocation (its canonical cipher hash must match
///   `chunk_cipher_hash` AND the invocation `body_hash` that the owner proof and `PoP` both sign);
/// - a tombstone on the object blocks the put (`409`);
/// - a chunk id owned by a different original owner (or a legacy unbound record) cannot be overwritten
///   (`403`), and the same owner cannot overwrite different content or resurrect a consumed chunk;
/// - a same-owner, byte-identical replay is idempotent with zero mutation (no write, `200`).
///
/// All authorization and binding checks complete before any store write.
pub(crate) fn relay_client_quic_object_put(
    request: &ramflux_transport::GatewayQuicRequest,
    trust_cache: &ramflux_node_core::RelayTrustSnapshotCache,
    store: &Arc<ramflux_node_core::RelayRedbStore>,
    state: &Arc<Mutex<ramflux_node_core::RelayCacheState>>,
    expected_node_id: &str,
    now: u64,
) -> ramflux_transport::GatewayQuicResponse {
    let envelope = match relay_client_quic_verify_invocation(
        request,
        trust_cache,
        expected_node_id,
        ramflux_node_core::ObjectRelayCapability::Put,
        now,
    ) {
        Ok(envelope) => envelope,
        Err(response) => return response,
    };
    let payload: RelayClientQuicPutPayload = match serde_json::from_value(request.body.clone()) {
        Ok(payload) => payload,
        Err(error) => {
            return relay_client_quic_response(
                401,
                serde_json::json!({ "error": format!("malformed put payload: {error}") }),
            );
        }
    };
    let token = &envelope.token;

    // Bind the ciphertext to the signed invocation: the cipher hash must be the canonical hash of the
    // ciphertext for this manifest/index, and must equal the `body_hash` the owner proof and PoP both
    // sign — so a valid invocation cannot be reused to store a different payload.
    let expected_cipher_hash = ramflux_node_core::object_relay_chunk_cipher_hash(
        &token.manifest_hash,
        payload.chunk_index,
        &payload.encrypted_chunk,
    );
    if payload.chunk_cipher_hash != expected_cipher_hash {
        return relay_client_quic_response(
            403,
            serde_json::json!({ "error": "relay put chunk cipher hash mismatch" }),
        );
    }
    if envelope.body_hash != payload.chunk_cipher_hash {
        return relay_client_quic_response(
            403,
            serde_json::json!({ "error": "relay put payload not bound to the signed body hash" }),
        );
    }

    // The chunk's own expiry must be a bounded future value within the token's window.
    let capped_expires_at =
        ramflux_node_core::clamp_relay_chunk_expires_at(now, payload.expires_at);
    if payload.expires_at <= now || capped_expires_at > token.expires_at {
        return relay_client_quic_response(
            403,
            serde_json::json!({ "error": "relay put chunk ttl invalid" }),
        );
    }

    // Build the candidate entry from the verified token + payload, then apply the persist-before-
    // publish store orchestration (ciphertext committed to redb before the meta is published).
    let candidate = ramflux_node_core::RelayChunkEntry {
        chunk_id: token.chunk_id.clone(),
        object_id: token.object_id.clone(),
        manifest_hash: token.manifest_hash.clone(),
        chunk_index: payload.chunk_index,
        chunk_cipher_hash: payload.chunk_cipher_hash.clone(),
        owner_signing_key_id: token.owner_signing_key_id.clone(),
        owner_public_key: token.owner_public_key.clone(),
        encrypted_chunk: payload.encrypted_chunk.clone(),
        stored_at: now,
        expires_at: capped_expires_at,
        delete_after_ack: payload.delete_after_ack,
        acked_by: std::collections::BTreeSet::new(),
        status: ramflux_node_core::RelayChunkStatus::Available,
    };
    let (stored, _inserted) =
        match ramflux_node_core::relay_store_put_candidate(store, state, candidate, now) {
            Ok(outcome) => outcome,
            Err(error) => {
                let status = error.status_code();
                return relay_client_quic_response(
                    status,
                    serde_json::json!({ "error": format!("relay put failed: {error}") }),
                );
            }
        };
    let put_response = ramflux_node_core::ObjectRelayPutResponse {
        chunk_id: stored.chunk_id.clone(),
        object_id: stored.object_id.clone(),
        manifest_hash: stored.manifest_hash.clone(),
        expires_at: stored.expires_at,
        status: stored.status,
    };
    match serde_json::to_value(put_response) {
        Ok(body) => relay_client_quic_response(200, body),
        Err(error) => relay_client_quic_response(
            500,
            serde_json::json!({ "error": format!("relay put serialization failed: {error}") }),
        ),
    }
}

/// Verified owner-session Tombstone data plane: after full v3 verification (owner proof required;
/// requester must be the owner device), records an object/manifest tombstone via the node-core
/// owner-session core. The tombstone the owner authorized is bound to the signed invocation
/// (`tombstone_hash` must equal `body_hash`), the object/manifest scope is taken from the verified
/// token, and the node-core core preserves the fail-closed empty-scope, cross-owner, replay
/// zero-mutation, and tombstone-wins semantics. All checks complete before any store write.
pub(crate) fn relay_client_quic_object_tombstone(
    request: &ramflux_transport::GatewayQuicRequest,
    trust_cache: &ramflux_node_core::RelayTrustSnapshotCache,
    store: &Arc<ramflux_node_core::RelayRedbStore>,
    state: &Arc<Mutex<ramflux_node_core::RelayCacheState>>,
    expected_node_id: &str,
    now: u64,
) -> ramflux_transport::GatewayQuicResponse {
    let envelope = match relay_client_quic_verify_invocation(
        request,
        trust_cache,
        expected_node_id,
        ramflux_node_core::ObjectRelayCapability::Tombstone,
        now,
    ) {
        Ok(envelope) => envelope,
        Err(response) => return response,
    };
    let payload: RelayClientQuicTombstonePayload =
        match serde_json::from_value(request.body.clone()) {
            Ok(payload) => payload,
            Err(error) => {
                return relay_client_quic_response(
                    401,
                    serde_json::json!({ "error": format!("malformed tombstone payload: {error}") }),
                );
            }
        };
    let token = &envelope.token;

    // Bind the tombstone to the signed invocation: its `tombstone_hash` is the `body_hash` the owner
    // proof and PoP sign, so a valid invocation cannot be reused to record a different tombstone.
    if envelope.body_hash != payload.tombstone_hash {
        return relay_client_quic_response(
            403,
            serde_json::json!({ "error": "relay tombstone not bound to the signed body hash" }),
        );
    }

    // Object and manifest scope come from the verified token, never the payload.
    let tombstone_request = ramflux_node_core::OwnerSessionTombstoneRequest {
        object_id: token.object_id.clone(),
        manifest_hash: Some(token.manifest_hash.clone()),
        tombstone_hash: payload.tombstone_hash,
        source_event_id: payload.source_event_id,
        signed_at: payload.signed_at,
        expires_at: payload.expires_at,
        owner_signing_key_id: token.owner_signing_key_id.clone(),
        owner_public_key: token.owner_public_key.clone(),
    };

    // Plan + reserve are atomic under one lock inside `relay_store_tombstone` (so no concurrent PUT
    // can slip an uncovered chunk past the tombstone); then persist-before-publish.
    let mutation = match ramflux_node_core::relay_store_tombstone(store, state, move |guard| {
        guard.plan_owner_session_tombstone(tombstone_request, now).map_err(Into::into)
    }) {
        Ok(mutation) => mutation,
        Err(error) => {
            let status = error.status_code();
            return relay_client_quic_response(
                status,
                serde_json::json!({ "error": format!("relay tombstone failed: {error}") }),
            );
        }
    };
    let tombstone_response = ramflux_node_core::ObjectRelayTombstoneResponse {
        object_id: mutation.tombstone.object_id.clone(),
        tombstone_hash: mutation.tombstone.tombstone_hash.clone(),
        expires_at: mutation.tombstone.expires_at,
    };
    match serde_json::to_value(tombstone_response) {
        Ok(body) => relay_client_quic_response(200, body),
        Err(error) => relay_client_quic_response(
            500,
            serde_json::json!({ "error": format!("relay tombstone serialization failed: {error}") }),
        ),
    }
}

/// Request router for the client-facing object surface. Serves the health probe, routes every verified
/// object operation (Get/Ack/Put/Tombstone) to the store-backed data plane, and returns `404` for
/// unknown routes.
pub(crate) fn relay_client_quic_route(
    request: &ramflux_transport::GatewayQuicRequest,
    trust_cache: &ramflux_node_core::RelayTrustSnapshotCache,
    store: &Arc<ramflux_node_core::RelayRedbStore>,
    state: &Arc<Mutex<ramflux_node_core::RelayCacheState>>,
    expected_node_id: &str,
    now: u64,
) -> ramflux_transport::GatewayQuicResponse {
    match (request.method.as_str(), request.path.as_str()) {
        ("GET", "/healthz") => relay_client_quic_response(
            200,
            serde_json::json!({ "service": "ramflux-relay", "status": "ok" }),
        ),
        ("POST", "/relay/v1/object/get_chunk") => {
            relay_client_quic_object_get(request, trust_cache, store, state, expected_node_id, now)
        }
        ("POST", "/relay/v1/object/ack") => {
            relay_client_quic_object_ack(request, trust_cache, store, state, expected_node_id, now)
        }
        ("POST", "/relay/v1/object/put_chunk") => {
            relay_client_quic_object_put(request, trust_cache, store, state, expected_node_id, now)
        }
        ("POST", "/relay/v1/object/tombstone") => relay_client_quic_object_tombstone(
            request,
            trust_cache,
            store,
            state,
            expected_node_id,
            now,
        ),
        _ => relay_client_quic_response(
            404,
            serde_json::json!({ "error": "unknown relay client endpoint" }),
        ),
    }
}
#[cfg(test)]
#[path = "tests/client_quic.rs"]
mod tests;
