// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use crate::client_quic::relay_client_quic_route;
use std::sync::{Arc, Mutex};

use crate::test_support::{
    V3_AUDIENCE_NODE, V3_CHUNK, V3_NOW, V3_OBJECT, V3_OWNER_ID, V3_OWNER_SEED, V3_REQUESTER_SEED,
    V3_TOMBSTONE_HASH, client_quic_object_request, client_quic_object_request_to,
    client_quic_request, v3_acked_by_count, v3_chunk_snapshot, v3_chunk_status, v3_envelope_body,
    v3_pinned_cache, v3_pk, v3_put_ciphertext, v3_put_request_body, v3_state_with, v3_stored_chunk,
    v3_temp_store, v3_tombstone_request_body, v3_trust_snapshot,
};

use ramflux_node_core::ObjectRelayCapability::{Ack, Get};

#[cfg(feature = "itest-http")]
#[test]
fn relay_client_quic_ack_fail_once_fails_exactly_once_when_enabled() {
    use std::sync::atomic::AtomicBool;
    // Disabled (env unset): the seam never fails, so normal itest ACKs are unaffected.
    let flag = AtomicBool::new(false);
    assert!(!super::relay_client_quic_ack_fail_once_with(&flag, false));
    assert!(!super::relay_client_quic_ack_fail_once_with(&flag, false));
    // Enabled: the first ACK fails and the once-token is consumed; every subsequent ACK on the
    // same relay process succeeds, so a retry recovers.
    let flag = AtomicBool::new(false);
    assert!(super::relay_client_quic_ack_fail_once_with(&flag, true));
    assert!(!super::relay_client_quic_ack_fail_once_with(&flag, true));
    assert!(!super::relay_client_quic_ack_fail_once_with(&flag, true));
}

#[test]
fn relay_client_quic_get_reads_stored_chunk() -> Result<(), String> {
    let store = v3_temp_store()?;
    let cache = v3_pinned_cache()?;
    let state = v3_state_with(&store, v3_stored_chunk(v3_pk(V3_OWNER_SEED), false))?;
    let response = relay_client_quic_route(
        &client_quic_object_request(v3_envelope_body(Get, |_| {})?),
        &cache,
        &store,
        &state,
        V3_AUDIENCE_NODE,
        V3_NOW,
    );
    assert_eq!(response.status, 200, "a fully verified get returns the stored chunk");
    let parsed: ramflux_node_core::ObjectRelayGetResponse =
        serde_json::from_value(response.body).map_err(|error| error.to_string())?;
    assert_eq!(parsed.chunk.chunk_id, V3_CHUNK);
    assert_eq!(parsed.chunk.encrypted_chunk, b"ciphertext-v3");
    Ok(())
}

#[test]
fn relay_client_quic_get_rejects_v2_missing_snapshot_and_wrong_owner() -> Result<(), String> {
    let store = v3_temp_store()?;
    let cache = v3_pinned_cache()?;
    let matching = v3_state_with(&store, v3_stored_chunk(v3_pk(V3_OWNER_SEED), false))?;

    // A v2/HMAC wire shape never parses as a v3 envelope: 401, and the store is never read.
    let v2 = client_quic_object_request(serde_json::json!({
        "token_version": 2, "token_id": "legacy", "mac": "deadbeef",
    }));
    assert_eq!(
        relay_client_quic_route(&v2, &cache, &store, &matching, V3_AUDIENCE_NODE, V3_NOW).status,
        401,
        "a v2 wire shape must never be admitted"
    );

    // Correctly-signed envelope, but the relay has NO pinned snapshot -> 403 (fail closed).
    let empty_cache = ramflux_node_core::RelayTrustSnapshotCache::new();
    assert_eq!(
        relay_client_quic_route(
            &client_quic_object_request(v3_envelope_body(Get, |_| {})?),
            &empty_cache,
            &store,
            &matching,
            V3_AUDIENCE_NODE,
            V3_NOW,
        )
        .status,
        403,
        "no pinned snapshot must fail closed"
    );

    // A body that smuggles a forged `snapshot` is ignored; with an empty cache it is still 403.
    let forged = serde_json::to_value(v3_trust_snapshot()).map_err(|error| error.to_string())?;
    let smuggled = v3_envelope_body(Get, |body| {
        body.insert("snapshot".to_owned(), forged);
    })?;
    assert_eq!(
        relay_client_quic_route(
            &client_quic_object_request(smuggled),
            &empty_cache,
            &store,
            &matching,
            V3_AUDIENCE_NODE,
            V3_NOW,
        )
        .status,
        403,
        "a body-supplied snapshot must never be trusted"
    );

    // Pinned cache + valid envelope, but the stored chunk was uploaded by a DIFFERENT original
    // owner -> 403. This is the RQ-03 original-owner binding.
    let foreign = v3_state_with(&store, v3_stored_chunk(v3_pk(V3_REQUESTER_SEED), false))?;
    assert_eq!(
        relay_client_quic_route(
            &client_quic_object_request(v3_envelope_body(Get, |_| {})?),
            &cache,
            &store,
            &foreign,
            V3_AUDIENCE_NODE,
            V3_NOW,
        )
        .status,
        403,
        "a chunk owned by a different original owner must not be readable"
    );

    // A tampered (unsigned) token is well-formed but fails crypto: 403.
    let tampered = v3_envelope_body(Get, |body| {
        if let Some(token) = body.get_mut("token").and_then(serde_json::Value::as_object_mut) {
            token.insert("object_id".to_owned(), serde_json::Value::String("forged".to_owned()));
        }
    })?;
    assert_eq!(
        relay_client_quic_route(
            &client_quic_object_request(tampered),
            &cache,
            &store,
            &matching,
            V3_AUDIENCE_NODE,
            V3_NOW,
        )
        .status,
        403,
        "a tampered token must fail verification"
    );
    Ok(())
}

#[test]
fn relay_client_quic_invalid_ack_leaves_store_untouched() -> Result<(), String> {
    let store = v3_temp_store()?;
    let cache = v3_pinned_cache()?;
    let state = v3_state_with(&store, v3_stored_chunk(v3_pk(V3_OWNER_SEED), true))?;
    // A tampered ack token fails verification BEFORE any store access, so nothing is mutated.
    let tampered = v3_envelope_body(Ack, |body| {
        if let Some(token) = body.get_mut("token").and_then(serde_json::Value::as_object_mut) {
            token.insert("nonce".to_owned(), serde_json::Value::String("forged".to_owned()));
        }
    })?;
    let response = relay_client_quic_route(
        &client_quic_object_request_to("/relay/v1/object/ack", tampered),
        &cache,
        &store,
        &state,
        V3_AUDIENCE_NODE,
        V3_NOW,
    );
    assert_eq!(response.status, 403, "a tampered ack must fail closed");
    assert_eq!(v3_acked_by_count(&state), 0, "a rejected ack must not mutate the chunk");
    let guard = state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let chunk = guard.chunk_entry(V3_CHUNK).ok_or("chunk missing")?;
    assert_eq!(
        chunk.status,
        ramflux_node_core::RelayChunkStatus::Available,
        "a rejected ack must not consume the chunk"
    );
    Ok(())
}

#[test]
fn relay_client_quic_ack_is_idempotent_and_respects_delete_policy() -> Result<(), String> {
    let cache = v3_pinned_cache()?;
    let ack_request = || -> Result<ramflux_transport::GatewayQuicRequest, String> {
        Ok(client_quic_object_request_to("/relay/v1/object/ack", v3_envelope_body(Ack, |_| {})?))
    };

    // (1) Non-delete chunk: two acks by the same grantee keep `acked_by_count` at 1 and leave the
    // chunk Available.
    let keep_store = v3_temp_store()?;
    let keep = v3_state_with(&keep_store, v3_stored_chunk(v3_pk(V3_OWNER_SEED), false))?;
    let first = relay_client_quic_route(
        &ack_request()?,
        &cache,
        &keep_store,
        &keep,
        V3_AUDIENCE_NODE,
        V3_NOW,
    );
    assert_eq!(first.status, 200);
    let first_body: ramflux_node_core::ObjectRelayAckResponse =
        serde_json::from_value(first.body).map_err(|error| error.to_string())?;
    assert_eq!(first_body.acked_by_count, 1);
    assert_eq!(first_body.status, ramflux_node_core::RelayChunkStatus::Available);
    let second = relay_client_quic_route(
        &ack_request()?,
        &cache,
        &keep_store,
        &keep,
        V3_AUDIENCE_NODE,
        V3_NOW,
    );
    let second_body: ramflux_node_core::ObjectRelayAckResponse =
        serde_json::from_value(second.body).map_err(|error| error.to_string())?;
    assert_eq!(second_body.acked_by_count, 1, "re-ack by the same grantee is idempotent");

    // (2) Delete-on-ack chunk: the first ack consumes it; a second ack does not resurrect it.
    let del_store = v3_temp_store()?;
    let consume = v3_state_with(&del_store, v3_stored_chunk(v3_pk(V3_OWNER_SEED), true))?;
    let consumed = relay_client_quic_route(
        &ack_request()?,
        &cache,
        &del_store,
        &consume,
        V3_AUDIENCE_NODE,
        V3_NOW,
    );
    let consumed_body: ramflux_node_core::ObjectRelayAckResponse =
        serde_json::from_value(consumed.body).map_err(|error| error.to_string())?;
    assert_eq!(consumed_body.status, ramflux_node_core::RelayChunkStatus::AckedDeleted);
    assert_eq!(consumed_body.acked_by_count, 1);
    let replayed = relay_client_quic_route(
        &ack_request()?,
        &cache,
        &del_store,
        &consume,
        V3_AUDIENCE_NODE,
        V3_NOW,
    );
    let replayed_body: ramflux_node_core::ObjectRelayAckResponse =
        serde_json::from_value(replayed.body).map_err(|error| error.to_string())?;
    assert_eq!(
        replayed_body.status,
        ramflux_node_core::RelayChunkStatus::AckedDeleted,
        "a consumed chunk is never resurrected"
    );
    assert_eq!(replayed_body.acked_by_count, 1);
    Ok(())
}

#[test]
fn relay_client_quic_object_routes_reject_mismatch_and_malformed() -> Result<(), String> {
    let store = v3_temp_store()?;
    let cache = v3_pinned_cache()?;
    let state = v3_state_with(&store, v3_stored_chunk(v3_pk(V3_OWNER_SEED), false))?;
    for path in ["/relay/v1/object/put_chunk", "/relay/v1/object/tombstone"] {
        // A Get-capability envelope on a put/tombstone route is a capability mismatch: 403.
        let mismatch = relay_client_quic_route(
            &client_quic_object_request_to(path, v3_envelope_body(Get, |_| {})?),
            &cache,
            &store,
            &state,
            V3_AUDIENCE_NODE,
            V3_NOW,
        );
        assert_eq!(mismatch.status, 403, "{path} must reject a mismatched capability");
        // A malformed body is rejected 401.
        let malformed = relay_client_quic_route(
            &client_quic_object_request_to(path, serde_json::Value::Null),
            &cache,
            &store,
            &state,
            V3_AUDIENCE_NODE,
            V3_NOW,
        );
        assert_eq!(malformed.status, 401, "{path} must reject a malformed body");
    }
    Ok(())
}

#[test]
fn relay_client_quic_put_persists_and_is_readable() -> Result<(), String> {
    let store = v3_temp_store()?;
    let cache = v3_pinned_cache()?;
    let state = Arc::new(Mutex::new(ramflux_node_core::RelayCacheState::new()));
    let response = relay_client_quic_route(
        &client_quic_object_request_to("/relay/v1/object/put_chunk", v3_put_request_body(|_| {})?),
        &cache,
        &store,
        &state,
        V3_AUDIENCE_NODE,
        V3_NOW,
    );
    assert_eq!(response.status, 200, "a valid owner-session put persists the chunk");
    let put_body: ramflux_node_core::ObjectRelayPutResponse =
        serde_json::from_value(response.body).map_err(|error| error.to_string())?;
    assert_eq!(put_body.chunk_id, V3_CHUNK);
    assert_eq!(put_body.status, ramflux_node_core::RelayChunkStatus::Available);

    // The stored chunk carries the owner's immutable binding and the exact ciphertext.
    let stored = v3_chunk_snapshot(&state).ok_or("chunk not stored")?;
    assert_eq!(stored.owner_signing_key_id, V3_OWNER_ID);
    assert_eq!(stored.owner_public_key, v3_pk(V3_OWNER_SEED));
    // The ciphertext is in redb (read through), not resident in the metadata index.
    let payload =
        store.relay_chunk_entry(V3_CHUNK).map_err(|error| error.to_string())?.ok_or("payload")?;
    assert_eq!(payload.encrypted_chunk, v3_put_ciphertext());

    // End-to-end: the owner-uploaded chunk is now readable by an authorized grantee via GET.
    let get = relay_client_quic_route(
        &client_quic_object_request(v3_envelope_body(Get, |_| {})?),
        &cache,
        &store,
        &state,
        V3_AUDIENCE_NODE,
        V3_NOW,
    );
    assert_eq!(get.status, 200, "the put chunk is readable by a valid get");
    Ok(())
}

#[test]
fn relay_client_quic_put_rejects_cross_owner_and_content_overwrite() -> Result<(), String> {
    let store = v3_temp_store()?;
    let cache = v3_pinned_cache()?;

    // (1) The chunk id is already owned by a DIFFERENT original owner -> 403, unchanged.
    let foreign = v3_state_with(&store, v3_stored_chunk(v3_pk(V3_REQUESTER_SEED), false))?;
    let cross = relay_client_quic_route(
        &client_quic_object_request_to("/relay/v1/object/put_chunk", v3_put_request_body(|_| {})?),
        &cache,
        &store,
        &foreign,
        V3_AUDIENCE_NODE,
        V3_NOW,
    );
    assert_eq!(cross.status, 403, "cross-owner overwrite must be rejected");
    let after = v3_chunk_snapshot(&foreign).ok_or("foreign chunk gone")?;
    assert_eq!(after.owner_public_key, v3_pk(V3_REQUESTER_SEED));
    let after_payload =
        store.relay_chunk_entry(V3_CHUNK).map_err(|error| error.to_string())?.ok_or("payload")?;
    assert_eq!(after_payload.encrypted_chunk, b"ciphertext-v3");

    // (2) Same owner, but the stored content differs from the request -> 403.
    let same_owner = v3_state_with(&store, v3_stored_chunk(v3_pk(V3_OWNER_SEED), false))?;
    let content = relay_client_quic_route(
        &client_quic_object_request_to("/relay/v1/object/put_chunk", v3_put_request_body(|_| {})?),
        &cache,
        &store,
        &same_owner,
        V3_AUDIENCE_NODE,
        V3_NOW,
    );
    assert_eq!(content.status, 403, "same-owner content overwrite must be rejected");
    Ok(())
}

#[test]
fn relay_client_quic_put_same_owner_same_content_replay_is_zero_mutation() -> Result<(), String> {
    let store = v3_temp_store()?;
    let cache = v3_pinned_cache()?;
    let state = Arc::new(Mutex::new(ramflux_node_core::RelayCacheState::new()));

    let first = relay_client_quic_route(
        &client_quic_object_request_to("/relay/v1/object/put_chunk", v3_put_request_body(|_| {})?),
        &cache,
        &store,
        &state,
        V3_AUDIENCE_NODE,
        V3_NOW,
    );
    assert_eq!(first.status, 200);
    let after_first = v3_chunk_snapshot(&state).ok_or("chunk not stored")?;

    // A byte-identical replay is idempotent and mutates nothing (same stored_at, expiry, status).
    let second = relay_client_quic_route(
        &client_quic_object_request_to("/relay/v1/object/put_chunk", v3_put_request_body(|_| {})?),
        &cache,
        &store,
        &state,
        V3_AUDIENCE_NODE,
        V3_NOW,
    );
    assert_eq!(second.status, 200, "an identical replay is idempotent");
    let after_second = v3_chunk_snapshot(&state).ok_or("chunk gone")?;
    assert_eq!(after_first, after_second, "an identical replay must be zero-mutation");
    Ok(())
}

#[test]
fn relay_client_quic_invalid_put_leaves_store_unchanged() -> Result<(), String> {
    let store = v3_temp_store()?;
    let cache = v3_pinned_cache()?;
    let state = Arc::new(Mutex::new(ramflux_node_core::RelayCacheState::new()));

    // A tampered owner-session token fails verification before any store access: 403, nothing
    // stored.
    let tampered = v3_put_request_body(|body| {
        if let Some(token) = body.get_mut("token").and_then(serde_json::Value::as_object_mut) {
            token.insert("nonce".to_owned(), serde_json::Value::String("forged".to_owned()));
        }
    })?;
    let response = relay_client_quic_route(
        &client_quic_object_request_to("/relay/v1/object/put_chunk", tampered),
        &cache,
        &store,
        &state,
        V3_AUDIENCE_NODE,
        V3_NOW,
    );
    assert_eq!(response.status, 403, "a tampered put must fail closed");
    assert!(v3_chunk_snapshot(&state).is_none(), "a rejected put must store nothing");

    // A payload whose cipher hash is not the canonical hash of the ciphertext is rejected before
    // any store write, so the ciphertext cannot be substituted under a valid invocation.
    let bad_hash = v3_put_request_body(|body| {
        body.insert(
            "chunk_cipher_hash".to_owned(),
            serde_json::Value::String("forged_hash".to_owned()),
        );
    })?;
    let bad = relay_client_quic_route(
        &client_quic_object_request_to("/relay/v1/object/put_chunk", bad_hash),
        &cache,
        &store,
        &state,
        V3_AUDIENCE_NODE,
        V3_NOW,
    );
    assert_eq!(bad.status, 403, "a payload not bound to its cipher hash must be rejected");
    assert!(v3_chunk_snapshot(&state).is_none(), "a rejected put must store nothing");
    Ok(())
}

#[test]
fn relay_client_quic_tombstone_applies_and_blocks_get() -> Result<(), String> {
    let store = v3_temp_store()?;
    let cache = v3_pinned_cache()?;
    let state = v3_state_with(&store, v3_stored_chunk(v3_pk(V3_OWNER_SEED), false))?;
    let response = relay_client_quic_route(
        &client_quic_object_request_to(
            "/relay/v1/object/tombstone",
            v3_tombstone_request_body(|_| {})?,
        ),
        &cache,
        &store,
        &state,
        V3_AUDIENCE_NODE,
        V3_NOW,
    );
    assert_eq!(response.status, 200, "a valid owner-session tombstone applies");
    let body: ramflux_node_core::ObjectRelayTombstoneResponse =
        serde_json::from_value(response.body).map_err(|error| error.to_string())?;
    assert_eq!(body.object_id, V3_OBJECT);
    assert_eq!(body.tombstone_hash, V3_TOMBSTONE_HASH);
    // The owned chunk is now tombstoned and no longer available to GET.
    assert_eq!(v3_chunk_status(&state), Some(ramflux_node_core::RelayChunkStatus::Tombstoned));
    let get = relay_client_quic_route(
        &client_quic_object_request(v3_envelope_body(Get, |_| {})?),
        &cache,
        &store,
        &state,
        V3_AUDIENCE_NODE,
        V3_NOW,
    );
    assert_eq!(get.status, 404, "a tombstoned chunk is no longer available");
    Ok(())
}

#[test]
fn relay_client_quic_tombstone_rejects_empty_and_cross_owner_scope() -> Result<(), String> {
    let store = v3_temp_store()?;
    let cache = v3_pinned_cache()?;

    // Empty scope: no owned chunk proves ownership -> 403, nothing recorded.
    let empty = Arc::new(Mutex::new(ramflux_node_core::RelayCacheState::new()));
    let empty_response = relay_client_quic_route(
        &client_quic_object_request_to(
            "/relay/v1/object/tombstone",
            v3_tombstone_request_body(|_| {})?,
        ),
        &cache,
        &store,
        &empty,
        V3_AUDIENCE_NODE,
        V3_NOW,
    );
    assert_eq!(empty_response.status, 403, "an empty-scope tombstone must fail closed");

    // Cross-owner: a chunk in scope owned by a different original owner -> 403, chunk untouched.
    let foreign = v3_state_with(&store, v3_stored_chunk(v3_pk(V3_REQUESTER_SEED), false))?;
    let cross = relay_client_quic_route(
        &client_quic_object_request_to(
            "/relay/v1/object/tombstone",
            v3_tombstone_request_body(|_| {})?,
        ),
        &cache,
        &store,
        &foreign,
        V3_AUDIENCE_NODE,
        V3_NOW,
    );
    assert_eq!(cross.status, 403, "a cross-owner tombstone must be rejected");
    assert_eq!(
        v3_chunk_status(&foreign),
        Some(ramflux_node_core::RelayChunkStatus::Available),
        "a rejected tombstone must not consume the chunk"
    );
    Ok(())
}

#[test]
fn relay_client_quic_invalid_tombstone_leaves_store_unchanged() -> Result<(), String> {
    let store = v3_temp_store()?;
    let cache = v3_pinned_cache()?;
    let state = v3_state_with(&store, v3_stored_chunk(v3_pk(V3_OWNER_SEED), false))?;
    // A tampered owner-session token fails verification before any store access: 403, unchanged.
    let tampered = v3_tombstone_request_body(|body| {
        if let Some(token) = body.get_mut("token").and_then(serde_json::Value::as_object_mut) {
            token.insert("nonce".to_owned(), serde_json::Value::String("forged".to_owned()));
        }
    })?;
    let response = relay_client_quic_route(
        &client_quic_object_request_to("/relay/v1/object/tombstone", tampered),
        &cache,
        &store,
        &state,
        V3_AUDIENCE_NODE,
        V3_NOW,
    );
    assert_eq!(response.status, 403, "a tampered tombstone must fail closed");
    assert_eq!(
        v3_chunk_status(&state),
        Some(ramflux_node_core::RelayChunkStatus::Available),
        "a rejected tombstone must not consume the chunk"
    );
    Ok(())
}

#[test]
fn relay_client_quic_route_serves_health_and_unknown() -> Result<(), String> {
    let store = v3_temp_store()?;
    let cache = v3_pinned_cache()?;
    let state = v3_state_with(&store, v3_stored_chunk(v3_pk(V3_OWNER_SEED), false))?;
    // Health probe is served.
    assert_eq!(
        relay_client_quic_route(
            &client_quic_request("GET", "/healthz"),
            &cache,
            &store,
            &state,
            V3_AUDIENCE_NODE,
            V3_NOW,
        )
        .status,
        200
    );
    // A bodyless object request is not a v3 envelope (401).
    for path in [
        "/relay/v1/object/put_chunk",
        "/relay/v1/object/get_chunk",
        "/relay/v1/object/ack",
        "/relay/v1/object/tombstone",
    ] {
        assert_eq!(
            relay_client_quic_route(
                &client_quic_request("POST", path),
                &cache,
                &store,
                &state,
                V3_AUDIENCE_NODE,
                V3_NOW,
            )
            .status,
            401,
            "object route {path} must fail closed on a non-v3 request"
        );
    }
    // Unknown route and wrong method are 404.
    assert_eq!(
        relay_client_quic_route(
            &client_quic_request("POST", "/nope"),
            &cache,
            &store,
            &state,
            V3_AUDIENCE_NODE,
            V3_NOW,
        )
        .status,
        404
    );
    assert_eq!(
        relay_client_quic_route(
            &client_quic_request("GET", "/relay/v1/object/get_chunk"),
            &cache,
            &store,
            &state,
            V3_AUDIENCE_NODE,
            V3_NOW,
        )
        .status,
        404,
        "wrong method must not match an object route"
    );
    Ok(())
}
