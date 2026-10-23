// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use crate::relay::{
    NodeCoreError, OBJECT_RELAY_CLOCK_SKEW_LEEWAY_SECONDS, OBJECT_RELAY_TOKEN_MAX_TTL_SECONDS,
    ObjectRelayCapability, OwnerAuthorizationProof, RelayAuthorizationKind, RelayInvocationV3,
    RequesterProofOfPossession, object_access_grant_binding_hash,
    object_access_grant_signing_bytes, owner_authorization_proof_binding_hash,
    requester_pop_signing_bytes, verify_object_access_grant, verify_owner_authorization_proof,
    verify_relay_invocation_v3, verify_relay_token_v3, verify_requester_pop,
};

use crate::relay::test_support::{
    V3_AUDIENCE_NODE, V3_BODY_HASH, V3_ISSUER_SEED, V3_OWNER_SEED, V3_REQUESTER_SEED,
    v3_grant_token, v3_owner_session_token, v3_pk, v3_resign_owner_proof, v3_resign_token, v3_sign,
    v3_signed_grant, v3_signed_owner_proof, v3_signed_pop,
};

use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

#[test]
fn v3_get_and_ack_invocation_accepts_valid() -> Result<(), String> {
    let now = 1_000_000;
    let issuer_pk = v3_pk(V3_ISSUER_SEED);
    for capability in [ObjectRelayCapability::Get, ObjectRelayCapability::Ack] {
        let grant =
            v3_signed_grant(now, vec![ObjectRelayCapability::Get, ObjectRelayCapability::Ack])?;
        let binding = object_access_grant_binding_hash(&grant).map_err(|e| e.to_string())?;
        let token = v3_grant_token(now, capability, binding)?;
        let pop = v3_signed_pop(&token, capability, V3_REQUESTER_SEED, now)?;
        let ctx = RelayInvocationV3 {
            token: &token,
            issuer_public_key: &issuer_pk,
            grant: Some(&grant),
            owner_proof: None,
            pop: &pop,
            expected_audience_node_id: V3_AUDIENCE_NODE,
            expected_body_hash: V3_BODY_HASH,
            capability,
            now,
        };
        verify_relay_invocation_v3(&ctx).map_err(|e| format!("{capability:?}: {e}"))?;
    }
    Ok(())
}

#[test]
fn v3_put_and_tombstone_invocation_accepts_valid() -> Result<(), String> {
    let now = 1_000_000;
    let issuer_pk = v3_pk(V3_ISSUER_SEED);
    for capability in [ObjectRelayCapability::Put, ObjectRelayCapability::Tombstone] {
        let proof = v3_signed_owner_proof(now, capability)?;
        let binding = owner_authorization_proof_binding_hash(&proof).map_err(|e| e.to_string())?;
        let token = v3_owner_session_token(now, capability, binding)?;
        let pop = v3_signed_pop(&token, capability, V3_OWNER_SEED, now)?;
        let ctx = RelayInvocationV3 {
            token: &token,
            issuer_public_key: &issuer_pk,
            grant: None,
            owner_proof: Some(&proof),
            pop: &pop,
            expected_audience_node_id: V3_AUDIENCE_NODE,
            expected_body_hash: V3_BODY_HASH,
            capability,
            now,
        };
        verify_relay_invocation_v3(&ctx).map_err(|e| format!("{capability:?}: {e}"))?;
    }
    Ok(())
}

#[test]
fn v3_rejects_v2_token_version() -> Result<(), String> {
    let now = 1_000_000;
    let issuer_pk = v3_pk(V3_ISSUER_SEED);
    let grant = v3_signed_grant(now, vec![ObjectRelayCapability::Get])?;
    let binding = object_access_grant_binding_hash(&grant).map_err(|e| e.to_string())?;
    let mut token = v3_grant_token(now, ObjectRelayCapability::Get, binding)?;
    token.token_version = 2;
    v3_resign_token(&mut token)?;
    assert!(matches!(
        verify_relay_token_v3(
            &token,
            &issuer_pk,
            ObjectRelayCapability::Get,
            V3_AUDIENCE_NODE,
            now
        ),
        Err(NodeCoreError::Unauthorized(_))
    ));
    Ok(())
}

#[test]
fn v3_rejects_canonical_tamper() -> Result<(), String> {
    let now = 1_000_000;
    let issuer_pk = v3_pk(V3_ISSUER_SEED);
    let grant = v3_signed_grant(now, vec![ObjectRelayCapability::Get])?;
    let binding = object_access_grant_binding_hash(&grant).map_err(|e| e.to_string())?;
    let token = v3_grant_token(now, ObjectRelayCapability::Get, binding)?;

    // Tamper token without re-signing -> issuer signature invalid.
    let mut tampered_token = token.clone();
    tampered_token.object_id = "object_forged".to_owned();
    assert!(
        verify_relay_token_v3(
            &tampered_token,
            &issuer_pk,
            ObjectRelayCapability::Get,
            V3_AUDIENCE_NODE,
            now
        )
        .is_err()
    );

    // Tamper grant without re-signing -> owner signature invalid.
    let mut tampered_grant = grant.clone();
    tampered_grant.grantee_device_hash = "forged_grantee".to_owned();
    assert!(verify_object_access_grant(&tampered_grant, ObjectRelayCapability::Get, now).is_err());

    // Tamper pop without re-signing -> requester signature invalid.
    let mut pop = v3_signed_pop(&token, ObjectRelayCapability::Get, V3_REQUESTER_SEED, now)?;
    pop.request_nonce = "forged_nonce".to_owned();
    assert!(verify_requester_pop(&pop, &token.requester_public_key, now).is_err());
    Ok(())
}

#[test]
fn v3_rejects_wrong_owner_or_grantee() -> Result<(), String> {
    let now = 1_000_000;
    let issuer_pk = v3_pk(V3_ISSUER_SEED);
    let grant = v3_signed_grant(now, vec![ObjectRelayCapability::Get])?;
    let binding = object_access_grant_binding_hash(&grant).map_err(|e| e.to_string())?;

    // Token owner differs from grant owner.
    let mut wrong_owner = v3_grant_token(now, ObjectRelayCapability::Get, binding.clone())?;
    wrong_owner.owner_public_key = v3_pk(V3_REQUESTER_SEED);
    v3_resign_token(&mut wrong_owner)?;
    let pop = v3_signed_pop(&wrong_owner, ObjectRelayCapability::Get, V3_REQUESTER_SEED, now)?;
    let ctx = RelayInvocationV3 {
        token: &wrong_owner,
        issuer_public_key: &issuer_pk,
        grant: Some(&grant),
        owner_proof: None,
        pop: &pop,
        expected_audience_node_id: V3_AUDIENCE_NODE,
        expected_body_hash: V3_BODY_HASH,
        capability: ObjectRelayCapability::Get,
        now,
    };
    assert!(matches!(verify_relay_invocation_v3(&ctx), Err(NodeCoreError::Unauthorized(_))));

    // Grant grantee differs from token requester.
    let mut wrong_grantee_grant = v3_signed_grant(now, vec![ObjectRelayCapability::Get])?;
    wrong_grantee_grant.grantee_device_hash = "other_grantee".to_owned();
    wrong_grantee_grant.owner_signature = v3_sign(
        &object_access_grant_signing_bytes(&wrong_grantee_grant).map_err(|e| e.to_string())?,
        V3_OWNER_SEED,
    );
    let binding2 =
        object_access_grant_binding_hash(&wrong_grantee_grant).map_err(|e| e.to_string())?;
    let token2 = v3_grant_token(now, ObjectRelayCapability::Get, binding2)?;
    let pop2 = v3_signed_pop(&token2, ObjectRelayCapability::Get, V3_REQUESTER_SEED, now)?;
    let ctx2 = RelayInvocationV3 {
        token: &token2,
        issuer_public_key: &issuer_pk,
        grant: Some(&wrong_grantee_grant),
        owner_proof: None,
        pop: &pop2,
        expected_audience_node_id: V3_AUDIENCE_NODE,
        expected_body_hash: V3_BODY_HASH,
        capability: ObjectRelayCapability::Get,
        now,
    };
    assert!(matches!(verify_relay_invocation_v3(&ctx2), Err(NodeCoreError::Unauthorized(_))));
    Ok(())
}

#[test]
fn v3_rejects_expired_future_ttl_and_over_max() -> Result<(), String> {
    let now = 1_000_000;
    let issuer_pk = v3_pk(V3_ISSUER_SEED);
    let grant = v3_signed_grant(now, vec![ObjectRelayCapability::Get])?;
    let binding = object_access_grant_binding_hash(&grant).map_err(|e| e.to_string())?;

    let mut expired = v3_grant_token(now, ObjectRelayCapability::Get, binding.clone())?;
    expired.issued_at = now - 600;
    expired.expires_at = now;
    v3_resign_token(&mut expired)?;
    assert!(matches!(
        verify_relay_token_v3(
            &expired,
            &issuer_pk,
            ObjectRelayCapability::Get,
            V3_AUDIENCE_NODE,
            now
        ),
        Err(NodeCoreError::TtlExpired { .. })
    ));

    let mut future = v3_grant_token(now, ObjectRelayCapability::Get, binding.clone())?;
    future.issued_at = now + OBJECT_RELAY_CLOCK_SKEW_LEEWAY_SECONDS + 1;
    future.expires_at = future.issued_at + 120;
    v3_resign_token(&mut future)?;
    assert!(matches!(
        verify_relay_token_v3(
            &future,
            &issuer_pk,
            ObjectRelayCapability::Get,
            V3_AUDIENCE_NODE,
            now
        ),
        Err(NodeCoreError::TtlExpired { .. })
    ));

    let mut over_max = v3_grant_token(now, ObjectRelayCapability::Get, binding)?;
    over_max.expires_at = over_max.issued_at + OBJECT_RELAY_TOKEN_MAX_TTL_SECONDS + 1;
    v3_resign_token(&mut over_max)?;
    assert!(matches!(
        verify_relay_token_v3(
            &over_max,
            &issuer_pk,
            ObjectRelayCapability::Get,
            V3_AUDIENCE_NODE,
            now
        ),
        Err(NodeCoreError::TtlExpired { .. })
    ));
    Ok(())
}

#[test]
fn v3_rejects_wrong_audience() -> Result<(), String> {
    let now = 1_000_000;
    let issuer_pk = v3_pk(V3_ISSUER_SEED);
    let grant = v3_signed_grant(now, vec![ObjectRelayCapability::Get])?;
    let binding = object_access_grant_binding_hash(&grant).map_err(|e| e.to_string())?;
    let token = v3_grant_token(now, ObjectRelayCapability::Get, binding)?;
    assert!(matches!(
        verify_relay_token_v3(&token, &issuer_pk, ObjectRelayCapability::Get, "node-z", now),
        Err(NodeCoreError::Unauthorized(_))
    ));
    Ok(())
}

#[test]
fn v3_rejects_proof_kind_mix() -> Result<(), String> {
    let now = 1_000_000;
    let issuer_pk = v3_pk(V3_ISSUER_SEED);
    let grant = v3_signed_grant(now, vec![ObjectRelayCapability::Get])?;
    let binding = object_access_grant_binding_hash(&grant).map_err(|e| e.to_string())?;
    let token = v3_grant_token(now, ObjectRelayCapability::Get, binding)?;
    let pop = v3_signed_pop(&token, ObjectRelayCapability::Get, V3_REQUESTER_SEED, now)?;
    let proof = v3_signed_owner_proof(now, ObjectRelayCapability::Put)?;

    // Get carrying an owner proof (extra proof) -> reject.
    let ctx_extra = RelayInvocationV3 {
        token: &token,
        issuer_public_key: &issuer_pk,
        grant: Some(&grant),
        owner_proof: Some(&proof),
        pop: &pop,
        expected_audience_node_id: V3_AUDIENCE_NODE,
        expected_body_hash: V3_BODY_HASH,
        capability: ObjectRelayCapability::Get,
        now,
    };
    assert!(matches!(verify_relay_invocation_v3(&ctx_extra), Err(NodeCoreError::Unauthorized(_))));

    // Get with no grant -> reject.
    let ctx_missing = RelayInvocationV3 {
        token: &token,
        issuer_public_key: &issuer_pk,
        grant: None,
        owner_proof: None,
        pop: &pop,
        expected_audience_node_id: V3_AUDIENCE_NODE,
        expected_body_hash: V3_BODY_HASH,
        capability: ObjectRelayCapability::Get,
        now,
    };
    assert!(matches!(
        verify_relay_invocation_v3(&ctx_missing),
        Err(NodeCoreError::Unauthorized(_))
    ));

    // Token with wrong authorization_kind for the capability -> reject at token verify.
    let mut wrong_kind = token.clone();
    wrong_kind.authorization_kind = RelayAuthorizationKind::OwnerSession;
    v3_resign_token(&mut wrong_kind)?;
    assert!(matches!(
        verify_relay_token_v3(
            &wrong_kind,
            &issuer_pk,
            ObjectRelayCapability::Get,
            V3_AUDIENCE_NODE,
            now
        ),
        Err(NodeCoreError::Unauthorized(_))
    ));

    // Put carrying a grant (wrong instrument) -> reject.
    let owner_token = v3_owner_session_token(
        now,
        ObjectRelayCapability::Put,
        owner_authorization_proof_binding_hash(&proof).map_err(|e| e.to_string())?,
    )?;
    let owner_pop = v3_signed_pop(&owner_token, ObjectRelayCapability::Put, V3_OWNER_SEED, now)?;
    let ctx_put_grant = RelayInvocationV3 {
        token: &owner_token,
        issuer_public_key: &issuer_pk,
        grant: Some(&grant),
        owner_proof: Some(&proof),
        pop: &owner_pop,
        expected_audience_node_id: V3_AUDIENCE_NODE,
        expected_body_hash: V3_BODY_HASH,
        capability: ObjectRelayCapability::Put,
        now,
    };
    assert!(matches!(
        verify_relay_invocation_v3(&ctx_put_grant),
        Err(NodeCoreError::Unauthorized(_))
    ));
    Ok(())
}

#[test]
fn v3_rejects_grant_with_put_or_tombstone_capability() -> Result<(), String> {
    let now = 1_000_000;
    // A grant carrying Put is invalid for any get/ack verification.
    let bad_grant =
        v3_signed_grant(now, vec![ObjectRelayCapability::Get, ObjectRelayCapability::Put])?;
    assert!(matches!(
        verify_object_access_grant(&bad_grant, ObjectRelayCapability::Get, now),
        Err(NodeCoreError::Unauthorized(_))
    ));
    // Asking a grant to authorize Tombstone is rejected.
    let grant = v3_signed_grant(now, vec![ObjectRelayCapability::Get, ObjectRelayCapability::Ack])?;
    assert!(matches!(
        verify_object_access_grant(&grant, ObjectRelayCapability::Tombstone, now),
        Err(NodeCoreError::Unauthorized(_))
    ));
    Ok(())
}

#[test]
fn v3_rejects_wrong_requester_key_nonce_body() -> Result<(), String> {
    let now = 1_000_000;
    let issuer_pk = v3_pk(V3_ISSUER_SEED);
    let grant = v3_signed_grant(now, vec![ObjectRelayCapability::Get])?;
    let binding = object_access_grant_binding_hash(&grant).map_err(|e| e.to_string())?;
    let token = v3_grant_token(now, ObjectRelayCapability::Get, binding)?;

    let base_ctx = |pop: &RequesterProofOfPossession, body: &str| -> bool {
        let ctx = RelayInvocationV3 {
            token: &token,
            issuer_public_key: &issuer_pk,
            grant: Some(&grant),
            owner_proof: None,
            pop,
            expected_audience_node_id: V3_AUDIENCE_NODE,
            expected_body_hash: body,
            capability: ObjectRelayCapability::Get,
            now,
        };
        matches!(verify_relay_invocation_v3(&ctx), Err(NodeCoreError::Unauthorized(_)))
    };

    // PoP signed with a key that is not the requester's -> signature fails.
    let wrong_key_pop = v3_signed_pop(&token, ObjectRelayCapability::Get, V3_ISSUER_SEED, now)?;
    assert!(base_ctx(&wrong_key_pop, V3_BODY_HASH));

    // Body hash mismatch.
    let good_pop = v3_signed_pop(&token, ObjectRelayCapability::Get, V3_REQUESTER_SEED, now)?;
    assert!(base_ctx(&good_pop, "different_body_hash"));

    // Tampered nonce after signing -> signature fails.
    let mut nonce_pop = good_pop.clone();
    nonce_pop.request_nonce = "tampered_nonce".to_owned();
    assert!(base_ctx(&nonce_pop, V3_BODY_HASH));

    // PoP bound to a different token id.
    let mut other_token_pop = good_pop.clone();
    other_token_pop.token_id = "other_token".to_owned();
    other_token_pop.signature = v3_sign(
        &requester_pop_signing_bytes(&other_token_pop).map_err(|e| e.to_string())?,
        V3_REQUESTER_SEED,
    );
    assert!(base_ctx(&other_token_pop, V3_BODY_HASH));
    Ok(())
}

#[test]
fn v3_rejects_authorization_binding_hash_mismatch() -> Result<(), String> {
    let now = 1_000_000;
    let issuer_pk = v3_pk(V3_ISSUER_SEED);
    let grant = v3_signed_grant(now, vec![ObjectRelayCapability::Get])?;
    // Token carries a bogus binding hash but is re-signed, so the issuer signature is valid and
    // only the grant-binding comparison fails.
    let token = v3_grant_token(now, ObjectRelayCapability::Get, "bogus_binding_hash".to_owned())?;
    let pop = v3_signed_pop(&token, ObjectRelayCapability::Get, V3_REQUESTER_SEED, now)?;
    let ctx = RelayInvocationV3 {
        token: &token,
        issuer_public_key: &issuer_pk,
        grant: Some(&grant),
        owner_proof: None,
        pop: &pop,
        expected_audience_node_id: V3_AUDIENCE_NODE,
        expected_body_hash: V3_BODY_HASH,
        capability: ObjectRelayCapability::Get,
        now,
    };
    assert!(matches!(verify_relay_invocation_v3(&ctx), Err(NodeCoreError::Unauthorized(_))));
    Ok(())
}

#[test]
fn v3_rejects_owner_proof_tampered_fields() -> Result<(), String> {
    let now = 1_000_000;
    let issuer_pk = v3_pk(V3_ISSUER_SEED);

    // Build a consistent Put invocation for a given (already-signed) owner proof and verify.
    let run = |proof: &OwnerAuthorizationProof| -> Result<Result<(), NodeCoreError>, String> {
        let binding = owner_authorization_proof_binding_hash(proof).map_err(|e| e.to_string())?;
        let token = v3_owner_session_token(now, ObjectRelayCapability::Put, binding)?;
        let pop = v3_signed_pop(&token, ObjectRelayCapability::Put, V3_OWNER_SEED, now)?;
        let ctx = RelayInvocationV3 {
            token: &token,
            issuer_public_key: &issuer_pk,
            grant: None,
            owner_proof: Some(proof),
            pop: &pop,
            expected_audience_node_id: V3_AUDIENCE_NODE,
            expected_body_hash: V3_BODY_HASH,
            capability: ObjectRelayCapability::Put,
            now,
        };
        Ok(verify_relay_invocation_v3(&ctx))
    };

    let valid = v3_signed_owner_proof(now, ObjectRelayCapability::Put)?;
    assert!(run(&valid)?.is_ok(), "baseline put owner proof must verify");

    // Re-signed semantic mismatches (signature + binding valid; a cross-check fails).
    let mut bad_body = valid.clone();
    bad_body.body_hash = "wrong_body".to_owned();
    assert!(matches!(run(&v3_resign_owner_proof(bad_body)?)?, Err(NodeCoreError::Unauthorized(_))));

    let mut bad_manifest = valid.clone();
    bad_manifest.manifest_hash = Some("wrong_manifest".to_owned());
    assert!(matches!(
        run(&v3_resign_owner_proof(bad_manifest)?)?,
        Err(NodeCoreError::Unauthorized(_))
    ));

    let mut none_chunk = valid.clone();
    none_chunk.chunk_id = None;
    assert!(matches!(
        run(&v3_resign_owner_proof(none_chunk)?)?,
        Err(NodeCoreError::Unauthorized(_))
    ));

    let mut wrong_chunk = valid.clone();
    wrong_chunk.chunk_id = Some("wrong_chunk".to_owned());
    assert!(matches!(
        run(&v3_resign_owner_proof(wrong_chunk)?)?,
        Err(NodeCoreError::Unauthorized(_))
    ));

    // Tamper the request_nonce without re-signing: the owner signature no longer verifies
    // (confirms request_nonce is part of the signed canonical bytes).
    let mut tampered_nonce = valid;
    tampered_nonce.request_nonce = "tampered_nonce".to_owned();
    assert!(run(&tampered_nonce)?.is_err());
    Ok(())
}

#[test]
fn v3_rejects_tombstone_delete_after_ack() -> Result<(), String> {
    let now = 1_000_000;
    let issuer_pk = v3_pk(V3_ISSUER_SEED);
    let proof = v3_signed_owner_proof(now, ObjectRelayCapability::Tombstone)?;
    let binding = owner_authorization_proof_binding_hash(&proof).map_err(|e| e.to_string())?;
    let mut token = v3_owner_session_token(now, ObjectRelayCapability::Tombstone, binding)?;
    token.delete_after_ack = true;
    v3_resign_token(&mut token)?;
    assert!(matches!(
        verify_relay_token_v3(
            &token,
            &issuer_pk,
            ObjectRelayCapability::Tombstone,
            V3_AUDIENCE_NODE,
            now
        ),
        Err(NodeCoreError::Unauthorized(_))
    ));
    Ok(())
}

#[test]
fn v3_rejects_wrong_proof_version() -> Result<(), String> {
    let now = 1_000_000;

    let mut grant = v3_signed_grant(now, vec![ObjectRelayCapability::Get])?;
    grant.version = 2;
    grant.owner_signature = v3_sign(
        &object_access_grant_signing_bytes(&grant).map_err(|e| e.to_string())?,
        V3_OWNER_SEED,
    );
    assert!(matches!(
        verify_object_access_grant(&grant, ObjectRelayCapability::Get, now),
        Err(NodeCoreError::ItestJson(_))
    ));

    let mut proof = v3_signed_owner_proof(now, ObjectRelayCapability::Put)?;
    proof.version = 2;
    let proof = v3_resign_owner_proof(proof)?;
    assert!(matches!(
        verify_owner_authorization_proof(&proof, ObjectRelayCapability::Put, now),
        Err(NodeCoreError::ItestJson(_))
    ));

    let grant2 = v3_signed_grant(now, vec![ObjectRelayCapability::Get])?;
    let binding = object_access_grant_binding_hash(&grant2).map_err(|e| e.to_string())?;
    let token = v3_grant_token(now, ObjectRelayCapability::Get, binding)?;
    let mut pop = v3_signed_pop(&token, ObjectRelayCapability::Get, V3_REQUESTER_SEED, now)?;
    pop.version = 2;
    pop.signature =
        v3_sign(&requester_pop_signing_bytes(&pop).map_err(|e| e.to_string())?, V3_REQUESTER_SEED);
    assert!(matches!(
        verify_requester_pop(&pop, &token.requester_public_key, now),
        Err(NodeCoreError::ItestJson(_))
    ));
    Ok(())
}

#[test]
fn v3_rejects_duplicate_capability_and_empty_fields() -> Result<(), String> {
    let now = 1_000_000;
    let issuer_pk = v3_pk(V3_ISSUER_SEED);

    // Duplicate capability in a grant.
    let dup_grant =
        v3_signed_grant(now, vec![ObjectRelayCapability::Get, ObjectRelayCapability::Get])?;
    assert!(matches!(
        verify_object_access_grant(&dup_grant, ObjectRelayCapability::Get, now),
        Err(NodeCoreError::Unauthorized(_))
    ));

    let grant = v3_signed_grant(now, vec![ObjectRelayCapability::Get])?;
    let binding = object_access_grant_binding_hash(&grant).map_err(|e| e.to_string())?;

    // Empty token nonce.
    let mut empty_nonce = v3_grant_token(now, ObjectRelayCapability::Get, binding.clone())?;
    empty_nonce.nonce = String::new();
    v3_resign_token(&mut empty_nonce)?;
    assert!(matches!(
        verify_relay_token_v3(
            &empty_nonce,
            &issuer_pk,
            ObjectRelayCapability::Get,
            V3_AUDIENCE_NODE,
            now
        ),
        Err(NodeCoreError::Unauthorized(_))
    ));

    // Empty owner public key on token.
    let mut empty_key = v3_grant_token(now, ObjectRelayCapability::Get, binding.clone())?;
    empty_key.owner_public_key = String::new();
    v3_resign_token(&mut empty_key)?;
    assert!(matches!(
        verify_relay_token_v3(
            &empty_key,
            &issuer_pk,
            ObjectRelayCapability::Get,
            V3_AUDIENCE_NODE,
            now
        ),
        Err(NodeCoreError::Unauthorized(_))
    ));

    // Empty PoP request nonce (re-signed so only the non-empty guard fires).
    let token = v3_grant_token(now, ObjectRelayCapability::Get, binding)?;
    let mut empty_pop_nonce =
        v3_signed_pop(&token, ObjectRelayCapability::Get, V3_REQUESTER_SEED, now)?;
    empty_pop_nonce.request_nonce = String::new();
    empty_pop_nonce.signature = v3_sign(
        &requester_pop_signing_bytes(&empty_pop_nonce).map_err(|e| e.to_string())?,
        V3_REQUESTER_SEED,
    );
    assert!(matches!(
        verify_requester_pop(&empty_pop_nonce, &token.requester_public_key, now),
        Err(NodeCoreError::Unauthorized(_))
    ));
    Ok(())
}
