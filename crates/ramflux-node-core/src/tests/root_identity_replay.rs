// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Copied literal names never share authenticated replay state across roots.
use super::*;

#[test]
fn copied_device_and_envelope_ids_have_independent_root_replay_buckets()
-> Result<(), Box<dyn std::error::Error>> {
    let bob = replay_source("bob")?;
    let root = ramflux_crypto::create_identity_root("mallory", [0xa1; 32]);
    let branch = ramflux_crypto::create_device_branch("mallory", "bob", 1, [0xa2; 32]);
    let mallory = ramflux_crypto::RootQualifiedDeviceRef::for_owned_device(&root, &branch)?;
    let mut message = envelope("next-bob-envelope", "target", DeliveryClass::OpaqueEvent);
    message.source_device_id = "bob".into();
    let now = message.created_at;
    let mut guard = NodeReplayGuardState::new();
    guard.check_envelope(&mallory, &message, now)?;
    guard.check_envelope(&bob, &message, now)?;
    assert_eq!(guard.len(), 2);
    assert!(guard.check_envelope(&mallory, &message, now).is_err());
    assert!(guard.check_envelope(&bob, &message, now).is_err());
    let mut restored: NodeReplayGuardState = serde_json::from_slice(&serde_json::to_vec(&guard)?)?;
    assert!(restored.check_envelope(&bob, &message, now).is_err());
    Ok(())
}

#[test]
fn request_replay_keys_bind_root_and_unambiguous_tuple_fields()
-> Result<(), Box<dyn std::error::Error>> {
    let open = gateway_open_frame("bob", "nonce");
    let auth = gateway_auth_frame(&open, "next-request", 1_760_000_000)?;
    let bob = replay_source("bob")?;
    let root = ramflux_crypto::create_identity_root("mallory", [0xa1; 32]);
    let branch = ramflux_crypto::create_device_branch("mallory", "bob", 1, [0xa2; 32]);
    let mallory = ramflux_crypto::RootQualifiedDeviceRef::for_owned_device(&root, &branch)?;
    let mut guard = NodeReplayGuardState::new();
    guard.check_signed_request(&mallory, &auth.signed_request, 1_760_000_001)?;
    guard.check_signed_request(&bob, &auth.signed_request, 1_760_000_001)?;
    assert!(guard.check_signed_request(&bob, &auth.signed_request, 1_760_000_001).is_err());
    let mut first = auth.signed_request.clone();
    first.nonce = "a:b".into();
    first.request_id = "c".into();
    let mut second = first.clone();
    second.nonce = "a".into();
    second.request_id = "b:c".into();
    assert_ne!(first.replay_tuple_key(&bob)?, second.replay_tuple_key(&bob)?);
    Ok(())
}

#[test]
fn legacy_unknown_root_replay_rows_cannot_preclaim_current_keys()
-> Result<(), Box<dyn std::error::Error>> {
    let mut message = envelope("next-bob-envelope", "target", DeliveryClass::OpaqueEvent);
    message.source_device_id = "bob".into();
    let mut guard: NodeReplayGuardState = serde_json::from_value(serde_json::json!({
        "accepted_by_key": {"bob:next-bob-envelope:next-bob-envelope": message.created_at + 3600}
    }))?;
    let bob = replay_source("bob")?;
    guard.check_envelope(&bob, &message, message.created_at)?;
    assert_eq!(guard.len(), 2);
    assert!(guard.accepted_entries().any(|(key, _)| key.starts_with("legacy/replay/")));
    Ok(())
}

#[test]
fn gateway_rejects_root_claim_and_committed_key_substitution_before_recording_replay()
-> Result<(), Box<dyn std::error::Error>> {
    let open = gateway_open_frame("bob", "nonce");
    let auth = gateway_auth_frame(&open, "next-request", 1_760_000_000)?;
    let mut registered = gateway_registered_key(&open)?;
    registered.branch_public_key = ramflux_crypto::public_key_base64url_from_seed([0xa2; 32]);
    assert!(registered.authenticated_device_identity().is_err());
    let mut registered = gateway_registered_key(&open)?;
    registered.signed_device_set.as_mut().ok_or("missing set")?.devices[0].device_epoch = 9;
    assert!(registered.authenticated_device_identity().is_err());
    let registered = gateway_registered_key(&open)?;
    let mut forged = auth.clone();
    forged
        .device_proof
        .ext
        .ext
        .insert("source_root_commitment".into(), serde_json::json!("other-root"));
    forged.device_proof.signed.signature =
        ramflux_crypto::sign_protocol_object(&forged.device_proof)?;
    forged.signed_request.device_proof_hash = ramflux_crypto::blake3_256_base64url(
        GATEWAY_DEVICE_PROOF_HASH_DOMAIN,
        &ramflux_protocol::canonical_json_bytes(&forged.device_proof)?,
    );
    forged.signed_request.signed.signature =
        ramflux_crypto::sign_protocol_object(&forged.signed_request)?;
    let mut guard = NodeReplayGuardState::new();
    assert!(
        validate_gateway_auth_with_replay(&open, &forged, 1_760_000_001, &mut guard, &registered)
            .is_err()
    );
    assert!(guard.is_empty());
    validate_gateway_auth_with_replay(&open, &auth, 1_760_000_001, &mut guard, &registered)?;
    Ok(())
}
