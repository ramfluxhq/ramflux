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

#[test]
fn replay_protection_survives_restart() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::temp_dir().join(format!(
        "gateway-replay-{}.redb",
        ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?)
    ));
    let open = gateway_open_frame("bob", "restart-nonce");
    let auth = gateway_auth_frame(&open, "restart-request", 1_760_000_000)?;
    let registered = gateway_registered_key(&open)?;
    let mut state = GatewayState::new();
    {
        let store = GatewayRedbStore::open(&path)?;
        store.save_state(&state)?;
        let source = validate_gateway_auth_with_replay(
            &open,
            &auth,
            1_760_000_001,
            state.replay_guard_state_mut(),
            &registered,
        )?;
        store.save_auth_replay(&source, &auth.signed_request, 1_760_000_001)?;
    }
    {
        let store = GatewayRedbStore::open(&path)?;
        let mut restored = store.load_state()?.ok_or("missing state")?;
        assert!(
            validate_gateway_auth_with_replay(
                &open,
                &auth,
                1_760_000_002,
                restored.replay_guard_state_mut(),
                &registered
            )
            .is_err()
        );
        // A subsequent whole checkpoint cannot overwrite the journal's replay evidence.
        store.save_state(&restored)?;
    }
    let store = GatewayRedbStore::open(&path)?;
    let mut restored = store.load_state()?.ok_or("missing checkpoint")?;
    assert!(
        validate_gateway_auth_with_replay(
            &open,
            &auth,
            1_760_000_003,
            restored.replay_guard_state_mut(),
            &registered
        )
        .is_err()
    );
    drop(store);
    std::fs::remove_file(path)?;
    Ok(())
}

#[test]
fn auth_does_not_rewrite_whole_gateway_state() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::temp_dir().join(format!(
        "gateway-auth-cost-{}.redb",
        ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?)
    ));
    let store = GatewayRedbStore::open(&path)?;
    let mut state = GatewayState::new();
    store.save_state(&state)?;
    let snapshots = store.full_snapshot_commit_count();
    let commits = store.durable_commit_count();
    let now = 1_760_000_000;
    for index in 0..8 {
        let open = gateway_open_frame("bob", &format!("nonce-{index}"));
        let auth = gateway_auth_frame(&open, &format!("request-{index}"), now)?;
        let registered = gateway_registered_key(&open)?;
        store.authenticate(&mut state, &open, &auth, now + 1, &registered)?;
        let resume = state.issue_resume_token(GatewayResumeIssueInput {
            session_id: &format!("session-{index}"),
            target_delivery_id: "target",
            device_id: "bob",
            device_epoch: 1,
            issued_at: u64::try_from(now)?,
            window_seconds: 300,
        });
        state.open_session(GatewaySession {
            session_id: format!("session-{index}"),
            target_delivery_id: "target".into(),
            device_id: "bob".into(),
            opened_at: u64::try_from(now)?,
            last_heartbeat_at: u64::try_from(now)?,
            lifecycle: GatewaySessionLifecycle::Live,
        });
        store.save_authenticated_session(
            &state,
            &format!("session-{index}"),
            &resume.metadata.resume_token_hash,
        )?;
    }
    assert_eq!(store.full_snapshot_commit_count(), snapshots);
    assert_eq!(store.durable_commit_count() - commits, 16);
    let restored = store.load_state()?.ok_or("missing overlay")?;
    assert!(restored.session("session-7").is_some());
    store.save_state(&state)?;
    assert_eq!(store.full_snapshot_commit_count(), snapshots + 1, "counter calibration");
    assert_eq!(
        state.prune_retained_sessions(
            u64::try_from(now)? + 301,
            300,
            &std::collections::BTreeSet::new()
        ),
        8
    );
    store.save_state(&state)?;
    drop(store);
    let store = GatewayRedbStore::open(&path)?;
    let restored = store.load_state()?.ok_or("missing pruned checkpoint")?;
    assert!(restored.session("session-7").is_none(), "pruned overlays must not resurrect sessions");
    drop(store);
    std::fs::remove_file(path)?;
    Ok(())
}

#[test]
fn signed_request_capacity_is_root_scoped_and_survives_restore()
-> Result<(), Box<dyn std::error::Error>> {
    let open = gateway_open_frame("bob", "capacity-nonce");
    let auth = gateway_auth_frame(&open, "capacity-request", 1_760_000_000)?;
    let bob = replay_source("bob")?;
    let mut guard = NodeReplayGuardState::new();
    for index in 0..crate::replay_guard::GATEWAY_REPLAY_SHARE {
        let mut request = auth.signed_request.clone();
        request.request_id = format!("capacity-{index}");
        guard.check_gateway_signed_request(&bob, &request, 1_760_000_001)?;
    }
    let mut guard: NodeReplayGuardState = serde_json::from_slice(&serde_json::to_vec(&guard)?)?;
    assert!(guard.check_gateway_signed_request(&bob, &auth.signed_request, 1_760_000_001).is_err());
    let root = ramflux_crypto::create_identity_root("mallory", [0xa1; 32]);
    let branch = ramflux_crypto::create_device_branch("mallory", "bob", 1, [0xa2; 32]);
    let mallory = ramflux_crypto::RootQualifiedDeviceRef::for_owned_device(&root, &branch)?;
    guard.check_gateway_signed_request(&mallory, &auth.signed_request, 1_760_000_001)?;
    Ok(())
}

#[test]
fn router_envelopes_ignore_gateway_replay_capacity() -> Result<(), Box<dyn std::error::Error>> {
    let bob = replay_source("bob")?;
    let mut message = envelope("router-beyond-gateway-cap", "target", DeliveryClass::OpaqueEvent);
    message.source_device_id = "bob".into();
    let mut guard = NodeReplayGuardState::new();
    // Exercise the exact r1 rejection boundary; these current request keys remain live.
    for index in 0..262_144_u64 {
        let mut digest = [0_u8; 32];
        digest.get_mut(..8).ok_or("digest prefix")?.copy_from_slice(&index.to_be_bytes());
        guard.restore_accepted(
            format!("request/v2/{}", ramflux_protocol::encode_base64url(digest)),
            message.created_at + 3600,
        );
    }
    let admitted = guard.accept_envelope_once(&bob, &message, message.created_at);
    assert!(
        matches!(admitted, Ok(true)),
        "gateway quota leaked into router envelope admission: {admitted:?}"
    );
    assert!(!guard.accept_envelope_once(&bob, &message, message.created_at)?);
    Ok(())
}

#[test]
fn gateway_root_admission_preserves_honest_auth_and_submit_after_saturation()
-> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::temp_dir().join(format!(
        "gateway-root-shares-{}.redb",
        ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?)
    ));
    let now = 1_760_000_000;
    let open = gateway_open_frame("bob", "honest-initial");
    let auth = gateway_auth_frame(&open, "honest-initial", now)?;
    let registered = gateway_registered_key(&open)?;
    let mut state = GatewayState::new();
    let store = GatewayRedbStore::open(&path)?;
    let honest = store.authenticate(&mut state, &open, &auth, now + 1, &registered)?;
    for index in 0..crate::replay_guard::GATEWAY_REPLAY_ROOTS - 1 {
        let seed = u8::try_from(index + 80)?;
        let root = ramflux_crypto::create_identity_root("admitted-attacker", [seed; 32]);
        let branch =
            ramflux_crypto::create_device_branch("admitted-attacker", "bob", 1, [seed; 32]);
        let source = ramflux_crypto::RootQualifiedDeviceRef::for_owned_device(&root, &branch)?;
        let mut request = auth.signed_request.clone();
        request.request_id = format!("attacker-{index}");
        state.replay_guard_state_mut().check_gateway_signed_request(&source, &request, now + 1)?;
        store.save_auth_replay(&source, &request, now + 1)?;
    }
    let outsider_root = ramflux_crypto::create_identity_root("unallocated", [241; 32]);
    let outsider_branch = ramflux_crypto::create_device_branch("unallocated", "bob", 1, [242; 32]);
    let outsider =
        ramflux_crypto::RootQualifiedDeviceRef::for_owned_device(&outsider_root, &outsider_branch)?;
    assert!(matches!(
        state.replay_guard_state_mut().check_gateway_signed_request(
            &outsider,
            &auth.signed_request,
            now + 1
        ),
        Err(NodeCoreError::GatewayReplayCapacity)
    ));
    let next_open = gateway_open_frame("bob", "honest-reauth");
    let next_auth = gateway_auth_frame(&next_open, "honest-reauth", now)?;
    store.authenticate(&mut state, &next_open, &next_auth, now + 1, &registered)?;
    let mut submit = auth.signed_request.clone();
    submit.request_id = "honest-submit".into();
    submit.path = "/gateway/session/own-device-fanout".into();
    state.replay_guard_state_mut().check_gateway_signed_request(&honest, &submit, now + 1)?;
    store.save_auth_replay(&honest, &submit, now + 1)?;
    drop(store);
    let store = GatewayRedbStore::open(&path)?;
    let mut restored = store.load_state()?.ok_or("root shares missing")?;
    let late = now + ramflux_protocol::MAX_ENVELOPE_TTL_SECONDS + 1;
    let mut fresh = submit.clone();
    fresh.created_at = late;
    fresh.expires_at = late + 60;
    fresh.request_id = "honest-after-expiry".into();
    assert!(matches!(
        restored.replay_guard_state_mut().check_gateway_signed_request(&outsider, &fresh, late),
        Err(NodeCoreError::GatewayReplayCapacity)
    ));
    restored.replay_guard_state_mut().check_gateway_signed_request(&honest, &fresh, late)?;
    store.save_auth_replay(&honest, &fresh, late)?;
    drop(store);
    let store = GatewayRedbStore::open(&path)?;
    let mut restored = store.load_state()?.ok_or("reserved roots lost on restart")?;
    assert!(matches!(
        restored.replay_guard_state_mut().check_gateway_signed_request(&outsider, &fresh, late),
        Err(NodeCoreError::GatewayReplayCapacity)
    ));
    fresh.request_id = "honest-after-second-restart".into();
    restored.replay_guard_state_mut().check_gateway_signed_request(&honest, &fresh, late)?;
    drop(store);
    std::fs::remove_file(path)?;
    Ok(())
}
