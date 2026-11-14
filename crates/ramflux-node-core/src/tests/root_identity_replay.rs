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
fn retired_replay_snapshot_rows_are_refused() {
    for key in ["bob:envelope:envelope", "envelope/v2/source/id", "legacy/replay/aWQ"] {
        assert!(
            serde_json::from_value::<NodeReplayGuardState>(serde_json::json!({
                "accepted_by_key": {key: 1_760_003_600_i64}
            }))
            .is_err()
        );
    }
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
    let path = temp_store_path("gateway-replay-durable")?;
    let open = gateway_open_frame("bob", "restart-nonce");
    let auth = gateway_auth_frame(&open, "restart-request", 1_760_000_000)?;
    let registered = gateway_registered_key(&open)?;
    {
        let store = GatewayRedbStore::open(&path)?;
        store.configure_replay(
            crate::test_support::federation_fixtures::gateway_replay_fixture_config(),
            1_760_000_001,
        )?;
        store.write_guard()?.authenticate_gateway(&open, &auth, &registered, 1_760_000_001)?;
    }
    for now in [1_760_000_002, 1_760_000_003] {
        let store = GatewayRedbStore::open(&path)?;
        store.configure_replay(
            crate::test_support::federation_fixtures::gateway_replay_fixture_config(),
            now,
        )?;
        let mut state = store.load_state()?.ok_or("missing state")?;
        assert!(state.replay_guard_state_mut().is_empty(), "startup materialized replay evidence");
        assert!(matches!(
            store.write_guard()?.authenticate_gateway(&open, &auth, &registered, now),
            Err(NodeCoreError::ReplayGuard(_))
        ));
        store.save_state(&state)?;
    }
    Ok(())
}

#[test]
fn auth_does_not_rewrite_whole_gateway_state() -> Result<(), Box<dyn std::error::Error>> {
    let path = ramflux_test_support::TestPath::new()
        .expect("test: allocate fixture directory")
        .child(format!(
            "gateway-auth-cost-{}.redb",
            ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?)
        ));
    let store = GatewayRedbStore::open(&path)?;
    store.configure_replay(
        crate::test_support::federation_fixtures::gateway_replay_fixture_config(),
        1_760_000_000,
    )?;
    let mut state = GatewayState::new();
    store.save_state(&state)?;
    let snapshots = store.full_snapshot_commit_count();
    let commits = store.durable_commit_count();
    let now = 1_760_000_000;
    for index in 0..8 {
        let open = gateway_open_frame("bob", &format!("nonce-{index}"));
        let auth = gateway_auth_frame(&open, &format!("request-{index}"), now)?;
        let registered = gateway_registered_key(&open)?;
        store.write_guard()?.authenticate_gateway(&open, &auth, &registered, now + 1)?;
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
    Ok(())
}

#[test]
fn signed_request_capacity_is_root_scoped_and_survives_restore()
-> Result<(), Box<dyn std::error::Error>> {
    let path = temp_store_path("gateway-small-shares")?;
    let config = GatewayReplayConfig {
        root_budget: 2,
        per_root_share: 4,
        storage_budget_bytes: 128 * 1024 * 1024,
    };
    let now = 1_760_000_000;
    let (open, auth, registered, _) = rooted_auth(1, "bob", "initial", now)?;
    {
        let store = GatewayRedbStore::open(&path)?;
        store.configure_replay(config, now)?;
        for index in 0..4 {
            let (open, auth, registered, _) =
                rooted_auth(1, "bob", &format!("capacity-{index}"), now)?;
            store.write_guard()?.authenticate_gateway(&open, &auth, &registered, now)?;
        }
    }
    let store = GatewayRedbStore::open(&path)?;
    store.configure_replay(config, now + 1)?;
    assert!(matches!(
        store.write_guard()?.authenticate_gateway(&open, &auth, &registered, now + 1),
        Err(NodeCoreError::GatewayReplayCapacity)
    ));
    let (open, auth, registered, _) = rooted_auth(2, "bob", "other-root", now)?;
    store.write_guard()?.authenticate_gateway(&open, &auth, &registered, now + 1)?;
    drop(store);
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

type RootedAuth = (
    GatewayOpenFrame,
    GatewayAuthFrame,
    DeviceAuthKeyResponse,
    ramflux_crypto::RootQualifiedDeviceRef,
);

fn rooted_auth(
    seed: u8,
    device: &str,
    nonce: &str,
    now: i64,
) -> Result<RootedAuth, Box<dyn std::error::Error>> {
    let open = gateway_open_frame(device, nonce);
    let devices = ["bob", "device-1", "device-2", "device-3"].map(str::to_owned);
    let registered = crate::test_support::federation_fixtures::gateway_registered_key_for_devices(
        &open, [seed; 32], &devices,
    )?;
    let source = registered.authenticated_device_identity_for("register", u64::try_from(now)?)?;
    let mut auth = gateway_auth_frame(&open, nonce, now)?;
    auth.device_proof
        .ext
        .ext
        .insert("source_root_commitment".into(), source.root_commitment().into());
    auth.device_proof.signed.signature = ramflux_crypto::sign_protocol_object_with_seed(
        &auth.device_proof,
        ramflux_crypto::FIXTURE_SIGNING_KEY_BYTES,
    )?;
    auth.signed_request.device_proof_hash = ramflux_crypto::blake3_256_base64url(
        GATEWAY_DEVICE_PROOF_HASH_DOMAIN,
        &ramflux_protocol::canonical_json_bytes(&auth.device_proof)?,
    );
    auth.signed_request.signed.signature = ramflux_crypto::sign_protocol_object_with_seed(
        &auth.signed_request,
        ramflux_crypto::FIXTURE_SIGNING_KEY_BYTES,
    )?;
    Ok((open, auth, registered, source))
}

#[test]
pub(crate) fn gateway_root_admission_preserves_honest_auth_and_submit_after_saturation()
-> Result<(), Box<dyn std::error::Error>> {
    let path = temp_store_path("gateway-more-than64-roots")?;
    let config = GatewayReplayConfig {
        root_budget: 70,
        per_root_share: 4,
        storage_budget_bytes: 128 * 1024 * 1024,
    };
    let now = 1_760_000_000;
    let store = GatewayRedbStore::open(&path)?;
    store.configure_replay(config, now)?;
    let (open, auth, registered, honest) = rooted_auth(0, "bob", "honest-initial", now)?;
    store.write_guard()?.authenticate_gateway(&open, &auth, &registered, now)?;
    for root in 1..70 {
        for (slot, device) in ["bob", "device-1", "device-2", "device-3"].iter().enumerate() {
            let (open, auth, registered, _) =
                rooted_auth(u8::try_from(root)?, device, &format!("root-{root}-slot-{slot}"), now)?;
            store.write_guard()?.authenticate_gateway(&open, &auth, &registered, now)?;
        }
        let (open, auth, registered, _) =
            rooted_auth(u8::try_from(root)?, "bob", &format!("root-{root}-exhausted"), now)?;
        assert!(matches!(
            store.write_guard()?.authenticate_gateway(&open, &auth, &registered, now),
            Err(NodeCoreError::GatewayReplayCapacity)
        ));
    }
    let (open, auth, registered, _) = rooted_auth(71, "bob", "outsider", now)?;
    assert!(matches!(
        store.write_guard()?.authenticate_gateway(&open, &auth, &registered, now),
        Err(NodeCoreError::GatewayReplayCapacity)
    ));
    let (open, auth, registered, _) = rooted_auth(0, "bob", "honest-reauth", now)?;
    store.write_guard()?.authenticate_gateway(&open, &auth, &registered, now)?;
    let mut submit = auth.signed_request.clone();
    submit.request_id = "honest-submit".into();
    submit.nonce = "honest-submit".into();
    submit.path = "/gateway/session/submit".into();
    submit.signed.signature = ramflux_crypto::sign_protocol_object_with_seed(
        &submit,
        ramflux_crypto::FIXTURE_SIGNING_KEY_BYTES,
    )?;
    ramflux_crypto::verify_canonical_signature(
        &ramflux_protocol::signed_bytes(&submit)?,
        &submit.signed.signature,
        &registered.branch_public_key,
    )?;
    store.save_auth_replay(&honest, &submit, now)?;
    drop(store);
    let store = GatewayRedbStore::open(&path)?;
    store.configure_replay(config, now + 1)?;
    assert!(matches!(
        store.save_auth_replay(&honest, &submit, now + 1),
        Err(NodeCoreError::ReplayGuard(_))
    ));
    let (open, auth, registered, _) = rooted_auth(0, "bob", "honest-after-restart", now)?;
    store.write_guard()?.authenticate_gateway(&open, &auth, &registered, now + 1)?;
    drop(store);
    std::fs::remove_file(path)?;
    Ok(())
}
