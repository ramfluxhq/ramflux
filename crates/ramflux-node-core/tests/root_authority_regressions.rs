// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Publication replay, deletion interleaving, legacy fencing and root-scoped routing regressions.
#[path = "root_bound_identity/support.rs"]
mod support;
use ramflux_crypto::*;
use ramflux_node_core::*;
use ramflux_protocol::{DeviceSetStatus, PrincipalKind, encode_base64url};
use serde_json::json;
use support::*;
fn other() -> TestResultFixture {
    named("bob", "alice-device", 21)
}
fn named(principal: &str, device_id: &str, seed: u8) -> TestResultFixture {
    let root = create_identity_root(principal, [seed; 32]);
    let device = create_device_branch(principal, device_id, 1, [seed + 1; 32]);
    let x = X25519KeyPair::from_seed([seed + 3; 32]);
    let binding = authorize_device_branch_v2(
        &root,
        &device,
        BranchAuthorization {
            audience: IDENTITY_BIND_AUDIENCE,
            capability_scope: vec![IDENTITY_BIND_CAPABILITY.into()],
            issued_at: 1000,
            expires_at: 2000,
            principal_kind: PrincipalKind::HeadlessAi,
            agreement_identity_public_key: x.public,
        },
    )?;
    let keys = device_key_commitments(
        &encode_base64url(device.signing_key.verifying_key().to_bytes()),
        &encode_base64url(x.public),
    )?;
    let set = sign_device_set(
        &root,
        DeviceSetSigningInput {
            principal_kind: PrincipalKind::HeadlessAi,
            device_set_epoch: 1,
            devices: vec![ramflux_protocol::SignedDeviceSetEntry {
                device_id: device.device_id.clone(),
                device_epoch: 1,
                signing_key_commitment: keys.0,
                agreement_key_commitment: keys.1,
                status: DeviceSetStatus::Active,
                revoked_at: None,
            }],
        },
    )?;
    let request = IdentityRegisterRequest {
        device_set: Some(set),
        proof: binding,
        root_public_key: encode_base64url(root.signing_key.verifying_key().to_bytes()),
        principal_commitment: identity_root_commitment(&root.signing_key.verifying_key()),
        branch_public_key: encode_base64url(device.signing_key.verifying_key().to_bytes()),
        target_delivery_id: format!("{principal}-target"),
        gateway_id: "gateway".into(),
        session_id: "bob-session".into(),
        push_alias_hash: None,
        now: 1100,
        registration_pow: None,
        source_ip_hash: None,
    };
    Ok(Fixture { root, device, x, request })
}
type TestResultFixture = Result<Fixture, Box<dyn std::error::Error>>;
fn path() -> Result<std::path::PathBuf, CryptoError> {
    Ok(std::env::temp_dir()
        .join(format!("rf-authority-r2-{}.redb", encode_base64url(random_32()?))))
}
fn lookup(f: &Fixture) -> Result<String, serde_json::Error> {
    Ok(format!(
        "root~{}",
        encode_base64url(serde_json::to_vec(&(
            &f.request.principal_commitment,
            &f.device.device_id
        ))?)
    ))
}
#[test]
fn a_thousand_exact_replays_do_not_write_the_registry() -> TestResult {
    let f = Fixture::new()?;
    let path = path()?;
    let store = RouterRedbStore::open(&path)?;
    let router = RouterCore::new();
    router.register_identity_durable(&f.request, &store)?;
    let count = store.identity_registry_write_count();
    let record = f.request.device_set.as_ref().ok_or("record")?;
    for _ in 0..1000 {
        assert_eq!(router.publish_signed_device_set(&f.publish(record.clone()), &store)?, *record);
    }
    assert_eq!(store.identity_registry_write_count(), count);
    let mut forged = f.publish(record.clone());
    forged.root_public_key = encode_base64url(
        create_identity_root("attacker", [77; 32]).signing_key.verifying_key().to_bytes(),
    );
    assert!(router.publish_signed_device_set(&forged, &store).is_err());
    assert_eq!(store.identity_registry_write_count(), count);
    drop(router);
    drop(store);
    std::fs::remove_file(path)?;
    Ok(())
}
#[test]
fn another_root_cannot_reserve_or_revoke_a_local_device_name() -> TestResult {
    let alice = Fixture::new()?;
    let bob = other()?;
    let mut registry = IdentityRegistry::new();
    registry.register_identity(&alice.request)?;
    let mut poisoned = alice.request.device_set.as_ref().ok_or("record")?.devices.clone();
    let mut reservation = poisoned[0].clone();
    reservation.device_id = "future-device".into();
    reservation.status = DeviceSetStatus::Revoked;
    reservation.revoked_at = Some(1100);
    poisoned.push(reservation);
    let set = sign_device_set(
        &alice.root,
        DeviceSetSigningInput {
            principal_kind: PrincipalKind::HeadlessAi,
            device_set_epoch: 2,
            devices: poisoned,
        },
    )?;
    registry.publish_signed_device_set(&alice.publish(set))?;
    // Same raw name is owned independently by each root; publication is no global reservation.
    registry.register_identity(&bob.request)?;
    let future = named("carol", "future-device", 51)?;
    registry.register_identity(&future.request)?;
    assert!(!registry.device_auth_key(&lookup(&future)?).ok_or("future device")?.revoked);
    for f in [&alice, &bob] {
        registry.publish_prekey(PrekeyPublishRequest {
            device_id: f.device.device_id.clone(),
            bundle: f.bundle()?,
        })?;
    }
    assert_eq!(registry.device_auth_key(&lookup(&alice)?).ok_or("alice")?.principal_id, "alice");
    assert_eq!(registry.device_auth_key(&lookup(&bob)?).ok_or("bob")?.principal_id, "bob");
    assert!(
        registry.device_auth_key("alice-device").is_none(),
        "ambiguous legacy lookup must fail closed"
    );
    // A complete revocation must retain the existing future-device tombstone.
    let mut all = registry
        .signed_device_set(&alice.request.principal_commitment)
        .ok_or("set")?
        .devices
        .clone();
    for entry in &mut all {
        entry.status = DeviceSetStatus::Revoked;
        entry.revoked_at.get_or_insert(1200);
    }
    let revoked = sign_device_set(
        &alice.root,
        DeviceSetSigningInput {
            principal_kind: PrincipalKind::HeadlessAi,
            device_set_epoch: 3,
            devices: all,
        },
    )?;
    registry.publish_signed_device_set(&alice.publish(revoked))?;
    assert!(registry.device_auth_key(&lookup(&alice)?).ok_or("alice")?.revoked);
    assert!(!registry.device_auth_key(&lookup(&bob)?).ok_or("bob")?.revoked);
    assert!(registry.prekey_bundle(&lookup(&bob)?).is_some());
    Ok(())
}
#[test]
fn empty_commitment_legacy_device_is_fenced_from_own_device_copies() -> TestResult {
    let f = Fixture::new()?;
    let legacy = create_device_branch("alice", "legacy", 1, [31; 32]);
    let proof = authorize_device_branch(
        &f.root,
        &legacy,
        IDENTITY_BIND_AUDIENCE,
        vec![IDENTITY_BIND_CAPABILITY.into()],
        1000,
        2000,
    )?;
    let old = json!({"root_public_keys":{"alice":f.request.root_public_key},"root_public_keys_by_commitment":{f.request.principal_commitment.clone():f.request.root_public_key},"devices":{"legacy":{"principal_id":"alice","device_id":"legacy","device_epoch":1,"branch_public_key":encode_base64url(legacy.signing_key.verifying_key().to_bytes()),"target_delivery_id":"legacy-target","branch_proof":proof}},"revoked_devices":[],"seen_proofs":[],"prekey_bundles":{}});
    let mut registry: IdentityRegistry = serde_json::from_value(old)?;
    assert_eq!(registry.active_own_device_targets("alice", "alice-device").len(), 1);
    // Publishing a root set permanently fences omitted legacy IDs, including blank commitments.
    registry.publish_signed_device_set(&f.publish(f.record(1, DeviceSetStatus::Active)?))?;
    assert_eq!(
        registry.active_own_device_targets("alice", "alice-device"),
        Vec::<(String, String)>::new()
    );
    assert!(registry.device_auth_key("legacy").ok_or("legacy")?.revoked);
    Ok(())
}
#[test]
fn deletion_cleanup_cannot_persist_a_snapshot_older_than_a_concurrent_publication() -> TestResult {
    use std::sync::Arc;
    let a = Fixture::new()?;
    let b = other()?;
    let path = path()?;
    let store = Arc::new(RouterRedbStore::open(&path)?);
    let router = Arc::new(RouterCore::new());
    router.register_identity_durable(&a.request, &store)?;
    router.register_identity_durable(&b.request, &store)?;
    store.save_router(&router)?;
    router.mvp7_apply_lifecycle_event(&LifecycleEventRequest {
        principal_id: "alice".into(),
        event_id: "delete".into(),
        event_type: "identity.deleted".into(),
        actor_device_id: a.device.device_id.clone(),
        lifecycle_epoch: 1,
        now: 1200,
        reason_code: "user_requested".into(),
        timelock_seconds: Some(1),
        recovery_quorum: None,
        recovery_quorum_proof: None,
    })?;
    let deleted = router.mvp7_finalize_delete(&LifecycleFinalizeRequest {
        principal_id: "alice".into(),
        now: 1202,
    })?;
    let _stale = router.mvp1_identities_snapshot();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::scope(|scope| {
        let publication = scope.spawn(|| -> Result<(), String> {
            router
                .publish_signed_device_set(
                    &b.publish(b.record(2, DeviceSetStatus::Revoked).map_err(|e| e.to_string())?),
                    &store,
                )
                .map_err(|e| e.to_string())?;
            tx.send(()).map_err(|e| e.to_string())
        });
        rx.recv()?;
        router.persist_deleted_target(&store, "target", &deleted.record)?;
        publication.join().map_err(|_| "publication thread")??;
        Ok::<_, Box<dyn std::error::Error>>(())
    })?;
    drop(router);
    drop(store);
    let store = RouterRedbStore::open(&path)?;
    let restored = store.load_router()?.ok_or("router")?;
    assert_eq!(
        restored.signed_device_set(&b.request.principal_commitment).ok_or("set")?.device_set_epoch,
        2
    );
    assert!(restored.mvp1_device_auth_key(&lookup(&b)?).ok_or("device")?.revoked);
    drop(restored);
    drop(store);
    std::fs::remove_file(path)?;
    Ok(())
}
