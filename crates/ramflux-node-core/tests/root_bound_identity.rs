// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Node enforcement of the root-proof, signed-set and prekey authority chain.
#[path = "root_bound_identity/support.rs"]
mod support;
use ramflux_crypto::*;
use ramflux_node_core::*;
use ramflux_protocol::{DeviceSetStatus, PrincipalKind, encode_base64url};
use support::*;

#[test]
fn one_time_prekeys_are_leased_once_and_exhaustion_is_counted_across_restart() -> TestResult {
    let f = Fixture::new()?;
    let signed = X25519KeyPair::from_seed([15; 32]);
    let one_time = vec![
        ("opk-1".to_owned(), X25519KeyPair::from_seed([21; 32]).public),
        ("opk-2".to_owned(), X25519KeyPair::from_seed([22; 32]).public),
    ];
    let bundle = create_rotating_prekey_bundle_with_lineage(
        &f.device,
        &f.device.signing_key,
        &f.x,
        &PrekeyBundleOptions {
            signed_prekey_id: "signed:rotating:1",
            signed_prekey: &signed,
            signed_prekey_created_at: 1_000,
            signed_prekey_expires_at: 605_800,
            one_time_prekeys: &one_time,
            prekey_bundle_counter: 1,
        },
    )?;
    let mut substituted = bundle.clone();
    substituted.one_time_prekey_id = Some("opk-1".to_owned());
    substituted.one_time_prekey = Some([99; 32]);
    assert!(verify_prekey_bundle(&f.device.signing_key.verifying_key(), &substituted).is_err());
    let identity = RootQualifiedDeviceRef::for_owned_device(&f.root, &f.device)?;
    let mut registry = IdentityRegistry::new();
    registry.register_identity(&f.request)?;
    registry.publish_prekey(PrekeyPublishRequest {
        device_id: f.device.device_id.clone(),
        bundle: bundle.clone(),
    })?;

    let first = registry.take_prekey_bundle(&identity, "source", 1_100)?.ok_or("first")?.0;
    let second = registry.take_prekey_bundle(&identity, "second-source", 1_101)?.ok_or("second")?.0;
    assert_ne!(first.one_time_prekey_id, second.one_time_prekey_id);
    assert_eq!(first.one_time_prekey_ids.len(), 0);
    assert_eq!(first.one_time_prekey_x25519_public.len(), 0);
    verify_prekey_bundle(&f.device.signing_key.verifying_key(), &first)?;
    let mut unleased = first.clone();
    unleased.one_time_prekey_id = Some("opk-2".to_owned());
    unleased.one_time_prekey = Some(one_time[1].1);
    assert!(
        verify_prekey_bundle(&f.device.signing_key.verifying_key(), &unleased).is_err(),
        "a fetcher must not be able to substitute a pooled but unleased OPK"
    );
    let exhausted =
        registry.take_prekey_bundle(&identity, "third-source", 1_102)?.ok_or("fallback")?;
    assert!(exhausted.1);
    assert!(exhausted.0.one_time_prekey_id.is_none());
    assert_eq!(registry.prekey_exhaustion_fallbacks(), 1);

    registry
        .publish_prekey(PrekeyPublishRequest { device_id: f.device.device_id.clone(), bundle })?;
    let mut restored: IdentityRegistry = serde_json::from_slice(&serde_json::to_vec(&registry)?)?;
    let replay = restored.take_prekey_bundle(&identity, "source", 1_103)?.ok_or("replay")?;
    assert!(replay.1, "idempotent publication replenished consumed OPKs");
    assert_eq!(restored.prekey_exhaustion_fallbacks(), 2);
    let _ = restored.take_prekey_bundle(&identity, "source", 1_104)?;
    let _ = restored.take_prekey_bundle(&identity, "source", 1_105)?;
    assert!(
        restored
            .take_prekey_bundle(&identity, "source", 1_103)?
            .ok_or("fallback")?
            .0
            .one_time_prekey_id
            .is_none()
    );
    Ok(())
}

#[test]
fn authenticated_prekey_leases_limit_each_pair_without_blocking_other_fetchers() -> TestResult {
    let target = Fixture::named("target", "target-device", 31)?;
    let first = Fixture::named("first", "first-device", 41)?;
    let second = Fixture::named("second", "second-device", 51)?;
    let router = RouterCore::new();
    for fixture in [&target, &first, &second] {
        router.mvp1_register_identity(&fixture.request)?;
    }
    let signed = X25519KeyPair::from_seed([61; 32]);
    let one_time = (0_u8..8)
        .map(|index| {
            (
                format!("opk-{index}"),
                X25519KeyPair::from_seed([index.saturating_add(70); 32]).public,
            )
        })
        .collect::<Vec<_>>();
    router.mvp1_publish_prekey(PrekeyPublishRequest {
        device_id: target.device.device_id.clone(),
        bundle: create_rotating_prekey_bundle_with_lineage(
            &target.device,
            &target.device.signing_key,
            &target.x,
            &PrekeyBundleOptions {
                signed_prekey_id: "target-signed",
                signed_prekey: &signed,
                signed_prekey_created_at: 1_000,
                signed_prekey_expires_at: 2_593_000,
                one_time_prekeys: &one_time,
                prekey_bundle_counter: 1,
            },
        )?,
    })?;
    let lookup = RootQualifiedDeviceRef::for_owned_device(&target.root, &target.device)?
        .storage_key()
        .to_owned();
    for manifest in [
        router.mvp1_device_manifest(&target.request.principal_commitment),
        router.mvp1_principal_manifest("target"),
    ] {
        let wire = serde_json::to_value(manifest.ok_or("public manifest")?)?;
        let bundle: &serde_json::Value = &wire["devices"][0]["prekey_bundle"];
        assert!(bundle["one_time_prekey_id"].is_null());
        assert!(bundle["one_time_prekey"].is_null());
        for field in
            ["one_time_prekey_ids", "one_time_prekey_x25519_public", "one_time_prekey_signatures"]
        {
            assert!(
                bundle.get(field).is_none_or(|value| value.as_array().is_some_and(Vec::is_empty))
            );
        }
    }
    let anonymous = router.mvp1_prekey_checked(&lookup)?;
    assert!(anonymous.bundle.as_ref().is_some_and(|bundle| {
        bundle.one_time_prekey_id.is_none() && bundle.one_time_prekey_ids.is_empty()
    }));
    assert_eq!(anonymous.available_one_time_prekeys, 8);

    let lease = |fixture: &Fixture| PrekeyLeaseRequest {
        device_id: lookup.clone(),
        fetcher_root_commitment: fixture.request.principal_commitment.clone(),
        fetcher_device_id: fixture.device.device_id.clone(),
        source_prefix: "203.0.113.0/24".into(),
    };
    let (response, _) = router.mvp1_prekey_lease(&lease(&first), 1_100)?;
    assert!(response.bundle.and_then(|bundle| bundle.one_time_prekey_id).is_some());
    for now in [1_101, 4_700, 87_499] {
        let (response, _) = router.mvp1_prekey_lease(&lease(&first), now)?;
        assert!(response.bundle.is_some_and(|bundle| bundle.one_time_prekey_id.is_none()));
    }
    let (response, _) = router.mvp1_prekey_lease(&lease(&first), 87_500)?;
    assert!(response.bundle.and_then(|bundle| bundle.one_time_prekey_id).is_some());
    let (other, _) = router.mvp1_prekey_lease(&lease(&second), 1_104)?;
    assert!(other.bundle.and_then(|bundle| bundle.one_time_prekey_id).is_some());

    let mut unknown = lease(&second);
    unknown.fetcher_root_commitment = "unknown-root".into();
    assert!(router.mvp1_prekey_lease(&unknown, 1_105).is_err());
    Ok(())
}

#[test]
fn one_time_prekey_lease_persists_as_a_per_device_delta() -> TestResult {
    let target = Fixture::named("target", "target-device", 71)?;
    let fetcher = Fixture::named("fetcher", "fetcher-device", 81)?;
    let path = std::env::temp_dir().join(format!(
        "ramflux-prekey-lease-{}.redb",
        ramflux_protocol::encode_base64url(random_32()?)
    ));
    let store = RouterRedbStore::open(&path)?;
    let router = RouterCore::new();
    router.register_identity_durable(&target.request, &store)?;
    router.register_identity_durable(&fetcher.request, &store)?;
    let one_time = (0_u8..4)
        .map(|index| {
            (
                format!("durable-opk-{index}"),
                X25519KeyPair::from_seed([index.saturating_add(90); 32]).public,
            )
        })
        .collect::<Vec<_>>();
    router.mvp1_publish_prekey(PrekeyPublishRequest {
        device_id: target.device.device_id.clone(),
        bundle: create_rotating_prekey_bundle_with_lineage(
            &target.device,
            &target.device.signing_key,
            &target.x,
            &PrekeyBundleOptions {
                signed_prekey_id: "durable-signed",
                signed_prekey: &X25519KeyPair::from_seed([89; 32]),
                signed_prekey_created_at: 1_000,
                signed_prekey_expires_at: 2_593_000,
                one_time_prekeys: &one_time,
                prekey_bundle_counter: 1,
            },
        )?,
    })?;
    router.persist_identity_registry(&store)?;
    let request = PrekeyLeaseRequest {
        device_id: RootQualifiedDeviceRef::for_owned_device(&target.root, &target.device)?
            .storage_key()
            .to_owned(),
        fetcher_root_commitment: fetcher.request.principal_commitment.clone(),
        fetcher_device_id: fetcher.device.device_id.clone(),
        source_prefix: "2001:db8:1:2::/64".into(),
    };
    let full_writes = store.identity_registry_write_count();
    let (first, state) = router.mvp1_prekey_lease(&request, 1_100)?;
    store.record_prekey_lease_state(&state)?;
    assert_eq!(store.identity_registry_write_count(), full_writes);
    let first_id = first.bundle.and_then(|bundle| bundle.one_time_prekey_id).ok_or("first")?;
    drop((router, store));

    let reopened = RouterRedbStore::open(&path)?;
    let restored = reopened.load_router()?.ok_or("router")?;
    let (second, _) = restored.mvp1_prekey_lease(&request, 1_101)?;
    let second_id = second.bundle.and_then(|bundle| bundle.one_time_prekey_id).ok_or("second")?;
    assert_ne!(first_id, second_id);
    assert_eq!(second.available_one_time_prekeys, 2);
    drop(reopened);
    std::fs::remove_file(path)?;
    Ok(())
}
#[test]
fn substitution_diagnostic_is_rejected_without_poisoning_the_real_registration() -> TestResult {
    let mut f = Fixture::new()?;
    let now = i64::try_from(
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs(),
    )?;
    f.request.now = now;
    f.request.proof = authorize_device_branch_v2(
        &f.root,
        &f.device,
        BranchAuthorization {
            audience: IDENTITY_BIND_AUDIENCE,
            capability_scope: vec![IDENTITY_BIND_CAPABILITY.into()],
            issued_at: now - 1,
            expires_at: now + 3600,
            principal_kind: PrincipalKind::HeadlessAi,
            agreement_identity_public_key: f.x.public,
        },
    )?;
    let mut registry = IdentityRegistry::new();
    let mut attack = f.request.clone();
    let replacement = create_device_branch("alice", "alice-device", 1, [13; 32]);
    attack.branch_public_key = encode_base64url(replacement.signing_key.verifying_key().to_bytes());
    let malicious = create_prekey_bundle(
        &replacement,
        &X25519KeyPair::from_seed([16; 32]),
        "signed:1",
        &X25519KeyPair::from_seed([15; 32]),
        None,
        None,
    )?;
    verify_prekey_bundle(&replacement.signing_key.verifying_key(), &malicious)?;
    assert!(registry.register_identity(&attack).is_err());
    assert_only_admission_charged(&registry, f.request.now)?;
    registry.register_identity(&f.request)?;
    assert!(
        registry
            .publish_prekey(PrekeyPublishRequest {
                device_id: f.device.device_id.clone(),
                bundle: malicious
            })
            .is_err()
    );
    let changed_x = create_prekey_bundle(
        &f.device,
        &X25519KeyPair::from_seed([17; 32]),
        "signed:2",
        &X25519KeyPair::from_seed([18; 32]),
        None,
        None,
    )?;
    verify_prekey_bundle(&f.device.signing_key.verifying_key(), &changed_x)?;
    assert!(
        registry
            .publish_prekey(PrekeyPublishRequest {
                device_id: f.device.device_id.clone(),
                bundle: changed_x
            })
            .is_err()
    );
    let bundle = f.bundle()?;
    registry.publish_prekey(PrekeyPublishRequest {
        device_id: f.device.device_id.clone(),
        bundle: bundle.clone(),
    })?;
    let manifest = registry.device_manifest(&f.request.principal_commitment).ok_or("manifest")?;
    assert_eq!(manifest.devices[0].prekey_bundle, bundle);
    assert_eq!(manifest.devices[0].branch_proof, f.request.proof);
    Ok(())
}
#[test]
fn signed_revocations_remain_visible_even_with_no_active_devices() -> TestResult {
    let f = Fixture::new()?;
    let mut registry = IdentityRegistry::new();
    registry.register_identity(&f.request)?;
    registry.publish_prekey(PrekeyPublishRequest {
        device_id: f.device.device_id.clone(),
        bundle: f.bundle()?,
    })?;
    let revoked = f.record(2, DeviceSetStatus::Revoked)?;
    registry.publish_signed_device_set(&f.publish(revoked.clone()))?;
    let snapshot = registry.clone();
    assert!(
        registry
            .publish_signed_device_set(&f.publish(f.record(1, DeviceSetStatus::Active)?))
            .is_err()
    );
    assert!(
        registry
            .publish_signed_device_set(&f.publish(f.record(3, DeviceSetStatus::Active)?))
            .is_err()
    );
    let mut unsigned = revoked.clone();
    unsigned.signature = String::new();
    assert!(registry.publish_signed_device_set(&f.publish(unsigned)).is_err());
    assert_eq!(registry, snapshot);
    registry.publish_signed_device_set(&f.publish(revoked.clone()))?;
    let manifest = registry.device_manifest(&f.request.principal_commitment).ok_or("manifest")?;
    assert_eq!(manifest.devices, []);
    assert_eq!(manifest.signed_device_set, Some(revoked));
    assert!(
        registry
            .prekey_bundle(&RootQualifiedDeviceRef::for_owned_device(&f.root, &f.device)?)
            .is_none()
    );
    assert!(
        registry
            .device_auth_key(&RootQualifiedDeviceRef::for_owned_device(&f.root, &f.device)?)
            .ok_or("device")?
            .revoked
    );
    assert!(registry.register_identity(&f.request).is_err());
    Ok(())
}
#[test]
fn root_cannot_change_an_established_principal_kind_or_alias_another_root() -> TestResult {
    let f = Fixture::new()?;
    let mut registry = IdentityRegistry::new();
    registry.register_identity(&f.request)?;
    let previous = registry.clone();
    let mut record = f.record(2, DeviceSetStatus::Active)?;
    record = sign_device_set(
        &f.root,
        DeviceSetSigningInput {
            principal_kind: PrincipalKind::Human,
            device_set_epoch: 2,
            devices: record.devices,
        },
    )?;
    verify_signed_device_set(&f.root.signing_key.verifying_key(), &record)?;
    assert!(registry.publish_signed_device_set(&f.publish(record)).is_err());
    let other = create_identity_root("alice", [19; 32]);
    let record = sign_device_set(
        &other,
        DeviceSetSigningInput {
            principal_kind: PrincipalKind::HeadlessAi,
            device_set_epoch: 2,
            devices: f.record(1, DeviceSetStatus::Active)?.devices,
        },
    )?;
    assert!(
        registry
            .publish_signed_device_set(&DeviceSetPublishRequest {
                root_public_key: encode_base64url(other.signing_key.verifying_key().to_bytes()),
                record
            })
            .is_err()
    );
    assert_eq!(registry, previous);
    Ok(())
}
#[test]
fn legacy_registry_load_is_readable_but_key_writes_require_root_bound_migration() -> TestResult {
    let f = Fixture::new()?;
    let proof = authorize_device_branch(
        &f.root,
        &f.device,
        IDENTITY_BIND_AUDIENCE,
        vec![IDENTITY_BIND_CAPABILITY.into()],
        1000,
        2000,
    )?;
    let legacy_bundle = create_prekey_bundle(
        &f.device,
        &f.x,
        "signed:1",
        &X25519KeyPair::from_seed([15; 32]),
        Some("legacy-opk".into()),
        Some(X25519KeyPair::from_seed([17; 32]).public),
    )?;
    let value = serde_json::json!({"root_public_keys":{"alice":f.request.root_public_key},"root_public_keys_by_commitment":{f.request.principal_commitment.clone():f.request.root_public_key},"devices":{"alice-device":{"principal_id":"alice","principal_commitment":f.request.principal_commitment,"device_id":"alice-device","device_epoch":1,"branch_public_key":f.request.branch_public_key,"target_delivery_id":"target","branch_proof":proof}},"revoked_devices":[],"seen_proofs":[],"prekey_bundles":{"alice-device":legacy_bundle}});
    let mut legacy: IdentityRegistry = serde_json::from_value(value)?;
    let manifest =
        legacy.device_manifest(&f.request.principal_commitment).ok_or("legacy manifest")?;
    assert!(manifest.devices[0].prekey_bundle.one_time_prekey_id.is_none());
    assert!(manifest.devices[0].prekey_bundle.one_time_prekey.is_none());
    assert_eq!(manifest.devices[0].prekey_bundle.one_time_prekey_ids, Vec::<String>::new());
    verify_prekey_bundle(
        &f.device.signing_key.verifying_key(),
        &manifest.devices[0].prekey_bundle,
    )?;
    assert!(manifest.signed_device_set.is_none());
    assert!(manifest.devices[0].branch_proof.key_binding.is_none());
    let mut old_request = f.request.clone();
    old_request.proof = proof;
    old_request.device_set = None;
    let before = legacy.clone();
    assert!(legacy.register_identity(&old_request).is_err());
    assert!(
        legacy
            .publish_prekey(PrekeyPublishRequest {
                device_id: f.device.device_id.clone(),
                bundle: f.bundle()?
            })
            .is_err()
    );
    assert_authority_unchanged_after_admission(&legacy, &before, f.request.now)?;
    legacy.register_identity(&f.request)?;
    legacy.publish_prekey(PrekeyPublishRequest {
        device_id: f.device.device_id.clone(),
        bundle: f.bundle()?,
    })?;
    assert!(
        legacy
            .device_manifest(&f.request.principal_commitment)
            .ok_or("upgraded manifest")?
            .signed_device_set
            .is_some()
    );
    assert!(legacy.register_identity(&old_request).is_err());
    Ok(())
}
#[test]
fn highest_signed_epoch_and_revocation_survive_durable_restart() -> TestResult {
    let f = Fixture::new()?;
    let path = std::env::temp_dir().join(format!(
        "rf-id01-{}-{}.redb",
        std::process::id(),
        encode_base64url(random_32()?)
    ));
    let store = RouterRedbStore::open(&path)?;
    let router = RouterCore::new();
    router.register_identity_durable(&f.request, &store)?;
    store.save_router(&router)?;
    let revoked = f.record(2, DeviceSetStatus::Revoked)?;
    router.publish_signed_device_set(&f.publish(revoked.clone()), &store)?;
    assert!(
        router
            .publish_signed_device_set(&f.publish(f.record(1, DeviceSetStatus::Active)?), &store)
            .is_err()
    );
    drop(router);
    drop(store);
    let store = RouterRedbStore::open(&path)?;
    let restored = store.load_router()?.ok_or("restored router")?;
    assert_eq!(restored.signed_device_set(&f.request.principal_commitment), Some(revoked));
    assert!(restored.mvp1_device_auth_key_checked(&qualified(&f)?)?.ok_or("device")?.revoked);
    assert!(
        restored
            .publish_signed_device_set(&f.publish(f.record(1, DeviceSetStatus::Active)?), &store)
            .is_err()
    );
    drop(restored);
    drop(store);
    std::fs::remove_file(path)?;
    Ok(())
}

#[test]
fn root_authorized_rotation_disables_old_keys_until_the_new_bound_registration() -> TestResult {
    let f = Fixture::new()?;
    let mut registry = IdentityRegistry::new();
    registry.register_identity(&f.request)?;
    registry.publish_prekey(PrekeyPublishRequest {
        device_id: f.device.device_id.clone(),
        bundle: f.bundle()?,
    })?;
    let next_device = create_device_branch("alice", "alice-device", 2, [31; 32]);
    let next_x = X25519KeyPair::from_seed([32; 32]);
    let keys = device_key_commitments(
        &encode_base64url(next_device.signing_key.verifying_key().to_bytes()),
        &encode_base64url(next_x.public),
    )?;
    let mut record = f.record(2, DeviceSetStatus::Active)?;
    record.devices[0].device_epoch = 2;
    record.devices[0].signing_key_commitment = keys.0;
    record.devices[0].agreement_key_commitment = keys.1;
    record = sign_device_set(
        &f.root,
        DeviceSetSigningInput {
            principal_kind: PrincipalKind::HeadlessAi,
            device_set_epoch: 2,
            devices: record.devices,
        },
    )?;
    registry.publish_signed_device_set(&f.publish(record))?;
    assert!(
        registry
            .device_auth_key(&RootQualifiedDeviceRef::for_owned_device(&f.root, &f.device)?)
            .is_none()
    );
    assert!(
        registry
            .prekey_bundle(&RootQualifiedDeviceRef::for_owned_device(&f.root, &f.device)?)
            .is_none()
    );
    assert!(registry.register_identity(&f.request).is_err());
    let mut request = f.request.clone();
    request.device_set = None;
    request.branch_public_key =
        encode_base64url(next_device.signing_key.verifying_key().to_bytes());
    request.proof = authorize_device_branch_v2(
        &f.root,
        &next_device,
        BranchAuthorization {
            audience: IDENTITY_BIND_AUDIENCE,
            capability_scope: vec![IDENTITY_BIND_CAPABILITY.into()],
            issued_at: 1100,
            expires_at: 2000,
            principal_kind: PrincipalKind::HeadlessAi,
            agreement_identity_public_key: next_x.public,
        },
    )?;
    registry.register_identity(&request)?;
    registry.publish_prekey(PrekeyPublishRequest {
        device_id: next_device.device_id.clone(),
        bundle: create_prekey_bundle(
            &next_device,
            &next_x,
            "signed:new",
            &X25519KeyPair::from_seed([33; 32]),
            None,
            None,
        )?,
    })?;
    assert_eq!(
        registry
            .device_auth_key(&RootQualifiedDeviceRef::for_owned_device(&f.root, &f.device)?)
            .ok_or("rotated device")?
            .branch_public_key,
        request.branch_public_key
    );
    Ok(())
}

#[test]
fn concurrent_publication_and_snapshot_persistence_never_restore_a_lower_epoch() -> TestResult {
    use std::sync::Arc;
    let f = Fixture::new()?;
    let path = std::env::temp_dir().join(format!(
        "rf-id01-race-{}-{}.redb",
        std::process::id(),
        encode_base64url(random_32()?)
    ));
    let store = Arc::new(RouterRedbStore::open(&path)?);
    let router = Arc::new(RouterCore::new());
    router.register_identity_durable(&f.request, &store)?;
    store.save_router(&router)?;
    let mut threads = Vec::new();
    for epoch in [2, 3, 4] {
        let request = f.publish(f.record(epoch, DeviceSetStatus::Active)?);
        let router = Arc::clone(&router);
        let store = Arc::clone(&store);
        threads.push(std::thread::spawn(move || -> Result<(), String> {
            // A lower epoch may lose the race; it must never replace a higher committed record.
            let _ = router.publish_signed_device_set(&request, &store);
            router.persist_identity_registry(&store).map_err(|e| e.to_string())
        }));
    }
    for thread in threads {
        thread.join().map_err(|_| "publication thread failed")??;
    }
    assert_eq!(
        router.signed_device_set(&f.request.principal_commitment).ok_or("record")?.device_set_epoch,
        4
    );
    drop(router);
    drop(store);
    let store = RouterRedbStore::open(&path)?;
    let restored = store.load_router()?.ok_or("restored router")?;
    assert_eq!(
        restored
            .signed_device_set(&f.request.principal_commitment)
            .ok_or("record")?
            .device_set_epoch,
        4
    );
    drop(restored);
    drop(store);
    std::fs::remove_file(path)?;
    Ok(())
}

#[test]
fn deleting_an_identity_does_not_allow_its_root_to_reclassify_or_reenroll() -> TestResult {
    let f = Fixture::new()?;
    let router = RouterCore::new();
    router.mvp1_register_identity(&f.request)?;
    router.mvp7_apply_lifecycle_event(&LifecycleEventRequest {
        principal_id: "alice".into(),
        event_id: "delete".into(),
        event_type: "identity.deleted".into(),
        actor_device_id: f.device.device_id.clone(),
        lifecycle_epoch: 1,
        now: 1200,
        reason_code: "user_requested".into(),
        timelock_seconds: Some(1),
        recovery_quorum: None,
        recovery_quorum_proof: None,
    })?;
    router.mvp7_finalize_delete(&LifecycleFinalizeRequest {
        principal_id: "alice".into(),
        now: 1202,
    })?;
    assert!(router.signed_device_set(&f.request.principal_commitment).is_none());
    let mut registry = router.mvp1_identities_snapshot();
    assert!(
        registry
            .publish_signed_device_set(&f.publish(f.record(3, DeviceSetStatus::Active)?))
            .is_err()
    );
    let record = sign_device_set(
        &f.root,
        DeviceSetSigningInput {
            principal_kind: PrincipalKind::Human,
            device_set_epoch: 4,
            devices: f.record(3, DeviceSetStatus::Active)?.devices,
        },
    )?;
    assert!(registry.publish_signed_device_set(&f.publish(record)).is_err());
    assert!(!router.mvp7_metadata_summary("alice").root_key_present);
    Ok(())
}

#[test]
fn individually_valid_proof_and_record_with_different_kinds_cannot_be_combined() -> TestResult {
    let f = Fixture::new()?;
    let mut request = f.request.clone();
    request.proof = authorize_device_branch_v2(
        &f.root,
        &f.device,
        BranchAuthorization {
            audience: IDENTITY_BIND_AUDIENCE,
            capability_scope: vec![IDENTITY_BIND_CAPABILITY.into()],
            issued_at: 1000,
            expires_at: 2000,
            principal_kind: PrincipalKind::Human,
            agreement_identity_public_key: f.x.public,
        },
    )?;
    verify_branch_proof(
        &f.root.signing_key.verifying_key(),
        &request.proof,
        IDENTITY_BIND_AUDIENCE,
        IDENTITY_BIND_CAPABILITY,
        1100,
    )?;
    let mut registry = IdentityRegistry::new();
    assert!(registry.register_identity(&request).is_err());
    assert_only_admission_charged(&registry, f.request.now)?;
    registry.register_identity(&f.request)?;
    Ok(())
}

fn qualified(f: &Fixture) -> Result<String, serde_json::Error> {
    Ok(format!(
        "root~{}",
        encode_base64url(serde_json::to_vec(&(
            &f.request.principal_commitment,
            &f.device.device_id
        ))?)
    ))
}

#[test]
fn historical_unqualified_proof_ids_cannot_reserve_a_current_root_qualified_proof() -> TestResult {
    let f = Fixture::new()?;
    let source = RootQualifiedDeviceRef::for_owned_device(&f.root, &f.device)?;
    let predicted = blake3_256_base64url(
        "ramflux.node.registration_proof.v2",
        &ramflux_protocol::canonical_json_bytes(&(
            source.storage_key(),
            &f.request.proof.proof_id,
        ))?,
    );
    let mut old = serde_json::to_value(IdentityRegistry::new())?;
    old.as_object_mut().ok_or("registry")?.remove("root_seen_proofs");
    old["seen_proofs"] = serde_json::json!([predicted]);
    let mut reopened: IdentityRegistry = serde_json::from_value(old)?;
    reopened.register_identity(&f.request)?;
    assert!(reopened.device_auth_key(&source).is_some());
    assert!(reopened.register_identity(&f.request).is_err());
    Ok(())
}

fn assert_only_admission_charged(registry: &IdentityRegistry, at: i64) -> TestResult {
    assert_authority_unchanged_after_admission(registry, &IdentityRegistry::new(), at)
}

fn assert_authority_unchanged_after_admission(
    registry: &IdentityRegistry,
    before: &IdentityRegistry,
    at: i64,
) -> TestResult {
    let mut actual = serde_json::to_value(registry)?;
    let previous = serde_json::to_value(before)?;
    assert_eq!(
        actual["registration_times_by_source_ip"]["unknown-source-ip"],
        serde_json::json!([at])
    );
    actual["registration_times_by_source_ip"] = previous["registration_times_by_source_ip"].clone();
    assert_eq!(actual, previous);
    Ok(())
}
