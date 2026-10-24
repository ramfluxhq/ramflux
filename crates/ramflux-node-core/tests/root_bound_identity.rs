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
fn substitution_diagnostic_is_rejected_without_poisoning_the_real_registration() -> TestResult {
    let f = Fixture::new()?;
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
    assert_eq!(registry, IdentityRegistry::new());
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
    assert!(registry.prekey_bundle(&qualified(&f)?).is_none());
    assert!(registry.device_auth_key(&qualified(&f)?).ok_or("device")?.revoked);
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
    let value = serde_json::json!({"root_public_keys":{"alice":f.request.root_public_key},"root_public_keys_by_commitment":{f.request.principal_commitment.clone():f.request.root_public_key},"devices":{"alice-device":{"principal_id":"alice","principal_commitment":f.request.principal_commitment,"device_id":"alice-device","device_epoch":1,"branch_public_key":f.request.branch_public_key,"target_delivery_id":"target","branch_proof":proof}},"revoked_devices":[],"seen_proofs":[],"prekey_bundles":{"alice-device":f.bundle()?}});
    let mut legacy: IdentityRegistry = serde_json::from_value(value)?;
    let manifest =
        legacy.device_manifest(&f.request.principal_commitment).ok_or("legacy manifest")?;
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
    assert_eq!(legacy, before);
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
    assert!(restored.mvp1_device_auth_key(&qualified(&f)?).ok_or("device")?.revoked);
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
    assert!(registry.device_auth_key(&qualified(&f)?).is_none());
    assert!(registry.prekey_bundle(&qualified(&f)?).is_none());
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
        registry.device_auth_key(&qualified(&f)?).ok_or("rotated device")?.branch_public_key,
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
    assert_eq!(registry, IdentityRegistry::new());
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
