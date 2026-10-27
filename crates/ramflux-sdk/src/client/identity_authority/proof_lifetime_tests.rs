// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Injectable registration clocks separate durable device authority from renewable session proofs.
use super::*;
#[test]
fn renewed_registration_at_two_hours_is_accepted_but_original_proof_replay_and_expiry_are_refused()
-> TestResult {
    let owner = Actor::new("alice", "one", 71, 72, 1)?;
    let record = owner.client.prepare_owned_authority(None)?;
    owner.client.account_db()?.persist_actor_state("identity/registration_set", &record)?;
    let start = now_unix_timestamp() - 7200;
    let request: ramflux_node_core::IdentityRegisterRequest = serde_json::from_value(
        serde_json::to_value(owner.client.mvp1_identity_registration_request_at(
            "one",
            "one",
            "initial",
            &record.principal_commitment,
            start,
        )?)?,
    )?;
    let mut node = ramflux_node_core::IdentityRegistry::new();
    node.register_identity(&request)?;
    node.publish_prekey(ramflux_node_core::PrekeyPublishRequest {
        device_id: "one".into(),
        bundle: owner
            .client
            .load_x3dh_private_state(&owner.client.owned_device_identity()?)?
            .bundle,
    })?;
    assert!(node.register_identity(&request).is_err(), "a still-live old proof remains a replay");
    let mut expired = request.clone();
    expired.now = start + 7200;
    assert!(node.register_identity(&expired).is_err());
    let manifest: SdkDeviceManifestResponse = serde_json::from_value(serde_json::to_value(
        node.device_manifest(&record.principal_commitment).ok_or("durable manifest")?,
    )?)?;
    verify_manifest(&manifest, &record.principal_commitment)?;
    owner.client.persist_identity_directory(&manifest)?;
    owner
        .client
        .account_db()?
        .persist_actor_state("identity/owned_proof_refresh_at", &(start + 10_000))?;
    assert!(
        owner.client.own_proof_refresh_due(start + 7200)?,
        "expired cached proof overrides a stale later refresh schedule on startup"
    );
    let renewal: ramflux_node_core::IdentityRegisterRequest = serde_json::from_value(
        serde_json::to_value(owner.client.mvp1_identity_registration_request_at(
            "one",
            "one",
            "renewed",
            &record.principal_commitment,
            start + 7200,
        )?)?,
    )?;
    assert_ne!(request.proof.proof_id, renewal.proof.proof_id);
    assert_eq!(
        request.device_set, renewal.device_set,
        "renewal does not change durable authorization"
    );
    node.register_identity(&renewal)?;
    assert!(node.register_identity(&renewal).is_err());
    let renewed = node.device_manifest(&record.principal_commitment).ok_or("manifest")?;
    assert_eq!(renewed.devices[0].branch_proof.proof_id, renewal.proof.proof_id);
    Ok(())
}
#[test]
fn legacy_constructor_renewal_has_a_distinct_time_bound_identifier() -> TestResult {
    let root = ramflux_crypto::create_identity_root("alice", [71; 32]);
    let device = ramflux_crypto::create_device_branch("alice", "one", 1, [72; 32]);
    let first = ramflux_crypto::authorize_device_branch(
        &root,
        &device,
        "ramflux-node",
        vec!["device.delivery.bind".into()],
        1000,
        4600,
    )?;
    let second = ramflux_crypto::authorize_device_branch(
        &root,
        &device,
        "ramflux-node",
        vec!["device.delivery.bind".into()],
        2800,
        6400,
    )?;
    assert_ne!(first.proof_id, second.proof_id);
    ramflux_crypto::verify_branch_proof(
        &root.signing_key.verifying_key(),
        &second,
        "ramflux-node",
        "device.delivery.bind",
        3000,
    )?;
    Ok(())
}

#[test]
fn durable_manifest_proof_age_is_bounded_to_thirty_days_with_an_injectable_clock() -> TestResult {
    let owner = Actor::new("alice", "one", 71, 72, 1)?;
    let manifest = owner.manifest()?;
    let issued = manifest.devices[0].legacy_proof()?.issued_at;
    let root = &manifest.principal_commitment;
    verify_manifest(&manifest, root)?;
    assert_eq!(
        super::super::verify::ready_manifest(manifest.clone(), issued + 7200).devices.len(),
        1
    );
    assert_eq!(
        super::super::verify::ready_manifest(manifest.clone(), issued + 30 * 86400).devices.len(),
        1
    );
    for now in [issued + 30 * 86400 + 1, issued - 301] {
        assert_eq!(super::super::verify::ready_manifest(manifest.clone(), now).devices.len(), 0);
    }
    assert_eq!(
        super::super::verify::ready_manifest(manifest.clone(), issued - 300).devices.len(),
        1
    );
    Ok(())
}

#[test]
fn one_dormant_device_never_invalidates_live_siblings_or_becomes_revoked() -> TestResult {
    let live = Actor::new("alice", "live", 71, 72, 1)?;
    let stale = Actor::new("alice", "dormant", 71, 73, 1)?;
    let future = Actor::new("alice", "future", 71, 74, 1)?;
    let receiver = Actor::new("bob", "bob", 81, 82, 1)?;
    let mut manifest = live.manifest()?;
    let now = now_unix_timestamp();
    for (actor, issued) in [(&stale, now - 31 * 86400), (&future, now + 3600)] {
        let mut entry = actor.manifest()?.devices.remove(0);
        let request = actor.client.mvp1_identity_registration_request_at(
            &actor.id,
            &actor.id,
            "proof-age",
            &manifest.principal_commitment,
            issued,
        )?;
        entry.branch_proof = Some(request.proof);
        manifest.devices.push(entry);
    }
    test_support::sign_manifest(
        live.client.identity_root.as_ref().ok_or("root")?,
        &mut manifest,
        2,
    )?;
    receiver.client.persist_identity_directory(&stale.manifest()?)?;
    // Simulate a legitimately cached pre-upgrade proof which has since aged 31 days.
    let dormant =
        receiver.client.device_identity_for_root(&manifest.principal_commitment, "dormant")?;
    let mut previous = stale.manifest()?;
    previous.devices[0] = manifest.devices[1].clone();
    let mut row = receiver
        .client
        .account_db()?
        .client_record("device", dormant.storage_key())?
        .ok_or("old cache")?;
    row.as_object_mut().ok_or("object")?.remove("proof_issued_at");
    receiver.client.account_db()?.persist_client_record("device", dormant.storage_key(), &row)?;
    receiver.client.account_db()?.persist_actor_state(
        &format!("identity/manifest-root/{}", manifest.principal_commitment),
        &previous,
    )?;
    verify_manifest(&manifest, &manifest.principal_commitment)?;
    receiver.client.persist_identity_directory(&manifest)?;
    let ready = super::super::verify::ready_manifest(manifest.clone(), now);
    assert_eq!(ready.devices.len(), 1);
    assert_eq!(ready.devices[0].device_id, "live");
    let live_ref =
        receiver.client.device_identity_for_root(&manifest.principal_commitment, "live")?;
    assert_eq!(receiver.client.trusted_device(&live_ref)?["target_delivery_id"], "live");
    let stale_ref =
        receiver.client.device_identity_for_root(&manifest.principal_commitment, "dormant")?;
    assert!(matches!(receiver.client.trusted_device(&stale_ref), Err(SdkError::InboundPending(_))));
    let future_ref = RamfluxClient::device_identity_from_manifest(&manifest, "future")?;
    assert!(receiver.client.trusted_device(&future_ref).is_err());
    assert_eq!(
        receiver
            .client
            .account_db()?
            .client_record("device", stale_ref.storage_key())?
            .ok_or("old metadata")?["revoked"],
        false
    );
    let set = receiver.client.observed_device_set(&manifest.principal_commitment)?.ok_or("set")?;
    assert_eq!(set.devices.len(), 3);
    assert!(set.devices.iter().all(|device| device.status == DeviceSetStatus::Active));
    // Old cached rows without a timestamp cannot silently retain stale permission after refresh.
    let mut cached = receiver
        .client
        .account_db()?
        .client_record("device", stale_ref.storage_key())?
        .ok_or("cached")?;
    cached.as_object_mut().ok_or("object")?.remove("proof_issued_at");
    receiver.client.account_db()?.persist_client_record(
        "device",
        stale_ref.storage_key(),
        &cached,
    )?;
    receiver.client.account_db()?.persist_actor_state(
        &format!("identity/manifest-root/{}", manifest.principal_commitment),
        &ready,
    )?;
    assert!(matches!(receiver.client.trusted_device(&stale_ref), Err(SdkError::InboundPending(_))));
    assert_served_ready_manifest(
        [(&live, now), (&stale, now - 31 * 86400), (&future, now + 3600)],
        &manifest,
    )?;
    Ok(())
}

#[test]
fn an_omitted_stale_advertisement_preserves_fresh_pre_upgrade_cached_material() -> TestResult {
    let peer = Actor::new("alice", "phone", 71, 72, 1)?;
    let receiver = Actor::new("bob", "bob", 81, 82, 1)?;
    let mut stale = peer.manifest()?;
    receiver.client.persist_identity_directory(&stale)?;
    let identity =
        receiver.client.device_identity_for_root(&stale.principal_commitment, "phone")?;
    let mut old = receiver
        .client
        .account_db()?
        .client_record("device", identity.storage_key())?
        .ok_or("cached")?;
    old.as_object_mut().ok_or("object")?.remove("proof_issued_at");
    receiver.client.account_db()?.persist_client_record("device", identity.storage_key(), &old)?;
    let request = peer.client.mvp1_identity_registration_request_at(
        "phone",
        "phone",
        "stale-advertisement",
        &stale.principal_commitment,
        now_unix_timestamp() - 31 * 86400,
    )?;
    stale.devices[0].branch_proof = Some(request.proof);
    receiver.client.persist_identity_directory(&stale)?;
    assert_eq!(receiver.client.trusted_device(&identity)?["device_id"], "phone");
    assert_eq!(
        receiver.client.observed_device_set(&stale.principal_commitment)?.ok_or("set")?.devices[0]
            .status,
        DeviceSetStatus::Active
    );
    Ok(())
}

fn assert_served_ready_manifest(
    actors: [(&Actor, i64); 3],
    manifest: &SdkDeviceManifestResponse,
) -> TestResult {
    let mut node = ramflux_node_core::IdentityRegistry::new();
    for (actor, issued) in actors {
        let request = actor.client.mvp1_identity_registration_request_at(
            &actor.id,
            &actor.id,
            "node-age",
            &manifest.principal_commitment,
            issued,
        )?;
        let mut request: ramflux_node_core::IdentityRegisterRequest =
            serde_json::from_value(serde_json::to_value(request)?)?;
        request.device_set = manifest.signed_device_set.clone();
        node.register_identity(&request)?;
        node.publish_prekey(ramflux_node_core::PrekeyPublishRequest {
            device_id: actor.id.clone(),
            bundle: actor.manifest()?.devices.remove(0).prekey_bundle,
        })?;
    }
    let served = node.device_manifest(&manifest.principal_commitment).ok_or("served")?;
    assert_eq!(served.devices.len(), 1);
    assert_eq!(served.devices[0].device_id, "live");
    assert_eq!(served.signed_device_set.ok_or("served signed set")?.devices.len(), 3);
    Ok(())
}

#[test]
fn unready_material_never_bypasses_root_bound_key_checks() -> TestResult {
    let owner = Actor::new("alice", "future", 71, 72, 1)?;
    let mut manifest = owner.manifest()?;
    manifest.devices[0].branch_proof = Some(
        owner
            .client
            .mvp1_identity_registration_request_at(
                "future",
                "future",
                "future-proof",
                &manifest.principal_commitment,
                now_unix_timestamp() + 3600,
            )?
            .proof,
    );
    verify_manifest(&manifest, &manifest.principal_commitment)?;
    assert_eq!(
        super::super::verify::ready_manifest(manifest.clone(), now_unix_timestamp()).devices.len(),
        0
    );
    let mut substituted = manifest.clone();
    substituted.devices[0].branch_public_key =
        ramflux_crypto::public_key_base64url_from_seed([99; 32]);
    assert!(
        verify_manifest(&substituted, &manifest.principal_commitment).is_err(),
        "unready cannot authenticate a substituted key"
    );
    manifest.devices[0].legacy_proof_mut()?.signature = "forged".into();
    assert!(
        verify_manifest(&manifest, &manifest.principal_commitment).is_err(),
        "unready cannot authenticate an invalid proof"
    );
    Ok(())
}
