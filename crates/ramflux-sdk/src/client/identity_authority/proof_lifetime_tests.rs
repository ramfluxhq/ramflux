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
    let issued = manifest.devices[0].branch_proof.issued_at;
    let root = &manifest.principal_commitment;
    super::super::verify::verify_manifest_at(&manifest, root, issued + 7200)?;
    super::super::verify::verify_manifest_at(&manifest, root, issued + 30 * 86400)?;
    assert!(
        super::super::verify::verify_manifest_at(&manifest, root, issued + 30 * 86400 + 1).is_err()
    );
    assert!(super::super::verify::verify_manifest_at(&manifest, root, issued - 61).is_err());
    Ok(())
}
