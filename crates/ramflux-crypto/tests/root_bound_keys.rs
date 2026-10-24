// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Regression for replacing a manifest key while retaining a genuine root proof.
use ramflux_crypto::*;
use ramflux_protocol::{
    DeviceKeyBinding, DeviceSetStatus, PrincipalKind, SignedDeviceSetEntry, SignedDeviceSetRecord,
    encode_base64url,
};
type TestResult = Result<(), Box<dyn std::error::Error>>;
fn binding(device: &DeviceBranch, x: &X25519KeyPair) -> DeviceKeyBinding {
    DeviceKeyBinding {
        version: 2,
        principal_kind: PrincipalKind::HeadlessAi,
        branch_signing_public_key: encode_base64url(device.signing_key.verifying_key().to_bytes()),
        agreement_identity_public_key: encode_base64url(x.public),
    }
}
fn entry(device: &DeviceBranch, x: &X25519KeyPair) -> Result<SignedDeviceSetEntry, CryptoError> {
    let (signing, agreement) = device_key_commitments(
        &encode_base64url(device.signing_key.verifying_key().to_bytes()),
        &encode_base64url(x.public),
    )?;
    Ok(SignedDeviceSetEntry {
        device_id: device.device_id.clone(),
        device_epoch: device.device_epoch,
        signing_key_commitment: signing,
        agreement_key_commitment: agreement,
        status: DeviceSetStatus::Active,
        revoked_at: None,
    })
}
fn set(
    root: &IdentityRoot,
    epoch: u64,
    devices: Vec<SignedDeviceSetEntry>,
) -> Result<SignedDeviceSetRecord, CryptoError> {
    sign_device_set(
        root,
        DeviceSetSigningInput {
            principal_kind: PrincipalKind::HeadlessAi,
            device_set_epoch: epoch,
            devices,
        },
    )
}
#[test]
fn replaced_branch_key_and_self_signed_bundle_cannot_reuse_a_genuine_root_proof() -> TestResult {
    let root = create_identity_root("alice", [11; 32]);
    let genuine = create_device_branch("alice", "alice-device", 1, [12; 32]);
    let replacement = create_device_branch("alice", "alice-device", 1, [13; 32]);
    let original_x = X25519KeyPair::from_seed([14; 32]);
    let replaced_x = X25519KeyPair::from_seed([16; 32]);
    let proof = authorize_device_branch_v2(
        &root,
        &genuine,
        BranchAuthorization {
            audience: "ramflux-node",
            capability_scope: vec!["device.delivery.bind".into()],
            issued_at: 1000,
            expires_at: 2000,
            principal_kind: PrincipalKind::HeadlessAi,
            agreement_identity_public_key: original_x.public,
        },
    )?;
    let attacker_bundle = create_prekey_bundle(
        &replacement,
        &replaced_x,
        "signed:1",
        &X25519KeyPair::from_seed([15; 32]),
        None,
        None,
    )?;
    verify_prekey_bundle(&replacement.signing_key.verifying_key(), &attacker_bundle)?;
    assert!(
        verify_root_bound_branch_proof(
            &root.signing_key.verifying_key(),
            &proof,
            &binding(&replacement, &replaced_x),
            "ramflux-node",
            "device.delivery.bind",
            1100
        )
        .is_err()
    );
    verify_root_bound_branch_proof(
        &root.signing_key.verifying_key(),
        &proof,
        &binding(&genuine, &original_x),
        "ramflux-node",
        "device.delivery.bind",
        1100,
    )?;
    assert!(
        verify_root_bound_branch_proof(
            &root.signing_key.verifying_key(),
            &proof,
            &binding(&genuine, &replaced_x),
            "ramflux-node",
            "device.delivery.bind",
            1100
        )
        .is_err()
    );
    let mut forged = proof.clone();
    forged.key_binding.as_mut().ok_or("binding")?.principal_kind = PrincipalKind::Human;
    assert!(
        verify_branch_proof(
            &root.signing_key.verifying_key(),
            &forged,
            "ramflux-node",
            "device.delivery.bind",
            1100
        )
        .is_err()
    );
    forged = proof.clone();
    forged.key_binding = None;
    assert!(
        verify_branch_proof(
            &root.signing_key.verifying_key(),
            &forged,
            "ramflux-node",
            "device.delivery.bind",
            1100
        )
        .is_err()
    );
    Ok(())
}
#[test]
fn legacy_proof_bytes_still_verify_but_cannot_authorize_any_advertised_key() -> TestResult {
    let root = create_identity_root("alice", [11; 32]);
    let device = create_device_branch("alice", "device", 1, [12; 32]);
    let proof = authorize_device_branch(
        &root,
        &device,
        "ramflux-node",
        vec!["device.delivery.bind".into()],
        1000,
        2000,
    )?;
    let encoded = serde_json::to_vec(&proof)?;
    assert!(!String::from_utf8(encoded.clone())?.contains("key_binding"));
    let restored: BranchProofDocument = ramflux_protocol::parse_i_json(&encoded)?;
    verify_branch_proof(
        &root.signing_key.verifying_key(),
        &restored,
        "ramflux-node",
        "device.delivery.bind",
        1100,
    )?;
    assert!(
        verify_root_bound_branch_proof(
            &root.signing_key.verifying_key(),
            &restored,
            &binding(&device, &X25519KeyPair::from_seed([14; 32])),
            "ramflux-node",
            "device.delivery.bind",
            1100
        )
        .is_err()
    );
    Ok(())
}
#[test]
fn complete_signed_sets_reject_rollback_omission_kind_change_and_resurrection() -> TestResult {
    let root = create_identity_root("alice", [11; 32]);
    let x = X25519KeyPair::from_seed([14; 32]);
    let first = entry(&create_device_branch("alice", "one", 1, [12; 32]), &x)?;
    let second = entry(&create_device_branch("alice", "two", 1, [13; 32]), &x)?;
    let initial = set(&root, 1, vec![second.clone(), first.clone()])?;
    verify_signed_device_set(&root.signing_key.verifying_key(), &initial)?;
    validate_device_set_transition(&initial, &initial)?;
    let omitted = set(&root, 2, vec![second])?;
    assert!(validate_device_set_transition(&initial, &omitted).is_err());
    let mut next = initial.clone();
    next.device_set_epoch = 2;
    next.principal_kind = PrincipalKind::Human;
    next = sign_device_set(
        &root,
        DeviceSetSigningInput {
            principal_kind: next.principal_kind,
            device_set_epoch: 2,
            devices: next.devices,
        },
    )?;
    verify_signed_device_set(&root.signing_key.verifying_key(), &next)?;
    assert!(validate_device_set_transition(&initial, &next).is_err());
    let mut revoked = initial.devices.clone();
    revoked[0].status = DeviceSetStatus::Revoked;
    revoked[0].revoked_at = Some(1100);
    let revoked = set(&root, 2, revoked)?;
    validate_device_set_transition(&initial, &revoked)?;
    assert!(validate_device_set_transition(&revoked, &initial).is_err());
    assert!(
        validate_device_set_transition(&revoked, &set(&root, 3, initial.devices.clone())?).is_err()
    );
    let mut changed = initial.devices.clone();
    changed[0] = entry(&create_device_branch("alice", "one", 1, [17; 32]), &x)?;
    assert!(validate_device_set_transition(&initial, &set(&root, 2, changed.clone())?).is_err());
    changed[0].device_epoch = 2;
    validate_device_set_transition(&initial, &set(&root, 2, changed)?)?;
    let mut unsigned = initial;
    unsigned.signature = String::new();
    assert!(verify_signed_device_set(&root.signing_key.verifying_key(), &unsigned).is_err());
    Ok(())
}
#[test]
fn device_set_ingress_and_key_material_are_bounded_and_strict() -> TestResult {
    let root = create_identity_root("alice", [11; 32]);
    let device = create_device_branch("alice", "one", 1, [12; 32]);
    let x = X25519KeyPair::from_seed([14; 32]);
    let record = set(&root, 1, vec![entry(&device, &x)?])?;
    let raw = serde_json::to_vec(&record)?;
    assert_eq!(SignedDeviceSetRecord::from_wire_bytes(&raw)?, record);
    let text = String::from_utf8(raw)?
        .replace("\"device_set_epoch\":1", "\"device_set_epoch\":1,\"device_set_epoch\":2");
    assert!(SignedDeviceSetRecord::from_wire_bytes(text.as_bytes()).is_err());
    assert!(SignedDeviceSetRecord::from_wire_bytes(&vec![b' '; 512 * 1024 + 1]).is_err());
    assert!(
        device_key_commitments(
            &encode_base64url(device.signing_key.verifying_key().to_bytes()),
            &encode_base64url([0; 32])
        )
        .is_err()
    );
    assert!(
        set(&root, ramflux_protocol::MAX_SAFE_JSON_INTEGER + 1, record.devices.clone()).is_err()
    );
    let mut invalid = record.devices;
    invalid[0].revoked_at = Some(1100);
    assert!(set(&root, 2, invalid).is_err());
    Ok(())
}

#[test]
fn root_bound_proof_accepts_only_the_documented_forward_clock_skew() -> TestResult {
    let root = create_identity_root("alice", [11; 32]);
    let device = create_device_branch("alice", "device", 1, [12; 32]);
    let x = X25519KeyPair::from_seed([14; 32]);
    let proof = authorize_device_branch_v2(
        &root,
        &device,
        BranchAuthorization {
            audience: "ramflux-node",
            capability_scope: vec!["device.delivery.bind".into()],
            issued_at: 1300,
            expires_at: 2300,
            principal_kind: PrincipalKind::HeadlessAi,
            agreement_identity_public_key: x.public,
        },
    )?;
    assert_eq!(BRANCH_PROOF_CLOCK_SKEW_SECONDS, 300);
    verify_root_bound_branch_proof(
        &root.signing_key.verifying_key(),
        &proof,
        &binding(&device, &x),
        "ramflux-node",
        "device.delivery.bind",
        1000,
    )?;
    assert!(
        verify_root_bound_branch_proof(
            &root.signing_key.verifying_key(),
            &proof,
            &binding(&device, &x),
            "ramflux-node",
            "device.delivery.bind",
            999
        )
        .is_err()
    );
    Ok(())
}
