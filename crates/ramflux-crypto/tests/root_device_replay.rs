// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Revocation and proof replay cannot cross accounts that reuse a device name.
use ramflux_crypto::*;

#[test]
fn copied_device_names_and_proof_ids_do_not_share_revocation_or_replay_state()
-> Result<(), CryptoError> {
    let alice = create_identity_root("alice", [1; 32]);
    let mallory = create_identity_root("mallory", [2; 32]);
    let alice_branch = create_device_branch("alice", "bob", 1, [3; 32]);
    let mallory_branch = create_device_branch("mallory", "bob", 1, [4; 32]);
    let honest = RootQualifiedDeviceRef::for_owned_device(&alice, &alice_branch)?;
    let attacker = RootQualifiedDeviceRef::for_owned_device(&mallory, &mallory_branch)?;
    let proof = |root: &IdentityRoot, branch: &DeviceBranch, id: &str| {
        let mut proof =
            authorize_device_branch(root, branch, "node", vec!["send".into()], 100, 1000)?;
        proof.proof_id = id.into();
        proof.signature = sign_canonical_bytes_with_seed(
            &branch_proof_signing_bytes(&proof)?,
            root.signing_key.to_bytes(),
        );
        Ok::<_, CryptoError>(proof)
    };
    let first = proof(&mallory, &mallory_branch, "next-proof")?;
    let genuine = proof(&alice, &alice_branch, "next-proof")?;
    let mut guard = DeviceRevocationReplayGuard::new();
    guard.accept_branch_proof(
        &attacker,
        &mallory.signing_key.verifying_key(),
        &first,
        "node",
        "send",
        101,
    )?;
    guard.accept_branch_proof(
        &honest,
        &alice.signing_key.verifying_key(),
        &genuine,
        "node",
        "send",
        101,
    )?;
    assert!(matches!(
        guard.accept_branch_proof(
            &honest,
            &alice.signing_key.verifying_key(),
            &genuine,
            "node",
            "send",
            101
        ),
        Err(CryptoError::BranchProofReplay)
    ));
    guard.revoke_device(&attacker);
    let next = proof(&alice, &alice_branch, "later-proof")?;
    let mut forged = next.clone();
    forged.signature = ramflux_protocol::encode_base64url([0; 64]);
    assert!(
        guard
            .accept_branch_proof(
                &honest,
                &alice.signing_key.verifying_key(),
                &forged,
                "node",
                "send",
                101
            )
            .is_err()
    );
    guard.accept_branch_proof(
        &honest,
        &alice.signing_key.verifying_key(),
        &next,
        "node",
        "send",
        101,
    )?;
    assert!(
        guard
            .accept_branch_proof(
                &attacker,
                &alice.signing_key.verifying_key(),
                &next,
                "node",
                "send",
                101
            )
            .is_err()
    );
    Ok(())
}
