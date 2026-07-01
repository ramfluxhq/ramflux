// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use ed25519_dalek::Signer;
use ramflux_protocol::{HomeNodeMigrationProof, SignatureAlg, SignedFields, decode_base64url};

use crate::{BranchProofDocument, CryptoError, DeviceBranch, verify_canonical_signature};

const MAX_MIGRATION_PROOF_VALIDITY_SECONDS: i64 = 30 * 24 * 60 * 60;

/// Signs a `HomeNodeMigrationProof` with the active actor device branch key.
///
/// # Errors
/// Returns an error when the proof is malformed, actor fields do not match the device branch,
/// canonical serialization fails, or signing inputs are invalid.
pub fn sign_home_node_migration_proof(
    mut proof: HomeNodeMigrationProof,
    device_branch: &DeviceBranch,
) -> Result<HomeNodeMigrationProof, CryptoError> {
    validate_home_node_migration_proof_fields(&proof, false)?;
    ensure_actor_matches_device_branch(&proof, device_branch)?;
    proof.signed = SignedFields {
        signing_key_id: device_branch_signing_key_id(device_branch),
        signature_alg: SignatureAlg::Ed25519,
        signature: String::new(),
    };
    let signed_bytes = ramflux_protocol::home_node_migration_proof_signed_bytes(&proof)?;
    let signature = device_branch.signing_key.sign(&signed_bytes);
    proof.signed.signature = ramflux_protocol::encode_base64url(signature.to_bytes());
    Ok(proof)
}

/// Verifies a `HomeNodeMigrationProof` against the actor device branch public key.
///
/// This validates the proof structure, proof signature, `branch_proof_hash`, and the available
/// `BranchProofDocument` actor-device binding. Full lineage active/fork checks require the
/// identity lineage state machine and are intentionally left to the caller for a later slice.
///
/// # Errors
/// Returns an error when validation, canonical serialization, base64 decoding, or signature
/// verification fails.
pub fn verify_home_node_migration_proof(
    proof: &HomeNodeMigrationProof,
    actor_device_public_key_base64url: &str,
    branch_proof: &BranchProofDocument,
    now: i64,
) -> Result<(), CryptoError> {
    validate_home_node_migration_proof_fields(proof, true)?;
    validate_home_node_migration_proof_time(proof, now)?;
    validate_home_node_migration_branch_binding(proof, branch_proof, now)?;
    let signed_bytes = ramflux_protocol::home_node_migration_proof_signed_bytes(proof)?;
    verify_canonical_signature(
        &signed_bytes,
        &proof.signed.signature,
        actor_device_public_key_base64url,
    )
}

/// Computes the `migration_proof_hash`.
///
/// # Errors
/// Returns an error when canonical JSON serialization fails.
pub fn migration_proof_hash(proof: &HomeNodeMigrationProof) -> Result<String, CryptoError> {
    Ok(ramflux_protocol::migration_proof_hash(proof)?)
}

/// Computes the branch proof hash used by `HomeNodeMigrationProof::branch_proof_hash`.
///
/// # Errors
/// Returns an error when canonical JSON serialization fails.
pub fn branch_proof_document_hash(proof: &BranchProofDocument) -> Result<String, CryptoError> {
    let canonical = ramflux_protocol::canonical_json_bytes(proof)?;
    Ok(ramflux_protocol::hash_base64url(ramflux_protocol::domain::BRANCH_PROOF, &canonical))
}

fn validate_home_node_migration_proof_fields(
    proof: &HomeNodeMigrationProof,
    require_signature_fields: bool,
) -> Result<(), CryptoError> {
    if proof.schema != ramflux_protocol::domain::HOME_NODE_MIGRATION_PROOF {
        return Err(CryptoError::InvalidHomeNodeMigrationProof("schema"));
    }
    if proof.domain != ramflux_protocol::domain::HOME_NODE_MIGRATION_PROOF {
        return Err(CryptoError::InvalidHomeNodeMigrationProof("domain"));
    }
    if proof.signed.signature_alg != SignatureAlg::Ed25519 {
        return Err(CryptoError::InvalidHomeNodeMigrationProof("signature_alg"));
    }
    for (field, value) in [
        ("proof_id", proof.proof_id.as_str()),
        ("identity_commitment", proof.identity_commitment.as_str()),
        ("lineage_head", proof.lineage_head.as_str()),
        ("actor_device_id", proof.actor_device_id.as_str()),
        ("old_home_node", proof.old_home_node.as_str()),
        ("new_home_node", proof.new_home_node.as_str()),
        ("new_home_node_key_hash", proof.new_home_node_key_hash.as_str()),
        ("route_record_hash", proof.route_record_hash.as_str()),
        ("nonce", proof.nonce.as_str()),
        ("branch_proof_hash", proof.branch_proof_hash.as_str()),
    ] {
        if value.is_empty() {
            return Err(CryptoError::InvalidHomeNodeMigrationProof(field));
        }
    }
    if require_signature_fields {
        let expected_signing_key_id = proof_signing_key_id(proof);
        if proof.signed.signing_key_id != expected_signing_key_id {
            return Err(CryptoError::InvalidHomeNodeMigrationProof("signing_key_id"));
        }
        for (field, value) in [
            ("signing_key_id", proof.signed.signing_key_id.as_str()),
            ("signature", proof.signed.signature.as_str()),
        ] {
            if value.is_empty() {
                return Err(CryptoError::InvalidHomeNodeMigrationProof(field));
            }
        }
    }
    validate_base64url_non_empty("new_home_node_key_hash", &proof.new_home_node_key_hash)?;
    validate_base64url_non_empty("route_record_hash", &proof.route_record_hash)?;
    validate_base64url_non_empty("nonce", &proof.nonce)?;
    validate_base64url_non_empty("branch_proof_hash", &proof.branch_proof_hash)?;
    if let Some(previous) = proof.previous_home_node_binding_hash.as_deref() {
        validate_base64url_non_empty("previous_home_node_binding_hash", previous)?;
    }
    if let Some(handoff) = proof.old_home_node_handoff_signature.as_deref() {
        validate_base64url_non_empty("old_home_node_handoff_signature", handoff)?;
    }
    Ok(())
}

fn validate_home_node_migration_proof_time(
    proof: &HomeNodeMigrationProof,
    now: i64,
) -> Result<(), CryptoError> {
    if proof.expires_at <= now {
        return Err(CryptoError::InvalidHomeNodeMigrationProof("expires_at"));
    }
    if proof.issued_at > proof.effective_at {
        return Err(CryptoError::InvalidHomeNodeMigrationProof("issued_at"));
    }
    if proof.effective_at > proof.expires_at {
        return Err(CryptoError::InvalidHomeNodeMigrationProof("effective_at"));
    }
    if proof.expires_at.saturating_sub(proof.issued_at) > MAX_MIGRATION_PROOF_VALIDITY_SECONDS {
        return Err(CryptoError::InvalidHomeNodeMigrationProof("validity_window"));
    }
    Ok(())
}

fn validate_home_node_migration_branch_binding(
    proof: &HomeNodeMigrationProof,
    branch_proof: &BranchProofDocument,
    now: i64,
) -> Result<(), CryptoError> {
    if branch_proof.principal_id != proof.identity_commitment {
        return Err(CryptoError::InvalidHomeNodeMigrationProof("branch_principal"));
    }
    if branch_proof.device_id != proof.actor_device_id {
        return Err(CryptoError::InvalidHomeNodeMigrationProof("branch_device"));
    }
    if branch_proof.device_epoch != proof.actor_device_epoch {
        return Err(CryptoError::InvalidHomeNodeMigrationProof("branch_epoch"));
    }
    if branch_proof.expires_at <= now {
        return Err(CryptoError::InvalidHomeNodeMigrationProof("branch_expires_at"));
    }
    if branch_proof_document_hash(branch_proof)? != proof.branch_proof_hash {
        return Err(CryptoError::InvalidHomeNodeMigrationProof("branch_proof_hash"));
    }
    Ok(())
}

fn ensure_actor_matches_device_branch(
    proof: &HomeNodeMigrationProof,
    device_branch: &DeviceBranch,
) -> Result<(), CryptoError> {
    if proof.identity_commitment != device_branch.principal_id {
        return Err(CryptoError::InvalidHomeNodeMigrationProof("identity_commitment"));
    }
    if proof.actor_device_id != device_branch.device_id {
        return Err(CryptoError::InvalidHomeNodeMigrationProof("actor_device_id"));
    }
    if proof.actor_device_epoch != device_branch.device_epoch {
        return Err(CryptoError::InvalidHomeNodeMigrationProof("actor_device_epoch"));
    }
    Ok(())
}

fn validate_base64url_non_empty(field: &'static str, value: &str) -> Result<(), CryptoError> {
    if decode_base64url(value)?.is_empty() {
        return Err(CryptoError::InvalidHomeNodeMigrationProof(field));
    }
    Ok(())
}

fn device_branch_signing_key_id(device_branch: &DeviceBranch) -> String {
    format!("device:{}:{}", device_branch.device_id, device_branch.device_epoch)
}

fn proof_signing_key_id(proof: &HomeNodeMigrationProof) -> String {
    format!("device:{}:{}", proof.actor_device_id, proof.actor_device_epoch)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{authorize_device_branch, create_device_branch, create_identity_root};

    const NOW: i64 = 1_760_000_000;

    #[test]
    fn home_node_migration_proof_signs_and_verifies() -> Result<(), CryptoError> {
        let fixture = ProofFixture::new()?;
        let signed = sign_home_node_migration_proof(fixture.proof, &fixture.device)?;
        verify_home_node_migration_proof(
            &signed,
            &fixture.actor_public_key,
            &fixture.branch_proof,
            NOW,
        )
    }

    #[test]
    fn home_node_migration_proof_rejects_wrong_key() -> Result<(), CryptoError> {
        let fixture = ProofFixture::new()?;
        let signed = sign_home_node_migration_proof(fixture.proof, &fixture.device)?;
        let wrong = create_device_branch("id_a", "dev_a", 7, [0x44; 32]);
        let wrong_public_key =
            ramflux_protocol::encode_base64url(wrong.signing_key.verifying_key().to_bytes());

        assert!(
            verify_home_node_migration_proof(
                &signed,
                &wrong_public_key,
                &fixture.branch_proof,
                NOW,
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn home_node_migration_proof_rejects_tampered_field() -> Result<(), CryptoError> {
        let fixture = ProofFixture::new()?;
        let mut signed = sign_home_node_migration_proof(fixture.proof, &fixture.device)?;
        signed.new_home_node = "node_evil.example".to_owned();

        assert!(
            verify_home_node_migration_proof(
                &signed,
                &fixture.actor_public_key,
                &fixture.branch_proof,
                NOW,
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn home_node_migration_proof_rejects_invalid_time_windows() -> Result<(), CryptoError> {
        let fixture = ProofFixture::new()?;
        let mut expired = sign_home_node_migration_proof(fixture.proof.clone(), &fixture.device)?;
        expired.expires_at = NOW;
        assert!(
            verify_home_node_migration_proof(
                &expired,
                &fixture.actor_public_key,
                &fixture.branch_proof,
                NOW,
            )
            .is_err()
        );

        let mut inverted = sign_home_node_migration_proof(fixture.proof, &fixture.device)?;
        inverted.effective_at = inverted.expires_at.saturating_add(1);
        assert!(
            verify_home_node_migration_proof(
                &inverted,
                &fixture.actor_public_key,
                &fixture.branch_proof,
                NOW,
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn home_node_migration_proof_hash_is_stable_and_excludes_handoff_signature()
    -> Result<(), CryptoError> {
        let fixture = ProofFixture::new()?;
        let signed = sign_home_node_migration_proof(fixture.proof, &fixture.device)?;
        let first = migration_proof_hash(&signed)?;
        let second = migration_proof_hash(&signed)?;
        assert_eq!(first, second);

        let mut with_handoff = signed.clone();
        with_handoff.old_home_node_handoff_signature =
            Some(ramflux_protocol::encode_base64url([0x77; 64]));
        assert_eq!(first, migration_proof_hash(&with_handoff)?);

        let mut tampered = signed;
        tampered.route_record_hash = ramflux_protocol::encode_base64url(b"different-route");
        assert_ne!(first, migration_proof_hash(&tampered)?);
        Ok(())
    }

    #[test]
    fn home_node_migration_proof_rejects_branch_binding_mismatch() -> Result<(), CryptoError> {
        let fixture = ProofFixture::new()?;
        let signed = sign_home_node_migration_proof(fixture.proof, &fixture.device)?;
        let mut wrong_branch = fixture.branch_proof;
        wrong_branch.device_epoch = wrong_branch.device_epoch.saturating_add(1);

        assert!(
            verify_home_node_migration_proof(
                &signed,
                &fixture.actor_public_key,
                &wrong_branch,
                NOW,
            )
            .is_err()
        );
        Ok(())
    }

    struct ProofFixture {
        device: DeviceBranch,
        branch_proof: BranchProofDocument,
        actor_public_key: String,
        proof: HomeNodeMigrationProof,
    }

    impl ProofFixture {
        fn new() -> Result<Self, CryptoError> {
            let root = create_identity_root("id_a", [0x11; 32]);
            let device = create_device_branch("id_a", "dev_a", 7, [0x22; 32]);
            let branch_proof = authorize_device_branch(
                &root,
                &device,
                "ramflux.home_node_migration",
                vec!["identity.home_node_migrate".to_owned()],
                NOW.saturating_sub(10),
                NOW.saturating_add(3_600),
            )?;
            let actor_public_key =
                ramflux_protocol::encode_base64url(device.signing_key.verifying_key().to_bytes());
            let proof = HomeNodeMigrationProof {
                schema: ramflux_protocol::domain::HOME_NODE_MIGRATION_PROOF.to_owned(),
                domain: ramflux_protocol::domain::HOME_NODE_MIGRATION_PROOF.to_owned(),
                signed: SignedFields {
                    signing_key_id: String::new(),
                    signature_alg: SignatureAlg::Ed25519,
                    signature: String::new(),
                },
                proof_id: "mig_01".to_owned(),
                identity_commitment: device.principal_id.clone(),
                lineage_head: "lineage_head_01".to_owned(),
                actor_device_id: device.device_id.clone(),
                actor_device_epoch: device.device_epoch,
                old_home_node: "node_a.example".to_owned(),
                new_home_node: "node_b.example".to_owned(),
                new_home_node_key_hash: ramflux_protocol::encode_base64url(b"new-node-key"),
                route_record_hash: ramflux_protocol::encode_base64url(b"route-record"),
                effective_at: NOW.saturating_add(10),
                expires_at: NOW.saturating_add(3_600),
                issued_at: NOW,
                nonce: ramflux_protocol::encode_base64url(b"migration-nonce"),
                branch_proof_hash: branch_proof_document_hash(&branch_proof)?,
                previous_home_node_binding_hash: Some(ramflux_protocol::encode_base64url(
                    b"old-home-binding",
                )),
                old_home_node_handoff_signature: None,
            };
            Ok(Self { device, branch_proof, actor_public_key, proof })
        }
    }
}
