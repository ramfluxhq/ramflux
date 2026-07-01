// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use serde::Serialize;

use crate::{HomeNodeMigrationProof, ProtocolError, canonical_json_bytes, domain, hash_base64url};

#[derive(Serialize)]
struct HomeNodeMigrationProofSignedEnvelope<'a> {
    schema: &'a str,
    domain: &'a str,
    body: HomeNodeMigrationProofSignedBody<'a>,
}

#[derive(Serialize)]
struct HomeNodeMigrationProofSignedBody<'a> {
    proof_id: &'a str,
    identity_commitment: &'a str,
    lineage_head: &'a str,
    actor_device_id: &'a str,
    actor_device_epoch: u64,
    old_home_node: &'a str,
    new_home_node: &'a str,
    new_home_node_key_hash: &'a str,
    route_record_hash: &'a str,
    effective_at: i64,
    expires_at: i64,
    issued_at: i64,
    nonce: &'a str,
    branch_proof_hash: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    previous_home_node_binding_hash: Option<&'a str>,
}

/// Canonical signed bytes for `ramflux.home_node_migration_proof.v1`.
///
/// # Errors
/// Returns an error when canonical JSON serialization fails.
pub fn home_node_migration_proof_signed_bytes(
    proof: &HomeNodeMigrationProof,
) -> Result<Vec<u8>, ProtocolError> {
    canonical_json_bytes(&HomeNodeMigrationProofSignedEnvelope {
        schema: &proof.schema,
        domain: &proof.domain,
        body: HomeNodeMigrationProofSignedBody {
            proof_id: &proof.proof_id,
            identity_commitment: &proof.identity_commitment,
            lineage_head: &proof.lineage_head,
            actor_device_id: &proof.actor_device_id,
            actor_device_epoch: proof.actor_device_epoch,
            old_home_node: &proof.old_home_node,
            new_home_node: &proof.new_home_node,
            new_home_node_key_hash: &proof.new_home_node_key_hash,
            route_record_hash: &proof.route_record_hash,
            effective_at: proof.effective_at,
            expires_at: proof.expires_at,
            issued_at: proof.issued_at,
            nonce: &proof.nonce,
            branch_proof_hash: &proof.branch_proof_hash,
            previous_home_node_binding_hash: proof.previous_home_node_binding_hash.as_deref(),
        },
    })
}

/// Computes `migration_proof_hash` for `ramflux.home_node_migration_proof.v1`.
///
/// # Errors
/// Returns an error when canonical JSON serialization fails.
pub fn migration_proof_hash(proof: &HomeNodeMigrationProof) -> Result<String, ProtocolError> {
    let signed_bytes = home_node_migration_proof_signed_bytes(proof)?;
    Ok(hash_base64url(domain::HOME_NODE_MIGRATION_PROOF, &signed_bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{SignatureAlg, SignedFields, domain};

    #[test]
    fn home_node_migration_signed_bytes_follow_spec_shape() -> Result<(), ProtocolError> {
        let proof = HomeNodeMigrationProof {
            schema: domain::HOME_NODE_MIGRATION_PROOF.to_owned(),
            domain: domain::HOME_NODE_MIGRATION_PROOF.to_owned(),
            signed: SignedFields {
                signing_key_id: "device:dev_a:7".to_owned(),
                signature_alg: SignatureAlg::Ed25519,
                signature: "sig".to_owned(),
            },
            proof_id: "mig_01".to_owned(),
            identity_commitment: "id_a".to_owned(),
            lineage_head: "lin_01".to_owned(),
            actor_device_id: "dev_a".to_owned(),
            actor_device_epoch: 7,
            old_home_node: "node_a.example".to_owned(),
            new_home_node: "node_b.example".to_owned(),
            new_home_node_key_hash: "node_key_hash".to_owned(),
            route_record_hash: "route_hash".to_owned(),
            effective_at: 1_760_000_010,
            expires_at: 1_760_000_100,
            issued_at: 1_760_000_000,
            nonce: "nonce".to_owned(),
            branch_proof_hash: "branch_hash".to_owned(),
            previous_home_node_binding_hash: Some("old_binding".to_owned()),
            old_home_node_handoff_signature: Some("handoff_sig".to_owned()),
        };

        let signed_bytes = home_node_migration_proof_signed_bytes(&proof)?;
        let canonical = String::from_utf8_lossy(&signed_bytes);

        assert!(canonical.contains(r#""body":{"actor_device_epoch":7"#));
        assert!(canonical.contains(r#""schema":"ramflux.home_node_migration_proof.v1""#));
        assert!(!canonical.contains("signature_alg"));
        assert!(!canonical.contains("signing_key_id"));
        assert!(!canonical.contains("signature"));
        assert!(!canonical.contains("old_home_node_handoff_signature"));
        Ok(())
    }
}
