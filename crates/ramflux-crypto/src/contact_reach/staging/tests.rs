// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Ephemeral AEAD keys cannot be replayed or recovered as a plaintext proof cache.
use super::*;
use ramflux_protocol::custody::{self, CustodyAuthority, Publication};
type TestResult = Result<(), Box<dyn std::error::Error>>;
fn d(n: u8) -> String {
    ramflux_protocol::encode_base64url([n; 32])
}
#[test]
fn cr_provenance_stage_is_encrypted_and_rejects_cross_stage_ciphertext() -> TestResult {
    let vector: serde_json::Value =
        serde_json::from_str(include_str!("../../../tests/fixtures/custody_v3.json"))?;
    let mut proof = ProvenanceAuthority {
        proof_hash: String::new(),
        authority: CustodyAuthority {
            publication: Publication {
                record: serde_json::from_value(
                    vector.get("record").ok_or("native record")?.clone(),
                )?,
                compacted_ids: None,
            },
            custodian_publication: None,
        },
        custodian_history: vec![],
    };
    proof.proof_hash = proof.content_hash()?;
    let root = &proof.authority.publication.record.body.account_anchor;
    let signers = vec![SignerReference {
        object_hash: d(50),
        object_kind: wire::ObjectKind::Policy,
        authority_head_hash: custody::object_hash(&proof.authority.publication.record)?,
        master_certificate_hash: custody::object_hash(
            &proof.authority.publication.record.body.master_certificate,
        )?,
        proof_hash: proof.proof_hash.clone(),
    }];
    let new = || ProvenanceStageBuilder::new(root, 1, &d(51), signers.clone());
    let mut one = new()?;
    one.push(&proof)?;
    let mut one = one.finish()?;
    let mut two = new()?;
    two.push(&proof)?;
    let mut two = two.finish()?;
    let plaintext = ramflux_protocol::canonical_json_bytes(&proof)?;
    let sealed = one.proofs.get(&proof.proof_hash).ok_or("sealed original proof")?;
    assert!(
        !sealed.ciphertext.windows(plaintext.len()).any(|window| window == plaintext.as_slice()),
        "private staging must not retain the native proof's plaintext JSON"
    );
    assert_eq!(
        one.read_proof(&proof.proof_hash)?,
        proof,
        "the owning ephemeral stage decrypts the exact original native tuple"
    );
    let catalogue = wire::Provenance {
        kind: wire::ProvenanceKind::ReachProvenance,
        version: 1,
        account_anchor: root.clone(),
        revision: 1,
        state_hash: d(51),
        signers,
        authorities: vec![proof.clone()],
    };
    assert_eq!(
        one.identity().hash,
        custody::framed_hash(wire::STATE_CONTENT_DOMAIN, &catalogue)?,
        "private encryption cannot change the externally pinned canonical catalogue identity"
    );
    assert!(
        one.staged_bytes() > plaintext.len(),
        "staging must charge ciphertext, nonce, selectors and private metadata"
    );
    let swapped = one.proofs.remove(&proof.proof_hash).ok_or("original ciphertext")?;
    two.proofs.insert(proof.proof_hash.clone(), swapped);
    assert!(
        two.read_proof(&proof.proof_hash).is_err(),
        "another stage's ciphertext cannot borrow a new stage's ephemeral key or scope"
    );
    assert!(
        one.read_proof(&d(52)).is_err(),
        "an arbitrary proof hash is never an authority lookup"
    );
    Ok(())
}
