// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Real encrypted rows, original native signatures and transaction rollback; no current-pin import.
use super::*;
use crate::{AccountDbKey, AccountIndex};
use ramflux_protocol::custody;
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
const NOW: u64 = 1_700_000_100;
fn d(n: u8) -> String {
    ramflux_protocol::encode_base64url([n; 32])
}
fn original()
-> TestResult<(ProvenanceAuthority, SignerReference, custody::Envelope<wire::ReachPolicy>)> {
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../ramflux-crypto/tests/fixtures/custody_v3.json"
    ))?;
    let record: custody::Envelope<custody::DeviceSet> =
        serde_json::from_value(fixture.get("record").ok_or("native fixture")?.clone())?;
    let current = ramflux_crypto::custody::verify_record(&record, NOW, None, None)?;
    let key =
        ramflux_crypto::custody::SelfSigningKey::from_vault_seed(&zeroize::Zeroizing::new([2; 32]));
    let policy = key.sign_reach_policy(
        wire::ReachPolicy {
            version: 1,
            operation_id: d(20),
            account_anchor: record.body.account_anchor.clone(),
            home_head_hash: d(21),
            expected_revision: 0,
            revision: 1,
            mode: wire::ReachMode::ContactsOnly,
            authority_head_hash: custody::object_hash(&record)?,
            master_certificate_hash: custody::object_hash(&record.body.master_certificate)?,
            actor: record.body.master_certificate.body.primary_device_ref.clone(),
            issued_at: NOW,
            expires_at: NOW + 300,
        },
        &current,
        NOW,
    )?;
    let mut proof = ProvenanceAuthority {
        proof_hash: String::new(),
        authority: custody::CustodyAuthority {
            publication: custody::Publication { record, compacted_ids: None },
            custodian_publication: None,
        },
        custodian_history: vec![],
    };
    proof.proof_hash = proof.content_hash()?;
    let reference = SignerReference {
        object_kind: ObjectKind::Policy,
        object_hash: custody::framed_hash(wire::OPERATION_HASH_DOMAIN, &policy)?,
        authority_head_hash: policy.body.authority_head_hash.clone(),
        master_certificate_hash: policy.body.master_certificate_hash.clone(),
        proof_hash: proof.proof_hash.clone(),
    };
    Ok((proof, reference, policy))
}
fn advanced(original: &ProvenanceAuthority) -> TestResult<ProvenanceAuthority> {
    let mut proof = original.clone();
    let mut body = proof.authority.publication.record.body.clone();
    body.device_set_epoch += 1;
    body.previous_record_hash = Some(custody::object_hash(&proof.authority.publication.record)?);
    body.issued_at = NOW + 1;
    let key =
        ramflux_crypto::custody::SelfSigningKey::from_vault_seed(&zeroize::Zeroizing::new([2; 32]));
    proof.authority.publication.record = key.sign_record(body)?;
    ramflux_crypto::custody::verify_publication(&proof.authority, NOW + 1)?;
    proof.proof_hash = proof.content_hash()?;
    Ok(proof)
}

#[test]
fn cr_provenance_individual_records_retain_originals_and_rollback_conflicts() -> TestResult {
    let temp = tempfile::TempDir::new()?;
    let index = AccountIndex::open(temp.path())?;
    let (proof, reference, policy) = original()?;
    let root = &policy.body.account_anchor;
    index.create_account("acct", root)?;
    let db = AccountDb::open(&index, "acct", &AccountDbKey::generate()?)?;
    db.retain_reach_provenance(root, std::slice::from_ref(&reference), [Ok(proof.clone())])?;
    assert!(
        !db.actor_state_exists("reach/provenance")?,
        "per-object persistence never creates an all-proof actor row"
    );
    assert_eq!(
        db.reach_provenance_reference(ObjectKind::Policy, &reference.object_hash)?,
        Some(reference.clone())
    );
    let retained =
        db.reach_provenance_proof(root, &reference.proof_hash)?.ok_or("original proof")?;
    ramflux_crypto::contact_reach::verify_historical_policy(&policy, &retained)?;
    let next = advanced(&proof)?;
    let mut changed = reference.clone();
    changed.proof_hash.clone_from(&next.proof_hash);
    assert!(db.retain_reach_provenance(root, &[changed], [Ok(next.clone())]).is_err());
    assert!(
        db.reach_provenance_proof(root, &next.proof_hash)?.is_none(),
        "a conflicting original reference rolls back the newly inserted proof too"
    );
    let fault: Result<(), StorageError> = db.write_transaction(|| {
        db.retain_reach_provenance(root, &[], [Ok(next.clone())])?;
        Err(StorageError::Integrity("injected before intent commit"))
    });
    assert!(fault.is_err(), "the owner fault must abort its nested proof changes");
    assert!(db.reach_provenance_proof(root, &next.proof_hash)?.is_none());
    assert_eq!(db.reach_provenance_proof_hashes()?, vec![proof.proof_hash]);
    assert_eq!(db.reach_provenance_references()?, vec![reference]);
    assert!(db.retain_reach_provenance(&d(80), &[], [Ok(retained)]).is_err());
    Ok(())
}

#[test]
fn cr_provenance_collection_preserves_live_originals_and_rolls_back_with_owner() -> TestResult {
    let temp = tempfile::TempDir::new()?;
    let index = AccountIndex::open(temp.path())?;
    let (proof, reference, policy) = original()?;
    let root = &policy.body.account_anchor;
    index.create_account("acct", root)?;
    let key = AccountDbKey::generate()?;
    let db = AccountDb::open(&index, "acct", &key)?;
    let next = advanced(&proof)?;
    let mut body = policy.body.clone();
    body.operation_id = d(22);
    body.expected_revision = 1;
    body.revision = 2;
    body.authority_head_hash = custody::object_hash(&next.authority.publication.record)?;
    body.issued_at = NOW + 1;
    body.expires_at = NOW + 301;
    let signer =
        ramflux_crypto::custody::SelfSigningKey::from_vault_seed(&zeroize::Zeroizing::new([2; 32]));
    let current = ramflux_crypto::custody::verify_publication(&next.authority, NOW + 1)?;
    let update = signer.sign_reach_policy(body, &current, NOW + 1)?;
    let next_reference = SignerReference {
        object_hash: custody::framed_hash(wire::OPERATION_HASH_DOMAIN, &update)?,
        authority_head_hash: update.body.authority_head_hash.clone(),
        proof_hash: next.proof_hash.clone(),
        ..reference.clone()
    };
    db.retain_reach_provenance(
        root,
        &[reference.clone(), next_reference.clone()],
        [Ok(proof.clone()), Ok(next.clone())],
    )?;
    let fault: Result<(), StorageError> = db.write_transaction(|| {
        db.collect_reach_provenance(root, std::slice::from_ref(&reference))?;
        Err(StorageError::Integrity("injected after collection before owner commit"))
    });
    assert!(fault.is_err(), "the injected owner failure must escape the transaction");
    assert_eq!(
        db.reach_provenance_references()?.len(),
        2,
        "owner failure restores both references"
    );
    assert!(
        db.reach_provenance_proof(root, &next.proof_hash)?.is_some(),
        "owner rollback must restore the collected proof body"
    );
    let mut missing = reference.clone();
    missing.object_hash = d(23);
    assert!(
        db.collect_reach_provenance(root, &[missing]).is_err(),
        "unknown live selectors must refuse before deletion"
    );
    assert!(
        db.collect_reach_provenance(&d(24), &[]).is_err(),
        "another root cannot collect this account's originals"
    );
    assert_eq!(
        db.reach_provenance_references()?.len(),
        2,
        "unknown live objects cannot authorize GC"
    );
    db.collect_reach_provenance(root, std::slice::from_ref(&reference))?;
    assert_eq!(
        db.reach_provenance_references()?,
        vec![reference.clone()],
        "collection must leave exactly the pinned original reference"
    );
    assert!(
        db.reach_provenance_proof(root, &next.proof_hash)?.is_none(),
        "an unreferenced successor proof must be collected"
    );
    drop(db);
    let db = AccountDb::open(&index, "acct", &key)?;
    let retained = db.reach_provenance_proof(root, &reference.proof_hash)?.ok_or("pinned proof")?;
    ramflux_crypto::contact_reach::verify_historical_policy(&policy, &retained)?;
    assert!(
        db.reach_provenance_proof(root, &next.proof_hash)?.is_none(),
        "reopening must preserve committed collection"
    );
    Ok(())
}

#[test]
fn cr_provenance_individual_record_byte_limit_precedes_decode() -> TestResult {
    let temp = tempfile::TempDir::new()?;
    let index = AccountIndex::open(temp.path())?;
    index.create_account("acct", "principal")?;
    let db = AccountDb::open(&index, "acct", &AccountDbKey::generate()?)?;
    db.persist_actor_state(&proof_key(&d(90))?, &"x".repeat(MAX_PROOF_BYTES + 1))?;
    assert!(matches!(
        db.reach_provenance_proof(&d(91), &d(90)),
        Err(StorageError::SegmentResourceCapacity { .. })
    ));
    let text = format!("\0{}", "é".repeat(MAX_PROOF_BYTES / 2 + 1));
    db.connection.execute(
        "UPDATE runtime_actor_state SET state_json=?1 WHERE state_kind=?2",
        params![text, proof_key(&d(90))?],
    )?;
    assert!(
        matches!(
            db.load_bounded_actor_state::<serde_json::Value>(&proof_key(&d(90))?, MAX_PROOF_BYTES),
            Err(StorageError::SegmentResourceCapacity { .. })
        ),
        "bounded actor reads must count NUL and Unicode bytes before allocating or decoding"
    );
    assert!(
        matches!(
            db.reach_provenance_proof(&d(91), &d(90)),
            Err(StorageError::SegmentResourceCapacity { .. })
        ),
        "a malformed TEXT row cannot hide bytes behind Unicode character counts or a NUL"
    );
    Ok(())
}
