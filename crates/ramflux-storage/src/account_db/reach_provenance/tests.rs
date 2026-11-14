// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Actual encrypted backup generations preserve both sets of historical originals.
use super::*;
use crate::{AccountDb, AccountDbKey, AccountIndex, BackupDatabase};
use ramflux_protocol::custody::{self, CustodyAuthority, Publication};
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
const NOW: u64 = 1_700_000_100;
fn d(n: u8) -> String {
    ramflux_protocol::encode_base64url([n; 32])
}
fn pool(advance: bool) -> TestResult<Pool> {
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../ramflux-crypto/tests/fixtures/custody_v3.json"
    ))?;
    let mut record: custody::Envelope<custody::DeviceSet> =
        serde_json::from_value(fixture.get("record").ok_or("native fixture record")?.clone())?;
    let key =
        ramflux_crypto::custody::SelfSigningKey::from_vault_seed(&zeroize::Zeroizing::new([2; 32]));
    if advance {
        let mut body = record.body.clone();
        body.device_set_epoch += 1;
        body.previous_record_hash = Some(custody::object_hash(&record)?);
        body.issued_at = NOW + 1;
        record = key.sign_record(body)?;
    }
    let time = NOW + u64::from(advance);
    let authority = ramflux_crypto::custody::verify_record(&record, time, None, None)?;
    let head = custody::object_hash(&record)?;
    let certificate = custody::object_hash(&record.body.master_certificate)?;
    let update = key.sign_reach_policy(
        wire::ReachPolicy {
            version: 1,
            operation_id: d(if advance { 21 } else { 20 }),
            account_anchor: record.body.account_anchor.clone(),
            home_head_hash: d(30),
            expected_revision: u64::from(advance),
            revision: 1 + u64::from(advance),
            mode: wire::ReachMode::ContactsOnly,
            authority_head_hash: head.clone(),
            master_certificate_hash: certificate.clone(),
            actor: record.body.master_certificate.body.primary_device_ref.clone(),
            issued_at: time,
            expires_at: time + 300,
        },
        &authority,
        time,
    )?;
    let mut proof = ProvenanceAuthority {
        proof_hash: String::new(),
        authority: CustodyAuthority {
            publication: Publication { record, compacted_ids: None },
            custodian_publication: None,
        },
        custodian_history: vec![],
    };
    proof.proof_hash = proof.content_hash()?;
    ramflux_crypto::contact_reach::verify_historical_policy(&update, &proof)?;
    let reference = SignerReference {
        object_hash: custody::framed_hash(wire::OPERATION_HASH_DOMAIN, &update)?,
        object_kind: wire::ObjectKind::Policy,
        authority_head_hash: head,
        master_certificate_hash: certificate,
        proof_hash: proof.proof_hash.clone(),
    };
    Ok(Pool { signers: vec![reference], authorities: vec![proof] })
}
#[test]
fn cr_provenance_backup_merge_unions_originals_and_refuses_conflicts() -> TestResult {
    for native in [false, true] {
        let temp = tempfile::TempDir::new()?;
        let source_index = AccountIndex::open(temp.path().join("source"))?;
        let local_index = AccountIndex::open(temp.path().join("local"))?;
        source_index.create_account("acct", "principal")?;
        local_index.create_account("acct", "principal")?;
        let source = AccountDb::open(&source_index, "acct", &AccountDbKey::generate()?)?;
        let local = AccountDb::open(&local_index, "acct", &AccountDbKey::generate()?)?;
        let original = pool(false)?;
        let incoming = pool(true)?;
        source.persist_actor_state(KEY, &incoming)?;
        local.persist_actor_state(KEY, &original)?;
        let incoming_path = temp.path().join("incoming.db");
        let snapshot = source.write_backup_snapshot(&incoming_path)?;
        let merged_path = temp.path().join("merged.db");
        let copied = local.write_backup_snapshot(&merged_path)?;
        let mut merged = BackupDatabase::open(&merged_path, &copied.key)?;
        if native {
            merged.merge_native_backup(&incoming_path, &snapshot.key, || Ok(()))?;
        } else {
            merged.merge_backup(&incoming_path, &snapshot.key, || Ok(()))?;
        }
        let saved = read(&merged.db, "main")?.ok_or("merged historical pool")?;
        assert_eq!(
            saved.signers.len(),
            2,
            "both local and incoming original object references survive backup merge"
        );
        assert_eq!(
            saved.authorities.len(),
            2,
            "a newer authority cannot overwrite the original signing context"
        );
        let before = ramflux_protocol::canonical_json_bytes(&saved)?;
        let mut conflict = pool(true)?;
        conflict.signers.first_mut().ok_or("incoming reference")?.object_hash =
            original.signers.first().ok_or("local reference")?.object_hash.clone();
        source.persist_actor_state(KEY, &conflict)?;
        let conflict_path = temp.path().join("conflict.db");
        let bad = source.write_backup_snapshot(&conflict_path)?;
        let result = if native {
            merged.merge_native_backup(&conflict_path, &bad.key, || Ok(()))
        } else {
            merged.merge_backup(&conflict_path, &bad.key, || Ok(()))
        };
        assert!(
            result.is_err(),
            "a conflicting proof for one original object refuses the whole merge"
        );
        assert_eq!(
            ramflux_protocol::canonical_json_bytes(
                &read(&merged.db, "main")?.ok_or("pool after refusal")?
            )?,
            before,
            "merge refusal must preserve every prior historical proof byte"
        );
    }
    Ok(())
}
