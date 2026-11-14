// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Actual encrypted full/native merge retains independent denials and their original proof closure.
use super::*;
use crate::{AccountDb, AccountDbKey, AccountIndex, BackupDatabase};
use ramflux_protocol::{contact_reach as wire, custody};
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
const NOW: u64 = 1_700_000_100;
fn d(n: u8) -> String {
    ramflux_protocol::encode_base64url([n; 32])
}

fn seed(db: &AccountDb, peer: u8, expected: u64) -> TestResult<String> {
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../ramflux-crypto/tests/fixtures/custody_v3.json"
    ))?;
    let record: custody::Envelope<custody::DeviceSet> =
        serde_json::from_value(fixture.get("record").ok_or("native record")?.clone())?;
    let current = ramflux_crypto::custody::verify_record(&record, NOW, None, None)?;
    let root = record.body.account_anchor.clone();
    let key =
        ramflux_crypto::custody::SelfSigningKey::from_vault_seed(&zeroize::Zeroizing::new([2; 32]));
    let subject = wire::Subject::Friendship { root: d(peer) };
    let update = key.sign_reach_admission(
        wire::Admission {
            version: 2,
            operation_id: d(peer + 1),
            recipient_root: root.clone(),
            home_head_hash: d(50),
            expected_revision: expected,
            subject: subject.clone(),
            decision: wire::Decision::Block,
            permissions: None,
            grant_until: None,
            authority_head_hash: custody::object_hash(&record)?,
            master_certificate_hash: custody::object_hash(&record.body.master_certificate)?,
            actor: record.body.master_certificate.body.primary_device_ref.clone(),
            notice_hash: None,
            evidence_hash: None,
            issued_at: NOW,
            expires_at: NOW + 300,
        },
        &current,
        NOW,
    )?;
    let denial = StateRecord::Block { subject: subject.clone(), update: update.clone() };
    let floor = StateRecord::Floor {
        subject,
        revision: expected + 1,
        denied: true,
        erase_generation: expected + 1,
        erased: true,
    };
    let mut proof = wire::ProvenanceAuthority {
        proof_hash: String::new(),
        authority: custody::CustodyAuthority {
            publication: custody::Publication { record, compacted_ids: None },
            custodian_publication: None,
        },
        custodian_history: vec![],
    };
    proof.proof_hash = proof.content_hash()?;
    ramflux_crypto::contact_reach::verify_historical_admission(&update, &proof)?;
    let mut signers = wire::record_signers(&denial)?;
    for signer in &mut signers {
        signer.proof_hash.clone_from(&proof.proof_hash);
    }
    db.persist_actor_state(
        "reach/provenance",
        &serde_json::json!({"signers":signers,"authorities":[proof]}),
    )?;
    db.persist_client_record("reach", "state", &serde_json::json!({
        "root":root,"revision":100-expected,"records":[],"restrictions":{"block":denial,"floor":floor}
    }))?;
    Ok(root)
}

#[test]
fn cr_retained_denials_and_proofs_survive_encrypted_full_and_native_restore() -> TestResult {
    for native in [false, true] {
        merge_mode(native)?;
    }
    Ok(())
}
fn merge_mode(native: bool) -> TestResult {
    let temp = tempfile::TempDir::new()?;
    let source_index = AccountIndex::open(temp.path().join("source"))?;
    let local_index = AccountIndex::open(temp.path().join("local"))?;
    source_index.create_account("acct", "principal")?;
    local_index.create_account("acct", "principal")?;
    let source = AccountDb::open(&source_index, "acct", &AccountDbKey::generate()?)?;
    let local = AccountDb::open(&local_index, "acct", &AccountDbKey::generate()?)?;
    let root = seed(&local, 20, 2)?;
    seed(&source, 30, 4)?;
    let incoming = temp.path().join("incoming.db");
    let input = source.write_backup_snapshot(&incoming)?;
    let merged_path = temp.path().join("merged.db");
    let output = local.write_backup_snapshot(&merged_path)?;
    let mut merged = BackupDatabase::open(&merged_path, &output.key)?;
    if native {
        merged.merge_native_backup(&incoming, &input.key, || Ok(()))?;
    } else {
        merged.merge_backup(&incoming, &input.key, || Ok(()))?;
    }
    let raw = read(&merged.db, "main", KEY)?.ok_or("restore restrictions")?;
    let staged: Restrictions = wire::decode(&raw, MAX_STATE_BYTES)?;
    assert_eq!(staged.root, root);
    assert_eq!(
        staged.records.len(),
        4,
        "newer local mirror cannot overwrite an incoming independent denial"
    );
    assert_eq!(
        staged
            .records
            .iter()
            .filter(|r| matches!(r, StateRecord::Floor { erased: true, .. }))
            .count(),
        2
    );
    let proofs: serde_json::Value = serde_json::from_slice(
        &read(&merged.db, "main", "reach/provenance")?.ok_or("proof union")?,
    )?;
    assert_eq!(
        proofs.get("signers").and_then(serde_json::Value::as_array).ok_or("signer array")?.len(),
        2
    );
    source.persist_client_record(
        "reach",
        "state",
        &serde_json::json!({"root":d(99),"records":[],"restrictions":{}}),
    )?;
    let bad_path = temp.path().join("bad.db");
    let bad = source.write_backup_snapshot(&bad_path)?;
    let result = if native {
        merged.merge_native_backup(&bad_path, &bad.key, || Ok(()))
    } else {
        merged.merge_backup(&bad_path, &bad.key, || Ok(()))
    };
    assert!(
        result.is_err(),
        "different-owner restriction import fails the whole encrypted generation"
    );
    assert_eq!(read(&merged.db, "main", KEY)?.ok_or("retained after refusal")?, raw);
    Ok(())
}

#[test]
fn cr_restore_restriction_counts_refuse_during_decode() -> TestResult {
    let floor = StateRecord::Floor {
        subject: wire::Subject::Friendship { root: d(80) },
        revision: 1,
        denied: true,
        erase_generation: 1,
        erased: true,
    };
    let records = vec![floor.clone(); 8193];
    let bytes = ramflux_protocol::canonical_json_bytes(&Restrictions { root: d(81), records })?;
    assert!(wire::decode::<Restrictions>(&bytes, MAX_STATE_BYTES).is_err());
    let map: BTreeMap<_, _> = (0..8193).map(|index| (index.to_string(), floor.clone())).collect();
    let saved = serde_json::json!({"root":d(81),"records":[],"restrictions":map});
    assert!(
        ramflux_protocol::parse_i_json::<Saved>(&ramflux_protocol::canonical_json_bytes(&saved)?)
            .is_err()
    );
    Ok(())
}

#[test]
fn cr_empty_restriction_restore_still_requires_fresh_reconciliation() -> TestResult {
    for native in [false, true] {
        let temp = tempfile::TempDir::new()?;
        let index = AccountIndex::open(temp.path().join("account"))?;
        index.create_account("acct", "principal")?;
        let source = AccountDb::open(&index, "acct", &AccountDbKey::generate()?)?;
        source.persist_client_record(
            "reach",
            "state",
            &serde_json::json!({
                "root":d(82),"revision":1,"records":[],"restrictions":{},"positive_pending":false
            }),
        )?;
        let incoming = temp.path().join("incoming.db");
        let snapshot = source.write_backup_snapshot(&incoming)?;
        let destination = temp.path().join("destination.db");
        let copied = source.write_backup_snapshot(&destination)?;
        let mut merged = BackupDatabase::open(&destination, &copied.key)?;
        if native {
            merged.merge_native_backup(&incoming, &snapshot.key, || Ok(()))?;
        } else {
            merged.merge_backup(&incoming, &snapshot.key, || Ok(()))?;
        }
        let staged: Restrictions = wire::decode(
            &read(&merged.db, "main", KEY)?.ok_or("reconciliation stage")?,
            MAX_STATE_BYTES,
        )?;
        assert_eq!(staged.root, d(82));
        assert!(
            staged.records.is_empty(),
            "absence of a negative is not restored positive authority"
        );
    }
    Ok(())
}
