// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Cold stage/account commit boundaries; an orphan encrypted stage grants no resume permission.
use super::*;
use ramflux_crypto::custody::pairing::PairingRole;

#[test]
fn pairing_full_cold_prelink_stage_refuses_resume_until_exact_account_commit() -> TestResult {
    let (root, db) = crate::tests::test_db("cold-stage-prelink")?;
    let stage = db.create_full_stage_for_test(local_stage_record_fixture()?, 604_900)?;
    let reference = stage.reference().clone();
    let digest = stage.resume_record()?.stage_digest()?;
    let mut row = linked_row()?;
    row.context = Some(reference.to_wire_bytes()?);
    drop(stage);
    drop(db);
    let index = AccountIndex::open(&root)?;
    assert!(
        AccountDb::open(&index, "acct", &AccountDbKey::derive("acct", b"wrong-data-password"))
            .is_err(),
        "test: unlinked stage made the original account key unnecessary"
    );
    let db =
        AccountDb::open(&index, "acct", &AccountDbKey::derive("acct", b"storage-test-secret"))?;
    assert!(db.pairing_live_rows()?.is_empty(), "test: stage commit invented an account link");
    assert!(
        db.open_full_transfer_stage(&row.operation_id, PairingRole::Initiator, 100).is_err(),
        "test: cold orphan files granted resume without an account commit"
    );
    // Only the actual account writer can retain the exact authenticated local reference.
    db.put_pairing_live(&row)?;
    drop(db);
    let db =
        AccountDb::open(&index, "acct", &AccountDbKey::derive("acct", b"storage-test-secret"))?;
    let reopened = db.open_full_transfer_stage(&row.operation_id, PairingRole::Initiator, 100)?;
    assert_eq!(
        reopened.resume_record()?.stage_digest()?,
        digest,
        "test: cold account commit reopened another stage record"
    );
    assert!(
        reopened.reference() == &reference,
        "test: cold resume changed its exact local binding"
    );
    assert_eq!(
        db.recover_pairing()?.admission,
        Admission::Closed,
        "test: a data-only stage link granted ordinary native admission"
    );
    Ok(())
}

#[test]
fn pairing_full_cold_prelink_missing_or_corrupt_key_never_opens_data() -> TestResult {
    for corrupt in [false, true] {
        let (root, db) = crate::tests::test_db("cold-stage-provider-boundary")?;
        let stage = db.create_full_stage_for_test(local_stage_record_fixture()?, 604_900)?;
        let mut row = linked_row()?;
        let reference = stage.reference().clone();
        row.context = Some(reference.to_wire_bytes()?);
        let key = root
            .join("custody_accounts/acct/full-transfer")
            .join(&reference.stage_id)
            .join("stage.key");
        drop(stage);
        // Simulate retained account metadata with unavailable provider bytes at reopen.
        if corrupt {
            std::fs::write(&key, b"incomplete-wrapper")?;
        } else {
            std::fs::remove_file(&key)?;
        }
        db.put_pairing_live(&row)?;
        drop(db);
        let index = AccountIndex::open(&root)?;
        let db =
            AccountDb::open(&index, "acct", &AccountDbKey::derive("acct", b"storage-test-secret"))?;
        assert!(
            db.open_full_transfer_stage(&row.operation_id, PairingRole::Initiator, 100).is_err(),
            "test: missing/corrupt independent stage key became a resumable data owner"
        );
        assert_eq!(
            db.pairing_live_rows()?,
            vec![row],
            "test: provider failure silently discharged the retained reconciliation link"
        );
        assert_eq!(
            db.recover_pairing()?.admission,
            Admission::Closed,
            "test: unavailable stage key granted ordinary native admission"
        );
    }
    Ok(())
}
