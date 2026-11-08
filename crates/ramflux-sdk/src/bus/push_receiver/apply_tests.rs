// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! First-leg stale suffix: after<=C<covered applies the useful remainder into W2.
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use super::apply::{
    ApplyError, ApplyFault, ApplyLoss, ApplyOutcome, ApplyPage, ApplyPoint, apply_page,
    apply_point, run as with_reject, validate_page, validate_point,
};
use ramflux_storage::{
    AccountDb, AccountDbKey, AccountIndex, ReceiveExpectation, ReceiveLedgerSnap, ReceiveStage,
    ReceiveStageResult, StorageError,
};

struct Harness {
    _root: tempfile::TempDir,
    db: AccountDb,
}

fn open() -> Result<Harness, StorageError> {
    let root = tempfile::tempdir().expect("tmp");
    let index = AccountIndex::open(root.path())?;
    index.create_account("acct", "principal")?;
    let db =
        AccountDb::open(&index, "acct", &AccountDbKey::derive("acct", b"storage-test-secret"))?;
    db.install_receive_ledger_schema()?;
    db.seed_receive_epoch_for_test("t", "e")?;
    Ok(Harness { _root: root, db })
}

fn expected(db: &AccountDb, cursor: u64) -> Result<ReceiveExpectation<'static>, StorageError> {
    Ok(ReceiveExpectation {
        target: "t",
        incarnation: "e",
        cursor,
        generation: 1,
        erasure_generation: db.privacy_erasure_generation()?,
    })
}

fn wire(seq: u64) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({"inbox_seq":seq,"target_delivery_id":"t","envelope":{
        "schema":"test","version":1,"domain":"test","signing_key_id":"key","signature_alg":"ed25519","signature":"sig",
        "envelope_id":"env","source_principal_id":"source","source_device_id":"device","target_delivery_id":"t",
        "delivery_class":"opaque_event","priority":"normal","ttl":60,"created_at":1,"encrypted_payload":"cipher","payload_hash":"hash"
    }}))
    .expect("entry")
}

fn stage(db: &AccountDb, cursor: u64, sequence: u64) -> Result<(), StorageError> {
    let bytes = wire(sequence);
    let result = db.receive_transaction(expected(db, cursor)?, 1, |tx| {
        tx.stage(ReceiveStage {
            target: "t",
            incarnation: "e",
            sequence,
            entry_json: &bytes,
            admission_key: "authenticated-key",
            retain_until: 100,
            first_seen: 1,
        })
    })?;
    assert!(matches!(result, ReceiveStageResult::Staged), "{result:?}");
    Ok(())
}

fn page<'a>(
    after: u64,
    covered: u64,
    issued: u64,
    entries: &'a [u64],
    known_losses: &'a [ApplyLoss<'a>],
    oversize_next: Option<u64>,
) -> ApplyPage<'a> {
    ApplyPage {
        target: "t",
        incarnation: "e",
        after,
        covered,
        issued,
        settled: 0,
        entries,
        known_losses,
        oversize_next,
        more: covered < issued,
    }
}

fn snap(db: &AccountDb) -> Result<ReceiveLedgerSnap, StorageError> {
    db.receive_ledger_snap_for_test("t")
}

#[test]
fn stale_page_suffix_progress() -> Result<(), ApplyError> {
    let harness = open()?;
    let db = &harness.db;
    let prefix = [ApplyLoss { from_seq: 1, to_seq: 10, reason: "expired" }];
    assert_eq!(
        apply_page(db, expected(db, 0)?, 1, page(0, 10, 20, &[], &prefix, None))?,
        ApplyOutcome::Covered { cursor: 10 }
    );
    stage(db, 10, 12)?;
    let losses = [
        ApplyLoss { from_seq: 6, to_seq: 11, reason: "expired" },
        ApplyLoss { from_seq: 13, to_seq: 20, reason: "nacked" },
    ];
    let stale = page(5, 20, 20, &[12], &losses, None);
    let before = snap(db)?;
    let rejected =
        with_reject(ApplyFault::RejectStale, || apply_page(db, expected(db, 10)?, 1, stale));
    assert!(
        matches!(rejected, Err(ApplyError::Protocol("receive page cursor stale"))),
        "{rejected:?}"
    );
    assert_eq!(snap(db)?, before, "rejecting a stale-C page leaves the suffix unapplied");

    assert_eq!(apply_page(db, expected(db, 10)?, 1, stale)?, ApplyOutcome::Covered { cursor: 20 });
    let once = snap(db)?;
    assert_eq!(once.cursor, 20);
    assert_eq!(
        once.losses,
        vec![
            (1, 10, 10, "expired".into()),
            (11, 11, 1, "expired".into()),
            (13, 20, 8, "nacked".into()),
        ]
    );
    assert_eq!(once.receipts, Vec::<(u64, String)>::new());
    assert_eq!(once.intents, vec![12]);
    assert_eq!(once.work, 0);
    assert_eq!(
        apply_page(db, expected(db, 20)?, 1, stale)?,
        ApplyOutcome::AlreadyCovered { cursor: 20 }
    );
    assert_eq!(snap(db)?, once, "re-applying the page has no duplicate effect");

    let oversize = page(20, 20, 30, &[], &[], Some(21));
    assert_eq!(
        apply_page(db, expected(db, 20)?, 1, oversize)?,
        ApplyOutcome::NeedPoint { seq: 21, cursor: 20 }
    );
    assert!(matches!(
        validate_page(&page(20, 20, 30, &[], &[], None)),
        Err(ApplyError::Protocol("receive page does not progress"))
    ));
    assert!(matches!(
        validate_point(
            21,
            "t",
            &ApplyPoint::Gone { seq: 21, observed_issued: 20, reason: "expired" }
        ),
        Err(ApplyError::Protocol("receive point gone observed below sequence"))
    ));
    assert!(matches!(
        validate_point(21, "t", &ApplyPoint::Entry { seq: 22, target: "t" }),
        Err(ApplyError::Protocol("receive point sequence mismatch"))
    ));
    assert!(matches!(
        validate_point(
            21,
            "t",
            &ApplyPoint::Gone { seq: 21, observed_issued: 30, reason: "bogus" }
        ),
        Err(ApplyError::Protocol("receive point gone reason invalid"))
    ));
    assert_eq!(
        apply_point(
            db,
            expected(db, 20)?,
            1,
            21,
            ApplyPoint::TooLarge { seq: 21, retain_until: 9_000 },
        )?,
        ApplyOutcome::Covered { cursor: 21 }
    );
    let too_large = snap(db)?;
    assert_eq!(too_large.cursor, 21);
    assert!(too_large.losses.iter().any(|row| row.0 == 21 && row.1 == 21 && row.3 == "oversize"));
    assert_eq!(too_large.intents, vec![12, 21]);
    assert_eq!(
        apply_point(
            db,
            expected(db, 21)?,
            1,
            22,
            ApplyPoint::Gone { seq: 22, observed_issued: 30, reason: "unknown" },
        )?,
        ApplyOutcome::Covered { cursor: 22 }
    );
    let gone = snap(db)?;
    assert_eq!(gone.cursor, 22);
    assert!(gone.losses.iter().any(|row| row.0 == 22 && row.3 == "unknown"));
    assert_eq!(gone.intents, vec![12, 21], "gone writes no intent");
    Ok(())
}
