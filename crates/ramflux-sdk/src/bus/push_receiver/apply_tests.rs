// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! First-leg stale suffix: after<=C<covered applies the useful remainder into W2.
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use super::apply::{
    ApplyError, ApplyFault, ApplyLoss, ApplyOutcome, ApplyPage, ApplyPoint, apply_page,
    apply_point, cover_held, run as with_reject, validate_page, validate_point,
};
use ramflux_storage::{
    AccountDb, AccountDbKey, AccountIndex, ReceiveCoverResult, ReceiveExpectation,
    ReceiveLedgerSnap, ReceiveStage, ReceiveStageResult, StorageError,
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
fn held_w1_advances_cursor() -> Result<(), ApplyError> {
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
    assert_eq!(
        apply_page(db, expected(db, 10)?, 1, stale)?,
        ApplyOutcome::NeedStage { sequence: 12, cursor: 11 }
    );
    let before = snap(db)?;
    assert_eq!(before.cursor, 11);
    assert_eq!(before.receipts, vec![(12, "staged".into())]);
    assert_eq!(before.intents, Vec::<u64>::new());
    assert_eq!(before.work, 1);

    assert_eq!(cover_held(db, expected(db, 11)?, 1, 12)?, ReceiveCoverResult::Covered);
    let after = snap(db)?;
    assert_eq!(after.cursor, 12, "held W2 must advance C over the held sequence");
    assert_eq!(after.receipts, vec![(12, "held".into())]);
    assert_eq!(after.intents, Vec::<u64>::new(), "held cover writes no ACK intent");
    assert_eq!(after.work, 1, "held cover keeps the work row");
    Ok(())
}

#[test]
#[allow(clippy::too_many_lines)]
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

    // Staged 12 is not finished: the page stops before it, keeps its receipt and work, and
    // writes no ACK intent. Only the W1 outcome (here completed) lets the same page finish.
    assert_eq!(
        apply_page(db, expected(db, 10)?, 1, stale)?,
        ApplyOutcome::NeedStage { sequence: 12, cursor: 11 }
    );
    let held_back = snap(db)?;
    assert_eq!(held_back.cursor, 11);
    assert_eq!(
        held_back.losses,
        vec![(1, 10, 10, "expired".into()), (11, 11, 1, "expired".into())]
    );
    assert_eq!(held_back.receipts, vec![(12, "staged".into())]);
    assert_eq!(held_back.intents, Vec::<u64>::new());
    assert_eq!(held_back.work, 1);
    assert!(!held_back.outbox.is_empty(), "the snapshot carries the gap outbox rows");

    db.set_receipt_disposition_for_test(12, "completed")?;
    assert_eq!(apply_page(db, expected(db, 11)?, 1, stale)?, ApplyOutcome::Covered { cursor: 20 });
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
    assert!(once.outbox.len() > held_back.outbox.len(), "the completed step adds gap outbox rows");
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
            "e",
            &ApplyPoint::Gone { seq: 21, observed_issued: 20, reason: "expired", incarnation: "e" }
        ),
        Err(ApplyError::Protocol("receive point gone observed below sequence"))
    ));
    assert!(matches!(
        validate_point(21, "t", "e", &ApplyPoint::Entry { seq: 22, target: "t", incarnation: "e" }),
        Err(ApplyError::Protocol("receive point sequence mismatch"))
    ));
    assert!(matches!(
        validate_point(
            21,
            "t",
            "e",
            &ApplyPoint::Gone { seq: 21, observed_issued: 30, reason: "bogus", incarnation: "e" }
        ),
        Err(ApplyError::Protocol("receive point gone reason invalid"))
    ));
    assert_eq!(
        apply_point(
            db,
            expected(db, 20)?,
            1,
            21,
            ApplyPoint::TooLarge { seq: 21, retain_until: 9_000, incarnation: "e" },
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
            ApplyPoint::Gone { seq: 22, observed_issued: 30, reason: "unknown", incarnation: "e" },
        )?,
        ApplyOutcome::Covered { cursor: 22 }
    );
    let gone = snap(db)?;
    assert_eq!(gone.cursor, 22);
    assert!(gone.losses.iter().any(|row| row.0 == 22 && row.3 == "unknown"));
    assert_eq!(gone.intents, vec![12, 21], "gone writes no intent");
    Ok(())
}

fn refuses(page: &ApplyPage<'_>, message: &str) {
    match validate_page(page) {
        Err(ApplyError::Protocol(got)) => assert_eq!(got, message),
        other => panic!("expected {message}, got {other:?}"),
    }
}

fn loss(from_seq: u64, to_seq: u64, reason: &str) -> ApplyLoss<'_> {
    ApplyLoss { from_seq, to_seq, reason }
}

#[test]
fn validate_page_refuses_each_bound_exactly() {
    refuses(&page(5, 4, 10, &[], &[], None), "receive page after exceeds covered");
    refuses(&page(0, 10, 5, &[], &[], None), "receive page covered exceeds issued");
    refuses(
        &ApplyPage { settled: 11, ..page(0, 10, 10, &[], &[], None) },
        "receive page settled exceeds issued",
    );
    refuses(&page(0, 10, 10, &[0], &[], None), "receive page entry outside coverage");
    refuses(&page(0, 10, 10, &[11], &[], None), "receive page entry outside coverage");
    refuses(&page(1, 10, 10, &[1], &[], None), "receive page entry outside coverage");
    refuses(&page(0, 10, 10, &[3, 3], &[], None), "receive page entry not sorted unique");
    refuses(&page(0, 10, 10, &[4, 3], &[], None), "receive page entry not sorted unique");
    refuses(
        &page(0, 10, 10, &[], &[loss(0, 3, "expired")], None),
        "receive page loss outside coverage",
    );
    refuses(
        &page(0, 10, 10, &[], &[loss(1, 11, "expired")], None),
        "receive page loss outside coverage",
    );
    refuses(
        &page(3, 10, 10, &[], &[loss(3, 4, "expired")], None),
        "receive page loss outside coverage",
    );
    refuses(&page(0, 10, 10, &[], &[loss(5, 4, "expired")], None), "receive page loss inverted");
    refuses(
        &page(0, 10, 10, &[], &[loss(1, 5, "expired"), loss(5, 8, "expired")], None),
        "receive page loss overlap",
    );
    refuses(
        &page(0, 10, 10, &[3], &[loss(1, 5, "expired")], None),
        "receive page entry overlaps loss",
    );
    refuses(
        &page(0, 10, 10, &[], &[loss(1, 5, "bogus")], None),
        "receive page loss reason invalid",
    );
    refuses(&page(0, 10, 20, &[], &[], Some(12)), "receive page marker invalid");
    refuses(&page(0, 10, 10, &[], &[], Some(11)), "receive page marker invalid");
    refuses(
        &ApplyPage { more: false, ..page(0, 10, 20, &[], &[], None) },
        "receive page more mismatch",
    );
}

#[test]
fn validate_page_inclusive_boundaries_are_accepted() {
    assert!(validate_page(&page(0, 1, 5, &[1], &[], None)).is_ok(), "entry at after+1");
    assert!(validate_page(&page(0, 10, 10, &[10], &[], None)).is_ok(), "entry at covered");
    let whole = [loss(1, 10, "expired")];
    assert!(
        validate_page(&page(0, 10, 10, &[], &whole, None)).is_ok(),
        "loss exactly (after, covered]"
    );
    assert!(
        validate_point(
            21,
            "t",
            "e",
            &ApplyPoint::Gone { seq: 21, observed_issued: 21, reason: "expired", incarnation: "e" }
        )
        .is_ok(),
        "observed_issued equal to the requested sequence"
    );
}

#[test]
fn validate_point_refuses_each_mismatch_exactly() {
    assert!(matches!(
        validate_point(1, "t", "e", &ApplyPoint::Entry { seq: 1, target: "u", incarnation: "e" }),
        Err(ApplyError::Protocol("receive point target mismatch"))
    ));
    assert!(matches!(
        validate_point(
            1,
            "t",
            "e",
            &ApplyPoint::TooLarge { seq: 2, retain_until: 9, incarnation: "e" }
        ),
        Err(ApplyError::Protocol("receive point sequence mismatch"))
    ));
    assert!(matches!(
        validate_point(
            1,
            "t",
            "e",
            &ApplyPoint::Gone { seq: 1, observed_issued: 1, reason: "expired", incarnation: "x" }
        ),
        Err(ApplyError::Protocol("receive point incarnation mismatch"))
    ));
}

#[test]
fn point_reply_over_unfinished_receipt_stops_then_settles() -> Result<(), ApplyError> {
    for disposition in ["staged", "held"] {
        let points = [
            ApplyPoint::Entry { seq: 1, target: "t", incarnation: "e" },
            ApplyPoint::TooLarge { seq: 1, retain_until: 9_000, incarnation: "e" },
            ApplyPoint::Gone { seq: 1, observed_issued: 1, reason: "unknown", incarnation: "e" },
        ];
        for point in points {
            let harness = open()?;
            let db = &harness.db;
            stage(db, 0, 1)?;
            db.set_receipt_disposition_for_test(1, disposition)?;
            let before = snap(db)?;
            assert_eq!(
                apply_point(db, expected(db, 0)?, 1, 1, point)?,
                ApplyOutcome::NeedStage { sequence: 1, cursor: 0 },
                "{disposition} receipt stops the point reply {point:?}"
            );
            assert_eq!(
                snap(db)?,
                before,
                "{disposition} stop writes no loss, intent or outbox row"
            );
            assert_eq!(snap(db)?.receipts, vec![(1, disposition.to_owned())]);
            assert_eq!(snap(db)?.work, 1, "{disposition} work survives the stop");

            db.set_receipt_disposition_for_test(1, "completed")?;
            assert_eq!(
                apply_point(db, expected(db, 0)?, 1, 1, point)?,
                ApplyOutcome::Covered { cursor: 1 },
                "completed W1 lets the same reply settle {point:?}"
            );
            let settled = snap(db)?;
            assert_eq!(settled.cursor, 1);
            assert_eq!(settled.intents, vec![1]);
            assert_eq!(settled.work, 0);
            assert_eq!(settled.receipts, Vec::<(u64, String)>::new());
        }
    }
    Ok(())
}

#[test]
fn point_and_page_mismatches_write_nothing() -> Result<(), ApplyError> {
    let harness = open()?;
    let db = &harness.db;
    let before = snap(db)?;
    let entry = ApplyPoint::Entry { seq: 1, target: "t", incarnation: "x" };
    let large = ApplyPoint::TooLarge { seq: 1, retain_until: 9, incarnation: "x" };
    let gone = ApplyPoint::Gone { seq: 1, observed_issued: 1, reason: "expired", incarnation: "x" };
    for point in [entry, large, gone] {
        assert!(matches!(
            apply_point(db, expected(db, 0)?, 1, 1, point),
            Err(ApplyError::Protocol("receive point incarnation mismatch"))
        ));
    }
    let wrong_e = ApplyPage { incarnation: "x", ..page(0, 1, 1, &[], &[], None) };
    assert!(matches!(
        apply_page(db, expected(db, 0)?, 1, wrong_e),
        Err(ApplyError::Protocol("receive page incarnation mismatch"))
    ));
    let wrong_target = ApplyPage { target: "u", ..page(0, 1, 1, &[], &[], None) };
    assert!(matches!(
        apply_page(db, expected(db, 0)?, 1, wrong_target),
        Err(ApplyError::Protocol("receive page target mismatch"))
    ));
    assert_eq!(snap(db)?, before, "refused replies write nothing");
    Ok(())
}
