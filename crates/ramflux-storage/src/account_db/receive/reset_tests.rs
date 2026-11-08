// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Incarnation reset, same-E freeze and the 64-value retired fence.
#![allow(clippy::expect_used, clippy::panic)]
use super::cover::{ReceiveCover, ReceiveCoverKind, ReceiveCoverResult, ReceiveGap};
use super::reset::{
    CURSOR_AHEAD, FaultKind, RETIRED_FENCE_CAP, ReceiveIssued, ReceiveReset, ReceiveResetReason,
    ReceiveResetResult, run as with_fault,
};
use super::stage_tests::{bytes, input, setup};
use super::*;
use crate::{AccountDb, ProjectionStore, StorageError};
use rusqlite::params;

fn expect<'a>(
    db: &AccountDb,
    incarnation: &'a str,
    cursor: u64,
) -> Result<ReceiveExpectation<'a>, StorageError> {
    Ok(ReceiveExpectation {
        target: "t",
        incarnation,
        cursor,
        generation: 1,
        erasure_generation: db.privacy_erasure_generation()?,
    })
}

fn epoch(db: &AccountDb) -> Result<(String, Vec<String>, u64, u64), StorageError> {
    let (incarnation, retired, activated, uncertain): (String, Vec<u8>, Vec<u8>, Vec<u8>) =
        db.connection.query_row(
            "SELECT incarnation_id,retired_incarnations,activated_cursor,legacy_uncertain_through FROM gateway_receive_epoch WHERE target_delivery_id='t'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )?;
    Ok((
        incarnation,
        super::retired_incarnations(&retired)?,
        u64::from_be_bytes(activated.try_into().expect("activated")),
        u64::from_be_bytes(uncertain.try_into().expect("uncertain")),
    ))
}

fn cursor(db: &AccountDb) -> Result<u64, StorageError> {
    db.receive_cursor("t")
}

fn reset_events(db: &AccountDb) -> Result<i64, StorageError> {
    Ok(db.connection.query_row(
        "SELECT count(*) FROM runtime_journal WHERE topic='inbox.reset'",
        [],
        |row| row.get(0),
    )?)
}

fn gap_events(db: &AccountDb) -> Result<i64, StorageError> {
    Ok(db.connection.query_row(
        "SELECT count(*) FROM runtime_journal WHERE topic='receive.gap'",
        [],
        |row| row.get(0),
    )?)
}

fn seed_unpublished_loss(db: &AccountDb, incarnation: &str) -> Result<(), StorageError> {
    db.connection.execute(
        "INSERT INTO gateway_inbox_loss VALUES('t',?1,?2,?2,?3,'unknown',1,'unavailable')",
        params![incarnation, 1u64.to_be_bytes().as_slice(), 1u64.to_be_bytes().as_slice()],
    )?;
    let keys = serde_json::json!({
        "source_key": format!("receive-gap:t:{incarnation}:1:1"),
        "target": "t",
        "incarnation": incarnation,
        "from_seq": 1,
        "to_seq": 1,
        "count": 1,
        "reason": "unknown",
        "classification": "unavailable",
    });
    db.connection.execute(
        "INSERT INTO runtime_outbox(table_name,change_kind,row_id,published,keys_json)
         VALUES('gateway_inbox_loss','insert',0,0,?1)",
        params![keys.to_string()],
    )?;
    Ok(())
}

fn put_held(db: &AccountDb, incarnation: &str, sequence: u64) -> Result<(), StorageError> {
    let seq = sequence.to_be_bytes();
    let wire = bytes(sequence);
    db.connection.execute(
        "INSERT INTO gateway_receive_receipt VALUES('t',?1,?2,'held',100,1)",
        params![incarnation, seq.as_slice()],
    )?;
    db.connection.execute(
        "INSERT INTO gateway_receive_work VALUES('t',?1,?2,?3,'authenticated-key',?4)",
        params![incarnation, seq.as_slice(), wire, i64::try_from(wire.len()).expect("bounded")],
    )?;
    Ok(())
}

fn stage_new(
    db: &AccountDb,
    incarnation: &str,
    cursor: u64,
    sequence: u64,
) -> Result<(), StorageError> {
    let wire = bytes(sequence);
    let mut page = input(&wire, sequence);
    page.incarnation = incarnation;
    db.receive_transaction(expect(db, incarnation, cursor)?, 1, |tx| tx.stage(page))?;
    Ok(())
}

fn reset_to(
    db: &AccountDb,
    incarnation: &str,
    cursor: u64,
    new_incarnation: &str,
    settled: u64,
    reason: ReceiveResetReason,
) -> Result<ReceiveResetResult, StorageError> {
    db.receive_transaction(expect(db, incarnation, cursor)?, 1, |tx| {
        tx.reset(ReceiveReset { new_incarnation, settled, reason })
    })
}

fn unverified_first_verified() -> Result<(), StorageError> {
    let (root, db) = setup("reset-u")?;
    db.connection.execute(
        "UPDATE gateway_receive_epoch SET incarnation_id='u', incarnation_verified=0 WHERE target_delivery_id='t'",
        [],
    )?;
    db.set_projection_checkpoint("gateway_receive_cursor:t", "100")?;
    db.publish_pending_receive_loss("t", "u", crate::unix_now())?;
    let result = reset_to(&db, "u", 100, "n", 30, ReceiveResetReason::IncarnationFirstVerified)?;
    assert_eq!(result, ReceiveResetResult::Reset);
    assert_eq!(cursor(&db)?, 30);
    let (incarnation, retired, activated, _) = epoch(&db)?;
    assert_eq!(incarnation, "n");
    assert_eq!(retired, vec!["u".to_owned()]);
    assert_eq!(activated, 30);
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn inbox_incarnation_reset() -> Result<(), StorageError> {
    let (root, db) = setup("reset-inbox")?;
    db.set_projection_checkpoint("gateway_receive_cursor:t", "100")?;
    seed_unpublished_loss(&db, "e")?;
    put_held(&db, "e", 40)?;
    db.send_direct_message("thread", "M", "peer", b"secret")?;
    db.connection.execute("INSERT INTO message_copy_binding VALUES('payload:hash','M')", [])?;
    let skipped = reset_to(&db, "e", 100, "n", 30, ReceiveResetReason::RouterReset)?;
    assert_eq!(skipped, ReceiveResetResult::PausedLoss, "WJ must run first");
    assert_eq!(cursor(&db)?, 100);
    db.publish_pending_receive_loss("t", "e", crate::unix_now())?;
    assert_eq!(gap_events(&db)?, 1);
    let unpublished: i64 = db.connection.query_row(
        "SELECT count(*) FROM runtime_outbox WHERE published=0 AND table_name='gateway_inbox_loss'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(unpublished, 0);
    match with_fault(FaultKind::BeforeCommit, || {
        reset_to(&db, "e", 100, "n", 30, ReceiveResetReason::RouterReset)
    }) {
        Err(StorageError::Integrity("receive reset before-commit")) => {}
        other => panic!("before-commit: {other:?}"),
    }
    assert_eq!(cursor(&db)?, 100, "before-commit keeps old C");
    let result = reset_to(&db, "e", 100, "n", 30, ReceiveResetReason::RouterReset)?;
    assert_eq!(result, ReceiveResetResult::Reset);
    assert_eq!(cursor(&db)?, 30, "C is first-page S, not zero");
    let (incarnation, retired, activated, uncertain) = epoch(&db)?;
    assert_eq!(incarnation, "n");
    assert_eq!(retired, vec!["e".to_owned()]);
    assert_eq!(activated, 30);
    assert_eq!(uncertain, 30);
    let prefix: i64 = db.connection.query_row(
        "SELECT count(*) FROM gateway_inbox_loss WHERE incarnation_id='n'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(prefix, 0, "zero prefix gap events");
    assert_eq!(reset_events(&db)?, 1);
    assert_eq!(gap_events(&db)?, 1, "WJ publishes pending old loss once");
    let due = db.receive_transaction(expect(&db, "e", 30)?, 1, |tx| tx.due_retained(64))?;
    assert_eq!(due, vec![40], "old held work stays local under retired E");
    stage_new(&db, "n", 30, 31)?;
    stage_new(&db, "n", 30, 50)?;
    assert_eq!(
        db.receive_transaction(expect(&db, "n", 30)?, 1, |tx| {
            tx.cover(ReceiveCover {
                sequence: 31,
                kind: ReceiveCoverKind::Terminal,
                gaps: &[],
                retain_until: 0,
            })
        })?,
        ReceiveCoverResult::Covered,
        "live 31 is delivered below old C=100"
    );
    assert_eq!(cursor(&db)?, 31);
    stage_new(&db, "n", 31, 33)?;
    assert_eq!(
        db.receive_transaction(expect(&db, "n", 31)?, 1, |tx| {
            tx.cover(ReceiveCover {
                sequence: 33,
                kind: ReceiveCoverKind::Terminal,
                gaps: &[ReceiveGap {
                    from_seq: 32,
                    to_seq: 32,
                    reason: "expired",
                    classification: "unavailable",
                }],
                retain_until: 0,
            })
        })?,
        ReceiveCoverResult::Covered,
        "same-E expiry crossing the settled cursor still yields a gap"
    );
    let expiry: i64 = db.connection.query_row(
        "SELECT count(*) FROM gateway_inbox_loss WHERE incarnation_id='n' AND classification='unavailable'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(expiry, 1);
    let bindings: i64 = db.connection.query_row(
        "SELECT count(*) FROM message_copy_binding WHERE copy_id='payload:hash'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(bindings, 1, "one effect per application marker");
    drop(db);
    std::fs::remove_dir_all(root)?;
    unverified_first_verified()
}

#[test]
#[allow(clippy::redundant_closure_for_method_calls)]
fn same_incarnation_regression() -> Result<(), StorageError> {
    let (root, db) = setup("reset-freeze")?;
    db.set_projection_checkpoint("gateway_receive_cursor:t", "100")?;
    let issued = db.receive_transaction(expect(&db, "e", 100)?, 1, |tx| tx.observe_issued(50))?;
    assert_eq!(issued, ReceiveIssued::Frozen);
    let freeze: String = db.connection.query_row(
        "SELECT last_event_id FROM projection_checkpoint WHERE projection_name='gateway_receive_freeze:t'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(freeze, CURSOR_AHEAD);
    put_held(&db, "e", 101)?;
    match db.receive_transaction(expect(&db, "e", 100)?, 1, |tx| {
        tx.cover(ReceiveCover {
            sequence: 101,
            kind: ReceiveCoverKind::Terminal,
            gaps: &[],
            retain_until: 0,
        })
    }) {
        Err(StorageError::Integrity(CURSOR_AHEAD)) => {}
        other => panic!("frozen cover: {other:?}"),
    }
    assert_eq!(cursor(&db)?, 100, "freeze writes no C");
    let later = db.receive_transaction(expect(&db, "e", 100)?, 1, |tx| tx.observe_issued(200))?;
    assert_eq!(later, ReceiveIssued::Frozen, "issued overtaking C does not resume");
    match db.receive_transaction(expect(&db, "e", 100)?, 1, |tx| {
        tx.cover(ReceiveCover {
            sequence: 101,
            kind: ReceiveCoverKind::Terminal,
            gaps: &[],
            retain_until: 0,
        })
    }) {
        Err(StorageError::Integrity(CURSOR_AHEAD)) => {}
        other => panic!("still frozen: {other:?}"),
    }
    db.receive_transaction(expect(&db, "e", 100)?, 1, |tx| tx.recover_cursor_ahead())?;
    assert_eq!(
        db.receive_transaction(expect(&db, "e", 100)?, 1, |tx| {
            tx.cover(ReceiveCover {
                sequence: 101,
                kind: ReceiveCoverKind::Terminal,
                gaps: &[],
                retain_until: 0,
            })
        })?,
        ReceiveCoverResult::Covered
    );
    assert_eq!(cursor(&db)?, 101);
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn retired_incarnation_fence() -> Result<(), StorageError> {
    let (root, db) = setup("reset-fence")?;
    db.set_projection_checkpoint("gateway_receive_cursor:t", "10")?;
    let retired: Vec<String> = (0..RETIRED_FENCE_CAP).map(|i| format!("r{i:02}")).collect();
    db.connection.execute(
        "UPDATE gateway_receive_epoch SET retired_incarnations=?1 WHERE target_delivery_id='t'",
        params![serde_json::to_vec(&retired)?],
    )?;
    db.publish_pending_receive_loss("t", "e", crate::unix_now())?;
    let paused = reset_to(&db, "e", 10, "n", 4, ReceiveResetReason::RouterReset)?;
    assert_eq!(paused, ReceiveResetResult::PausedFence);
    let (incarnation, still, activated, _) = epoch(&db)?;
    assert_eq!(incarnation, "e", "65th transition does not grow the fence");
    assert_eq!(still.len(), RETIRED_FENCE_CAP);
    assert_eq!(still, retired);
    assert_eq!(activated, 0);
    assert_eq!(cursor(&db)?, 10, "no C write");
    assert_eq!(reset_events(&db)?, 0, "no reset write");
    let intents: i64 =
        db.connection.query_row("SELECT count(*) FROM gateway_ack_intent", [], |row| row.get(0))?;
    assert_eq!(intents, 0, "no ACK write");
    let pause: String = db.connection.query_row(
        "SELECT last_event_id FROM projection_checkpoint WHERE projection_name='gateway_receive_pause:t'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(pause, "retired_incarnation_fence");
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}
