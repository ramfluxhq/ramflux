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

#[derive(Debug, PartialEq)]
struct ResetSnap {
    cursor: u64,
    incarnation: String,
    retired: Vec<String>,
    activated: u64,
    uncertain: u64,
    intents: i64,
    loss: i64,
    compat: i64,
    held: i64,
    reset_events: i64,
    freeze: Option<String>,
}

fn reset_snap(db: &AccountDb) -> Result<ResetSnap, StorageError> {
    let (incarnation, retired, activated, uncertain) = epoch(db)?;
    let intents: i64 = db.connection.query_row(
        "SELECT count(*) FROM gateway_ack_intent WHERE target_delivery_id='t' AND incarnation_id='e'",
        [],
        |row| row.get(0),
    )?;
    let loss: i64 = db.connection.query_row(
        "SELECT count(*) FROM gateway_inbox_loss WHERE target_delivery_id='t' AND incarnation_id='e'",
        [],
        |row| row.get(0),
    )?;
    let compat: i64 = db.connection.query_row(
        "SELECT count(*) FROM gateway_receive_receipt WHERE target_delivery_id='t' AND incarnation_id='e' AND disposition IN ('completed','rejected')",
        [],
        |row| row.get(0),
    )?;
    let held: i64 = db.connection.query_row(
        "SELECT count(*) FROM gateway_receive_receipt WHERE target_delivery_id='t' AND incarnation_id='e' AND disposition='held'",
        [],
        |row| row.get(0),
    )?;
    let freeze = db.projection_checkpoint("gateway_receive_freeze:t")?;
    Ok(ResetSnap {
        cursor: cursor(db)?,
        incarnation,
        retired,
        activated,
        uncertain,
        intents,
        loss,
        compat,
        held,
        reset_events: reset_events(db)?,
        freeze,
    })
}

fn seed_old_e_effects(db: &AccountDb) -> Result<(), StorageError> {
    let completed = 3u64.to_be_bytes();
    let rejected = 4u64.to_be_bytes();
    let intent = 2u64.to_be_bytes();
    let wire3 = bytes(3);
    let wire4 = bytes(4);
    db.connection.execute(
        "INSERT INTO gateway_ack_intent VALUES('t','e',?1,0,0,0,100)",
        params![intent.as_slice()],
    )?;
    db.connection.execute(
        "INSERT INTO gateway_receive_receipt VALUES('t','e',?1,'completed',100,1)",
        params![completed.as_slice()],
    )?;
    db.connection.execute(
        "INSERT INTO gateway_receive_work VALUES('t','e',?1,?2,'authenticated-key',?3)",
        params![completed.as_slice(), wire3, i64::try_from(wire3.len()).expect("bounded")],
    )?;
    db.connection.execute(
        "INSERT INTO gateway_receive_receipt VALUES('t','e',?1,'rejected',100,1)",
        params![rejected.as_slice()],
    )?;
    db.connection.execute(
        "INSERT INTO gateway_receive_work VALUES('t','e',?1,?2,'authenticated-key',?3)",
        params![rejected.as_slice(), wire4, i64::try_from(wire4.len()).expect("bounded")],
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
        tx.reset(ReceiveReset { new_incarnation, settled, issued: settled, after: 0, reason })
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
#[allow(clippy::too_many_lines)]
fn inbox_incarnation_reset() -> Result<(), StorageError> {
    let (root, db) = setup("reset-inbox")?;
    db.set_projection_checkpoint("gateway_receive_cursor:t", "100")?;
    seed_unpublished_loss(&db, "e")?;
    put_held(&db, "e", 40)?;
    seed_old_e_effects(&db)?;
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
    let pre = reset_snap(&db)?;
    assert_eq!(pre.intents, 1);
    assert_eq!(pre.loss, 1);
    assert_eq!(pre.compat, 2);
    assert_eq!(pre.held, 1);
    assert_eq!(pre.reset_events, 0);
    match with_fault(FaultKind::BeforeCommit, || {
        reset_to(&db, "e", 100, "n", 30, ReceiveResetReason::RouterReset)
    }) {
        Err(StorageError::Integrity("receive reset before-commit")) => {}
        other => panic!("before-commit: {other:?}"),
    }
    assert_eq!(reset_snap(&db)?, pre, "before-commit keeps C, E, fence, intents, loss, compat");
    let result = reset_to(&db, "e", 100, "n", 30, ReceiveResetReason::RouterReset)?;
    assert_eq!(result, ReceiveResetResult::Reset);
    assert_eq!(cursor(&db)?, 30, "C is first-page S, not zero");
    let (incarnation, retired, activated, uncertain) = epoch(&db)?;
    assert_eq!(incarnation, "n");
    assert_eq!(retired, vec!["e".to_owned()]);
    assert_eq!(activated, 30);
    assert_eq!(uncertain, 30);
    let after = reset_snap(&db)?;
    assert_eq!(after.intents, 0, "old-E ACK intents are local-only after reset");
    assert_eq!(after.loss, 0, "old-E loss rows are released");
    assert_eq!(after.compat, 0, "terminal compat receipts are released");
    assert_eq!(after.held, 1, "staged/held work remains");
    assert_eq!(after.reset_events, 1);
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
    assert_eq!(db.receive_pause("t")?.as_deref(), Some("retired_incarnation_fence"));
    db.write_transaction(|| db.clear_receive_pause("t"))?;
    assert_eq!(db.receive_pause("t")?, None);
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn reset_refuses_retired_incarnation_and_validates_first_page() -> Result<(), StorageError> {
    let (root, db) = setup("reset-retired-new")?;
    db.set_projection_checkpoint("gateway_receive_cursor:t", "10")?;
    db.connection.execute(
        "UPDATE gateway_receive_epoch SET retired_incarnations=?1 WHERE target_delivery_id='t'",
        params![serde_json::to_vec(&vec!["old".to_owned()])?],
    )?;
    db.publish_pending_receive_loss("t", "e", crate::unix_now())?;
    let before = reset_snap(&db)?;
    match reset_to(&db, "e", 10, "old", 4, ReceiveResetReason::RouterReset) {
        Err(StorageError::Integrity("receive reset incarnation is retired")) => {}
        other => panic!("retired new E: {other:?}"),
    }
    assert_eq!(reset_snap(&db)?, before, "retired new E writes nothing");

    match db.receive_transaction(expect(&db, "e", 10)?, 1, |tx| {
        tx.reset(ReceiveReset {
            new_incarnation: "n",
            settled: 4,
            issued: 4,
            after: 1,
            reason: ReceiveResetReason::RouterReset,
        })
    }) {
        Err(StorageError::Integrity("receive reset after must be zero")) => {}
        other => panic!("after: {other:?}"),
    }
    match db.receive_transaction(expect(&db, "e", 10)?, 1, |tx| {
        tx.reset(ReceiveReset {
            new_incarnation: "n",
            settled: 5,
            issued: 4,
            after: 0,
            reason: ReceiveResetReason::RouterReset,
        })
    }) {
        Err(StorageError::Integrity("receive reset settled prefix invalid")) => {}
        other => panic!("S>issued: {other:?}"),
    }
    assert_eq!(reset_snap(&db)?, before);
    let equal = db.receive_transaction(expect(&db, "e", 10)?, 1, |tx| {
        tx.reset(ReceiveReset {
            new_incarnation: "n",
            settled: 4,
            issued: 4,
            after: 0,
            reason: ReceiveResetReason::RouterReset,
        })
    })?;
    assert_eq!(equal, ReceiveResetResult::Reset);
    assert_eq!(cursor(&db)?, 4);
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn empty_unverified_cursor_zero_initializes_without_reset_event() -> Result<(), StorageError> {
    let (root, db) = setup("reset-empty-u")?;
    db.connection.execute(
        "UPDATE gateway_receive_epoch SET incarnation_id='u', incarnation_verified=0 WHERE target_delivery_id='t'",
        [],
    )?;
    db.publish_pending_receive_loss("t", "u", crate::unix_now())?;
    let result = reset_to(&db, "u", 0, "n", 0, ReceiveResetReason::IncarnationFirstVerified)?;
    assert_eq!(result, ReceiveResetResult::Reset);
    assert_eq!(cursor(&db)?, 0);
    let (incarnation, retired, activated, _) = epoch(&db)?;
    assert_eq!(incarnation, "n");
    assert_eq!(retired, vec!["u".to_owned()]);
    assert_eq!(activated, 0);
    assert_eq!(reset_events(&db)?, 0, "empty U with C=0 emits no inbox_reset");
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn reset_clears_freeze_and_observe_issued_refuses_retired() -> Result<(), StorageError> {
    let (root, db) = setup("reset-clear-freeze")?;
    db.set_projection_checkpoint("gateway_receive_cursor:t", "10")?;
    assert_eq!(
        db.receive_transaction(expect(&db, "e", 10)?, 1, |tx| tx.observe_issued(10))?,
        ReceiveIssued::Live,
        "issued==C stays live"
    );
    assert_eq!(
        db.receive_transaction(expect(&db, "e", 10)?, 1, |tx| tx.observe_issued(1))?,
        ReceiveIssued::Frozen
    );
    assert_eq!(
        db.projection_checkpoint("gateway_receive_freeze:t")?.as_deref(),
        Some(CURSOR_AHEAD)
    );
    db.publish_pending_receive_loss("t", "e", crate::unix_now())?;
    assert_eq!(
        reset_to(&db, "e", 10, "n", 4, ReceiveResetReason::RouterReset)?,
        ReceiveResetResult::Reset
    );
    assert_eq!(db.projection_checkpoint("gateway_receive_freeze:t")?, None);
    assert_eq!(
        db.receive_transaction(expect(&db, "n", 4)?, 1, |tx| tx.observe_issued(8))?,
        ReceiveIssued::Live
    );
    match db.receive_transaction(expect(&db, "e", 4)?, 1, |tx| tx.observe_issued(8)) {
        Err(StorageError::Integrity(super::RETIRED_INCARNATION)) => {}
        other => panic!("retired observe_issued: {other:?}"),
    }
    match db.receive_transaction(expect(&db, "e", 4)?, 1, |tx| {
        tx.reset(ReceiveReset {
            new_incarnation: "x",
            settled: 4,
            issued: 4,
            after: 0,
            reason: ReceiveResetReason::RouterReset,
        })
    }) {
        Err(StorageError::Integrity(super::RETIRED_INCARNATION)) => {}
        other => panic!("retired reset: {other:?}"),
    }
    match db.receive_transaction(expect(&db, "n", 4)?, 1, |tx| {
        tx.reset(ReceiveReset {
            new_incarnation: "",
            settled: 4,
            issued: 4,
            after: 0,
            reason: ReceiveResetReason::RouterReset,
        })
    }) {
        Err(StorageError::Integrity("receive reset identity missing")) => {}
        other => panic!("empty E: {other:?}"),
    }
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn retired_fence_admits_the_sixty_fourth() -> Result<(), StorageError> {
    let (root, db) = setup("reset-fence-64")?;
    db.set_projection_checkpoint("gateway_receive_cursor:t", "10")?;
    let retired: Vec<String> = (0..RETIRED_FENCE_CAP - 1).map(|i| format!("r{i:02}")).collect();
    db.connection.execute(
        "UPDATE gateway_receive_epoch SET retired_incarnations=?1 WHERE target_delivery_id='t'",
        params![serde_json::to_vec(&retired)?],
    )?;
    db.publish_pending_receive_loss("t", "e", crate::unix_now())?;
    assert_eq!(
        reset_to(&db, "e", 10, "n", 4, ReceiveResetReason::RouterReset)?,
        ReceiveResetResult::Reset
    );
    let (_, still, _, _) = epoch(&db)?;
    assert_eq!(still.len(), RETIRED_FENCE_CAP);
    assert!(still.contains(&"e".to_owned()));
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}
