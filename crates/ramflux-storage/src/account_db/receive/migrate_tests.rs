// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Direct old-DB migration preserves C and classifies (C,S] as `legacy_unverified`.
#![allow(clippy::expect_used, clippy::panic)]
use super::migrate::{ReceiveMigrate, ReceiveMigrateResult};
use super::reset::{ReceiveReset, ReceiveResetReason, ReceiveResetResult};
use super::stage_tests::{bytes, setup};
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

fn epoch(db: &AccountDb) -> Result<(String, i64, Vec<String>, u64, u64), StorageError> {
    let (incarnation, verified, retired, activated, uncertain): (String, i64, Vec<u8>, Vec<u8>, Vec<u8>) =
        db.connection.query_row(
            "SELECT incarnation_id,incarnation_verified,retired_incarnations,activated_cursor,legacy_uncertain_through FROM gateway_receive_epoch WHERE target_delivery_id='t'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
        )?;
    Ok((
        incarnation,
        verified,
        super::retired_incarnations(&retired)?,
        u64::from_be_bytes(activated.try_into().expect("activated")),
        u64::from_be_bytes(uncertain.try_into().expect("uncertain")),
    ))
}

fn cursor(db: &AccountDb) -> Result<u64, StorageError> {
    db.receive_cursor("t")
}

fn reset_count(db: &AccountDb) -> Result<i64, StorageError> {
    Ok(db.connection.query_row(
        "SELECT count(*) FROM runtime_journal WHERE topic='inbox.reset'",
        [],
        |row| row.get(0),
    )?)
}

fn unverified_seqs(db: &AccountDb) -> Result<Vec<u64>, StorageError> {
    let mut query = db.connection.prepare(
        "SELECT from_seq,to_seq,count,classification FROM gateway_inbox_loss WHERE target_delivery_id='t'",
    )?;
    let rows = query.query_map([], |row| {
        Ok((
            row.get::<_, Vec<u8>>(0)?,
            row.get::<_, Vec<u8>>(1)?,
            row.get::<_, Vec<u8>>(2)?,
            row.get::<_, String>(3)?,
        ))
    })?;
    let mut seqs = Vec::new();
    for row in rows {
        let (from, to, count, class) = row?;
        assert_eq!(class, "legacy_unverified");
        let from = u64::from_be_bytes(from.try_into().expect("from"));
        let to = u64::from_be_bytes(to.try_into().expect("to"));
        let count = u64::from_be_bytes(count.try_into().expect("count"));
        assert_eq!(count, to.saturating_sub(from).saturating_add(1));
        seqs.extend(from..=to);
    }
    seqs.sort_unstable();
    Ok(seqs)
}

fn held_seqs(db: &AccountDb) -> Result<Vec<u64>, StorageError> {
    let mut query = db.connection.prepare(
        "SELECT inbox_seq FROM gateway_receive_receipt WHERE target_delivery_id='t' AND disposition='held' ORDER BY inbox_seq",
    )?;
    let rows = query.query_map([], |row| row.get::<_, Vec<u8>>(0))?;
    let mut out = Vec::new();
    for row in rows {
        out.push(u64::from_be_bytes(row?.try_into().expect("seq")));
    }
    Ok(out)
}

#[test]
fn legacy_prior_crash_classification() -> Result<(), StorageError> {
    let (root, db) = crate::tests::test_db("migrate-direct")?;
    db.set_projection_checkpoint("gateway_receive_cursor:t", "10")?;
    let wire5 = bytes(5);
    db.hold_unrouted("u5", 5, &wire5, 1)?;
    let wire7 = bytes(7);
    db.connection
        .execute("INSERT INTO runtime_inbox_retry VALUES('r7',?1,0,1,1)", params![wire7])?;
    let migrated = db.write_transaction(|| {
        db.migrate_direct(ReceiveMigrate { target: "t", incarnation: "e" })
    })?;
    assert_eq!(migrated, ReceiveMigrateResult::Migrated);
    assert_eq!(cursor(&db)?, 10, "direct migration preserves C");
    let (incarnation, verified, retired, activated, uncertain) = epoch(&db)?;
    assert_eq!(incarnation, "e");
    assert_eq!(verified, 1);
    assert_eq!(retired, Vec::<String>::new());
    assert_eq!(activated, 10);
    assert_eq!(uncertain, 0);
    assert_eq!(held_seqs(&db)?, vec![5, 7], "retries/unrouted import before inference");
    assert_eq!(reset_count(&db)?, 0, "direct migration emits no reset");

    db.receive_transaction(expect(&db, "e", 10)?, 1, |tx| tx.fence_first_page(20, 30))?;
    assert_eq!(cursor(&db)?, 10);
    let (incarnation, _, _, activated, uncertain) = epoch(&db)?;
    assert_eq!(incarnation, "e");
    assert_eq!(activated, 10);
    assert_eq!(uncertain, 30, "fence through first issued P");
    assert_eq!(unverified_seqs(&db)?, (11..=20).collect::<Vec<_>>());
    assert_eq!(reset_count(&db)?, 0);
    db.receive_transaction(expect(&db, "e", 10)?, 1, |tx| tx.fence_first_page(20, 30))?;
    assert_eq!(unverified_seqs(&db)?, (11..=20).collect::<Vec<_>>(), "exactly once");
    drop(db);
    std::fs::remove_dir_all(&root)?;

    let (root, db) = setup("migrate-u-to-e")?;
    db.connection.execute(
        "UPDATE gateway_receive_epoch SET incarnation_id='u', incarnation_verified=0 WHERE target_delivery_id='t'",
        [],
    )?;
    db.set_projection_checkpoint("gateway_receive_cursor:t", "100")?;
    db.connection.execute(
        "INSERT INTO gateway_inbox_loss VALUES('t','u',?1,?1,?2,'unknown',1,'unavailable')",
        params![1u64.to_be_bytes().as_slice(), 1u64.to_be_bytes().as_slice()],
    )?;
    let keys = serde_json::json!({
        "source_key": "receive-gap:t:u:1:1",
        "target": "t",
        "incarnation": "u",
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
    let existing = db.write_transaction(|| {
        db.migrate_direct(ReceiveMigrate { target: "t", incarnation: "e" })
    })?;
    assert_eq!(existing, ReceiveMigrateResult::Existing, "U→E is reset, not migrate");
    assert_eq!(cursor(&db)?, 100);
    db.publish_pending_receive_loss("t", "u", crate::unix_now())?;
    let result = db.receive_transaction(expect(&db, "u", 100)?, 1, |tx| {
        tx.reset(ReceiveReset {
            new_incarnation: "e",
            settled: 30,
            reason: ReceiveResetReason::IncarnationFirstVerified,
        })
    })?;
    assert_eq!(result, ReceiveResetResult::Reset);
    assert_eq!(cursor(&db)?, 30);
    let (incarnation, verified, retired, activated, uncertain) = epoch(&db)?;
    assert_eq!(incarnation, "e");
    assert_eq!(verified, 1);
    assert_eq!(retired, vec!["u".to_owned()]);
    assert_eq!(activated, 30);
    assert_eq!(uncertain, 30);
    let prefix: i64 = db.connection.query_row(
        "SELECT count(*) FROM gateway_inbox_loss WHERE target_delivery_id='t' AND incarnation_id='e'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(prefix, 0, "U→E imports S with zero prefix losses");
    assert_eq!(reset_count(&db)?, 1);
    let reason: String = db.connection.query_row(
        "SELECT CAST(body_json AS TEXT) FROM runtime_journal WHERE topic='inbox.reset'",
        [],
        |row| row.get(0),
    )?;
    assert!(reason.contains("incarnation_first_verified"), "{reason}");
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}
