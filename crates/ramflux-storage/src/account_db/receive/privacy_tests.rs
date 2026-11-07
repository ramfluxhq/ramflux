// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Late-stage fence: an input is dropped only on deletion tied to that exact input.
#![allow(clippy::expect_used, clippy::panic)]
use super::stage_tests::{
    entry, footprints, input, locator, receipt_state, run, setup, work_for, work_rows,
};
use crate::{AccountDb, StorageError};
use rusqlite::params;
use serde_json::json;

type R = super::stage::ReceiveStageResult;

fn reopen(root: &std::path::Path, db: AccountDb) -> Result<AccountDb, StorageError> {
    drop(db);
    AccountDb::open(
        &crate::AccountIndex::open(root)?,
        "acct",
        &crate::AccountDbKey::derive("acct", b"storage-test-secret"),
    )
}

#[test]
fn erasure_late_stage_and_process() -> Result<(), StorageError> {
    let (root, db) = setup("w0-late-stage")?;
    db.connection.disable_background_checkpoints_for_test();
    db.send_direct_message("thread", "M", "peer", b"secret")?;
    db.connection.execute("INSERT INTO message_copy_binding VALUES('payload:H','M')", [])?;
    let wire = entry(1, "H", None);
    assert_eq!(run(&db, input(&wire, 1))?, R::Staged);
    db.delete_direct_message("thread", "M", "local", "delete-m")?;
    assert_eq!(receipt_state(&db, 1)?.as_deref(), Some("erased"));
    // (a) Redelivering the erased coordinate returns Erased and stores no work.
    assert_eq!(run(&db, input(&wire, 1))?, R::Erased);
    assert_eq!(work_rows(&db)?, 0);
    // (b) After reopen, (a) still holds.
    let db = reopen(&root, db)?;
    db.connection.disable_background_checkpoints_for_test();
    assert_eq!(run(&db, input(&wire, 1))?, R::Erased);
    assert_eq!(work_rows(&db)?, 0);
    // (c) Re-fire: a fresh envelope id whose payload is bound to the deleted M after the
    // fact is caught by the post-insert re-read, with no work and no footprint row left.
    db.connection.execute("INSERT INTO message_copy_binding VALUES('payload:H3','M')", [])?;
    let mut fresh: serde_json::Value =
        serde_json::from_slice(&entry(2, "H3", None)).expect("entry fixture");
    fresh["envelope"]["envelope_id"] = json!("env-fresh");
    let fresh = serde_json::to_vec(&fresh).expect("entry encoding");
    assert_eq!(run(&db, input(&fresh, 2))?, R::Erased);
    assert_eq!(receipt_state(&db, 2)?.as_deref(), Some("erased"));
    assert_eq!(work_for(&db, 2)?, 0);
    assert!(!footprints(&db)?.iter().any(|(_, at)| *at == locator(2)));
    drop(db);
    std::fs::remove_dir_all(root)?;
    already_seen_unprojected_collision_stays_staged()
}

/// Cell (d), run inside `erasure_late_stage_and_process` on its own database.
fn already_seen_unprojected_collision_stays_staged() -> Result<(), StorageError> {
    let (root, db) = setup("w0-collision-b")?;
    db.connection.disable_background_checkpoints_for_test();
    // (d) A was routed on envelope id `env` and then deleted, so A's deleted-envelope marker
    // exists. B shares the envelope id, differs in sender and payload, was already seen and is
    // not projected. Neither the marker nor the seen record is deletion authority for B.
    db.send_direct_message("thread", "A", "peer", b"secret")?;
    db.persist_actor_state(
        "routed/committed/A",
        &json!({"routing":{"message_id":"A"},"projected":true,
            "entry":{"envelope":{"envelope_id":"env","payload_hash":"HA"}}}),
    )?;
    db.delete_direct_message("thread", "A", "local", "delete-a")?;
    let mut value: serde_json::Value =
        serde_json::from_slice(&entry(5, "HB", None)).expect("entry fixture");
    value["envelope"]["source_principal_id"] = json!("other-source");
    value["envelope"]["source_device_id"] = json!("other-device");
    let wire = serde_json::to_vec(&value).expect("entry encoding");
    let seen = db.routed_seen_key(&wire)?;
    db.persist_actor_state(&seen, &json!({"sender":"other-device"}))?;
    db.persist_actor_state("routed/committed/B", &json!({"projected":false}))?;
    assert_eq!(run(&db, input(&wire, 5))?, R::Staged);
    assert_eq!(work_rows(&db)?, 1);
    assert!(footprints(&db)?.contains(&("copy:payload:HB".to_owned(), locator(5))));
    // After reopen the same work is still present and recoverable.
    let db = reopen(&root, db)?;
    db.connection.disable_background_checkpoints_for_test();
    assert_eq!(run(&db, input(&wire, 5))?, R::Existing);
    assert_eq!(work_rows(&db)?, 1);
    assert_eq!(receipt_state(&db, 5)?.as_deref(), Some("staged"));
    let stored: Vec<u8> = db.connection.query_row(
        "SELECT entry_json FROM gateway_receive_work WHERE inbox_seq=?1",
        params![5u64.to_be_bytes().as_slice()],
        |row| row.get(0),
    )?;
    assert_eq!(stored, wire);
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}
