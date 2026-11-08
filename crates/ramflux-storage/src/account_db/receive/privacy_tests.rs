// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Late-stage fence: an input is dropped only on deletion tied to that exact input.
#![allow(clippy::expect_used, clippy::panic)]
use super::ReceiveExpectation;
use super::privacy::ReceiveBind;
use super::stage_tests::{
    entry, footprints, input, locator, receipt_state, run, run_at, setup, work_for, work_rows,
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

pub(super) fn bind(
    db: &AccountDb,
    sequence: u64,
    message: &str,
) -> Result<ReceiveBind, StorageError> {
    db.receive_transaction(
        ReceiveExpectation {
            target: "t",
            incarnation: "e",
            cursor: 0,
            generation: 1,
            erasure_generation: db.privacy_erasure_generation()?,
        },
        1,
        |tx| tx.bind_logical_message(sequence, message),
    )
}

/// A direct TRUNCATE checkpoint is clean and leaves an empty `-wal`.
fn assert_wal_truncated(db: &AccountDb) -> Result<(), StorageError> {
    let busy: i64 =
        db.connection.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| row.get(0))?;
    assert_eq!(busy, 0);
    let mut wal = db.path.clone().into_os_string();
    wal.push("-wal");
    assert_eq!(std::fs::metadata(&wal).map_or(0, |meta| meta.len()), 0);
    Ok(())
}

fn erasure_pending(db: &AccountDb) -> Result<i64, StorageError> {
    Ok(db.connection.query_row(
        "SELECT erasure_pending FROM runtime_privacy_maintenance WHERE singleton=1",
        [],
        |row| row.get(0),
    )?)
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
    // (f) stage -> bind -> erase: the unbound row is adopted by the bound message.
    db.send_direct_message("thread", "F", "peer", b"secret")?;
    let staged = entry(10, "HF", None);
    assert_eq!(run(&db, input(&staged, 10))?, R::Staged);
    assert!(footprints(&db)?.contains(&("copy:payload:HF".to_owned(), locator(10))));
    assert_eq!(bind(&db, 10, "F")?, ReceiveBind::Bound);
    assert!(footprints(&db)?.contains(&("F".to_owned(), locator(10))));
    db.delete_direct_message("thread", "F", "local", "delete-f")?;
    assert_eq!(receipt_state(&db, 10)?.as_deref(), Some("erased"));
    assert_eq!(work_for(&db, 10)?, 0);
    // (g) stage -> erase -> late bind, from a settled WAL.
    db.send_direct_message("thread", "A", "peer", b"secret")?;
    let late = entry(11, "HA", None);
    assert_eq!(run(&db, input(&late, 11))?, R::Staged);
    db.delete_direct_message("thread", "A", "local", "delete-a")?;
    assert_eq!(receipt_state(&db, 11)?.as_deref(), Some("staged"), "unbound work is not A's yet");
    db.connection.execute(
        "UPDATE runtime_privacy_maintenance SET erasure_pending=0 WHERE singleton=1",
        [],
    )?;
    assert_wal_truncated(&db)?;
    assert_eq!(erasure_pending(&db)?, 0);
    assert_eq!(bind(&db, 11, "A")?, ReceiveBind::Erased);
    assert_eq!(receipt_state(&db, 11)?.as_deref(), Some("erased"));
    assert_eq!(work_for(&db, 11)?, 0);
    assert!(!footprints(&db)?.iter().any(|(_, at)| *at == locator(11)));
    assert_eq!(erasure_pending(&db)?, 1, "late bind re-arms WAL retirement");
    assert_wal_truncated(&db)?;
    // (j) A source preparation gate sees the late erase: open before, refused after.
    let gate = |db: &AccountDb, sequence: u64| {
        db.receive_transaction(
            ReceiveExpectation {
                target: "t",
                incarnation: "e",
                cursor: 0,
                generation: 1,
                erasure_generation: db.privacy_erasure_generation()?,
            },
            1,
            |tx| tx.require_open_input(sequence),
        )
    };
    db.send_direct_message("thread", "S", "peer", b"secret")?;
    let source = entry(12, "HS", None);
    assert_eq!(run(&db, input(&source, 12))?, R::Staged);
    gate(&db, 12)?;
    db.delete_direct_message("thread", "S", "local", "delete-s")?;
    assert_eq!(bind(&db, 12, "S")?, ReceiveBind::Erased);
    let refused = gate(&db, 12);
    assert!(
        matches!(
            refused,
            Err(StorageError::Integrity("source effect requires staged receive work"))
        ),
        "{:?}",
        refused.err()
    );
    own_copy_late_w1_locator(&db)?;
    // (i) Binding a terminal receipt fails with the exact text.
    let terminal = bind(&db, 11, "A");
    assert!(
        matches!(
            terminal,
            Err(StorageError::Integrity("receive bind requires a staged or held receipt"))
        ),
        "{:?}",
        terminal.err()
    );
    drop(db);
    std::fs::remove_dir_all(root)?;
    fresh_sequence_replay_of_an_erased_tuple()?;
    already_seen_unprojected_collision_stays_staged()
}

/// (p) P14 own-copy locator: W1 binds the locator to the message; a late erase removes it.
fn own_copy_late_w1_locator(db: &AccountDb) -> Result<(), StorageError> {
    db.send_direct_message("thread", "P", "peer", b"secret")?;
    let own_copy = entry(13, "HP", None);
    assert_eq!(run(db, input(&own_copy, 13))?, R::Staged);
    assert_eq!(bind(db, 13, "P")?, ReceiveBind::Bound);
    db.persist_message_actor_state(
        "P",
        "own-device/sequence-locator/P",
        &json!({"target":"t","incarnation":"e","sequence":13}),
    )?;
    assert!(db.actor_state_exists("own-device/sequence-locator/P")?);
    db.delete_direct_message("thread", "P", "local", "delete-p")?;
    assert!(
        !db.actor_state_exists("own-device/sequence-locator/P")?,
        "late erase must drop the own-copy sequence locator"
    );
    assert_eq!(receipt_state(db, 13)?.as_deref(), Some("erased"));
    own_copy_locator_backup_exclusion()
}

/// Counts own-copy locator rows in runtime actor state, message footprints and copy bindings.
fn own_copy_locator_rows(conn: &rusqlite::Connection) -> rusqlite::Result<(i64, i64, i64)> {
    Ok((
        conn.query_row(
            "SELECT count(*) FROM runtime_actor_state WHERE state_kind LIKE 'own-device/sequence-locator/%'",
            [],
            |row| row.get(0),
        )?,
        conn.query_row(
            "SELECT count(*) FROM message_footprint WHERE locator LIKE 'own-device/sequence-locator/%'",
            [],
            |row| row.get(0),
        )?,
        conn.query_row(
            "SELECT count(*) FROM message_copy_binding WHERE copy_id LIKE 'actor:own-device/sequence-locator/%'",
            [],
            |row| row.get(0),
        )?,
    ))
}

/// Decrypted native backup contains neither ledger rows nor the own-copy sequence locator.
fn own_copy_locator_backup_exclusion() -> Result<(), StorageError> {
    let (root, db) = crate::tests::test_db("w1-own-copy-backup")?;
    db.send_direct_message("thread", "B", "peer", b"secret")?;
    db.persist_message_actor_state(
        "B",
        "own-device/sequence-locator/B",
        &json!({"target":"t","incarnation":"e","sequence":1}),
    )?;
    db.persist_actor_state(
        "directory/conversation/seq-locator",
        &json!({"target":"t","incarnation":"e","sequence":1}),
    )?;
    let live = db.connection.call(|conn| own_copy_locator_rows(conn))?;
    assert!(live.0 == 1 && live.1 >= 1 && live.2 == 1, "locator is registered live: {live:?}");
    // Archive path (install.rs fresh restore): the strip runs on a live copy of the rows.
    let archived = crate::tests::test_db("w1-own-copy-archive")?;
    archived.1.persist_message_actor_state(
        "B",
        "own-device/sequence-locator/B",
        &json!({"target":"t","incarnation":"e","sequence":1}),
    )?;
    archived
        .1
        .connection
        .call(|conn| crate::account_db::backup_retirement::archive_outbound_state(conn))?;
    assert_eq!(
        archived.1.connection.call(|conn| own_copy_locator_rows(conn))?,
        (0, 0, 0),
        "archive_outbound must drop the locator, footprint and binding rows"
    );
    // Snapshot file: opened directly with the snapshot key, never through the live handle.
    let incoming = root.join("incoming.db");
    let snapshot = db.write_backup_snapshot(&incoming)?;
    let file = rusqlite::Connection::open(&incoming)?;
    file.execute_batch(&format!("PRAGMA key = \"x'{}'\";", snapshot.key.sqlcipher_hex()))?;
    assert_eq!(
        own_copy_locator_rows(&file)?,
        (0, 0, 0),
        "decrypted backup file must not contain the own-copy locator, footprint or binding"
    );
    let leaked: i64 = file.query_row(
        "SELECT count(*) FROM runtime_actor_state WHERE state_kind='directory/conversation/seq-locator'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(leaked, 1, "the strip is narrow: other actor state stays in the backup");
    drop(file);
    // Fresh restore into a live account: the merged account holds no locator rows.
    let local_index = crate::AccountIndex::open(root.join("local"))?;
    local_index.create_account("acct", "principal")?;
    let local_key = crate::AccountDbKey::derive("acct", b"storage-test-secret");
    let local = AccountDb::open(&local_index, "acct", &local_key)?;
    let target = root.join("merged.db");
    let copied = local.write_backup_snapshot(&target)?;
    let mut merged = crate::BackupDatabase::open(&target, &copied.key)?;
    merged.merge_native_backup(&incoming, &snapshot.key, || Ok(()))?;
    assert_eq!(
        own_copy_locator_rows(&merged.db)?,
        (0, 0, 0),
        "restored account must not contain the own-copy locator"
    );
    drop(db);
    drop(archived.1);
    std::fs::remove_dir_all(archived.0)?;
    drop(local);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

/// A work entry whose authenticated tuple is exactly (principal, device, key, payload) and whose
/// lifetime is fresh, so its erasure leaves a live tombstone.
pub(super) fn fresh_entry(sequence: u64, payload: &str, principal: &str, device: &str) -> Vec<u8> {
    let mut v: serde_json::Value =
        serde_json::from_slice(&super::stage_tests::bytes(sequence)).expect("entry fixture");
    v["envelope"]["payload_hash"] = json!(payload);
    v["envelope"]["source_principal_id"] = json!(principal);
    v["envelope"]["source_device_id"] = json!(device);
    v["envelope"]["envelope_id"] = json!(format!("env-{sequence}"));
    v["envelope"]["created_at"] = json!(crate::unix_now());
    v["envelope"]["ttl"] = json!(3600);
    serde_json::to_vec(&v).expect("entry encoding")
}

/// Cells (k)-(n): a fresh-sequence replay of an erased tuple is `Erased` at W0 (the letters
/// continue the card's (j)-(m) after lane 2's cell (j)). Each holds immediately and after reopen.
fn fresh_sequence_replay_of_an_erased_tuple() -> Result<(), StorageError> {
    let (root, db) = setup("w0-fresh-replay")?;
    db.connection.disable_background_checkpoints_for_test();
    // (k) Staged work of A, then A is deleted: the tuple is tombstoned. A new coordinate with the
    // same tuple is erased with no work and no admission key.
    db.send_direct_message("thread", "A", "peer", b"secret")?;
    db.connection.execute("INSERT INTO message_copy_binding VALUES('payload:HK','A')", [])?;
    let first = fresh_entry(1, "HK", "kp", "kd");
    assert_eq!(run(&db, input(&first, 1))?, R::Staged);
    db.delete_direct_message("thread", "A", "local", "delete-k")?;
    let replay = fresh_entry(5, "HK", "kp", "kd");
    assert_eq!(run(&db, input(&replay, 5))?, R::Erased);
    assert_eq!(receipt_state(&db, 5)?.as_deref(), Some("erased"));
    assert_eq!(work_for(&db, 5)?, 0);
    assert!(!footprints(&db)?.iter().any(|(_, at)| *at == locator(5)));
    let admission: i64 = db.connection.query_row(
        "SELECT count(*) FROM gateway_receive_work WHERE inbox_seq=?1",
        params![5_u64.to_be_bytes().as_slice()],
        |row| row.get(0),
    )?;
    assert_eq!(admission, 0, "no work row, so no admission key is stored");
    let db = reopen(&root, db)?;
    db.connection.disable_background_checkpoints_for_test();
    let again = fresh_entry(6, "HK", "kp", "kd");
    assert_eq!(run(&db, input(&again, 6))?, R::Erased);
    assert_eq!(receipt_state(&db, 6)?.as_deref(), Some("erased"));
    assert_eq!(work_for(&db, 6)?, 0);
    // (l) A routed copy is the source: its tuple is tombstoned by deleting the message.
    db.send_direct_message("thread", "R", "peer", b"secret")?;
    db.connection.execute("INSERT INTO message_copy_binding VALUES('payload:HL','R')", [])?;
    let routed = serde_json::from_slice::<serde_json::Value>(&fresh_entry(2, "HL", "lp", "ld"))
        .expect("routed fixture");
    db.persist_actor_state(
        "routed/committed/HL",
        &json!({"routing":{"message_id":"R"},"entry":{"envelope":routed["envelope"]}}),
    )?;
    db.delete_direct_message("thread", "R", "local", "delete-l")?;
    let routed_replay = fresh_entry(7, "HL", "lp", "ld");
    assert_eq!(run(&db, input(&routed_replay, 7))?, R::Erased);
    assert_eq!(work_for(&db, 7)?, 0);
    // (m) The match is exact: the same payload from another device is a different tuple.
    let other_device = fresh_entry(8, "HK", "kp", "other-device");
    assert_eq!(run(&db, input(&other_device, 8))?, R::Staged);
    assert_eq!(work_for(&db, 8)?, 1);
    // (n) Exact expiry boundary at W0: live means expires_at > now. Inclusive at both ends,
    // pinned through stage_at so the test does not wait on the wall clock.
    let now = crate::unix_now();
    db.connection.execute("UPDATE receive_erased_input SET expires_at=?1", params![now])?;
    let at_now = fresh_entry(9, "HK", "kp", "kd");
    assert_eq!(run_at(&db, input(&at_now, 9), now)?, R::Staged);
    assert_eq!(work_for(&db, 9)?, 1);
    db.connection.execute("UPDATE receive_erased_input SET expires_at=?1", params![now + 1])?;
    let at_plus = fresh_entry(10, "HK", "kp", "kd");
    assert_eq!(run_at(&db, input(&at_plus, 10), now)?, R::Erased);
    assert_eq!(work_for(&db, 10)?, 0);
    assert_eq!(receipt_state(&db, 10)?.as_deref(), Some("erased"));
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
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
    // B's seen marker is derived the way the real lookup does: from the canonical envelope,
    // not from the whole inbox entry (which no replay lookup ever hashes).
    let canonical = {
        let parsed: serde_json::Value = serde_json::from_slice(&wire).expect("entry fixture");
        let envelope: ramflux_protocol::Envelope =
            serde_json::from_value(parsed["envelope"].clone()).expect("envelope fixture");
        ramflux_protocol::canonical_json_bytes(&envelope).expect("canonical envelope")
    };
    let seen = db.routed_seen_key(&canonical)?;
    assert_ne!(seen, db.routed_seen_key(&wire)?, "the entry hash is not the replay key");
    db.persist_actor_state(&seen, &json!({"sender":"other-device"}))?;
    db.persist_actor_state("routed/committed/B", &json!({"projected":false}))?;
    // The real lookup now sees B, and A's deleted-envelope marker covers the shared id: the
    // forbidden conjunction is present, so only the absence of a marker-based drop keeps B.
    assert_eq!(db.inbox_envelope_marker(&wire)?, Some(seen.clone()));
    assert!(db.actor_state_exists(&seen)?);
    assert!(db.deleted_inbox_envelope(&wire)?.is_some());
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
    // (h) The collision B binds to its live message instead of being dropped.
    db.send_direct_message("thread", "B", "peer", b"secret")?;
    assert_eq!(bind(&db, 5, "B")?, ReceiveBind::Bound);
    assert!(footprints(&db)?.contains(&("B".to_owned(), locator(5))));
    assert_eq!(work_rows(&db)?, 1);
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn receive_bind_refusals_leave_state_unchanged_and_held_receipts_bind() -> Result<(), StorageError>
{
    let (root, db) = setup("w0-bind-refusals")?;
    db.connection.disable_background_checkpoints_for_test();
    db.send_direct_message("thread", "L", "peer", b"secret")?;
    let snapshot = |db: &AccountDb| -> Result<(i64, i64, usize), StorageError> {
        Ok((
            db.connection
                .query_row("SELECT count(*) FROM gateway_receive_receipt", [], |r| r.get(0))?,
            work_rows(db)?,
            footprints(db)?.len(),
        ))
    };
    // A coordinate with no receipt at all.
    let before = snapshot(&db)?;
    let missing = bind(&db, 20, "L");
    assert!(
        matches!(
            missing,
            Err(StorageError::Integrity("receive bind requires a staged or held receipt"))
        ),
        "{:?}",
        missing.err()
    );
    assert_eq!(snapshot(&db)?, before);
    // A staged receipt whose work is gone.
    db.connection.execute(
        "INSERT INTO gateway_receive_receipt VALUES('t','e',?1,'staged',100,1)",
        params![21u64.to_be_bytes().as_slice()],
    )?;
    let before = snapshot(&db)?;
    let workless = bind(&db, 21, "L");
    assert!(
        matches!(workless, Err(StorageError::Integrity("receive bind requires staged work"))),
        "{:?}",
        workless.err()
    );
    assert_eq!(snapshot(&db)?, before);
    assert_eq!(receipt_state(&db, 21)?.as_deref(), Some("staged"));
    // A held receipt binds like a staged one.
    let held = entry(22, "HH", None);
    assert_eq!(run(&db, input(&held, 22))?, R::Staged);
    db.connection.execute(
        "UPDATE gateway_receive_receipt SET disposition='held' WHERE inbox_seq=?1",
        params![22u64.to_be_bytes().as_slice()],
    )?;
    assert_eq!(bind(&db, 22, "L")?, ReceiveBind::Bound);
    assert!(footprints(&db)?.contains(&("L".to_owned(), locator(22))));
    assert_eq!(receipt_state(&db, 22)?.as_deref(), Some("held"));
    assert_eq!(work_for(&db, 22)?, 1);
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}
