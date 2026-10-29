// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::*;

#[test]
fn runtime_wal_sqlcipher_snapshot_and_rekey() -> Result<(), StorageError> {
    let (root, mut writer) = test_db("wal-cipher-probe")?;
    assert_eq!(writer.encryption_mode(), EncryptionMode::SqlCipher);
    let cipher: String =
        writer.connection.query_row("PRAGMA cipher_version", [], |row| row.get(0))?;
    let journal: String =
        writer.connection.query_row("PRAGMA journal_mode", [], |row| row.get(0))?;
    let full: i64 = writer.connection.query_row("PRAGMA synchronous", [], |row| row.get(0))?;
    let busy: i64 = writer.connection.query_row("PRAGMA busy_timeout", [], |row| row.get(0))?;
    println!("SQLCipher {cipher}; journal_mode={journal}; synchronous={full}; busy_timeout={busy}");
    assert_eq!(journal, "wal");
    assert_eq!(full, 2);
    assert_eq!(busy, 5000);
    for (pragma, expected) in [("fullfsync", 1), ("secure_delete", 1), ("wal_autocheckpoint", 0)] {
        assert_eq!(
            writer
                .connection
                .query_row(&format!("PRAGMA {pragma}"), [], |row| row.get::<_, i64>(0))?,
            expected,
            "{pragma}"
        );
    }
    writer.enable_runtime()?;
    assert_eq!(
        writer.connection.query_row("PRAGMA synchronous", [], |row| row.get::<_, i64>(0))?,
        2
    );
    writer.connection.execute_batch(
        "CREATE TABLE wal_probe (value TEXT); INSERT INTO wal_probe VALUES ('before');",
    )?;
    let read_db = writer.open_reader()?;
    let reader = &read_db.connection;
    reader.execute_batch("PRAGMA busy_timeout=1000; BEGIN;")?;
    let before: String = reader.query_row("SELECT value FROM wal_probe", [], |row| row.get(0))?;
    assert_eq!(before, "before");
    writer.connection.execute_batch("UPDATE wal_probe SET value='after';")?;
    let snapshot: String = reader.query_row("SELECT value FROM wal_probe", [], |row| row.get(0))?;
    assert_eq!(snapshot, "before");
    reader.execute_batch("COMMIT;")?;
    let latest: String = reader.query_row("SELECT value FROM wal_probe", [], |row| row.get(0))?;
    assert_eq!(latest, "after");
    drop(read_db);
    let new_key = AccountDbKey::derive("acct", b"new-storage-secret");
    writer.rekey(&new_key)?;
    drop(writer);
    let index = AccountIndex::open(&root)?;
    let reopened = AccountDb::open(&index, "acct", &new_key)?;
    let latest: String =
        reopened.connection.query_row("SELECT value FROM wal_probe", [], |row| row.get(0))?;
    assert_eq!(latest, "after");
    drop(reopened);
    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn runtime_outbox_rolls_back_with_domain_write() -> Result<(), StorageError> {
    let (root, db) = test_db("runtime-outbox-rollback")?;
    db.enable_runtime()?;
    {
        let _transaction = db.connection.immediate_transaction()?;
        db.append_event("rolled-back", "test", b"rolled back")?;
        assert_ne!(db.pending_outbox(256)?, Vec::new());
    }
    assert_eq!(db.pending_outbox(256)?, Vec::new());
    let count: i64 = db.connection.query_row(
        "SELECT count(*) FROM local_event_log WHERE event_id='rolled-back'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(count, 0);
    drop(db);
    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn runtime_outbox_survives_exit_before_publish() -> Result<(), StorageError> {
    const ENV: &str = "RAMFLUX_STORAGE_TEST_CRASH_ROOT";
    if let Some(root) = std::env::var_os(ENV) {
        let index = AccountIndex::open(root)?;
        let key = AccountDbKey::derive("acct", b"storage-test-secret");
        let db = AccountDb::open(&index, "acct", &key)?;
        db.enable_runtime()?;
        db.append_event("committed-before-publish", "test", b"committed crash payload")?;
        // Bypass Rust destructors: leave the uncheckpointed encrypted WAL behind.
        std::process::exit(86);
    }
    let (root, db) = test_db("runtime-outbox-crash")?;
    db.enable_runtime()?;
    drop(db);
    let status = std::process::Command::new(std::env::current_exe()?)
        .args([
            "--exact",
            "tests::runtime_tests::runtime_outbox_survives_exit_before_publish",
            "--nocapture",
        ])
        .env(ENV, &root)
        .status()?;
    assert_eq!(status.code(), Some(86));
    let index = AccountIndex::open(&root)?;
    let key = AccountDbKey::derive("acct", b"storage-test-secret");
    let reopened = AccountDb::open(&index, "acct", &key)?;
    reopened.enable_runtime()?;
    let count: i64 = reopened.connection.query_row(
        "SELECT count(*) FROM local_event_log WHERE event_id='committed-before-publish'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(count, 1);
    let entries = reopened.pending_outbox(256)?;
    assert!(entries.iter().any(|entry| entry.table_name == "local_event_log"));
    let sequence = entries.last().map_or(0, |entry| entry.sequence);
    reopened.mark_outbox_published(sequence)?;
    assert_eq!(reopened.pending_outbox(256)?, Vec::new());
    drop(reopened);
    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn runtime_idempotency_receipts_reject_conflicts_and_pending_retries() -> Result<(), StorageError> {
    let (root, db) = test_db("runtime-idempotency")?;
    db.enable_runtime()?;
    assert_eq!(db.reserve_operation("operation", "intent")?, None);
    assert!(db.reserve_operation("operation", "intent").is_err());
    let response = serde_json::json!({"applied": 1});
    db.complete_operation("operation", &response)?;
    assert_eq!(db.reserve_operation("operation", "intent")?, Some(response.clone()));
    assert!(db.reserve_operation("operation", "different intent").is_err());
    drop(db);
    let index = AccountIndex::open(&root)?;
    let key = AccountDbKey::derive("acct", b"storage-test-secret");
    let reopened = AccountDb::open(&index, "acct", &key)?;
    reopened.enable_runtime()?;
    assert_eq!(reopened.reserve_operation("operation", "intent")?, Some(response));
    drop(reopened);
    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn runtime_control_batch_and_outbox_rollback_together() -> Result<(), StorageError> {
    let (root, db) = test_db("runtime-batch-rollback")?;
    db.connection.execute_batch("CREATE TRIGGER fail_control BEFORE INSERT ON runtime_actor_state WHEN NEW.state_kind='fail' BEGIN SELECT RAISE(ABORT,'injected control failure'); END;")?;
    let result = db.persist_actor_state_batch(&[
        ("first".to_owned(), serde_json::json!({"value":1})),
        ("fail".to_owned(), serde_json::json!({"value":2})),
    ]);
    assert!(result.is_err());
    assert_eq!(db.load_actor_state::<serde_json::Value>("first")?, None);
    assert_eq!(db.pending_outbox(256)?, Vec::new());
    db.persist_actor_state("same", &serde_json::json!({"value":1}))?;
    let entries = db.pending_outbox(256)?;
    let sequence = entries.last().map_or(0, |entry| entry.sequence);
    db.mark_outbox_published(sequence)?;
    db.persist_actor_state("same", &serde_json::json!({"value":1}))?;
    db.connection.execute_batch(
        "UPDATE runtime_actor_state SET state_json=state_json WHERE state_kind='same'",
    )?;
    assert_eq!(db.pending_outbox(256)?, Vec::new(), "a no-op update emits no invalidation");
    drop(db);
    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn imported_ratchet_retirement_preserves_causal_edges_counters_and_history_signatures()
-> Result<(), StorageError> {
    let (root, db, _device) = signed_test_db("ratchet-retirement-ledger")?;
    let first = "dm.session:thread:recv:own-device-sync:old1";
    let last = "dm.session:thread:recv:own-device-sync:old2";
    db.append_event("before", "text", b"before")?;
    db.append_event(first, "dm.ratchet_session", b"old private snapshot")?;
    db.append_event("after", "text", b"after")?;
    db.append_event(last, "dm.ratchet_session", b"latest private snapshot")?;
    db.connection.execute(
        "UPDATE local_event_log SET causal_prev_json=?1 WHERE event_id='after'",
        rusqlite::params![serde_json::to_string(&vec![first, "before"])?],
    )?;
    db.connection.execute(
        "INSERT INTO event_causal_dependency VALUES('after',?1,'fulfilled')",
        rusqlite::params![first],
    )?;
    db.set_projection_checkpoint("dm_session:thread:recv", last)?;
    db.enable_runtime()?;
    assert!(db.event_body(first)?.is_none());
    assert!(db.event_body(last)?.is_none());
    let tombstones:i64=db.connection.query_row("SELECT count(*) FROM local_event_log WHERE signature_status='retired' AND event_body=x'7b7d' AND length(signature)=0",[],|row|row.get(0))?;
    assert_eq!(tombstones, 2);
    let dangling:i64=db.connection.query_row("SELECT count(*) FROM event_causal_dependency d LEFT JOIN local_event_log e ON e.event_id=d.depends_on_event_id WHERE e.event_id IS NULL",[],|row|row.get(0))?;
    assert_eq!(dangling, 0);
    let previous: String = db.connection.query_row(
        "SELECT causal_prev_json FROM local_event_log WHERE event_id='after'",
        [],
        |row| row.get(0),
    )?;
    for id in serde_json::from_str::<Vec<String>>(&previous)? {
        let exists: bool = db.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM local_event_log WHERE event_id=?1)",
            rusqlite::params![id],
            |row| row.get(0),
        )?;
        assert!(exists);
    }
    db.append_event("next", "text", b"next")?;
    let counter: i64 = db.connection.query_row(
        "SELECT device_counter FROM local_event_log WHERE event_id='next'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(counter, 5);
    let bundle = db.export_history_bundle("device", "target")?;
    assert_eq!(bundle.encrypted_event_batch.len(), 3);
    assert!(
        bundle.encrypted_event_batch.iter().all(|event| event.event_type != "dm.ratchet_session")
    );
    let (target_root, target, _) = signed_test_db("ratchet-retirement-import")?;
    target.import_history_bundle(&bundle)?;
    assert_eq!(target.event_body("after")?, Some(b"after".to_vec()));
    drop(target);
    drop(db);
    fs::remove_dir_all(target_root)?;
    fs::remove_dir_all(root)?;
    Ok(())
}
