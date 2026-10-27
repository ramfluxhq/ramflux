// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Private jobs cannot race their public progress, escape into backups or overwrite another job.
use super::*;
use crate::{AccountDbKey, AccountIndex, BackupDatabase};
use std::path::PathBuf;
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
struct Root(PathBuf);
impl Drop for Root {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn hash(byte: u8) -> String {
    ramflux_protocol::encode_base64url([byte; 32])
}
fn fixture() -> Result<(Root, AccountIndex, AccountDb, AccountDbKey)> {
    let root = Root(std::env::temp_dir().join(format!(
        "rf-home-migration-{}",
        ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?)
    )));
    let index = AccountIndex::open(&root.0)?;
    index.create_account("human", &hash(1))?;
    let key = AccountDbKey::generate()?;
    let db = AccountDb::open(&index, "human", &key)?;
    Ok((root, index, db, key))
}
fn progress(id: &str, revision: u64, phase: &str) -> Value {
    serde_json::json!({"operation_id":id,"seq":revision,"phase":phase,"source":"source","target":null,
        "home_epoch":null,"home_hash":null,"commit_deadline":null,"forward_until":null,
        "backlog":{"scheduled":0,"forwarded":0,"receiver_acked":0,"expired":0,"rejected":0,"evidence_required":0,"remaining":0}})
}
fn save(
    db: &AccountDb,
    id: &str,
    revision: u64,
    phase: &str,
) -> std::result::Result<(), StorageError> {
    db.persist_home_migration(HomeMigrationWrite {
        operation_id: id,
        account_anchor: &hash(1),
        intent_hash: &hash(2),
        expected_revision: (revision > 1).then_some(revision - 1),
        revision,
        active: true,
        recovery_blocked: phase == "seal_sent",
        next_attempt_at: 100,
        state: b"PRIVATE_AUTHORIZATION_AND_ADMISSION",
        progress: &progress(id, revision, phase),
    })
}
#[test]
fn home_migration_immutable_progress_and_private_state_survive_reopen_without_collapsing_phases()
-> Result {
    let (_root, index, db, key) = fixture()?;
    let id = hash(3);
    save(&db, &id, 1, "intent")?;
    save(&db, &id, 2, "prepare_sent")?;
    let entries =
        db.pending_outbox(256)?.into_iter().filter(|e| e.table_name == TAG).collect::<Vec<_>>();
    assert_eq!(entries.len(), 2);
    assert_eq!(
        db.home_migration_transition(entries[0].row_id)?.ok_or("first transition")?["phase"],
        "intent"
    );
    assert_eq!(
        db.home_migration_transition(entries[1].row_id)?.ok_or("second transition")?["phase"],
        "prepare_sent"
    );
    assert!(!serde_json::to_string(&entries)?.contains("PRIVATE_AUTHORIZATION"));
    let before = db.home_migration_job(&id)?.ok_or("saved job")?;
    drop(db);
    let reopened = AccountDb::open(&index, "human", &key)?;
    assert_eq!(reopened.home_migration_job(&id)?.ok_or("reopened job")?, before);
    Ok(())
}
#[test]
fn home_migration_failed_outbox_or_outer_transaction_leaves_no_partial_phase() -> Result {
    let (_root, _index, db, _key) = fixture()?;
    let id = hash(3);
    db.connection.execute_batch("CREATE TRIGGER fail_migration_outbox BEFORE INSERT ON runtime_outbox WHEN NEW.table_name='home_migration_progress' BEGIN SELECT RAISE(ABORT,'fixture'); END;")?;
    assert!(save(&db, &id, 1, "intent").is_err());
    assert!(db.home_migration_job(&id)?.is_none());
    let count: u64 = db.connection.query_row(
        "SELECT count(*) FROM runtime_home_migration_transition",
        [],
        |r| r.get(0),
    )?;
    assert_eq!(count, 0);
    db.connection.execute_batch("DROP TRIGGER fail_migration_outbox;")?;
    save(&db, &id, 1, "intent")?;
    let result = db.write_transaction(|| -> std::result::Result<(), StorageError> {
        save(&db, &id, 2, "seal_sent")?;
        Err(StorageError::AuthorizationRejected)
    });
    assert!(result.is_err());
    assert_eq!(db.home_migration_job(&id)?.ok_or("original job")?.revision, 1);
    assert_eq!(db.pending_outbox(256)?.into_iter().filter(|e| e.table_name == TAG).count(), 1);
    assert!(save(&db, &hash(4), 1, "intent").is_err());
    assert!(save(&db, &id, 1, "intent").is_err());
    assert_eq!(db.active_home_migration()?.ok_or("active")?.operation_id, id);
    Ok(())
}
#[test]
fn home_migration_export_and_import_cannot_rearm_private_jobs_or_migration_events() -> Result {
    let (root, _index, db, _key) = fixture()?;
    let id = hash(3);
    save(&db, &id, 1, "seal_sent")?;
    db.append_journal(
        "migration-fixture",
        "home_migration.progress",
        &progress(&id, 1, "seal_sent"),
        100,
        None,
    )?;
    let path = root.0.join("snapshot.db");
    let snapshot = db.write_backup_snapshot(&path)?;
    let archive = BackupDatabase::open(&path, &snapshot.key)?;
    let tables:u64=archive.db.query_row("SELECT count(*) FROM sqlite_master WHERE type='table' AND name LIKE 'runtime_home_migration_%'",[],|r|r.get(0))?;
    assert_eq!(tables, 0);
    let outbox: u64 = archive.db.query_row(
        "SELECT count(*) FROM runtime_outbox WHERE table_name='home_migration_progress'",
        [],
        |r| r.get(0),
    )?;
    let journal: u64 = archive.db.query_row(
        "SELECT count(*) FROM runtime_journal WHERE topic='home_migration.progress'",
        [],
        |r| r.get(0),
    )?;
    assert_eq!((outbox, journal), (0, 0));
    assert!(db.home_migration_job(&id)?.ok_or("live job")?.recovery_blocked);
    // An older/untrusted archive may carry private work; installation strips it too.
    archive.db.execute_batch("CREATE TABLE runtime_home_migration_job(state_json BLOB); INSERT INTO runtime_home_migration_job VALUES(x'0102');")?;
    archive.archive_outbound()?;
    let jobs:u64=archive.db.query_row("SELECT count(*) FROM sqlite_master WHERE type='table' AND name='runtime_home_migration_job'",[],|r|r.get(0))?;
    assert_eq!(jobs, 0);
    Ok(())
}

#[test]
fn home_migration_never_returns_a_send_plan_inside_an_uncommitted_outer_transaction() -> Result {
    let (_root, _index, db, _key) = fixture()?;
    let id = hash(3);
    let result = db.write_transaction(|| save(&db, &id, 1, "seal_sent"));
    assert!(matches!(result, Err(StorageError::AuthorizationRejected)));
    assert!(db.home_migration_job(&id)?.is_none());
    assert!(db.pending_outbox(256)?.iter().all(|entry| entry.table_name != TAG));
    Ok(())
}
