// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Backup-path exclusion for the S6b P16 application-outbox row kind
//! (`gateway/application-outbox/`). Existing policy already excludes `gateway/%`.
#![allow(clippy::expect_used, clippy::panic)]

use crate::{AccountDb, AccountIndex, BackupDatabase, BackupOpenMode, StorageError};
use serde_json::json;

const OUTBOX: &str = "gateway/application-outbox/";

fn count(db: &rusqlite::Connection, prefix: &str) -> Result<i64, StorageError> {
    Ok(db.query_row(
        "SELECT count(*) FROM runtime_actor_state WHERE state_kind LIKE ?1",
        rusqlite::params![format!("{prefix}%")],
        |row| row.get(0),
    )?)
}

fn seed(db: &AccountDb) -> Result<(), StorageError> {
    db.persist_actor_state(
        &format!("{OUTBOX}row"),
        &json!({"envelope_id": "e1", "payload_hash": "p", "committed_key": "routed/committed/k"}),
    )?;
    db.persist_actor_state(
        "gateway/application-published/row",
        &json!({"envelope_id": "e1", "payload_hash": "p", "committed_key": "routed/committed/k"}),
    )?;
    db.persist_actor_state("surface/application-outbox/leaked", &json!({"envelope_id": "leak"}))?;
    Ok(())
}

fn assert_absent(db: &rusqlite::Connection, label: &str) -> Result<(), StorageError> {
    assert_eq!(count(db, OUTBOX)?, 0, "{label} must strip application outbox");
    Ok(())
}

/// Exclusion on the decrypted page-copy, archive sanitize, native merge, `archive_outbound`,
/// and a fresh restore (install → `copy_to` → normalize → `archive_outbound`).
#[test]
fn application_outbox_backup_exclusion() -> Result<(), StorageError> {
    let (root, db) = crate::tests::test_db("application-outbox-backup")?;
    seed(&db)?;
    assert_eq!(db.actor_state_usage(OUTBOX)?.0, 1, "live outbox must exist before backup");
    db.retire_outbound_for_recovery("recovery-head")?;
    assert_eq!(
        db.actor_state_usage(OUTBOX)?.0,
        1,
        "live recovery must keep pending application outbox rows"
    );
    assert_eq!(
        db.actor_state_usage("gateway/application-published/")?.0,
        1,
        "live recovery must keep the published marker"
    );

    let incoming = root.join("incoming.db");
    let snapshot = db.write_backup_snapshot(&incoming)?;
    let file = BackupDatabase::open(&incoming, &snapshot.key)?;
    assert_eq!(count(&file.db, OUTBOX)?, 1, "decrypted page copy must still hold the outbox");
    drop(file);

    let published = root.join("published.db");
    std::fs::copy(&incoming, &published)?;
    let archive = BackupDatabase::open(&published, &snapshot.key)?;
    archive.sanitize_native_backup()?;
    assert_absent(&archive.db, "archive sanitize")?;
    drop(archive);
    let published_file = BackupDatabase::open(&published, &snapshot.key)?;
    assert_absent(&published_file.db, "published backup file")?;
    drop(published_file);

    let local_index = AccountIndex::open(root.join("local"))?;
    local_index.create_account("acct", "principal")?;
    let local_key = crate::AccountDbKey::derive("acct", b"storage-test-secret");
    let local = AccountDb::open(&local_index, "acct", &local_key)?;
    let target = root.join("merged.db");
    let copied = local.write_backup_snapshot(&target)?;
    let mut merged = BackupDatabase::open(&target, &copied.key)?;
    merged.merge_native_backup(&incoming, &snapshot.key, || Ok(()))?;
    assert_absent(&merged.db, "native merge")?;
    let leaked: i64 = merged.db.query_row(
        "SELECT count(*) FROM runtime_actor_state WHERE state_kind='surface/application-outbox/leaked'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(
        leaked, 1,
        "omit gateway/ backup exclusion: a surface-prefixed outbox row is imported"
    );
    drop(merged);

    let archived_path = root.join("archive-outbound.db");
    std::fs::copy(&incoming, &archived_path)?;
    let archived = BackupDatabase::open(&archived_path, &snapshot.key)?;
    archived.archive_outbound()?;
    assert_absent(&archived.db, "archive_outbound")?;
    drop(archived);

    // Fresh restore: install → copy_to → normalize → archive_outbound.
    let restore_root = root.join("restore");
    let restore_index = AccountIndex::open(&restore_root)?;
    let account = restore_index.create_account("acct", "principal")?;
    let installed = restore_root.join(account.db_relative_path);
    std::fs::create_dir_all(installed.parent().ok_or(StorageError::AuthorizationRejected)?)?;
    let incoming_open = BackupDatabase::open_restore_input(
        &incoming,
        &snapshot.key,
        BackupOpenMode::PreNormalization,
    )?;
    incoming_open.copy_to(&installed, &snapshot.key)?;
    drop(incoming_open);
    let mut restored = BackupDatabase::open_restore_input(
        &installed,
        &snapshot.key,
        BackupOpenMode::PreNormalization,
    )?;
    restored.normalize_backup_candidate()?;
    restored.archive_outbound()?;
    assert_absent(&restored.db, "fresh restore")?;
    drop(restored);

    drop(db);
    drop(local);
    std::fs::remove_dir_all(root)?;
    Ok(())
}
