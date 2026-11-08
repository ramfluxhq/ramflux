// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Backup-path exclusion for the S6b P17 reply-outbox row kind (`gateway/reply-outbox/`
//! and `gateway/reply-transferred/`). Existing policy already excludes `gateway/%`.
#![allow(clippy::expect_used, clippy::panic)]

use crate::{AccountDb, AccountIndex, BackupDatabase, StorageError};
use serde_json::json;

const OUTBOX: &str = "gateway/reply-outbox/";
const MARKER: &str = "gateway/reply-transferred/";

fn count(db: &rusqlite::Connection, prefix: &str) -> Result<i64, StorageError> {
    Ok(db.query_row(
        "SELECT count(*) FROM runtime_actor_state WHERE state_kind LIKE ?1",
        rusqlite::params![format!("{prefix}%")],
        |row| row.get(0),
    )?)
}

/// Exclusion on backup file, archive sanitize, native merge and fresh restore.
#[test]
fn reply_outbox_backup_exclusion() -> Result<(), StorageError> {
    let (root, db) = crate::tests::test_db("reply-outbox-backup")?;
    db.persist_actor_state(&format!("{OUTBOX}row"), &json!({"envelope_id": "e1"}))?;
    db.persist_actor_state(&format!("{MARKER}row"), &true)?;
    db.persist_actor_state("surface/reply-outbox/leaked", &json!({"envelope_id": "leak"}))?;

    let incoming = root.join("incoming.db");
    let snapshot = db.write_backup_snapshot(&incoming)?;
    let archive_path = root.join("archive.db");
    std::fs::copy(&incoming, &archive_path)?;

    let archive = BackupDatabase::open(&archive_path, &snapshot.key)?;
    archive.sanitize_native_backup()?;
    assert_eq!(count(&archive.db, OUTBOX)?, 0, "archive sanitize must strip reply outbox");
    assert_eq!(count(&archive.db, MARKER)?, 0, "archive sanitize must strip reply marker");
    drop(archive);
    let file = BackupDatabase::open(&archive_path, &snapshot.key)?;
    assert_eq!(count(&file.db, OUTBOX)?, 0, "published backup file must strip reply outbox");
    drop(file);

    let local_index = AccountIndex::open(root.join("local"))?;
    local_index.create_account("acct", "principal")?;
    let local_key = crate::AccountDbKey::derive("acct", b"storage-test-secret");
    let local = AccountDb::open(&local_index, "acct", &local_key)?;
    let target = root.join("merged.db");
    let copied = local.write_backup_snapshot(&target)?;
    let mut merged = BackupDatabase::open(&target, &copied.key)?;
    merged.merge_native_backup(&incoming, &snapshot.key, || Ok(()))?;
    assert_eq!(count(&merged.db, OUTBOX)?, 0, "native merge must strip reply outbox");
    assert_eq!(count(&merged.db, MARKER)?, 0, "native merge must strip reply marker");
    let leaked: i64 = merged.db.query_row(
        "SELECT count(*) FROM runtime_actor_state WHERE state_kind='surface/reply-outbox/leaked'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(
        leaked, 1,
        "omit gateway/ backup exclusion: a surface-prefixed outbox row is imported"
    );

    let restore_index = AccountIndex::open(root.join("restore"))?;
    restore_index.create_account("acct", "principal")?;
    let restore_key = crate::AccountDbKey::derive("acct", b"storage-test-secret");
    let restore = AccountDb::open(&restore_index, "acct", &restore_key)?;
    let restore_target = root.join("fresh-restore.db");
    let restore_snap = restore.write_backup_snapshot(&restore_target)?;
    let mut fresh = BackupDatabase::open(&restore_target, &restore_snap.key)?;
    fresh.merge_native_backup(&incoming, &snapshot.key, || Ok(()))?;
    assert_eq!(count(&fresh.db, OUTBOX)?, 0, "fresh restore must strip reply outbox");

    drop(db);
    drop(local);
    drop(restore);
    std::fs::remove_dir_all(root)?;
    Ok(())
}
