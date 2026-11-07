// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Completing migration of pre-fix replay and envelope copies, merge registration and refusal.
use super::tests::{actor_owners, audit, envelope_value, old_archive_trigger_fixture, reopen};
use super::*;
use crate::{AccountDbKey, AccountIndex};
use serde_json::json;

const MARKER: &str = "footprint_replay_migration:v1";

fn checkpoint(db: &AccountDb, name: &str) -> Result<Option<String>, StorageError> {
    use rusqlite::OptionalExtension;
    Ok(db
        .connection
        .query_row(
            "SELECT last_event_id FROM projection_checkpoint WHERE projection_name=?1",
            params![name],
            |row| row.get(0),
        )
        .optional()?)
}

/// An envelope-bearing value with a payload hash no other row shares.
fn unique_value(owner: &str, n: usize) -> serde_json::Value {
    let mut value = envelope_value(owner);
    value["entry"]["envelope"]["payload_hash"] = json!(format!("payload-{n}"));
    value
}

fn count(db: &AccountDb, sql: &str) -> Result<i64, StorageError> {
    Ok(db.connection.query_row(sql, [], |row| row.get(0))?)
}

/// 2,500 pre-fix rows: 1,200 no-op replay values and 1,300 envelope copies across both tables.
/// Owners are mixed live/deleted; `late` owns the highest-rowid copy of each table.
fn pre_fix_fixture(name: &str) -> Result<(std::path::PathBuf, AccountDb), StorageError> {
    let (root, db) = old_archive_trigger_fixture(name)?;
    for owner in ["live", "late", "gone"] {
        db.send_direct_message("thread", owner, "peer", b"secret")?;
    }
    db.delete_direct_message("thread", "gone", "local", "delete-gone")?;
    db.write_transaction(|| -> Result<(), StorageError> {
        for n in 0..600 {
            let noop = serde_json::to_vec(&json!({"event_id":format!("e{n}")}))?;
            db.connection.execute(
                "INSERT INTO runtime_actor_state(state_kind,state_json) VALUES(?1,?2)",
                params![format!("legacy/replay/a2i/r{n}"), noop],
            )?;
            db.connection.execute(
                "INSERT INTO backup_archived_actor_state(source,state_kind,state_json) VALUES('s',?1,?2)",
                params![format!("legacy/replay/a2i/a{n}"), noop],
            )?;
        }
        for n in 0..700 {
            let owner = if n == 699 { "late" } else if n % 2 == 0 { "live" } else { "gone" };
            let prefix = if n % 3 == 0 { "legacy/replay/committed" } else { "zz-new" };
            db.connection.execute(
                "INSERT INTO runtime_actor_state(state_kind,state_json) VALUES(?1,?2)",
                params![format!("{prefix}/r{n}"), serde_json::to_vec(&unique_value(owner, n))?],
            )?;
        }
        for n in 0..600 {
            let owner = if n == 599 { "late" } else if n % 2 == 0 { "live" } else { "gone" };
            db.connection.execute(
                "INSERT INTO backup_archived_actor_state(source,state_kind,state_json) VALUES('s',?1,?2)",
                params![format!("zz-new/a{n}"), serde_json::to_vec(&unique_value(owner, 1000 + n))?],
            )?;
        }
        db.connection.execute(
            "DELETE FROM projection_checkpoint WHERE projection_name LIKE 'footprint_replay_migration:v1%'",
            [],
        )?;
        Ok(())
    })?;
    db.connection.execute_batch(
        "CREATE TABLE footprint_migration_test_visits(table_name TEXT,row_id INTEGER);",
    )?;
    assert_eq!(checkpoint(&db, MARKER)?, None);
    Ok((root, db))
}

fn message_rows(db: &AccountDb, owner: &str) -> Result<(i64, i64), StorageError> {
    let live = count(
        db,
        &format!(
            "SELECT count(*) FROM runtime_actor_state WHERE state_kind GLOB '*/r[0-9]*' \
             AND json_extract(CAST(state_json AS TEXT),'$.routing.message_id')='{owner}'"
        ),
    )?;
    let archived = count(
        db,
        &format!(
            "SELECT count(*) FROM backup_archived_actor_state WHERE state_kind GLOB 'zz-new/a[0-9]*' \
             AND json_extract(CAST(state_json AS TEXT),'$.routing.message_id')='{owner}'"
        ),
    )?;
    Ok((live, archived))
}

#[test]
fn replay_footprint_migration_completes_on_open() -> Result<(), StorageError> {
    let (root, db) = pre_fix_fixture("footprint-migration-complete")?;
    let db = reopen(&root, db)?;
    // (a) One open completes: marker, cursors at the end, audit empty.
    assert_eq!(checkpoint(&db, MARKER)?.as_deref(), Some("complete"));
    for table in ["runtime_actor_state", "backup_archived_actor_state"] {
        let cursor = checkpoint(&db, &format!("{MARKER}:{table}"))?;
        assert_eq!(cursor, Some(i64::MAX.to_string()), "{table}");
    }
    assert_eq!(audit(&db)?, Vec::<String>::new());
    // (b) Every candidate, no-op rows included, is visited exactly once.
    assert_eq!(count(&db, "SELECT count(*) FROM footprint_migration_test_visits")?, 2500);
    assert_eq!(
        count(
            &db,
            "SELECT count(DISTINCT table_name||row_id) FROM footprint_migration_test_visits"
        )?,
        2500
    );
    // Copies of the already-deleted owner were erased; live and late copies were registered.
    assert_eq!(message_rows(&db, "gone")?, (0, 0));
    let (live_runtime, live_archive) = message_rows(&db, "live")?;
    assert!(live_runtime > 0 && live_archive > 0);
    assert_eq!(message_rows(&db, "late")?, (1, 1));
    // (c) Deleting M_late, whose copies sit in the last chunk, leaves no residual copy.
    db.delete_direct_message("thread", "late", "local", "delete-late")?;
    assert_eq!(message_rows(&db, "late")?, (0, 0));
    let db = reopen(&root, db)?;
    assert_eq!(message_rows(&db, "late")?, (0, 0));
    assert_eq!(message_rows(&db, "live")?, (live_runtime, live_archive));
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn replay_footprint_migration_resumes_from_its_cursor_after_a_crash() -> Result<(), StorageError> {
    let (root, db) = pre_fix_fixture("footprint-migration-crash")?;
    // (e) The first open stops once after its second chunk; the next open resumes.
    db.connection.execute_batch(
        "CREATE TABLE footprint_migration_test_stop(chunks INTEGER); INSERT INTO footprint_migration_test_stop VALUES(2);",
    )?;
    assert!(reopen(&root, db).is_err());
    let db = AccountDb::open(
        &AccountIndex::open(&root)?,
        "acct",
        &AccountDbKey::derive("acct", b"storage-test-secret"),
    )?;
    assert_eq!(checkpoint(&db, MARKER)?.as_deref(), Some("complete"));
    assert_eq!(audit(&db)?, Vec::<String>::new());
    assert_eq!(
        count(
            &db,
            "SELECT count(DISTINCT table_name||row_id) FROM footprint_migration_test_visits"
        )?,
        2500
    );
    assert_eq!(count(&db, "SELECT count(*) FROM footprint_migration_test_visits")?, 2500);
    assert_eq!(message_rows(&db, "late")?, (1, 1));
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn replay_footprint_migration_marker_gates_deletion_and_merge() -> Result<(), StorageError> {
    // (f) Without the marker, deletion and merge refuse with the typed error.
    let (root, db) = crate::tests::test_db("footprint-migration-refusal")?;
    db.send_direct_message("thread", "message", "peer", b"secret")?;
    db.connection
        .execute("DELETE FROM projection_checkpoint WHERE projection_name=?1", params![MARKER])?;
    let error = db.delete_direct_message("thread", "message", "local", "delete");
    assert!(matches!(error, Err(StorageError::FootprintMigrationIncomplete)), "{error:?}");
    db.connection.execute(
        "INSERT INTO projection_checkpoint VALUES(?1,1,'complete',NULL,0)",
        params![MARKER],
    )?;
    db.delete_direct_message("thread", "message", "local", "delete")?;
    drop(db);
    std::fs::remove_dir_all(root)?;

    let root = crate::tests::temp_root("footprint-migration-merge-refusal");
    let source_index = AccountIndex::open(root.join("source"))?;
    let local_index = AccountIndex::open(root.join("local"))?;
    source_index.create_account("account", "root")?;
    local_index.create_account("account", "root")?;
    let source = AccountDb::open(&source_index, "account", &AccountDbKey::generate()?)?;
    let local = AccountDb::open(&local_index, "account", &AccountDbKey::generate()?)?;
    let incoming = root.join("incoming.db");
    let snapshot = source.write_backup_snapshot(&incoming)?;
    let path = root.join("merged.db");
    let target = local.write_backup_snapshot(&path)?;
    let mut merged = crate::BackupDatabase::open(&path, &target.key)?;
    merged
        .db
        .execute("DELETE FROM projection_checkpoint WHERE projection_name=?1", params![MARKER])?;
    let error = merged.merge_backup(&incoming, &snapshot.key, || Ok(()));
    assert!(matches!(error, Err(StorageError::FootprintMigrationIncomplete)), "{:?}", error.err());
    drop(merged);
    drop(source);
    drop(local);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn replay_footprint_migration_merge_erases_late_owner_and_registers_imported_rows()
-> Result<(), StorageError> {
    let root = crate::tests::temp_root("footprint-migration-merge");
    let source_index = AccountIndex::open(root.join("source"))?;
    let local_index = AccountIndex::open(root.join("local"))?;
    source_index.create_account("account", "root")?;
    local_index.create_account("account", "root")?;
    let source_key = AccountDbKey::derive("account", b"source-secret");
    let local_key = AccountDbKey::derive("account", b"local-secret");
    let source = AccountDb::open(&source_index, "account", &source_key)?;
    let local = AccountDb::open(&local_index, "account", &local_key)?;
    for db in [&source, &local] {
        db.send_direct_message("thread", "late", "peer", b"secret")?;
        db.send_direct_message("thread", "kept", "peer", b"secret")?;
    }
    // (d) The incoming snapshot deletes M_late; the local copies are pre-fix rows that the
    // next open registers.
    source.delete_direct_message("thread", "late", "local", "delete-late")?;
    for (n, (key, owner)) in
        [("zz-new/local-late", "late"), ("zz-new/local-kept", "kept")].into_iter().enumerate()
    {
        local.connection.execute(
            "INSERT INTO runtime_actor_state(state_kind,state_json) VALUES(?1,?2)",
            params![key, serde_json::to_vec(&unique_value(owner, 5000 + n))?],
        )?;
    }
    local.connection.execute(
        "DELETE FROM projection_checkpoint WHERE projection_name LIKE 'footprint_replay_migration:v1%'",
        [],
    )?;
    drop(local);
    let local = AccountDb::open(&local_index, "account", &local_key)?;
    assert_eq!(actor_owners(&local, "zz-new/local-late")?.len(), 2);
    // (g) Pre-fix rows that exist only in the incoming snapshot carry no footprint.
    for (n, key) in ["zz-new/imported", "legacy/replay/committed/imported"].into_iter().enumerate()
    {
        source.connection.execute(
            "INSERT INTO runtime_actor_state(state_kind,state_json) VALUES(?1,?2)",
            params![key, serde_json::to_vec(&unique_value("kept", 6000 + n))?],
        )?;
    }
    let incoming = root.join("incoming.db");
    let snapshot = source.write_backup_snapshot(&incoming)?;
    let path = root.join("merged.db");
    let target = local.write_backup_snapshot(&path)?;
    let mut merged = crate::BackupDatabase::open(&path, &target.key)?;
    merged.merge_backup(&incoming, &snapshot.key, || Ok(()))?;
    let rows = |db: &rusqlite::Connection, like: &str| -> rusqlite::Result<i64> {
        db.query_row(
            "SELECT (SELECT count(*) FROM runtime_actor_state WHERE state_kind GLOB ?1) \
                  + (SELECT count(*) FROM backup_archived_actor_state WHERE state_kind GLOB ?1)",
            params![like],
            |row| row.get(0),
        )
    };
    assert_eq!(rows(&merged.db, "zz-new/local-late")?, 0);
    assert_eq!(rows(&merged.db, "zz-new/local-kept")?, 1);
    let imported = |db: &rusqlite::Connection| -> rusqlite::Result<i64> {
        db.query_row(
            "SELECT count(*) FROM runtime_actor_state a JOIN message_footprint f \
             ON f.kind='actor' AND f.locator=a.state_kind AND f.message_id='kept' \
             WHERE a.state_kind IN ('zz-new/imported','legacy/replay/committed/imported')",
            [],
            |row| row.get(0),
        )
    };
    assert_eq!(imported(&merged.db)?, 2);
    assert_eq!(audit::unregistered_envelope_copies(&merged.db, 16)?, Vec::<String>::new());
    merged
        .db
        .execute("UPDATE direct_message_projection SET deleted=1 WHERE message_id='kept'", [])?;
    assert_eq!(rows(&merged.db, "*imported")?, 0);
    assert_eq!(rows(&merged.db, "zz-new/local-kept")?, 0);
    drop(merged);
    let reopened = crate::BackupDatabase::open(&path, &target.key)?;
    assert_eq!(rows(&reopened.db, "*imported")?, 0);
    drop(reopened);
    drop(local);
    drop(source);
    std::fs::remove_dir_all(root)?;
    Ok(())
}
