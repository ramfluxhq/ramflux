// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::*;
use ramflux_storage::{AccountDb, AccountIndex, BackupOpenMode};

#[test]
fn candidate_input_checks_authenticated_counts_before_private_changes()
-> Result<(), Box<dyn std::error::Error>> {
    let root = ramflux_test_support::TestPath::new()
        .expect("test: allocate fixture directory")
        .child(format!(
            "rf-worker-input-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_nanos()
        ));
    let index = AccountIndex::open(&root)?;
    index.create_account("account", "principal")?;
    let key = AccountDbKey::generate()?;
    let db = AccountDb::open(&index, "account", &key)?;
    db.persist_actor_state("surface/state/input", &serde_json::json!({"revision":1}))?;
    for mode in [BackupOpenMode::PreNormalization, BackupOpenMode::Normalized] {
        let path = root.join(format!("input-{mode:?}.db"));
        let snapshot = db.write_backup_snapshot(&path)?;
        let input = open_checked_input(&path, &snapshot.key, &snapshot.counts, mode)
            .map_err(|e| format!("input failed: {e:?}"))?;
        assert_eq!(input.original_input().counts.surfaces, 1);
        let mut wrong = snapshot.counts.clone();
        wrong.surfaces += 1;
        let Err(error) = open_checked_input(&path, &snapshot.key, &wrong, mode) else {
            return Err("authenticated count mismatch accepted".into());
        };
        assert_eq!(error.code, BackupFailureCode::Tampered);
        input.put_state("surface/state/private", &serde_json::json!({"revision":2}))?;
        assert_eq!(input.counts()?.surfaces, 2);
        assert_eq!(input.original_input().counts, snapshot.counts);
    }
    drop(db);
    drop(index);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

fn raw_snapshot(
    path: &std::path::Path,
    key: &AccountDbKey,
) -> rusqlite::Result<rusqlite::Connection> {
    use std::fmt::Write;
    let mut hex = zeroize::Zeroizing::new(String::new());
    for byte in key.bytes() {
        write!(&mut *hex, "{byte:02x}").map_err(|_| rusqlite::Error::InvalidQuery)?;
    }
    let sql = zeroize::Zeroizing::new(format!("PRAGMA key=\"x'{}'\"", hex.as_str()));
    let db = rusqlite::Connection::open(path)?;
    db.execute_batch(&sql)?;
    Ok(db)
}

#[test]
fn checked_pre_bundle_input_can_be_restored_twice_without_foreign_authority()
-> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let index = AccountIndex::open(root.path())?;
    index.create_account("account", "principal")?;
    let key = AccountDbKey::generate()?;
    let db = AccountDb::open(&index, "account", &key)?;
    let archive_path = root.path().join("original.db");
    let archive = db.write_backup_snapshot(&archive_path)?;
    let raw = raw_snapshot(&archive_path, &archive.key)?;
    raw.execute_batch(
        "DROP TABLE account_mac_bundle; DELETE FROM schema_migration WHERE schema_version=14;",
    )?;
    for prefix in ["message/deleted/", "message/deleted-envelope/"] {
        raw.execute(
            "INSERT INTO runtime_actor_state VALUES(?1,?2)",
            rusqlite::params![
                format!("{prefix}{}", ramflux_protocol::encode_base64url([0x31; 32])),
                br#"{"version":2}"#.as_slice()
            ],
        )?;
    }
    drop(raw);
    let original = std::fs::read(&archive_path)?;
    for mode in 0..3 {
        let target_path = root.path().join(format!("target-{mode}.db"));
        let target = db.write_backup_snapshot(&target_path)?;
        let mut merged = BackupDatabase::open(&target_path, &target.key)?;
        for round in 0..2 {
            let stage_path = root.path().join(format!("stage-{mode}-{round}.db"));
            std::fs::copy(&archive_path, &stage_path)?;
            let staged = open_checked_input(
                &stage_path,
                &archive.key,
                &archive.counts,
                BackupOpenMode::PreNormalization,
            )
            .map_err(|e| format!("production input check failed: {e:?}"))?;
            drop(staged);
            let stage_bytes = std::fs::read(&stage_path)?;
            match mode {
                0 => {
                    merged.merge_backup(&stage_path, &archive.key, || Ok(()))?;
                }
                1 => {
                    merged.merge_native_backup(&stage_path, &archive.key, || Ok(()))?;
                }
                _ => {
                    merged.merge_backup_candidate(&stage_path, &archive.key, || Ok(()))?;
                }
            }
            let inspect = raw_snapshot(&target_path, &target.key)?;
            assert_eq!(
                inspect.query_row("SELECT count(*) FROM account_mac_bundle", [], |r| r
                    .get::<_, u64>(0))?,
                1
            );
            assert_eq!(
                inspect
                    .query_row("SELECT count(*) FROM account_mac_marker_bundle", [], |r| r
                        .get::<_, u64>(0))?,
                0
            );
            assert_eq!(
                inspect.query_row(
                    "SELECT count(*) FROM account_mac_legacy_origin WHERE kind='marker'",
                    [],
                    |r| r.get::<_, u64>(0)
                )?,
                2
            );
            assert_eq!(std::fs::read(&stage_path)?, stage_bytes);
        }
    }
    assert_eq!(std::fs::read(&archive_path)?, original);
    Ok(())
}

#[test]
fn initial_archive_observation_ignores_archive_supplied_private_origin()
-> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let index = AccountIndex::open(root.path())?;
    index.create_account("account", "principal")?;
    let key = AccountDbKey::generate()?;
    let db = AccountDb::open(&index, "account", &key)?;
    for (n, mode) in
        [BackupOpenMode::PreNormalization, BackupOpenMode::Normalized].into_iter().enumerate()
    {
        let path = root.path().join(format!("input-{n}.db"));
        let saved = db.write_backup_snapshot(&path)?;
        let raw = raw_snapshot(&path, &saved.key)?;
        let physical: i64 =
            raw.query_row("SELECT MAX(schema_version) FROM schema_migration", [], |r| r.get(0))?;
        raw.execute_batch("CREATE TABLE backup_input_origin(singleton INTEGER PRIMARY KEY,schema_version INTEGER NOT NULL); INSERT INTO backup_input_origin VALUES(1,12);")?;
        drop(raw);
        let input = open_checked_input(&path, &saved.key, &saved.counts, mode)
            .map_err(|e| format!("initial archive: {e:?}"))?;
        assert_eq!(input.original_input().schema_version, physical);
        let reopened = BackupDatabase::open_restore_input(&path, &saved.key, mode)?;
        assert_eq!(reopened.original_input().schema_version, physical);
    }
    Ok(())
}
