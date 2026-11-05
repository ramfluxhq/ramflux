// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Process death at the SQL durability boundary, followed by retry on the same stage.
use super::tests::fixture;
type TestResult = Result<(), Box<dyn std::error::Error>>;
use crate::{AccountDbKey, BackupDatabase, StorageError};
use rusqlite::Connection;

pub(in crate::account_db) fn before_commit(db: &Connection) -> Result<(), StorageError> {
    if db.query_row(
        "SELECT EXISTS(SELECT 1 FROM temp.sqlite_master WHERE name='abort_before_commit')",
        [],
        |r| r.get::<_, bool>(0),
    )? {
        assert!(!db.is_autocommit());
        assert_eq!(
            db.query_row(
                "SELECT count(*) FROM object_erasure_lookup WHERE lookup='incoming-opaque'",
                [],
                |r| r.get::<_, u64>(0)
            )?,
            1
        );
        std::process::abort();
    }
    Ok(())
}

#[test]
fn e14_child_abort_before_commit() -> TestResult {
    const ENV: &str = "RAMFLUX_RESTORE_SQL_ABORT_ROOT";
    if let Some(root) = std::env::var_os(ENV) {
        let root = std::path::PathBuf::from(root);
        let key = AccountDbKey::from_bytes([31; 32]);
        let mut stage = BackupDatabase::open(&root.join("abort-stage.db"), &key)?;
        stage.db.execute_batch("CREATE TEMP TABLE abort_before_commit(x);")?;
        stage.merge_backup_candidate(&root.join("abort-source.db"), &key, || Ok(()))?;
        return Err("child missed SQL abort checkpoint".into());
    }
    fixture("child-abort", |root, live, target, path, key| {
        let stage_path = root.join("abort-stage.db");
        let source_path = root.join("abort-source.db");
        let shared = AccountDbKey::from_bytes([31; 32]);
        target.copy_to(&stage_path, &shared)?;
        BackupDatabase::open(path, key)?.copy_to(&source_path, &shared)?;
        let source_before = std::fs::read(&source_path)?;
        let selected = crate::AccountIndex::open(root)?.account("acct")?;
        let status = std::process::Command::new(std::env::current_exe()?)
            .args(["--exact", "account_db::backup_selector_admission::staging_tests::e14_child_abort_before_commit", "--nocapture"])
            .env(ENV,root).status()?;
        #[cfg(unix)]
        {
            use std::os::unix::process::ExitStatusExt;
            assert_eq!(status.signal(), Some(6), "expected SIGABRT at SQL boundary");
        }
        let mut reopened = BackupDatabase::open(&stage_path, &shared)?;
        assert_eq!(
            reopened.db.query_row(
                "SELECT count(*) FROM object_erasure_lookup WHERE lookup='incoming-opaque'",
                [],
                |r| r.get::<_, u64>(0)
            )?,
            0
        );
        assert_eq!(reopened.db.query_row("SELECT count(*) FROM sqlite_master WHERE name LIKE 'backup_%admission' OR name='backup_lookup_origin'",[],|r|r.get::<_,u64>(0))?,0);
        assert_eq!(crate::AccountIndex::open(root)?.account("acct")?, selected);
        let _ = live;
        reopened.merge_backup_candidate(&source_path, &shared, || Ok(()))?;
        assert_eq!(
            reopened.db.query_row(
                "SELECT count(*) FROM object_erasure_lookup WHERE lookup='incoming-opaque'",
                [],
                |r| r.get::<_, u64>(0)
            )?,
            1
        );
        reopened.check_integrity()?;
        assert_eq!(std::fs::read(&source_path)?, source_before);
        Ok(())
    })
}
