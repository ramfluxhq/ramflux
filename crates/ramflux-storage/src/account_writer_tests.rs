// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Real child processes prove account ownership survives worker/reader lifetimes.

use crate::{AccountDb, AccountDbKey, AccountIndex, StorageError};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

type TestResult = Result<(), Box<dyn std::error::Error>>;
const CHILD_TEST: &str = "account_writer_tests::account_writer_process_fixture";

fn open(root: &Path) -> Result<AccountDb, StorageError> {
    AccountDb::open(
        &AccountIndex::open(root)?,
        "acct",
        &AccountDbKey::derive("acct", b"storage-test-secret"),
    )
}

struct ChildGuard(Child);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn child(root: &Path, mode: &str) -> Result<ChildGuard, std::io::Error> {
    Ok(ChildGuard(
        Command::new(std::env::current_exe()?)
            .args(["--exact", CHILD_TEST, "--nocapture"])
            .env("RAMFLUX_WRITER_LOCK_TEST_ROOT", root)
            .env("RAMFLUX_WRITER_LOCK_TEST_MODE", mode)
            .stdin(Stdio::null())
            .spawn()?,
    ))
}

fn completed(root: &Path, mode: &str) -> TestResult {
    let mut child = child(root, mode)?;
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(status) = child.0.try_wait()? {
            assert!(status.success(), "writer fixture {mode}: {status}");
            return Ok(());
        }
        assert!(Instant::now() < deadline, "writer fixture {mode} timed out");
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn account_writer_process_fixture() -> TestResult {
    let Some(root) = std::env::var_os("RAMFLUX_WRITER_LOCK_TEST_ROOT") else {
        return Ok(());
    };
    let root = Path::new(&root);
    let mode = std::env::var("RAMFLUX_WRITER_LOCK_TEST_MODE")?;
    if mode == "metadata-busy" {
        let index = AccountIndex::open(root)?;
        let before = index.account("acct")?;
        assert!(matches!(
            index.create_account("acct", "replacement"),
            Err(StorageError::AccountWriterBusy(_))
        ));
        let wrapped = crate::WrappedAccountDbKey {
            key_wrapping_provider: "test".into(),
            key_wrapping_ref: "test:acct".into(),
            nonce: [1; 12],
            wrapped_key: vec![2; 48],
        };
        let install = crate::BackupIndexInstall {
            account_id: "acct",
            principal_commitment: &before.principal_commitment,
            db_relative_path: "accounts/acct/generation_new/account.db",
            object_relative_path: "accounts/acct/generation_new",
            manifest_json: b"test manifest",
            wrapped_key: &wrapped,
        };
        assert!(matches!(
            index.install_backup_generation(&install),
            Err(StorageError::AccountWriterBusy(_))
        ));
        let after = index.account("acct")?;
        assert_eq!(after.principal_commitment, before.principal_commitment);
        assert_eq!(after.db_relative_path, before.db_relative_path);
        return Ok(());
    }
    let result = open(root);
    if mode == "busy" {
        assert!(
            matches!(result, Err(StorageError::AccountWriterBusy(ref account)) if account == "acct")
        );
        return Ok(());
    }
    let _db = result?;
    if mode == "hold" {
        std::fs::write(root.join("holder-ready"), [])?;
        // Bound this fixture even if its parent crashes before cleaning it up.
        std::thread::sleep(Duration::from_secs(60));
    } else {
        assert_eq!(mode, "open");
    }
    Ok(())
}

#[test]
fn account_writer_two_process_exclusion_and_lost_holder_recovery() -> TestResult {
    let (root, writer) = crate::tests::test_db("cross-process-writer")?;
    let reader = writer.open_reader()?;
    let worker_clone = writer.connection.clone();
    let lock_path = root.join("accounts/acct/.writer.lock");
    assert_eq!(std::fs::metadata(&lock_path)?.len(), 0);
    completed(&root, "busy")?;
    completed(&root, "metadata-busy")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::{PermissionsExt, symlink};
        assert_eq!(std::fs::metadata(&lock_path)?.permissions().mode() & 0o777, 0o600);
        let alias = root.join("index-alias");
        symlink(&root, &alias)?;
        completed(&alias, "busy")?;
    }
    // Same-owner SQLite connections remain supported and share the process lease.
    let second = open(&root)?;
    drop(writer);
    drop(second);
    completed(&root, "busy")?;
    drop(worker_clone);
    // Query-only readers do not retain the writer lease.
    completed(&root, "open")?;
    let index = AccountIndex::open(&root)?;
    let restore_lease = index.acquire_account_writer("acct")?;
    completed(&root, "busy")?;
    drop(restore_lease);
    completed(&root, "open")?;
    drop(index);
    drop(reader);

    let mut holder = child(&root, "hold")?;
    let deadline = Instant::now() + Duration::from_secs(30);
    while !root.join("holder-ready").exists() {
        assert!(holder.0.try_wait()?.is_none(), "holder exited before readiness");
        assert!(Instant::now() < deadline, "holder startup timed out");
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(matches!(open(&root), Err(StorageError::AccountWriterBusy(_))));
    holder.0.kill()?;
    holder.0.wait()?;
    // The persistent empty file is not ownership; the killed process's kernel
    // lock is gone. No PID/mtime deletion or backup-restored lease is needed.
    assert!(lock_path.exists());
    completed(&root, "open")?;
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn backup_snapshot_contains_database_not_writer_ownership() -> TestResult {
    let (root, writer) = crate::tests::test_db("backup-no-writer-lease")?;
    let backup_dir = root.join("export");
    std::fs::create_dir(&backup_dir)?;
    let snapshot = backup_dir.join("account.db");
    let saved = writer.write_backup_snapshot(&snapshot)?;
    assert!(snapshot.exists());
    assert!(!backup_dir.join(".writer.lock").exists());
    drop(writer);
    // A restored database uses its destination account's fresh process lease.
    let destination = root.join("restored");
    let index = AccountIndex::open(&destination)?;
    let record = index.create_account("acct", "principal")?;
    std::fs::copy(snapshot, destination.join(record.db_relative_path))?;
    let restored = AccountDb::open(&index, "acct", &saved.key)?;
    completed(&destination, "busy")?;
    drop(restored);
    // The empty destination lock file stays local and grants no stored authority.
    assert_eq!(std::fs::metadata(destination.join("accounts/acct/.writer.lock"))?.len(), 0);
    std::fs::remove_dir_all(root)?;
    Ok(())
}
