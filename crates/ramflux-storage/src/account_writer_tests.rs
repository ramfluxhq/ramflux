// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Real child processes prove account ownership survives worker/reader lifetimes.

use crate::{AccountDb, AccountDbKey, AccountIndex, StorageError};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Barrier, Mutex, mpsc};
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

#[test]
fn same_process_reacquire_waits_until_the_previous_descriptor_is_closed() -> TestResult {
    let (root, writer) = crate::tests::test_db("same-process-writer-drop")?;
    drop(writer);
    let index = AccountIndex::open(&root)?;
    let lease = index.acquire_account_writer("acct")?;
    let expected = root.join("accounts/acct/.writer.lock").canonicalize()?;
    let (entered_tx, entered_rx) = mpsc::sync_channel(1);
    let (release_tx, release_rx) = mpsc::sync_channel(1);
    let release_rx = Arc::new(Mutex::new(release_rx));
    crate::account_writer::set_drop_hook(Some(Arc::new(move |path| {
        if path == expected {
            let _ = entered_tx.send(());
            if let Ok(receiver) = release_rx.lock() {
                let _ = receiver.recv();
            }
        }
    })))?;

    let dropping = std::thread::spawn(move || drop(lease));
    entered_rx.recv_timeout(Duration::from_secs(5))?;
    let root_for_reopen = root.clone();
    let (result_tx, result_rx) = mpsc::sync_channel(1);
    let reopening = std::thread::spawn(move || {
        let result = AccountIndex::open(&root_for_reopen)
            .and_then(|index| index.acquire_account_writer("acct"));
        let _ = result_tx.send(result);
    });
    assert!(
        result_rx.recv_timeout(Duration::from_millis(50)).is_err(),
        "reacquire must wait while the old descriptor is still locked"
    );
    release_tx.send(())?;
    dropping.join().map_err(|_| "drop thread panicked")?;
    let reopened = result_rx.recv_timeout(Duration::from_secs(5))??;
    reopening.join().map_err(|_| "reopen thread panicked")?;
    crate::account_writer::set_drop_hook(None)?;
    drop(reopened);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn same_process_registry_stress_never_reports_account_busy() -> TestResult {
    const THREADS: usize = 8;
    const CYCLES: usize = 2_000;
    let (root, writer) = crate::tests::test_db("same-process-writer-stress")?;
    drop(writer);
    let start = Arc::new(Barrier::new(THREADS));
    let mut workers = Vec::new();
    for _ in 0..THREADS {
        let root = root.clone();
        let start = Arc::clone(&start);
        workers.push(std::thread::spawn(move || -> Result<usize, StorageError> {
            let index = AccountIndex::open(root)?;
            start.wait();
            let mut busy = 0;
            for _ in 0..CYCLES {
                match index.acquire_account_writer("acct") {
                    Ok(lease) => drop(lease),
                    Err(StorageError::AccountWriterBusy(_)) => busy += 1,
                    Err(error) => return Err(error),
                }
            }
            Ok(busy)
        }));
    }
    let mut busy = 0;
    for worker in workers {
        busy += worker.join().map_err(|_| "writer stress thread panicked")??;
    }
    assert_eq!(busy, 0, "same-process registry handoff must never surface as account busy");
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn writer_lock_filesystem_error_names_the_real_lock_path() -> TestResult {
    let (root, writer) = crate::tests::test_db("writer-lock-open-error")?;
    drop(writer);
    let account = root.join("accounts/acct");
    let path = account.join(".writer.lock");
    std::fs::remove_file(&path)?;
    std::fs::create_dir(&path)?;
    let expected = account.canonicalize()?.join(".writer.lock");
    let Err(error) = AccountIndex::open(&root)?.acquire_account_writer("acct") else {
        return Err("directory lock path unexpectedly opened".into());
    };
    let message = error.to_string();
    assert!(message.contains("account writer lock failed"));
    assert!(message.contains(path.to_string_lossy().as_ref()));
    assert!(
        matches!(error, StorageError::AccountWriterLock { path: ref failed, .. } if failed == &expected)
    );
    std::fs::remove_dir_all(root)?;
    Ok(())
}
