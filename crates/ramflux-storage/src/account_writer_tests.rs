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
fn poisoned_registry_drop_releases_ownership_and_removes_the_entry() -> TestResult {
    let (root, writer) = crate::tests::test_db("poisoned-writer-registry")?;
    drop(writer);
    let index = AccountIndex::open(&root)?;
    let lease = index.acquire_account_writer("acct")?;
    crate::account_writer::poison_registry();
    drop(lease);
    let (sent, received) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let result = index.acquire_account_writer("acct").map(drop);
        let _ = sent.send(result);
    });
    received
        .recv_timeout(std::time::Duration::from_secs(10))
        .map_err(|_| "writer reacquisition stalled after poisoned registry teardown")??;
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
    let Err(error) = AccountIndex::open(&root)?.acquire_account_writer("acct") else {
        return Err("directory lock path unexpectedly opened".into());
    };
    let message = error.to_string();
    assert!(message.contains("account writer lock failed"));
    assert!(message.contains(path.to_string_lossy().as_ref()));
    assert!(
        matches!(error, StorageError::Io(ref source) if source.kind() == std::io::ErrorKind::IsADirectory)
    );
    std::fs::remove_dir_all(root)?;
    Ok(())
}

fn wrapped_key() -> crate::WrappedAccountDbKey {
    crate::WrappedAccountDbKey {
        key_wrapping_provider: "platform-local-vault".to_owned(),
        key_wrapping_ref: "platform-local-vault:acct".to_owned(),
        nonce: [7; 12],
        wrapped_key: vec![9; 48],
    }
}

/// Relative path to (length, bytes) for every regular file under `dir`, sidecars included.
fn file_set(dir: &Path) -> std::io::Result<std::collections::BTreeMap<String, Vec<u8>>> {
    fn walk(
        base: &Path,
        dir: &Path,
        out: &mut std::collections::BTreeMap<String, Vec<u8>>,
    ) -> std::io::Result<()> {
        for entry in std::fs::read_dir(dir)? {
            let path = entry?.path();
            if path.is_dir() {
                walk(base, &path, out)?;
            } else {
                let name = path.strip_prefix(base).map_err(std::io::Error::other)?;
                out.insert(name.to_string_lossy().into_owned(), std::fs::read(&path)?);
            }
        }
        Ok(())
    }
    let mut out = std::collections::BTreeMap::new();
    walk(dir, dir, &mut out)?;
    Ok(out)
}

fn expect_busy<T>(result: &Result<T, StorageError>, id: &str) {
    assert!(
        matches!(&result, Err(StorageError::AccountWriterBusy(busy)) if busy == id),
        "expected AccountWriterBusy({id}), got {:?}",
        result.as_ref().err()
    );
}

fn expect_not_found<T>(result: &Result<T, StorageError>, id: &str) {
    assert!(
        matches!(&result, Err(StorageError::AccountNotFound(missing)) if missing == id),
        "expected AccountNotFound({id}), got {:?}",
        result.as_ref().err()
    );
}

#[test]
fn removed_account_never_reopens_empty() -> TestResult {
    // (a) Erase while open: Busy; state, wrapped key and DB bytes unchanged.
    let (root, db) = crate::tests::test_db("removed-account-reopen")?;
    let index = AccountIndex::open(&root)?;
    index.store_wrapped_db_key("acct", &wrapped_key())?;
    let account_dir = root.join("accounts/acct");
    // The storage layer has no background threads; open's maintenance has completed, so the
    // file set is stable while the handle stays idle.
    let before = file_set(&account_dir)?;
    assert!(before.contains_key("ramflux_local.sqlite"));
    expect_busy(&index.erase_account_database("acct"), "acct");
    assert_eq!(index.account("acct")?.account_state, "active");
    assert_eq!(index.load_wrapped_db_key("acct")?, Some(wrapped_key()));
    assert_eq!(file_set(&account_dir)?, before);
    // (d) shared holder refuses exclusive; (f) the refused erase left the account usable.
    drop(db);
    let shared = index.acquire_account_writer("acct")?;
    expect_busy(&index.erase_account_database("acct"), "acct");
    drop(shared);
    drop(open(&root)?);
    // (d) exclusive holder refuses shared, open and a second exclusive.
    let exclusive = crate::account_writer::AccountWriter::acquire_exclusive(&root, "acct")?;
    expect_busy(&index.acquire_account_writer("acct").map(drop), "acct");
    expect_busy(&open(&root).map(drop), "acct");
    expect_busy(
        &crate::account_writer::AccountWriter::acquire_exclusive(&root, "acct").map(drop),
        "acct",
    );
    drop(exclusive);
    // (b) Closed materialized account: erase is Ok and the key is cleared. File absence is
    // asserted by `account_erase_removes_db_wal_shm`.
    assert_eq!(index.load_wrapped_db_key("acct")?, Some(wrapped_key()));
    index.erase_account_database("acct")?;
    assert_eq!(index.account("acct")?.account_state, "removed");
    assert!(index.load_wrapped_db_key("acct")?.is_none());
    expect_not_found(&open(&root).map(drop), "acct");
    let db_file = account_dir.join("ramflux_local.sqlite");
    assert!(!db_file.exists(), "open must not recreate the DB of a removed account");
    index.erase_account_database("acct")?;
    // (e) Bad and unknown ids.
    for bad in ["", "..", "a/b", "/abs"] {
        assert!(
            matches!(index.erase_account_database(bad), Err(StorageError::AuthorizationRejected)),
            "bad id {bad:?}"
        );
    }
    expect_not_found(&index.erase_account_database("unknown"), "unknown");
    std::fs::remove_dir_all(root)?;
    Ok(())
}

struct OpenHookReset;
impl Drop for OpenHookReset {
    fn drop(&mut self) {
        crate::account_erase::set_open_race_hook(None);
    }
}

struct UpgradeHookReset;
impl Drop for UpgradeHookReset {
    fn drop(&mut self) {
        crate::account_writer::set_upgrade_hook(None);
    }
}

#[test]
fn busy_never_drops_the_last_owner_under_the_registry_lock() -> TestResult {
    // The upgraded Arc becomes the last one when the original holder drops between the
    // upgrade and the Busy decision. Both ownership modes must return Busy, not deadlock.
    for (holder_exclusive, requester_exclusive) in [(false, true), (true, false)] {
        let (root, db) = crate::tests::test_db("busy-last-owner")?;
        drop(db);
        let index = AccountIndex::open(&root)?;
        let canonical = root.join("accounts/acct/.writer.lock").canonicalize()?;
        let holder = if holder_exclusive {
            crate::account_writer::AccountWriter::acquire_exclusive(&root, "acct")?
        } else {
            crate::account_writer::AccountWriter::acquire(&root, "acct")?
        };
        let (upgraded_tx, upgraded_rx) = mpsc::sync_channel(1);
        let (go_tx, go_rx) = mpsc::sync_channel(1);
        let go_rx = Mutex::new(go_rx);
        let _reset = UpgradeHookReset;
        // The hook runs with the registry mutex held, so it must never panic (a panic could drop
        // the last owner under that lock). Failures are recorded and asserted after completion.
        let barrier_failures = Arc::new(Mutex::new(Vec::<&'static str>::new()));
        let hook_failures = Arc::clone(&barrier_failures);
        crate::account_writer::set_upgrade_hook(Some(Arc::new(move |path| {
            if path != canonical {
                return;
            }
            let note = |failure: &'static str| {
                if let Ok(mut failures) = hook_failures.lock() {
                    failures.push(failure);
                }
            };
            if upgraded_tx.send(()).is_err() {
                note("upgrade notification channel closed");
            }
            match go_rx.lock() {
                Ok(receiver) => {
                    if receiver.recv_timeout(Duration::from_secs(10)).is_err() {
                        note("upgrade barrier timed out or its channel closed");
                    }
                }
                Err(_) => note("upgrade barrier mutex poisoned"),
            }
        })));
        let (done_tx, done_rx) = mpsc::sync_channel(1);
        let root_for_request = root.clone();
        std::thread::spawn(move || {
            let result = if requester_exclusive {
                crate::account_writer::AccountWriter::acquire_exclusive(&root_for_request, "acct")
            } else {
                crate::account_writer::AccountWriter::acquire(&root_for_request, "acct")
            };
            let _ = done_tx.send(result.map(drop));
        });
        upgraded_rx.recv_timeout(Duration::from_secs(10))?;
        drop(holder);
        go_tx.send(())?;
        let result = done_rx
            .recv_timeout(Duration::from_secs(10))
            .map_err(|_| "Busy deadlocked: the last owner was dropped under the registry lock")?;
        expect_busy(&result, "acct");
        // A barrier that was released by timeout instead of by the coordinator would let Busy
        // drop an Arc while the original holder still exists, which hides the deadlock.
        let failures = barrier_failures.lock().map_err(|_| "barrier failure log poisoned")?.clone();
        assert!(failures.is_empty(), "upgrade barrier failed: {failures:?}");
        drop(index);
        std::fs::remove_dir_all(root)?;
    }
    Ok(())
}

#[test]
fn removed_account_open_barrier_on_unmaterialized_account() -> TestResult {
    // (c) Erase lands between open's first read and its writer lease.
    let root = crate::tests::temp_root("removed-account-barrier");
    let index = AccountIndex::open(&root)?;
    index.create_account("ghost", "principal")?;
    let db_file = root.join("accounts/ghost/ramflux_local.sqlite");
    assert!(!db_file.exists());
    let (entered_tx, entered_rx) = mpsc::sync_channel(1);
    let (release_tx, release_rx) = mpsc::sync_channel(1);
    let release_rx = Mutex::new(release_rx);
    let timed_out = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let hook_timed_out = Arc::clone(&timed_out);
    let _reset = OpenHookReset;
    crate::account_erase::set_open_race_hook(Some(Arc::new(move |account| {
        if account != "ghost" {
            return;
        }
        let _ = entered_tx.send(());
        let released = release_rx
            .lock()
            .map_err(|_| ())
            .and_then(|receiver| receiver.recv_timeout(Duration::from_secs(10)).map_err(|_| ()));
        if released.is_err() {
            hook_timed_out.store(true, std::sync::atomic::Ordering::SeqCst);
        }
    })));
    let root_for_open = root.clone();
    let opener = std::thread::spawn(move || {
        AccountIndex::open(&root_for_open).and_then(|index| {
            AccountDb::open(&index, "ghost", &AccountDbKey::derive("ghost", b"storage-test-secret"))
                .map(drop)
        })
    });
    entered_rx.recv_timeout(Duration::from_secs(10))?;
    index.erase_account_database("ghost")?;
    release_tx.send(())?;
    let result = opener.join().map_err(|_| "opener thread panicked")?;
    assert!(
        !timed_out.load(std::sync::atomic::Ordering::SeqCst),
        "barrier release was not delivered; the opener resumed without the erase ordering"
    );
    expect_not_found(&result, "ghost");
    assert!(!db_file.exists(), "open must not create the DB path of a removed account");
    std::fs::remove_dir_all(root)?;
    Ok(())
}

fn lock_inode(path: &Path) -> std::io::Result<u64> {
    use std::os::unix::fs::MetadataExt;
    Ok(std::fs::metadata(path)?.ino())
}

#[test]
fn account_erase_removes_db_wal_shm() -> TestResult {
    let (root, db) = crate::tests::test_db("account-erase-files")?;
    let dir = root.join("accounts/acct");
    let main = dir.join("ramflux_local.sqlite");
    let (wal, shm) = (dir.join("ramflux_local.sqlite-wal"), dir.join("ramflux_local.sqlite-shm"));
    db.persist_actor_state("erase/kind", &serde_json::json!({"k": "v"}))?;
    let segment = db.segment_store()?;
    drop(segment);
    let segments = dir.join("ramflux_local.segments");
    std::fs::write(segments.join("seg-1"), b"segment-bytes")?;
    std::fs::create_dir_all(dir.join("objects"))?;
    std::fs::write(dir.join("objects/o-1"), b"object-bytes")?;
    std::fs::write(dir.join(".backup-generation"), b"hint")?;
    let (wal_copy, shm_copy) = (std::fs::read(&wal)?, std::fs::read(&shm)?);
    drop(db);
    std::fs::write(&wal, &wal_copy)?;
    std::fs::write(&shm, &shm_copy)?;
    let journal = dir.join("ramflux_local.sqlite-journal");
    std::fs::write(&journal, b"journal")?;
    for path in [&main, &wal, &shm, &journal] {
        assert!(
            std::fs::metadata(path)?.len() > 0,
            "{} must be nonempty before erase",
            path.display()
        );
    }
    assert!(segments.join("seg-1").exists() && dir.join("objects/o-1").exists());
    let lock = dir.join(".writer.lock");
    let inode = lock_inode(&lock)?;

    let index = AccountIndex::open(&root)?;
    index.erase_account_database("acct")?;
    for path in [
        &main,
        &wal,
        &shm,
        &journal,
        &segments,
        &dir.join("objects"),
        &dir.join(".backup-generation"),
    ] {
        assert!(!path.exists(), "{} must be erased", path.display());
    }
    assert_eq!(lock_inode(&lock)?, inode, "the writer lock inode is kept");
    assert_eq!(index.account("acct")?.account_state, "removed");
    // (c) idempotent.
    index.erase_account_database("acct")?;
    assert_eq!(lock_inode(&lock)?, inode);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn account_erase_refuses_symlinks_before_any_unlink() -> TestResult {
    let (root, db) = crate::tests::test_db("account-erase-symlink")?;
    drop(db);
    let dir = root.join("accounts/acct");
    let outside = root.join("outside");
    std::fs::create_dir_all(&outside)?;
    std::fs::write(outside.join("keep"), b"keep")?;
    std::fs::remove_dir_all(dir.join("objects"))?;
    std::os::unix::fs::symlink(&outside, dir.join("objects"))?;
    let main = dir.join("ramflux_local.sqlite");
    assert!(main.exists());
    let index = AccountIndex::open(&root)?;
    let result = index.erase_account_database("acct");
    assert!(
        matches!(result, Err(StorageError::Integrity("account erase symlink"))),
        "got {result:?}"
    );
    assert!(main.exists(), "nothing is unlinked before the symlink refusal");
    assert!(dir.join("objects").symlink_metadata()?.file_type().is_symlink());
    assert_eq!(std::fs::read(outside.join("keep"))?, b"keep");
    std::fs::remove_dir_all(root)?;
    Ok(())
}

fn plant(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, bytes)
}

#[test]
fn account_erase_generations_and_symlinks() -> TestResult {
    // (a) generation DB, sidecars and segments are removed; (b) an inner symlink is unlinked,
    // never followed.
    let (root, db) = crate::tests::test_db("account-erase-generations")?;
    drop(db);
    let dir = root.join("accounts/acct");
    let outside = root.join("outside");
    plant(&outside.join("file"), b"keep")?;
    for name in ["account.db", "account.db-wal", "account.db-shm", "account.segments/seg"] {
        plant(&dir.join("generation_1").join(name), b"gen")?;
    }
    plant(&dir.join("generation_2/x"), b"gen")?;
    std::os::unix::fs::symlink(outside.join("file"), dir.join("generation_2/link"))?;
    plant(&dir.join("generation_file"), b"stray")?;
    plant(&dir.join("generationless"), b"unrelated")?;
    AccountIndex::open(&root)?.erase_account_database("acct")?;
    for gone in ["generation_1", "generation_2", "generation_file", "ramflux_local.sqlite"] {
        assert!(dir.join(gone).symlink_metadata().is_err(), "{gone} must be erased");
    }
    assert_eq!(std::fs::read(outside.join("file"))?, b"keep");
    assert!(dir.join("generationless").exists(), "only the generation_ prefix is owned");
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn account_erase_generation_top_level_symlink_refused_before_any_unlink() -> TestResult {
    // (c)
    let (root, db) = crate::tests::test_db("account-erase-generation-link")?;
    drop(db);
    let dir = root.join("accounts/acct");
    let outside = root.join("outside_dir");
    plant(&outside.join("file"), b"keep")?;
    plant(&dir.join("generation_1/account.db"), b"gen")?;
    std::os::unix::fs::symlink(&outside, dir.join("generation_3"))?;
    let result = AccountIndex::open(&root)?.erase_account_database("acct");
    assert!(
        matches!(result, Err(StorageError::Integrity("account erase symlink"))),
        "got {result:?}"
    );
    for kept in ["ramflux_local.sqlite", "generation_1/account.db", "objects"] {
        assert!(dir.join(kept).exists(), "{kept} must survive the refusal");
    }
    assert!(dir.join("generation_3").symlink_metadata()?.file_type().is_symlink());
    assert_eq!(std::fs::read(outside.join("file"))?, b"keep");
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn account_erase_resumes_after_crash() -> TestResult {
    // (d) Crash after the tombstone only: open refuses and files are intact; erase completes.
    let (root, db) = crate::tests::test_db("account-erase-resume")?;
    drop(db);
    let dir = root.join("accounts/acct");
    plant(&dir.join("generation_1/account.db"), b"gen")?;
    plant(&dir.join("objects/o"), b"obj")?;
    let index = AccountIndex::open(&root)?;
    index.connection.execute(
        "UPDATE local_account SET account_state='removed', wrapped_key=NULL, wrapped_key_nonce=NULL
          WHERE local_account_id='acct'",
        [],
    )?;
    let main = dir.join("ramflux_local.sqlite");
    let before = std::fs::read(&main)?;
    expect_not_found(&open(&root).map(drop), "acct");
    assert_eq!(std::fs::read(&main)?, before);
    assert!(dir.join("generation_1/account.db").exists() && dir.join("objects/o").exists());
    // Mid-removal crash: some files already gone before the retry.
    std::fs::remove_file(&main)?;
    index.erase_account_database("acct")?;
    for gone in ["generation_1", "objects", "ramflux_local.sqlite"] {
        assert!(dir.join(gone).symlink_metadata().is_err(), "{gone} must be erased");
    }
    expect_not_found(&open(&root).map(drop), "acct");
    assert!(!main.exists(), "a removed account never reopens empty");
    std::fs::remove_dir_all(root)?;
    Ok(())
}
