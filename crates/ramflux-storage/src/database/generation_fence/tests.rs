// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use crate::{AccountDb, AccountDbKey, AccountIndex, StorageError};
use std::time::Duration;
type TestResult = Result<(), Box<dyn std::error::Error>>;
fn open(root: &std::path::Path) -> Result<AccountDb, StorageError> {
    let index = AccountIndex::open(root)?;
    if index.account("acct").is_err() {
        index.create_account("acct", "principal")?;
    }
    AccountDb::open(&index, "acct", &AccountDbKey::derive("acct", b"test-rebase-key"))
}
#[test]
fn pairing_full_fourth_fence_excludes_both_workers_without_blocking_owned_queries() -> TestResult {
    let root = tempfile::TempDir::new()?;
    let db = open(root.path())?;
    let other = open(root.path())?;
    let first = db.connection.clone();
    let second = other.connection.clone();
    db.with_full_transfer_install_fence(|| -> Result<(), StorageError> {
        for connection in [first, second] {
            let refused = std::thread::spawn(move || {
                connection.query_row("SELECT 1", [], |row| row.get::<_, u64>(0))
            })
            .join()
            .map_err(|_| std::io::Error::other("test: peer worker panicked"))?;
            assert!(
                refused
                    .is_err_and(|error| error.sqlite_error_code()
                        == Some(rusqlite::ErrorCode::DatabaseBusy)),
                "test: ordinary queued worker crossed the final rebase fence"
            );
        }
        db.persist_actor_state("test/fenced-local", &1_u64)?;
        let (cut, observation) = db.pin_full_transfer_target()?;
        observation.require_current(&db)?;
        drop(cut);
        Ok(())
    })?;
    other.persist_actor_state("test/after-release", &2_u64)?;
    assert_eq!(
        db.load_actor_state::<u64>("test/after-release")?,
        Some(2),
        "test: successful local rebase did not release ordinary writers"
    );
    Ok(())
}
#[test]
fn pairing_full_fourth_fence_deadline_and_error_release_without_reviving_retired_workers()
-> TestResult {
    let root = tempfile::TempDir::new()?;
    let db = open(root.path())?;
    let guard = db.full_local_unlock_guard()?;
    let result = db.connection.with_generation_rebase(Duration::ZERO, || guard.require_unlocked());
    assert!(
        matches!(result, Err(StorageError::PairingField("Busy"))),
        "test: expired final-rebase scope still allowed local key work"
    );
    guard.require_unlocked()?;
    db.persist_actor_state("test/after-timeout", &1_u64)?;
    let failed = db.with_full_transfer_install_fence(|| -> Result<(), StorageError> {
        Err(StorageError::PairingField("ManifestMismatch"))
    });
    assert!(
        matches!(failed, Err(StorageError::PairingField("ManifestMismatch"))),
        "test: local rebase refusal was hidden"
    );
    db.persist_actor_state("test/after-refusal", &2_u64)?;
    db.with_full_transfer_install_fence(|| -> Result<(), StorageError> {
        db.connection.call_generation(|_| (Ok(()), true))?;
        Ok(())
    })?;
    assert!(
        guard.require_unlocked().is_err(),
        "test: nested G2 did not retire the original weak owner"
    );
    assert!(
        db.persist_actor_state("test/stale", &3_u64).is_err(),
        "test: old worker wrote after fenced generation retirement"
    );
    let selected = open(root.path())?;
    selected.persist_actor_state("test/new-worker", &4_u64)?;
    Ok(())
}
