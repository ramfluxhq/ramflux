// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Real encrypted clock commits, failed effects, reopen, read boundaries and both merge modes.
use super::*;
use crate::{AccountDbKey, AccountIndex, BackupDatabase};
type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn cr_reach_clock_survives_refused_effects_and_reopen() -> TestResult {
    let temp = tempfile::TempDir::new()?;
    let index = AccountIndex::open(temp.path())?;
    index.create_account("acct", &ramflux_protocol::encode_base64url([1; 32]))?;
    let key = AccountDbKey::generate()?;
    let db = AccountDb::open(&index, "acct", &key)?;
    assert_eq!(db.reach_fenced_now(100)?, 100, "first observation is committed independently");
    let now = db.reach_fenced_now(200)?;
    let refused: Result<(), StorageError> = db.write_transaction(|| {
        db.persist_actor_state("clock-test/effect", &now)?;
        Err(StorageError::Integrity("injected refused effect"))
    });
    assert!(refused.is_err(), "the effect callback must actually roll back");
    assert!(
        !db.actor_state_exists("clock-test/effect")?,
        "refusal must erase its tentative effect"
    );
    assert_eq!(db.reach_fenced_now(100)?, 200, "the separate observation survives effect rollback");
    let nested: Result<u64, StorageError> = db.write_transaction(|| db.reach_fenced_now(300));
    assert!(nested.is_err(), "an operation cannot observe a new clock inside its fallible writer");
    let reader = db.open_reader()?;
    assert!(reader.reach_fenced_now(300).is_err(), "read-only phases cannot pretend to commit UTC");
    drop(reader);
    drop(db);
    let db = AccountDb::open(&index, "acct", &key)?;
    assert_eq!(
        db.reach_fenced_now(1)?,
        200,
        "reopen cannot lower the independently committed floor"
    );
    let start =
        Instant::now().checked_sub(std::time::Duration::from_secs(4)).ok_or("test instant")?;
    *db.reach_clock.borrow_mut() = Some((start, 200));
    assert!(
        db.reach_fenced_now(1)? >= 204,
        "monotonic elapsed time advances a rolled-back wall clock"
    );
    assert!(
        db.reach_fenced_now(MAX + 1).is_err(),
        "unsafe UTC values must refuse instead of clamp"
    );
    Ok(())
}

#[test]
fn cr_reach_clock_full_and_native_merge_keep_the_largest_observation() -> TestResult {
    for native in [false, true] {
        merge_mode(native)?;
    }
    Ok(())
}
fn merge_mode(native: bool) -> TestResult {
    let temp = tempfile::TempDir::new()?;
    let local_index = AccountIndex::open(temp.path().join("local"))?;
    let source_index = AccountIndex::open(temp.path().join("source"))?;
    let root = ramflux_protocol::encode_base64url([2; 32]);
    local_index.create_account("acct", &root)?;
    source_index.create_account("acct", &root)?;
    let local = AccountDb::open(&local_index, "acct", &AccountDbKey::generate()?)?;
    let source = AccountDb::open(&source_index, "acct", &AccountDbKey::generate()?)?;
    local.reach_fenced_now(200)?;
    source.reach_fenced_now(100)?;
    let output_path = temp.path().join("output.db");
    let output = local.write_backup_snapshot(&output_path)?;
    let mut merged = BackupDatabase::open(&output_path, &output.key)?;
    for (index, observed, expected) in [(0, 100, 200), (1, 300, 300)] {
        source.reach_fenced_now(observed)?;
        let incoming_path = temp.path().join(format!("incoming-{index}.db"));
        let incoming = source.write_backup_snapshot(&incoming_path)?;
        if native {
            merged.merge_native_backup(&incoming_path, &incoming.key, || Ok(()))?;
        } else {
            merged.merge_backup(&incoming_path, &incoming.key, || Ok(()))?;
        }
        assert_eq!(
            read(&merged.db, false)?,
            Some(expected),
            "clock merge takes the maximum in either direction"
        );
    }
    source.persist_actor_state(KEY, &(MAX + 1))?;
    let bad_path = temp.path().join("bad.db");
    let bad = source.write_backup_snapshot(&bad_path)?;
    let refused = if native {
        merged.merge_native_backup(&bad_path, &bad.key, || Ok(()))
    } else {
        merged.merge_backup(&bad_path, &bad.key, || Ok(()))
    };
    assert!(refused.is_err(), "an unsafe imported floor must abort the encrypted generation");
    assert_eq!(
        read(&merged.db, false)?,
        Some(300),
        "failed import preserves the existing clock floor"
    );
    let malformed = BackupDatabase::open(&bad_path, &bad.key)?;
    malformed.db.execute_batch("DROP TABLE runtime_actor_state")?;
    drop(malformed);
    let refused = if native {
        merged.merge_native_backup(&bad_path, &bad.key, || Ok(()))
    } else {
        merged.merge_backup(&bad_path, &bad.key, || Ok(()))
    };
    assert!(refused.is_err(), "a missing current actor schema cannot select a compatibility path");
    assert_eq!(
        read(&merged.db, false)?,
        Some(300),
        "schema refusal must preserve the complete existing generation"
    );
    Ok(())
}
