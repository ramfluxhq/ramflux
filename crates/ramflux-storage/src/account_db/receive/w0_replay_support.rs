// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Test support: a restored database must erase a fresh-sequence replay of a tombstoned tuple
//! at W0, immediately and after reopen.
#![allow(clippy::expect_used, clippy::panic)]
use super::privacy_tests::fresh_entry;
use super::stage::ReceiveStageResult;
use super::stage_tests::{input, receipt_state, run, work_for};
use crate::{AccountDb, AccountDbKey, AccountIndex, BackupDatabase, StorageError};
use rusqlite::params;

/// (principal, device, payload hash): the fields a replay repeats; the signing key is fixed.
pub(super) type Tuple = (String, String, String);

fn prepare(db: &AccountDb) -> Result<(), StorageError> {
    let present: bool = db.connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name='gateway_receive_receipt')",
        [],
        |r| r.get(0),
    )?;
    if !present {
        db.install_receive_ledger_schema()?;
    }
    db.connection.execute(
        "INSERT OR IGNORE INTO gateway_receive_epoch VALUES('t','e',1,x'',?1,?1)",
        params![0u64.to_be_bytes().as_slice()],
    )?;
    Ok(())
}

/// Installs a merged backup as an account database under `root/name` and returns its index.
pub(super) fn install(
    root: &std::path::Path,
    name: &str,
    path: &std::path::Path,
    key: &AccountDbKey,
) -> Result<AccountIndex, StorageError> {
    let dir = root.join(name);
    let index = AccountIndex::open(&dir)?;
    let account = index.create_account("account", "root")?;
    let target = dir.join(account.db_relative_path);
    std::fs::create_dir_all(target.parent().ok_or(StorageError::AuthorizationRejected)?)?;
    BackupDatabase::open(path, key)?.copy_to(&target, key)?;
    Ok(index)
}

/// Replays every tuple on an already open database at coordinates starting at `base`.
pub(super) fn assert_erased(
    db: &AccountDb,
    tuples: &[Tuple],
    base: u64,
) -> Result<(), StorageError> {
    prepare(db)?;
    for (n, (principal, device, payload)) in (base..).zip(tuples) {
        let wire = fresh_entry(n, payload, principal, device);
        assert_eq!(
            run(db, input(&wire, n))?,
            ReceiveStageResult::Erased,
            "W0 must erase the replay of {payload}"
        );
        assert_eq!(receipt_state(db, n)?.as_deref(), Some("erased"));
        assert_eq!(work_for(db, n)?, 0);
    }
    Ok(())
}

/// Opens the installed copy twice (so the second pass is after reopen) and replays every tuple.
pub(super) fn assert_erased_after_reopen(
    index: &AccountIndex,
    key: &AccountDbKey,
    tuples: &[Tuple],
) -> Result<(), StorageError> {
    let first = AccountDb::open(index, "account", key)?;
    assert_erased(&first, tuples, 1_000)?;
    drop(first);
    let second = AccountDb::open(index, "account", key)?;
    assert_erased(&second, tuples, 2_000)?;
    Ok(())
}
