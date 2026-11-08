// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! First-leg `activation_revert_preserves_ledger`: discriminator, guards, crash cuts.
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use super::activation::{FIRST_ACTIVATION_DEFAULT, LEGACY_RECEIVE_ACTIVATED, ReceiveActivation};
use super::migrate::{ReceiveMigrate, ReceiveMigrateResult};
use super::stage::{ReceiveStage, ReceiveStageResult};
use super::{ReceiveExpectation, ReceiveTransaction};
use crate::{AccountDb, AccountDbKey, AccountIndex, StorageError, durability_test_hooks};
use rusqlite::params;
use std::{
    path::Path,
    process::{Child, Command},
    sync::Arc,
    time::{Duration, Instant},
};

const TARGET: &str = "t";
const INCARNATION: &str = "e";

fn reopen(root: &Path) -> Result<AccountDb, StorageError> {
    AccountDb::open(
        &AccountIndex::open(root)?,
        "acct",
        &AccountDbKey::derive("acct", b"storage-test-secret"),
    )
}

fn migrate() -> ReceiveMigrate<'static> {
    ReceiveMigrate { target: TARGET, incarnation: INCARNATION }
}

fn wait(mut child: Child) -> std::process::ExitStatus {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(status) = child.try_wait().expect("poll child") {
            return status;
        }
        if Instant::now() >= deadline {
            child.kill().expect("kill hung child");
            child.wait().expect("reap hung child");
            panic!("activation child exceeded 30-second hang guard");
        }
        std::thread::yield_now();
    }
}

fn child(root: &Path, mode: &str) -> std::process::ExitStatus {
    wait(
        Command::new(std::env::current_exe().expect("test executable"))
            .args([
                "--exact",
                "account_db::receive::activation_tests::activation_child",
                "--nocapture",
            ])
            .env("RAMFLUX_ACTIVATION_CHILD_ROOT", root)
            .env("RAMFLUX_ACTIVATION_CHILD_MODE", mode)
            .spawn()
            .expect("spawn child"),
    )
}

fn old_writer_child(root: &Path) -> std::process::ExitStatus {
    wait(
        Command::new(std::env::current_exe().expect("test executable"))
            .args(["--exact", "account_db::receive::tests::ledger_child", "--nocapture"])
            .env("RAMFLUX_RECEIVE_CHILD_ROOT", root)
            .env("RAMFLUX_RECEIVE_CHILD_MODE", "old-writer")
            .spawn()
            .expect("spawn old-writer child"),
    )
}

fn persist_work(db: &AccountDb) -> Result<(), StorageError> {
    let bytes = super::stage_tests::bytes(1);
    let input = ReceiveStage {
        target: TARGET,
        incarnation: INCARNATION,
        sequence: 1,
        entry_json: &bytes,
        admission_key: "authenticated-key",
        retain_until: 100,
        first_seen: 1,
    };
    db.receive_transaction(
        ReceiveExpectation {
            target: TARGET,
            incarnation: INCARNATION,
            cursor: 0,
            generation: 1,
            erasure_generation: db.privacy_erasure_generation()?,
        },
        1,
        |tx: &ReceiveTransaction<'_>| {
            assert_eq!(tx.stage(input)?, ReceiveStageResult::Staged);
            tx.hold_receipt(1)?;
            Ok(())
        },
    )?;
    db.connection.execute(
        "INSERT INTO gateway_ack_intent VALUES(?1,?2,?3,1,0,1,100)",
        params![TARGET, INCARNATION, 2u64.to_be_bytes().as_slice()],
    )?;
    Ok(())
}

fn assert_work(db: &AccountDb) -> Result<(), StorageError> {
    let held: i64 = db.connection.query_row(
        "SELECT count(*) FROM gateway_receive_receipt WHERE disposition='held'",
        [],
        |row| row.get(0),
    )?;
    let work: i64 =
        db.connection
            .query_row("SELECT count(*) FROM gateway_receive_work", [], |row| row.get(0))?;
    let acks: i64 =
        db.connection.query_row("SELECT count(*) FROM gateway_ack_intent", [], |row| row.get(0))?;
    assert_eq!((held, work, acks), (1, 1, 1));
    Ok(())
}

#[test]
fn activation_child() -> Result<(), StorageError> {
    let Some(root) = std::env::var_os("RAMFLUX_ACTIVATION_CHILD_ROOT") else {
        return Ok(());
    };
    let mode = std::env::var("RAMFLUX_ACTIVATION_CHILD_MODE").expect("child mode");
    let db = reopen(Path::new(&root))?;
    let after = mode == "after";
    let _observer = durability_test_hooks::observe(
        db.path.clone(),
        Arc::new(move |sql, completed, autocommit| {
            if sql == "COMMIT" && completed == after {
                assert_eq!(autocommit, after);
                std::process::abort();
            }
            Ok(())
        }),
    )?;
    let _ = db.activate_receive_ledger(migrate())?;
    panic!("real COMMIT cut did not fire");
}

/// Activate, persist staged/held work and an uncertain ACK, reopen default-off: Activated, guards
/// refuse legacy writes, old writers still refuse. Negative: legacy receive must not succeed.
#[test]
fn activation_revert_preserves_ledger() -> Result<(), StorageError> {
    let (root, db) = crate::tests::test_db("receive-activation-revert")?;
    const { assert!(!FIRST_ACTIVATION_DEFAULT) };
    assert_eq!(db.receive_activation()?, ReceiveActivation::Inactive);
    assert_eq!(db.first_activate_if_default(migrate())?, None);
    assert_eq!(db.receive_activation()?, ReceiveActivation::Inactive);
    assert_eq!(db.activate_receive_ledger(migrate())?, ReceiveMigrateResult::Migrated);
    persist_work(&db)?;
    db.checkpoint_retired_secrets()?;
    let path = db.path.clone();
    drop(db);
    let db = reopen(&root)?;
    assert_eq!(db.receive_activation()?, ReceiveActivation::Activated);
    assert!(
        matches!(
            db.refuse_legacy_receive(),
            Err(StorageError::Integrity(LEGACY_RECEIVE_ACTIVATED))
        ),
        "legacy writers must refuse an activated DB"
    );
    assert_work(&db)?;
    db.checkpoint_retired_secrets()?;
    drop(db);
    let before = std::fs::read(&path)?;
    assert!(old_writer_child(&root).success(), "previous writer refusal child failed");
    assert_eq!(std::fs::read(&path)?, before, "old writer changed encrypted DB");
    let db = reopen(&root)?;
    assert_eq!(db.receive_activation()?, ReceiveActivation::Activated);
    assert_work(&db)?;
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn activation_commit_is_atomic() -> Result<(), StorageError> {
    for mode in ["before", "after"] {
        let (root, db) = crate::tests::test_db(&format!("receive-activation-cut-{mode}"))?;
        drop(db);
        let status = child(&root, mode);
        #[cfg(unix)]
        {
            use std::os::unix::process::ExitStatusExt;
            assert_eq!(status.signal(), Some(6), "must hit the abort hook");
        }
        assert!(!status.success(), "child must abort at the real COMMIT");
        let db = reopen(&root)?;
        let activated = db.receive_activation()? == ReceiveActivation::Activated;
        let epoch: i64 = db.connection.query_row(
            "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='gateway_receive_epoch'",
            [],
            |row| row.get(0),
        )?;
        let rows: i64 = if epoch == 0 {
            0
        } else {
            db.connection
                .query_row("SELECT count(*) FROM gateway_receive_epoch", [], |row| row.get(0))?
        };
        if mode == "after" {
            assert!(activated && rows == 1, "after COMMIT is the complete activated state");
        } else {
            assert!(!activated && rows == 0, "before COMMIT is the inactive pre-activation state");
        }
        drop(db);
        std::fs::remove_dir_all(root)?;
    }
    Ok(())
}

#[test]
fn activation_before_commit_fault_rolls_back() -> Result<(), StorageError> {
    let (root, db) = crate::tests::test_db("receive-activation-fault")?;
    let error = super::activation::run(super::activation::FaultKind::BeforeCommit, || {
        db.activate_receive_ledger(migrate())
    });
    assert!(
        matches!(error, Err(StorageError::Integrity("receive activation before-commit"))),
        "{error:?}"
    );
    assert_eq!(db.receive_activation()?, ReceiveActivation::Inactive);
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}
