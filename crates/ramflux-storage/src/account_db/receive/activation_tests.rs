// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! First-leg `activation_revert_preserves_ledger`: discriminator, guards, crash cuts.
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use super::activation::{
    ACTIVATION_KEY, FIRST_ACTIVATION_DEFAULT, LEGACY_RECEIVE_ACTIVATED, MISSING_EPOCH,
    ReceiveActivation, UNKNOWN_ACTIVATION,
};
use super::cover::{ReceiveCover, ReceiveCoverKind, ReceiveCoverResult};
use super::migrate::{ReceiveMigrate, ReceiveMigrateResult};
use super::stage::{ReceiveStage, ReceiveStageResult};
use super::{ReceiveExpectation, ReceiveTransaction};
use crate::{
    AccountDb, AccountDbKey, AccountIndex, ProjectionStore, StorageError, durability_test_hooks,
};
use rusqlite::{OptionalExtension, params};
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

fn expect<'a>(db: &AccountDb, cursor: u64) -> Result<ReceiveExpectation<'a>, StorageError> {
    Ok(ReceiveExpectation {
        target: TARGET,
        incarnation: INCARNATION,
        cursor,
        generation: 1,
        erasure_generation: db.privacy_erasure_generation()?,
    })
}

fn persist_work(db: &AccountDb) -> Result<(), StorageError> {
    let first = super::stage_tests::bytes(1);
    db.receive_transaction(expect(db, 0)?, 1, |tx: &ReceiveTransaction<'_>| {
        assert_eq!(
            tx.stage(ReceiveStage {
                target: TARGET,
                incarnation: INCARNATION,
                sequence: 1,
                entry_json: &first,
                admission_key: "authenticated-key",
                retain_until: 100,
                first_seen: 1,
            })?,
            ReceiveStageResult::Staged
        );
        assert_eq!(
            tx.cover(ReceiveCover {
                sequence: 1,
                kind: ReceiveCoverKind::Terminal,
                gaps: &[],
                retain_until: 0,
            })?,
            ReceiveCoverResult::Covered
        );
        Ok(())
    })?;
    let second = super::stage_tests::bytes(2);
    db.receive_transaction(expect(db, 1)?, 1, |tx: &ReceiveTransaction<'_>| {
        assert_eq!(
            tx.stage(ReceiveStage {
                target: TARGET,
                incarnation: INCARNATION,
                sequence: 2,
                entry_json: &second,
                admission_key: "authenticated-key",
                retain_until: 100,
                first_seen: 1,
            })?,
            ReceiveStageResult::Staged
        );
        tx.hold_receipt(2)?;
        Ok(())
    })?;
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

fn table_count(db: &AccountDb, table: &str) -> Result<i64, StorageError> {
    let exists: i64 = db.connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1)",
        params![table],
        |row| row.get(0),
    )?;
    if exists == 0 {
        return Ok(0);
    }
    Ok(db.connection.query_row(&format!("SELECT count(*) FROM {table}"), [], |row| row.get(0))?)
}

fn held_work(db: &AccountDb) -> Result<(i64, i64), StorageError> {
    if table_count(db, "gateway_receive_receipt")? == 0 {
        return Ok((0, 0));
    }
    let held: i64 = db.connection.query_row(
        "SELECT count(*) FROM gateway_receive_receipt WHERE disposition='held'",
        [],
        |row| row.get(0),
    )?;
    let work: i64 =
        db.connection
            .query_row("SELECT count(*) FROM gateway_receive_work", [], |row| row.get(0))?;
    Ok((held, work))
}

fn activated_cursor(db: &AccountDb) -> Result<Option<u64>, StorageError> {
    if table_count(db, "gateway_receive_epoch")? == 0 {
        return Ok(None);
    }
    let blob: Option<Vec<u8>> = db
        .connection
        .query_row(
            "SELECT activated_cursor FROM gateway_receive_epoch WHERE target_delivery_id=?1",
            params![TARGET],
            |row| row.get(0),
        )
        .optional()?;
    Ok(blob.map(|bytes| u64::from_be_bytes(bytes.try_into().expect("activated cursor"))))
}

#[test]
fn activation_commit_is_atomic() -> Result<(), StorageError> {
    for mode in ["before", "after"] {
        let (root, db) = crate::tests::test_db(&format!("receive-activation-cut-{mode}"))?;
        db.set_projection_checkpoint("gateway_receive_cursor:t", "7")?;
        db.hold_unrouted("env-1", 5, &super::stage_tests::bytes(5), 1)?;
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
        let rows = table_count(&db, "gateway_receive_epoch")?;
        let cursor = db.receive_cursor(TARGET)?;
        let unrouted = table_count(&db, "runtime_unrouted")?;
        let (held, work) = held_work(&db)?;
        if mode == "after" {
            assert!(
                activated
                    && rows == 1
                    && cursor == 7
                    && activated_cursor(&db)? == Some(7)
                    && held == 1
                    && work == 1
                    && unrouted == 1,
                "after COMMIT is the complete activated state"
            );
        } else {
            assert!(
                !activated && rows == 0 && cursor == 7 && held == 0 && work == 0 && unrouted == 1,
                "before COMMIT is the inactive pre-activation state"
            );
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

#[test]
fn unknown_discriminator_fails_closed() -> Result<(), StorageError> {
    let (root, db) = crate::tests::test_db("receive-activation-unknown")?;
    db.set_projection_checkpoint(ACTIVATION_KEY, "garbage")?;
    assert!(
        matches!(db.receive_activation(), Err(StorageError::Integrity(UNKNOWN_ACTIVATION))),
        "unknown discriminator must not read Inactive"
    );
    assert!(
        matches!(db.refuse_legacy_receive(), Err(StorageError::Integrity(UNKNOWN_ACTIVATION))),
        "legacy writers must fail closed on an unknown discriminator"
    );
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn activated_without_epoch_refuses_second_activation() -> Result<(), StorageError> {
    let (root, db) = crate::tests::test_db("receive-activation-missing-epoch")?;
    assert_eq!(db.activate_receive_ledger(migrate())?, ReceiveMigrateResult::Migrated);
    db.write_transaction(|| {
        db.connection.execute("DELETE FROM gateway_receive_epoch", [])?;
        assert!(
            matches!(
                db.activate_receive_ledger_in(migrate()),
                Err(StorageError::Integrity(MISSING_EPOCH))
            ),
            "Activated with no epoch must fail closed"
        );
        assert!(
            matches!(
                db.activate_receive_ledger_in(ReceiveMigrate {
                    target: "other",
                    incarnation: INCARNATION,
                }),
                Err(StorageError::Integrity(MISSING_EPOCH))
            ),
            "second target on an Activated account must fail closed"
        );
        Ok::<(), StorageError>(())
    })?;
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}
