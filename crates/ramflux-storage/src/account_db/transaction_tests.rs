// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Account write-entry regression tests for SQLite writer-lock acquisition.

use super::AccountDb;
use crate::{AccountDbKey, AccountIndex, StorageError};
use std::path::Path;
use std::sync::mpsc::SyncSender;

fn second_writer(root: &Path) -> Result<AccountDb, StorageError> {
    let index = AccountIndex::open(root)?;
    AccountDb::open(&index, "acct", &AccountDbKey::derive("acct", b"storage-test-secret"))
}

fn hold_writer(
    db: AccountDb,
    ready: SyncSender<()>,
) -> std::thread::JoinHandle<Result<(), StorageError>> {
    std::thread::spawn(move || {
        let transaction = db.connection.immediate_transaction()?;
        ready.send(()).map_err(|_| StorageError::AuthorizationRejected)?;
        std::thread::sleep(std::time::Duration::from_millis(250));
        transaction.commit()?;
        Ok(())
    })
}

#[test]
fn surface_transaction_waits_for_a_competing_writer_before_reading() -> Result<(), StorageError> {
    let (root, contender) = crate::tests::test_db("surface-immediate-writer")?;
    let holder = second_writer(&root)?;
    let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(1);
    let worker = hold_writer(holder, ready_tx);
    ready_rx.recv().map_err(|_| StorageError::AuthorizationRejected)?;

    contender.surface_transaction(|| {
        let _: i64 = contender.connection.query_row(
            "SELECT count(*) FROM runtime_actor_state",
            [],
            |row| row.get(0),
        )?;
        contender.connection.execute(
            "INSERT INTO runtime_actor_state(state_kind,state_json) VALUES('surface/test','{}')",
            [],
        )?;
        Ok::<(), StorageError>(())
    })?;

    worker.join().map_err(|_| StorageError::AuthorizationRejected)??;
    drop(contender);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn contact_consent_waits_for_a_competing_writer_before_reading() -> Result<(), StorageError> {
    let (root, contender) = crate::tests::test_db("contact-consent-immediate-writer")?;
    contender.fence_contact_request("contact-root", "declined", 100)?;
    let holder = second_writer(&root)?;
    let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(1);
    let worker = hold_writer(holder, ready_tx);
    ready_rx.recv().map_err(|_| StorageError::AuthorizationRejected)?;

    contender.clear_contact_request_fence("contact-root", Some("declined"))?;
    assert_eq!(contender.retained_contact_request_fence("contact-root")?, None);

    worker.join().map_err(|_| StorageError::AuthorizationRejected)??;
    drop(contender);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn backup_reader_nested_snapshot_keeps_outer_snapshot_pinned() -> Result<(), StorageError> {
    let (root, writer) = crate::tests::test_db("backup-reader-nesting")?;
    let reader = writer.open_backup_reader()?;
    assert!(reader.is_query_only()?);
    assert!(!reader.connection.is_autocommit()?);
    reader.read_snapshot(|| {
        let _: i64 =
            reader
                .connection
                .query_row("SELECT count(*) FROM runtime_actor_state", [], |row| row.get(0))?;
        Ok::<(), StorageError>(())
    })?;
    assert!(!reader.connection.is_autocommit()?);
    assert!(reader.write_transaction(|| Ok::<(), StorageError>(())).is_err());
    drop(reader);
    drop(writer);
    std::fs::remove_dir_all(root)?;
    Ok(())
}
