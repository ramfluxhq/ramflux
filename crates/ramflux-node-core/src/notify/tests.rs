// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::{NOTIFY_WAKE_DUE, NOTIFY_WAKE_FORMAT, NOTIFY_WAKE_LEDGER, NotifyRedbStore};
use crate::{NodeCoreError, NotifyWalStore};
use redb::{ReadableDatabase, ReadableTable, ReadableTableMetadata};

type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

#[test]
fn n1_persisted_predecessor_and_zero_retention_require_reset() -> TestResult {
    let temp = tempfile::TempDir::new()?;
    let predecessor = temp.path().join("predecessor.redb");
    {
        let db = redb::Database::create(&predecessor)?;
        let tx = db.begin_write()?;
        tx.open_table(NOTIFY_WAKE_LEDGER)?;
        tx.commit()?;
    }
    assert!(
        matches!(
            NotifyRedbStore::open_without_wal(&predecessor),
            Err(NodeCoreError::NotifyWakeStateResetRequired)
        ),
        "an unversioned predecessor ledger was silently accepted"
    );
    let zero = temp.path().join("zero.redb");
    {
        let store = NotifyRedbStore::open_without_wal(&zero)?;
        store.tombstone_wake_id("zero", None)?;
        let mut row = store.load_wake_ledger_row("zero")?.ok_or("test: tombstone missing")?;
        row.retain_until = 0;
        let bytes = serde_json::to_vec(&row)?;
        let tx = store.db.begin_write()?;
        tx.open_table(NOTIFY_WAKE_LEDGER)?.insert("zero", bytes.as_slice())?;
        tx.commit()?;
    }
    assert!(
        matches!(
            NotifyRedbStore::open_without_wal(&zero),
            Err(NodeCoreError::NotifyWakeStateResetRequired)
        ),
        "a persisted zero horizon was silently made immortal"
    );
    Ok(())
}

#[test]
fn n1_cancel_horizon_survives_restart_and_bounded_cleanup() -> TestResult {
    let temp = tempfile::TempDir::new()?;
    let path = temp.path().join("notify.redb");
    let until = {
        let store = NotifyRedbStore::open_without_wal(&path)?;
        for id in 0..129 {
            store.tombstone_wake_id(&format!("cancel-{id}"), None)?;
        }
        store.load_wake_ledger_row("cancel-0")?.ok_or("test: first cancel missing")?.retain_until
    };
    let store = NotifyRedbStore::open_without_wal(&path)?;
    store.tombstone_wake_id("cancel-0", None)?;
    assert_eq!(
        store.load_wake_ledger_row("cancel-0")?.ok_or("test: replay missing")?.retain_until,
        until,
        "repeated cancellation refreshed the fixed original horizon"
    );
    assert_eq!(store.prune_wake_ledger(until - 1)?, 0, "denial retired before its horizon");
    assert_eq!(store.prune_wake_ledger(until)?, 128, "cleanup exceeded its indexed batch limit");
    assert_eq!(store.prune_wake_ledger(until + 1)?, 1, "remaining denial never retired");
    let tx = store.db.begin_read()?;
    assert_eq!(tx.open_table(NOTIFY_WAKE_DUE)?.len()?, 0, "cleanup left an uncharged due index");
    assert_eq!(
        tx.open_table(NOTIFY_WAKE_FORMAT)?.get("notify_wake_state_format")?.map(|v| v.value()),
        Some(1),
        "fresh ledger lost its N1 marker"
    );
    Ok(())
}

#[test]
fn n1_wal_marker_and_cancel_denial_survive_real_reopen() -> TestResult {
    let temp = tempfile::TempDir::new()?;
    let root = temp.path().join("wal");
    {
        let wal = NotifyWalStore::open(&root)?;
        wal.tombstone_wake("cancel-before-enqueue")?;
    }
    {
        let wal = NotifyWalStore::open(&root)?;
        assert!(wal.wake_is_closed("cancel-before-enqueue"), "WAL restart forgot cancellation");
        wal.tombstone_wake("cancel-before-enqueue")?;
    }
    std::fs::write(root.join("notify_wake_state_format"), b"0\n")?;
    assert!(
        matches!(NotifyWalStore::open(&root), Err(NodeCoreError::NotifyWakeStateResetRequired)),
        "unsupported WAL format was accepted"
    );
    std::fs::remove_file(root.join("notify_wake_state_format"))?;
    assert!(
        matches!(NotifyWalStore::open(&root), Err(NodeCoreError::NotifyWakeStateResetRequired)),
        "unversioned predecessor WAL segments were accepted"
    );
    Ok(())
}
