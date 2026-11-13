// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Reopened redb counters remain charged until their exact fixed-window expiry.
use super::*;
use crate::RouterRedbStore;
type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;
#[test]
fn cr_rate_counter_survives_reopen_for_two_windows_then_releases() -> TestResult {
    let dir = tempfile::TempDir::new()?;
    let path = dir.path().join("quota.redb");
    let store = RouterRedbStore::open_without_wal(&path)?;
    let tx = store.begin_write()?;
    super::super::charge(&tx, "rate-test", (4, 0), (4, 0), 7200)?;
    tx.commit()?;
    drop(store);
    let store = RouterRedbStore::open_without_wal(&path)?;
    let tx = store.begin_write()?;
    clean(&tx, 7199)?;
    assert!(
        super::super::charge(&tx, "rate-test", (1, 0), (4, 0), 7200).is_err(),
        "reopen and the next window cannot reset an unexpired charge"
    );
    drop(tx);
    let tx = store.begin_write()?;
    clean(&tx, 7200)?;
    super::super::charge(&tx, "rate-test", (1, 0), (4, 0), 14400)?;
    let table = tx.open_table(COUNTERS)?;
    let value = table.get("rate-test")?.ok_or("counter")?;
    let count: Counter = row(value.value())?;
    assert_eq!(count.entries, 1, "expired rate state must release before the next admission");
    drop(value);
    drop(table);
    tx.commit()?;
    Ok(())
}
#[test]
fn cr_unsolicited_metadata_cannot_consume_accepted_metadata_reserve() -> TestResult {
    let dir = tempfile::TempDir::new()?;
    let store = RouterRedbStore::open_without_wal(dir.path().join("quota.redb"))?;
    let tx = store.begin_write()?;
    for (key, capacity) in metadata(ReachClass::Unsolicited) {
        super::super::charge(&tx, key, capacity, capacity, 0)?;
        assert!(
            super::super::charge(&tx, key, (1, 1), capacity, 0).is_err(),
            "full unsolicited metadata must refuse additional strangers"
        );
    }
    for (key, capacity) in metadata(ReachClass::Accepted) {
        super::super::charge(&tx, key, (1, 100), capacity, 0)?;
    }
    tx.commit()?;
    Ok(())
}

#[test]
fn cr_replied_metadata_keeps_half_for_accepted_after_reopen() -> TestResult {
    let dir = tempfile::TempDir::new()?;
    let path = dir.path().join("metadata.redb");
    {
        let store = RouterRedbStore::open_without_wal(&path)?;
        let tx = store.begin_write()?;
        // Aggregate counter charges exercise the durable quota component without allocating
        // tens of thousands of payloads. Full receiving-path acceptance is a separate gate.
        for (key, capacity) in metadata(ReachClass::Replied) {
            super::super::charge(&tx, key, (32_768, 16 * 1024 * 1024), capacity, 0)?;
        }
        tx.commit()?;
    }
    let store = RouterRedbStore::open_without_wal(&path)?;
    let tx = store.begin_write()?;
    let (key, capacity) = metadata(ReachClass::Replied)
        .into_iter()
        .find(|(key, _)| *key == "metadata-replied")
        .ok_or("replied compartment")?;
    assert!(
        super::super::charge(&tx, key, (1, 1), capacity, 0).is_err(),
        "replied metadata saturation must survive reopen and stop at its own half"
    );
    for (key, capacity) in metadata(ReachClass::Accepted) {
        super::super::charge(&tx, key, (32_768, 16 * 1024 * 1024), capacity, 0)?;
    }
    tx.commit()?;
    Ok(())
}
#[test]
fn cr_accepted_metadata_can_borrow_unused_replied_half() -> TestResult {
    let dir = tempfile::TempDir::new()?;
    let store = RouterRedbStore::open_without_wal(dir.path().join("metadata.redb"))?;
    let tx = store.begin_write()?;
    for (key, capacity) in metadata(ReachClass::Accepted) {
        super::super::charge(&tx, key, capacity, capacity, 0)?;
        assert!(
            super::super::charge(&tx, key, (1, 1), capacity, 0).is_err(),
            "accepted borrowing remains bounded by the whole shared pool"
        );
    }
    tx.commit()?;
    Ok(())
}
