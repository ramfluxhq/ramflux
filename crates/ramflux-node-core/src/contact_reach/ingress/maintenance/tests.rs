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
    let store = RouterRedbStore::open_without_wal(&dir.path().join("quota.redb"))?;
    let tx = store.begin_write()?;
    let (key, cap) = metadata(ReachClass::Unsolicited);
    super::super::charge(&tx, key, (cap, 32 * 1024 * 1024), (cap, 32 * 1024 * 1024), 0)?;
    assert!(
        super::super::charge(&tx, key, (1, 1), (cap, 32 * 1024 * 1024), 0).is_err(),
        "full unsolicited metadata must refuse additional strangers"
    );
    let (accepted, cap) = metadata(ReachClass::Accepted);
    super::super::charge(&tx, accepted, (1, 100), (cap, 32 * 1024 * 1024), 0)?;
    tx.commit()?;
    Ok(())
}
