// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Insert-only birth arbitration and conditional reservation release.
use super::*;
fn snapshot(index: &AccountIndex, id: &str) -> Result<Vec<rusqlite::types::Value>, StorageError> {
    let columns: usize = index.connection.query_row(
        "SELECT COUNT(*) FROM pragma_table_info('local_account')",
        [],
        |row| row.get(0),
    )?;
    Ok(index.connection.query_row(
        "SELECT * FROM local_account WHERE local_account_id=?1",
        rusqlite::params![id],
        |row| (0..columns).map(|i| row.get(i)).collect(),
    )?)
}
fn wrapped() -> WrappedAccountDbKey {
    WrappedAccountDbKey {
        key_wrapping_provider: "test".into(),
        key_wrapping_ref: "legacy-key".into(),
        nonce: [4; 12],
        wrapped_key: vec![5; 48],
    }
}
#[test]
fn account_index_reservation_preserves_every_legacy_row_and_wrapped_key_byte()
-> Result<(), StorageError> {
    let root = std::env::temp_dir().join(format!(
        "rf-reservation-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos())
    ));
    let index = AccountIndex::open(&root)?;
    index.create_account("existing", "legacy-root")?;
    index.store_wrapped_db_key("existing", &wrapped())?;
    let before = snapshot(&index, "existing")?;
    let result = index.reserve_account("existing", "custody-anchor");
    assert_eq!(snapshot(&index, "existing")?, before);
    assert!(matches!(result, Err(StorageError::AccountAlreadyExists(_))));
    drop(index);
    fs::remove_dir_all(root)?;
    Ok(())
}
#[test]
fn account_index_release_never_deletes_a_different_owner_or_a_wrapped_key()
-> Result<(), StorageError> {
    let root = std::env::temp_dir().join(format!(
        "rf-release-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos())
    ));
    let index = AccountIndex::open(&root)?;
    index.reserve_account("birth", "anchor")?;
    let before = snapshot(&index, "birth")?;
    assert!(!index.release_unwrapped_reservation("birth", "different")?);
    assert_eq!(snapshot(&index, "birth")?, before);
    index.store_wrapped_db_key("birth", &wrapped())?;
    let before = snapshot(&index, "birth")?;
    assert!(!index.release_unwrapped_reservation("birth", "anchor")?);
    assert_eq!(snapshot(&index, "birth")?, before);
    index.reserve_account("unwrapped", "another-anchor")?;
    assert!(index.release_unwrapped_reservation("unwrapped", "another-anchor")?);
    assert!(matches!(index.account("unwrapped"), Err(StorageError::AccountNotFound(_))));
    drop(index);
    fs::remove_dir_all(root)?;
    Ok(())
}
