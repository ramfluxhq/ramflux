// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Restore and merge union of erased-input tombstones, with the generic merge skipping the table.
#![allow(clippy::expect_used, clippy::panic)]
use crate::{AccountDb, AccountDbKey, AccountIndex, BackupDatabase, StorageError};
use rusqlite::params;

struct Pair {
    root: std::path::PathBuf,
    source: AccountDb,
    local: AccountDb,
    bundle: String,
}

fn pair(name: &str) -> Result<Pair, StorageError> {
    let root = crate::tests::temp_root(name);
    let source_index = AccountIndex::open(root.join("source"))?;
    let local_index = AccountIndex::open(root.join("local"))?;
    source_index.create_account("account", "root")?;
    local_index.create_account("account", "root")?;
    let source = AccountDb::open(&source_index, "account", &AccountDbKey::generate()?)?;
    let local = AccountDb::open(&local_index, "account", &AccountDbKey::generate()?)?;
    let bundle =
        local.connection.query_row("SELECT bundle_id FROM account_mac_bundle", [], |r| r.get(0))?;
    Ok(Pair { root, source, local, bundle })
}

fn put(db: &AccountDb, selector: &str, bundle: &str, expires_at: i64) -> Result<(), StorageError> {
    db.connection.execute(
        "INSERT INTO receive_erased_input VALUES(?1,?2,?3) \
         ON CONFLICT(selector) DO UPDATE SET expires_at=excluded.expires_at",
        params![selector, bundle, expires_at],
    )?;
    Ok(())
}

fn merge(
    pair: &Pair,
) -> Result<(BackupDatabase, std::path::PathBuf, crate::AccountDbKey), StorageError> {
    let incoming = pair.root.join("incoming.db");
    let snapshot = pair.source.write_backup_snapshot(&incoming)?;
    let path = pair.root.join("merged.db");
    let target = pair.local.write_backup_snapshot(&path)?;
    let mut merged = BackupDatabase::open(&path, &target.key)?;
    merged.merge_backup(&incoming, &snapshot.key, || Ok(()))?;
    Ok((merged, path, target.key))
}

fn expiry(db: &rusqlite::Connection, selector: &str) -> rusqlite::Result<Option<i64>> {
    use rusqlite::OptionalExtension;
    db.query_row(
        "SELECT expires_at FROM receive_erased_input WHERE selector=?1",
        params![selector],
        |r| r.get(0),
    )
    .optional()
}

#[test]
#[allow(clippy::too_many_lines)] // one named test carries all eight cells
fn erased_input_restore_union() -> Result<(), StorageError> {
    let now = crate::unix_now();
    // (a) A duplicate selector keeps the local, larger expiry.
    let p = pair("erased-union-a")?;
    put(&p.local, "dup", &p.bundle, now + 2000)?;
    put(&p.source, "dup", &p.bundle, now + 1000)?;
    let (merged, ..) = merge(&p)?;
    assert_eq!(expiry(&merged.db, "dup")?, Some(now + 2000));
    drop(merged);
    // (b) The incoming, larger expiry wins in the reverse arrangement.
    let p = pair("erased-union-b")?;
    put(&p.local, "dup", &p.bundle, now + 1000)?;
    put(&p.source, "dup", &p.bundle, now + 2000)?;
    let (merged, ..) = merge(&p)?;
    assert_eq!(expiry(&merged.db, "dup")?, Some(now + 2000));
    drop(merged);
    // (c) Disjoint inputs union to 2N rows; (d) expired incoming rows are dropped; the local
    // expired row is swept (S2).
    let p = pair("erased-union-c")?;
    for n in 0..20 {
        put(&p.local, &format!("local-{n}"), &p.bundle, now + 3000)?;
        put(&p.source, &format!("incoming-{n}"), &p.bundle, now + 3000)?;
    }
    put(&p.source, "incoming-expired", &p.bundle, now - 10)?;
    put(&p.local, "local-expired", &p.bundle, now - 10)?;
    let (merged, path, key) = merge(&p)?;
    let rows: i64 =
        merged.db.query_row("SELECT count(*) FROM receive_erased_input", [], |r| r.get(0))?;
    assert_eq!(rows, 40);
    assert_eq!(expiry(&merged.db, "incoming-expired")?, None);
    assert_eq!(expiry(&merged.db, "local-expired")?, None);
    drop(merged);
    // (g) After reopen the merged rows are still present.
    let reopened = BackupDatabase::open(&path, &key)?;
    assert_eq!(expiry(&reopened.db, "incoming-7")?, Some(now + 3000));
    assert_eq!(expiry(&reopened.db, "local-7")?, Some(now + 3000));
    drop(reopened);
    // (e) An unknown incoming bundle refuses the merge atomically.
    let p = pair("erased-union-e")?;
    put(&p.local, "kept", &p.bundle, now + 3000)?;
    put(&p.source, "foreign", "bogus-bundle", now + 3000)?;
    let incoming = p.root.join("incoming.db");
    let snapshot = p.source.write_backup_snapshot(&incoming)?;
    let path = p.root.join("merged.db");
    let target = p.local.write_backup_snapshot(&path)?;
    let mut merged = BackupDatabase::open(&path, &target.key)?;
    let refused = merged.merge_backup(&incoming, &snapshot.key, || Ok(()));
    assert!(
        matches!(
            refused,
            Err(StorageError::Integrity("erased-input bundle unknown to the merged set"))
        ),
        "{:?}",
        refused.err()
    );
    // Zero rows changed: the local row survives and the foreign row never arrived.
    assert_eq!(expiry(&merged.db, "kept")?, Some(now + 3000));
    assert_eq!(expiry(&merged.db, "foreign")?, None);
    drop(merged);
    // (f) A bundle mismatch on an equal selector is refused.
    let p = pair("erased-union-f")?;
    let other: String =
        p.source
            .connection
            .query_row("SELECT bundle_id FROM account_mac_bundle", [], |r| r.get(0))?;
    put(&p.local, "same", &p.bundle, now + 3000)?;
    put(&p.source, "same", &other, now + 3000)?;
    let refused = merge(&p).map(|_| ());
    assert!(
        matches!(refused, Err(StorageError::Integrity("erased-input bundle mismatch"))),
        "{:?}",
        refused.err()
    );
    // (h) Whole-generation restore carries the table unstripped.
    let p = pair("erased-union-h")?;
    put(&p.source, "carried", &p.bundle, now + 3000)?;
    let snapshot_path = p.root.join("generation.db");
    let snapshot = p.source.write_backup_snapshot(&snapshot_path)?;
    let generation = BackupDatabase::open(&snapshot_path, &snapshot.key)?;
    assert_eq!(expiry(&generation.db, "carried")?, Some(now + 3000));
    Ok(())
}
