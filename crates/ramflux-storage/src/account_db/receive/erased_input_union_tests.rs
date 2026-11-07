// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Restore and merge union of erased-input tombstones, with the generic merge skipping the table.
#![allow(clippy::expect_used, clippy::panic)]
use crate::{AccountDb, AccountDbKey, AccountIndex, BackupDatabase, StorageError};
use rusqlite::params;

pub(super) struct Pair {
    pub(super) root: std::path::PathBuf,
    pub(super) source: AccountDb,
    pub(super) local: AccountDb,
    pub(super) bundle: String,
}

pub(super) fn pair(name: &str) -> Result<Pair, StorageError> {
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

pub(super) fn merge(
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

pub(super) fn expiry(db: &rusqlite::Connection, selector: &str) -> rusqlite::Result<Option<i64>> {
    use rusqlite::OptionalExtension;
    db.query_row(
        "SELECT expires_at FROM receive_erased_input WHERE selector=?1",
        params![selector],
        |r| r.get(0),
    )
    .optional()
}

type State = (Vec<String>, Vec<String>, Vec<(String, i64)>);

/// Bundles, domain rows and tombstones: everything a refused merge must leave untouched.
fn state(db: &rusqlite::Connection) -> rusqlite::Result<State> {
    let column = |sql: &str| -> rusqlite::Result<Vec<String>> {
        db.prepare(sql)?.query_map([], |r| r.get(0))?.collect()
    };
    let mut tombstones =
        db.prepare("SELECT selector,expires_at FROM receive_erased_input ORDER BY 1")?;
    let tombstones =
        tombstones.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?.collect::<Result<_, _>>()?;
    Ok((
        column("SELECT bundle_id FROM account_mac_bundle ORDER BY 1")?,
        column("SELECT message_id FROM direct_message_projection ORDER BY 1")?,
        tombstones,
    ))
}

/// Runs a merge that must fail with the exact `Integrity` text. The incoming snapshot carries a
/// message and its own MAC bundle that a successful merge would import; none of it may remain,
/// immediately or after reopen.
fn assert_refused(p: &Pair, expected: &'static str) -> Result<(), StorageError> {
    p.source.send_direct_message("thread", "incoming-only", "peer", b"payload")?;
    let incoming = p.root.join("incoming.db");
    let snapshot = p.source.write_backup_snapshot(&incoming)?;
    let path = p.root.join("merged.db");
    let target = p.local.write_backup_snapshot(&path)?;
    let mut merged = BackupDatabase::open(&path, &target.key)?;
    let before = state(&merged.db)?;
    assert!(!before.1.contains(&"incoming-only".to_owned()));
    let refused = merged.merge_backup(&incoming, &snapshot.key, || Ok(()));
    assert!(
        matches!(&refused, Err(StorageError::Integrity(text)) if *text == expected),
        "{:?}",
        refused.err()
    );
    assert_eq!(state(&merged.db)?, before, "refused merge changed state");
    drop(merged);
    let reopened = BackupDatabase::open(&path, &target.key)?;
    assert_eq!(state(&reopened.db)?, before, "refused merge changed state after reopen");
    Ok(())
}

#[test]
fn erased_input_merge_sweep_and_union_honour_the_expiry_boundary() -> Result<(), StorageError> {
    let db = rusqlite::Connection::open_in_memory()?;
    db.execute_batch(
        "ATTACH ':memory:' AS incoming;
         CREATE TABLE main.account_mac_bundle(bundle_id TEXT);
         INSERT INTO account_mac_bundle VALUES('b');
         CREATE TABLE main.message_copy_binding(copy_id TEXT,message_id TEXT);
         CREATE TABLE main.receive_erased_input(selector TEXT PRIMARY KEY,bundle_id TEXT,expires_at INTEGER);
         CREATE TABLE incoming.receive_erased_input(selector TEXT PRIMARY KEY,bundle_id TEXT,expires_at INTEGER);",
    )?;
    let now = 5_000;
    for (table, selector, at) in [
        ("main", "local-now", now),
        ("main", "local-next", now + 1),
        ("incoming", "incoming-now", now),
        ("incoming", "incoming-next", now + 1),
    ] {
        db.execute(
            &format!("INSERT INTO {table}.receive_erased_input VALUES(?1,'b',?2)"),
            params![selector, at],
        )?;
    }
    super::erased_input::merge_from_at(&db, "incoming", now)?;
    let kept: Vec<String> = db
        .prepare("SELECT selector FROM main.receive_erased_input ORDER BY 1")?
        .query_map([], |r| r.get(0))?
        .collect::<Result<_, _>>()?;
    // expires_at == now is expired (dropped and swept); now + 1 is live (kept and imported).
    assert_eq!(kept, vec!["incoming-next".to_owned(), "local-next".to_owned()]);
    Ok(())
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
    // Positive control for the refusal oracle: a successful merge imports this message and the
    // source's own MAC bundle, so their absence after a refusal is meaningful.
    p.source.send_direct_message("thread", "incoming-only", "peer", b"payload")?;
    let (merged, path, key) = merge(&p)?;
    let imported = state(&merged.db)?;
    assert!(imported.1.contains(&"incoming-only".to_owned()));
    assert_eq!(imported.0.len(), 2, "local and source bundles");
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
    assert_refused(&p, "erased-input bundle unknown to the merged set")?;
    // (f) A bundle mismatch on an equal selector is refused, also atomically.
    let p = pair("erased-union-f")?;
    let other: String =
        p.source
            .connection
            .query_row("SELECT bundle_id FROM account_mac_bundle", [], |r| r.get(0))?;
    put(&p.local, "same", &p.bundle, now + 3000)?;
    put(&p.source, "same", &other, now + 3000)?;
    assert_refused(&p, "erased-input bundle mismatch")?;
    // (h) Whole-generation restore carries the table unstripped.
    let p = pair("erased-union-h")?;
    put(&p.source, "carried", &p.bundle, now + 3000)?;
    let snapshot_path = p.root.join("generation.db");
    let snapshot = p.source.write_backup_snapshot(&snapshot_path)?;
    let generation = BackupDatabase::open(&snapshot_path, &snapshot.key)?;
    assert_eq!(expiry(&generation.db, "carried")?, Some(now + 3000));
    Ok(())
}
