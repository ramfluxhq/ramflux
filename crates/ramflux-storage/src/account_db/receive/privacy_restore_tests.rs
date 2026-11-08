// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! `ledger_privacy_restore`: published backups, merged generations and restore installs carry
//! tombstones and bindings, never the five gateway tables, receive C/E or receive-work footprints.
#![allow(clippy::expect_used, clippy::panic, clippy::too_many_lines)]
use super::erased_capture_tests::current;
use super::erased_input_union_tests::pair;
use super::privacy::ReceiveBind;
use super::privacy_tests::bind;
use super::stage_tests::{bytes, input, run, work_rows};
use super::w0_replay_support::{Tuple, assert_erased, install};
use crate::AccountDbKey;
use crate::{
    AccountDb, AccountIndex, BackupDatabase, BackupIndexInstall, BackupOpenMode, StorageError,
};
use rusqlite::params;
use rusqlite::types::ValueRef;
use serde_json::{Value, json};
use std::path::Path;

struct LedgerCounts {
    receipts: i64,
    work: i64,
    acks: i64,
    losses: i64,
    epochs: i64,
    work_footprints: i64,
    checkpoints: i64,
}

fn count(db: &rusqlite::Connection, sql: &str) -> rusqlite::Result<i64> {
    db.query_row(sql, [], |row| row.get(0))
}

fn ledger_counts(db: &rusqlite::Connection) -> rusqlite::Result<LedgerCounts> {
    Ok(LedgerCounts {
        receipts: count(db, "SELECT count(*) FROM gateway_receive_receipt")?,
        work: count(db, "SELECT count(*) FROM gateway_receive_work")?,
        acks: count(db, "SELECT count(*) FROM gateway_ack_intent")?,
        losses: count(db, "SELECT count(*) FROM gateway_inbox_loss")?,
        epochs: count(db, "SELECT count(*) FROM gateway_receive_epoch")?,
        work_footprints: count(
            db,
            "SELECT count(*) FROM message_footprint WHERE kind='receive_work'",
        )?,
        checkpoints: count(
            db,
            "SELECT count(*) FROM projection_checkpoint WHERE projection_name GLOB 'gateway_receive_*'",
        )?,
    })
}

fn assert_stripped(db: &rusqlite::Connection, where_from: &str) -> rusqlite::Result<()> {
    let c = ledger_counts(db)?;
    assert_eq!(c.receipts, 0, "{where_from} receipts");
    assert_eq!(c.work, 0, "{where_from} work");
    assert_eq!(c.acks, 0, "{where_from} acks");
    assert_eq!(c.losses, 0, "{where_from} losses");
    assert_eq!(c.epochs, 0, "{where_from} epochs");
    assert_eq!(c.work_footprints, 0, "{where_from} receive_work footprints");
    assert_eq!(c.checkpoints, 0, "{where_from} receive checkpoints");
    Ok(())
}

fn ledger_counts_account(db: &AccountDb) -> rusqlite::Result<LedgerCounts> {
    db.connection.call(|raw| ledger_counts(raw))
}

fn assert_stripped_account(db: &AccountDb, where_from: &'static str) -> rusqlite::Result<()> {
    db.connection.call(move |raw| assert_stripped(raw, where_from))
}

fn work(payload: &str, principal: &str, device: &str, now: i64) -> Vec<u8> {
    let mut v: Value = serde_json::from_slice(&bytes(1)).expect("entry fixture");
    v["envelope"]["payload_hash"] = json!(payload);
    v["envelope"]["source_principal_id"] = json!(principal);
    v["envelope"]["source_device_id"] = json!(device);
    v["envelope"]["created_at"] = json!(now);
    v["envelope"]["ttl"] = json!(3600);
    serde_json::to_vec(&v).expect("entry encoding")
}

fn put_tombstone(
    db: &AccountDb,
    principal: &str,
    device: &str,
    payload: &str,
    expires_at: i64,
) -> Result<(String, String), StorageError> {
    let (bundle, selector) = current(db, principal, device, payload)?;
    db.connection.execute(
        "INSERT INTO receive_erased_input VALUES(?1,?2,?3) \
         ON CONFLICT(selector) DO UPDATE SET expires_at=max(expires_at,excluded.expires_at)",
        params![selector, bundle, expires_at],
    )?;
    db.connection.execute(
        "INSERT INTO message_copy_binding VALUES(?1,'keep')",
        params![format!("erased-input:{bundle}:{selector}:{expires_at}")],
    )?;
    Ok((bundle, selector))
}

/// Writes the live generation as-is, with the receive ledger present. `write_backup_snapshot`
/// always strips it, so this is the only way to exercise the strips in `copy_to` and the merges.
fn unstripped_snapshot(db: &AccountDb, path: &Path) -> Result<AccountDbKey, StorageError> {
    let key = AccountDbKey::generate()?;
    let hex = key.sqlcipher_hex();
    let fingerprint = key.fingerprint();
    let destination = path.to_owned();
    db.connection.call(move |source| {
        let mut target = rusqlite::Connection::open(destination)?;
        target.execute_batch(&format!(
            "PRAGMA key = \"x'{hex}'\"; PRAGMA synchronous=FULL; PRAGMA journal_mode=DELETE;"
        ))?;
        {
            let backup = rusqlite::backup::Backup::new(source, &mut target)?;
            backup.run_to_completion(128, std::time::Duration::ZERO, None)?;
        }
        target.execute(
            "UPDATE account_key_check SET key_fingerprint=?1 WHERE singleton_id=1",
            params![fingerprint],
        )?;
        target.close().map_err(|(_, error)| error)?;
        Ok(())
    })?;
    Ok(key)
}

/// The wire ID (sequence 1 as locator text and as big-endian bytes) and the payload bytes.
fn wire_needles() -> [Vec<u8>; 3] {
    [b"p-work".to_vec(), b"0000000000000001".to_vec(), 1u64.to_be_bytes().to_vec()]
}

fn scan_rows(db: &rusqlite::Connection, sql: &str) -> rusqlite::Result<usize> {
    let needles = wire_needles();
    let mut query = db.prepare(sql)?;
    let columns = query.column_count();
    let mut rows = query.query([])?;
    let mut hits = 0;
    while let Some(row) = rows.next()? {
        for column in 0..columns {
            let hit = match row.get_ref(column)? {
                ValueRef::Text(value) | ValueRef::Blob(value) => {
                    needles.iter().any(|n| value.windows(n.len()).any(|w| w == n.as_slice()))
                }
                _ => false,
            };
            hits += usize::from(hit);
        }
    }
    Ok(hits)
}

/// Counts wire-ID or payload hits in the five gateway tables, receive-work footprints and
/// receive checkpoints.
fn ledger_leaks(db: &rusqlite::Connection) -> rusqlite::Result<usize> {
    let mut hits = 0;
    for table in [
        "gateway_receive_work",
        "gateway_receive_receipt",
        "gateway_ack_intent",
        "gateway_inbox_loss",
        "gateway_receive_epoch",
    ] {
        hits += scan_rows(db, &format!("SELECT * FROM {table}"))?;
    }
    hits += scan_rows(
        db,
        "SELECT message_id,locator FROM message_footprint WHERE kind='receive_work'",
    )?;
    hits += scan_rows(
        db,
        "SELECT projection_name,last_event_id FROM projection_checkpoint \
         WHERE projection_name GLOB 'gateway_receive_*'",
    )?;
    Ok(hits)
}

#[test]
fn privacy_restore_strips_unstripped_inputs() -> Result<(), StorageError> {
    let now = crate::unix_now();
    let p = pair("privacy-restore-unstripped")?;
    p.local.send_direct_message("thread", "keep", "peer", b"x")?;
    p.source.send_direct_message("thread", "keep", "peer", b"x")?;
    seed_ledger(&p.local, now)?;
    put_tombstone(&p.local, "ap", "ad", "payload-a", now + 3_900)?;
    put_tombstone(&p.local, "bp", "bd", "payload-b", now + 3_900)?;

    // Restore leg: copy_to from an input that still holds the receive ledger.
    let raw_path = p.root.join("raw.db");
    let raw_key = unstripped_snapshot(&p.local, &raw_path)?;
    let raw = BackupDatabase::open(&raw_path, &raw_key)?;
    assert!(ledger_leaks(&raw.db)? > 0, "raw input must still hold the ledger");
    let private = p.root.join("private.db");
    let private_key = AccountDbKey::generate()?;
    raw.copy_to(&private, &private_key)?;
    drop(raw);
    let private_db = BackupDatabase::open(&private, &private_key)?;
    assert_stripped(&private_db.db, "copy_to")?;
    assert_eq!(ledger_leaks(&private_db.db)?, 0, "copy_to leaked a wire ID or payload");
    drop(private_db);

    // Merge leg: a target that still holds the ledger, merged with a stripped incoming generation.
    let incoming = p.root.join("incoming.db");
    let incoming_snap = p.source.write_backup_snapshot(&incoming)?;
    let target_path = p.root.join("merge-target.db");
    let target_key = unstripped_snapshot(&p.local, &target_path)?;
    let mut merged = BackupDatabase::open(&target_path, &target_key)?;
    assert!(ledger_leaks(&merged.db)? > 0, "merge target must still hold the ledger");
    merged.merge_backup(&incoming, &incoming_snap.key, || Ok(()))?;
    drop(merged);
    let merged = BackupDatabase::open(&target_path, &target_key)?;
    assert_stripped(&merged.db, "merged")?;
    assert_eq!(ledger_leaks(&merged.db)?, 0, "merge leaked a wire ID or payload");
    drop(merged);

    // Archive leg: the outbound archive strip on an unstripped generation.
    let archive_path = p.root.join("archive-target.db");
    let archive_key = unstripped_snapshot(&p.local, &archive_path)?;
    let archive = BackupDatabase::open(&archive_path, &archive_key)?;
    assert!(ledger_leaks(&archive.db)? > 0, "archive target must still hold the ledger");
    archive.archive_outbound()?;
    drop(archive);
    let archive = BackupDatabase::open(&archive_path, &archive_key)?;
    assert_stripped(&archive.db, "archived")?;
    assert_eq!(ledger_leaks(&archive.db)?, 0, "archive leaked a wire ID or payload");
    Ok(())
}

/// Stages `payload` at `sequence`, binds it to `message` through the receive path, then deletes
/// `message`. The binding outlives the deletion and fires once it is captured.
fn stage_bind_delete(
    db: &AccountDb,
    sequence: u64,
    message: &str,
    tuple: (&str, &str, &str),
    now: i64,
) -> Result<(String, String), StorageError> {
    let (principal, device, payload) = tuple;
    db.send_direct_message("thread", message, "peer", b"x")?;
    let mut entry: Value =
        serde_json::from_slice(&work(payload, principal, device, now)).expect("entry");
    entry["inbox_seq"] = json!(sequence);
    entry["target_delivery_id"] = json!("t");
    let wire = serde_json::to_vec(&entry).expect("entry encoding");
    assert_eq!(run(db, input(&wire, sequence))?, super::stage::ReceiveStageResult::Staged);
    assert_eq!(bind(db, sequence, message)?, ReceiveBind::Bound);
    db.delete_direct_message("thread", message, "local", &format!("d-{message}"))?;
    current(db, principal, device, payload)
}

fn file_set(dir: &Path) -> std::io::Result<std::collections::BTreeMap<String, Vec<u8>>> {
    fn walk(
        base: &Path,
        dir: &Path,
        out: &mut std::collections::BTreeMap<String, Vec<u8>>,
    ) -> std::io::Result<()> {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return Ok(());
        };
        for entry in entries {
            let path = entry?.path();
            if path.is_dir() {
                walk(base, &path, out)?;
            } else {
                let name = path.strip_prefix(base).map_err(std::io::Error::other)?;
                out.insert(name.to_string_lossy().into_owned(), std::fs::read(&path)?);
            }
        }
        Ok(())
    }
    let mut out = std::collections::BTreeMap::new();
    walk(dir, dir, &mut out)?;
    Ok(out)
}

/// Seeds one pending receive (`p-work`, sequence 1) and the rest of the receive ledger on `db`.
fn seed_ledger(db: &AccountDb, now: i64) -> Result<(), StorageError> {
    db.install_receive_ledger_schema()?;
    db.connection.execute(
        "INSERT INTO gateway_receive_epoch VALUES('t','e',1,x'',?1,?1)",
        params![5u64.to_be_bytes().as_slice()],
    )?;
    let wire = work("p-work", "wp", "wd", now);
    assert_eq!(run(db, input(&wire, 1))?, super::stage::ReceiveStageResult::Staged);
    db.connection.execute(
        "INSERT INTO gateway_ack_intent VALUES('t','e',?1,1,0,1,100)",
        params![2u64.to_be_bytes().as_slice()],
    )?;
    db.connection.execute(
        "INSERT INTO gateway_inbox_loss VALUES('t','e',?1,?1,?2,'gap',1,'legacy_unverified')",
        params![3u64.to_be_bytes().as_slice(), 1u64.to_be_bytes().as_slice()],
    )?;
    Ok(())
}

/// Checkpoints that name the receive cursor; written after staging, since staging needs cursor 0.
fn seed_checkpoints(db: &AccountDb) -> Result<(), StorageError> {
    db.connection.execute(
        "INSERT INTO projection_checkpoint(projection_name,projection_version,last_event_id,updated_at) \
         VALUES('gateway_receive_cursor:t',1,'c',1)",
        [],
    )?;
    db.connection.execute(
        "INSERT INTO projection_checkpoint(projection_name,projection_version,last_event_id,updated_at) \
         VALUES('gateway_receive_conflict:t',1,'x',1)",
        [],
    )?;
    Ok(())
}

#[test]
fn ledger_privacy_restore() -> Result<(), StorageError> {
    let now = crate::unix_now();
    let p = pair("ledger-privacy-restore")?;
    p.local.send_direct_message("thread", "keep", "peer", b"x")?;
    p.source.send_direct_message("thread", "keep", "peer", b"x")?;
    seed_ledger(&p.local, now)?;
    // Pending work bound to a live message: its binding must stay inert, never a tombstone.
    p.local
        .connection
        .execute("INSERT INTO message_copy_binding VALUES('payload:p-work','keep')", [])?;
    let pending = current(&p.local, "wp", "wd", "p-work")?.1;
    // Real deleted messages A and B: bound work through the receive path, then the deletion.
    let (_, selector_a) = stage_bind_delete(&p.local, 2, "A", ("ap", "ad", "payload-a"), now)?;
    let (_, selector_b) = stage_bind_delete(&p.local, 3, "B", ("bp", "bd", "payload-b"), now)?;
    seed_checkpoints(&p.local)?;
    let before = ledger_counts_account(&p.local)?;
    assert!(before.receipts > 0 && before.work > 0 && before.epochs > 0);
    assert!(before.acks > 0 && before.losses > 0 && before.checkpoints > 0);
    let snapshot_path = p.root.join("snap.db");
    let snapshot = p.local.write_backup_snapshot(&snapshot_path)?;
    let published = BackupDatabase::open(&snapshot_path, &snapshot.key)?;
    assert_stripped(&published.db, "snapshot")?;
    assert_eq!(
        count(&published.db, "SELECT count(*) FROM receive_erased_input")?,
        2,
        "A and B tombstones only; pending work is never tombstoned"
    );
    assert!(super::erased_input_union_tests::expiry(&published.db, &selector_a)?.is_some());
    assert!(super::erased_input_union_tests::expiry(&published.db, &selector_b)?.is_some());
    assert_eq!(super::erased_input_union_tests::expiry(&published.db, &pending)?, None);
    let bindings: i64 = count(
        &published.db,
        "SELECT count(*) FROM message_copy_binding WHERE copy_id GLOB 'erased-input:*'",
    )?;
    assert_eq!(bindings, 1, "the pending work keeps an inert binding on its live message");
    drop(published);

    let original_open = BackupDatabase::open_restore_input(
        &snapshot_path,
        &snapshot.key,
        BackupOpenMode::Normalized,
    )?;
    let original = original_open.original_input().clone();
    assert_eq!(original.schema_version, 15);
    assert!(original.counts.messages >= 1);
    let pre = BackupDatabase::open_restore_input(
        &snapshot_path,
        &snapshot.key,
        BackupOpenMode::PreNormalization,
    )?;
    assert_eq!(pre.original_input().schema_version, original.schema_version);
    assert_eq!(pre.original_input().counts, original.counts);
    let private = p.root.join("private.db");
    pre.copy_to(&private, &snapshot.key)?;
    let reopened =
        pre.reopen_restore_input(&private, &snapshot.key, BackupOpenMode::PreNormalization)?;
    assert_eq!(reopened.original_input(), pre.original_input());
    let normalized =
        reopened.reopen_restore_input(&private, &snapshot.key, BackupOpenMode::Normalized)?;
    assert_eq!(normalized.original_input(), pre.original_input());
    assert_stripped(&normalized.db, "normalized copy")?;
    drop(normalized);
    drop(reopened);
    drop(pre);
    drop(original_open);

    let incoming = p.root.join("incoming.db");
    let incoming_snap = p.source.write_backup_snapshot(&incoming)?;
    let mut merged = BackupDatabase::open(&snapshot_path, &snapshot.key)?;
    merged.merge_backup(&incoming, &incoming_snap.key, || Ok(()))?;
    assert_stripped(&merged.db, "merged")?;
    drop(merged);

    let restored_index = install(&p.root, "restored", &private, &snapshot.key)?;
    let restored = AccountDb::open(&restored_index, "account", &snapshot.key)?;
    assert_stripped_account(&restored, "restored install")?;
    let tuples: Vec<Tuple> = vec![
        ("ap".to_owned(), "ad".to_owned(), "payload-a".to_owned()),
        ("bp".to_owned(), "bd".to_owned(), "payload-b".to_owned()),
    ];
    assert_erased(&restored, &tuples, 1_000)?;
    // Collision B: `wire` was pending at backup time. The gateway redelivers it after restore.
    let wire = work("p-work", "wp", "wd", now);
    assert_eq!(run(&restored, input(&wire, 1))?, super::stage::ReceiveStageResult::Staged);
    assert_eq!(work_rows(&restored)?, 1, "one staged work row after redelivery");
    drop(restored);

    let (erase_root, erase_db) = crate::tests::test_db("ledger-privacy-removed")?;
    let erase_index = AccountIndex::open(&erase_root)?;
    let record = erase_index.account("acct")?;
    drop(erase_db);
    erase_index.erase_account_database("acct")?;
    assert_eq!(erase_index.account("acct")?.account_state, "removed");
    let before_files = file_set(&erase_root)?;
    let wrapped = crate::WrappedAccountDbKey {
        key_wrapping_provider: "platform-local-vault".to_owned(),
        key_wrapping_ref: "platform-local-vault:acct".to_owned(),
        nonce: [7; 12],
        wrapped_key: vec![9; 48],
    };
    let refused = erase_index.install_backup_generation(&BackupIndexInstall {
        account_id: "acct",
        principal_commitment: &record.principal_commitment,
        db_relative_path: "accounts/acct/generation_new/account.db",
        object_relative_path: "accounts/acct/generation_new",
        manifest_json: b"test manifest",
        wrapped_key: &wrapped,
    });
    assert!(
        matches!(&refused, Err(StorageError::AccountNotFound(id)) if id == "acct"),
        "{refused:?}"
    );
    assert_eq!(file_set(&erase_root)?, before_files, "removed account files unchanged");
    Ok(())
}
