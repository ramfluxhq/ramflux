// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! `ledger_privacy_restore`: published backups, merged generations and restore installs carry
//! tombstones and bindings, never the five gateway tables, receive C/E or receive-work footprints.
#![allow(clippy::expect_used, clippy::panic, clippy::too_many_lines)]
use super::erased_capture_tests::current;
use super::erased_input_union_tests::pair;
use super::stage_tests::{bytes, input, run};
use super::w0_replay_support::{Tuple, assert_erased, install};
use crate::{
    AccountDb, AccountIndex, BackupDatabase, BackupIndexInstall, BackupOpenMode, StorageError,
};
use rusqlite::params;
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

#[test]
fn ledger_privacy_restore() -> Result<(), StorageError> {
    let now = crate::unix_now();
    let p = pair("ledger-privacy-restore")?;
    p.local.send_direct_message("thread", "keep", "peer", b"x")?;
    p.source.send_direct_message("thread", "keep", "peer", b"x")?;
    p.local.install_receive_ledger_schema()?;
    p.local.connection.execute(
        "INSERT INTO gateway_receive_epoch VALUES('t','e',1,x'',?1,?1)",
        params![5u64.to_be_bytes().as_slice()],
    )?;
    let wire = work("p-work", "wp", "wd", now);
    assert_eq!(run(&p.local, input(&wire, 1))?, super::stage::ReceiveStageResult::Staged);
    p.local.connection.execute(
        "INSERT INTO gateway_ack_intent VALUES('t','e',?1,1,0,1,100)",
        params![2u64.to_be_bytes().as_slice()],
    )?;
    p.local.connection.execute(
        "INSERT INTO gateway_inbox_loss VALUES('t','e',?1,?1,?2,'gap',1,'legacy_unverified')",
        params![3u64.to_be_bytes().as_slice(), 1u64.to_be_bytes().as_slice()],
    )?;
    p.local.connection.execute(
        "INSERT INTO projection_checkpoint(projection_name,projection_version,last_event_id,updated_at) \
         VALUES('gateway_receive_cursor:t',1,'c',1)",
        [],
    )?;
    p.local.connection.execute(
        "INSERT INTO projection_checkpoint(projection_name,projection_version,last_event_id,updated_at) \
         VALUES('gateway_receive_conflict:t',1,'x',1)",
        [],
    )?;
    let before = ledger_counts_account(&p.local)?;
    assert!(before.receipts > 0 && before.work > 0 && before.epochs > 0);
    assert!(before.acks > 0 && before.losses > 0 && before.checkpoints > 0);
    let expires = now + 3_900;
    let (_, selector_a) = put_tombstone(&p.local, "ap", "ad", "payload-a", expires)?;
    let (_, selector_b) = put_tombstone(&p.local, "bp", "bd", "payload-b", expires)?;

    let snapshot_path = p.root.join("snap.db");
    let snapshot = p.local.write_backup_snapshot(&snapshot_path)?;
    let published = BackupDatabase::open(&snapshot_path, &snapshot.key)?;
    assert_stripped(&published.db, "snapshot")?;
    assert_eq!(
        count(&published.db, "SELECT count(*) FROM receive_erased_input")?,
        3,
        "work carry plus A and B"
    );
    let bindings: i64 = count(
        &published.db,
        "SELECT count(*) FROM message_copy_binding WHERE copy_id GLOB 'erased-input:*'",
    )?;
    assert_eq!(bindings, 2, "erased-input bindings carried");
    assert_eq!(super::erased_input_union_tests::expiry(&published.db, &selector_a)?, Some(expires));
    assert_eq!(super::erased_input_union_tests::expiry(&published.db, &selector_b)?, Some(expires));
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
