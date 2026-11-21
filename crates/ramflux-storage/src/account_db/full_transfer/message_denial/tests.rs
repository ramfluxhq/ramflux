// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Ordinary deletion -> exact owner encoding -> encrypted private B generation.
use super::*;
use crate::{AccountDb, AccountDbKey, AccountIndex, BackupDatabase};
use ramflux_protocol::custody::{DeviceRef, pairing::full_transfer::read_record_header};
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn database(label: &str) -> TestResult<(tempfile::TempDir, AccountDb)> {
    let root = tempfile::Builder::new().prefix(label).tempdir()?;
    let index = AccountIndex::open(root.path())?;
    index.create_account("acct", &ramflux_protocol::encode_base64url([3; 32]))?;
    let db = AccountDb::open(&index, "acct", &AccountDbKey::derive("acct", label.as_bytes()))?;
    Ok((root, db))
}
fn encoded(db: &AccountDb) -> TestResult<Zeroizing<Vec<u8>>> {
    let rule = full_transfer_catalog()
        .iter()
        .find(|rule| rule.id == FAMILY)
        .ok_or("test: message denial owner absent")?;
    Ok(db.connection.call(move |raw| { raw.query_row(
        "SELECT tombstone_id,conversation_id,message_id,delete_scope,created_at FROM message_tombstone_projection WHERE tombstone_id='delete-id'",
        [], move |row| {
            let mut bytes = Zeroizing::new(Vec::new());
            Ok(encode(rule,row,&mut *bytes).map(|_| bytes))
        },
    ) })??)
}

#[test]
fn full_message_denial_round_trip_erases_private_copy_preserves_live_target() -> TestResult {
    let (_source_root, a) = database("full-denial-source")?;
    let (target_root, b) = database("full-denial-target")?;
    for db in [&a, &b] {
        db.send_direct_message("thread", "message", "peer", b"private-body-canary")?;
    }
    a.delete_direct_message("thread", "message", "all", "delete-id")?;
    let bytes = encoded(&a)?;
    assert!(
        !bytes.windows(b"private-body-canary".len()).any(|part| part == b"private-body-canary"),
        "test: tombstone export retained erased content"
    );
    let path = target_root.path().join("private-copy.db");
    let snapshot = b.write_full_transfer_snapshot_cancellable(
        &path,
        std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
    )?;
    let mut private = BackupDatabase::open_full_receiver_copy(&path, &snapshot.key)?;
    let source = DeviceRef {
        account_anchor: ramflux_protocol::encode_base64url([3; 32]),
        device_id: "original-source".into(),
        device_epoch: 1,
    };
    private.db.execute_batch("BEGIN IMMEDIATE")?;
    for _ in 0..2 {
        let mut input = bytes.as_slice();
        let header = read_record_header(&mut input)?.ok_or("test: tombstone header absent")?;
        private.apply_full_fixed_base_record(&source, &header, &mut input)?;
        assert!(input.is_empty(), "test: semantic owner left unverified trailing cells");
    }
    private.db.execute_batch("COMMIT")?;
    let (deleted, body, sender): (bool, Vec<u8>, String) = private.db.query_row(
        "SELECT deleted,encrypted_body,sender_id FROM direct_message_projection WHERE message_id='message'",
        [], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?)),
    )?;
    assert!(
        deleted && body.is_empty() && sender.is_empty(),
        "test: imported denial failed to scrub B's private message"
    );
    assert_eq!(
        private.db.query_row("SELECT count(*) FROM message_tombstone_projection", [], |row| row
            .get::<_, u64>(0))?,
        1,
        "test: repeated owner import duplicated denial"
    );
    let live = b.direct_message_by_id("message")?.ok_or("test: live B message lost")?;
    assert!(!live.deleted, "test: private transfer application mutated live B");
    drop(private);
    let reopened = BackupDatabase::open_full_receiver_copy(&path, &snapshot.key)?;
    assert!(
        reopened.db.query_row(
            "SELECT deleted FROM direct_message_projection WHERE message_id='message'",
            [],
            |row| row.get::<_, bool>(0)
        )?,
        "test: tombstone/private erasure did not survive encrypted reopen"
    );
    Ok(())
}

#[test]
fn full_message_denial_refuses_changed_key_and_catalog_before_application() -> TestResult {
    let (_root, a) = database("full-denial-invalid")?;
    a.send_direct_message("thread", "message", "peer", b"body")?;
    a.delete_direct_message("thread", "message", "all", "delete-id")?;
    let bytes = encoded(&a)?;
    let mut input = bytes.as_slice();
    let mut header = read_record_header(&mut input)?.ok_or("test: tombstone header absent")?;
    let rule = full_transfer_catalog()
        .iter()
        .find(|rule| rule.id == FAMILY)
        .ok_or("test: owner absent")?;
    header.key = encode_stable_key([(CellType::Utf8, b"another-id".as_slice())])?.to_string();
    assert!(
        copy(rule, &header, &mut input, &mut std::io::sink()).is_err(),
        "test: owner accepted a key unrelated to the actual denial"
    );
    header.codec_version = U64(1);
    assert!(
        matches!(
            copy(rule, &header, &mut bytes.as_slice(), &mut std::io::sink()),
            Err(StorageError::PairingField("SchemaMismatch"))
        ),
        "test: owner reinterpreted an older codec version"
    );
    Ok(())
}

#[test]
fn full_message_denial_blocks_redelivery_when_target_never_had_the_message() -> TestResult {
    let (_source_root, a) = database("full-denial-absent-source")?;
    let (target_root, b) = database("full-denial-absent-target")?;
    a.send_direct_message("thread", "message", "peer", b"erased-original")?;
    a.delete_direct_message("thread", "message", "all", "delete-id")?;
    let bytes = encoded(&a)?;
    let path = target_root.path().join("private-copy.db");
    let snapshot = b.write_full_transfer_snapshot_cancellable(
        &path,
        std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
    )?;
    let private = BackupDatabase::open_full_receiver_copy(&path, &snapshot.key)?;
    private.db.execute_batch("BEGIN IMMEDIATE")?;
    let mut input = bytes.as_slice();
    let header = read_record_header(&mut input)?.ok_or("test: denial header absent")?;
    apply(&private.db, &header, &mut input)?;
    private.db.execute_batch("COMMIT")?;
    assert!(
        crate::account_db::deleted_messages::message_is_deleted_on(&private.db, "message")?,
        "test: new primary accepted redelivery of a message erased before its enrollment"
    );
    Ok(())
}
