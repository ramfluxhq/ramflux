// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! P19 first-leg `all_receive_writers_guard`: inventory, exclusive bind, managed ACK
//! refusal, SQL/inbox/ACK/hold-delete hooks, held never acknowledged. P25 completes live wiring.
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use super::authority::{AuthorityKind, LedgerAuthority};
use super::executor::{
    CoverOutcome, LedgerExecutor, group_remove_unrouted_in, message_receive_ack_in,
    reset_actor_accounts,
};
use super::hooks;
use super::inventory::{SITES, WriterClass};
use super::managed_ack::{MANAGED_ACK_CODE, managed_public_ack};
use crate::bus::io::local_bus_error_code;
use crate::bus::protocol::LocalBusMessageAckRequest;
use crate::prelude::*;
use ramflux_storage::{
    AccountDb, AccountDbKey, AccountIndex, ReceiveCover, ReceiveCoverKind, ReceiveCoverResult,
    ReceiveExpectation, ReceiveStage, ReceiveStageResult, StorageError,
};
use std::fs;
use std::path::{Path, PathBuf};

struct Harness {
    _root: tempfile::TempDir,
    db: AccountDb,
}

fn open() -> Result<Harness, StorageError> {
    let root = tempfile::tempdir().expect("tmp");
    let index = AccountIndex::open(root.path())?;
    index.create_account("acct", "principal")?;
    let db =
        AccountDb::open(&index, "acct", &AccountDbKey::derive("acct", b"storage-test-secret"))?;
    db.install_receive_ledger_schema()?;
    db.seed_receive_epoch_for_test("t", "e")?;
    Ok(Harness { _root: root, db })
}

fn expected(db: &AccountDb, cursor: u64) -> Result<ReceiveExpectation<'static>, StorageError> {
    Ok(ReceiveExpectation {
        target: "t",
        incarnation: "e",
        cursor,
        generation: 1,
        erasure_generation: db.privacy_erasure_generation()?,
    })
}

fn wire(seq: u64) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({"inbox_seq":seq,"target_delivery_id":"t","envelope":{
        "schema":"test","version":1,"domain":"test","signing_key_id":"key","signature_alg":"ed25519","signature":"sig",
        "envelope_id":"env","source_principal_id":"source","source_device_id":"device","target_delivery_id":"t",
        "delivery_class":"opaque_event","priority":"normal","ttl":60,"created_at":1,"encrypted_payload":"cipher","payload_hash":"hash"
    }}))
    .expect("entry")
}

fn into_storage(error: SdkError) -> StorageError {
    match error {
        SdkError::Storage(storage) => storage,
        SdkError::ObjectErased => StorageError::ObjectErased,
        other => panic!("executor error: {other}"),
    }
}

fn stage(db: &AccountDb, cursor: u64, sequence: u64) -> Result<(), StorageError> {
    let bytes = wire(sequence);
    let result = db.receive_transaction(expected(db, cursor)?, 1, |tx| {
        tx.stage(ReceiveStage {
            target: "t",
            incarnation: "e",
            sequence,
            entry_json: &bytes,
            admission_key: "authenticated-key",
            retain_until: 100,
            first_seen: 1,
        })
    })?;
    assert!(matches!(result, ReceiveStageResult::Staged), "{result:?}");
    Ok(())
}

fn rel_src(path: &Path, src_root: &Path) -> String {
    format!("src/{}", path.strip_prefix(src_root).expect("src").display()).replace('\\', "/")
}

fn is_fixture(rel: &str) -> bool {
    rel.contains("/tests/") || rel.ends_with("_tests.rs") || rel.contains("/push_receiver/")
}

fn writer_patterns(src: &str) -> bool {
    src.contains("persist_gateway_receive_cursor")
        || src.contains("ack_gateway_entry")
        || src.contains("ack_gateway_delivery")
        || src.contains("remove_unrouted")
        || src.contains("engine.ack(")
}

fn walk_rs(dir: &Path, files: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).expect("read src") {
        let entry = entry.expect("dirent");
        let path = entry.path();
        if path.is_dir() {
            walk_rs(&path, files);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            files.push(path);
        }
    }
}

fn assert_inventory_scan() {
    let src_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    for site in SITES {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(site.file);
        assert!(path.is_file(), "inventory names missing file {}", site.file);
    }
    let mut files = Vec::new();
    walk_rs(&src_root, &mut files);
    let mut missing = Vec::new();
    for path in files {
        let rel = rel_src(&path, &src_root);
        if is_fixture(&rel) {
            continue;
        }
        let src = fs::read_to_string(&path).expect("read rust");
        if writer_patterns(&src) && !SITES.iter().any(|site| site.file == rel) {
            missing.push(rel);
        }
    }
    assert!(missing.is_empty(), "unclassified production receive writers: {missing:?}");
    assert!(SITES.iter().any(|site| site.file == "src/bus/dispatch/message.rs"
        && site.symbol == "message.ack"
        && site.executor.contains("managed_public_ack")));
    assert!(SITES.iter().any(|site| site.class == WriterClass::FixtureOnly));
}

fn cover(
    exec: &LedgerExecutor,
    db: &AccountDb,
    cursor: u64,
    sequence: u64,
    kind: ReceiveCoverKind,
) -> Result<CoverOutcome, SdkError> {
    db.receive_transaction(expected(db, cursor)?, 1, |tx| {
        exec.cover_in(tx, ReceiveCover { sequence, kind, gaps: &[], retain_until: 0 })
            .map_err(into_storage)
    })
    .map_err(SdkError::from)
}

fn assert_exclusive_and_managed_ack() -> Result<(), SdkError> {
    reset_actor_accounts();
    let actor = LedgerExecutor::actor();
    actor.bind_account("acct-p19")?;
    let standalone = LedgerExecutor::standalone();
    match standalone.bind_account("acct-p19") {
        Err(SdkError::Storage(StorageError::AccountWriterBusy(id))) if id == "acct-p19" => {}
        other => panic!("expected AccountWriterBusy, got {other:?}"),
    }
    standalone.bind_account("acct-other")?;
    let request = LocalBusMessageAckRequest {
        envelope_id: "env-1".to_owned(),
        receiver_device_id: "dev-1".to_owned(),
        received_at: 42,
    };
    assert_eq!(
        serde_json::to_value(&request).expect("ack request shape"),
        serde_json::json!({
            "envelope_id": "env-1",
            "receiver_device_id": "dev-1",
            "received_at": 42,
        })
    );
    match managed_public_ack(&request) {
        Err(ref error @ SdkError::InboundRejected(ref code)) if code == MANAGED_ACK_CODE => {
            assert_eq!(local_bus_error_code(error), MANAGED_ACK_CODE);
        }
        other => panic!("expected managed ACK refusal, got {other:?}"),
    }
    Ok(())
}

fn assert_hooks(exec: &LedgerExecutor, db: &AccountDb) -> Result<(), SdkError> {
    hooks::clear();
    exec.request_inbox_in(0, 64);
    let inbox = hooks::take_inbox();
    assert_eq!(inbox.len(), 1);
    assert_eq!(inbox[0].after, 0);
    assert_eq!(exec.load_startup_cursor(db, "t")?, 0);
    assert_eq!(hooks::take_sql().len(), 0, "startup C is read-only");
    stage(db, 0, 1)?;
    let w2 = cover(exec, db, 0, 1, ReceiveCoverKind::Terminal)?;
    assert_eq!(w2.result, ReceiveCoverResult::Covered);
    assert!(w2.ack_eligible);
    assert_eq!(w2.authority.kind(), AuthorityKind::W2);
    let sql = hooks::take_sql();
    assert_eq!(sql.len(), 1);
    assert_eq!(sql[0].token.kind(), AuthorityKind::W2);
    let wa = exec.mint_wa(w2.authority, w2.ack_eligible, 1)?;
    message_receive_ack_in(exec, &wa, 1)?;
    let cursor = exec.load_startup_cursor(db, "t")?;
    let acks = hooks::take_acks();
    assert!(!acks.is_empty(), "conversation ACK must produce a wire frame");
    for frame in &acks {
        assert!(frame.token.is_some_and(LedgerAuthority::is_wa), "ACK outside WA: {frame:?}");
        assert!(frame.seq <= cursor, "ACK s>C: {frame:?}");
    }
    match exec.persist_receive_checkpoint_in(db, &wa, "t", 1) {
        Err(SdkError::Storage(StorageError::AuthorizationRejected)) => {}
        other => panic!("WA must not write C, got {other:?}"),
    }
    assert_eq!(hooks::take_sql().len(), 0);
    stage(db, 1, 2)?;
    let held = cover(exec, db, 1, 2, ReceiveCoverKind::Held)?;
    assert!(!held.ack_eligible);
    match exec.mint_wa(held.authority, held.ack_eligible, 2) {
        Err(SdkError::Storage(StorageError::Integrity(
            "held sequence is not eligible for ACK",
        ))) => {}
        other => panic!("held must not mint WA, got {other:?}"),
    }
    assert_eq!(hooks::take_acks().len(), 0, "held never acknowledged");
    db.hold_unrouted("hold-1", 2, b"{}", 1)?;
    group_remove_unrouted_in(exec, db, &held.authority, "hold-1")?;
    assert_eq!(db.unrouted_count()?, 0, "authorized hold delete must remove the row");
    let deletes = hooks::take_deletes();
    assert!(
        deletes.iter().any(|row| {
            row.id == "hold-1" && row.token.is_some_and(LedgerAuthority::allows_hold_delete)
        }),
        "delete hook detects missing transaction authority: {deletes:?}"
    );
    db.hold_unrouted("hold-2", 2, b"{}", 1)?;
    match group_remove_unrouted_in(exec, db, &wa, "hold-2") {
        Err(SdkError::Storage(StorageError::AuthorizationRejected)) => {}
        other => panic!("WA must not delete holds, got {other:?}"),
    }
    assert_eq!(hooks::take_deletes().len(), 0);
    Ok(())
}

#[test]
fn all_receive_writers_guard() -> Result<(), SdkError> {
    assert_inventory_scan();
    assert_exclusive_and_managed_ack()?;
    let harness = open()?;
    assert_hooks(&LedgerExecutor::standalone(), &harness.db)
}
