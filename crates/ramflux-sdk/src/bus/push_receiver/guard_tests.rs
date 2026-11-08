// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! P19 first-leg `all_receive_writers_guard`: inventory, exclusive bind, managed ACK
//! refusal, SQL/inbox/ACK/hold-delete hooks, held never acknowledged. P25 completes live wiring.
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use super::authority::LedgerAuthority;
use super::executor::authority::AuthorityKind;
use super::executor::{
    CoverOutcome, LedgerExecutor, cover_outcome_for_test, group_remove_unrouted_in,
    message_receive_ack_in, settle_outcome_for_test,
};
use super::hooks;
use super::inventory::{SCAN_SYMBOLS, SITES, WriterClass};
use super::managed_ack::{MANAGED_ACK_CODE, managed_public_ack};
use crate::bus::io::local_bus_error_code;
use crate::bus::protocol::LocalBusMessageAckRequest;
use crate::prelude::*;
use ramflux_storage::{
    AccountDb, AccountDbKey, AccountIndex, ReceiveCover, ReceiveCoverKind, ReceiveCoverResult,
    ReceiveExpectation, ReceiveSettle, ReceiveSettleKind, ReceiveSettleResult, ReceiveStage,
    ReceiveStageResult, StorageError,
};
use std::collections::HashMap;
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

fn skip_scan(rel: &str) -> bool {
    rel.contains("/tests/")
        || rel.contains("_tests/")
        || rel.ends_with("_tests.rs")
        || rel.ends_with("inventory.rs")
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

fn rel_under(path: &Path, root: &Path, prefix: &str) -> String {
    format!("{prefix}{}", path.strip_prefix(root).expect("src").display()).replace('\\', "/")
}

fn expected_counts() -> HashMap<String, usize> {
    let mut counts = HashMap::new();
    for site in SITES {
        *counts.entry(format!("{}::{}", site.file, site.symbol)).or_insert(0) += site.count;
    }
    counts
}

fn scan_tree(
    root: &Path,
    prefix: &str,
    expected: &HashMap<String, usize>,
    missing: &mut Vec<String>,
) {
    if !root.is_dir() {
        missing.push(format!("missing scan root {}", root.display()));
        return;
    }
    let mut files = Vec::new();
    walk_rs(root, &mut files);
    for path in files {
        let rel = rel_under(&path, root, prefix);
        if skip_scan(&rel) {
            continue;
        }
        let src = fs::read_to_string(&path).expect("read rust");
        for symbol in SCAN_SYMBOLS {
            let actual = src.matches(symbol).count();
            if actual == 0 {
                continue;
            }
            let want = expected.get(&format!("{rel}::{symbol}")).copied().unwrap_or(0);
            if want != actual {
                missing.push(format!("{rel} {symbol} actual={actual} expected={want}"));
            }
        }
    }
}

fn assert_inventory_scan() {
    let sdk_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let rf_root = workspace.join("apps/rf/src");
    for site in SITES {
        let path = if site.file.starts_with("apps/") {
            workspace.join(site.file)
        } else {
            Path::new(env!("CARGO_MANIFEST_DIR")).join(site.file)
        };
        assert!(path.is_file(), "inventory names missing file {}", site.file);
    }
    let expected = expected_counts();
    let mut missing = Vec::new();
    scan_tree(&sdk_root, "src/", &expected, &mut missing);
    scan_tree(&rf_root, "apps/rf/src/", &expected, &mut missing);
    assert!(missing.is_empty(), "unclassified production receive writers: {missing:?}");
    assert!(SITES.iter().any(|site| site.file == "src/bus/dispatch/message.rs"
        && site.symbol == "message.ack"
        && site.executor.contains("managed_public_ack")));
    assert!(
        SITES
            .iter()
            .any(|site| site.file == "src/bus/dispatch/message.rs"
                && site.symbol == "message.receive")
    );
    assert!(SITES.iter().any(|site| site.file == "src/client/a2i.rs" && site.count >= 1));
    assert!(
        SITES.iter().any(|site| site.file == "src/client/account.rs"
            && site.symbol == "set_projection_checkpoint")
    );
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

fn settle(
    exec: &LedgerExecutor,
    db: &AccountDb,
    cursor: u64,
    sequence: u64,
    kind: ReceiveSettleKind,
) -> Result<super::executor::SettleOutcome, SdkError> {
    db.receive_transaction(expected(db, cursor)?, 1, |tx| {
        exec.settle_in(tx, ReceiveSettle { sequence, kind }).map_err(into_storage)
    })
    .map_err(SdkError::from)
}

fn assert_exclusive_and_managed_ack() -> Result<(), SdkError> {
    let actor = LedgerExecutor::bind_actor("acct-p19-actor")?;
    let standalone = LedgerExecutor::bind_standalone("acct-p19-actor");
    match standalone {
        Err(SdkError::Storage(StorageError::AccountWriterBusy(id))) if id == "acct-p19-actor" => {}
        other => panic!("expected AccountWriterBusy, got {other:?}"),
    }
    let other = LedgerExecutor::bind_standalone("acct-p19-other")?;
    assert_ne!(actor.account(), other.account());
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

fn assert_exclusive_across_threads() -> Result<(), SdkError> {
    let actor = LedgerExecutor::bind_actor("acct-p19-threads")?;
    let busy = std::thread::spawn(|| LedgerExecutor::bind_standalone("acct-p19-threads"))
        .join()
        .expect("join");
    match busy {
        Err(SdkError::Storage(StorageError::AccountWriterBusy(id))) if id == "acct-p19-threads" => {
        }
        other => panic!("expected AccountWriterBusy across threads, got {other:?}"),
    }
    drop(actor);
    let _freed = LedgerExecutor::bind_standalone("acct-p19-threads")?;
    Ok(())
}

fn assert_storage_result_tokens() {
    let paused = cover_outcome_for_test(7, ReceiveCoverKind::Terminal, ReceiveCoverResult::Paused);
    assert!(paused.authority.is_none());
    assert!(!paused.ack_eligible);
    let held_cover = cover_outcome_for_test(7, ReceiveCoverKind::Held, ReceiveCoverResult::Covered);
    assert_eq!(held_cover.authority.map(LedgerAuthority::kind), Some(AuthorityKind::W2));
    assert!(!held_cover.ack_eligible);
    let paused_settle =
        settle_outcome_for_test(3, ReceiveSettleKind::Terminal, ReceiveSettleResult::Paused, false);
    assert!(paused_settle.authority.is_none());
    assert!(!paused_settle.ack_eligible);
    let held_settle =
        settle_outcome_for_test(3, ReceiveSettleKind::Held, ReceiveSettleResult::Held, false);
    assert!(held_settle.authority.is_none());
    assert!(!held_settle.ack_eligible);
    let covered_settle =
        settle_outcome_for_test(4, ReceiveSettleKind::Terminal, ReceiveSettleResult::Settled, true);
    assert_eq!(covered_settle.authority.map(LedgerAuthority::kind), Some(AuthorityKind::W2));
    assert!(covered_settle.ack_eligible);
}

fn assert_hooks(exec: &LedgerExecutor, db: &AccountDb) -> Result<(), SdkError> {
    hooks::clear();
    exec.request_inbox_in(0, 64);
    let inbox = hooks::take_inbox();
    assert_eq!(inbox.len(), 1);
    assert_eq!(inbox[0].after, 0);
    let startup = exec.load_startup_cursor(db, "t")?;
    assert_eq!(startup.incarnation, "e");
    assert_eq!(startup.cursor, 0);
    assert_eq!(hooks::take_sql().len(), 0, "startup C is read-only");
    stage(db, 0, 1)?;
    let w2 = cover(exec, db, 0, 1, ReceiveCoverKind::Terminal)?;
    assert_eq!(w2.result, ReceiveCoverResult::Covered);
    assert!(w2.ack_eligible);
    assert_eq!(w2.authority.map(LedgerAuthority::kind), Some(AuthorityKind::W2));
    let sql = hooks::take_sql();
    assert_eq!(sql.len(), 1);
    assert_eq!(sql[0].token.kind(), AuthorityKind::W2);
    let wa = exec.mint_wa(w2.authority, w2.ack_eligible, 1)?;
    message_receive_ack_in(exec, &wa, 1)?;
    let cursor = exec.load_startup_cursor(db, "t")?.cursor;
    let acks = hooks::take_acks();
    assert!(!acks.is_empty(), "conversation ACK must produce a wire frame");
    for frame in &acks {
        assert!(frame.token.is_some_and(LedgerAuthority::is_wa), "ACK outside WA: {frame:?}");
        assert!(frame.seq <= cursor, "ACK s>C: {frame:?}");
    }
    match db.receive_transaction(expected(db, 1)?, 1, |tx| {
        exec.persist_receive_checkpoint_in(tx, &wa, 1).map_err(into_storage)
    }) {
        Err(StorageError::AuthorizationRejected) => {}
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
    let held_token = held.authority.expect("held cover that wrote C mints W2");
    db.hold_unrouted("hold-1", 2, b"{}", 1)?;
    group_remove_unrouted_in(exec, db, &held_token, "hold-1")?;
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

fn assert_settle_outcomes(exec: &LedgerExecutor, db: &AccountDb) -> Result<(), SdkError> {
    hooks::clear();
    stage(db, 2, 3)?;
    let held = cover(exec, db, 2, 3, ReceiveCoverKind::Held)?;
    assert_eq!(held.result, ReceiveCoverResult::Covered);
    hooks::clear();
    let below = settle(exec, db, 3, 3, ReceiveSettleKind::Terminal)?;
    assert_eq!(below.result, ReceiveSettleResult::Settled);
    assert_eq!(below.authority.map(LedgerAuthority::kind), Some(AuthorityKind::Ws));
    assert!(below.ack_eligible);
    assert_eq!(hooks::take_sql().len(), 0, "below-C settle must not write C");
    stage(db, 3, 4)?;
    let advanced = settle(exec, db, 3, 4, ReceiveSettleKind::Terminal)?;
    assert_eq!(advanced.result, ReceiveSettleResult::Settled);
    assert_eq!(advanced.authority.map(LedgerAuthority::kind), Some(AuthorityKind::W2));
    assert!(advanced.ack_eligible);
    let sql = hooks::take_sql();
    assert_eq!(sql.len(), 1);
    assert_eq!(sql[0].token.kind(), AuthorityKind::W2);
    stage(db, 4, 5)?;
    let kept = cover(exec, db, 4, 5, ReceiveCoverKind::Held)?;
    assert!(!kept.ack_eligible);
    hooks::clear();
    let held_settle = settle(exec, db, 5, 5, ReceiveSettleKind::Held)?;
    assert_eq!(held_settle.result, ReceiveSettleResult::Held);
    assert!(held_settle.authority.is_none());
    assert!(!held_settle.ack_eligible);
    match exec.mint_wa(held_settle.authority, held_settle.ack_eligible, 5) {
        Err(SdkError::Storage(StorageError::Integrity("storage result minted no ACK token"))) => {}
        other => panic!("held settle must not mint WA, got {other:?}"),
    }
    assert_eq!(hooks::take_acks().len(), 0);
    Ok(())
}

#[test]
fn all_receive_writers_guard() -> Result<(), SdkError> {
    assert_inventory_scan();
    assert_exclusive_and_managed_ack()?;
    assert_exclusive_across_threads()?;
    assert_storage_result_tokens();
    let harness = open()?;
    let exec = LedgerExecutor::bind_standalone("acct-p19-hooks")?;
    assert_hooks(&exec, &harness.db)?;
    assert_settle_outcomes(&exec, &harness.db)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn exclusive_bind_is_process_wide() -> Result<(), SdkError> {
    let actor = LedgerExecutor::bind_actor("acct-p19-tokio")?;
    let join = tokio::task::spawn_blocking(|| LedgerExecutor::bind_actor("acct-p19-tokio"))
        .await
        .expect("join");
    match join {
        Err(SdkError::Storage(StorageError::AccountWriterBusy(id))) if id == "acct-p19-tokio" => {}
        other => panic!("expected AccountWriterBusy, got {other:?}"),
    }
    drop(actor);
    let _ = LedgerExecutor::bind_standalone("acct-p19-tokio")?;
    Ok(())
}
