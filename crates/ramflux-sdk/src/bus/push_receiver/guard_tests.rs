// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! P19 first-leg `all_receive_writers_guard`: inventory, exclusive bind, managed ACK
//! refusal, SQL/inbox/ACK/hold-delete hooks, held never acknowledged. P25 completes live wiring.
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use super::authority::LedgerAuthority;
use super::executor::authority::AuthorityKind;
use super::executor::{
    CoverOutcome, LedgerExecutor, bind_outcome_for_test, cover_outcome_for_test,
    group_remove_unrouted_in, message_receive_ack_in, reset_outcome_for_test,
    settle_outcome_for_test,
};
use super::hooks;
use super::inventory::{SCAN_SYMBOLS, SITES, WriterClass};
use super::managed_ack::{MANAGED_ACK_CODE, managed_public_ack};
use crate::bus::io::local_bus_error_code;
use crate::bus::protocol::{LocalBusFrame, LocalBusMessageAckRequest};
use crate::prelude::*;
use ramflux_storage::{
    AccountDb, AccountDbKey, AccountIndex, ReceiveBind, ReceiveCover, ReceiveCoverKind,
    ReceiveCoverResult, ReceiveExpectation, ReceiveReset, ReceiveResetReason, ReceiveResetResult,
    ReceiveSettle, ReceiveSettleKind, ReceiveSettleResult, ReceiveStage, ReceiveStageResult,
    StorageError,
};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

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
    let _ = db.activate_receive_ledger(ramflux_storage::ReceiveMigrate {
        target: "t",
        incarnation: "e",
    })?;
    Ok(Harness { _root: root, db })
}

fn open_legacy() -> Result<Harness, StorageError> {
    let root = tempfile::tempdir().expect("tmp");
    let index = AccountIndex::open(root.path())?;
    index.create_account("acct", "principal")?;
    let db =
        AccountDb::open(&index, "acct", &AccountDbKey::derive("acct", b"storage-test-secret"))?;
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

fn count_symbol(src: &str, symbol: &str, rel: &str) -> usize {
    let mut count = 0;
    let mut rest = src;
    while let Some(at) = rest.find(symbol) {
        let after = &rest[at + symbol.len()..];
        // Skip the account.rs wrapper name only when counting the shorter prefix.
        if symbol == "persist_receive_cursor"
            && after.starts_with("_if_inactive")
            && rel == "src/client/account.rs"
        {
            rest = after;
            continue;
        }
        count += 1;
        rest = after;
    }
    count
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
            let actual = count_symbol(&src, symbol, &rel);
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
    assert!(SCAN_SYMBOLS.contains(&"persist_receive_cursor"));
    assert!(SCAN_SYMBOLS.contains(&"persist_receive_cursor_if_inactive"));
    assert!(SITES.iter().any(|site| site.file == "src/client/account.rs"
        && site.symbol == "persist_receive_cursor_if_inactive"
        && site.class == WriterClass::ProductionLegacy
        && site.count == 1));
    assert!(SITES.iter().any(|site| site.file == "src/bus/push_receiver/executor.rs"
        && site.symbol == "persist_receive_cursor"
        && site.count == 1));
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
    assert!(SITES.iter().any(|site| site.file == "src/client/account.rs"
        && site.symbol == "persist_gateway_receive_cursor"
        && site.class == WriterClass::ProductionLegacy
        && site.executor.contains("persist_receive_checkpoint_in")
        && site.count == 1));
    assert!(
        !SITES
            .iter()
            .any(|site| site.file == "src/client/account.rs"
                && site.symbol == "persist_receive_cursor"),
        "account.rs persist_receive_cursor substring is not a separate site"
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
        inbox_seq: None,
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

fn assert_h1_ack_gate() -> Result<(), SdkError> {
    let managed = open()?;
    assert!(managed.db.receive_ledger_installed()?, "schema 15 must activate managed ACK");
    let legacy = open_legacy()?;
    assert!(
        !legacy.db.receive_ledger_installed()?,
        "production accounts without schema 15 keep legacy ACK"
    );
    let src = fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("src/bus/dispatch/message.rs"),
    )
    .expect("message.rs");
    assert!(src.contains("receive_ledger_installed"), "H1 ledger gate missing");
    assert!(src.contains("managed_public_ack"), "managed refusal missing");
    assert!(src.contains("ack_gateway_delivery"), "legacy ACK body missing");
    assert!(src.contains("mark_acked"), "legacy mark missing");
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

fn assert_constructor_grep() {
    let sdk_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    walk_rs(&sdk_root, &mut files);
    let allow = ["bus/push_receiver/executor.rs", "bus/push_receiver/executor/authority.rs"];
    let mut bad = Vec::new();
    for path in files {
        let rel =
            path.strip_prefix(&sdk_root).expect("src").display().to_string().replace('\\', "/");
        if skip_scan(&format!("src/{rel}")) {
            continue;
        }
        let src = fs::read_to_string(&path).expect("read rust");
        let allowed = allow.iter().any(|file| rel == *file);
        for name in ["w2", "reset", "wa", "ws", "erasure"] {
            let ctor = format!("LedgerAuthority::{name}(");
            if src.contains(&ctor) && !allowed {
                bad.push(format!("{rel} {ctor}"));
            }
        }
        for name in ["reset", "erasure"] {
            let banned = format!("observe_{name}_in");
            if src.contains(&banned) {
                bad.push(format!("{rel} {banned}"));
            }
        }
    }
    assert!(bad.is_empty(), "token constructors outside conversion: {bad:?}");
    assert_constructor_visibility();
}

fn assert_constructor_visibility() {
    let authority =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("src/bus/push_receiver/executor/authority.rs");
    let src = fs::read_to_string(&authority).expect("authority.rs");
    for name in ["w2", "reset", "wa", "ws", "erasure"] {
        let decl = format!("pub(super) const fn {name}(");
        assert!(src.contains(&decl), "authority constructor must be declared pub(super): {decl}");
        for wider in [format!("pub const fn {name}("), format!("pub(crate) const fn {name}(")] {
            assert!(!src.contains(&wider), "authority constructor widened: {wider}");
        }
    }
    assert_eq!(
        src.matches("pub(super) const fn").count(),
        5,
        "exactly the five authority constructors are pub(super)"
    );
}

fn assert_storage_result_tokens() {
    let paused =
        cover_outcome_for_test(7, ReceiveCoverKind::Terminal, ReceiveCoverResult::Paused, 0);
    assert!(paused.authority.is_none());
    assert!(!paused.ack_eligible);
    let held_cover =
        cover_outcome_for_test(7, ReceiveCoverKind::Held, ReceiveCoverResult::Covered, 0);
    assert_eq!(held_cover.authority.as_ref().map(LedgerAuthority::kind), Some(AuthorityKind::W2));
    assert!(!held_cover.ack_eligible);
    let paused_settle = settle_outcome_for_test(
        3,
        ReceiveSettleKind::Terminal,
        ReceiveSettleResult::Paused,
        false,
        0,
    );
    assert!(paused_settle.authority.is_none());
    assert!(!paused_settle.ack_eligible);
    let held_settle =
        settle_outcome_for_test(3, ReceiveSettleKind::Held, ReceiveSettleResult::Held, false, 0);
    assert!(held_settle.authority.is_none());
    assert!(!held_settle.ack_eligible);
    let held_wrote_c =
        settle_outcome_for_test(3, ReceiveSettleKind::Held, ReceiveSettleResult::Held, true, 0);
    assert!(held_wrote_c.authority.is_none(), "Held must not mint W2 even when C advanced");
    let paused_wrote_c = settle_outcome_for_test(
        3,
        ReceiveSettleKind::Terminal,
        ReceiveSettleResult::Paused,
        true,
        0,
    );
    assert!(paused_wrote_c.authority.is_none(), "Paused must not mint W2 even when C advanced");
    let covered_settle = settle_outcome_for_test(
        4,
        ReceiveSettleKind::Terminal,
        ReceiveSettleResult::Settled,
        true,
        0,
    );
    assert_eq!(
        covered_settle.authority.as_ref().map(LedgerAuthority::kind),
        Some(AuthorityKind::W2)
    );
    assert!(covered_settle.ack_eligible);
    let below_c = settle_outcome_for_test(
        4,
        ReceiveSettleKind::Terminal,
        ReceiveSettleResult::Settled,
        false,
        0,
    );
    assert_eq!(below_c.authority.as_ref().map(LedgerAuthority::kind), Some(AuthorityKind::Ws));
    let reset_ok = reset_outcome_for_test(9, ReceiveResetResult::Reset, 0);
    assert_eq!(reset_ok.authority.as_ref().map(LedgerAuthority::kind), Some(AuthorityKind::Reset));
    assert!(reset_outcome_for_test(9, ReceiveResetResult::PausedFence, 0).authority.is_none());
    assert!(reset_outcome_for_test(9, ReceiveResetResult::PausedLoss, 0).authority.is_none());
    let erased = bind_outcome_for_test(8, ReceiveBind::Erased, 0);
    assert_eq!(erased.authority.as_ref().map(LedgerAuthority::kind), Some(AuthorityKind::Erasure));
    assert!(bind_outcome_for_test(8, ReceiveBind::Bound, 0).authority.is_none());
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
    assert_eq!(w2.authority.as_ref().map(LedgerAuthority::kind), Some(AuthorityKind::W2));
    let sql = hooks::take_sql();
    assert_eq!(sql.len(), 1);
    assert_eq!(sql[0].kind, AuthorityKind::W2);
    let wa = exec.mint_wa(w2.authority, w2.ack_eligible, 1)?;
    message_receive_ack_in(exec, wa, 1)?;
    let cursor = exec.load_startup_cursor(db, "t")?.cursor;
    let acks = hooks::take_acks();
    assert!(!acks.is_empty(), "conversation ACK must produce a wire frame");
    for frame in &acks {
        assert_eq!(frame.kind, Some(AuthorityKind::Wa), "ACK outside WA: {frame:?}");
        assert!(frame.seq <= cursor, "ACK s>C: {frame:?}");
    }
    Ok(())
}

fn assert_held_never_acked_and_authorized_delete(
    exec: &LedgerExecutor,
    db: &AccountDb,
) -> Result<(), SdkError> {
    let held_synth =
        cover_outcome_for_test(2, ReceiveCoverKind::Held, ReceiveCoverResult::Covered, 0);
    match exec.mint_wa(held_synth.authority, held_synth.ack_eligible, 2) {
        Err(SdkError::Storage(StorageError::Integrity(
            "held sequence is not eligible for ACK",
        ))) => {}
        other => panic!("held must not mint WA, got {other:?}"),
    }
    assert_eq!(hooks::take_acks().len(), 0, "held never acknowledged");
    stage(db, 1, 2)?;
    db.hold_unrouted("hold-1", 2, b"{}", 1)?;
    db.receive_transaction(expected(db, 1)?, 1, |tx| {
        let held = exec
            .cover_in(
                tx,
                ReceiveCover {
                    sequence: 2,
                    kind: ReceiveCoverKind::Held,
                    gaps: &[],
                    retain_until: 0,
                },
            )
            .map_err(into_storage)?;
        assert!(!held.ack_eligible);
        let token = held.authority.expect("held cover that wrote C mints W2");
        group_remove_unrouted_in(exec, tx, token, "hold-1").map_err(into_storage)
    })?;
    assert_eq!(db.unrouted_count()?, 0, "authorized hold delete must remove the row");
    let deletes = hooks::take_deletes();
    assert!(
        deletes.iter().any(|row| {
            row.id == "hold-1" && row.kind.is_some_and(|kind| kind != AuthorityKind::Wa)
        }),
        "delete hook detects missing transaction authority: {deletes:?}"
    );
    db.hold_unrouted("hold-2", 2, b"{}", 1)?;
    let wa = exec.mint_wa(
        cover_outcome_for_test(1, ReceiveCoverKind::Terminal, ReceiveCoverResult::Covered, 0)
            .authority,
        true,
        1,
    )?;
    match db.receive_transaction(expected(db, 2)?, 1, |tx| {
        group_remove_unrouted_in(exec, tx, wa, "hold-2").map_err(into_storage)
    }) {
        Err(StorageError::AuthorizationRejected) => {}
        other => panic!("WA must not delete holds, got {other:?}"),
    }
    assert_eq!(hooks::take_deletes().len(), 0);
    Ok(())
}

fn assert_token_binding(exec: &LedgerExecutor, db: &AccountDb) -> Result<(), SdkError> {
    hooks::clear();
    let wa = exec.mint_wa(
        cover_outcome_for_test(1, ReceiveCoverKind::Terminal, ReceiveCoverResult::Covered, 0)
            .authority,
        true,
        1,
    )?;
    match db.receive_transaction(expected(db, 2)?, 1, |tx| {
        exec.persist_receive_checkpoint_in(tx, wa, 1).map_err(into_storage)
    }) {
        Err(StorageError::AuthorizationRejected) => {}
        other => panic!("WA must not write C, got {other:?}"),
    }
    assert_eq!(hooks::take_sql().len(), 0);
    db.receive_transaction(expected(db, 2)?, 1, |tx| {
        let token = cover_outcome_for_test(
            2,
            ReceiveCoverKind::Terminal,
            ReceiveCoverResult::Covered,
            tx.writer_id(),
        )
        .authority
        .expect("w2");
        match exec.persist_receive_checkpoint_in(tx, token, 2).map_err(into_storage) {
            Err(StorageError::AuthorizationRejected) => Ok(()),
            other => panic!("W2 must not write C through persist, got {other:?}"),
        }
    })?;
    db.receive_transaction(expected(db, 2)?, 1, |tx| {
        let token = cover_outcome_for_test(
            3,
            ReceiveCoverKind::Terminal,
            ReceiveCoverResult::Covered,
            tx.writer_id() ^ 1,
        )
        .authority
        .expect("w2");
        match exec.persist_receive_checkpoint_in(tx, token, 3).map_err(into_storage) {
            Err(StorageError::AuthorizationRejected) => Ok(()),
            other => panic!("expected writer bind, got {other:?}"),
        }
    })?;
    db.hold_unrouted("hold-bind", 2, b"{}", 1)?;
    db.receive_transaction(expected(db, 2)?, 1, |tx| {
        let token = cover_outcome_for_test(
            2,
            ReceiveCoverKind::Held,
            ReceiveCoverResult::Covered,
            tx.writer_id() ^ 1,
        )
        .authority
        .expect("w2");
        match exec.remove_unrouted_in(tx, token, "hold-bind").map_err(into_storage) {
            Err(StorageError::AuthorizationRejected) => Ok(()),
            other => panic!("expected writer bind on delete, got {other:?}"),
        }
    })?;
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
    assert_eq!(below.authority.as_ref().map(LedgerAuthority::kind), Some(AuthorityKind::Ws));
    assert!(below.ack_eligible);
    assert_eq!(hooks::take_sql().len(), 0, "below-C settle must not write C");
    stage(db, 3, 4)?;
    let advanced = settle(exec, db, 3, 4, ReceiveSettleKind::Terminal)?;
    assert_eq!(advanced.result, ReceiveSettleResult::Settled);
    assert_eq!(advanced.authority.as_ref().map(LedgerAuthority::kind), Some(AuthorityKind::W2));
    assert!(advanced.ack_eligible);
    let sql = hooks::take_sql();
    assert_eq!(sql.len(), 1);
    assert_eq!(sql[0].kind, AuthorityKind::W2);
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

/// Positive paths through real storage. W2 mints from `cover_in`, which already writes C in the
/// same transaction, so a later W2 persist at that sequence must refuse (exact-C rule). The
/// positive persist write is exercised through a Reset token from the real `reset_in`.
#[test]
fn real_storage_positive_paths() -> Result<(), SdkError> {
    let h = open()?;
    let exec = LedgerExecutor::bind_standalone("acct-p19-real")?;
    hooks::clear();
    stage(&h.db, 0, 1)?;
    let first = cover(&exec, &h.db, 0, 1, ReceiveCoverKind::Terminal)?;
    assert_eq!(first.authority.as_ref().map(LedgerAuthority::kind), Some(AuthorityKind::W2));
    assert_eq!(exec.load_startup_cursor(&h.db, "t")?.cursor, 1, "cover wrote C=1");
    hooks::clear();

    stage(&h.db, 1, 2)?;
    h.db.receive_transaction(expected(&h.db, 1)?, 1, |tx| {
        let minted = exec
            .cover_in(
                tx,
                ReceiveCover {
                    sequence: 2,
                    kind: ReceiveCoverKind::Terminal,
                    gaps: &[],
                    retain_until: 0,
                },
            )
            .map_err(into_storage)?;
        let token = minted.authority.expect("covered W2 mints a token");
        assert_eq!(tx.receive_cursor()?, 2);
        match exec.persist_receive_checkpoint_in(tx, token, 2).map_err(into_storage) {
            Err(StorageError::AuthorizationRejected) => Ok(()),
            other => panic!("storage already wrote C=2; W2 persist must refuse, got {other:?}"),
        }
    })?;
    assert_eq!(exec.load_startup_cursor(&h.db, "t")?.cursor, 2, "exact C after cover");
    let sql = hooks::take_sql();
    assert_eq!(sql.len(), 1, "only the cover hook fired: {sql:?}");
    assert_eq!((sql[0].seq, sql[0].kind), (2, AuthorityKind::W2));

    hooks::clear();
    h.db.receive_transaction(expected(&h.db, 2)?, 1, |tx| {
        let reset = exec
            .reset_in(
                tx,
                ReceiveReset {
                    new_incarnation: "e2",
                    settled: 2,
                    issued: 2,
                    after: 0,
                    reason: ReceiveResetReason::RouterReset,
                },
            )
            .map_err(into_storage)?;
        assert_eq!(reset.result, ReceiveResetResult::Reset);
        let token = reset.authority.expect("real reset mints a Reset token");
        exec.persist_receive_checkpoint_in(tx, token, 2).map_err(into_storage)
    })?;
    assert_eq!(exec.load_startup_cursor(&h.db, "t")?.incarnation, "e2", "reset committed E");
    assert_eq!(exec.load_startup_cursor(&h.db, "t")?.cursor, 2, "reset kept C=S");
    let sql = hooks::take_sql();
    assert_eq!(sql.len(), 1, "persist hook fired once: {sql:?}");
    assert_eq!((sql[0].seq, sql[0].kind), (2, AuthorityKind::Reset));

    // Real bind: message already deleted, so the staged work is erased and an Erasure token
    // deletes the joined hold row.
    let e = open()?;
    stage(&e.db, 0, 1)?;
    e.db.send_direct_message("thread", "A", "peer", b"secret")?;
    e.db.delete_direct_message("thread", "A", "local", "delete-a")?;
    e.db.hold_unrouted("hold-erase", 1, b"{}", 1)?;
    hooks::clear();
    e.db.receive_transaction(expected(&e.db, 0)?, 1, |tx| {
        let bound = exec.bind_logical_in(tx, 1, "A").map_err(into_storage)?;
        assert_eq!(bound.result, ReceiveBind::Erased);
        let token = bound.authority.expect("erased bind mints an Erasure token");
        exec.remove_unrouted_in(tx, token, "hold-erase").map_err(into_storage)
    })?;
    assert_eq!(e.db.unrouted_count()?, 0, "erasure token deleted the hold row");
    let deletes = hooks::take_deletes();
    assert!(
        deletes
            .iter()
            .any(|row| row.id == "hold-erase" && row.kind == Some(AuthorityKind::Erasure)),
        "delete hook records Erasure: {deletes:?}"
    );
    Ok(())
}

/// L1: the managed `message.ack` branch, dispatched for an account whose schema 15 is installed.
/// Asserts the refusal code (no legacy engine call is reachable on this branch).
#[tokio::test(flavor = "current_thread")]
async fn managed_message_ack_refuses_at_dispatch_with_schema_15() -> Result<(), SdkError> {
    let root = crate::bus::runtime_tests::root("p19-r4-managed-ack");
    let id = "acct-p19-ack";
    let account =
        crate::bus::runtime_tests::account(&root, id, None, Arc::new(AtomicBool::new(false)))?;
    {
        let db = account.client.account_db()?;
        assert!(!db.receive_ledger_installed()?, "fixture starts without schema 15");
        db.install_receive_ledger_schema()?;
        assert!(db.receive_ledger_installed()?, "schema 15 installed");
    }
    let mut state = LocalBusDaemonState {
        account_index: None,
        nodes: crate::node::NodeStore::load(&root, &[])?,
        config: LocalBusConfig::new(root.join("bus.sock"), &root),
        accounts: BTreeMap::new(),
        active_account_id: None,
        attended_accounts: BTreeSet::new(),
        subscribers: BTreeMap::new(),
    };
    state.accounts.insert(id.to_owned(), account);
    let (outbound, _) = mpsc::channel(1);
    let connection = LocalBusConnectionState::new(1, outbound);
    let request = LocalBusFrame::request(
        "ack",
        Some(id.to_owned()),
        "test",
        "message.ack",
        serde_json::json!({
            "envelope_id": "env-1",
            "receiver_device_id": "device-acct-p19-ack",
            "received_at": 42,
        }),
    );
    let result =
        crate::bus::dispatch::dispatch_message_bus_request(&request, &mut state, &connection).await;
    let outcome = match result {
        Err(SdkError::InboundRejected(ref code)) if code == MANAGED_ACK_CODE => Ok(()),
        Err(other) => {
            Err(format!("managed ACK must refuse with {MANAGED_ACK_CODE}, got {other:?}"))
        }
        Ok(_) => Err("managed ACK must not succeed".to_owned()),
    };
    drop(state);
    let _ = std::fs::remove_dir_all(&root);
    outcome.map_err(SdkError::LocalBus)
}

#[tokio::test(flavor = "current_thread")]
async fn all_receive_writers_guard() -> Result<(), SdkError> {
    assert_inventory_scan();
    assert_constructor_grep();
    assert_exclusive_and_managed_ack()?;
    assert_h1_ack_gate()?;
    assert_exclusive_across_threads()?;
    assert_storage_result_tokens();
    let harness = open()?;
    let exec = LedgerExecutor::bind_standalone("acct-p19-hooks")?;
    assert_hooks(&exec, &harness.db)?;
    assert_held_never_acked_and_authorized_delete(&exec, &harness.db)?;
    assert_token_binding(&exec, &harness.db)?;
    assert_settle_outcomes(&exec, &harness.db)?;
    Box::pin(crate::bus::runtime_tests::assert_activated_group_unrouted_replay_refused()).await
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
