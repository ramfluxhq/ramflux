// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! `erased_input_restore_union` lifecycle cells: merge-triggered capture of local tuple sources.
//! The exact selector must exist after the merge and after reopen even though the merge deletes
//! the only local source (cell viii is the absence oracle).
#![allow(clippy::expect_used, clippy::panic, clippy::too_many_lines)]
use super::erased_capture_tests::{current, full};
use super::erased_input_union_tests::{Pair, assert_refused, expiry, merge, pair};
use super::stage_tests::{bytes, input, run};
use crate::{AccountDb, BackupDatabase, StorageError};
use rusqlite::params;
use serde_json::{Value, json};

/// A local tuple the merge must leave a tombstone for (or must not).
struct Expect {
    selector: String,
    expires_at: i64,
}

fn both_have_message(p: &Pair) -> Result<(), StorageError> {
    p.local.send_direct_message("thread", "M", "peer", b"x")?;
    p.source.send_direct_message("thread", "M", "peer", b"x")?;
    Ok(())
}

fn work(sequence: u64, payload: &str, principal: &str, device: &str, now: i64) -> Vec<u8> {
    let mut v: Value = serde_json::from_slice(&bytes(sequence)).expect("entry fixture");
    v["envelope"]["payload_hash"] = json!(payload);
    v["envelope"]["source_principal_id"] = json!(principal);
    v["envelope"]["source_device_id"] = json!(device);
    v["envelope"]["created_at"] = json!(now);
    v["envelope"]["ttl"] = json!(3600);
    serde_json::to_vec(&v).expect("entry encoding")
}

fn ledger(db: &AccountDb) -> Result<(), StorageError> {
    db.install_receive_ledger_schema()?;
    db.connection.execute(
        "INSERT INTO gateway_receive_epoch VALUES('t','e',1,x'',?1,?1)",
        params![0u64.to_be_bytes().as_slice()],
    )?;
    Ok(())
}

/// Local binding (i) for a fresh tuple.
fn seed_binding(p: &Pair, payload: &str, now: i64) -> Result<Expect, StorageError> {
    let (bundle, selector) = current(&p.local, "lp", "ld", payload)?;
    let expires_at = now + 600;
    p.local.connection.execute(
        "INSERT INTO message_copy_binding VALUES(?1,'M')",
        params![format!("erased-input:{bundle}:{selector}:{expires_at}")],
    )?;
    Ok(Expect { selector, expires_at })
}

/// Local `routed/committed` copy (source ii) bound to M through its payload.
fn seed_routed(p: &Pair, payload: &str, now: i64) -> Result<Expect, StorageError> {
    p.local.connection.execute(
        "INSERT INTO message_copy_binding VALUES(?1,'M')",
        params![format!("payload:{payload}")],
    )?;
    p.local.persist_actor_state(
        &format!("routed/committed/{payload}"),
        &json!({"routing":{"message_id":"M"},"entry":{"envelope":full("rp","rd",payload,now,3600)}}),
    )?;
    let (_, selector) = current(&p.local, "rp", "rd", payload)?;
    Ok(Expect { selector, expires_at: now + 3_900 })
}

/// Live staged work (source iii) owned through its payload binding.
fn seed_work(p: &Pair, payload: &str, now: i64) -> Result<Expect, StorageError> {
    ledger(&p.local)?;
    let wire = work(1, payload, "wp", "wd", now);
    assert_eq!(run(&p.local, input(&wire, 1))?, super::stage::ReceiveStageResult::Staged);
    p.local.connection.execute(
        "INSERT INTO message_copy_binding VALUES(?1,'M')",
        params![format!("payload:{payload}")],
    )?;
    let (_, selector) = current(&p.local, "wp", "wd", payload)?;
    Ok(Expect { selector, expires_at: now + 3_900 })
}

fn delete_incoming(p: &Pair) -> Result<(), StorageError> {
    p.source.delete_direct_message("thread", "M", "local", "delete-m")?;
    Ok(())
}

fn deleted(db: &rusqlite::Connection) -> rusqlite::Result<bool> {
    db.query_row("SELECT deleted FROM direct_message_projection WHERE message_id='M'", [], |r| {
        r.get(0)
    })
}

/// Candidate-mode merge: the same pipeline as `merge`, through `merge_backup_candidate`.
fn merge_candidate(
    p: &Pair,
) -> Result<(BackupDatabase, std::path::PathBuf, crate::AccountDbKey), StorageError> {
    let incoming = p.root.join("incoming.db");
    let snapshot = p.source.write_backup_snapshot(&incoming)?;
    let path = p.root.join("merged.db");
    let target = p.local.write_backup_snapshot(&path)?;
    let mut merged = BackupDatabase::open(&path, &target.key)?;
    merged.merge_backup_candidate(&incoming, &snapshot.key, || Ok(()))?;
    Ok((merged, path, target.key))
}

/// Merges, then checks the tombstones (or their absence) immediately and after reopen.
fn check(
    p: &Pair,
    expected: &[Expect],
    present: bool,
    message_deleted: bool,
) -> Result<(), StorageError> {
    check_with(p, expected, present, message_deleted, merge)
}

type Merged = Result<(BackupDatabase, std::path::PathBuf, crate::AccountDbKey), StorageError>;

fn check_with(
    p: &Pair,
    expected: &[Expect],
    present: bool,
    message_deleted: bool,
    run: impl FnOnce(&Pair) -> Merged,
) -> Result<(), StorageError> {
    let (merged, path, key) = run(p)?;
    assert_eq!(deleted(&merged.db)?, message_deleted, "message end state");
    let verify = |db: &rusqlite::Connection| -> Result<(), StorageError> {
        for e in expected {
            let want = present.then_some(e.expires_at);
            assert_eq!(expiry(db, &e.selector)?, want, "selector {}", e.selector);
        }
        Ok(())
    };
    verify(&merged.db)?;
    drop(merged);
    let reopened = BackupDatabase::open(&path, &key)?;
    verify(&reopened.db)?;
    drop(reopened);
    Ok(())
}

#[test]
fn erased_input_restore_union_lifecycle_local_sources() -> Result<(), StorageError> {
    let now = crate::unix_now();
    // (ii) A routed/committed copy is the only local source; the merge deletes it.
    let p = pair("erased-life-ii")?;
    both_have_message(&p)?;
    let ii = seed_routed(&p, "pii", now)?;
    delete_incoming(&p)?;
    check(&p, &[ii], true, true)?;
    // (iv-a) Local live with live staged work, incoming deleted: the local tuple is captured.
    let p = pair("erased-life-iva")?;
    both_have_message(&p)?;
    let iva = seed_work(&p, "piva", now)?;
    delete_incoming(&p)?;
    check(&p, &[iva], true, true)?;
    // (vi) A local-only binding on an ordinary M replaced by an incoming deleted row.
    let p = pair("erased-life-vi")?;
    both_have_message(&p)?;
    let vi = seed_binding(&p, "pvi", now)?;
    delete_incoming(&p)?;
    check(&p, &[vi], true, true)?;
    // (vii) As (vi), plus an incoming copy that re-fires M's erasure mid-loop.
    let p = pair("erased-life-vii")?;
    both_have_message(&p)?;
    let vii = seed_binding(&p, "pvii", now)?;
    p.source
        .connection
        .execute("INSERT INTO message_copy_binding VALUES('payload:pvii-copy','M')", [])?;
    p.source.persist_actor_state(
        "routed/committed/pvii-copy",
        &json!({"routing":{"message_id":"M"},"entry":{"envelope":full("rp","rd","pvii-copy",now,3600)}}),
    )?;
    delete_incoming(&p)?;
    check(&p, &[vii], true, true)?;
    // (viii) Over-capture is discarded: M ends the merge live, so no row exists for its tuples.
    let p = pair("erased-life-viii")?;
    both_have_message(&p)?;
    let viii = seed_binding(&p, "pviii", now)?;
    check(&p, &[viii], false, false)?;
    Ok(())
}

#[test]
fn erased_input_restore_union_lifecycle_candidate_preservation() -> Result<(), StorageError> {
    let now = crate::unix_now();
    // (ix) Candidate mode: preservation deletes the only local source (the routed copy) before
    // the late capture point, so only capture before `prepare` records the selector.
    let p = pair("erased-life-ix")?;
    both_have_message(&p)?;
    let ix = seed_routed(&p, "pix", now)?;
    p.local.connection.execute(
        "INSERT INTO object_payload_actor VALUES('commitment-ix','routed/committed/pix')",
        [],
    )?;
    p.local.connection.execute("INSERT INTO object_erasure_fence VALUES('commitment-ix')", [])?;
    delete_incoming(&p)?;
    check_with(&p, &[ix], true, true, merge_candidate)?;
    Ok(())
}

/// Incoming binding (i) on a source message, selector derived with the source's own bundle.
fn source_binding(p: &Pair, payload: &str, expires_at: i64) -> Result<Expect, StorageError> {
    let (bundle, selector) = current(&p.source, "sp", "sd", payload)?;
    p.source.connection.execute(
        "INSERT INTO message_copy_binding VALUES(?1,'M')",
        params![format!("erased-input:{bundle}:{selector}:{expires_at}")],
    )?;
    Ok(Expect { selector, expires_at })
}

/// Local deletion of M with nothing to capture: M is deleted and has no tuple source.
fn delete_local(p: &Pair) -> Result<(), StorageError> {
    p.local.delete_direct_message("thread", "M", "local", "delete-local")?;
    Ok(())
}

#[test]
fn erased_input_restore_union_lifecycle_incoming_sources() -> Result<(), StorageError> {
    let now = crate::unix_now();
    // (iii) Incoming live with a binding, local deleted: the binding converts to a tombstone.
    let p = pair("erased-life-iii")?;
    both_have_message(&p)?;
    delete_local(&p)?;
    let iii = source_binding(&p, "piii", now + 600)?;
    check(&p, &[iii], true, true)?;
    // (iv-b) The same direction with two incoming variants of one tuple: the maximum wins.
    let p = pair("erased-life-ivb")?;
    both_have_message(&p)?;
    delete_local(&p)?;
    let (bundle, selector) = current(&p.source, "sp", "sd", "pivb")?;
    for at in [now + 300, now + 900] {
        p.source.connection.execute(
            "INSERT INTO message_copy_binding VALUES(?1,'M')",
            params![format!("erased-input:{bundle}:{selector}:{at}")],
        )?;
    }
    check(&p, &[Expect { selector, expires_at: now + 900 }], true, true)?;
    // (x) Incoming-only legacy source: the only tuple is a routed/committed copy on the
    // incoming side. Selectors use the local bundle.
    let p = pair("erased-life-x")?;
    both_have_message(&p)?;
    delete_local(&p)?;
    p.source.connection.execute("INSERT INTO message_copy_binding VALUES('payload:px','M')", [])?;
    p.source.persist_actor_state(
        "routed/committed/px",
        &json!({"routing":{"message_id":"M"},"entry":{"envelope":full("xp","xd","px",now,3600)}}),
    )?;
    let (_, selector) = current(&p.local, "xp", "xd", "px")?;
    check(&p, &[Expect { selector, expires_at: now + 3_900 }], true, true)?;
    Ok(())
}

#[test]
fn erased_input_restore_union_lifecycle_imported_binding_then_local_delete()
-> Result<(), StorageError> {
    let now = crate::unix_now();
    // (i) A live M with binding (i) is imported; deleting it afterwards leaves the tombstone.
    let p = pair("erased-life-i")?;
    p.source.send_direct_message("thread", "M", "peer", b"x")?;
    let i = source_binding(&p, "pi", now + 600)?;
    let (merged, path, key) = merge(&p)?;
    assert!(!deleted(&merged.db)?);
    assert_eq!(expiry(&merged.db, &i.selector)?, None, "a live target only keeps the binding");
    let binding: String = merged.db.query_row(
        "SELECT copy_id FROM message_copy_binding WHERE message_id='M' AND copy_id GLOB 'erased-input:*'",
        [],
        |r| r.get(0),
    )?;
    assert!(binding.ends_with(&format!(":{}", i.expires_at)), "{binding}");
    drop(merged);
    let installed = p.root.join("installed");
    let index = crate::AccountIndex::open(&installed)?;
    let account = index.create_account("account", "root")?;
    let target = installed.join(account.db_relative_path);
    std::fs::create_dir_all(target.parent().ok_or(StorageError::AuthorizationRejected)?)?;
    BackupDatabase::open(&path, &key)?.copy_to(&target, &key)?;
    let restored = AccountDb::open(&index, "account", &key)?;
    restored.delete_direct_message("thread", "M", "local", "delete-after-restore")?;
    assert_eq!(
        restored.connection.query_row(
            "SELECT expires_at FROM receive_erased_input WHERE selector=?1",
            params![i.selector],
            |r| r.get::<_, i64>(0),
        )?,
        i.expires_at
    );
    drop(restored);
    let again = AccountDb::open(&index, "account", &key)?;
    assert_eq!(
        again.connection.query_row(
            "SELECT expires_at FROM receive_erased_input WHERE selector=?1",
            params![i.selector],
            |r| r.get::<_, i64>(0),
        )?,
        i.expires_at,
        "after reopen"
    );
    Ok(())
}

#[test]
fn erased_input_restore_union_lifecycle_refuses_bad_incoming_bindings() -> Result<(), StorageError>
{
    let now = crate::unix_now();
    // (v) A malformed binding refuses the merge at staging, with zero changes.
    let p = pair("erased-life-v-malformed")?;
    p.source.send_direct_message("thread", "M", "peer", b"x")?;
    p.source.connection.execute(
        "INSERT INTO message_copy_binding VALUES('erased-input:not-base64:also-bad:123','M')",
        [],
    )?;
    assert_refused(&p, "malformed erased-input binding")?;
    // (v) A well-formed binding whose bundle the merged set does not know refuses at reconcile.
    let p = pair("erased-life-v-unknown")?;
    p.source.send_direct_message("thread", "M", "peer", b"x")?;
    let (_, selector) = current(&p.source, "sp", "sd", "pv")?;
    let foreign = ramflux_protocol::encode_base64url([9_u8; 32]);
    p.source.connection.execute(
        "INSERT INTO message_copy_binding VALUES(?1,'M')",
        params![format!("erased-input:{foreign}:{selector}:{}", now + 600)],
    )?;
    assert_refused(&p, "erased-input bundle unknown to the merged set")?;
    Ok(())
}
