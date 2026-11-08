// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Capture helpers, run against an attached `incoming` fixture schema.
#![allow(clippy::expect_used, clippy::panic, clippy::too_many_lines)]
use super::erased_capture::{
    NON_SOURCE_KINDS, SOURCE_KINDS, Side, capture_for, reconcile_merge_capture,
    stage_merge_capture, sweep_open,
};
use super::erased_input::ErasedTuple;
use crate::{AccountDb, StorageError};
use rusqlite::{Connection, params};
use serde_json::{Value, json};

const LABEL: &[u8] = b"ramflux/deleted-envelope/v1";

fn on<T: Send + 'static>(
    db: &AccountDb,
    f: impl FnOnce(&Connection) -> Result<T, StorageError> + Send + 'static,
) -> Result<T, StorageError> {
    db.connection.call(move |raw| Ok(f(raw)))?
}

/// Attaches an empty `incoming` schema shaped like the tables the helpers read.
fn attach(db: &AccountDb) -> Result<(), StorageError> {
    on(db, |raw| {
        raw.execute_batch(
            "ATTACH ':memory:' AS incoming;
             CREATE TABLE IF NOT EXISTS main.backup_archived_actor_state(source TEXT,state_kind TEXT,state_json BLOB);
             CREATE TABLE incoming.direct_message_projection AS SELECT * FROM main.direct_message_projection WHERE 0;
             CREATE TABLE incoming.message_copy_binding AS SELECT * FROM main.message_copy_binding WHERE 0;
             CREATE TABLE incoming.message_footprint AS SELECT * FROM main.message_footprint WHERE 0;
             CREATE TABLE incoming.runtime_actor_state AS SELECT * FROM main.runtime_actor_state WHERE 0;
             CREATE TABLE incoming.backup_archived_actor_state AS SELECT * FROM main.backup_archived_actor_state WHERE 0;",
        )?;
        Ok(())
    })
}

fn message(
    db: &AccountDb,
    schema: &'static str,
    id: &'static str,
    deleted: bool,
) -> Result<(), StorageError> {
    on(db, move |raw| {
        raw.execute(
            &format!("INSERT INTO {schema}.direct_message_projection(conversation_id,message_id,sender_id,encrypted_body,metadata_json,deleted,created_at) VALUES('c',?1,'s',x'',x'7b7d',?2,1)"),
            params![id, i64::from(deleted)],
        )?;
        Ok(())
    })
}

fn bind(
    db: &AccountDb,
    schema: &'static str,
    copy: String,
    id: &'static str,
) -> Result<(), StorageError> {
    on(db, move |raw| {
        raw.execute(
            &format!("INSERT INTO {schema}.message_copy_binding VALUES(?1,?2)"),
            params![copy, id],
        )?;
        Ok(())
    })
}

pub(super) fn full(
    principal: &str,
    device: &str,
    payload: &str,
    created_at: i64,
    ttl: i64,
) -> Value {
    json!({"source_principal_id":principal,"source_device_id":device,"signing_key_id":"key",
        "payload_hash":payload,"created_at":created_at,"ttl":ttl})
}

/// A footprinted actor row (a `routed/committed` style copy) in `schema`.
fn actor_copy(
    db: &AccountDb,
    schema: &'static str,
    table: &'static str,
    key: &'static str,
    id: &'static str,
    value: Value,
) -> Result<(), StorageError> {
    on(db, move |raw| {
        let body = serde_json::to_vec(&value).expect("value");
        let kind = if table == "runtime_actor_state" { "actor" } else { "archived_actor" };
        if table == "runtime_actor_state" {
            raw.execute(
                &format!(
                    "INSERT INTO {schema}.runtime_actor_state(state_kind,state_json) VALUES(?1,?2)"
                ),
                params![key, body],
            )?;
            raw.execute(
                &format!("INSERT INTO {schema}.message_footprint VALUES(?1,'{kind}',?2)"),
                params![id, key],
            )?;
        } else {
            raw.execute(
                &format!("INSERT INTO {schema}.backup_archived_actor_state VALUES('s',?1,?2)"),
                params![key, body],
            )?;
            let rowid: i64 = raw.query_row(
                &format!("SELECT max(rowid) FROM {schema}.backup_archived_actor_state"),
                [],
                |r| r.get(0),
            )?;
            raw.execute(
                &format!("INSERT INTO {schema}.message_footprint VALUES(?1,'{kind}',?2)"),
                params![id, rowid.to_string()],
            )?;
        }
        Ok(())
    })
}

pub(super) fn current(
    db: &AccountDb,
    principal: &str,
    device: &str,
    payload: &str,
) -> Result<(String, String), StorageError> {
    let (principal, device, payload) =
        (principal.to_owned(), device.to_owned(), payload.to_owned());
    on(db, move |raw| {
        let tuple = ErasedTuple {
            principal: &principal,
            device: &device,
            signing_key_id: "key",
            payload_hash: &payload,
        };
        let value = tuple.canonical()?;
        super::super::mac_subkeys::bundle_macs(raw, LABEL, &value)?
            .into_iter()
            .next()
            .ok_or(StorageError::AuthorizationRejected)
    })
}

/// Every retained bundle's selector for one tuple, matching the erased-input binding rule.
pub(super) fn all_selectors(
    db: &AccountDb,
    principal: &str,
    device: &str,
    payload: &str,
) -> Result<Vec<String>, StorageError> {
    let (principal, device, payload) =
        (principal.to_owned(), device.to_owned(), payload.to_owned());
    on(db, move |raw| {
        let tuple = ErasedTuple {
            principal: &principal,
            device: &device,
            signing_key_id: "key",
            payload_hash: &payload,
        };
        let value = tuple.canonical()?;
        Ok(super::super::mac_subkeys::bundle_macs(raw, LABEL, &value)?
            .into_iter()
            .map(|(_, selector)| selector)
            .collect())
    })
}

fn binding_id(bundle: &str, selector: &str, expires_at: i64) -> String {
    format!("erased-input:{bundle}:{selector}:{expires_at}")
}

pub(super) fn tombstone(db: &AccountDb, selector: &str) -> Result<Option<i64>, StorageError> {
    use rusqlite::OptionalExtension;
    Ok(db
        .connection
        .query_row(
            "SELECT expires_at FROM receive_erased_input WHERE selector=?1",
            params![selector],
            |r| r.get(0),
        )
        .optional()?)
}

pub(super) fn bindings(db: &AccountDb, id: &str) -> Result<Vec<String>, StorageError> {
    let mut q = db.connection.prepare(
        "SELECT copy_id FROM message_copy_binding WHERE message_id=?1 AND copy_id GLOB 'erased-input:*' ORDER BY 1",
    )?;
    Ok(q.query_map(params![id], |r| r.get(0))?.collect::<Result<_, _>>()?)
}

pub(super) fn lifetime(created_at: i64, ttl: i64, now: i64) -> i64 {
    created_at.min(now + 120) + ttl.min(604_800) + 300
}

pub(super) fn count(db: &AccountDb, sql: &str) -> Result<i64, StorageError> {
    Ok(db.connection.query_row(sql, [], |r| r.get(0))?)
}

fn staged(db: &AccountDb) -> Result<(i64, i64), StorageError> {
    Ok((
        count(db, "SELECT count(*) FROM temp.backup_erased_capture")?,
        count(db, "SELECT count(*) FROM temp.backup_erased_capture_message")?,
    ))
}

#[test]
fn erased_input_binding_import_and_capture_helpers() -> Result<(), StorageError> {
    let now = crate::unix_now();
    // (a) A live target keeps the binding with the maximum expiry and collapses variants.
    let (root, db) = crate::tests::test_db("erased-capture-a")?;
    attach(&db)?;
    let (bundle, selector) = current(&db, "p", "d", "pa")?;
    message(&db, "main", "M", false)?;
    message(&db, "incoming", "M", false)?;
    bind(&db, "main", binding_id(&bundle, &selector, now + 500), "M")?;
    bind(&db, "incoming", binding_id(&bundle, &selector, now + 1_000), "M")?;
    on(&db, move |raw| {
        stage_merge_capture(raw, Side::Local, now)?;
        stage_merge_capture(raw, Side::Incoming, now)?;
        reconcile_merge_capture(raw, now)
    })?;
    assert_eq!(bindings(&db, "M")?, vec![binding_id(&bundle, &selector, now + 1_000)]);
    // The reverse arrangement keeps the longer local variant.
    on(&db, |raw| {
        raw.execute_batch(
            "DELETE FROM main.message_copy_binding; DELETE FROM incoming.message_copy_binding;",
        )
        .map_err(Into::into)
    })?;
    bind(&db, "main", binding_id(&bundle, &selector, now + 2_000), "M")?;
    bind(&db, "incoming", binding_id(&bundle, &selector, now + 1_000), "M")?;
    on(&db, move |raw| {
        stage_merge_capture(raw, Side::Local, now)?;
        stage_merge_capture(raw, Side::Incoming, now)?;
        reconcile_merge_capture(raw, now)
    })?;
    assert_eq!(bindings(&db, "M")?, vec![binding_id(&bundle, &selector, now + 2_000)]);
    drop(db);
    std::fs::remove_dir_all(root)?;

    // (b) A deleted target becomes a tombstone (max-merged); (c) an absent target is skipped;
    // (d) an expired binding is not even staged.
    let (root, db) = crate::tests::test_db("erased-capture-bcd")?;
    attach(&db)?;
    let (bundle, sel_b) = current(&db, "p", "d", "pb")?;
    let (_, sel_c) = current(&db, "p", "d", "pc")?;
    let (_, sel_d) = current(&db, "p", "d", "pd")?;
    for id in ["MB", "MC", "MD"] {
        message(&db, "incoming", id, false)?;
    }
    message(&db, "main", "MB", true)?;
    message(&db, "main", "MD", false)?;
    bind(&db, "incoming", binding_id(&bundle, &sel_b, now + 700), "MB")?;
    bind(&db, "incoming", binding_id(&bundle, &sel_c, now + 700), "MC")?;
    bind(&db, "incoming", binding_id(&bundle, &sel_d, now - 5), "MD")?;
    db.connection.execute(
        "INSERT INTO receive_erased_input VALUES(?1,?2,?3)",
        params![&sel_b, &bundle, now + 900],
    )?;
    on(&db, move |raw| {
        stage_merge_capture(raw, Side::Local, now)?;
        stage_merge_capture(raw, Side::Incoming, now)
    })?;
    assert_eq!(staged(&db)?, (2, 2), "the expired binding must not be staged");
    on(&db, move |raw| reconcile_merge_capture(raw, now))?;
    assert_eq!(tombstone(&db, &sel_b)?, Some(now + 900), "max-merge keeps the longer expiry");
    assert_eq!(tombstone(&db, &sel_c)?, None);
    assert!(bindings(&db, "MC")?.is_empty() && bindings(&db, "MD")?.is_empty());
    assert_eq!(tombstone(&db, &sel_d)?, None);
    drop(db);
    std::fs::remove_dir_all(root)?;

    // (e)/(j) A malformed incoming binding is refused at staging, an unknown bundle at
    // reconcile, each with zero changes.
    let (root, db) = crate::tests::test_db("erased-capture-ej")?;
    attach(&db)?;
    message(&db, "incoming", "M", false)?;
    message(&db, "main", "M", true)?;
    bind(&db, "incoming", "erased-input:not-base64:also-bad:123".to_owned(), "M")?;
    let before = (
        count(&db, "SELECT count(*) FROM receive_erased_input")?,
        count(&db, "SELECT count(*) FROM message_copy_binding")?,
    );
    let refused = on(&db, move |raw| stage_merge_capture(raw, Side::Incoming, now));
    assert!(
        matches!(refused, Err(StorageError::Integrity("malformed erased-input binding"))),
        "{refused:?}"
    );
    on(&db, |raw| {
        raw.execute_batch("DELETE FROM incoming.message_copy_binding").map_err(Into::into)
    })?;
    let (_, selector) = current(&db, "p", "d", "pe")?;
    let foreign = ramflux_protocol::encode_base64url([9_u8; 32]);
    bind(&db, "incoming", binding_id(&foreign, &selector, now + 700), "M")?;
    on(&db, move |raw| {
        stage_merge_capture(raw, Side::Local, now)?;
        stage_merge_capture(raw, Side::Incoming, now)
    })?;
    let refused = on(&db, move |raw| reconcile_merge_capture(raw, now));
    assert!(
        matches!(
            refused,
            Err(StorageError::Integrity("erased-input bundle unknown to the merged set"))
        ),
        "{refused:?}"
    );
    assert_eq!(
        before,
        (
            count(&db, "SELECT count(*) FROM receive_erased_input")?,
            count(&db, "SELECT count(*) FROM message_copy_binding")?
        )
    );
    drop(db);
    std::fs::remove_dir_all(root)?;

    // (f) capture_for records sources (i) a binding, (ii) a routed copy and (iii) live work.
    let (root, db) = crate::tests::test_db("erased-capture-f")?;
    db.install_receive_ledger_schema()?;
    db.send_direct_message("thread", "F", "peer", b"x")?;
    let (bundle, sel_i) = current(&db, "p", "d", "unused")?;
    db.connection.execute(
        "INSERT INTO message_copy_binding VALUES(?1,'F')",
        params![binding_id(&bundle, &sel_i, now + 600)],
    )?;
    db.persist_actor_state(
        "routed/committed/f",
        &json!({"routing":{"message_id":"F"},"entry":{"envelope":full("p2","d2","pf2",now,3600)}}),
    )?;
    let (_, sel_ii) = current(&db, "p2", "d2", "pf2")?;
    db.connection.execute("INSERT INTO message_copy_binding VALUES('payload:pf3','F')", [])?;
    let work = {
        let mut v: Value =
            serde_json::from_slice(&super::stage_tests::bytes(1)).expect("entry fixture");
        v["envelope"]["payload_hash"] = json!("pf3");
        v["envelope"]["source_principal_id"] = json!("p3");
        v["envelope"]["source_device_id"] = json!("d3");
        v["envelope"]["created_at"] = json!(now);
        v["envelope"]["ttl"] = json!(3600);
        serde_json::to_vec(&v).expect("entry encoding")
    };
    db.connection.execute(
        "INSERT INTO gateway_receive_epoch VALUES('t','e',1,x'',?1,?1)",
        params![0u64.to_be_bytes().as_slice()],
    )?;
    assert_eq!(
        super::stage_tests::run(&db, super::stage_tests::input(&work, 1))?,
        super::stage::ReceiveStageResult::Staged
    );
    let (_, sel_iii) = current(&db, "p3", "d3", "pf3")?;
    on(&db, move |raw| capture_for(raw, &["F"], now))?;
    assert_eq!(tombstone(&db, &sel_i)?, Some(now + 600));
    assert_eq!(tombstone(&db, &sel_ii)?, Some(lifetime(now, 3600, now)));
    assert_eq!(tombstone(&db, &sel_iii)?, Some(lifetime(now, 3600, now)));
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn erased_input_open_sweep_is_partial_and_merge_sweep_is_full() -> Result<(), StorageError> {
    // (g) 1,500 expired rows and bindings plus 10 live of each: one open removes 1,024 of each
    // kind, the next removes the rest; live entries are never touched.
    let (root, db) = crate::tests::test_db("erased-capture-g")?;
    let now = crate::unix_now();
    db.write_transaction(|| -> Result<(), StorageError> {
        for n in 0..1_510 {
            let at = if n < 1_500 { now - 10 } else { now + 10_000 };
            db.connection.execute(
                "INSERT INTO receive_erased_input VALUES(?1,'b',?2)",
                params![format!("sel-{n:04}"), at],
            )?;
            db.connection.execute(
                "INSERT INTO message_copy_binding VALUES(?1,'M')",
                params![format!("erased-input:b:s{n:04}:{at}")],
            )?;
        }
        Ok(())
    })?;
    let expired = |db: &AccountDb| -> Result<(i64, i64), StorageError> {
        Ok((
            count(
                db,
                &format!(
                    "SELECT count(*) FROM receive_erased_input WHERE expires_at<={}",
                    crate::unix_now()
                ),
            )?,
            count(
                db,
                &format!(
                    "SELECT count(*) FROM message_copy_binding WHERE copy_id GLOB 'erased-input:*' AND CAST(substr(copy_id,length(rtrim(copy_id,'0123456789'))+1) AS INTEGER)<={}",
                    crate::unix_now()
                ),
            )?,
        ))
    };
    let open = |root: &std::path::Path, db: AccountDb| -> Result<AccountDb, StorageError> {
        drop(db);
        AccountDb::open(
            &crate::AccountIndex::open(root)?,
            "acct",
            &crate::AccountDbKey::derive("acct", b"storage-test-secret"),
        )
    };
    let db = open(&root, db)?;
    assert_eq!(expired(&db)?, (476, 476));
    let db = open(&root, db)?;
    assert_eq!(expired(&db)?, (0, 0));
    assert_eq!(count(&db, "SELECT count(*) FROM receive_erased_input")?, 10);
    assert_eq!(
        count(
            &db,
            "SELECT count(*) FROM message_copy_binding WHERE copy_id GLOB 'erased-input:*'"
        )?,
        10
    );
    // S2: a merge sweep clears a seeded remainder completely, including bindings.
    attach(&db)?;
    on(&db, |raw| {
        raw.execute_batch("CREATE TABLE incoming.receive_erased_input AS SELECT * FROM main.receive_erased_input WHERE 0;")?;
        raw.execute("INSERT INTO main.receive_erased_input VALUES('old','b',1)", [])?;
        raw.execute(
            "INSERT INTO main.message_copy_binding VALUES('erased-input:b:old:1','M')",
            [],
        )?;
        Ok(())
    })?;
    on(&db, move |raw| super::erased_input::merge_from_at(raw, "incoming", now))?;
    assert_eq!(expired(&db)?, (0, 0));
    assert_eq!(count(&db, "SELECT count(*) FROM receive_erased_input WHERE selector='old'")?, 0);
    drop(db);
    std::fs::remove_dir_all(root)?;
    let _ = sweep_open;
    Ok(())
}

/// How a message stands on each side when its tuple is staged, and where main ends up.
#[derive(Clone, Copy)]
enum Final {
    Deleted,
    Live,
    Absent,
}

#[test]
fn erased_input_reconcile_covers_every_origin_and_final_state() -> Result<(), StorageError> {
    // (h) origin x final state, with distinct tuples and messages per combination.
    let now = crate::unix_now();
    let (root, db) = crate::tests::test_db("erased-capture-h")?;
    attach(&db)?;
    let cases: [(&'static str, &'static str, Final); 9] = [
        ("local", "L-del", Final::Deleted),
        ("local", "L-live", Final::Live),
        ("local", "L-abs", Final::Absent),
        ("binding", "B-del", Final::Deleted),
        ("binding", "B-live", Final::Live),
        ("binding", "B-abs", Final::Absent),
        ("routed", "R-del", Final::Deleted),
        ("routed", "R-live", Final::Live),
        ("routed", "R-abs", Final::Absent),
    ];
    let mut expect = Vec::new();
    for (origin, id, state) in cases {
        let payload = format!("pay-{id}");
        let (bundle, selector) = current(&db, "p", "d", &payload)?;
        message(&db, "main", id, false)?;
        match origin {
            "local" => bind(&db, "main", binding_id(&bundle, &selector, now + 800), id)?,
            "binding" => {
                message(&db, "incoming", id, false)?;
                bind(&db, "incoming", binding_id(&bundle, &selector, now + 800), id)?;
            }
            _ => {
                message(&db, "incoming", id, false)?;
                let leaked: &'static str = Box::leak(payload.clone().into_boxed_str());
                bind(&db, "incoming", format!("payload:{payload}"), id)?;
                actor_copy(
                    &db,
                    "incoming",
                    "runtime_actor_state",
                    leaked,
                    id,
                    json!({"entry":{"envelope":full("p","d",&payload,now,3600)}}),
                )?;
            }
        }
        expect.push((origin, id, state, bundle, selector));
    }
    on(&db, move |raw| {
        stage_merge_capture(raw, Side::Local, now)?;
        stage_merge_capture(raw, Side::Incoming, now)
    })?;
    for (_, id, state, ..) in &expect {
        match state {
            Final::Deleted => {
                let id = *id;
                on(&db, move |raw| {
                    raw.execute(
                        "UPDATE main.direct_message_projection SET deleted=1 WHERE message_id=?1",
                        params![id],
                    )?;
                    Ok(())
                })?;
            }
            Final::Absent => {
                let id = *id;
                on(&db, move |raw| {
                    raw.execute(
                        "DELETE FROM main.direct_message_projection WHERE message_id=?1",
                        params![id],
                    )?;
                    Ok(())
                })?;
            }
            Final::Live => {}
        }
    }
    on(&db, move |raw| reconcile_merge_capture(raw, now))?;
    for (origin, id, state, bundle, selector) in expect {
        let exact_binding = binding_id(
            &bundle,
            &selector,
            if origin == "routed" { lifetime(now, 3600, now) } else { now + 800 },
        );
        match (origin, state) {
            (_, Final::Deleted) => assert!(tombstone(&db, &selector)?.is_some(), "{id}: tombstone"),
            (_, Final::Absent) => {
                assert_eq!(tombstone(&db, &selector)?, None, "{id}");
                // Nothing is imported for an absent target (a local binding is simply left).
                if origin != "local" {
                    assert!(bindings(&db, id)?.is_empty(), "{id}");
                }
            }
            ("binding", Final::Live) => {
                assert_eq!(bindings(&db, id)?, vec![exact_binding], "{id}: imported");
            }
            ("local", Final::Live) => {
                assert_eq!(bindings(&db, id)?, vec![exact_binding], "{id}: untouched");
            }
            (_, Final::Live) => {
                assert_eq!(tombstone(&db, &selector)?, None, "{id}");
                assert!(bindings(&db, id)?.is_empty(), "{id}: discarded");
            }
        }
    }
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn erased_input_staging_reads_only_fixed_bound_paths_and_derives_exactly()
-> Result<(), StorageError> {
    let now = crate::unix_now();
    let (root, db) = crate::tests::test_db("erased-capture-ikl")?;
    attach(&db)?;
    for id in ["MI", "MX", "ML", "MC"] {
        message(&db, "incoming", id, false)?;
    }
    // (i) An incoming routed tuple is derived exactly; an expired one is skipped.
    bind(&db, "incoming", "payload:pi".to_owned(), "MI")?;
    actor_copy(
        &db,
        "incoming",
        "runtime_actor_state",
        "routed/committed/i",
        "MI",
        json!({"routing":{"message_id":"MI"},"entry":{"envelope":full("pp","dd","pi",now,1800)}}),
    )?;
    bind(&db, "incoming", "payload:pold".to_owned(), "MI")?;
    actor_copy(
        &db,
        "incoming",
        "runtime_actor_state",
        "routed/committed/old",
        "MI",
        json!({"entry":{"envelope":full("pp","dd","pold",1,60)}}),
    )?;
    // (k) An envelope object under `ext` is ignored.
    bind(&db, "incoming", "payload:px".to_owned(), "MX")?;
    actor_copy(
        &db,
        "incoming",
        "runtime_actor_state",
        "other/x",
        "MX",
        json!({"entry":{"ext":{"envelope":full("pp","dd","px",now,3600)}}}),
    )?;
    // (l) A copy whose payload is not bound to its message is ignored.
    actor_copy(
        &db,
        "incoming",
        "runtime_actor_state",
        "routed/committed/l",
        "ML",
        json!({"entry":{"envelope":full("pp","dd","unbound",now,3600)}}),
    )?;
    // Rule (C): an unfootprinted legacy replay row is staged through its bound payload.
    bind(&db, "incoming", "payload:pc".to_owned(), "MC")?;
    on(&db, move |raw| {
        raw.execute(
            "INSERT INTO incoming.runtime_actor_state(state_kind,state_json) VALUES('legacy/replay/committed/c',?1)",
            params![serde_json::to_vec(&json!({"entry":{"envelope":full("pp","dd","pc",now,3600)}})).expect("value")],
        )?;
        Ok(())
    })?;
    on(&db, move |raw| stage_merge_capture(raw, Side::Incoming, now))?;
    let (_, sel_i) = current(&db, "pp", "dd", "pi")?;
    let (_, sel_c) = current(&db, "pp", "dd", "pc")?;
    let rows = {
        let mut q = db
            .connection
            .prepare("SELECT selector,expires_at FROM temp.backup_erased_capture ORDER BY 1")?;
        let rows: Vec<(String, i64)> =
            q.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?.collect::<Result<_, _>>()?;
        rows
    };
    let mut expected = vec![(sel_i, lifetime(now, 1800, now)), (sel_c, lifetime(now, 3600, now))];
    expected.sort();
    assert_eq!(rows, expected, "only the exact, bound, in-window tuples are staged");
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn erased_input_staging_collapses_the_sixteen_bundle_overlap() -> Result<(), StorageError> {
    // (m) tau has bindings under all 16 bundles; its current and archived routed copies
    // duplicate the current-bundle selector.
    let now = crate::unix_now();
    for deleted in [false, true] {
        let (root, db) = crate::tests::test_db(&format!("erased-capture-m{deleted}"))?;
        attach(&db)?;
        let (current_bundle, current_selector) = current(&db, "pp", "dd", "pm")?;
        let mut pairs = vec![(current_bundle.clone(), current_selector.clone())];
        on(&db, |raw| {
            use sha2::Digest;
            for n in 1..16_u8 {
                let keys = [n; 192];
                let mut hash = sha2::Sha256::new();
                hash.update(b"ramflux.account-mac-bundle.v1");
                hash.update(keys);
                raw.execute(
                    "INSERT INTO account_mac_bundle(bundle_id,subkeys,is_current) VALUES(?1,?2,0)",
                    params![ramflux_protocol::encode_base64url(hash.finalize()), keys.as_slice()],
                )?;
            }
            Ok(())
        })?;
        let others: Vec<String> = db
            .connection
            .prepare("SELECT bundle_id FROM account_mac_bundle WHERE is_current=0 ORDER BY 1")?
            .query_map([], |r| r.get(0))?
            .collect::<Result<_, _>>()?;
        for (n, bundle) in others.into_iter().enumerate() {
            let selector =
                ramflux_protocol::encode_base64url([u8::try_from(n).expect("small") + 100; 32]);
            pairs.push((bundle, selector));
        }
        assert_eq!(pairs.len(), 16);
        message(&db, "main", "MM", deleted)?;
        message(&db, "incoming", "MM", false)?;
        for (bundle, selector) in &pairs {
            bind(&db, "incoming", binding_id(bundle, selector, now + 900), "MM")?;
        }
        bind(&db, "incoming", "payload:pm".to_owned(), "MM")?;
        let value = json!({"routing":{"message_id":"MM"},"entry":{"envelope":full("pp","dd","pm",now,3600)}});
        actor_copy(
            &db,
            "incoming",
            "runtime_actor_state",
            "routed/committed/m",
            "MM",
            value.clone(),
        )?;
        actor_copy(
            &db,
            "incoming",
            "backup_archived_actor_state",
            "routed/committed/m",
            "MM",
            value,
        )?;
        on(&db, move |raw| {
            stage_merge_capture(raw, Side::Local, now)?;
            stage_merge_capture(raw, Side::Incoming, now)
        })?;
        assert_eq!(staged(&db)?, (16, 16), "one association per (selector, bundle)");
        let eligible = count(
            &db,
            &format!(
                "SELECT binding_eligible FROM temp.backup_erased_capture_message WHERE selector='{current_selector}' AND bundle_id='{current_bundle}'"
            ),
        )?;
        assert_eq!(eligible, 1, "the overlapped current-bundle association stays eligible");
        let max_expiry = count(
            &db,
            &format!(
                "SELECT expires_at FROM temp.backup_erased_capture WHERE selector='{current_selector}'"
            ),
        )?;
        assert_eq!(max_expiry, lifetime(now, 3600, now).max(now + 900));
        on(&db, move |raw| reconcile_merge_capture(raw, now))?;
        if deleted {
            assert_eq!(count(&db, "SELECT count(*) FROM receive_erased_input")?, 16);
        } else {
            assert_eq!(bindings(&db, "MM")?.len(), 16);
        }
        drop(db);
        std::fs::remove_dir_all(root)?;
    }
    Ok(())
}

#[test]
fn erased_input_source_kinds_classify_every_footprint_kind() {
    // The classification is data: no kind is both Source and Non-source, and each Source kind
    // names a distinct table.
    let mut kinds: Vec<&str> = SOURCE_KINDS.iter().map(|s| s.kind).collect();
    kinds.extend(NON_SOURCE_KINDS);
    let mut sorted = kinds.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(sorted.len(), kinds.len());
    let mut tables: Vec<&str> = SOURCE_KINDS.iter().map(|s| s.table).collect();
    tables.sort_unstable();
    tables.dedup();
    assert_eq!(tables.len(), SOURCE_KINDS.len());
}

#[test]
fn erased_input_import_collapses_local_variants_to_the_combined_maximum() -> Result<(), StorageError>
{
    let now = crate::unix_now();
    let (root, db) = crate::tests::test_db("erased-capture-collapse")?;
    attach(&db)?;
    let (bundle, selector) = current(&db, "p", "d", "pcollapse")?;
    message(&db, "main", "M", false)?;
    message(&db, "incoming", "M", false)?;
    // Two local variants straddle the incoming one; the local maximum wins and is the only one left.
    bind(&db, "main", binding_id(&bundle, &selector, now + 500), "M")?;
    bind(&db, "main", binding_id(&bundle, &selector, now + 2_000), "M")?;
    bind(&db, "incoming", binding_id(&bundle, &selector, now + 1_000), "M")?;
    on(&db, move |raw| {
        stage_merge_capture(raw, Side::Local, now)?;
        stage_merge_capture(raw, Side::Incoming, now)?;
        reconcile_merge_capture(raw, now)
    })?;
    assert_eq!(bindings(&db, "M")?, vec![binding_id(&bundle, &selector, now + 2_000)]);
    // Two local variants below the incoming one collapse to the incoming expiry.
    on(&db, |raw| raw.execute_batch("DELETE FROM main.message_copy_binding").map_err(Into::into))?;
    bind(&db, "main", binding_id(&bundle, &selector, now + 300), "M")?;
    bind(&db, "main", binding_id(&bundle, &selector, now + 400), "M")?;
    on(&db, move |raw| {
        stage_merge_capture(raw, Side::Local, now)?;
        stage_merge_capture(raw, Side::Incoming, now)?;
        reconcile_merge_capture(raw, now)
    })?;
    assert_eq!(bindings(&db, "M")?, vec![binding_id(&bundle, &selector, now + 1_000)]);
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn erased_input_sweeps_remove_negative_expiry_bindings() -> Result<(), StorageError> {
    let now = crate::unix_now();
    let (root, db) = crate::tests::test_db("erased-capture-negative")?;
    attach(&db)?;
    on(&db, |raw| {
        raw.execute_batch(
            "CREATE TABLE incoming.receive_erased_input AS SELECT * FROM main.receive_erased_input WHERE 0;",
        )
        .map_err(Into::into)
    })?;
    let seed = |db: &AccountDb| -> Result<(), StorageError> {
        for (copy, message) in [
            ("erased-input:b:neg:-2000000000", "M"),
            ("erased-input:b:zero:0", "M"),
            ("erased-input:b:live:2000000000000", "M"),
        ] {
            db.connection.execute(
                "INSERT OR IGNORE INTO message_copy_binding VALUES(?1,?2)",
                params![copy, message],
            )?;
        }
        Ok(())
    };
    let remaining = |db: &AccountDb| bindings(db, "M");
    // S3 (account open sweep).
    seed(&db)?;
    on(&db, move |raw| sweep_open(raw, now).map_err(Into::into))?;
    assert_eq!(remaining(&db)?, vec!["erased-input:b:live:2000000000000".to_owned()]);
    // S2 (merge sweep).
    seed(&db)?;
    on(&db, move |raw| super::erased_input::merge_from_at(raw, "incoming", now))?;
    assert_eq!(remaining(&db)?, vec!["erased-input:b:live:2000000000000".to_owned()]);
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

fn id_of(len: usize, fill: u8) -> String {
    ramflux_protocol::encode_base64url(vec![fill; len])
}

#[test]
fn erased_input_binding_validator_rejects_each_predicate_in_isolation() -> Result<(), StorageError>
{
    let now = crate::unix_now();
    let (root, db) = crate::tests::test_db("erased-capture-validator")?;
    attach(&db)?;
    message(&db, "incoming", "M", false)?;
    let good_b = id_of(32, 1);
    let good_s = id_of(32, 2);
    let state = |db: &AccountDb| -> Result<(i64, i64, i64, i64), StorageError> {
        Ok((
            staged(db)?.0,
            staged(db)?.1,
            count(db, "SELECT count(*) FROM receive_erased_input")?,
            count(db, "SELECT count(*) FROM main.message_copy_binding")?,
        ))
    };
    let refuse = |db: &AccountDb, copy: String| -> Result<(), StorageError> {
        on(db, |raw| {
            raw.execute_batch("DELETE FROM incoming.message_copy_binding").map_err(Into::into)
        })?;
        bind(db, "incoming", copy.clone(), "M")?;
        on(db, move |raw| stage_merge_capture(raw, Side::Local, now))?;
        let before = state(db)?;
        let result = on(db, move |raw| stage_merge_capture(raw, Side::Incoming, now));
        assert!(
            matches!(result, Err(StorageError::Integrity("malformed erased-input binding"))),
            "{copy}: {result:?}"
        );
        assert_eq!(state(db)?, before, "{copy}: state changed");
        Ok(())
    };
    refuse(&db, binding_id(&id_of(31, 1), &good_s, now + 100))?;
    refuse(&db, binding_id(&id_of(33, 1), &good_s, now + 100))?;
    refuse(&db, binding_id(&good_b, &id_of(31, 2), now + 100))?;
    refuse(&db, binding_id(&good_b, &id_of(33, 2), now + 100))?;
    refuse(&db, format!("erased-input:{good_b}:{good_s}:not-a-number"))?;
    refuse(&db, format!("erased-input:{good_b}:{good_s}:9223372036854775808"))?;
    refuse(&db, format!("erased-input:{good_b}:{good_s}:"))?;
    // Expiry boundary: `== now` is expired and not staged; `now + 1` is staged.
    for (expiry, expected) in [(now, (0, 0)), (now + 1, (1, 1))] {
        on(&db, |raw| {
            raw.execute_batch("DELETE FROM incoming.message_copy_binding").map_err(Into::into)
        })?;
        bind(&db, "incoming", binding_id(&good_b, &good_s, expiry), "M")?;
        on(&db, move |raw| {
            stage_merge_capture(raw, Side::Local, now)?;
            stage_merge_capture(raw, Side::Incoming, now)
        })?;
        assert_eq!(staged(&db)?, expected, "expiry {expiry}");
    }
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn erased_input_reconcile_sweeps_expired_rows_up_to_the_bound() -> Result<(), StorageError> {
    let now = crate::unix_now();
    let (root, db) = crate::tests::test_db("erased-capture-reconcile-sweep")?;
    attach(&db)?;
    let (bundle, selector) = current(&db, "p", "d", "psweep")?;
    message(&db, "incoming", "MB", false)?;
    message(&db, "main", "MB", true)?;
    bind(&db, "incoming", binding_id(&bundle, &selector, now + 700), "MB")?;
    for n in 0..100 {
        db.connection.execute(
            "INSERT INTO receive_erased_input VALUES(?1,?2,1)",
            params![format!("expired-{n:03}"), &bundle],
        )?;
    }
    on(&db, move |raw| {
        stage_merge_capture(raw, Side::Local, now)?;
        stage_merge_capture(raw, Side::Incoming, now)?;
        reconcile_merge_capture(raw, now)
    })?;
    assert_eq!(tombstone(&db, &selector)?, Some(now + 700));
    assert_eq!(
        count(&db, "SELECT count(*) FROM receive_erased_input WHERE expires_at<=1")?,
        36,
        "one reconcile reclaims at most 64 expired rows"
    );
    assert_eq!(count(&db, "SELECT count(*) FROM receive_erased_input")?, 37);
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}
