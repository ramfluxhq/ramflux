// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! `erased_input_source_inventory_local`: every Source family on the local side leaves its exact
//! selector when the merge deletes the owning message. Archived rows are produced by an earlier
//! merge, as in production.
#![allow(clippy::expect_used, clippy::panic, clippy::too_many_lines)]
use super::erased_capture_tests::{current, full};
use super::erased_input_union_tests::{Pair, expiry, pair};
use super::stage_tests::{bytes, input, run};
use crate::{BackupDatabase, StorageError};
use rusqlite::params;
use serde_json::{Value, json};

/// One family: the message that owns it, the payload that names its tuple, and the SQL that
/// stores the envelope in its table.
struct Family {
    kind: &'static str,
    message: String,
    payload: String,
}

impl Family {
    fn new(kind: &'static str) -> Self {
        Self { kind, message: format!("F-{kind}"), payload: format!("p-{kind}") }
    }
}

fn body(payload: &str, now: i64) -> Vec<u8> {
    serde_json::to_vec(&json!({"entry":{"envelope":full("ip","id",payload,now,3600)}}))
        .expect("body")
}

fn bind_payload(db: &crate::AccountDb, f: &Family) -> Result<(), StorageError> {
    db.connection.execute(
        "INSERT INTO message_copy_binding VALUES(?1,?2)",
        params![format!("payload:{}", f.payload), f.message],
    )?;
    Ok(())
}

/// Stores the family's row on `db` after binding its payload, so the footprint triggers register it.
fn seed_local(db: &crate::AccountDb, f: &Family, n: i64, now: i64) -> Result<(), StorageError> {
    bind_payload(db, f)?;
    let b = body(&f.payload, now);
    let key = format!("{}-{}", f.kind, n);
    match f.kind {
        "actor" => db.persist_actor_state(
            &format!("routed/committed/{}", f.payload),
            &json!({"routing":{"message_id":f.message},"entry":{"envelope":full("ip","id",&f.payload,now,3600)}}),
        )?,
        "event" => {
            db.connection.execute(
                "INSERT INTO local_event_log VALUES(?1,'test','peer','device',?2,?2,1,NULL,?3,x'1234','verified','pending')",
                params![key, n, b],
            )?;
        }
        "unrouted" => {
            db.connection.execute(
                "INSERT INTO runtime_unrouted VALUES(?1,1,?2,1)",
                params![key, b],
            )?;
        }
        "retry" => {
            db.connection.execute(
                "INSERT INTO runtime_inbox_retry VALUES(?1,?2,0,1,1)",
                params![key, b],
            )?;
        }
        "dead_letter" => {
            db.connection.execute(
                "INSERT INTO runtime_inbox_dead_letter VALUES(?1,?2,'e',1)",
                params![key, b],
            )?;
        }
        "journal" => {
            db.append_journal(
                &key,
                "message.test",
                &json!({"message_id":f.message,"envelope":full("ip","id",&f.payload,now,3600)}),
                1,
                None,
            )?;
        }
        "group_pending_undecrypted" => {
            db.connection.execute(
                "INSERT INTO group_pending_undecrypted VALUES(?1,'g','thread',1,'s',1,?2,1)",
                params![f.message, b],
            )?;
        }
        "contact_message_request" => {}
        "receive_work" => {
            stage_work(db, &f.payload, now)?;
        }
        other => panic!("unseeded family {other}"),
    }
    Ok(())
}

fn work(payload: &str, now: i64) -> Vec<u8> {
    let mut v: Value = serde_json::from_slice(&bytes(1)).expect("entry fixture");
    v["envelope"]["payload_hash"] = json!(payload);
    v["envelope"]["source_principal_id"] = json!("ip");
    v["envelope"]["source_device_id"] = json!("id");
    v["envelope"]["created_at"] = json!(now);
    v["envelope"]["ttl"] = json!(3600);
    serde_json::to_vec(&v).expect("entry encoding")
}

fn stage_work(db: &crate::AccountDb, payload: &str, now: i64) -> Result<(), StorageError> {
    db.install_receive_ledger_schema()?;
    db.connection.execute(
        "INSERT INTO gateway_receive_epoch VALUES('t','e',1,x'',?1,?1)",
        params![0u64.to_be_bytes().as_slice()],
    )?;
    let wire = work(payload, now);
    assert_eq!(run(db, input(&wire, 1))?, super::stage::ReceiveStageResult::Staged);
    Ok(())
}

#[test]
fn erased_input_source_inventory_local() -> Result<(), StorageError> {
    let now = crate::unix_now();
    let kinds = [
        "actor",
        "event",
        "unrouted",
        "retry",
        "dead_letter",
        "journal",
        "group_pending_undecrypted",
        "contact_message_request",
        "receive_work",
    ];
    let p = pair("erased-inventory-local")?;
    let families: Vec<Family> = kinds.iter().map(|k| Family::new(k)).collect();
    for f in &families {
        p.local.send_direct_message("thread", &f.message, "peer", b"x")?;
        p.source.send_direct_message("thread", &f.message, "peer", b"x")?;
    }
    for (n, f) in (1_i64..).zip(&families) {
        seed_local(&p.local, f, n, now)?;
    }
    // Archived families come from an earlier merge of a snapshot that carries them: a
    // group-transfer actor row (archived only) and an event row.
    p.local.send_direct_message("thread", "A", "peer", b"x")?;
    p.source.send_direct_message("thread", "A", "peer", b"x")?;
    p.source
        .connection
        .execute("INSERT INTO message_copy_binding VALUES('payload:p-archived','A')", [])?;
    p.source.persist_actor_state(
        "group-transfer/p-archived",
        &json!({"entry":{"envelope":full("ip","id","p-archived",now,3600)}}),
    )?;
    p.source
        .connection
        .execute("INSERT INTO message_copy_binding VALUES('payload:p-archived-event','A')", [])?;
    p.source.connection.execute(
        "INSERT INTO local_event_log VALUES('ev-archived','test','peer','device',900,900,1,NULL,?1,x'1234','verified','pending')",
        params![body("p-archived-event", now)],
    )?;
    // The local account owns the same payloads (its own bindings), as a real account would.
    for payload in ["p-archived", "p-archived-event"] {
        p.local.connection.execute(
            "INSERT INTO message_copy_binding VALUES(?1,'A')",
            params![format!("payload:{payload}")],
        )?;
    }
    let first = p.root.join("incoming-1.db");
    let first_snapshot = p.source.write_backup_snapshot(&first)?;
    let path = p.root.join("merged.db");
    let target = p.local.write_backup_snapshot(&path)?;
    let mut merged = BackupDatabase::open(&path, &target.key)?;
    merged.merge_backup(&first, &first_snapshot.key, || Ok(()))?;
    // Exactly two archived copies of the row are expected, one per archive source key: the
    // group-transfer pass (`archive_group_transfer`) stores it under `import`, and the general
    // imported-archive pass (`preserve_imported_archives`) stores every incoming actor row under
    // the incoming key's fingerprint. Both are retained history and both are capture sources.
    let mut sources: Vec<String> = merged
        .db
        .prepare("SELECT source FROM backup_archived_actor_state WHERE state_kind='group-transfer/p-archived' ORDER BY source")?
        .query_map([], |r| r.get(0))?
        .collect::<Result<_, _>>()?;
    let mut want = vec!["import".to_owned(), first_snapshot.key.fingerprint()];
    want.sort();
    sources.sort();
    assert_eq!(sources, want, "the earlier merge archived the group-transfer row twice");
    let kinds: Vec<String> = merged
        .db
        .prepare("SELECT DISTINCT kind FROM message_footprint WHERE message_id='A' ORDER BY 1")?
        .query_map([], |r| r.get(0))?
        .collect::<Result<_, _>>()?;
    assert_eq!(
        kinds,
        vec!["archived_actor".to_owned(), "archived_event".to_owned(), "event".to_owned()],
        "the earlier merge registered footprints for the archived copies and the imported event"
    );
    // A held contact request is seeded after the earlier merge: the generic merge drops a held
    // request whose message already exists in the conversation, so it cannot survive a merge.
    let contact = Family::new("contact_message_request");
    merged.db.execute(
        "INSERT INTO contact_message_request VALUES('c','s',?1,'thread',?2,10,9999999999,1)",
        params![contact.message, body(&contact.payload, now)],
    )?;
    // Second merge: the incoming side deletes every message, so each family must leave a tombstone.
    for f in &families {
        p.source.delete_direct_message("thread", &f.message, "local", &format!("d-{}", f.kind))?;
    }
    p.source.delete_direct_message("thread", "A", "local", "d-a")?;
    let second = p.root.join("incoming-2.db");
    let second_snapshot = p.source.write_backup_snapshot(&second)?;
    merged.merge_backup(&second, &second_snapshot.key, || Ok(()))?;
    let mut expected: Vec<(String, String)> = families
        .iter()
        .map(|f| Ok((f.kind.to_owned(), f.payload.clone())))
        .collect::<Result<_, StorageError>>()?;
    expected.push(("archived_actor".to_owned(), "p-archived".to_owned()));
    expected.push(("archived_event".to_owned(), "p-archived-event".to_owned()));
    let verify = |db: &rusqlite::Connection| -> Result<(), StorageError> {
        let mut wrong = Vec::new();
        for (kind, payload) in &expected {
            let (_, selector) = current_in(&p, payload)?;
            if expiry(db, &selector)? != Some(now + 3_900) {
                wrong.push(kind.as_str());
            }
        }
        assert_eq!(wrong, Vec::<&str>::new(), "families without their exact selector");
        Ok(())
    };
    verify(&merged.db)?;
    drop(merged);
    verify(&BackupDatabase::open(&path, &target.key)?.db)?;
    Ok(())
}

fn current_in(p: &Pair, payload: &str) -> Result<(String, String), StorageError> {
    current(&p.local, "ip", "id", payload)
}
