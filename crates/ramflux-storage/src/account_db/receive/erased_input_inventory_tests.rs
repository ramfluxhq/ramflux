// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! `erased_input_source_inventory_local` and `_incoming`: every Source family on the local side leaves its exact
//! selector when the merge deletes the owning message. Archived rows are produced by an earlier
//! merge, as in production.
#![allow(clippy::expect_used, clippy::panic, clippy::too_many_lines)]
use super::erased_capture_tests::{current, full};
use super::erased_input_union_tests::{Pair, expiry, pair};
use super::stage_tests::{bytes, input, run};
use crate::{AccountDb, AccountDbKey, AccountIndex, BackupDatabase, StorageError};
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

/// A tuple expected as a tombstone: its family name, exact selector and exact expiry.
struct Want {
    kind: &'static str,
    selector: String,
    expires_at: i64,
}

/// Messages of the extra families: class (A) binding, a quarantined committed receipt and the
/// a2i control receipt (an absence cell: it holds no inbound envelope).
const EXTRA_MESSAGES: [&str; 3] = ["B-bind", "B-legacy", "B-a2i"];

/// Seeds the three extra families on `db` and returns the tombstones they must leave.
fn seed_extra(db: &AccountDb, derive: &AccountDb, now: i64) -> Result<Vec<Want>, StorageError> {
    let mut wanted = Vec::new();
    // (A) the `erased-input:` binding itself carries its selector.
    let (bundle, selector) = current(db, "ip", "id", "p-bind")?;
    db.connection.execute(
        "INSERT INTO message_copy_binding VALUES(?1,'B-bind')",
        params![format!("erased-input:{bundle}:{selector}:{}", now + 600)],
    )?;
    wanted.push(Want { kind: "erased_input_binding", selector, expires_at: now + 600 });
    // `legacy/replay/committed` is reached through the real quarantine sequence: the receipt
    // is rewritten under the quarantine key, then the original key is removed.
    db.connection.execute(
        "INSERT INTO message_copy_binding VALUES('payload:p-legacy-committed','B-legacy')",
        [],
    )?;
    let receipt = json!({"routing":{"message_id":"B-legacy"},"entry":{"envelope":full("ip","id","p-legacy-committed",now,3600)}});
    let old = "routed/committed/old-legacy";
    db.persist_actor_state(old, &receipt)?;
    db.persist_actor_state(
        &format!("legacy/replay/committed/{}", ramflux_protocol::encode_base64url(old.as_bytes())),
        &receipt,
    )?;
    db.remove_actor_state(old)?;
    // Merge derives selectors with the merging account's own bundles.
    let (_, selector) = current(derive, "ip", "id", "p-legacy-committed")?;
    wanted.push(Want { kind: "legacy_replay_committed", selector, expires_at: now + 3_900 });
    // `legacy/replay/a2i` holds an a2i control event, never an inbound envelope: no tombstone.
    db.connection
        .execute("INSERT INTO message_copy_binding VALUES('payload:p-a2i','B-a2i')", [])?;
    db.persist_actor_state(
        &format!("legacy/replay/a2i/{}", ramflux_protocol::encode_base64url(b"a2i/old")),
        &json!({"event_id":"e","source_device_id":"d","action":"request_approval"}),
    )?;
    Ok(wanted)
}

/// Every `SOURCE_KINDS` family is covered by a seeded family, an archived family or a declared
/// exclusion; a new kind makes this fail.
fn assert_covers_source_kinds(seeded: &[&str], declared_exclusions: &[&str]) {
    let mut covered: Vec<&str> = seeded.to_vec();
    covered.extend(["archived_actor", "archived_event"]);
    covered.extend(declared_exclusions);
    covered.sort_unstable();
    let mut registry: Vec<&str> =
        super::erased_capture::SOURCE_KINDS.iter().map(|k| k.kind).collect();
    registry.sort_unstable();
    assert_eq!(covered, registry, "the inventory covers exactly SOURCE_KINDS");
}

fn tombstone_count(db: &rusqlite::Connection) -> rusqlite::Result<i64> {
    db.query_row("SELECT count(*) FROM receive_erased_input", [], |r| r.get(0))
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
    assert_covers_source_kinds(&kinds, &[]);
    let p = pair("erased-inventory-local")?;
    let families: Vec<Family> = kinds.iter().map(|k| Family::new(k)).collect();
    for f in &families {
        p.local.send_direct_message("thread", &f.message, "peer", b"x")?;
        p.source.send_direct_message("thread", &f.message, "peer", b"x")?;
    }
    for id in EXTRA_MESSAGES {
        p.local.send_direct_message("thread", id, "peer", b"x")?;
        p.source.send_direct_message("thread", id, "peer", b"x")?;
    }
    let extra = seed_extra(&p.local, &p.local, now)?;
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
    // The earlier merge also imported the event as a live row; remove it so the archived copy
    // is the only source of that tuple.
    merged.db.execute("DELETE FROM local_event_log WHERE event_id='ev-archived'", [])?;
    let footprint_kinds: Vec<String> = merged
        .db
        .prepare("SELECT DISTINCT kind FROM message_footprint WHERE message_id='A' ORDER BY 1")?
        .query_map([], |r| r.get(0))?
        .collect::<Result<_, _>>()?;
    assert_eq!(
        footprint_kinds,
        vec!["archived_actor".to_owned(), "archived_event".to_owned()],
        "only the archived copies carry the tuples of A"
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
    for id in EXTRA_MESSAGES {
        p.source.delete_direct_message("thread", id, "local", &format!("d-{id}"))?;
    }
    let second = p.root.join("incoming-2.db");
    let second_snapshot = p.source.write_backup_snapshot(&second)?;
    merged.merge_backup(&second, &second_snapshot.key, || Ok(()))?;
    let mut expected: Vec<Want> = Vec::new();
    for f in &families {
        let (_, selector) = current_in(&p, &f.payload)?;
        expected.push(Want { kind: f.kind, selector, expires_at: now + 3_900 });
    }
    for (kind, payload) in
        [("archived_actor", "p-archived"), ("archived_event", "p-archived-event")]
    {
        let (_, selector) = current_in(&p, payload)?;
        expected.push(Want { kind, selector, expires_at: now + 3_900 });
    }
    // The source deleted A itself, which captured the two archived-family tuples under the
    // source's own bundle; the merge unions those tombstones in as well.
    for (kind, payload) in [
        ("source_capture_group_transfer", "p-archived"),
        ("source_capture_event", "p-archived-event"),
    ] {
        let (_, selector) = current(&p.source, "ip", "id", payload)?;
        expected.push(Want { kind, selector, expires_at: now + 3_900 });
    }
    expected.extend(extra);
    let verify = |db: &rusqlite::Connection| -> Result<(), StorageError> {
        let mut wrong = Vec::new();
        for w in &expected {
            if expiry(db, &w.selector)? != Some(w.expires_at) {
                wrong.push(w.kind);
            }
        }
        assert_eq!(wrong, Vec::<&str>::new(), "families without their exact selector");
        // Exactly the expected tuples: the a2i receipt left nothing behind.
        assert_eq!(tombstone_count(db)?, i64::try_from(expected.len()).expect("count"));
        let archived: i64 = db.query_row(
            "SELECT count(*) FROM backup_archived_actor_state WHERE state_kind='group-transfer/p-archived'",
            [],
            |r| r.get(0),
        )?;
        assert_eq!(archived, 0, "both archived group-transfer copies are erased");
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

/// An account of the same root, used to build the incoming snapshot.
fn carrier_account(p: &Pair, name: &str) -> Result<(AccountIndex, AccountDb), StorageError> {
    let index = AccountIndex::open(p.root.join(name))?;
    index.create_account("account", "root")?;
    let db = AccountDb::open(&index, "account", &AccountDbKey::generate()?)?;
    Ok((index, db))
}

#[test]
fn erased_input_source_inventory_incoming() -> Result<(), StorageError> {
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
    ];
    assert_covers_source_kinds(&kinds, &["receive_work"]);
    // `receive_work` is absent on purpose: installing the receive ledger stamps schema version
    // 15 on the incoming account, which a merge refuses as too new (`AccountSchemaTooNew`), and
    // backups are to strip the ledger tables (P03b). An incoming snapshot cannot carry it yet.
    let p = pair("erased-inventory-incoming")?;
    let families: Vec<Family> = kinds.iter().map(|k| Family::new(k)).collect();
    // The local account holds every message and deletes it: it has no source of its own.
    let mut messages: Vec<String> = families.iter().map(|f| f.message.clone()).collect();
    messages.extend(["A".to_owned(), "L".to_owned()]);
    messages.extend(EXTRA_MESSAGES.map(str::to_owned));
    for id in &messages {
        p.local.send_direct_message("thread", id, "peer", b"x")?;
        p.local.delete_direct_message("thread", id, "local", &format!("d-{id}"))?;
    }
    // Archived families come from an earlier merge into the incoming account: a group-transfer
    // actor row (archived only) and an event row, both carried by a first snapshot.
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
    let early = p.root.join("early.db");
    let early_snapshot = p.source.write_backup_snapshot(&early)?;
    let (mid, mid_db) = carrier_account(&p, "mid")?;
    let mid_path = p.root.join("mid.db");
    let mid_target = mid_db.write_backup_snapshot(&mid_path)?;
    let mut mid_merged = BackupDatabase::open(&mid_path, &mid_target.key)?;
    mid_merged.merge_backup(&early, &early_snapshot.key, || Ok(()))?;
    drop(mid_db);
    // The merged result is installed as the incoming account.
    let carrier_root = p.root.join("carrier");
    let carrier_index = AccountIndex::open(&carrier_root)?;
    let account = carrier_index.create_account("account", "root")?;
    let installed = carrier_root.join(account.db_relative_path);
    std::fs::create_dir_all(installed.parent().ok_or(StorageError::AuthorizationRejected)?)?;
    mid_merged.copy_to(&installed, &mid_target.key)?;
    drop(mid_merged);
    drop(mid);
    let carrier = AccountDb::open(&carrier_index, "account", &mid_target.key)?;
    for payload in ["p-archived", "p-archived-event"] {
        carrier.connection.execute(
            "INSERT INTO message_copy_binding VALUES(?1,'A')",
            params![format!("payload:{payload}")],
        )?;
    }
    // The earlier merge also imported the event as a live row; remove it so the archived copy
    // is the only source of that tuple.
    carrier.connection.execute("DELETE FROM local_event_log WHERE event_id='ev-archived'", [])?;
    for f in &families {
        carrier.send_direct_message("thread", &f.message, "peer", b"x")?;
    }
    for id in EXTRA_MESSAGES {
        carrier.send_direct_message("thread", id, "peer", b"x")?;
    }
    let extra = seed_extra(&carrier, &p.local, now)?;
    for (n, f) in (1_i64..).zip(&families) {
        seed_local(&carrier, f, n, now)?;
    }
    let contact = Family::new("contact_message_request");
    carrier.connection.execute(
        "INSERT INTO contact_message_request VALUES('c','s',?1,'thread',?2,10,9999999999,1)",
        params![contact.message, body(&contact.payload, now)],
    )?;
    // Rule C: a replay row written before footprints existed has no footprint and is owned
    // only through its payload binding.
    carrier.send_direct_message("thread", "L", "peer", b"x")?;
    carrier
        .connection
        .execute("INSERT INTO message_copy_binding VALUES('payload:p-legacy','L')", [])?;
    carrier.connection.execute(
        "INSERT INTO runtime_actor_state(state_kind,state_json) VALUES('legacy/replay/committed/l',?1)",
        params![body("p-legacy", now)],
    )?;
    carrier.connection.execute(
        "DELETE FROM message_footprint WHERE kind='actor' AND locator='legacy/replay/committed/l'",
        [],
    )?;
    let unfootprinted: i64 = carrier.connection.query_row(
        "SELECT count(*) FROM message_footprint WHERE locator='legacy/replay/committed/l'",
        [],
        |r| r.get(0),
    )?;
    assert_eq!(unfootprinted, 0, "the legacy replay row has no footprint");
    let incoming = p.root.join("incoming.db");
    let incoming_snapshot = carrier.write_backup_snapshot(&incoming)?;
    let path = p.root.join("merged.db");
    let target = p.local.write_backup_snapshot(&path)?;
    let mut merged = BackupDatabase::open(&path, &target.key)?;
    merged.merge_backup(&incoming, &incoming_snapshot.key, || Ok(()))?;
    let mut expected: Vec<Want> = Vec::new();
    for f in &families {
        let (_, selector) = current(&p.local, "ip", "id", &f.payload)?;
        expected.push(Want { kind: f.kind, selector, expires_at: now + 3_900 });
    }
    for (kind, payload) in [
        ("archived_actor", "p-archived"),
        ("archived_event", "p-archived-event"),
        ("legacy_replay_rule_c", "p-legacy"),
    ] {
        let (_, selector) = current(&p.local, "ip", "id", payload)?;
        expected.push(Want { kind, selector, expires_at: now + 3_900 });
    }
    expected.extend(extra);
    let verify = |db: &rusqlite::Connection| -> Result<(), StorageError> {
        let mut wrong = Vec::new();
        for w in &expected {
            if expiry(db, &w.selector)? != Some(w.expires_at) {
                wrong.push(w.kind);
            }
        }
        assert_eq!(wrong, Vec::<&str>::new(), "families without their exact selector");
        assert_eq!(tombstone_count(db)?, i64::try_from(expected.len()).expect("count"));
        Ok(())
    };
    verify(&merged.db)?;
    drop(merged);
    verify(&BackupDatabase::open(&path, &target.key)?.db)?;
    Ok(())
}

#[test]
fn erased_input_incoming_receive_ledger_is_refused_as_too_new() -> Result<(), StorageError> {
    // Declared exclusion: `receive_work` cannot be an incoming Source family yet. Installing the
    // receive ledger stamps schema version 15 and a merge refuses any newer incoming schema.
    // Pinning the exact refusal means the family is added to the incoming inventory when merge
    // compatibility (P03b) lands, and this test is then replaced.
    let p = pair("erased-inventory-incoming-ledger")?;
    p.source.install_receive_ledger_schema()?;
    let incoming = p.root.join("incoming.db");
    let snapshot = p.source.write_backup_snapshot(&incoming)?;
    let path = p.root.join("merged.db");
    let target = p.local.write_backup_snapshot(&path)?;
    let mut merged = BackupDatabase::open(&path, &target.key)?;
    let refused = merged.merge_backup(&incoming, &snapshot.key, || Ok(()));
    assert!(
        matches!(
            &refused,
            Err(StorageError::AccountSchemaTooNew { schema_version: 15, supported: 14 })
        ),
        "{:?}",
        refused.err()
    );
    Ok(())
}
