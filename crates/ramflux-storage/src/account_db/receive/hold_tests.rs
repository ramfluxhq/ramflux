// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Quota isolation and atomic W0 → hold/journal/receipt admission.
#![allow(clippy::expect_used, clippy::panic)]
use super::ReceiveExpectation;
use super::hold::{ReceiveHold, ReceiveHoldClass as Class, ReceiveHoldJournal, ReceiveHoldResult};
use super::stage::{ReceiveStage, ReceiveStageResult};
use crate::{AccountDb, ProjectionStore, StorageError};
use rusqlite::params;

#[derive(Clone, Debug, Eq, PartialEq)]
struct Snap {
    cursor: String,
    receipts: Vec<(Vec<u8>, String)>,
    work: Vec<(Vec<u8>, Vec<u8>, String, i64)>,
    intents: Vec<Vec<u8>>,
    unrouted: Vec<(String, i64, Vec<u8>)>,
    policy: Vec<(String, String, i64, String, String)>,
    journal: Vec<(String, String, Vec<u8>)>,
}

fn expect_for<'a>(
    db: &AccountDb,
    incarnation: &'a str,
    cursor: u64,
) -> Result<ReceiveExpectation<'a>, StorageError> {
    Ok(ReceiveExpectation {
        target: "t",
        incarnation,
        cursor,
        generation: 1,
        erasure_generation: db.privacy_erasure_generation()?,
    })
}

fn entry(sequence: u64, payload_bytes: usize) -> Vec<u8> {
    let mut value: serde_json::Value =
        serde_json::from_slice(&super::stage_tests::bytes(sequence)).expect("fixture json");
    value["envelope"]["encrypted_payload"] = serde_json::json!("x".repeat(payload_bytes));
    serde_json::to_vec(&value).expect("fixture encoding")
}

fn set_verified_source(db: &AccountDb, key: &str, source: &str) -> Result<(), StorageError> {
    db.connection.execute(
        "INSERT INTO runtime_inbox_policy VALUES(?1,?2,1,1,604801,0,'none','',0,0)",
        params![key, source],
    )?;
    Ok(())
}

fn stage(
    db: &AccountDb,
    cursor: u64,
    sequence: u64,
    key: &str,
    wire: &[u8],
) -> Result<(), StorageError> {
    stage_for(db, "e", cursor, sequence, key, wire)
}

fn stage_for(
    db: &AccountDb,
    incarnation: &str,
    cursor: u64,
    sequence: u64,
    key: &str,
    wire: &[u8],
) -> Result<(), StorageError> {
    let result = db.receive_transaction(expect_for(db, incarnation, cursor)?, 1, |tx| {
        tx.stage(ReceiveStage {
            target: "t",
            incarnation,
            sequence,
            entry_json: wire,
            admission_key: key,
            retain_until: 604_801,
            first_seen: i64::try_from(sequence).unwrap_or(i64::MAX),
        })
    })?;
    assert!(matches!(result, ReceiveStageResult::Staged | ReceiveStageResult::Existing));
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn admit(
    db: &AccountDb,
    cursor: u64,
    sequence: u64,
    key: &str,
    class: Class,
    contact_root: Option<&str>,
    unrouted: bool,
) -> Result<ReceiveHoldResult, StorageError> {
    admit_for(db, "e", cursor, sequence, key, class, contact_root, unrouted)
}

#[allow(clippy::too_many_arguments)]
fn admit_for(
    db: &AccountDb,
    incarnation: &str,
    cursor: u64,
    sequence: u64,
    key: &str,
    class: Class,
    contact_root: Option<&str>,
    unrouted: bool,
) -> Result<ReceiveHoldResult, StorageError> {
    let source_key = format!("unrouted:{key}");
    let body = serde_json::json!({
        "envelope_id": format!("env-{sequence}"),
        "claimed_source_device_id": "claimed-only",
        "payload_hash": format!("hash-{sequence}"),
        "inbox_seq": sequence,
    });
    db.receive_transaction(expect_for(db, incarnation, cursor)?, 1, |tx| {
        tx.admit_hold(ReceiveHold {
            sequence,
            admission_key: key,
            class,
            contact_root,
            unrouted_id: unrouted.then_some(key),
            journal: unrouted.then_some(ReceiveHoldJournal {
                source_key: &source_key,
                topic: "message.unrouted",
                body: &body,
                subject: None,
            }),
            at: i64::try_from(sequence).unwrap_or(i64::MAX),
        })
    })
}

#[allow(clippy::too_many_arguments)]
fn put_hold(
    db: &AccountDb,
    cursor: u64,
    sequence: u64,
    class: Class,
    source: Option<&str>,
    contact_root: Option<&str>,
    payload_bytes: usize,
) -> Result<ReceiveHoldResult, StorageError> {
    put_hold_for(db, "e", "admission", cursor, sequence, class, source, contact_root, payload_bytes)
}

#[allow(clippy::too_many_arguments)]
fn put_hold_for(
    db: &AccountDb,
    incarnation: &str,
    key_prefix: &str,
    cursor: u64,
    sequence: u64,
    class: Class,
    source: Option<&str>,
    contact_root: Option<&str>,
    payload_bytes: usize,
) -> Result<ReceiveHoldResult, StorageError> {
    let key = format!("{key_prefix}-{sequence}");
    if let Some(source) = source {
        set_verified_source(db, &key, source)?;
    }
    let wire = entry(sequence, payload_bytes);
    stage_for(db, incarnation, cursor, sequence, &key, &wire)?;
    admit_for(
        db,
        incarnation,
        cursor,
        sequence,
        &key,
        class,
        contact_root,
        class == Class::Unrouted,
    )
}

fn snap(db: &AccountDb) -> Result<Snap, StorageError> {
    fn collect<T>(
        db: &AccountDb,
        sql: &str,
        map: impl FnMut(&crate::database::Row) -> rusqlite::Result<T>,
    ) -> Result<Vec<T>, StorageError> {
        let mut query = db.connection.prepare(sql)?;
        Ok(query.query_map([], map)?.collect::<rusqlite::Result<Vec<_>>>()?)
    }
    let cursor =
        db.projection_checkpoint("gateway_receive_cursor:t")?.unwrap_or_else(|| "0".to_owned());
    Ok(Snap {
        cursor,
        receipts: collect(
            db,
            "SELECT inbox_seq,disposition FROM gateway_receive_receipt WHERE target_delivery_id='t' AND incarnation_id='e' ORDER BY inbox_seq",
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?,
        work: collect(
            db,
            "SELECT inbox_seq,entry_json,admission_key,byte_len FROM gateway_receive_work WHERE target_delivery_id='t' AND incarnation_id='e' ORDER BY inbox_seq",
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )?,
        intents: collect(
            db,
            "SELECT inbox_seq FROM gateway_ack_intent WHERE target_delivery_id='t' AND incarnation_id='e' ORDER BY inbox_seq",
            |row| row.get(0),
        )?,
        unrouted: collect(
            db,
            "SELECT envelope_id,inbox_seq,entry_json FROM runtime_unrouted ORDER BY inbox_seq,envelope_id",
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?,
        policy: collect(
            db,
            "SELECT envelope_key,source,trusted,failure_class,subject FROM runtime_inbox_policy ORDER BY envelope_key",
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
        )?,
        journal: collect(
            db,
            "SELECT source_key,topic,body_json FROM runtime_journal WHERE source_key LIKE 'unrouted:%' OR source_key LIKE 'receive-hold-terminal:%' ORDER BY source_key",
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?,
    })
}

fn reopen(root: &std::path::Path) -> Result<AccountDb, StorageError> {
    AccountDb::open(
        &crate::AccountIndex::open(root)?,
        "acct",
        &crate::AccountDbKey::derive("acct", b"storage-test-secret"),
    )
}

fn admission_child(root: &std::path::Path, mode: &str) -> std::process::ExitStatus {
    std::process::Command::new(std::env::current_exe().expect("test executable"))
        .args(["--exact", "account_db::receive::hold_tests::held_admission_child", "--nocapture"])
        .env("RAMFLUX_HOLD_CHILD_ROOT", root)
        .env("RAMFLUX_HOLD_CHILD_MODE", mode)
        .status()
        .expect("spawn admission child")
}

#[test]
fn held_admission_child() -> Result<(), StorageError> {
    let Some(root) = std::env::var_os("RAMFLUX_HOLD_CHILD_ROOT") else {
        return Ok(());
    };
    let mode = std::env::var("RAMFLUX_HOLD_CHILD_MODE").expect("child mode");
    let db = reopen(std::path::Path::new(&root))?;
    let commit_after = mode == "after";
    let _observer = crate::durability_test_hooks::observe(
        db.path.clone(),
        std::sync::Arc::new(move |sql, completed, autocommit| {
            if sql == "COMMIT" && completed == commit_after {
                assert_eq!(autocommit, commit_after);
                std::process::abort();
            }
            Ok(())
        }),
    )?;
    admit(&db, 0, 1, "admission-one", Class::Unrouted, None, true)?;
    panic!("real outer COMMIT hook did not abort the child")
}

#[test]
#[allow(clippy::too_many_lines)]
fn hold_source_class_quotas() -> Result<(), StorageError> {
    let (root, db) = super::stage_tests::setup("hold-quotas")?;
    let mut cursor = 0;

    // The per-class and per-verified-source ceilings evict the oldest row by WS, not DELETE.
    for sequence in 1..=65 {
        let source = format!("root-unrouted-{sequence}/device");
        let outcome = put_hold(&db, cursor, sequence, Class::Unrouted, Some(&source), None, 32)?;
        assert!(matches!(outcome, ReceiveHoldResult::Held { .. }));
        cursor = sequence;
    }
    let unrouted: i64 =
        db.connection.query_row("SELECT count(*) FROM runtime_unrouted", [], |r| r.get(0))?;
    let held: i64 = db.connection.query_row(
        "SELECT count(*) FROM gateway_receive_receipt WHERE disposition='held'",
        [],
        |r| r.get(0),
    )?;
    let orphaned: i64 = db.connection.query_row(
        "SELECT count(*) FROM gateway_receive_receipt r LEFT JOIN gateway_receive_work w USING(target_delivery_id,incarnation_id,inbox_seq) WHERE r.disposition IN ('held','quarantined') AND w.inbox_seq IS NULL",
        [],
        |r| r.get(0),
    )?;
    assert_eq!(unrouted, 64);
    assert_eq!(held, 64);
    assert_eq!(orphaned, 0);
    let event: i64 = db.connection.query_row(
        "SELECT count(*) FROM runtime_journal WHERE topic='inbox.receive_failure' AND json_extract(CAST(body_json AS TEXT),'$.reason')='held_evicted'",
        [],
        |r| r.get(0),
    )?;
    assert_eq!(event, 1, "oldest eviction has one typed event");
    let first_intent: i64 = db.connection.query_row(
        "SELECT count(*) FROM gateway_ack_intent WHERE inbox_seq=?1",
        params![1u64.to_be_bytes().as_slice()],
        |r| r.get(0),
    )?;
    assert_eq!(first_intent, 1, "WS transfers the reserved slot to an intent");

    // A single verified source also cannot monopolize the unrouted class.
    for sequence in 66..=130 {
        assert!(matches!(
            put_hold(
                &db,
                cursor,
                sequence,
                Class::Unrouted,
                Some("root-single-source/device"),
                None,
                32
            )?,
            ReceiveHoldResult::Held { .. }
        ));
        cursor = sequence;
    }
    let source_unrouted: i64 = db.connection.query_row(
        "SELECT count(*) FROM gateway_receive_work w JOIN gateway_receive_receipt r USING(target_delivery_id,incarnation_id,inbox_seq) JOIN runtime_inbox_policy p ON p.envelope_key=w.admission_key WHERE p.source='root-single-source/device' AND r.disposition='held'",
        [],
        |r| r.get(0),
    )?;
    assert_eq!(source_unrouted, 64);

    // A verified source cannot exceed its 64-row hold budget; distinct roots avoid contact-root
    // eviction masking the source partition.
    for sequence in 131..=195 {
        assert!(matches!(
            put_hold(
                &db,
                cursor,
                sequence,
                Class::Contact,
                Some("root-policy/device"),
                Some(&format!("contact-policy-{sequence}")),
                32
            )?,
            ReceiveHoldResult::Held { .. }
        ));
        cursor = sequence;
    }
    let policy_count: i64 = db.connection.query_row(
        "SELECT count(*) FROM gateway_receive_work w JOIN gateway_receive_receipt r USING(target_delivery_id,incarnation_id,inbox_seq) JOIN runtime_inbox_policy p ON p.envelope_key=w.admission_key WHERE p.source='root-policy/device' AND p.failure_class='receive_hold_contact' AND r.disposition='held'",
        [],
        |r| r.get(0),
    )?;
    assert_eq!(policy_count, 64);

    // Unknown claimed identities share one unverified bucket rather than gaining one quota each.
    for sequence in 196..=260 {
        let outcome = put_hold(
            &db,
            cursor,
            sequence,
            Class::Contact,
            None,
            Some(&format!("contact-root-{sequence}")),
            32,
        )?;
        assert!(matches!(outcome, ReceiveHoldResult::Held { .. }));
        cursor = sequence;
    }
    let contact_count: i64 = db.connection.query_row(
        "SELECT count(*) FROM gateway_receive_work w JOIN gateway_receive_receipt r USING(target_delivery_id,incarnation_id,inbox_seq) JOIN runtime_inbox_policy p ON p.envelope_key=w.admission_key WHERE p.failure_class='receive_hold_contact' AND r.disposition='held'",
        [],
        |r| r.get(0),
    )?;
    assert_eq!(contact_count, 64, "unverified claimed roots share one source bucket");

    // Source-byte pressure evicts the oldest authenticated-source hold at 4 MiB.
    let source = "root-byte/device";
    for sequence in 261..=265 {
        let outcome = put_hold(
            &db,
            cursor,
            sequence,
            Class::Contact,
            Some(source),
            Some(&format!("contact-byte-{sequence}")),
            900_000,
        )?;
        assert!(matches!(outcome, ReceiveHoldResult::Held { .. }));
        cursor = sequence;
    }
    let bytes: i64 = db.connection.query_row(
        "SELECT coalesce(sum(w.byte_len),0) FROM gateway_receive_work w JOIN gateway_receive_receipt r USING(target_delivery_id,incarnation_id,inbox_seq) JOIN runtime_inbox_policy p ON p.envelope_key=w.admission_key WHERE p.source=?1 AND r.disposition='held'",
        params![source],
        |r| r.get(0),
    )?;
    assert!(bytes <= 4 * 1024 * 1024, "source bytes exceed ceiling: {bytes}");
    for sequence in 266..=267 {
        put_hold(
            &db,
            cursor,
            sequence,
            Class::Contact,
            Some(&format!("root-contact-{sequence}/device")),
            Some("same-contact-root"),
            32,
        )?;
        cursor = sequence;
    }
    let same_root: i64 = db.connection.query_row(
        "SELECT count(*) FROM gateway_receive_work w JOIN gateway_receive_receipt r USING(target_delivery_id,incarnation_id,inbox_seq) JOIN runtime_inbox_policy p ON p.envelope_key=w.admission_key WHERE p.failure_class='receive_hold_contact' AND p.subject='same-contact-root' AND r.disposition='held'",
        [],
        |r| r.get(0),
    )?;
    assert_eq!(same_root, 1, "contact admission is isolated to one row per root");

    // A mixed-class pool admits exactly the aggregate 256-row ceiling.
    drop(db);
    std::fs::remove_dir_all(root)?;

    // Byte pressure is independent of the per-source byte limit: distinct verified owners
    // cannot consume more than the 16 MiB aggregate budget.
    let (root, db) = super::stage_tests::setup("hold-aggregate-bytes")?;
    let mut cursor = 0;
    for sequence in 1..=17 {
        let source = format!("root-byte-{sequence}/device");
        assert!(matches!(
            put_hold(&db, cursor, sequence, Class::Policy, Some(&source), None, 1_000_000)?,
            ReceiveHoldResult::Held { .. }
        ));
        cursor = sequence;
    }
    let total_bytes: i64 = db.connection.query_row(
        "SELECT coalesce(sum(w.byte_len),0) FROM gateway_receive_work w JOIN gateway_receive_receipt r USING(target_delivery_id,incarnation_id,inbox_seq) WHERE r.disposition='held'",
        [],
        |r| r.get(0),
    )?;
    assert!(total_bytes <= 16 * 1024 * 1024, "aggregate bytes exceed ceiling: {total_bytes}");
    drop(db);
    std::fs::remove_dir_all(root)?;

    let (root, db) = super::stage_tests::setup("hold-global-quotas")?;
    let mut cursor = 0;
    for sequence in 1..=256 {
        let (class, source) = if sequence <= 64 {
            (Class::Unrouted, format!("root-u-{sequence}/device"))
        } else if sequence <= 128 {
            (Class::Contact, format!("root-c-{sequence}/device"))
        } else {
            (Class::Policy, format!("root-p-{sequence}/device"))
        };
        let root_key = format!("root-{sequence}");
        assert!(matches!(
            put_hold(
                &db,
                cursor,
                sequence,
                class,
                Some(&source),
                (class == Class::Contact).then_some(root_key.as_str()),
                32
            )?,
            ReceiveHoldResult::Held { .. }
        ));
        cursor = sequence;
    }
    let count: i64 = db.connection.query_row(
        "SELECT count(*) FROM gateway_receive_receipt WHERE disposition='held'",
        [],
        |r| r.get(0),
    )?;
    assert_eq!(count, 256);
    let result = put_hold(&db, cursor, 257, Class::Policy, Some("root-last/device"), None, 32)?;
    assert!(matches!(
        result,
        ReceiveHoldResult::Held { evicted } if evicted == vec![129]
    ));
    let count: i64 = db.connection.query_row(
        "SELECT count(*) FROM gateway_receive_receipt WHERE disposition='held'",
        [],
        |r| r.get(0),
    )?;
    assert_eq!(count, 256, "a full policy class evicts only within that class");
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn hold_quotas_count_retired_incarnation_rows() -> Result<(), StorageError> {
    retired_count_ceiling()?;
    retired_byte_ceiling()?;
    Ok(())
}

fn retire_active_incarnation(db: &AccountDb) -> Result<(), StorageError> {
    db.connection.execute(
        "UPDATE gateway_receive_epoch
         SET incarnation_id='e2', retired_incarnations=?1
         WHERE target_delivery_id='t'",
        params![serde_json::to_vec(&["e"])?],
    )?;
    db.set_projection_checkpoint("gateway_receive_cursor:t", "0")?;
    Ok(())
}

fn fill_retired_count_fixture(db: &AccountDb) -> Result<u64, StorageError> {
    assert!(matches!(
        put_hold(db, 0, 1, Class::Contact, Some("old-source/device"), Some("old-root"), 32)?,
        ReceiveHoldResult::Held { .. }
    ));
    retire_active_incarnation(db)?;
    let mut cursor = 0;
    for sequence in 1..=64 {
        put_hold_for(
            db,
            "e2",
            "new-unrouted",
            cursor,
            sequence,
            Class::Unrouted,
            Some(&format!("new-u-{sequence}/device")),
            None,
            32,
        )?;
        cursor = sequence;
    }
    for sequence in 65..=127 {
        put_hold_for(
            db,
            "e2",
            "new-contact",
            cursor,
            sequence,
            Class::Contact,
            Some(&format!("new-c-{sequence}/device")),
            Some(&format!("new-root-{sequence}")),
            32,
        )?;
        cursor = sequence;
    }
    for sequence in 128..=255 {
        put_hold_for(
            db,
            "e2",
            "new-policy",
            cursor,
            sequence,
            Class::Policy,
            Some(&format!("new-p-{sequence}/device")),
            None,
            32,
        )?;
        cursor = sequence;
    }
    Ok(cursor)
}

fn retired_count_ceiling() -> Result<(), StorageError> {
    let (root, db) = super::stage_tests::setup("hold-retired-target-count")?;
    let cursor = fill_retired_count_fixture(&db)?;
    let count: i64 = db.connection.query_row(
        "SELECT count(*) FROM gateway_receive_receipt WHERE target_delivery_id='t' AND disposition='held'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(count, 256, "the retired hold consumes the target-wide slot");
    assert_eq!(
        put_hold_for(
            &db,
            "e2",
            "new-contact",
            cursor,
            256,
            Class::Contact,
            Some("new-candidate/device"),
            Some("new-candidate-root"),
            32,
        )?,
        ReceiveHoldResult::Held { evicted: vec![1] },
        "oldest retired hold is evicted through WS to admit at the target-wide ceiling"
    );
    let old_work: i64 = db.connection.query_row(
        "SELECT count(*) FROM gateway_receive_work WHERE target_delivery_id='t' AND incarnation_id='e'",
        [],
        |row| row.get(0),
    )?;
    let old_intents: i64 = db.connection.query_row(
        "SELECT count(*) FROM gateway_ack_intent WHERE target_delivery_id='t' AND incarnation_id='e'",
        [],
        |row| row.get(0),
    )?;
    let old_event: i64 = db.connection.query_row(
        "SELECT count(*) FROM runtime_journal WHERE topic='inbox.receive_failure'
           AND json_extract(CAST(body_json AS TEXT),'$.incarnation_id')='e'
           AND json_extract(CAST(body_json AS TEXT),'$.reason')='held_evicted'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(old_work, 0, "retired eviction removes retained work");
    assert_eq!(old_intents, 0, "retired-E cleanup must not create an ACK intent");
    assert_eq!(old_event, 1, "the typed eviction event names its retired incarnation");
    let count: i64 = db.connection.query_row(
        "SELECT count(*) FROM gateway_receive_receipt WHERE target_delivery_id='t' AND disposition='held'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(count, 256);
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

fn retired_byte_ceiling() -> Result<(), StorageError> {
    let (root, db) = super::stage_tests::setup("hold-retired-target-bytes")?;
    put_hold(&db, 0, 1, Class::Policy, Some("old-byte-source/device"), None, 1_000_000)?;
    retire_active_incarnation(&db)?;
    let mut cursor = 0;
    for sequence in 1..=15 {
        put_hold_for(
            &db,
            "e2",
            "new-byte-policy",
            cursor,
            sequence,
            Class::Policy,
            Some(&format!("new-byte-{sequence}/device")),
            None,
            1_000_000,
        )?;
        cursor = sequence;
    }
    let outcome = put_hold_for(
        &db,
        "e2",
        "new-byte-policy",
        cursor,
        16,
        Class::Policy,
        Some("new-byte-candidate/device"),
        None,
        1_000_000,
    )?;
    assert_eq!(outcome, ReceiveHoldResult::Held { evicted: vec![1] });
    let held_bytes: i64 = db.connection.query_row(
        "SELECT coalesce(sum(w.byte_len),0) FROM gateway_receive_work w
         JOIN gateway_receive_receipt r USING(target_delivery_id,incarnation_id,inbox_seq)
         WHERE w.target_delivery_id='t' AND r.disposition='held'",
        [],
        |row| row.get(0),
    )?;
    assert!(
        held_bytes <= 16 * 1024 * 1024,
        "retired-E bytes count toward the target cap: {held_bytes}"
    );
    let old_intents: i64 = db.connection.query_row(
        "SELECT count(*) FROM gateway_ack_intent WHERE target_delivery_id='t' AND incarnation_id='e'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(old_intents, 0, "byte-pressure cleanup of retired E does not ACK");
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn held_admission_stage_crash() -> Result<(), StorageError> {
    let (root, db) = super::stage_tests::setup("held-admission-crash")?;
    let wire = entry(1, 32);
    stage(&db, 0, 1, "admission-one", &wire)?;
    let w0 = snap(&db)?;
    let fault = super::hold::run(|| admit(&db, 0, 1, "admission-one", Class::Unrouted, None, true));
    assert!(matches!(fault, Err(StorageError::Integrity("receive hold before-commit"))));
    assert_eq!(snap(&db)?, w0, "before outer COMMIT preserves W0 and no partial hold");
    drop(db);
    let db = reopen(&root)?;
    assert_eq!(snap(&db)?, w0, "W0 survives a real database reopen after the cut");
    drop(db);
    assert!(!admission_child(&root, "before").success(), "before-COMMIT child must die");
    let db = reopen(&root)?;
    assert_eq!(snap(&db)?, w0, "process death before COMMIT leaves only W0");
    drop(db);
    assert!(!admission_child(&root, "after").success(), "after-COMMIT child must die");
    let db = reopen(&root)?;
    let committed = snap(&db)?;
    assert_eq!(committed.cursor, "1");
    assert_eq!(committed.receipts, vec![(1u64.to_be_bytes().to_vec(), "held".into())]);
    assert_eq!(committed.work.len(), 1, "held receipt always has recovery work");
    assert_eq!(committed.unrouted.len(), 1);
    assert_eq!(committed.journal.len(), 1, "one unique unrouted journal effect");
    drop(db);
    let db = reopen(&root)?;
    assert_eq!(snap(&db)?, committed, "post-commit reopen observes the complete admission");
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn staged_hold_has_work_and_receipt() -> Result<(), StorageError> {
    let (root, db) = super::stage_tests::setup("held-work-pair")?;
    let wire = entry(1, 32);
    stage(&db, 0, 1, "admission-one", &wire)?;
    assert!(matches!(
        admit(&db, 0, 1, "admission-one", Class::Unrouted, None, true)?,
        ReceiveHoldResult::Held { .. }
    ));
    let pair: i64 = db.connection.query_row(
        "SELECT count(*) FROM gateway_receive_receipt r JOIN gateway_receive_work w USING(target_delivery_id,incarnation_id,inbox_seq) WHERE r.disposition='held'",
        [],
        |r| r.get(0),
    )?;
    assert_eq!(pair, 1);
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

fn journal_terminal_keys(db: &AccountDb) -> Result<Vec<String>, StorageError> {
    let mut query = db.connection.prepare(
        "SELECT source_key FROM runtime_journal
         WHERE topic='inbox.receive_failure' ORDER BY source_key",
    )?;
    Ok(query.query_map([], |row| row.get(0))?.collect::<rusqlite::Result<Vec<_>>>()?)
}

fn set_work_bytes(
    db: &AccountDb,
    incarnation: &str,
    sequence: u64,
    bytes: i64,
) -> Result<(), StorageError> {
    db.connection.execute(
        "UPDATE gateway_receive_work SET entry_json=zeroblob(?1),byte_len=?1
         WHERE target_delivery_id='t' AND incarnation_id=?2 AND inbox_seq=?3",
        params![bytes, incarnation, sequence.to_be_bytes().as_slice()],
    )?;
    Ok(())
}

#[test]
fn evicted_journal_uses_row_incarnation() -> Result<(), StorageError> {
    let (root, db) = super::stage_tests::setup("hold-evict-incarnation")?;
    assert!(matches!(
        put_hold(&db, 0, 1, Class::Unrouted, Some("old-u/device"), None, 32)?,
        ReceiveHoldResult::Held { .. }
    ));
    retire_active_incarnation(&db)?;
    let mut cursor = 0;
    for sequence in 1..=65 {
        put_hold_for(
            &db,
            "e2",
            "new-u",
            cursor,
            sequence,
            Class::Unrouted,
            Some(&format!("new-u-{sequence}/device")),
            None,
            32,
        )?;
        cursor = sequence;
    }
    let keys = journal_terminal_keys(&db)?;
    assert_eq!(keys.len(), 2);
    assert!(keys.contains(&"receive-hold-terminal:t:e:1".to_owned()));
    assert!(keys.contains(&"receive-hold-terminal:t:e2:1".to_owned()));
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn evict_retired_unrouted_keeps_live_redelivery() -> Result<(), StorageError> {
    let (root, db) = super::stage_tests::setup("hold-unrouted-redeliver")?;
    let wire = entry(1, 32);
    stage(&db, 0, 1, "shared", &wire)?;
    set_verified_source(&db, "shared", "old-src/device")?;
    assert!(matches!(
        admit(&db, 0, 1, "shared", Class::Unrouted, None, true)?,
        ReceiveHoldResult::Held { .. }
    ));
    db.connection
        .execute("UPDATE gateway_receive_receipt SET first_seen=0 WHERE incarnation_id='e'", [])?;
    retire_active_incarnation(&db)?;
    let live = entry(1, 32);
    stage_for(&db, "e2", 0, 1, "shared", &live)?;
    assert!(matches!(
        admit_for(&db, "e2", 0, 1, "shared", Class::Unrouted, None, true)?,
        ReceiveHoldResult::Held { .. }
    ));
    let mut cursor = 1;
    for sequence in 2u64..=64 {
        put_hold_for(
            &db,
            "e2",
            "fill",
            cursor,
            sequence,
            Class::Unrouted,
            Some(&format!("fill-{sequence}/device")),
            None,
            32,
        )?;
        cursor = sequence;
    }
    let unrouted: i64 = db.connection.query_row(
        "SELECT count(*) FROM runtime_unrouted WHERE envelope_id='shared'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(unrouted, 1, "live redelivery keeps the unrouted row");
    let live_work: i64 = db.connection.query_row(
        "SELECT count(*) FROM gateway_receive_work WHERE admission_key='shared' AND incarnation_id='e2'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(live_work, 1);
    let old_work: i64 = db.connection.query_row(
        "SELECT count(*) FROM gateway_receive_work WHERE admission_key='shared' AND incarnation_id='e'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(old_work, 0, "retired copy was evicted");
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn hold_admission_refuses_each_identity_error() -> Result<(), StorageError> {
    let (root, db) = super::stage_tests::setup("hold-identity-errors")?;
    let wire = entry(1, 32);
    stage(&db, 0, 1, "admission-one", &wire)?;
    let identity = db.receive_transaction(expect_for(&db, "e", 0)?, 1, |tx| {
        tx.admit_hold(ReceiveHold {
            sequence: 0,
            admission_key: "admission-one",
            class: Class::Unrouted,
            contact_root: None,
            unrouted_id: None,
            journal: None,
            at: 1,
        })
    });
    assert!(matches!(identity, Err(StorageError::Integrity("receive hold identity missing"))));
    let empty = db.receive_transaction(expect_for(&db, "e", 0)?, 1, |tx| {
        tx.admit_hold(ReceiveHold {
            sequence: 1,
            admission_key: "",
            class: Class::Unrouted,
            contact_root: None,
            unrouted_id: None,
            journal: None,
            at: 1,
        })
    });
    assert!(matches!(empty, Err(StorageError::Integrity("receive hold identity missing"))));
    let root_missing = db.receive_transaction(expect_for(&db, "e", 0)?, 1, |tx| {
        tx.admit_hold(ReceiveHold {
            sequence: 1,
            admission_key: "admission-one",
            class: Class::Contact,
            contact_root: None,
            unrouted_id: None,
            journal: None,
            at: 1,
        })
    });
    assert!(matches!(root_missing, Err(StorageError::Integrity("contact hold root missing"))));
    let staged = db.receive_transaction(expect_for(&db, "e", 0)?, 1, |tx| {
        tx.admit_hold(ReceiveHold {
            sequence: 2,
            admission_key: "missing",
            class: Class::Unrouted,
            contact_root: None,
            unrouted_id: None,
            journal: None,
            at: 1,
        })
    });
    assert!(matches!(staged, Err(StorageError::Integrity("hold requires staged work"))));
    let key = db.receive_transaction(expect_for(&db, "e", 0)?, 1, |tx| {
        tx.admit_hold(ReceiveHold {
            sequence: 1,
            admission_key: "other-key",
            class: Class::Unrouted,
            contact_root: None,
            unrouted_id: None,
            journal: None,
            at: 1,
        })
    });
    assert!(matches!(key, Err(StorageError::Integrity("hold admission key differs from W0"))));
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn hold_pauses_when_no_evictable_candidate() -> Result<(), StorageError> {
    let (root, db) = super::stage_tests::setup("hold-paused")?;
    for sequence in 2u64..=65 {
        let seq = sequence.to_be_bytes();
        let key = format!("seed-{sequence}");
        let wire = entry(sequence, 32);
        db.connection.execute(
            "INSERT INTO gateway_receive_receipt VALUES('t','e',?1,'held',604801,?2)",
            params![seq.as_slice(), i64::try_from(sequence).unwrap_or(i64::MAX)],
        )?;
        db.connection.execute(
            "INSERT INTO gateway_receive_work VALUES('t','e',?1,?2,?3,?4)",
            params![seq.as_slice(), &wire, key, i64::try_from(wire.len()).unwrap_or(i64::MAX)],
        )?;
        db.connection.execute(
            "INSERT INTO runtime_unrouted VALUES(?1,?2,?3,?4)",
            params![key, sequence, &wire, i64::try_from(sequence).unwrap_or(i64::MAX)],
        )?;
    }
    let wire = entry(1, 32);
    stage(&db, 0, 1, "admission-one", &wire)?;
    let w0 = snap(&db)?;
    let paused = admit(&db, 0, 1, "admission-one", Class::Unrouted, None, true)?;
    assert_eq!(paused, ReceiveHoldResult::Paused);
    assert_eq!(snap(&db)?, w0, "Paused leaves staged W0 unchanged");
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn hold_byte_boundaries_are_inclusive() -> Result<(), StorageError> {
    const SOURCE: i64 = 4 * 1024 * 1024;
    const AGGREGATE: i64 = 16 * 1024 * 1024;
    let (root, db) = super::stage_tests::setup("hold-source-bytes")?;
    let wire = entry(1, 32);
    stage(&db, 0, 1, "src-exact", &wire)?;
    set_verified_source(&db, "src-exact", "root-src/device")?;
    set_work_bytes(&db, "e", 1, SOURCE)?;
    assert!(matches!(
        admit(&db, 0, 1, "src-exact", Class::Policy, None, false)?,
        ReceiveHoldResult::Held { .. }
    ));
    let bytes: i64 = db.connection.query_row(
        "SELECT coalesce(sum(w.byte_len),0) FROM gateway_receive_work w
         JOIN gateway_receive_receipt r USING(target_delivery_id,incarnation_id,inbox_seq)
         WHERE r.disposition='held'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(bytes, SOURCE);
    drop(db);
    std::fs::remove_dir_all(root)?;

    let (root, db) = super::stage_tests::setup("hold-source-over")?;
    let wire = entry(1, 32);
    stage(&db, 0, 1, "src-over", &wire)?;
    set_verified_source(&db, "src-over", "root-src/device")?;
    set_work_bytes(&db, "e", 1, SOURCE + 1)?;
    let w0 = snap(&db)?;
    assert_eq!(
        admit(&db, 0, 1, "src-over", Class::Policy, None, false)?,
        ReceiveHoldResult::Paused
    );
    assert_eq!(snap(&db)?, w0);
    drop(db);
    std::fs::remove_dir_all(root)?;

    let (root, db) = super::stage_tests::setup("hold-aggregate-bytes-exact")?;
    let mut cursor = 0;
    for sequence in 1..=4 {
        let key = format!("agg-{sequence}");
        let source = format!("root-agg-{sequence}/device");
        let wire = entry(sequence, 32);
        stage(&db, cursor, sequence, &key, &wire)?;
        set_verified_source(&db, &key, &source)?;
        set_work_bytes(&db, "e", sequence, SOURCE)?;
        assert!(matches!(
            admit(&db, cursor, sequence, &key, Class::Policy, None, false)?,
            ReceiveHoldResult::Held { .. }
        ));
        cursor = sequence;
    }
    let total: i64 = db.connection.query_row(
        "SELECT coalesce(sum(w.byte_len),0) FROM gateway_receive_work w
         JOIN gateway_receive_receipt r USING(target_delivery_id,incarnation_id,inbox_seq)
         WHERE r.disposition='held'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(total, AGGREGATE);
    drop(db);
    std::fs::remove_dir_all(root)?;

    let (root, db) = super::stage_tests::setup("hold-aggregate-over")?;
    let mut cursor = 0;
    for sequence in 1..=4 {
        let key = format!("agg-{sequence}");
        let source = format!("root-agg-{sequence}/device");
        let wire = entry(sequence, 32);
        stage(&db, cursor, sequence, &key, &wire)?;
        set_verified_source(&db, &key, &source)?;
        set_work_bytes(&db, "e", sequence, SOURCE)?;
        assert!(matches!(
            admit(&db, cursor, sequence, &key, Class::Policy, None, false)?,
            ReceiveHoldResult::Held { .. }
        ));
        cursor = sequence;
    }
    let wire = entry(5, 32);
    stage(&db, cursor, 5, "agg-5", &wire)?;
    set_verified_source(&db, "agg-5", "root-agg-5/device")?;
    set_work_bytes(&db, "e", 5, 1)?;
    assert!(matches!(
        admit(&db, cursor, 5, "agg-5", Class::Policy, None, false)?,
        ReceiveHoldResult::Held { evicted } if evicted == vec![1]
    ));
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn policy_hold_eviction_drops_retry() -> Result<(), StorageError> {
    let (root, db) = super::stage_tests::setup("hold-policy-retry-evict")?;
    let source = "root-pol/device";
    let wire = entry(1, 32);
    stage(&db, 0, 1, "admission-1", &wire)?;
    set_verified_source(&db, "admission-1", source)?;
    assert!(matches!(
        admit(&db, 0, 1, "admission-1", Class::Policy, None, false)?,
        ReceiveHoldResult::Held { .. }
    ));
    db.defer_inbox_entry("admission-1", &wire, 1)?;
    assert_eq!(
        db.connection.query_row(
            "SELECT count(*) FROM runtime_inbox_retry WHERE envelope_key='admission-1'",
            [],
            |row| row.get::<_, i64>(0),
        )?,
        1
    );
    let mut cursor = 1u64;
    for sequence in 2..=8 {
        assert!(matches!(
            put_hold(&db, cursor, sequence, Class::Policy, Some(source), None, 32)?,
            ReceiveHoldResult::Held { .. }
        ));
        cursor = sequence;
    }
    assert!(matches!(
        put_hold(&db, cursor, 9, Class::Policy, Some(source), None, 32)?,
        ReceiveHoldResult::Held { evicted } if evicted == vec![1]
    ));
    let retry: i64 = db.connection.query_row(
        "SELECT count(*) FROM runtime_inbox_retry WHERE envelope_key='admission-1'",
        [],
        |row| row.get(0),
    )?;
    let policy: i64 = db.connection.query_row(
        "SELECT count(*) FROM runtime_inbox_policy WHERE envelope_key='admission-1'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(retry, 0, "evicted policy hold drops its retry row");
    assert_eq!(policy, 0, "evicted policy hold drops its policy row");
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn policy_hold_eviction_keeps_retry_on_live_redelivery() -> Result<(), StorageError> {
    let source = "root-pol/device";
    let (root, db) = super::stage_tests::setup("hold-policy-retry-keep")?;
    let wire = entry(1, 32);
    stage(&db, 0, 1, "shared", &wire)?;
    set_verified_source(&db, "shared", source)?;
    assert!(matches!(
        admit(&db, 0, 1, "shared", Class::Policy, None, false)?,
        ReceiveHoldResult::Held { .. }
    ));
    db.defer_inbox_entry("shared", &wire, 1)?;
    db.connection
        .execute("UPDATE gateway_receive_receipt SET first_seen=0 WHERE incarnation_id='e'", [])?;
    retire_active_incarnation(&db)?;
    let live = entry(1, 32);
    stage_for(&db, "e2", 0, 1, "shared", &live)?;
    assert!(matches!(
        admit_for(&db, "e2", 0, 1, "shared", Class::Policy, None, false)?,
        ReceiveHoldResult::Held { .. }
    ));
    let mut cursor = 1u64;
    for sequence in 2..=7 {
        assert!(matches!(
            put_hold_for(
                &db,
                "e2",
                "fill",
                cursor,
                sequence,
                Class::Policy,
                Some(source),
                None,
                32
            )?,
            ReceiveHoldResult::Held { evicted } if evicted.is_empty()
        ));
        cursor = sequence;
    }
    assert!(matches!(
        put_hold_for(&db, "e2", "fill", cursor, 8, Class::Policy, Some(source), None, 32)?,
        ReceiveHoldResult::Held { evicted } if evicted == vec![1]
    ));
    let retry: i64 = db.connection.query_row(
        "SELECT count(*) FROM runtime_inbox_retry WHERE envelope_key='shared'",
        [],
        |row| row.get(0),
    )?;
    let policy: i64 = db.connection.query_row(
        "SELECT count(*) FROM runtime_inbox_policy WHERE envelope_key='shared'",
        [],
        |row| row.get(0),
    )?;
    let old: i64 = db.connection.query_row(
        "SELECT count(*) FROM gateway_receive_work WHERE admission_key='shared' AND incarnation_id='e'",
        [],
        |row| row.get(0),
    )?;
    let live_work: i64 = db.connection.query_row(
        "SELECT count(*) FROM gateway_receive_work WHERE admission_key='shared' AND incarnation_id='e2'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(old, 0, "retired policy hold was evicted");
    assert_eq!(live_work, 1);
    assert_eq!(retry, 1, "live redelivery keeps the retry row");
    assert_eq!(policy, 1, "live redelivery keeps the policy row");
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}
