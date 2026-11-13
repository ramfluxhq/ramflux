// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Algebraic properties of the restore join and its effect on real encrypted backup merges.
use super::*;
use crate::{AccountDb, RawInnerCopyKind, RawInnerCopyWrite};
use serde_json::json;
use std::path::PathBuf;
type TestResult = Result<(), Box<dyn std::error::Error>>;

fn pair(revision: u64, event: u8) -> EditPair {
    EditPair { revision, event_id: vec![event; 16] }
}

fn copy(name: &str) -> RetainedCopy {
    ("actor".into(), name.into())
}

/// Every state over four register values and all subsets of two openings, plus erasure.
fn universe() -> Vec<RestoreMessage> {
    let mut states = vec![RestoreMessage::Erased];
    for edit in [None, Some(pair(1, 1)), Some(pair(1, 2)), Some(pair(2, 0))] {
        for mask in 0_u8..4 {
            let mut openings = BTreeSet::new();
            if mask & 1 != 0 {
                openings.insert(copy("first-recipient-opening"));
            }
            if mask & 2 != 0 {
                openings.insert(copy("second-recipient-opening"));
            }
            states.push(RestoreMessage::Live { edit: edit.clone(), openings });
        }
    }
    states
}

#[test]
fn edit_restore_merge_is_commutative() {
    for left in universe() {
        for right in universe() {
            assert_eq!(merge(&left, &right), merge(&right, &left), "{left:?} / {right:?}");
        }
    }
}

#[test]
fn edit_restore_merge_is_associative() {
    let states = universe();
    for first in &states {
        for second in &states {
            for third in &states {
                assert_eq!(
                    merge(&merge(first, second), third),
                    merge(first, &merge(second, third)),
                    "{first:?} / {second:?} / {third:?}"
                );
            }
        }
    }
}

#[test]
fn edit_restore_merge_is_idempotent() {
    for state in universe() {
        assert_eq!(merge(&state, &state), state);
        for other in universe() {
            let joined = merge(&state, &other);
            assert_eq!(merge(&joined, &other), joined, "absorbing a merged copy again");
        }
    }
}

#[test]
fn edit_restore_erasure_dominates_every_revision_and_opening() {
    for state in universe() {
        assert_eq!(merge(&state, &RestoreMessage::Erased), RestoreMessage::Erased);
        assert_eq!(merge(&RestoreMessage::Erased, &state), RestoreMessage::Erased);
    }
}

#[test]
fn edit_restore_winner_is_greatest_revision_then_raw_event_id() {
    let live = |edit: Option<EditPair>, name: &str| RestoreMessage::Live {
        edit,
        openings: BTreeSet::from([copy(name)]),
    };
    // An equal revision is decided by the raw event id, never by which copy is local.
    assert_eq!(
        merge(&live(Some(pair(2, 1)), "low"), &live(Some(pair(2, 9)), "high")),
        live(Some(pair(2, 9)), "high")
    );
    assert_eq!(
        merge(&live(Some(pair(2, 9)), "high"), &live(Some(pair(2, 1)), "low")),
        live(Some(pair(2, 9)), "high")
    );
    // A greater revision beats any event id; an Edit beats the unedited original.
    assert_eq!(
        merge(&live(Some(pair(3, 0)), "new"), &live(Some(pair(2, 255)), "old")),
        live(Some(pair(3, 0)), "new")
    );
    assert_eq!(
        merge(&live(None, "original"), &live(Some(pair(1, 0)), "edit")),
        live(Some(pair(1, 0)), "edit")
    );
    // A shorter raw id that is a prefix orders below the longer one, exactly as byte slices do.
    let short = Some(EditPair { revision: 4, event_id: vec![7] });
    let long = Some(EditPair { revision: 4, event_id: vec![7, 0] });
    assert_eq!(merge(&live(short, "short"), &live(long.clone(), "long")), live(long, "long"));
}

#[test]
fn edit_restore_unions_openings_only_for_the_same_winner() {
    let live = |edit: Option<EditPair>, names: &[&str]| RestoreMessage::Live {
        edit,
        openings: names.iter().map(|name| copy(name)).collect(),
    };
    assert_eq!(
        merge(&live(Some(pair(5, 5)), &["phone"]), &live(Some(pair(5, 5)), &["tablet"])),
        live(Some(pair(5, 5)), &["phone", "tablet"])
    );
    assert_eq!(
        merge(&live(Some(pair(5, 5)), &["phone"]), &live(Some(pair(4, 9)), &["stale"])),
        live(Some(pair(5, 5)), &["phone"]),
        "an opening of a losing revision must not survive"
    );
    assert_eq!(
        merge(&live(None, &["phone"]), &live(None, &["tablet"])),
        live(None, &["phone", "tablet"])
    );
}

struct Side {
    root: PathBuf,
    db: AccountDb,
    _guard: crate::tests::TestDirGuard,
}

fn edited_copy(
    name: &str,
    body: &[u8],
    revision: u64,
    event: u8,
) -> Result<Side, Box<dyn std::error::Error>> {
    let (root, db) = crate::tests::test_db(name)?;
    let root_guard = crate::tests::TestDirGuard(root.clone());
    db.send_direct_message("conversation", "target", "peer", b"original body")?;
    db.replace_generated_message_content(
        "conversation",
        "target",
        body,
        &crate::MessageMetadata::default(),
    )?;
    db.persist_message_actor_state(
        "target",
        "routed/edit-revision/target",
        &json!({"revision":revision,"event_id":vec![event; 16]}),
    )?;
    db.persist_message_actor_state(
        "target",
        "routed/current-edit-proof/target",
        &json!({"proof_of":body}),
    )?;
    db.persist_message_actor_state("target", "routed/report-opening-retired/target", &true)?;
    db.write_transaction(|| {
        db.put_unsupported_raw_copy(RawInnerCopyWrite {
            owner_id: "target",
            verified_source_anchor: "verified-source",
            copy_id: "history/current-edit/target",
            kind: RawInnerCopyKind::HistoryContainer,
            bytes: body,
            bounded_metadata: &[],
        })
    })?;
    Ok(Side { root, db, _guard: root_guard })
}

/// Merge `incoming` into a private generation of `local`; returns the merged generation.
fn restore(local: &Side, incoming: &Side) -> Result<BackupDatabase, Box<dyn std::error::Error>> {
    let archive = incoming.root.join("incoming.db");
    let first = incoming.db.write_backup_snapshot(&archive)?;
    let path = local.root.join("merged.db");
    let second = local.db.write_backup_snapshot(&path)?;
    let mut merged = BackupDatabase::open(&path, &second.key)?;
    merged.merge_backup(&archive, &first.key, || Ok(()))?;
    Ok(merged)
}

fn register(merged: &BackupDatabase) -> Result<Option<EditPair>, Box<dyn std::error::Error>> {
    let bytes: Option<Vec<u8>> = merged
        .db
        .query_row(
            "SELECT state_json FROM runtime_actor_state WHERE state_kind='routed/edit-revision/target'",
            [],
            |row| row.get(0),
        )
        .optional()?;
    Ok(bytes.map(|bytes| serde_json::from_slice(&bytes)).transpose()?)
}

fn body(merged: &BackupDatabase) -> Result<Option<Vec<u8>>, Box<dyn std::error::Error>> {
    Ok(merged
        .db
        .query_row(
            "SELECT encrypted_body FROM direct_message_projection WHERE message_id='target' AND deleted=0",
            [],
            |row| row.get(0),
        )
        .optional()?)
}

/// No table of the merged generation may still hold the losing revision's bytes.
fn absent_everywhere(merged: &BackupDatabase, needle: &[u8]) -> TestResult {
    let tables = {
        let mut query = merged.db.prepare(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'",
        )?;
        query.query_map([], |row| row.get::<_, String>(0))?.collect::<rusqlite::Result<Vec<_>>>()?
    };
    for table in tables {
        let columns = {
            let mut query = merged.db.prepare(&format!("PRAGMA table_info(\"{table}\")"))?;
            query
                .query_map([], |row| row.get::<_, String>(1))?
                .collect::<rusqlite::Result<Vec<_>>>()?
        };
        for column in columns {
            let found: bool = merged.db.query_row(
                &format!(
                    "SELECT EXISTS(SELECT 1 FROM \"{table}\" WHERE instr(CAST(\"{column}\" AS BLOB),?1)>0)"
                ),
                [needle],
                |row| row.get(0),
            )?;
            assert!(!found, "losing revision bytes survive in {table}.{column}");
        }
    }
    Ok(())
}

fn finish(merged: BackupDatabase, copies: [Side; 2]) {
    drop(merged);
    drop(copies);
}

#[test]
fn restored_equal_revision_edit_takes_greater_event_id_in_both_directions() -> TestResult {
    for incoming_wins in [true, false] {
        let low = edited_copy("edit-restore-low", b"losing-edit-body-canary", 2, 1)?;
        let high = edited_copy("edit-restore-high", b"winning-edit-body", 2, 9)?;
        let merged = if incoming_wins { restore(&low, &high)? } else { restore(&high, &low)? };
        assert_eq!(register(&merged)?, Some(pair(2, 9)), "incoming_wins={incoming_wins}");
        assert_eq!(body(&merged)?.as_deref(), Some(b"winning-edit-body".as_slice()));
        let raw: Vec<u8> = merged.db.query_row(
            "SELECT raw_bytes FROM raw_inner_copy WHERE copy_id='history/current-edit/target'",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(raw, b"winning-edit-body");
        absent_everywhere(&merged, b"losing-edit-body-canary")?;
        finish(merged, [low, high]);
    }
    Ok(())
}

#[test]
fn restored_older_edit_never_replaces_local_winner_or_revives_its_openings() -> TestResult {
    let local = edited_copy("edit-restore-newer", b"current-edit-body", 7, 0)?;
    let archive = edited_copy("edit-restore-older", b"stale-edit-body-canary", 6, 255)?;
    archive.db.persist_message_actor_state(
        "target",
        "routed/origin-evidence/target",
        &json!({"opening":"stale-edit-body-canary"}),
    )?;
    let merged = restore(&local, &archive)?;
    assert_eq!(register(&merged)?, Some(pair(7, 0)));
    assert_eq!(body(&merged)?.as_deref(), Some(b"current-edit-body".as_slice()));
    absent_everywhere(&merged, b"stale-edit-body-canary")?;
    finish(merged, [local, archive]);
    Ok(())
}

#[test]
fn restored_edit_retires_unedited_local_original_and_its_evidence() -> TestResult {
    let (root, db) = crate::tests::test_db("edit-restore-original")?;
    let root_guard = crate::tests::TestDirGuard(root.clone());
    db.send_direct_message("conversation", "target", "peer", b"original-body-canary")?;
    db.persist_message_actor_state(
        "target",
        "routed/origin-evidence/target",
        &json!({"opening":"original-body-canary"}),
    )?;
    let local = Side { root, db, _guard: root_guard };
    let archive = edited_copy("edit-restore-edited", b"edited-body", 1, 3)?;
    let merged = restore(&local, &archive)?;
    assert_eq!(register(&merged)?, Some(pair(1, 3)));
    assert_eq!(body(&merged)?.as_deref(), Some(b"edited-body".as_slice()));
    let retired: Vec<u8> = merged.db.query_row(
        "SELECT state_json FROM runtime_actor_state WHERE state_kind='routed/report-opening-retired/target'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(retired, b"true");
    absent_everywhere(&merged, b"original-body-canary")?;
    finish(merged, [local, archive]);
    Ok(())
}

#[test]
fn restore_erasure_dominates_edit_in_both_directions() -> TestResult {
    for local_erased in [true, false] {
        let erased = edited_copy("edit-restore-erased", b"erased-side-body-canary", 9, 9)?;
        erased.db.delete_direct_message("conversation", "target", "local", "erase-target")?;
        let live = edited_copy("edit-restore-live", b"live-side-body-canary", 10, 1)?;
        let merged = if local_erased { restore(&erased, &live)? } else { restore(&live, &erased)? };
        assert_eq!(register(&merged)?, None, "local_erased={local_erased}");
        assert_eq!(body(&merged)?, None);
        for canary in [b"erased-side-body-canary".as_slice(), b"live-side-body-canary".as_slice()] {
            absent_everywhere(&merged, canary)?;
        }
        let proofs: i64 = merged.db.query_row(
            "SELECT count(*) FROM runtime_actor_state WHERE state_kind IN ('routed/current-edit-proof/target','routed/origin-evidence/target','routed/original-header/target')",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(proofs, 0);
        finish(merged, [erased, live]);
    }
    Ok(())
}

#[test]
fn restored_same_winner_unions_distinct_openings_and_keeps_one_named_copy() -> TestResult {
    let local = edited_copy("edit-restore-union-local", b"shared-edit-body", 4, 4)?;
    let archive = edited_copy("edit-restore-union-archive", b"shared-edit-body", 4, 4)?;
    local.db.persist_message_actor_state(
        "target",
        "routed/own-sent-attestation/target/phone",
        &json!({"device":"phone"}),
    )?;
    archive.db.persist_message_actor_state(
        "target",
        "routed/own-sent-attestation/target/tablet",
        &json!({"device":"tablet"}),
    )?;
    let merged = restore(&local, &archive)?;
    assert_eq!(register(&merged)?, Some(pair(4, 4)));
    let openings: i64 = merged.db.query_row(
        "SELECT count(*) FROM runtime_actor_state WHERE state_kind LIKE 'routed/own-sent-attestation/target/%'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(openings, 2, "openings of the same winning Edit are unioned");
    let indexed: i64 = merged.db.query_row(
        "SELECT count(*) FROM message_footprint WHERE message_id='target' AND locator LIKE 'routed/own-sent-attestation/target/%'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(indexed, 2, "restored openings stay owned by the message erase fence");
    finish(merged, [local, archive]);
    Ok(())
}

#[test]
fn unsupported_raw_copy_survives_backup_restore_byte_exact() -> TestResult {
    let (source_root, source) = crate::tests::test_db("unsupported-restore-source")?;
    let source_root_guard = crate::tests::TestDirGuard(source_root.clone());
    let (target_root, target) = crate::tests::test_db("unsupported-restore-target")?;
    let target_root_guard = crate::tests::TestDirGuard(target_root.clone());
    // An unknown kind with unknown fields, a non-minimal varint and trailing zero bytes.
    let exact = b"\xfa\x7f\x05unkn\x00\x80\x80\x00\x0a\x00\x00\xff".to_vec();
    source.write_transaction(|| {
        source.put_unsupported_raw_copy(RawInnerCopyWrite {
            owner_id: "unknown-owner",
            verified_source_anchor: "verified-source",
            copy_id: "routed/unsupported-copy/unknown-owner",
            kind: RawInnerCopyKind::OuterInner,
            bytes: &exact,
            bounded_metadata: b"bounded",
        })
    })?;
    assert!(source.raw_inner_copy("routed/unsupported-copy/unknown-owner")?.is_some());
    let source = Side { root: source_root, db: source, _guard: source_root_guard };
    let target = Side { root: target_root, db: target, _guard: target_root_guard };
    let merged = restore(&target, &source)?;
    let (kind, digest, bytes, metadata, anchor): (String, Vec<u8>, Vec<u8>, Vec<u8>, String) =
        merged.db.query_row(
            "SELECT c.copy_kind,c.raw_digest,c.raw_bytes,c.copy_metadata,o.source_anchor FROM raw_inner_copy c JOIN raw_inner_owner o USING(owner_id) WHERE c.copy_id='routed/unsupported-copy/unknown-owner'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
        )?;
    assert_eq!(bytes, exact, "an unknown kind must survive restore byte-exact");
    assert_eq!(digest.len(), 32);
    assert_eq!(kind, "outer_inner");
    assert_eq!(metadata, b"bounded");
    assert_eq!(anchor, "verified-source");
    // A second restore of the same archive is idempotent for the retained copy.
    let archive = source.root.join("incoming.db");
    let again = source.db.write_backup_snapshot(&source.root.join("again.db"))?;
    let mut merged = merged;
    merged.merge_backup(&source.root.join("again.db"), &again.key, || Ok(()))?;
    let copies: i64 = merged.db.query_row(
        "SELECT count(*) FROM raw_inner_copy WHERE owner_id='unknown-owner'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(copies, 1);
    assert!(archive.exists());
    finish(merged, [source, target]);
    Ok(())
}

#[test]
fn own_sent_attestation_copy_restores_and_stays_fenced_by_deletion() -> TestResult {
    let attest = |name: &str| -> Result<Side, Box<dyn std::error::Error>> {
        let (root, db) = crate::tests::test_db(name)?;
        let root_guard = crate::tests::TestDirGuard(root.clone());
        db.send_direct_message("conversation", "target", "device", b"own sent body")?;
        db.write_transaction(|| {
            db.put_unsupported_raw_copy(RawInnerCopyWrite {
                owner_id: "target",
                verified_source_anchor: "own-root",
                copy_id: "routed/own-sent-attestation/target/target",
                kind: RawInnerCopyKind::SourceEvidence,
                bytes: b"own-attestation-canary",
                bounded_metadata: &[],
            })
        })?;
        Ok(Side { root, db, _guard: root_guard })
    };
    let archive = attest("own-attestation-archive")?;
    let (root, db) = crate::tests::test_db("own-attestation-fresh")?;
    let root_guard = crate::tests::TestDirGuard(root.clone());
    let fresh = Side { root, db, _guard: root_guard };
    let merged = restore(&fresh, &archive)?;
    let bytes: Vec<u8> = merged.db.query_row(
        "SELECT raw_bytes FROM raw_inner_copy WHERE copy_id='routed/own-sent-attestation/target/target'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(bytes, b"own-attestation-canary");
    finish(merged, [fresh, archive]);

    let archive = attest("own-attestation-stale-archive")?;
    let erased = attest("own-attestation-erased")?;
    erased.db.delete_direct_message("conversation", "target", "local", "erase-own")?;
    let merged = restore(&erased, &archive)?;
    absent_everywhere(&merged, b"own-attestation-canary")?;
    finish(merged, [erased, archive]);
    Ok(())
}

#[test]
fn restore_keeps_greatest_parked_edit_and_marks_review() -> TestResult {
    let parked = |name: &str,
                  event: u8,
                  bytes: &[u8]|
     -> Result<Side, Box<dyn std::error::Error>> {
        let (root, db) = crate::tests::test_db(name)?;
        let root_guard = crate::tests::TestDirGuard(root.clone());
        let copy_id = format!("early-edit/target/{event}");
        db.write_transaction(|| {
            db.put_unsupported_raw_copy(RawInnerCopyWrite {
                owner_id: &format!("edit-event-{event}"),
                verified_source_anchor: "author-root",
                copy_id: &copy_id,
                kind: RawInnerCopyKind::OuterInner,
                bytes,
                bounded_metadata: &[],
            })
        })?;
        db.persist_actor_state(
            "routed/pending-edit/target/author-root",
            &json!({"revision":3,"event_id":vec![event; 16],"copy_id":copy_id,"committed_key":"routed/committed/none"}),
        )?;
        Ok(Side { root, db, _guard: root_guard })
    };
    for incoming_wins in [true, false] {
        let low = parked("parked-restore-low", 1, b"parked-losing-edit-canary")?;
        let high = parked("parked-restore-high", 9, b"parked-winning-edit")?;
        let merged = if incoming_wins { restore(&low, &high)? } else { restore(&high, &low)? };
        let stored: Vec<u8> = merged.db.query_row(
            "SELECT state_json FROM runtime_actor_state WHERE state_kind='routed/pending-edit/target/author-root'",
            [],
            |row| row.get(0),
        )?;
        let stored: EditPair = serde_json::from_slice(&stored)?;
        assert_eq!(Some(stored), Some(pair(3, 9)), "incoming_wins={incoming_wins}");
        absent_everywhere(&merged, b"parked-losing-edit-canary")?;
        let review: Vec<u8> = merged.db.query_row(
            "SELECT state_json FROM runtime_actor_state WHERE state_kind=?1",
            [PARKED_EDIT_REVIEW],
            |row| row.get(0),
        )?;
        assert_eq!(review, b"true");
        finish(merged, [low, high]);
    }
    Ok(())
}
