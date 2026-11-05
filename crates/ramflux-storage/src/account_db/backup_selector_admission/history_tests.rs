// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Compatibility arbitration and independent historical authority witnesses.
use super::super::backup_merge::BackupMergeMode;
use crate::{
    AccountDb, BackupDatabase, BackupOpenMode, ObjectReferenceAdmission, ObjectReferenceOwner,
    ObjectWrite, StorageError,
};
use ramflux_crypto::{object_erasure_commitment, object_erasure_lookup};
use rusqlite::params;
use serde_json::json;
type TestResult = Result<(), Box<dyn std::error::Error>>;

fn register(db: &AccountDb, selector: &str, message: &str) -> TestResult {
    db.send_direct_message("thread", message, "peer", b"body")?;
    let reference =
        json!({"object_id":"wire","manifest_hash":"manifest","slot":selector,"owner":message});
    let hash = ramflux_crypto::blake3_256_base64url(
        "ramflux.attachment.reference.v1",
        &ramflux_protocol::canonical_json_bytes(&reference)?,
    );
    db.register_object_reference(
        ObjectReferenceAdmission::FreshMessage,
        &ObjectReferenceOwner {
            reference_hash: &hash,
            wire_id: "wire",
            manifest_hash: "manifest",
            selector,
            message_id: message,
            reference: &reference,
            metadata: &json!({"message_id":message}),
        },
    )?;
    Ok(())
}
fn payload(db: &AccountDb, at: i64) -> TestResult {
    db.upsert_object(&ObjectWrite {
        object_id: "wire",
        manifest_hash: "manifest",
        nonce: "n",
        ciphertext: b"payload",
        plaintext_hash: "plain",
        tombstoned: false,
        backup_excluded: false,
        content_key: Some(&[7; 32]),
        object: &json!({}),
        updated_at: at,
    })?;
    Ok(())
}

fn legacy(case: &str) -> TestResult {
    let (root, db) = crate::tests::test_db(case)?;
    let selector = if case == "live" { "alias" } else { "wire" };
    register(&db, selector, "message")?;
    payload(&db, if case == "newer" { 30 } else { 5 })?;
    if case == "target-tombstone" {
        db.set_object_tombstoned_with_revocation("wire", Some("peer"), Some("revoke"), 10)?;
    }
    let target_path = root.join("target.db");
    let saved = db.write_backup_snapshot(&target_path)?;
    if case == "live" {
        db.set_object_tombstoned("alias")?;
    }
    // Historical zero fixture: retain genuine ownership and all original veto assertions.
    db.connection.execute("UPDATE object_index SET tombstoned=1,ciphertext=x'',chunk_count=0,manifest_hash=zeroblob(32),chunk_manifest_hash=zeroblob(32),updated_at=20 WHERE object_id=?1",params![selector])?;
    let input = root.join("input.db");
    let snapshot = db.write_backup_snapshot(&input)?;
    // Export remains unchanged for untouched live legacy rows (no startup scrub).
    assert_eq!(
        db.connection.query_row(
            "SELECT length(manifest_hash) FROM object_index WHERE object_id=?1",
            params![selector],
            |r| r.get::<_, u64>(0)
        )?,
        32
    );
    let source = BackupDatabase::open_restore_input(
        &input,
        &snapshot.key,
        BackupOpenMode::PreNormalization,
    )?;
    let commitment = object_erasure_commitment("principal", "wire", "manifest");
    if case == "unowned" || case == "closed" {
        source.db.execute_batch(
            "DELETE FROM object_message_reference; DELETE FROM object_retention_reference;",
        )?;
    }
    drop(source);
    let mut target = BackupDatabase::open(&target_path, &saved.key)?;
    if case == "fenced" {
        target.db.execute("INSERT INTO object_erasure_fence VALUES(?1)", [&commitment])?;
    }
    if case == "unowned" || case == "closed" {
        target.db.execute_batch("DELETE FROM object_message_reference; DELETE FROM object_retention_reference; DELETE FROM object_index;")?;
    }
    if case == "closed" {
        target.db.execute(
            "INSERT INTO object_erasure_lookup VALUES(?1,?2)",
            params![object_erasure_lookup("principal", "wire"), commitment],
        )?;
    }
    let before = std::fs::read(&input)?;
    target.merge_backup_candidate(&input, &snapshot.key, || Ok(()))?;
    if ["fenced", "unowned", "closed"].contains(&case) {
        assert_eq!(
            target.db.query_row("SELECT count(*) FROM object_index", [], |r| r.get::<_, u64>(0))?,
            0
        );
        assert_eq!(
            target.db.query_row("SELECT count(*) FROM object_retention_reference", [], |r| r
                .get::<_, u64>(0))?,
            0
        );
    } else {
        assert_eq!(
            target.db.query_row(
                "SELECT count(*) FROM object_index WHERE object_id=?1",
                [selector],
                |r| r.get::<_, u64>(0)
            )?,
            1,
            "winning revocation lost"
        );
        let state=target.db.query_row("SELECT tombstoned,length(ciphertext),CAST(manifest_hash AS TEXT) FROM object_index WHERE object_id=?1",[selector],|r|Ok((r.get::<_,bool>(0)?,r.get::<_,u64>(1)?,r.get::<_,String>(2)?)))?;
        assert_eq!(
            state,
            (case != "newer", if case == "newer" { 7 } else { 0 }, "manifest".into()),
            "winning revocation lost"
        );
        assert_eq!(
            target.db.query_row("SELECT count(*) FROM object_message_reference", [], |r| r
                .get::<_, u64>(0))?,
            1
        );
    }
    assert_eq!(std::fs::read(&input)?, before);
    target.check_integrity()?;
    drop(target);
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}
#[test]
fn e12_alias_zero_with_live_reference_stays_revocation_capable() -> TestResult {
    legacy("live")
}
#[test]
fn e12_zero_incoming_over_live_known_wire_keeps_arbitration() -> TestResult {
    legacy("wire-arbitration")
}
#[test]
fn e12_current_newer_live_row_wins() -> TestResult {
    legacy("newer")
}
#[test]
fn e12_current_tombstone_over_newer_payload() -> TestResult {
    let (root, db) = crate::tests::test_db("current-tombstone")?;
    register(&db, "wire", "message")?;
    payload(&db, 30)?;
    let input = root.join("input.db");
    let source = db.write_backup_snapshot(&input)?;
    db.set_object_tombstoned_with_revocation("wire", Some("peer"), Some("revoke"), 10)?;
    let path = root.join("target.db");
    let saved = db.write_backup_snapshot(&path)?;
    let mut target = BackupDatabase::open(&path, &saved.key)?;
    target.merge_backup_candidate(&input, &source.key, || Ok(()))?;
    assert!(target.db.query_row(
        "SELECT tombstoned FROM object_index WHERE object_id='wire'",
        [],
        |r| r.get::<_, bool>(0)
    )?);
    target.check_integrity()?;
    drop(target);
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}
#[test]
fn e12_fenced_zero_omitted() -> TestResult {
    legacy("fenced")
}
#[test]
fn e12_unowned_zero_omitted() -> TestResult {
    legacy("unowned")
}
#[test]
fn e12_zero_against_closed_lookup_omitted() -> TestResult {
    legacy("closed")
}

fn partial() -> TestResult {
    let (root, db) = crate::tests::test_db("partial-survivor")?;
    register(&db, "alias", "m1")?;
    register(&db, "alias", "m2")?;
    db.set_object_tombstoned("alias")?;
    db.connection.execute(
        "INSERT INTO object_erasure_lookup VALUES(?1,?2)",
        params![
            object_erasure_lookup("principal", "alias"),
            object_erasure_commitment("principal", "wire", "manifest")
        ],
    )?;
    db.delete_direct_message("thread", "m1", "local", "delete")?;
    let input = root.join("input.db");
    let source = db.write_backup_snapshot(&input)?;
    let path = root.join("target.db");
    let saved = db.write_backup_snapshot(&path)?;
    let mut target = BackupDatabase::open(&path, &saved.key)?;
    target.merge_backup_candidate(&input, &source.key, || Ok(()))?;
    assert_eq!(
        target.db.query_row(
            "SELECT count(*) FROM object_message_reference WHERE message_id='m2'",
            [],
            |r| r.get::<_, u64>(0)
        )?,
        1
    );
    assert!(target.db.query_row(
        "SELECT tombstoned FROM object_index WHERE object_id='alias'",
        [],
        |r| r.get::<_, bool>(0)
    )?);
    target.check_integrity()?;
    drop(target);
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}
fn reverse_partial() -> TestResult {
    let (root, db) = crate::tests::test_db("reverse-partial")?;
    db.send_direct_message("thread", "m2", "peer", b"body")?;
    let path = root.join("target.db");
    let saved = db.write_backup_snapshot(&path)?;
    register(&db, "alias", "m2")?;
    db.set_object_tombstoned("alias")?;
    let lookup = object_erasure_lookup("principal", "alias");
    db.connection.execute(
        "INSERT INTO object_erasure_lookup VALUES(?1,?2)",
        params![lookup, object_erasure_commitment("principal", "wire", "manifest")],
    )?;
    let input = root.join("input.db");
    let source = db.write_backup_snapshot(&input)?;
    let mut target = BackupDatabase::open(&path, &saved.key)?;
    target.merge_backup_pipeline(
        &input,
        &source.key,
        (BackupMergeMode::FullAccount(None), true),
        &mut || Ok(()),
        |db| {
            assert_eq!(
                db.query_row(
                    "SELECT count(*) FROM backup_lookup_origin WHERE lookup=?1 AND side='target'",
                    [&lookup],
                    |r| r.get::<_, u64>(0)
                )?,
                0
            );
            assert_eq!(
                db.query_row(
                    "SELECT count(*) FROM backup_lookup_origin WHERE lookup=?1 AND side='incoming'",
                    [&lookup],
                    |r| r.get::<_, u64>(0)
                )?,
                1
            );
            Ok(())
        },
    )?;
    assert_eq!(
        target.db.query_row(
            "SELECT count(*) FROM object_message_reference WHERE message_id='m2'",
            [],
            |r| r.get::<_, u64>(0)
        )?,
        1
    );
    assert!(target.db.query_row(
        "SELECT tombstoned FROM object_index WHERE object_id='alias'",
        [],
        |r| r.get::<_, bool>(0)
    )?);
    target.check_integrity()?;
    drop(target);
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}
#[test]
fn e8_target_partial_lookup_keeps_live_alias_owner() -> TestResult {
    partial()
}
#[test]
fn e8_reverse_incoming_partial_lookup_admits_source_survivor() -> TestResult {
    reverse_partial()
}

fn replacement(mode: &str, replay_old: bool) -> TestResult {
    let (root, db) = crate::tests::test_db("replacement-restore")?;
    register(&db, "old-alias", "message")?;
    payload(&db, 1)?;
    let old = root.join("old.db");
    let old_saved = db.write_backup_snapshot(&old)?;
    db.delete_direct_message("thread", "message", "local", "delete")?;
    let path = root.join("target.db");
    let saved = db.write_backup_snapshot(&path)?;
    let manifest = replace(&db)?;
    let input = root.join("replacement.db");
    let source = db.write_backup_snapshot(&input)?;
    let input_db = BackupDatabase::open(&input, &source.key)?;
    alter_receipt(&input_db, mode)?;
    drop(input_db);
    let before = std::fs::read(&input)?;
    let mut target = BackupDatabase::open(&path, &saved.key)?;
    let result = target.merge_backup_pipeline(
        &input,
        &source.key,
        (BackupMergeMode::FullAccount(None), true),
        &mut || Ok(()),
        |db| {
            if mode == "valid" {
                let before = super::replacements::HASH_COUNT.get();
                assert_replacement_access(db, &manifest)?;
                let commitment = object_erasure_commitment("principal", "wire", &manifest);
                assert!(super::replacements::checked(db, "incoming", &commitment)?);
                assert!(super::replacements::checked(db, "incoming", &commitment)?);
                assert_eq!(
                    super::replacements::HASH_COUNT.get(),
                    before + 1,
                    "repeat copy checks must reuse the streamed hash"
                );
            }
            Ok(())
        },
    );
    if mode == "valid" {
        result?;
        assert_eq!(
            target.db.query_row(
                "SELECT CAST(manifest_hash AS TEXT) FROM object_index WHERE object_id='wire'",
                [],
                |r| r.get::<_, String>(0)
            )?,
            manifest
        );
        assert_eq!(
            target.db.query_row(
                "SELECT count(*) FROM object_identity_replacement WHERE commitment=?1",
                [object_erasure_commitment("principal", "wire", &manifest)],
                |r| r.get::<_, u64>(0)
            )?,
            1
        );
        assert_eq!(target.db.query_row("SELECT count(*) FROM object_identity_replacement WHERE commitment='unrelated-receipt'",[],|r|r.get::<_,u64>(0))?,0);
        if replay_old {
            target.merge_backup_candidate(&old, &old_saved.key, || Ok(()))?;
            assert_eq!(
                target.db.query_row(
                    "SELECT count(*) FROM object_retention_reference WHERE selector='old-alias'",
                    [],
                    |r| r.get::<_, u64>(0)
                )?,
                0
            );
            assert_eq!(
                target.db.query_row(
                    "SELECT count(*) FROM object_index WHERE object_id='old-alias'",
                    [],
                    |r| r.get::<_, u64>(0)
                )?,
                0
            );
            assert_eq!(
                target.db.query_row(
                    "SELECT count(*) FROM object_erasure_fence WHERE commitment=?1",
                    [object_erasure_commitment("principal", "wire", "manifest")],
                    |r| r.get::<_, u64>(0)
                )?,
                1
            );
        }
    } else {
        assert!(matches!(result, Err(StorageError::ObjectIdentityConflict)), "{result:?}");
        assert_eq!(
            target.db.query_row("SELECT count(*) FROM object_index", [], |r| r.get::<_, u64>(0))?,
            0
        );
    }
    assert_eq!(std::fs::read(&input)?, before);
    target.check_integrity()?;
    drop(target);
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}
#[test]
fn e9_checked_replacement_restores_new_wire() -> TestResult {
    replacement("valid", false)
}
#[test]
fn e9_old_aliases_cannot_return_and_old_fence_kept() -> TestResult {
    replacement("valid", true)
}
#[test]
fn e9_missing_or_forged_receipt_refuses() -> TestResult {
    replacement("missing", false)?;
    replacement("forged", false)?;
    replacement("corrupt", false)
}

fn alter_receipt(input_db: &BackupDatabase, mode: &str) -> TestResult {
    input_db
        .db
        .execute("INSERT INTO object_identity_replacement VALUES('unrelated-receipt')", [])?;
    if mode == "corrupt" {
        input_db
            .db
            .execute("UPDATE object_index SET ciphertext=x'010203' WHERE object_id='wire'", [])?;
    }
    if mode != "valid" && mode != "corrupt" {
        input_db.db.execute_batch("DELETE FROM object_identity_replacement;")?;
        if mode == "forged" {
            input_db.db.execute(
                "INSERT INTO object_identity_replacement VALUES('wrong-commitment')",
                [],
            )?;
        }
    }
    Ok(())
}

fn assert_replacement_access(
    db: &rusqlite::Connection,
    manifest: &str,
) -> Result<(), StorageError> {
    assert!(!super::placeholders::erased(db, "principal", "wire", Some(manifest), "incoming")?);
    assert!(super::placeholders::erased(db, "principal", "old-alias", Some("manifest"), "main")?);
    Ok(())
}

fn replace(db: &AccountDb) -> Result<String, StorageError> {
    let ciphertext = b"replacement ciphertext";
    let manifest =
        ramflux_crypto::blake3_256_base64url(ramflux_protocol::domain::OBJECT_MANIFEST, ciphertext);
    db.replace_object(
        None,
        &ObjectWrite {
            object_id: "wire",
            manifest_hash: &manifest,
            nonce: "n",
            ciphertext,
            plaintext_hash: "plain",
            tombstoned: false,
            backup_excluded: false,
            content_key: Some(&[9; 32]),
            object: &json!({"replacement":true}),
            updated_at: 2,
        },
    )?;
    Ok(manifest)
}

#[path = "history_review_tests.rs"]
mod review_probes;

#[path = "history_pr10_review_tests.rs"]
mod pr10_review_probes;

#[path = "history_pr10_r3_tests.rs"]
mod pr10_r2_probes;

#[path = "history_pr10_r4_tests.rs"]
mod pr10_r4_probes;

#[path = "history_pr10_r5_tests.rs"]
mod pr10_r5_probes;
