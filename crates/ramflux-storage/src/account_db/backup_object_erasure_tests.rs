// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::*;
use crate::{BackupDatabase, ObjectReferenceOwner, ObjectWrite};
use serde_json::{Value, json};

fn owned(db: &AccountDb) -> Result<(), StorageError> {
    db.send_direct_message("thread", "message", "peer", b"body")?;
    let reference = json!({"reference":{"object_id":"wire","manifest_hash":"manifest"},"private":"attachment-canary"});
    let metadata = json!({"object_id":"wire","manifest_hash":"manifest","message_id":"message","direction":"incoming","private":"attachment-canary"});
    db.register_object_reference(
        crate::ObjectReferenceAdmission::FreshMessage,
        &ObjectReferenceOwner {
            reference_hash: "reference",
            wire_id: "wire",
            manifest_hash: "manifest",
            selector: "wire",
            message_id: "message",
            reference: &reference,
            metadata: &metadata,
        },
    )?;
    db.upsert_object(&ObjectWrite {
        object_id: "wire",
        manifest_hash: "manifest",
        nonce: "nonce",
        ciphertext: b"attachment-canary",
        plaintext_hash: "plain",
        tombstoned: false,
        backup_excluded: false,
        content_key: Some(&[7; 32]),
        object: &json!({"private":"attachment-canary"}),
        updated_at: 1,
    })?;
    db.persist_actor_state_batch(&[
        ("attachment/reference/wire".into(), reference),
        ("directory/object/wire".into(), metadata),
        ("attachment/chunk/wire/manifest/0".into(), json!({"private":"attachment-canary"})),
    ])?;
    Ok(())
}

// Mutation: merge objects before the portable fence set.
#[test]
fn backup_fence_wins_over_old_payload_references_and_archives_in_both_merge_modes()
-> Result<(), StorageError> {
    for native in [false, true] {
        let (root, db) = crate::tests::test_db(&format!("object-backup-fence-{native}"))?;
        owned(&db)?;
        let old_path = root.join("old.db");
        let old = db.write_backup_snapshot(&old_path)?;
        db.delete_direct_message("thread", "message", "local", "delete")?;
        let new_path = root.join("new.db");
        let current = db.write_backup_snapshot(&new_path)?;
        let mut merged = BackupDatabase::open(&new_path, &current.key)?;
        if native {
            merged.merge_native_backup(&old_path, &old.key, || Ok(()))?;
        } else {
            merged.merge_backup(&old_path, &old.key, || Ok(()))?;
        }
        assert_eq!(
            merged.db.query_row("SELECT COUNT(*) FROM object_index", [], |r| r.get::<_, i64>(0))?,
            0
        );
        assert_eq!(
            merged.db.query_row("SELECT COUNT(*) FROM object_erasure_fence", [], |r| r
                .get::<_, i64>(0))?,
            1
        );
        for table in ["runtime_actor_state", "backup_archived_actor_state"] {
            let retained:bool=merged.db.query_row(&format!("SELECT EXISTS(SELECT 1 FROM {table} WHERE instr(CAST(state_json AS TEXT),'attachment-canary')>0)"),[],|r|r.get(0))?;
            assert!(!retained, "retained private copy in {table}");
        }
        drop(merged);
        drop(db);
        std::fs::remove_dir_all(root)?;
    }
    Ok(())
}

// Mutation: retain a local payload when an incoming newer fence covers its exact identity.
#[test]
fn incoming_backup_fence_retires_preexisting_payload_regardless_of_payload_timestamp()
-> Result<(), StorageError> {
    let (root, db) = crate::tests::test_db("incoming-object-fence")?;
    owned(&db)?;
    let local_path = root.join("local.db");
    let local = db.write_backup_snapshot(&local_path)?;
    db.delete_direct_message("thread", "message", "local", "delete")?;
    let deleted_path = root.join("deleted.db");
    let deleted = db.write_backup_snapshot(&deleted_path)?;
    let mut target = BackupDatabase::open(&local_path, &local.key)?;
    target.db.execute("UPDATE object_index SET updated_at=9223372036854775807", [])?;
    target.merge_backup(&deleted_path, &deleted.key, || Ok(()))?;
    assert_eq!(
        target.db.query_row("SELECT COUNT(*) FROM object_index", [], |r| r.get::<_, i64>(0))?,
        0
    );
    drop(target);
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

// Mutation: omit portable fence tables when copying or rekeying an account snapshot.
#[test]
fn post_delete_backup_keeps_fences_and_writer_floor_across_copy_and_rekey()
-> Result<(), StorageError> {
    let (root, db) = crate::tests::test_db("portable-object-fence")?;
    owned(&db)?;
    db.delete_direct_message("thread", "message", "local", "delete")?;
    let path = root.join("snapshot.db");
    let snapshot = db.write_backup_snapshot(&path)?;
    let archive = BackupDatabase::open(&path, &snapshot.key)?;
    let copied = root.join("copied.db");
    let key = AccountDbKey::generate()?;
    archive.copy_to(&copied, &key)?;
    let restored = BackupDatabase::open(&copied, &key)?;
    let rekey = AccountDbKey::generate()?;
    restored.rekey(&rekey)?;
    drop(restored);
    let restored = BackupDatabase::open(&copied, &rekey)?;
    assert_eq!(
        restored
            .db
            .query_row("SELECT COUNT(*) FROM object_erasure_fence", [], |r| r.get::<_, i64>(0))?,
        1
    );
    assert_eq!(
        restored.db.query_row(
            "SELECT checksum FROM schema_migration WHERE schema_version=1",
            [],
            |r| r.get::<_, String>(0)
        )?,
        crate::schema_object_erasure::SENTINEL
    );
    drop(restored);
    drop(archive);
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

// Mutation: replay a previously cached payload-bearing response after its object retires.
#[test]
fn object_erasure_compacts_retry_responses_including_responses_without_an_object_id()
-> Result<(), StorageError> {
    let (root, db) = crate::tests::test_db("object-operation-erasure")?;
    owned(&db)?;
    assert!(db.reserve_operation("operation", "fingerprint", "")?.is_none());
    db.bind_operation_objects("operation", &json!({"object_id":"wire"}))?;
    db.complete_operation(
        "operation",
        &json!({"data_base64":"attachment-canary","key":"key-canary"}),
    )?;
    db.delete_direct_message("thread", "message", "local", "delete")?;
    assert!(matches!(
        db.reserve_operation("operation", "fingerprint", ""),
        Err(StorageError::ObjectErased)
    ));
    let response: String = db.connection.query_row(
        "SELECT response_json FROM runtime_operation WHERE operation_id='operation'",
        [],
        |r| r.get(0),
    )?;
    assert_eq!(serde_json::from_str::<Value>(&response)?, json!({"object_erased":true}));
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

// Mutation: silently install an archive reference with no reconstructable message ownership.
#[test]
fn unsafe_archive_reference_is_a_typed_refusal_before_install() -> Result<(), StorageError> {
    let (root, db) = crate::tests::test_db("unsafe-object-archive")?;
    db.persist_actor_state("attachment/reference/unowned",&json!({"reference":{"object_id":"unowned","manifest_hash":"manifest"},"prepared_slot":{"object_key":vec![7;32]}}))?;
    let path = root.join("unsafe.db");
    let snapshot = db.write_backup_snapshot(&path)?;
    assert!(matches!(
        BackupDatabase::open(&path, &snapshot.key),
        Err(StorageError::ObjectOwnershipUnverified { schema_version: 14 })
    ));
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

// Mutation: accept a different manifest on an erased wire without its portable replacement receipt.
#[test]
fn backup_replacement_receipt_allows_new_identity_and_refuses_unapproved_reuse()
-> Result<(), StorageError> {
    let (root, db) = crate::tests::test_db("backup-object-replacement")?;
    owned(&db)?;
    db.delete_direct_message("thread", "message", "local", "delete")?;
    let target_path = root.join("deleted.db");
    let target = db.write_backup_snapshot(&target_path)?;
    let ciphertext = b"replacement ciphertext";
    let manifest =
        ramflux_crypto::blake3_256_base64url(ramflux_protocol::domain::OBJECT_MANIFEST, ciphertext);
    db.replace_object(
        None,
        &ObjectWrite {
            object_id: "wire",
            manifest_hash: &manifest,
            nonce: "new-nonce",
            ciphertext,
            plaintext_hash: "new-plain",
            tombstoned: false,
            backup_excluded: false,
            content_key: Some(&[9; 32]),
            object: &json!({"replacement":true}),
            updated_at: 2,
        },
    )?;
    let source_path = root.join("replacement.db");
    let source = db.write_backup_snapshot(&source_path)?;
    let mut target_db = BackupDatabase::open(&target_path, &target.key)?;
    target_db.merge_backup(&source_path, &source.key, || Ok(()))?;
    assert_eq!(
        target_db.db.query_row(
            "SELECT CAST(manifest_hash AS TEXT) FROM object_index WHERE object_id='wire'",
            [],
            |r| r.get::<_, String>(0)
        )?,
        manifest
    );
    assert_eq!(
        target_db
            .db
            .query_row("SELECT COUNT(*) FROM object_erasure_fence", [], |r| r.get::<_, i64>(0))?,
        1
    );
    drop(target_db);
    let unapproved = BackupDatabase::open(&source_path, &source.key)?;
    unapproved.db.execute("DELETE FROM object_identity_replacement", [])?;
    drop(unapproved);
    let empty_path = root.join("empty.db");
    let key = AccountDbKey::generate()?;
    let source_db = BackupDatabase::open(&target_path, &target.key)?;
    source_db.copy_to(&empty_path, &key)?;
    drop(source_db);
    let mut empty = BackupDatabase::open(&empty_path, &key)?;
    empty.db.execute("DELETE FROM object_index", [])?;
    empty.db.execute("DELETE FROM object_retention_payload", [])?;
    empty.db.execute("DELETE FROM object_identity_replacement", [])?;
    assert!(matches!(
        empty.merge_backup(&source_path, &source.key, || Ok(())),
        Err(StorageError::ObjectIdentityConflict)
    ));
    assert_eq!(
        empty.db.query_row("SELECT COUNT(*) FROM object_index", [], |r| r.get::<_, i64>(0))?,
        0
    );
    drop(empty);
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

// Regression: payload bindings must exclude copies even when the JSON uses wire_object_id.
#[test]
fn backup_payload_bound_wire_object_actor_is_not_preserved_after_erasure()
-> Result<(), Box<dyn std::error::Error>> {
    for candidate in [false, true] {
        for incoming_fence in [false, true] {
            for fenced in [false, true] {
                let (root, db) = crate::tests::test_db(&format!(
                    "preserve-payload-{candidate}-{incoming_fence}-{fenced}"
                ))?;
                let canary = "payload-preservation-secret-canary";
                let actor = "attachment/upload/opaque";
                db.persist_actor_state(
                    actor,
                    &json!({
                        "wire_object_id":"victim", "manifest_hash":"vm", "content_key":canary
                    }),
                )?;
                let incoming_path = root.join("incoming.db");
                let incoming_key = db.write_backup_snapshot(&incoming_path)?.key;
                let target_path = root.join("target.db");
                let target_key = db.write_backup_snapshot(&target_path)?.key;
                let incoming = BackupDatabase::open(&incoming_path, &incoming_key)?;
                let mut target = BackupDatabase::open(&target_path, &target_key)?;
                for copy in [&incoming, &target] {
                    assert_eq!(
                        copy.db.query_row(
                            "SELECT count(*) FROM object_payload_actor WHERE state_kind=?1",
                            [actor],
                            |r| r.get::<_, i64>(0)
                        )?,
                        1
                    );
                    copy.db.execute_batch("CREATE TABLE IF NOT EXISTS backup_archived_actor_state(source TEXT NOT NULL,state_kind TEXT NOT NULL,state_json BLOB NOT NULL,PRIMARY KEY(source,state_kind));")?;
                    copy.db.execute("INSERT INTO backup_archived_actor_state SELECT 'prior',state_kind,state_json FROM runtime_actor_state WHERE state_kind=?1", [actor])?;
                }
                if fenced {
                    let authority = if incoming_fence { &incoming } else { &target };
                    let principal: String = authority.db.query_row(
                        "SELECT principal_commitment FROM runtime_account_identity WHERE singleton=1",
                        [], |r| r.get(0)
                    )?;
                    authority.db.execute(
                        "INSERT INTO object_erasure_fence VALUES(?1)",
                        [ramflux_crypto::object_erasure_commitment(&principal, "victim", "vm")],
                    )?;
                }
                drop(incoming);
                let source_before = std::fs::read(&incoming_path)?;
                if candidate {
                    target.merge_backup_candidate(&incoming_path, &incoming_key, || Ok(()))?;
                } else {
                    target.merge_backup(&incoming_path, &incoming_key, || Ok(()))?;
                }
                assert_eq!(std::fs::read(&incoming_path)?, source_before);
                assert_payload_canary(&target.db, canary, fenced)?;
                let copied_path = root.join("reopened.db");
                let copied_key = AccountDbKey::generate()?;
                target.copy_to(&copied_path, &copied_key)?;
                let reopened = BackupDatabase::open(&copied_path, &copied_key)?;
                assert_payload_canary(&reopened.db, canary, fenced)?;
                drop(reopened);
                drop(target);
                drop(db);
                std::fs::remove_dir_all(root)?;
            }
        }
    }
    Ok(())
}

fn assert_payload_canary(
    db: &rusqlite::Connection,
    canary: &str,
    erased: bool,
) -> rusqlite::Result<()> {
    let tables = db
        .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")?
        .query_map([], |r| r.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let mut found = false;
    for table in tables {
        let mut query = db.prepare(&format!("SELECT * FROM \"{}\"", table.replace('"', "\"\"")))?;
        let columns = query.column_count();
        let mut rows = query.query([])?;
        while let Some(row) = rows.next()? {
            for column in 0..columns {
                if let rusqlite::types::ValueRef::Text(bytes)
                | rusqlite::types::ValueRef::Blob(bytes) = row.get_ref(column)?
                    && bytes.windows(canary.len()).any(|part| part == canary.as_bytes())
                {
                    assert!(!erased, "erased payload copy remains in {table}");
                    found = true;
                }
            }
        }
    }
    assert_eq!(found, !erased, "live payload control must retain its copy");
    Ok(())
}
