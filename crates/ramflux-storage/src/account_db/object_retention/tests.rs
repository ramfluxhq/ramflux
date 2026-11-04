// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::*;
use crate::{EventStore, ObjectWrite};
use serde_json::json;

pub(super) fn install(db: &AccountDb, message: &str, reference: &str) -> Result<(), StorageError> {
    db.send_direct_message("thread", message, "peer", b"body")?;
    db.register_object_reference(
        crate::ObjectReferenceAdmission::FreshMessage,
        &ObjectReferenceOwner {
            reference_hash: reference,
            wire_id: "wire",
            manifest_hash: "manifest",
            selector: "wire",
            message_id: message,
            reference: &json!({"object_id":"wire","slot":reference}),
            metadata: &json!({"object_id":"wire","message_id":message}),
        },
    )?;
    Ok(())
}

pub(super) fn payload(db: &AccountDb) -> Result<(), StorageError> {
    db.upsert_object(&ObjectWrite {
        object_id: "wire",
        manifest_hash: "manifest",
        nonce: "nonce",
        ciphertext: b"cipher-canary",
        plaintext_hash: "plain-hash",
        tombstoned: false,
        backup_excluded: false,
        content_key: Some(&[7; 32]),
        object: &json!({"secret":"body-canary"}),
        updated_at: 1,
    })
}

// Mutation: omit the existing-reference edge insert in register_object_reference.
#[test]
fn shared_reference_keeps_payload_until_last_message_then_fences_reimport()
-> Result<(), StorageError> {
    let (root, db) = crate::tests::test_db("object-shared-reference")?;
    install(&db, "one", "reference")?;
    install(&db, "two", "reference")?;
    assert_eq!(db.client_message_object_ids("one")?, vec!["wire"]);
    assert_eq!(db.client_message_object_ids("two")?, vec!["wire"]);
    payload(&db)?;
    db.persist_actor_state(
        "directory/object/wire",
        &json!({"object_id":"wire","message_id":"one"}),
    )?;
    db.delete_direct_message("thread", "one", "local", "delete-one")?;
    assert!(db.load_object::<Value>("wire")?.is_some());
    assert_eq!(
        db.load_actor_state::<Value>("directory/object/wire")?
            .map(|value| value["message_id"].clone()),
        Some(json!("two"))
    );
    db.delete_direct_message("thread", "two", "local", "delete-two")?;
    assert!(matches!(db.load_object::<Value>("wire"), Err(StorageError::ObjectErased)));
    assert!(matches!(payload(&db), Err(StorageError::ObjectErased)));
    assert_eq!(db.object_erasure_generation()?, 1);
    assert_eq!(
        db.connection.query_row("SELECT COUNT(*) FROM object_index", [], |r| r.get::<_, i64>(0))?,
        0
    );
    drop(db);
    let index = crate::AccountIndex::open(&root)?;
    let key = crate::AccountDbKey::derive("acct", b"storage-test-secret");
    let reopened = AccountDb::open(&index, "acct", &key)?;
    assert!(matches!(reopened.load_object::<Value>("wire"), Err(StorageError::ObjectErased)));
    drop(reopened);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

// Mutation: remove the retention_class='imported' predicate from the erasure driver.
#[test]
fn standalone_retention_survives_last_message_deletion() -> Result<(), StorageError> {
    let (root, db) = crate::tests::test_db("object-standalone-retention")?;
    db.retain_object("wire", "manifest", ObjectRetention::Standalone)?;
    install(&db, "one", "reference")?;
    payload(&db)?;
    db.delete_direct_message("thread", "one", "local", "delete")?;
    assert!(db.load_object::<Value>("wire")?.is_some());
    assert_eq!(db.object_erasure_generation()?, 0);
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

// Mutation: notify the cache before committing the outer transaction.
#[test]
fn rollback_preserves_edges_payload_and_generation_without_retirement_notification()
-> Result<(), StorageError> {
    let (root, db) = crate::tests::test_db("object-erasure-rollback")?;
    install(&db, "one", "reference")?;
    payload(&db)?;
    let notified = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let observed = Arc::clone(&notified);
    db.observe_object_retirement(Arc::new(move |_| {
        observed.store(true, std::sync::atomic::Ordering::SeqCst);
    }))?;
    let outcome: Result<(), StorageError> = db.write_transaction(|| {
        db.delete_direct_message("thread", "one", "local", "delete")?;
        Err(StorageError::AuthorizationRejected)
    });
    assert!(outcome.is_err());
    assert!(!notified.load(std::sync::atomic::Ordering::SeqCst));
    assert!(db.load_object::<Value>("wire")?.is_some());
    assert_eq!(db.object_erasure_generation()?, 0);
    db.delete_direct_message("thread", "one", "local", "delete")?;
    assert!(notified.load(std::sync::atomic::Ordering::SeqCst));
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

// Mutation: leave the primary reference projection pointing at the deleted owner's slot.
#[test]
fn shared_payload_reselects_surviving_private_reference_and_erases_unowned_slot_alias()
-> Result<(), StorageError> {
    let (root, db) = crate::tests::test_db("object-private-reference")?;
    install(&db, "one", "slot-one")?;
    install(&db, "two", "slot-two")?;
    payload(&db)?;
    db.persist_actor_state(
        "attachment/reference/wire",
        &json!({"object_id":"wire","slot":"slot-one"}),
    )?;
    db.persist_actor_state(
        "directory/object/wire",
        &json!({"object_id":"wire","message_id":"one"}),
    )?;
    for (reference, alias) in [("slot-one", "alias-one"), ("slot-two", "alias-two")] {
        let key = format!("attachment/reference-by-slot/{alias}");
        db.persist_actor_state(&key, &"wire")?;
        db.register_object_reference_actor(reference, &key)?;
    }
    db.persist_actor_state("attachment/chunk/wire/manifest/0", &json!({"cipher":"chunk-canary"}))?;
    db.delete_direct_message("thread", "one", "local", "delete-one")?;
    assert_eq!(
        db.load_actor_state::<Value>("attachment/reference/wire")?.map(|v| v["slot"].clone()),
        Some(json!("slot-two"))
    );
    assert_eq!(
        db.load_actor_state::<Value>("directory/object/wire")?.map(|v| v["message_id"].clone()),
        Some(json!("two"))
    );
    assert!(!db.actor_state_exists("attachment/reference-by-slot/alias-one")?);
    assert!(db.actor_state_exists("attachment/reference-by-slot/alias-two")?);
    assert!(db.actor_state_exists("attachment/chunk/wire/manifest/0")?);
    db.delete_direct_message("thread", "two", "local", "delete-two")?;
    assert!(!db.actor_state_exists("attachment/chunk/wire/manifest/0")?);
    assert!(!db.actor_state_exists("attachment/reference-by-slot/alias-two")?);
    assert!(matches!(
        db.persist_actor_state(
            "attachment/ack/stale/0",
            &json!({"object_id":"wire","acknowledged":true})
        ),
        Err(StorageError::ObjectErased)
    ));
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

// Mutation: let an unconverted pre-send hold survive Drop.
#[test]
fn abandoned_pre_send_hold_erases_payload_but_converted_message_hold_survives()
-> Result<(), StorageError> {
    let (root, db) = crate::tests::test_db("object-pre-send-release")?;
    let hold = db.pre_send_object_hold("wire", "manifest")?;
    payload(&db)?;
    drop(hold);
    assert!(matches!(db.load_object::<Value>("wire"), Err(StorageError::ObjectErased)));
    let hold = db.pre_send_object_hold("other-wire", "other-manifest")?;
    db.send_direct_message("thread", "sent", "peer", b"body")?;
    db.register_object_reference(
        crate::ObjectReferenceAdmission::FreshMessage,
        &ObjectReferenceOwner {
            reference_hash: "other-reference",
            wire_id: "other-wire",
            manifest_hash: "other-manifest",
            selector: "other-wire",
            message_id: "sent",
            reference: &json!({}),
            metadata: &json!({}),
        },
    )?;
    drop(hold);
    db.check_object_identity("other-wire", "other-manifest")?;
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

// Mutation: delete object_index by wire id rather than the exact retired manifest.
#[test]
fn erased_unmaterialized_reference_does_not_delete_a_different_live_manifest()
-> Result<(), StorageError> {
    let (root, db) = crate::tests::test_db("object-manifest-isolation")?;
    install(&db, "one", "reference")?;
    payload(&db)?;
    db.send_direct_message("thread", "other", "peer", b"body")?;
    db.register_object_reference(
        crate::ObjectReferenceAdmission::FreshMessage,
        &ObjectReferenceOwner {
            reference_hash: "other-reference",
            wire_id: "wire",
            manifest_hash: "different-manifest",
            selector: "received:other",
            message_id: "other",
            reference: &json!({}),
            metadata: &json!({}),
        },
    )?;
    db.delete_direct_message("thread", "other", "local", "delete-other")?;
    assert!(db.load_object::<Value>("wire")?.is_some());
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

// Mutation: commit a fence without invoking registered runtime resource retirement.
#[test]
fn last_owner_commit_closes_and_unlinks_runtime_owned_plaintext_spool() -> Result<(), StorageError>
{
    let (root, db) = crate::tests::test_db("object-spool-retirement")?;
    install(&db, "one", "reference")?;
    payload(&db)?;
    let path = root.join("owned.spool");
    std::fs::write(&path, b"spool-private-body")?;
    let open = Arc::new(std::sync::Mutex::new(Some(std::fs::File::open(&path)?)));
    let weak = Arc::downgrade(&open);
    let cleanup_path = path.clone();
    db.register_object_resource(
        "download",
        "wire",
        "manifest",
        Arc::new(move || {
            if let Some(file) = weak.upgrade() {
                file.lock().map_err(|_| StorageError::AuthorizationRejected)?.take();
            }
            std::fs::remove_file(&cleanup_path)?;
            Ok(())
        }),
    )?;
    db.delete_direct_message("thread", "one", "local", "delete")?;
    assert!(!path.exists());
    assert!(open.lock().map_err(|_| StorageError::AuthorizationRejected)?.is_none());
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

// Mutation: omit any legacy/payload/key/actor/archive/work-row arm from the erasure driver.
#[test]
fn attachment_erasure_canary_covers_payload_legacy_tables_archives_journal_and_work_rows()
-> Result<(), StorageError> {
    let (root, db) = crate::tests::test_db("object-erasure-canary")?;
    install(&db, "one", "reference")?;
    payload(&db)?;
    db.connection.execute_batch("CREATE TABLE backup_archived_actor_state(source TEXT NOT NULL,state_kind TEXT NOT NULL,state_json BLOB NOT NULL,PRIMARY KEY(source,state_kind)); CREATE TABLE backup_archived_local_event(source TEXT NOT NULL,event_id TEXT NOT NULL,event_body BLOB NOT NULL,PRIMARY KEY(source,event_id));")?;
    db.connection.call(|db| super::super::message_footprint::install(db))?;
    let secret = b"private-canary";
    db.connection.execute("INSERT INTO object_manifest VALUES('wire',CAST('manifest' AS BLOB),?1,NULL,?1,?1,NULL,?1,1,14,NULL,1)", params![secret])?;
    db.connection.execute(
        "INSERT INTO object_key_slot VALUES('slot','wire','device',?1,NULL,?2,'aead')",
        params![secret, [7_u8; 32].as_slice()],
    )?;
    db.connection.execute("INSERT INTO object_chunk VALUES('chunk','wire',0,?1,NULL,14,'private-canary','complete',1)",params![secret])?;
    db.connection.execute("INSERT INTO object_tombstone VALUES('old','wire','object','private-canary','private-canary',1,NULL,?1)",params![secret])?;
    db.connection.execute("INSERT INTO object_operation VALUES('wire','operation','complete',?1,'manifest','plain-hash',?1,NULL,1,1)",params![secret])?;
    db.connection.execute("INSERT INTO object_transfer_state(transfer_id,object_id,direction,peer_device_id,manifest_hash,resume_token,missing_chunk_bitmap,completed_chunk_bitmap,state,updated_at) VALUES('transfer','wire','download','peer',CAST('manifest' AS BLOB),'private-canary',?1,?1,'complete',1)",params![secret])?;
    let value = json!({"message_id":"one","object_id":"wire","secret":"private-canary"});
    db.persist_actor_state("attachment/fetch/wire", &value)?;
    db.persist_actor_state("attachment/chunk/wire/manifest/0", &value)?;
    db.append_journal("source", "message.attachment", &value, 1, None)?;
    db.append_event("event", "message.attachment", &serde_json::to_vec(&value)?)?;
    db.connection.execute(
        "INSERT INTO backup_archived_actor_state VALUES('archive','attachment/old',?1)",
        params![serde_json::to_vec(&value)?],
    )?;
    db.connection.execute(
        "INSERT INTO backup_archived_local_event VALUES('archive','event',?1)",
        params![serde_json::to_vec(&value)?],
    )?;
    db.register_object_reference(
        crate::ObjectReferenceAdmission::FreshMessage,
        &ObjectReferenceOwner {
            reference_hash: "private-reference",
            wire_id: "wire",
            manifest_hash: "manifest",
            selector: "wire",
            message_id: "one",
            reference: &value,
            metadata: &value,
        },
    )?;
    db.reserve_operation("canary-operation", "fingerprint")?;
    db.bind_operation_objects("canary-operation", &json!({"object_id":"wire"}))?;
    db.complete_operation(
        "canary-operation",
        &json!({"payload":"private-canary","key":"body-canary"}),
    )?;
    db.delete_direct_message("thread", "one", "local", "delete")?;
    assert_erasure_canary_absent(&db)?;
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

// Mutation: use the payload-fence cursor as the snapshot publication generation.
#[test]
fn shared_reference_erasure_invalidates_snapshot_resources_without_retiring_payload()
-> Result<(), StorageError> {
    let (root, db) = crate::tests::test_db("shared-snapshot-generation")?;
    install(&db, "one", "reference")?;
    install(&db, "two", "reference")?;
    payload(&db)?;
    let reader = db.open_reader()?;
    let generation = reader.privacy_erasure_generation()?;
    let retired = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let notification = Arc::clone(&retired);
    let _registration = reader.register_privacy_resource(
        "snapshot",
        generation,
        Arc::new(move || {
            notification.store(true, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        }),
    )?;
    db.delete_direct_message("thread", "one", "local", "delete-one")?;
    assert_eq!(db.object_erasure_generation()?, 0);
    assert!(db.privacy_erasure_generation()? > generation);
    assert!(retired.load(std::sync::atomic::Ordering::SeqCst));
    assert!(db.load_object::<Value>("wire")?.is_some());
    assert!(matches!(
        reader.register_privacy_resource("stale", generation, Arc::new(|| Ok(()))),
        Err(StorageError::ObjectErased)
    ));
    drop(reader);
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

pub(super) fn assert_erasure_canary_absent(db: &AccountDb) -> Result<(), StorageError> {
    db.connection.call(|sql| {
        let names = sql
            .prepare(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'",
            )?
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        for name in names {
            let quoted = name.replace('"', "\"\"");
            let mut query = sql.prepare(&format!("SELECT * FROM \"{quoted}\""))?;
            let columns = query.column_count();
            let mut rows = query.query([])?;
            while let Some(row) = rows.next()? {
                for column in 0..columns {
                    let (rusqlite::types::ValueRef::Text(bytes)
                    | rusqlite::types::ValueRef::Blob(bytes)) = row.get_ref(column)?
                    else {
                        continue;
                    };
                    for canary in [
                        b"private-canary".as_slice(),
                        b"cipher-canary",
                        b"body-canary",
                        &[7_u8; 32],
                    ] {
                        assert!(
                            !bytes.windows(canary.len()).any(|part| part == canary),
                            "secret retained in {name} column {column}"
                        );
                    }
                }
            }
        }
        Ok(())
    })?;
    Ok(())
}
