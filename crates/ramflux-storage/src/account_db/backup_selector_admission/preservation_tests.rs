// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Candidate production merge preservation and historical-selector regression witnesses.
use super::*;
use crate::{BackupDatabase, ObjectReferenceAdmission, ObjectReferenceOwner};
use serde_json::json;
type TestResult = Result<(), Box<dyn std::error::Error>>;
const CANARY: &str = "retired-reference-canary";

fn scan(db: &Connection) -> TestResult {
    let tables = db
        .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")?
        .query_map([], |r| r.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    for table in tables {
        let mut q = db.prepare(&format!("SELECT * FROM \"{}\"", table.replace('"', "\"\"")))?;
        let columns = q.column_count();
        let mut rows = q.query([])?;
        while let Some(row) = rows.next()? {
            for column in 0..columns {
                if let rusqlite::types::ValueRef::Text(bytes)
                | rusqlite::types::ValueRef::Blob(bytes) = row.get_ref(column)?
                {
                    assert!(
                        !bytes.windows(CANARY.len()).any(|v| v == CANARY.as_bytes()),
                        "canary in {table}"
                    );
                }
            }
        }
    }
    Ok(())
}
fn restore(label: &str, placeholder: bool, historical: bool, fault: bool) -> TestResult {
    super::tests::fixture(label, |root, live, target, _, _| {
        seed_payload(live, target)?;
        let message = if historical { "never-deleted-m3" } else { "retired-owner" };
        live.send_direct_message("thread", message, "peer", b"surviving-content")?;
        let reference = json!({"object_id":"wire","manifest_hash":"manifest","key_slot":{"object_id":"wire","slot_id":CANARY},"plaintext_hash":"plain"});
        let hash = blake3_256_base64url(
            "ramflux.attachment.reference.v1",
            &ramflux_protocol::canonical_json_bytes(&reference)?,
        );
        live.register_object_reference(
            ObjectReferenceAdmission::FreshMessage,
            &ObjectReferenceOwner {
                reference_hash: &hash,
                wire_id: "wire",
                manifest_hash: "manifest",
                selector: CANARY,
                message_id: message,
                reference: &reference,
                metadata: &json!({"message_id":message}),
            },
        )?;
        let kept = admitted_sibling(live)?;
        let path = root.join("preservation-source.db");
        let saved = live.write_backup_snapshot(&path)?;
        let source = BackupDatabase::open(&path, &saved.key)?;
        source.ensure_missing_manifest()?;
        source.db.execute(
            "INSERT INTO backup_missing_attachment VALUES(?1,'manifest','plain')",
            [CANARY],
        )?;
        let actor = json!({"reference":reference,"prepared_slot":CANARY});
        for key in [format!("attachment/reference/{CANARY}"), format!("directory/object/{CANARY}")]
        {
            source.db.execute(
                "INSERT OR IGNORE INTO object_payload_actor VALUES(?1,?2)",
                params![object_erasure_commitment("principal", "wire", "manifest"), key],
            )?;
            source.db.execute(
                "INSERT OR REPLACE INTO runtime_actor_state VALUES(?1,?2)",
                params![key, serde_json::to_vec(&actor)?],
            )?;
        }
        source.db.execute_batch("CREATE TABLE backup_archived_actor_state(source TEXT NOT NULL,state_kind TEXT NOT NULL,state_json BLOB NOT NULL,PRIMARY KEY(source,state_kind)); CREATE TABLE backup_archived_local_event AS SELECT 'old' AS source,* FROM local_event_log WHERE 0;")?;
        source.db.execute(
            "INSERT INTO backup_archived_actor_state VALUES('old','historical/shared',?1)",
            params![serde_json::to_vec(&json!({"items":[actor,kept]}))?],
        )?;
        source.db.execute("INSERT INTO local_event_log VALUES('mixed-event','test','peer','device',999,999,1,NULL,?1,x'1234','verified','pending')",params![serde_json::to_vec(&json!({"items":[actor,kept]}))?])?;
        source.db.execute_batch("INSERT INTO backup_archived_local_event SELECT 'old',* FROM local_event_log WHERE event_id='mixed-event';")?;
        if placeholder {
            source.db.execute("INSERT INTO object_index(object_id,manifest_hash,ciphertext,chunk_count,chunk_manifest_hash,tombstoned,updated_at,object_body,object_state,total_cipher_size,created_at) VALUES(?1,?2,x'',0,?2,1,1,x'7b7d','revoked',0,1)",params![CANARY,b"manifest".as_slice()])?;
        }
        drop(source);
        let before = std::fs::read(&path)?;
        let commitment = object_erasure_commitment("principal", "wire", "manifest");
        target.db.execute(
            "INSERT INTO object_erasure_lookup VALUES(?1,?2)",
            params![object_erasure_lookup("principal", CANARY), commitment],
        )?;
        assert_eq!(
            target.db.query_row(
                "SELECT count(*) FROM object_erasure_fence WHERE commitment=?1",
                [&commitment],
                |r| r.get::<_, u64>(0)
            )?,
            0
        );
        assert!(!live.message_is_deleted(message)?);
        assert_eq!(
            target.db.query_row(
                "SELECT count(*) FROM object_retention_reference WHERE selector=?1",
                [CANARY],
                |r| r.get::<_, u64>(0)
            )?,
            0
        );
        if fault {
            verify_rollback(target, &path, &saved.key, &before)?;
            return Ok(());
        }
        target.merge_backup_candidate(&path, &saved.key, || Ok(()))?;
        assert_eq!(std::fs::read(&path)?, before);
        verify_target(target, &hash, message)?;
        verify_snapshot(root, target, &saved.key)?;

        Ok(())
    })
}
#[test]
fn e7_incoming_reference_without_placeholder_excluded() -> TestResult {
    restore("preserve-no-placeholder", false, false, false)
}
#[test]
fn e7_d7_style_object_exclusion_retained() -> TestResult {
    restore("preserve-d7", true, false, false)
}
#[test]
fn e7_lookup_only_restore_does_not_import_alias() -> TestResult {
    restore("preserve-lookup", true, false, false)
}
#[test]
fn e17_historical_lookup_alone_omits_never_deleted_m3_attachment() -> TestResult {
    restore("preserve-history", false, true, false)
}
#[test]
fn e14_fault_after_archive_preservation() -> TestResult {
    restore("preserve-fault", false, false, true)
}

fn verify_target(target: &BackupDatabase, hash: &str, message: &str) -> TestResult {
    assert_eq!(
        target.db.query_row(
            "SELECT ciphertext FROM object_index WHERE object_id='wire'",
            [],
            |r| r.get::<_, Vec<u8>>(0)
        )?,
        b"m1-payload"
    );
    for table in
        ["object_retention_reference", "object_message_reference", "object_reference_actor"]
    {
        let predicate =
            if table == "object_retention_reference" { "selector=?1" } else { "reference_hash=?1" };
        let value = if table == "object_retention_reference" { CANARY } else { hash };
        assert_eq!(
            target.db.query_row(
                &format!("SELECT count(*) FROM {table} WHERE {predicate}"),
                [value],
                |r| r.get::<_, u64>(0)
            )?,
            0
        );
    }
    assert_eq!(
        target.db.query_row(
            "SELECT count(*) FROM message_copy_binding WHERE copy_id='object:'||?1",
            [CANARY],
            |r| r.get::<_, u64>(0)
        )?,
        0
    );
    assert_eq!(
        target.db.query_row(
            "SELECT deleted FROM direct_message_projection WHERE message_id=?1",
            [message],
            |r| r.get::<_, u64>(0)
        )?,
        0
    );
    assert_eq!(
        target.db.query_row(
            "SELECT signature_status FROM local_event_log WHERE event_id='mixed-event'",
            [],
            |r| r.get::<_, String>(0)
        )?,
        "retired"
    );
    assert_eq!(
        target.db.query_row(
            "SELECT length(signature) FROM local_event_log WHERE event_id='mixed-event'",
            [],
            |r| r.get::<_, u64>(0)
        )?,
        0
    );
    let body: Vec<u8> = target.db.query_row(
        "SELECT event_body FROM local_event_log WHERE event_id='mixed-event'",
        [],
        |r| r.get(0),
    )?;
    assert!(String::from_utf8(body)?.contains("keep-sibling"));
    for table in TABLES {
        assert_eq!(
            target.db.query_row(
                "SELECT count(*) FROM sqlite_master WHERE name=?1",
                [table],
                |r| r.get::<_, u64>(0)
            )?,
            0
        );
    }
    for table in
        ["object_erasure_work", "object_reference_erasure_work", "object_projection_erasure_work"]
    {
        assert_eq!(
            target
                .db
                .query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get::<_, u64>(0))?,
            0
        );
    }
    scan(&target.db)?;
    Ok(())
}

#[test]
fn bounded_preservation_decode_refuses_atomically() -> TestResult {
    for oversized in [false, true] {
        super::tests::fixture(
            if oversized { "preserve-oversize" } else { "preserve-malformed" },
            |_, _, target, path, key| {
                let source = BackupDatabase::open(path, key)?;
                let body = if oversized { vec![b' '; 1_048_577] } else { b"{invalid".to_vec() };
                source.db.execute("INSERT INTO runtime_actor_state VALUES('attachment/reference-by-sender/bounded',?1)",params![body])?;
                drop(source);
                let before = std::fs::read(path)?;
                assert!(matches!(
                    target.merge_backup_candidate(path, key, || Ok(())),
                    Err(StorageError::ObjectOwnershipUnverified { .. })
                ));
                assert_eq!(std::fs::read(path)?, before);
                assert_eq!(
                    target.db.query_row(
                        "SELECT count(*) FROM sqlite_master WHERE name='backup_preserved_copy'",
                        [],
                        |r| r.get::<_, u64>(0)
                    )?,
                    0
                );
                Ok(())
            },
        )?;
    }
    Ok(())
}

fn verify_snapshot(
    root: &std::path::Path,
    target: &BackupDatabase,
    key: &crate::AccountDbKey,
) -> TestResult {
    let installed = root.join("installed");
    let index = crate::AccountIndex::open(&installed)?;
    let account = index.create_account("acct", "principal")?;
    let copy = installed.join(account.db_relative_path);
    std::fs::create_dir_all(copy.parent().ok_or(StorageError::AuthorizationRejected)?)?;
    target.copy_to(&copy, key)?;
    let reopened = crate::AccountDb::open(&index, "acct", key)?;
    assert!(matches!(reopened.check_object_access(CANARY), Err(StorageError::ObjectErased)));
    reopened.check_object_access("wire")?;
    reopened.checkpoint_retired_secrets()?;
    let snapshot_path = root.join("post-restore-snapshot.db");
    let snapshot = reopened.write_backup_snapshot(&snapshot_path)?;
    let snapshot = BackupDatabase::open(&snapshot_path, &snapshot.key)?;
    scan(&snapshot.db)?;

    Ok(())
}

fn seed_payload(live: &crate::AccountDb, target: &BackupDatabase) -> TestResult {
    live.upsert_object(&crate::ObjectWrite {
        object_id: "wire",
        manifest_hash: "manifest",
        nonce: "nonce",
        ciphertext: b"stale-m1-payload",
        plaintext_hash: "plain",
        tombstoned: false,
        backup_excluded: false,
        content_key: Some(&[7; 32]),
        object: &json!({"object_id":"wire"}),
        updated_at: 1,
    })?;
    target.db.execute("INSERT INTO object_index(object_id,manifest_hash,chunk_manifest_hash,object_state,total_cipher_size,chunk_count,created_at,updated_at,ciphertext,object_body) VALUES('wire',?1,?1,'available',10,1,1,2,?2,x'7b7d')",params![b"manifest".as_slice(),b"m1-payload".as_slice()])?;
    Ok(())
}

fn admitted_sibling(live: &crate::AccountDb) -> Result<Value, StorageError> {
    let reference = json!({"object_id":"wire","manifest_hash":"manifest","key_slot":{"object_id":"wire","slot_id":"keep-slot"}});
    let hash = blake3_256_base64url(
        "ramflux.attachment.reference.v1",
        &ramflux_protocol::canonical_json_bytes(&reference)?,
    );
    live.send_direct_message("thread", "kept-owner", "peer", b"kept body")?;
    live.register_object_reference(
        ObjectReferenceAdmission::FreshMessage,
        &ObjectReferenceOwner {
            reference_hash: &hash,
            wire_id: "wire",
            manifest_hash: "manifest",
            selector: "kept-selector",
            message_id: "kept-owner",
            reference: &reference,
            metadata: &json!({"message_id":"kept-owner"}),
        },
    )?;
    Ok(json!({"reference":reference,"text":"keep-sibling"}))
}

fn verify_rollback(
    target: &mut BackupDatabase,
    path: &std::path::Path,
    key: &crate::AccountDbKey,
    before: &[u8],
) -> TestResult {
    target.db.execute_batch("CREATE TEMP TABLE backup_preservation_abort(marker INTEGER);")?;
    assert!(target.merge_backup_candidate(path, key, || Ok(())).is_err());
    assert_eq!(
        target.db.query_row(
            "SELECT count(*) FROM object_retention_reference WHERE selector=?1",
            [CANARY],
            |r| r.get::<_, u64>(0)
        )?,
        0
    );
    assert_eq!(std::fs::read(path)?, before);
    assert_eq!(
        target.db.query_row(
            "SELECT count(*) FROM main.sqlite_master WHERE name LIKE 'backup_archived_%'",
            [],
            |r| r.get::<_, u64>(0)
        )?,
        0
    );

    Ok(())
}
