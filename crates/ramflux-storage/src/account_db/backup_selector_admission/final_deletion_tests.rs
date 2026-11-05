// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Incoming deletion retires a target alias only in the production final pass.
use super::*;
use crate::{BackupDatabase, ObjectReferenceAdmission, ObjectReferenceOwner};
use serde_json::json;
type TestResult = Result<(), Box<dyn std::error::Error>>;
const ALIAS: &str = "pending-alias-canary";

#[test]
fn e20_incoming_deletion_retires_linked_target_alias() -> TestResult {
    for (survivor, marker_only) in [(false, false), (true, false), (false, true), (true, true)] {
        super::tests::fixture("final-target-delete", |root, live, target, _, _| {
            // The fixture's original owner keeps the shared payload live.
            live.upsert_object(&crate::ObjectWrite {
                object_id: "wire",
                manifest_hash: "manifest",
                nonce: "nonce",
                ciphertext: b"m1-ciphertext",
                plaintext_hash: "plain",
                tombstoned: false,
                backup_excluded: false,
                content_key: Some(&[7; 32]),
                object: &json!({"object_id":"wire"}),
                updated_at: 1,
            })?;
            let reference = json!({"object_id":"wire","manifest_hash":"manifest","key_slot":{"object_id":"wire","slot_id":ALIAS}});
            let hash = blake3_256_base64url(
                "ramflux.attachment.reference.v1",
                &ramflux_protocol::canonical_json_bytes(&reference)?,
            );
            for message in if survivor { vec!["m2", "m3"] } else { vec!["m2"] } {
                live.send_direct_message("thread", message, "peer", b"owner-body")?;
                live.register_object_reference(
                    ObjectReferenceAdmission::FreshMessage,
                    &ObjectReferenceOwner {
                        reference_hash: &hash,
                        wire_id: "wire",
                        manifest_hash: "manifest",
                        selector: ALIAS,
                        message_id: message,
                        reference: &reference,
                        metadata: &json!({"message_id":message}),
                    },
                )?;
            }
            live.set_object_tombstoned(ALIAS)?;
            let actor = format!("attachment/reference/{ALIAS}");
            live.persist_actor_state(&actor, &json!({"reference":reference}))?;
            live.register_object_reference_actor(&hash, &actor)?;
            let path = root.join("linked-target.db");
            let saved = live.write_backup_snapshot(&path)?;
            *target = BackupDatabase::open(&path, &saved.key)?;
            live.delete_direct_message("thread", "m2", "local", "delete")?;
            let incoming = root.join("deleted-source.db");
            let source_key = live.write_backup_snapshot(&incoming)?.key;
            let source = BackupDatabase::open(&incoming, &source_key)?;
            // A tombstone-only or marker-only input cannot replace the target projection or unlink
            // it through generic timestamp arbitration before the final pass.
            source
                .db
                .execute_batch("DELETE FROM direct_message_projection WHERE message_id='m2';")?;
            // This partial archive supplies deletion authority without selector history.
            source.db.execute(
                "DELETE FROM object_erasure_lookup WHERE lookup=?1",
                [object_erasure_lookup("principal", ALIAS)],
            )?;
            if marker_only {
                source.db.execute(
                    "DELETE FROM message_tombstone_projection WHERE message_id='m2'",
                    [],
                )?;
            }
            drop(source);
            let before = std::fs::read(&incoming)?;
            final_deletion::BEFORE.set(Some(before_pass));
            final_deletion::AFTER.set(Some(after_pass));
            let result = target.merge_backup_candidate(&incoming, &source_key, || Ok(()));
            final_deletion::BEFORE.set(None);
            final_deletion::AFTER.set(None);
            result?;
            assert_eq!(std::fs::read(&incoming)?, before);
            verify_retirement(target, survivor)?;
            reopen_snapshot(root, target, &saved.key, survivor)?;
            Ok(())
        })?;
    }
    Ok(())
}

fn before_pass(db: &Connection) -> Result<(), StorageError> {
    assert_eq!(count(db, "SELECT count(*) FROM object_erasure_fence")?, 0);
    assert_eq!(
        db.query_row(
            "SELECT count(*) FROM object_erasure_lookup WHERE lookup=?1",
            [object_erasure_lookup("principal", ALIAS)],
            |r| r.get::<_, u64>(0)
        )?,
        0
    );
    assert!(matches!(
        final_deletion::verify(db),
        Err(StorageError::ObjectOwnershipUnverified { .. })
    ));
    assert_eq!(count(db, "SELECT count(*) FROM backup_target_delete WHERE message_id='m2'")?, 1);
    assert_eq!(
        count(db, "SELECT count(*) FROM object_message_reference WHERE message_id='m2'")?,
        1
    );
    assert_eq!(
        count(
            db,
            "SELECT count(*) FROM object_retention_reference WHERE selector='pending-alias-canary'"
        )?,
        1
    );
    assert_eq!(
        count(db, "SELECT count(*) FROM backup_reference_admission WHERE message_id='m2'")?,
        0
    );
    assert_eq!(
        count(
            db,
            "SELECT count(*) FROM direct_message_projection WHERE message_id='m2' AND deleted=0"
        )?,
        1
    );
    Ok(())
}
fn count(db: &Connection, sql: &str) -> rusqlite::Result<u64> {
    db.query_row(sql, [], |r| r.get(0))
}
fn reopen_snapshot(
    root: &std::path::Path,
    target: &BackupDatabase,
    key: &crate::AccountDbKey,
    survivor: bool,
) -> TestResult {
    let installed = root.join("installed");
    let index = crate::AccountIndex::open(&installed)?;
    let account = index.create_account("acct", "principal")?;
    let path = installed.join(account.db_relative_path);
    std::fs::create_dir_all(path.parent().ok_or(StorageError::AuthorizationRejected)?)?;
    target.copy_to(&path, key)?;
    let reopened = crate::AccountDb::open(&index, "acct", key)?;
    reopened.check_object_access("wire")?;
    if survivor {
        reopened.check_object_access(ALIAS)?;
    } else {
        assert!(matches!(reopened.check_object_access(ALIAS), Err(StorageError::ObjectErased)));
    }
    reopened.checkpoint_retired_secrets()?;
    let path = root.join("final-snapshot.db");
    let saved = reopened.write_backup_snapshot(&path)?;
    let snapshot = BackupDatabase::open(&path, &saved.key)?;
    snapshot.check_integrity()?;
    if !survivor {
        scan(&target.db)?;
        scan(&snapshot.db)?;
    }
    Ok(())
}
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
                        !bytes.windows(ALIAS.len()).any(|v| v == ALIAS.as_bytes()),
                        "canary in {table}"
                    );
                }
            }
        }
    }
    Ok(())
}

fn after_pass(db: &Connection) -> Result<(), StorageError> {
    assert_eq!(
        count(db, "SELECT count(*) FROM object_message_reference WHERE message_id='m2'")?,
        0,
        "final pass left pending target edge"
    );
    Ok(())
}

fn verify_retirement(target: &BackupDatabase, survivor: bool) -> TestResult {
    assert_eq!(
        count(&target.db, "SELECT count(*) FROM object_message_reference WHERE message_id='m2'")?,
        0
    );
    assert_eq!(
        count(
            &target.db,
            "SELECT count(*) FROM direct_message_projection WHERE message_id='m2' AND deleted=1"
        )?,
        1
    );
    assert_eq!(count(&target.db, "SELECT count(*) FROM object_erasure_fence")?, 0);
    assert_eq!(
        count(
            &target.db,
            "SELECT count(*) FROM object_retention_reference WHERE selector='pending-alias-canary'"
        )?,
        u64::from(survivor)
    );
    assert_eq!(
        count(
            &target.db,
            "SELECT count(*) FROM object_reference_actor WHERE state_kind LIKE '%pending-alias-canary%'"
        )?,
        u64::from(survivor)
    );
    assert_eq!(
        count(
            &target.db,
            "SELECT count(*) FROM runtime_actor_state WHERE state_kind='attachment/reference/pending-alias-canary'"
        )?,
        u64::from(survivor)
    );
    assert_eq!(
        count(
            &target.db,
            "SELECT count(*) FROM object_index WHERE object_id='pending-alias-canary'"
        )?,
        u64::from(survivor)
    );
    assert_eq!(
        count(
            &target.db,
            "SELECT count(*) FROM message_copy_binding WHERE copy_id='object:pending-alias-canary' AND message_id='m2'"
        )?,
        0
    );
    assert_eq!(
        count(
            &target.db,
            "SELECT count(*) FROM message_copy_binding WHERE copy_id='object:pending-alias-canary' AND message_id='m3'"
        )?,
        u64::from(survivor)
    );
    assert_eq!(
        target.db.query_row(
            "SELECT ciphertext FROM object_index WHERE object_id='wire'",
            [],
            |r| r.get::<_, Vec<u8>>(0)
        )?,
        b"m1-ciphertext"
    );
    let lookup = object_erasure_lookup("principal", ALIAS);
    assert_eq!(
        target.db.query_row(
            "SELECT count(*) FROM object_erasure_lookup WHERE lookup=?1 AND commitment=?2",
            params![lookup, object_erasure_commitment("principal", "wire", "manifest")],
            |r| r.get::<_, u64>(0)
        )?,
        u64::from(!survivor)
    );
    Ok(())
}
