// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
use super::*;
use serde_json::json;
type TestResult = Result<(), Box<dyn std::error::Error>>;
const OLD: &[u8] = b"original-body-canary-never-retained-after-edit";
const OPENING: [u8; 32] = [91; 32];

fn populate(db: &AccountDb) -> Result<(), StorageError> {
    db.write_transaction(|| {
        db.import_direct_message_projection(crate::DirectMessageWrite { conversation_id:"conversation", message_id:"target", sender_id:"peer", encrypted_body:OLD, metadata:&crate::MessageMetadata::default(), created_at:1 })?;
        db.put_known_content_evidence("target", "conversation", OLD, b"original-provenance", &OPENING)?;
        for key in ["own-copy/prepared/target", "history/page/cached", "self-sync/state/draft"] {
            db.persist_message_actor_state("target", key, &json!({"conversation_id":"conversation","value":{"revision":"1"},"old_body":String::from_utf8_lossy(OLD),"opening":OPENING}))?;
        }
        db.persist_message_actor_state("target", "routed/original-header/target", &json!({"identity":"body-free-original"}))?;
        db.persist_message_actor_state("target", "old-recipient-opening/second", &json!({"opening":OPENING}))?;
        Ok(())
    })
}
fn replace(db: &AccountDb, body: &[u8]) -> Result<(), StorageError> {
    db.write_transaction(|| {
        db.retire_message_payload_copies("target", &["routed/original-header/target".into()])?;
        db.replace_generated_message_content(
            "conversation",
            "target",
            body,
            &crate::MessageMetadata::default(),
        )?;
        Ok(())
    })
}

#[test]
fn edit_retires_original_opening_everywhere() -> TestResult {
    let (root, db) = crate::tests::test_db("edit-retirement-all-copies")?;
    populate(&db)?;
    replace(&db, b"current Edit")?;
    assert!(db.known_content_evidence("target")?.is_none());
    for prefix in
        ["own-copy/prepared/", "history/page/", "self-sync/state/", "old-recipient-opening/"]
    {
        assert!(db.actor_state_keys(prefix)?.is_empty(), "copy survives: {prefix}");
    }
    scan(&db, OLD)?;
    scan(&db, &OPENING)?;
    scan(&db, serde_json::to_string(&OPENING)?.as_bytes())?;
    assert_eq!(db.message_content("target")?.as_deref(), Some(b"current Edit".as_slice()));
    assert!(db.actor_state_exists("routed/original-header/target")?);
    db.delete_direct_message("conversation", "target", "local", "delete")?;
    assert!(!db.actor_state_exists("routed/original-header/target")?);
    assert!(db.message_content("target")?.is_none());
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn edit_retirement_failure_rolls_back_content_and_original_evidence() -> TestResult {
    let (root, db) = crate::tests::test_db("edit-retirement-rollback")?;
    populate(&db)?;
    let result: Result<(), StorageError> = db.write_transaction(|| {
        db.retire_message_payload_copies("target", &[])?;
        db.replace_generated_message_content(
            "conversation",
            "target",
            b"uncommitted Edit",
            &crate::MessageMetadata::default(),
        )?;
        // Fault boundary after retirement and before the body-free evidence write.
        Err(StorageError::AuthorizationRejected)
    });
    assert!(result.is_err());
    assert_eq!(db.message_content("target")?.as_deref(), Some(OLD));
    assert_eq!(
        db.known_content_evidence("target")?.ok_or("opening lost on rollback")?.report_opening,
        OPENING
    );
    assert!(db.actor_state_exists("routed/original-header/target")?);
    assert!(db.actor_state_exists("old-recipient-opening/second")?);
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

fn scan(db: &AccountDb, forbidden: &[u8]) -> Result<(), StorageError> {
    let forbidden = forbidden.to_vec();
    db.connection.call(move |raw| {
        let check = || -> Result<(), StorageError> {
            let mut tables = raw.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")?;
            let names = tables.query_map([], |row| row.get::<_,String>(0))?.collect::<rusqlite::Result<Vec<_>>>()?;
            for name in names {
                let mut query = raw.prepare(&format!("SELECT * FROM \"{}\"", name.replace('"', "\"\"")))?;
                let columns = query.column_count(); let mut rows = query.query([])?;
                while let Some(row) = rows.next()? {
                    for column in 0..columns {
                        if let rusqlite::types::ValueRef::Text(bytes) | rusqlite::types::ValueRef::Blob(bytes) = row.get_ref(column)? {
                            assert!(!bytes.windows(forbidden.len()).any(|window| window == forbidden), "retired bytes in {name} column {column}");
                        }
                    }
                }
            }
            Ok(())
        };
        Ok(check())
    }).map_err(StorageError::from)?
}
