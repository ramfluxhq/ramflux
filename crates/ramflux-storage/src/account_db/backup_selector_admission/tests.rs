// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::super::backup_merge::BackupMergeMode;
use super::*;
use crate::{AccountDbKey, BackupDatabase, ObjectReferenceAdmission, ObjectReferenceOwner};
use serde_json::json;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn fixture(
    label: &str,
    run: impl FnOnce(
        &std::path::Path,
        &crate::AccountDb,
        &mut BackupDatabase,
        &std::path::Path,
        &AccountDbKey,
    ) -> TestResult,
) -> TestResult {
    let (root, db) = crate::tests::test_db(label)?;
    db.send_direct_message("thread", "message", "peer", b"body")?;
    let hash = blake3_256_base64url(
        "ramflux.object.transport.owner.v1",
        &ramflux_protocol::canonical_json_bytes(&("wire", "manifest", "message"))?,
    );
    db.register_object_reference(
        ObjectReferenceAdmission::FreshMessage,
        &ObjectReferenceOwner {
            reference_hash: &hash,
            wire_id: "wire",
            manifest_hash: "manifest",
            selector: "wire",
            message_id: "message",
            reference: &json!({}),
            metadata: &json!({}),
        },
    )?;
    let incoming = root.join("incoming.db");
    let snapshot = db.write_backup_snapshot(&incoming)?;
    let target = root.join("target.db");
    let selected = db.write_backup_snapshot(&target)?;
    let mut target_db = BackupDatabase::open(&target, &selected.key)?;
    target_db.db.execute_batch("INSERT INTO object_erasure_lookup VALUES('dual-opaque','old'); INSERT INTO object_erasure_lookup VALUES('target-opaque','old');")?;
    let source = BackupDatabase::open(&incoming, &snapshot.key)?;
    source.db.execute_batch("INSERT INTO object_erasure_lookup VALUES('dual-opaque','old'); INSERT INTO object_erasure_lookup VALUES('incoming-opaque','old');")?;
    drop(source);
    run(&root, &db, &mut target_db, &incoming, &snapshot.key)?;
    target_db.check_integrity()?;
    drop(target_db);
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

fn absent(db: &Connection) -> rusqlite::Result<()> {
    for database in ["main", "temp"] {
        for table in TABLES {
            assert_eq!(
                db.query_row(
                    &format!("SELECT count(*) FROM {database}.sqlite_master WHERE name=?1"),
                    [table],
                    |r| r.get::<_, u64>(0)
                )?,
                0,
                "{database}.{table}"
            );
        }
    }
    Ok(())
}

fn no_canary(db: &Connection) -> rusqlite::Result<()> {
    let tables = db
        .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")?
        .query_map([], |r| r.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    for table in tables {
        let mut query = db.prepare(&format!("SELECT * FROM \"{}\"", table.replace('"', "\"\"")))?;
        let columns = query.column_count();
        let mut rows = query.query([])?;
        while let Some(row) = rows.next()? {
            for column in 0..columns {
                if let rusqlite::types::ValueRef::Text(bytes)
                | rusqlite::types::ValueRef::Blob(bytes) = row.get_ref(column)?
                {
                    assert!(
                        !bytes
                            .windows(b"scratch-secret-canary".len())
                            .any(|part| part == b"scratch-secret-canary"),
                        "canary in {table}"
                    );
                }
            }
        }
    }
    Ok(())
}

#[test]
fn e14_fault_after_lookup_origin_capture() -> TestResult {
    fixture("origin-rollback", |root, live, target, path, key| {
        let index = crate::AccountIndex::open(root)?;
        let selected_before = index.account("acct")?;
        let live_before: u64 = live.connection.query_row(
            "SELECT count(*) FROM object_retention_reference",
            [],
            |r| r.get(0),
        )?;
        let source_before = std::fs::read(path)?;
        let before: u64 =
            target.db.query_row("SELECT count(*) FROM object_erasure_lookup", [], |r| r.get(0))?;
        let result = target.merge_backup_pipeline(path,key,(BackupMergeMode::FullAccount(None),true),&mut ||Ok(()),|db| {
            let origins = db.prepare("SELECT side,lookup FROM backup_lookup_origin ORDER BY side,lookup")?.query_map([],|r|Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?)))?.collect::<rusqlite::Result<Vec<_>>>()?;
            assert_eq!(origins, vec![("incoming".into(),"dual-opaque".into()),("incoming".into(),"incoming-opaque".into()),("target".into(),"dual-opaque".into()),("target".into(),"target-opaque".into())]);
            assert!(!db.query_row("SELECT EXISTS(SELECT 1 FROM main.object_erasure_lookup WHERE lookup='incoming-opaque')",[],|r|r.get::<_,bool>(0))?);
            Err(StorageError::AuthorizationRejected)
        });
        assert!(matches!(result, Err(StorageError::AuthorizationRejected)));
        absent(&target.db)?;
        assert_eq!(
            target.db.query_row("SELECT count(*) FROM object_erasure_lookup", [], |r| r
                .get::<_, u64>(0))?,
            before
        );
        assert_eq!(std::fs::read(path)?, source_before);
        assert_eq!(index.account("acct")?, selected_before);
        assert_eq!(
            live.connection.query_row(
                "SELECT count(*) FROM object_retention_reference",
                [],
                |r| r.get::<_, u64>(0)
            )?,
            live_before
        );
        // Reopen the failed private stage, then retry the real candidate merge.
        let retry_path = root.join("retry.db");
        let retry_key = AccountDbKey::generate()?;
        target.copy_to(&retry_path, &retry_key)?;
        let mut retry = BackupDatabase::open(&retry_path, &retry_key)?;
        retry.merge_backup_candidate(path, key, || Ok(()))?;
        absent(&retry.db)?;
        Ok(())
    })
}

#[test]
fn e14_scratch_tables_never_in_temp() -> TestResult {
    fixture("scratch-placement", |_, _, target, path, key| {
        target.merge_backup_pipeline(
            path,
            key,
            (BackupMergeMode::FullAccount(None), true),
            &mut || Ok(()),
            |db| {
                for table in TABLES {
                    assert_eq!(
                        db.query_row(
                            "SELECT count(*) FROM main.sqlite_master WHERE name=?1",
                            [table],
                            |r| r.get::<_, u64>(0)
                        )?,
                        1
                    );
                    assert_eq!(
                        db.query_row(
                            "SELECT count(*) FROM temp.sqlite_master WHERE name=?1",
                            [table],
                            |r| r.get::<_, u64>(0)
                        )?,
                        0
                    );
                }
                for (table, columns) in [
                    (
                        "backup_reference_admission",
                        vec!["side", "reference_hash", "message_id", "selector", "commitment"],
                    ),
                    (
                        "backup_selector_admission",
                        vec!["side", "selector", "commitment", "decision"],
                    ),
                    ("backup_lookup_origin", vec!["side", "lookup", "commitment"]),
                    (
                        "backup_target_delete",
                        vec!["reference_hash", "message_id", "selector", "commitment"],
                    ),
                ] {
                    let actual = db
                        .prepare(&format!("PRAGMA main.table_info({table})"))?
                        .query_map([], |r| r.get::<_, String>(1))?
                        .collect::<rusqlite::Result<Vec<_>>>()?;
                    assert_eq!(actual, columns);
                }
                for (table, keys) in [
                    ("backup_reference_admission", vec!["side", "reference_hash", "message_id"]),
                    ("backup_selector_admission", vec!["side", "selector", "commitment"]),
                    ("backup_lookup_origin", vec!["side", "lookup"]),
                    ("backup_target_delete", vec!["reference_hash", "message_id"]),
                ] {
                    let actual = db
                        .prepare(&format!(
                            "SELECT name FROM pragma_table_info('{table}') WHERE pk>0 ORDER BY pk"
                        ))?
                        .query_map([], |r| r.get::<_, String>(0))?
                        .collect::<rusqlite::Result<Vec<_>>>()?;
                    assert_eq!(actual, keys);
                }
                for (index, columns) in [
                    ("backup_reference_selector", vec!["side", "selector", "commitment"]),
                    ("backup_reference_commitment", vec!["side", "commitment", "reference_hash"]),
                    ("backup_lookup_side", vec!["lookup", "side"]),
                    ("backup_target_selector", vec!["selector", "commitment"]),
                    ("backup_target_message", vec!["message_id", "reference_hash"]),
                ] {
                    let actual = db
                        .prepare(&format!("PRAGMA main.index_info({index})"))?
                        .query_map([], |r| r.get::<_, String>(2))?
                        .collect::<rusqlite::Result<Vec<_>>>()?;
                    assert_eq!(actual, columns);
                }
                Ok(())
            },
        )?;
        absent(&target.db)?;
        Ok(())
    })
}

#[test]
fn e14_success_drops_all_four_scratch_tables() -> TestResult {
    fixture("scratch-lifecycle", |root, db, target, path, key| {
        // A foreign archive's operation tables must never become generic merge input.
        let source = BackupDatabase::open(path, key)?;
        source.db.execute_batch("CREATE TABLE backup_reference_admission(private TEXT); INSERT INTO backup_reference_admission VALUES('scratch-secret-canary');")?;
        drop(source);
        target.merge_backup_candidate(path, key, || Ok(()))?;
        absent(&target.db)?;
        let copy = root.join("copy.db");
        let copy_key = AccountDbKey::generate()?;
        target.copy_to(&copy, &copy_key)?;
        let reopened = BackupDatabase::open(&copy, &copy_key)?;
        absent(&reopened.db)?;
        no_canary(&reopened.db)?;
        assert!(
            !std::fs::read(&copy)?
                .windows(b"scratch-secret-canary".len())
                .any(|w| w == b"scratch-secret-canary")
        );
        // Both snapshot writers strip stale operation tables, without changing the source.
        db.connection.execute_batch("CREATE TABLE backup_lookup_origin(side TEXT,lookup TEXT,commitment TEXT); INSERT INTO backup_lookup_origin VALUES('target','scratch-secret-canary','secret');")?;
        let snapshot_path = root.join("clean-snapshot.db");
        let snapshot = db.write_backup_snapshot(&snapshot_path)?;
        let snapshot_db = BackupDatabase::open(&snapshot_path, &snapshot.key)?;
        absent(&snapshot_db.db)?;
        no_canary(&snapshot_db.db)?;
        target.db.execute_batch("CREATE TABLE backup_lookup_origin(side TEXT,lookup TEXT,commitment TEXT); INSERT INTO backup_lookup_origin VALUES('target','scratch-secret-canary','secret');")?;
        let stripped_path = root.join("clean-copy.db");
        let stripped_key = AccountDbKey::generate()?;
        target.copy_to(&stripped_path, &stripped_key)?;
        let stripped = BackupDatabase::open(&stripped_path, &stripped_key)?;
        absent(&stripped.db)?;
        no_canary(&stripped.db)?;
        drop_scratch(&target.db)?;
        Ok(())
    })
}

#[test]
fn candidate_validates_both_inputs_and_reference_domains_before_union() -> TestResult {
    for database in ["main", "incoming"] {
        for change in [
            "UPDATE {db}.object_retention_reference SET reference_hash='forged'",
            "UPDATE {db}.object_retention_payload SET wire_lookup='forged'",
            "UPDATE {db}.object_retention_reference SET selector_lookup='forged'",
            "UPDATE {db}.object_message_reference SET message_id='absent'",
            "UPDATE {db}.object_retention_reference SET reference_json=x'7b227265666572656e6365223a7b226f626a6563745f6964223a2277697265222c226d616e69666573745f68617368223a226d616e6966657374227d7d'",
            "UPDATE {db}.schema_migration SET checksum='forged' WHERE schema_version=1",
        ] {
            fixture("invalid-input", |_, _, target, path, key| {
                if database == "main" {
                    target.db.execute_batch(&change.replace("{db}", "main"))?;
                } else {
                    let source = BackupDatabase::open(path, key)?;
                    source.db.execute_batch(&change.replace("{db}", "main"))?;
                }
                assert!(matches!(
                    target.merge_backup_candidate(path, key, || Ok(())),
                    Err(StorageError::ObjectOwnershipUnverified { .. })
                ));
                absent(&target.db)?;
                assert!(!target.db.query_row("SELECT EXISTS(SELECT 1 FROM object_erasure_lookup WHERE lookup='incoming-opaque')",[],|r|r.get::<_,bool>(0))?);
                Ok(())
            })?;
        }
    }
    Ok(())
}

#[test]
fn candidate_accepts_wrapped_and_unwrapped_attachment_hashes() -> TestResult {
    for wrapped in [false, true] {
        fixture("attachment-encoding", |_, _, target, path, key| {
            let source = BackupDatabase::open(path, key)?;
            for input in [&target.db, &source.db] {
                let inner = json!({"object_id":"wire","manifest_hash":"manifest"});
                let hash = blake3_256_base64url(
                    "ramflux.attachment.reference.v1",
                    &ramflux_protocol::canonical_json_bytes(&inner)?,
                );
                let value =
                    if wrapped { json!({"reference":inner,"prepared_slot":null}) } else { inner };
                input.execute(
                    "UPDATE object_retention_reference SET reference_hash=?1,reference_json=?2",
                    params![hash, serde_json::to_vec(&value)?],
                )?;
                input.execute("UPDATE object_message_reference SET reference_hash=?1", [hash])?;
            }
            drop(source);
            target.merge_backup_candidate(path, key, || Ok(()))?;
            absent(&target.db)?;
            Ok(())
        })?;
    }
    Ok(())
}
