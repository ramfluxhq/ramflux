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

#[test]
fn e8_conflicting_identities_refuse_atomically() -> TestResult {
    fixture("conflicting-identity", |_, _, target, path, key| {
        let source = BackupDatabase::open(path, key)?;
        source.db.execute("UPDATE object_erasure_lookup SET commitment='different-authenticated-history' WHERE lookup='dual-opaque'", [])?;
        drop(source);
        let before = std::fs::read(path)?;
        assert!(matches!(
            target.merge_backup_candidate(path, key, || Ok(())),
            Err(StorageError::ObjectOwnershipUnverified { .. })
        ));
        assert_eq!(
            target.db.query_row(
                "SELECT commitment FROM object_erasure_lookup WHERE lookup='dual-opaque'",
                [],
                |r| r.get::<_, String>(0)
            )?,
            "old"
        );
        absent(&target.db)?;
        assert_eq!(std::fs::read(path)?, before);
        Ok(())
    })
}

fn phase_fault(point: &'static str) -> TestResult {
    fixture(point, |root, live, target, path, key| {
        let source_before = std::fs::read(path)?;
        let index = crate::AccountIndex::open(root)?;
        let selected = index.account("acct")?;
        graph::FAULT.set(Some(point));
        let result = target.merge_backup_candidate(path, key, || Ok(()));
        graph::FAULT.set(None);
        assert!(matches!(result, Err(StorageError::AuthorizationRejected)));
        absent(&target.db)?;
        assert!(!target.db.query_row(
            "SELECT EXISTS(SELECT 1 FROM object_erasure_lookup WHERE lookup='incoming-opaque')",
            [],
            |r| r.get::<_, bool>(0)
        )?);
        assert_eq!(std::fs::read(path)?, source_before);
        assert_eq!(index.account("acct")?, selected);
        assert_eq!(
            live.connection.query_row(
                "SELECT count(*) FROM object_retention_reference",
                [],
                |r| r.get::<_, u64>(0)
            )?,
            1
        );
        let copy = root.join("retry-phase.db");
        let copy_key = AccountDbKey::generate()?;
        target.copy_to(&copy, &copy_key)?;
        let mut reopened = BackupDatabase::open(&copy, &copy_key)?;
        reopened.merge_backup_candidate(path, key, || Ok(()))?;
        absent(&reopened.db)?;
        Ok(())
    })
}

#[test]
fn e14_fault_after_fence_union() -> TestResult {
    phase_fault("fence_union")
}
#[test]
fn e14_fault_after_graph_admission() -> TestResult {
    phase_fault("graph_admission")
}

fn install_input_marker(
    target: &BackupDatabase,
    source: &BackupDatabase,
    donor_db: &BackupDatabase,
    direction: &str,
    kind: &str,
) -> TestResult {
    let (id, bytes): (String, zeroize::Zeroizing<Vec<u8>>) =
        donor_db.db.query_row("SELECT bundle_id,subkeys FROM account_mac_bundle", [], |r| {
            Ok((r.get(0)?, zeroize::Zeroizing::new(r.get(1)?)))
        })?;
    // Both encryption keys and MAC authorities differ between inputs.
    source.db.execute("DELETE FROM account_mac_bundle", [])?;
    source
        .db
        .execute("INSERT INTO account_mac_bundle VALUES(?1,?2,1)", params![id, bytes.as_slice()])?;
    let authority = if direction == "main" { &target.db } else { &source.db };
    let foreign = kind == "foreign";
    let mac = if foreign {
        // The donor bundle is foreign to target; the original target
        // bundle is foreign to incoming. Neither current key matches.
        let other = if direction == "main" { &source.db } else { &target.db };
        let (foreign_id, foreign_bytes): (String, zeroize::Zeroizing<Vec<u8>>) = other.query_row(
            "SELECT bundle_id,subkeys FROM account_mac_bundle WHERE is_current=1",
            [],
            |r| Ok((r.get(0)?, zeroize::Zeroizing::new(r.get(1)?))),
        )?;
        let mac =
            super::super::mac_subkeys::current_mac(other, b"ramflux/tombstone-key/v1", b"message")?;
        authority.execute(
            "INSERT INTO account_mac_bundle VALUES(?1,?2,0)",
            params![foreign_id, foreign_bytes.as_slice()],
        )?;
        authority.execute_batch("CREATE TABLE account_mac_marker_bundle(state_kind TEXT PRIMARY KEY,bundle_id TEXT NOT NULL)")?;
        authority.execute(
            "INSERT INTO account_mac_marker_bundle VALUES(?1,?2)",
            params![format!("message/deleted/{mac}"), foreign_id],
        )?;
        mac
    } else if kind == "legacy" {
        blake3_256_base64url("ramflux.deleted-message.v1", b"message")
    } else {
        super::super::mac_subkeys::current_mac(
            authority,
            if kind == "envelope" {
                b"ramflux/deleted-envelope/v1"
            } else {
                b"ramflux/tombstone-key/v1"
            },
            if kind == "envelope" { b"envelope" } else { b"message" },
        )?
    };
    if kind != "control" {
        let name = format!(
            "message/{}{mac}",
            if kind == "envelope" { "deleted-envelope/" } else { "deleted/" }
        );
        authority.execute(
            "INSERT INTO runtime_actor_state VALUES(?1,?2)",
            params![name, br#"{"version":2}"#.as_slice()],
        )?;
    }
    for input in [&target.db, &source.db] {
        input.execute(
            "INSERT OR IGNORE INTO message_copy_binding VALUES('envelope:envelope','message')",
            [],
        )?;
        assert!(!input.query_row("SELECT EXISTS(SELECT 1 FROM direct_message_projection WHERE deleted=1) OR EXISTS(SELECT 1 FROM message_tombstone_projection) OR EXISTS(SELECT 1 FROM group_message_tombstone_projection)", [], |r|r.get::<_,bool>(0))?);
    }
    Ok(())
}

#[test]
fn graph_admission_uses_each_inputs_mac_subkey_bundles() -> TestResult {
    for direction in ["main", "incoming"] {
        for kind in ["current", "foreign", "envelope", "legacy", "control"] {
            fixture("bilateral-markers", |root, _, target, path, key| {
                let (donor_root, donor) = crate::tests::test_db("marker-authority-donor")?;
                let donor_path = root.join("donor.db");
                let snapshot = donor.write_backup_snapshot(&donor_path)?;
                let donor_db = BackupDatabase::open(&donor_path, &snapshot.key)?;
                let source = BackupDatabase::open(path, key)?;
                install_input_marker(target, &source, &donor_db, direction, kind)?;
                drop(source);
                let source_before = std::fs::read(path)?;
                let observe = |db: &Connection| {
                    graph::classify(db)?;
                    let kept: u64 =
                        db.query_row("SELECT count(*) FROM backup_reference_admission", [], |r| {
                            r.get(0)
                        })?;
                    assert_eq!(kept, if kind == "control" { 2 } else { 0 }, "{direction}/{kind}");
                    assert_eq!(
                        db.query_row("SELECT count(*) FROM backup_target_delete", [], |r| r
                            .get::<_, u64>(0))?,
                        u64::from(direction == "incoming" && kind != "control")
                    );
                    assert_eq!(
                        db.query_row(
                            "SELECT count(*) FROM backup_selector_admission WHERE decision='erase'",
                            [],
                            |r| r.get::<_, u64>(0)
                        )?,
                        if kind == "control" { 0 } else { 2 }
                    );
                    // Classification cannot unlink the pending target owner.
                    assert_eq!(
                        db.query_row(
                            "SELECT count(*) FROM main.object_message_reference",
                            [],
                            |r| r.get::<_, u64>(0)
                        )?,
                        1
                    );
                    Err(StorageError::AuthorizationRejected)
                };
                for retry in [false, true] {
                    let rekeyed_source = root.join("rekeyed-source.db");
                    let new_key = AccountDbKey::generate()?;
                    let (input_path, input_key) = if retry {
                        let source = BackupDatabase::open(path, key)?;
                        source.copy_to(&rekeyed_source, &new_key)?;
                        let rekeyed_target = root.join("rekeyed-target.db");
                        let target_key = AccountDbKey::generate()?;
                        target.copy_to(&rekeyed_target, &target_key)?;
                        *target = BackupDatabase::open(&rekeyed_target, &target_key)?;
                        (rekeyed_source.as_path(), &new_key)
                    } else {
                        (path, key)
                    };
                    let input_before = std::fs::read(input_path)?;
                    let result = target.merge_backup_pipeline(
                        input_path,
                        input_key,
                        (BackupMergeMode::FullAccount(None), true),
                        &mut || Ok(()),
                        observe,
                    );
                    assert!(matches!(result, Err(StorageError::AuthorizationRejected)));
                    absent(&target.db)?;
                    assert_eq!(
                        blake3_256_base64url("test.archive.v1", &std::fs::read(input_path)?),
                        blake3_256_base64url("test.archive.v1", &input_before),
                        "merge changed its source archive"
                    );
                    if !retry {
                        assert_eq!(
                            blake3_256_base64url("test.archive.v1", &std::fs::read(path)?),
                            blake3_256_base64url("test.archive.v1", &source_before)
                        );
                    }
                }
                drop(donor_db);
                drop(donor);
                std::fs::remove_dir_all(donor_root)?;
                Ok(())
            })?;
        }
    }
    Ok(())
}

#[test]
fn classification_preserves_lookup_origin_and_fence_dominance() -> TestResult {
    for origin in ["target", "incoming"] {
        for survivor in [false, true] {
            for fence in [false, true] {
                fixture("graph-origin", |_, _, target, path, key| {
                    let source = BackupDatabase::open(path, key)?;
                    let lookup: String = source.db.query_row(
                        "SELECT selector_lookup FROM object_retention_reference",
                        [],
                        |r| r.get(0),
                    )?;
                    let commitment: String = source.db.query_row(
                        "SELECT commitment FROM object_retention_reference",
                        [],
                        |r| r.get(0),
                    )?;
                    let history = if origin == "target" { &target.db } else { &source.db };
                    history.execute(
                        "INSERT INTO object_erasure_lookup VALUES(?1,?2)",
                        params![lookup, commitment],
                    )?;
                    if !survivor {
                        target.db.execute_batch("DELETE FROM object_message_reference; DELETE FROM object_retention_reference;")?;
                    }
                    if fence {
                        source.db.execute(
                            "INSERT INTO object_erasure_fence VALUES(?1)",
                            [&commitment],
                        )?;
                    }
                    drop(source);
                    let result = target.merge_backup_pipeline(path,key,(BackupMergeMode::FullAccount(None),true),&mut ||Ok(()),|db| {
                        graph::classify(db)?;
                        let admitted: u64 = db.query_row("SELECT count(*) FROM backup_reference_admission WHERE side='incoming'",[],|r|r.get(0))?;
                        assert_eq!(admitted,u64::from(!fence && (origin == "incoming" || survivor)),"{origin}/{survivor}/{fence}");
                        assert_eq!(db.query_row("SELECT count(*) FROM backup_lookup_origin WHERE side=?1 AND lookup=?2",params![origin,lookup],|r|r.get::<_,u64>(0))?,1);
                        Err(StorageError::AuthorizationRejected)
                    });
                    assert!(
                        matches!(result, Err(StorageError::AuthorizationRejected)),
                        "{origin}/{survivor}/{fence}: {result:?}"
                    );
                    absent(&target.db)?;
                    Ok(())
                })?;
            }
        }
    }
    Ok(())
}

#[test]
fn dependency_fences_reach_fixed_point_across_both_graphs() -> TestResult {
    fixture("bilateral-dependencies", |_, _, target, path, key| {
        let source = BackupDatabase::open(path, key)?;
        let root: String = target.db.query_row(
            "SELECT principal_commitment FROM runtime_account_identity WHERE singleton=1",
            [],
            |r| r.get(0),
        )?;
        let child: String =
            target
                .db
                .query_row("SELECT commitment FROM object_retention_reference", [], |r| r.get(0))?;
        let first = object_erasure_commitment(&root, "first", "manifest");
        let second = object_erasure_commitment(&root, "second", "manifest");
        for input in [&target.db, &source.db] {
            for (wire, commitment) in [("first", &first), ("second", &second)] {
                input.execute("INSERT INTO object_retention_payload(commitment,wire_id,manifest_hash,wire_lookup,retention_class) VALUES(?1,?2,'manifest',?3,'transport')", params![commitment,wire,object_erasure_lookup(&root,wire)])?;
            }
        }
        target.db.execute(
            "INSERT INTO object_payload_dependency VALUES(?1,?2)",
            params![first, second],
        )?;
        source.db.execute(
            "INSERT INTO object_payload_dependency VALUES(?1,?2)",
            params![second, child],
        )?;
        source.db.execute("INSERT INTO object_erasure_fence VALUES(?1)", [child])?;
        drop(source);
        let result = target.merge_backup_pipeline(
            path,
            key,
            (BackupMergeMode::FullAccount(None), true),
            &mut || Ok(()),
            |db| {
                graph::classify(db)?;
                assert_eq!(
                    db.query_row("SELECT count(*) FROM object_erasure_fence", [], |r| r
                        .get::<_, u64>(0))?,
                    3
                );
                assert_eq!(
                    db.query_row("SELECT count(*) FROM backup_reference_admission", [], |r| r
                        .get::<_, u64>(0))?,
                    0
                );
                Err(StorageError::AuthorizationRejected)
            },
        );
        assert!(matches!(result, Err(StorageError::AuthorizationRejected)));
        absent(&target.db)?;
        assert_eq!(
            target.db.query_row("SELECT count(*) FROM object_erasure_fence", [], |r| r
                .get::<_, u64>(0))?,
            0
        );
        Ok(())
    })
}
