// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Constant-closure VM budgets with unrelated ownership and private copies.
use super::*;
use rusqlite::StatementStatus;
use serde_json::json;

fn unrelated_rows(db: &AccountDb, count: i64) -> Result<(), StorageError> {
    db.write_transaction(|| {
        db.connection.execute_batch("CREATE TEMP TABLE budget_unrelated(i INTEGER PRIMARY KEY);")?;
        db.connection.execute("INSERT INTO budget_unrelated WITH RECURSIVE n(i) AS (SELECT 1 WHERE ?1>0 UNION ALL SELECT i+1 FROM n WHERE i<?1) SELECT i FROM n", params![count])?;
        db.connection.execute_batch(r"
            INSERT INTO object_retention_payload SELECT 'c-'||i,'wire-'||i,'manifest','lookup-'||i,'imported',NULL,0 FROM budget_unrelated;
            INSERT INTO object_retention_reference SELECT 'ref-'||i,'c-'||i,'alias-'||i,'selector-'||i,x'7b7d' FROM budget_unrelated;
            INSERT INTO object_message_reference SELECT 'message-'||i,'ref-'||i,x'7b7d' FROM budget_unrelated;
            INSERT INTO object_index(object_id,chunk_manifest_hash,object_state,total_cipher_size,chunk_count,created_at,updated_at,manifest_hash,nonce,ciphertext,tombstoned,backup_excluded,object_body)
            SELECT 'alias-'||i,CAST('manifest' AS BLOB),'tombstoned',0,0,1,1,CAST('manifest' AS BLOB),x'',x'',1,0,x'7b7d' FROM budget_unrelated;
            INSERT INTO runtime_actor_state(state_kind,state_json) SELECT 'attachment/reference/alias-'||i,CAST(json_object('reference',json_object('object_id','wire-'||i,'manifest_hash','manifest')) AS BLOB) FROM budget_unrelated;
            INSERT INTO object_payload_actor SELECT 'c-'||i,'attachment/reference/alias-'||i FROM budget_unrelated;
            INSERT INTO object_reference_actor SELECT 'ref-'||i,'attachment/reference/alias-'||i FROM budget_unrelated;
            INSERT INTO message_copy_binding SELECT 'object:alias-'||i,'message-'||i FROM budget_unrelated;
            INSERT OR IGNORE INTO message_footprint SELECT 'message-'||i,'actor','attachment/reference/alias-'||i FROM budget_unrelated;
            INSERT INTO message_footprint SELECT 'message-'||i,'revocation_selector',json_object('selector','alias-'||i,'wire','wire-'||i,'manifest','manifest','commitment','c-'||i,'selector_lookup','selector-'||i) FROM budget_unrelated;
            DROP TABLE budget_unrelated;
        ")?;
        Ok(())
    })
}

fn candidate(db: &AccountDb, transport: bool) -> Result<(), StorageError> {
    super::tests::install(db, "affected", "affected-reference")?;
    super::tests::payload(db)?;
    db.persist_actor_state(
        "attachment/reference/wire",
        &json!({"reference":{"object_id":"wire","manifest_hash":"manifest"}}),
    )?;
    db.register_object_reference(
        ObjectReferenceAdmission::FreshMessage,
        &ObjectReferenceOwner {
            reference_hash: "alias-reference",
            wire_id: "wire",
            manifest_hash: "manifest",
            selector: "alias",
            message_id: "affected",
            reference: &json!({"reference":{"object_id":"wire","manifest_hash":"manifest"}}),
            metadata: &json!({"message_id":"affected"}),
        },
    )?;
    db.set_object_tombstoned("alias")?;
    if transport {
        db.retain_object("wire", "manifest", ObjectRetention::OwnDeviceTransport)?;
    }
    Ok(())
}

fn bound(baseline: &mut Option<u64>, steps: u64, count: i64, label: &str) {
    let base = *baseline.get_or_insert(steps);
    let ceiling = (base * 105).div_ceil(100) + 64;
    eprintln!("{label}: N={count} steps={steps} baseline={base} ceiling={ceiling}");
    assert!(
        steps <= ceiling,
        "{label} scales with unrelated rows: N={count}, steps={steps}, base={base}, ceiling={ceiling}"
    );
}

fn end_to_end(transport: bool) -> Result<(), StorageError> {
    let mut baseline = None;
    for count in [0, 1_000, 10_000] {
        let (root, db) = crate::tests::test_db("selector-budget")?;
        candidate(&db, transport)?;
        unrelated_rows(&db, count)?;
        let (result, steps) = db.measure_sqlite_vm_steps(|| {
            if transport {
                db.retire_transport_object("wire", "manifest")
            } else {
                db.delete_direct_message("thread", "affected", "local", "delete").map(|_| ())
            }
        })?;
        result?;
        bound(
            &mut baseline,
            steps,
            count,
            if transport { "transport retirement" } else { "message deletion" },
        );
        assert!(matches!(db.check_object_access("wire"), Err(StorageError::ObjectErased)));
        assert_eq!(
            db.connection
                .query_row("SELECT count(*) FROM object_index", [], |r| r.get::<_, i64>(0))?,
            count
        );
        assert_eq!(
            db.connection
                .query_row("SELECT count(*) FROM object_message_reference", [], |r| r
                    .get::<_, i64>(0))?,
            count
        );
        for table in [
            "object_erasure_work",
            "object_reference_erasure_work",
            "object_projection_erasure_work",
        ] {
            assert_eq!(
                db.connection.query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r
                    .get::<_, i64>(0))?,
                0
            );
        }
        drop(db);
        std::fs::remove_dir_all(root)?;
    }
    Ok(())
}

#[test]
fn b1_message_delete_end_to_end_budget() -> Result<(), StorageError> {
    end_to_end(false)
}

#[test]
fn b1_transport_retire_end_to_end_budget() -> Result<(), StorageError> {
    end_to_end(true)
}

#[test]
fn b1_g4_candidate_delete_budget() -> Result<(), StorageError> {
    let mut baseline = None;
    for count in [0, 1_000, 10_000] {
        let (root, db) = crate::tests::test_db("selector-candidate-budget")?;
        candidate(&db, false)?;
        unrelated_rows(&db, count)?;
        db.connection.execute("INSERT INTO object_reference_erasure_work SELECT reference_hash,selector,selector_lookup,commitment FROM object_retention_reference WHERE reference_hash='alias-reference'", [])?;
        db.connection
            .execute("DELETE FROM object_message_reference WHERE message_id='affected'", [])?;
        db.connection.execute(
            "DELETE FROM object_retention_reference WHERE reference_hash='alias-reference'",
            [],
        )?;
        let steps = db.connection.call(|raw| {
            // Fully step the production candidate DELETE, including its triggers.
            let sql = super::selector_erasure::RETIRE
                .split(';')
                .find(|s| s.trim_start().starts_with("DELETE FROM object_index"))
                .ok_or(rusqlite::Error::InvalidQuery)?;
            let mut statement = raw.prepare(sql)?;
            statement.reset_status(StatementStatus::VmStep);
            statement.execute([])?;
            u64::try_from(statement.get_status(StatementStatus::VmStep))
                .map_err(|_| rusqlite::Error::InvalidQuery)
        })?;
        bound(&mut baseline, steps, count, "G4 candidate DELETE");
        assert_eq!(
            db.connection.query_row(
                "SELECT count(*) FROM object_index WHERE object_id='alias'",
                [],
                |r| r.get::<_, i64>(0)
            )?,
            0
        );
        drop(db);
        std::fs::remove_dir_all(root)?;
    }
    Ok(())
}

#[test]
fn b1_g3_capture_and_lookup_budget() -> Result<(), StorageError> {
    let mut baselines = [None; 3];
    for count in [0, 1_000, 10_000] {
        let (root, db) = crate::tests::test_db("selector-capture-budget")?;
        candidate(&db, false)?;
        unrelated_rows(&db, count)?;
        db.connection.execute("INSERT INTO object_erasure_work SELECT commitment,wire_id,manifest_hash FROM object_retention_payload WHERE wire_id='wire'", [])?;
        let steps = db.connection.call(|raw| {
            let body = super::schema::payload_erasure_body(raw)?;
            let prefixes = [
                "INSERT INTO object_reference_erasure_work",
                "INSERT INTO object_erasure_lookup SELECT w.selector_lookup",
                "INSERT INTO object_erasure_lookup SELECT wire_lookup",
            ];
            let mut measured = Vec::new();
            for (index, prefix) in prefixes.into_iter().enumerate() {
                if index == 1 {
                    // Retirement removes owners between capture and lookup publication.
                    raw.execute(
                        "DELETE FROM object_message_reference WHERE message_id='affected'",
                        [],
                    )?;
                }
                let sql = body
                    .split(';')
                    .find(|s| s.trim_start().starts_with(prefix))
                    .ok_or(rusqlite::Error::InvalidQuery)?;
                let mut q = raw.prepare(sql)?;
                q.reset_status(StatementStatus::VmStep);
                q.execute([])?;
                measured.push(
                    u64::try_from(q.get_status(StatementStatus::VmStep))
                        .map_err(|_| rusqlite::Error::InvalidQuery)?,
                );
            }
            Ok(measured)
        })?;
        for (index, steps) in steps.into_iter().enumerate() {
            bound(
                &mut baselines[index],
                steps,
                count,
                ["G3 capture", "selector lookup", "payload lookup"][index],
            );
        }
        assert_eq!(
            db.connection.query_row(
                "SELECT count(*) FROM object_reference_erasure_work",
                [],
                |r| r.get::<_, i64>(0)
            )?,
            2
        );
        assert_eq!(
            db.connection.query_row("SELECT count(*) FROM object_erasure_lookup", [], |r| r
                .get::<_, i64>(0))?,
            2
        );
        drop(db);
        std::fs::remove_dir_all(root)?;
    }
    Ok(())
}

#[test]
fn b1_legacy_hook_delete_budget() -> Result<(), StorageError> {
    let mut baseline = None;
    for count in [0, 1_000, 10_000] {
        let (root, db) = crate::tests::test_db("legacy-hook-budget")?;
        super::selector_legacy_tests::fixture(&db)?;
        unrelated_rows(&db, count)?;
        let (result, steps) = db.measure_sqlite_vm_steps(|| {
            db.delete_direct_message("thread", "message", "local", "delete")
        })?;
        result?;
        bound(&mut baseline, steps, count, "legacy footprint deletion");
        assert!(matches!(
            db.check_object_access("private-canary"),
            Err(StorageError::ObjectErased)
        ));
        assert!(!db.object_is_tombstoned("private-canary")?);
        assert_eq!(db.privacy_erasure_generation()?, 1);
        let survivors: i64 =
            db.connection.query_row("SELECT COUNT(*) FROM object_index", [], |row| row.get(0))?;
        assert_eq!(survivors, count);
        let footprints: i64 = db.connection.query_row(
            "SELECT COUNT(*) FROM message_footprint WHERE kind='revocation_selector'",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(footprints, count);
        drop(db);
        std::fs::remove_dir_all(root)?;
    }
    Ok(())
}

#[test]
fn b1_managed_legacy_survivor_budget() -> Result<(), StorageError> {
    let mut baseline = None;
    for count in [0, 1_000, 10_000] {
        let (root, db) = crate::tests::test_db("managed-legacy-budget")?;
        super::selector_legacy_tests::fixture(&db)?;
        super::tests::install(&db, "wire-owner", "wire-reference")?;
        db.send_direct_message("thread", "managed", "peer", b"body")?;
        db.register_object_reference(
            ObjectReferenceAdmission::FreshMessage,
            &ObjectReferenceOwner {
                reference_hash: "managed-reference",
                wire_id: "wire",
                manifest_hash: "manifest",
                selector: "private-canary",
                message_id: "managed",
                reference: &json!({"reference":{"object_id":"wire","manifest_hash":"manifest"}}),
                metadata: &json!({"message_id":"managed"}),
            },
        )?;
        unrelated_rows(&db, count)?;
        let (result, steps) = db.measure_sqlite_vm_steps(|| {
            db.delete_direct_message("thread", "managed", "local", "delete")
        })?;
        result?;
        bound(&mut baseline, steps, count, "managed legacy survivor");
        assert!(db.object_is_tombstoned("private-canary")?);
        assert!(db.actor_state_exists("attachment/reference/private-canary")?);
        let survivors: i64 =
            db.connection.query_row("SELECT COUNT(*) FROM object_index", [], |r| r.get(0))?;
        assert_eq!(survivors, count + 1);
        let lookups: i64 = db.connection.query_row(
            "SELECT COUNT(*) FROM object_erasure_lookup WHERE lookup=?1",
            params![object_erasure_lookup(db.object_erasure_root(), "private-canary")],
            |r| r.get(0),
        )?;
        assert_eq!(lookups, 0);
        drop(db);
        std::fs::remove_dir_all(root)?;
    }
    Ok(())
}
