// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Candidate classification budgets; input validation and scratch capture are outside the window.
use super::*;
use crate::{AccountDb, BackupDatabase, ObjectReferenceAdmission, ObjectReferenceOwner};
use rusqlite::StatementStatus;
use serde_json::json;
type TestResult = Result<(), Box<dyn std::error::Error>>;
const BINDINGS: &str = "SELECT copy_id,message_id FROM main.message_copy_binding UNION ALL SELECT copy_id,message_id FROM incoming.message_copy_binding";

fn standalone(db: &Connection, sql: &str, message: Option<&str>) -> rusqlite::Result<u64> {
    let mut statement = db.prepare(sql)?;
    statement.reset_status(StatementStatus::VmStep);
    {
        let mut rows = if let Some(message) = message {
            statement.query([message])?
        } else {
            statement.query([])?
        };
        while rows.next()?.is_some() {}
    }
    u64::try_from(statement.get_status(StatementStatus::VmStep))
        .map_err(|_| rusqlite::Error::InvalidQuery)
}

fn sample(n: i64, m: usize) -> Result<Vec<u64>, Box<dyn std::error::Error>> {
    let mut measured = Vec::new();
    super::tests::fixture("restore-classification-budget", |root, live, target, _, _| {
        add_candidates(live, m)?;
        let path = root.join("budget-input.db");
        let snapshot = live.write_backup_snapshot(&path)?;
        // Unrelated local messages, bindings, actors, footprints and group restrictions.
        // The reference candidate set stays fixed; whole-restore traversal is not bounded here.
        target
            .db
            .execute_batch("BEGIN; CREATE TABLE main.budget_numbers(i INTEGER PRIMARY KEY);")?;
        target.db.execute("INSERT INTO budget_numbers WITH RECURSIVE n(i) AS (SELECT 1 WHERE ?1>0 UNION ALL SELECT i+1 FROM n WHERE i<?1) SELECT i FROM n", [n])?;
        target.db.execute_batch(r"
INSERT INTO message_copy_binding SELECT 'group:other:unrelated-'||i,'unrelated-'||i FROM budget_numbers;
INSERT INTO message_copy_binding VALUES('group:missing:missing','message');
INSERT INTO runtime_actor_state SELECT 'budget/'||i,x'7b7d' FROM budget_numbers;
INSERT INTO message_footprint SELECT 'unrelated-'||i,'actor','budget/'||i FROM budget_numbers;
INSERT INTO message_footprint SELECT 'unrelated-'||i,'revocation_selector',json_object('selector','alias-'||i,'wire','wire-'||i,'manifest','manifest','commitment','c-'||i) FROM budget_numbers;
INSERT INTO group_message_tombstone_projection SELECT 'other','unrelated-'||i,'delete','device','all',1,'',1 FROM budget_numbers;
INSERT INTO message_tombstone_projection SELECT 'dm-delete-'||i,'other-dm','unrelated-tombstone-'||i,'all',1 FROM budget_numbers;
INSERT INTO direct_message_projection(conversation_id,message_id,sender_id,encrypted_body,metadata_json,deleted,is_own,scrub_version,created_at) SELECT 'other-dm','unrelated-deleted-'||i,'peer',x'',x'7b7d',1,0,0,1 FROM budget_numbers;
DROP TABLE budget_numbers; COMMIT;")?;
        let source_before = std::fs::read(&path)?;
        target.db.execute(
            &format!("ATTACH DATABASE ?1 AS incoming KEY \"x'{}'\"", snapshot.key.sqlcipher_hex()),
            [path.to_str().ok_or("non-UTF8 test path")?],
        )?;
        target.db.execute_batch("BEGIN IMMEDIATE;")?;
        prepare(&target.db)?;
        assert_eq!(
            target.db.query_row(
                "SELECT count(*) FROM message_footprint WHERE message_id GLOB 'unrelated-*' AND kind='revocation_selector'",
                [],
                |r| r.get::<_, i64>(0)
            )?,
            n
        );
        for sql in [
            "SELECT count(*) FROM message_tombstone_projection WHERE message_id GLOB 'unrelated-tombstone-*'",
            "SELECT count(*) FROM direct_message_projection WHERE message_id GLOB 'unrelated-deleted-*' AND deleted=1",
        ] {
            assert_eq!(target.db.query_row(sql, [], |r| r.get::<_, i64>(0))?, n);
        }
        assert_eq!(target.db.query_row("SELECT count(*) FROM backup_message_delete WHERE side='main' AND message_id GLOB 'unrelated-*'", [], |r| r.get::<_, i64>(0))?, 2 * n);
        for table in TABLES {
            assert!(!target.db.query_row(
                "SELECT EXISTS(SELECT 1 FROM temp.sqlite_master WHERE name=?1)",
                [table],
                |r| r.get::<_, bool>(0)
            )?);
        }
        calibrate(target, n, m)?;
        // Traverse and seed target authority outside the candidate window.
        graph::classify(&target.db)?;
        target.db.execute_batch("DELETE FROM backup_reference_admission WHERE side='incoming'; DELETE FROM backup_selector_admission WHERE side='incoming';")?;
        let candidates = target.db.prepare("SELECT r.reference_hash,m.message_id,r.selector,r.commitment FROM incoming.object_retention_reference r JOIN incoming.object_message_reference m USING(reference_hash)")?
            .query_map([], |r| Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?,r.get::<_,String>(2)?,r.get::<_,String>(3)?)))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        assert_eq!(candidates.len(), m);
        // Unrelated ownership graph and scratch-index population are setup, never metered.
        target.db.execute_batch("CREATE TABLE main.budget_numbers(i INTEGER PRIMARY KEY);")?;
        target.db.execute("INSERT INTO budget_numbers WITH RECURSIVE n(i) AS (SELECT 1 WHERE ?1>0 UNION ALL SELECT i+1 FROM n WHERE i<?1) SELECT i FROM n", [n])?;
        target.db.execute_batch(r"
INSERT INTO object_retention_payload SELECT 'c-'||i,'wire-'||i,'manifest','lookup-'||i,'imported',NULL,0 FROM budget_numbers;
INSERT INTO object_retention_reference SELECT 'ref-'||i,'c-'||i,'alias-'||i,'selector-'||i,x'7b7d' FROM budget_numbers;
INSERT INTO object_message_reference SELECT 'unrelated-'||i,'ref-'||i,x'7b7d' FROM budget_numbers;
INSERT INTO object_index(object_id,chunk_manifest_hash,object_state,total_cipher_size,chunk_count,created_at,updated_at,manifest_hash,nonce,ciphertext,tombstoned,backup_excluded,object_body)
SELECT 'alias-'||i,CAST('manifest' AS BLOB),'tombstoned',0,0,1,1,CAST('manifest' AS BLOB),x'',x'',1,0,x'7b7d' FROM budget_numbers;
INSERT INTO object_reference_actor SELECT 'ref-'||i,'budget/'||i FROM budget_numbers;
INSERT INTO object_payload_actor SELECT 'c-'||i,'budget/'||i FROM budget_numbers;
INSERT INTO backup_reference_admission SELECT 'target','ref-'||i,'unrelated-'||i,'alias-'||i,'c-'||i FROM budget_numbers;
INSERT INTO backup_selector_admission SELECT 'target','alias-'||i,'c-'||i,'keep' FROM budget_numbers;
DROP TABLE budget_numbers;")?;
        measured = measure_candidates(target, &candidates)?;
        // Decisions are independent of unrelated state, including on the U26 broken index path.
        for (hash, message, selector, commitment) in &candidates {
            assert!(target.db.query_row("SELECT EXISTS(SELECT 1 FROM backup_reference_admission r JOIN backup_selector_admission s USING(side,selector,commitment) WHERE r.side='incoming' AND r.reference_hash=?1 AND r.message_id=?2 AND r.selector=?3 AND r.commitment=?4 AND s.decision='keep')", params![hash,message,selector,commitment], |r|r.get::<_,bool>(0))?);
        }
        let rows =
            target.db.query_row("SELECT count(*) FROM backup_reference_admission", [], |r| {
                r.get::<_, usize>(0)
            })?;
        assert_eq!(rows, m + 1 + usize::try_from(n)?);
        assert_eq!(
            target.db.query_row(
                "SELECT count(*) FROM backup_selector_admission WHERE decision='keep'",
                [],
                |r| r.get::<_, usize>(0)
            )?,
            m + 1 + usize::try_from(n)?
        );
        assert_eq!(
            target.db.query_row("SELECT count(*) FROM backup_target_delete", [], |r| r
                .get::<_, usize>(0))?,
            0
        );
        target.db.execute_batch("ROLLBACK; DETACH DATABASE incoming;")?;
        assert_eq!(std::fs::read(&path)?, source_before);
        Ok(())
    })?;
    Ok(measured)
}

#[test]
fn b2_classification_independent_of_unrelated_local_n() -> TestResult {
    let baseline = sample(0, 1)?;
    for n in [1_000, 10_000] {
        let steps = sample(n, 1)?;
        assert_eq!(steps.len(), baseline.len());
        for (index, (&steps, &base)) in steps.iter().zip(&baseline).enumerate().rev() {
            let ceiling = (base * 105).div_ceil(100) + 64;
            eprintln!("N={n} statement={index} steps={steps} baseline={base} ceiling={ceiling}");
            assert!(
                steps <= ceiling,
                "classification statement {index}: N={n}, {steps} > {ceiling}"
            );
        }
    }
    Ok(())
}

#[test]
fn b2_classification_linear_in_incoming_candidates() -> TestResult {
    let baseline = sample(100, 1)?;
    for m in [10, 100] {
        let steps = sample(100, m)?;
        assert_eq!(steps.len(), baseline.len());
        for (index, (&steps, &base)) in steps.iter().zip(&baseline).enumerate().rev() {
            let ceiling = u64::try_from(m)? * base + 64;
            eprintln!("M={m} statement={index} steps={steps} baseline={base} ceiling={ceiling}");
            assert!(
                steps <= ceiling,
                "classification statement {index}: M={m}, {steps} > {ceiling}"
            );
        }
    }
    Ok(())
}

fn add_candidates(live: &AccountDb, m: usize) -> TestResult {
    live.connection.execute_batch("PRAGMA synchronous=OFF;")?;
    for i in 1..m {
        let message = format!("candidate-{i}");
        let wire = format!("candidate-wire-{i}");
        live.send_direct_message("thread", &message, "peer", b"body")?;
        let hash = blake3_256_base64url(
            "ramflux.object.transport.owner.v1",
            &ramflux_protocol::canonical_json_bytes(&(&wire, "manifest", &message))?,
        );
        live.register_object_reference(
            ObjectReferenceAdmission::FreshMessage,
            &ObjectReferenceOwner {
                reference_hash: &hash,
                wire_id: &wire,
                manifest_hash: "manifest",
                selector: &wire,
                message_id: &message,
                reference: &json!({}),
                metadata: &json!({}),
            },
        )?;
    }
    Ok(())
}

fn calibrate(target: &BackupDatabase, n: i64, m: usize) -> TestResult {
    // Known scan on the exact worker connection proves the grouped meter is live.
    let (calibration, calibration_steps) = target.measure_restore_vm_steps(|| {
        target.db.query_row("SELECT sum(length(copy_id)) FROM main.message_copy_binding", [], |r| {
            r.get::<_, i64>(0)
        })
    });
    assert!(calibration? > 0 && calibration_steps > 0);
    let (error, _) = target
        .measure_restore_vm_steps(|| target.db.execute_batch("SELECT * FROM missing_meter_table"));
    assert!(error.is_err());
    // A removed progress handler cannot touch this independent counter.
    // Positive, repeatable calibration after an error exercises handler reset.
    let (_, repeated) = target.measure_restore_vm_steps(|| {
        target.db.query_row("SELECT sum(length(copy_id)) FROM main.message_copy_binding", [], |r| {
            r.get::<_, i64>(0)
        })
    });
    assert_eq!(repeated, calibration_steps);
    eprintln!("calibration N={n} M={m}: {calibration_steps}");

    Ok(())
}

type Candidate = (String, String, String, String);
fn measure_candidates(
    target: &BackupDatabase,
    candidates: &[Candidate],
) -> Result<Vec<u64>, Box<dyn std::error::Error>> {
    let mut measured = Vec::new();
    let mut statements = Vec::new();
    for (schema, bindings) in [
        ("main", BINDINGS),
        ("incoming", BINDINGS),
        ("main", "SELECT copy_id,message_id FROM main.message_copy_binding"),
    ] {
        statements.extend(restrictions::queries(schema, bindings));
    }
    for sql in statements {
        let mut total = 0;
        for (_, message, _, _) in candidates {
            total += standalone(&target.db, &sql, Some(message))?;
        }
        assert!(total > 0);
        measured.push(total);
    }
    let mut veto_steps = 0;
    for (hash, _, selector, commitment) in candidates {
        let mut query = target.db.prepare(graph::VETO)?;
        query.reset_status(StatementStatus::VmStep);
        let _: bool = query.query_row(params![hash, selector, commitment], |r| r.get(0))?;
        veto_steps += u64::try_from(query.get_status(StatementStatus::VmStep))?;
    }
    measured.push(veto_steps);
    measured.extend(standalone_owner_writes(&target.db, candidates)?);
    let mut fence_steps = 0;
    for (_, _, _, commitment) in candidates {
        let mut statement = target.db.prepare(graph::FENCED)?;
        statement.reset_status(StatementStatus::VmStep);
        let _: bool = statement.query_row([commitment], |r| r.get(0))?;
        fence_steps += u64::try_from(statement.get_status(StatementStatus::VmStep))?;
    }
    measured.push(fence_steps);

    let target_candidate = target.db.query_row("SELECT r.reference_hash,m.message_id,r.selector,r.commitment FROM main.object_retention_reference r JOIN main.object_message_reference m USING(reference_hash) WHERE r.selector='wire'", [], |r| Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?,r.get::<_,String>(2)?,r.get::<_,String>(3)?)))?;
    target.db.execute(
        "DELETE FROM backup_reference_admission WHERE side='target' AND reference_hash=?1",
        [&target_candidate.0],
    )?;
    target.db.execute(
        "DELETE FROM backup_selector_admission WHERE side='target' AND selector=?1",
        [&target_candidate.2],
    )?;
    let (result, grouped) = target.measure_restore_vm_steps(|| -> Result<(), StorageError> {
        let (hash, message, selector, commitment) = &target_candidate;
        graph::classify_owner(&target.db, "target", hash, message, selector, commitment)?;
        graph::classify_selector(&target.db, "target", selector, commitment)?;
        for (hash, message, selector, commitment) in candidates {
            graph::classify_owner(&target.db, "incoming", hash, message, selector, commitment)?;
        }
        for (_, _, selector, commitment) in candidates {
            graph::classify_selector(&target.db, "incoming", selector, commitment)?;
        }
        Ok(())
    });
    result?;
    assert!(grouped > 0);
    // Fully step the production selector decision independently against populated admissions.
    target.db.execute_batch("SAVEPOINT selector_statement; DELETE FROM backup_selector_admission WHERE side='incoming';")?;
    let mut statement = target.db.prepare(graph::SELECTOR)?;
    let mut selector_steps = 0;
    for (_, _, selector, commitment) in candidates {
        statement.reset_status(StatementStatus::VmStep);
        statement.execute(params!["incoming", selector, commitment])?;
        selector_steps += u64::try_from(statement.get_status(StatementStatus::VmStep))?;
    }
    measured.push(selector_steps);
    drop(statement);
    target.db.execute_batch("ROLLBACK TO selector_statement; RELEASE selector_statement;")?;
    measured.push(grouped);
    assert!(measured.iter().all(|&steps| steps > 0));
    Ok(measured)
}

fn standalone_owner_writes(
    db: &Connection,
    candidates: &[Candidate],
) -> Result<[u64; 2], Box<dyn std::error::Error>> {
    let mut steps = [0; 2];
    for (hash, message, selector, commitment) in candidates {
        db.execute_batch("SAVEPOINT owner_statements;")?;
        for (index, sql) in [graph::ADMIT, graph::PENDING].into_iter().enumerate() {
            let mut statement = db.prepare(sql)?;
            statement.reset_status(StatementStatus::VmStep);
            if index == 0 {
                statement.execute(params!["incoming", hash, message, selector, commitment])?;
            } else {
                statement.execute(params![hash, message, selector, commitment])?;
            }
            steps[index] += u64::try_from(statement.get_status(StatementStatus::VmStep))?;
        }
        db.execute_batch("ROLLBACK TO owner_statements; RELEASE owner_statements;")?;
    }
    Ok(steps)
}
