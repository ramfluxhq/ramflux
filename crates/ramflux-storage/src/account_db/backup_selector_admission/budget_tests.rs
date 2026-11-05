// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Candidate classification budgets; input validation and scratch capture are outside the window.
use super::*;
use crate::{ObjectReferenceAdmission, ObjectReferenceOwner};
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
    Ok(u64::try_from(statement.get_status(StatementStatus::VmStep)).unwrap())
}

fn sample(n: i64, m: usize) -> Result<Vec<u64>, Box<dyn std::error::Error>> {
    let mut measured = Vec::new();
    super::tests::fixture("restore-classification-budget", |root, live, target, _, _| {
        for i in 1..m {
            let message = format!("candidate-{i}");
            live.send_direct_message("thread", &message, "peer", b"body")?;
            let hash = blake3_256_base64url(
                "ramflux.object.transport.owner.v1",
                &ramflux_protocol::canonical_json_bytes(&("wire", "manifest", &message))?,
            );
            live.register_object_reference(
                ObjectReferenceAdmission::FreshMessage,
                &ObjectReferenceOwner {
                    reference_hash: &hash,
                    wire_id: "wire",
                    manifest_hash: "manifest",
                    selector: "wire",
                    message_id: &message,
                    reference: &json!({}),
                    metadata: &json!({}),
                },
            )?;
        }
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
INSERT INTO group_message_tombstone_projection SELECT 'other','unrelated-'||i,'delete','device','all',1,'',1 FROM budget_numbers;
DROP TABLE budget_numbers; COMMIT;")?;
        let source_before = std::fs::read(&path)?;
        target.db.execute(
            &format!("ATTACH DATABASE ?1 AS incoming KEY \"x'{}'\"", snapshot.key.sqlcipher_hex()),
            [path.to_str().unwrap()],
        )?;
        target.db.execute_batch("BEGIN IMMEDIATE;")?;
        prepare(&target.db)?;
        for table in TABLES {
            assert!(!target.db.query_row(
                "SELECT EXISTS(SELECT 1 FROM temp.sqlite_master WHERE name=?1)",
                [table],
                |r| r.get::<_, bool>(0)
            )?);
        }
        // Known scan on the exact worker connection proves the grouped meter is live.
        let (calibration, calibration_steps) = target.measure_restore_vm_steps(|| {
            target.db.query_row(
                "SELECT sum(length(copy_id)) FROM main.message_copy_binding",
                [],
                |r| r.get::<_, i64>(0),
            )
        });
        assert!(calibration? > 0 && calibration_steps > 0);
        let (error, _) = target.measure_restore_vm_steps(|| {
            target.db.execute_batch("SELECT * FROM missing_meter_table")
        });
        assert!(error.is_err());
        // A removed progress handler cannot touch this independent counter.
        // Positive, repeatable calibration after an error exercises handler reset.
        let (_, repeated) = target.measure_restore_vm_steps(|| {
            target.db.query_row(
                "SELECT sum(length(copy_id)) FROM main.message_copy_binding",
                [],
                |r| r.get::<_, i64>(0),
            )
        });
        assert_eq!(repeated, calibration_steps);
        eprintln!("calibration N={n} M={m}: {calibration_steps}");

        let mut statements = vec![(graph::CONFLICT.to_owned(), false)];
        statements.extend(
            graph::FENCES
                .split(';')
                .filter(|s| !s.trim().is_empty())
                .map(|s| (s.to_owned(), false)),
        );
        statements.extend(restrictions::queries("main", BINDINGS).map(|s| (s, true)));
        let decision_start = statements.len();
        statements.extend(
            graph::DECISIONS
                .split(';')
                .filter(|s| !s.trim().is_empty())
                .map(|s| (s.to_owned(), false)),
        );
        // Seed the standalone decision statements with actual production admissions.
        target.db.execute_batch("SAVEPOINT seed_admissions;")?;
        graph::classify(&target.db)?;
        target.db.execute_batch("DELETE FROM backup_selector_admission;")?;
        for (index, (sql, parameter)) in statements.into_iter().enumerate() {
            target.db.execute_batch("SAVEPOINT standalone_budget;")?;
            // Conflict/fence/deletion reads are independent of the seeded rows;
            // decision writes use populated admissions and an empty selector result set.
            let steps = standalone(&target.db, &sql, parameter.then_some("message"))?;
            if index >= decision_start {
                assert!(steps > 0);
            }

            target.db.execute_batch("ROLLBACK TO standalone_budget; RELEASE standalone_budget;")?;
            assert!(steps > 0, "unobserved standalone statement: {sql}");
            measured.push(steps);
        }
        target.db.execute_batch("ROLLBACK TO seed_admissions; RELEASE seed_admissions;")?;
        let (result, grouped) = target.measure_restore_vm_steps(|| graph::classify(&target.db));
        result?;
        assert!(grouped > 0);
        measured.push(grouped);
        // Decisions are independent of unrelated state, including on the U26 broken index path.
        let rows =
            target.db.query_row("SELECT count(*) FROM backup_reference_admission", [], |r| {
                r.get::<_, usize>(0)
            })?;
        assert_eq!(rows, m + 1);
        assert_eq!(
            target.db.query_row(
                "SELECT count(*) FROM backup_selector_admission WHERE decision='keep'",
                [],
                |r| r.get::<_, usize>(0)
            )?,
            2
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
