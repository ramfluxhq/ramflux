// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Preservation regressions with public-path controls.
use super::*;
use crate::{AccountDb, AccountDbKey, AccountIndex, BackupDatabase};
use serde_json::json;
type TestResult = Result<(), Box<dyn std::error::Error>>;

fn residual(db: &Connection, canary: &str) -> rusqlite::Result<Vec<String>> {
    let tables = db
        .prepare(
            "SELECT name FROM main.sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'",
        )?
        .query_map([], |r| r.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let mut hits = Vec::new();
    for table in tables {
        let mut q =
            db.prepare(&format!("SELECT * FROM main.\"{}\"", table.replace('"', "\"\"")))?;
        let n = q.column_count();
        let mut rows = q.query([])?;
        while let Some(row) = rows.next()? {
            for c in 0..n {
                if let rusqlite::types::ValueRef::Text(b) | rusqlite::types::ValueRef::Blob(b) =
                    row.get_ref(c)?
                    && b.windows(canary.len()).any(|w| w == canary.as_bytes())
                {
                    hits.push(table.clone());
                }
            }
        }
    }
    Ok(hits)
}

fn merge(
    target: &mut BackupDatabase,
    path: &std::path::Path,
    key: &crate::AccountDbKey,
    candidate: bool,
) -> Result<(), StorageError> {
    if candidate {
        target.merge_backup_candidate(path, key, || Ok(())).map(|_| ())
    } else {
        target.merge_backup(path, key, || Ok(())).map(|_| ())
    }
}

/// Transport-bound actor of a fenced (retired) history container.
#[test]
fn review_transport_actor_of_fenced_container_not_preserved() -> TestResult {
    let mut out = Vec::new();
    for candidate in [false, true] {
        super::tests::fixture(&format!("rv7-transport-{candidate}"), |_, _, target, path, key| {
            let canary = "rv7-transport-canary";
            let source = BackupDatabase::open(path, key)?;
            let c = object_erasure_commitment("principal", "hist", "hm");
            source.db.execute(
                "INSERT INTO runtime_actor_state VALUES('own-device/sync/receipt/r1/next',?1)",
                params![serde_json::to_vec(&json!({"cursor":canary}))?],
            )?;
            source.db.execute(
                "INSERT INTO object_transport_actor VALUES(?1,'own-device/sync/receipt/r1/next')",
                params![c],
            )?;
            source.db.execute("INSERT INTO object_erasure_fence VALUES(?1)", params![c])?;
            drop(source);
            let r = merge(target, path, key, candidate);
            assert!(r.is_ok(), "restore failed: {r:?}");
            let hits = if r.is_ok() { residual(&target.db, canary)? } else { vec![] };
            assert!(hits.is_empty(), "residual in {hits:?}");
            out.push(format!("candidate={candidate} result={:?} residual={hits:?}", r.err()));
            Ok(())
        })?;
    }
    eprintln!("{out:#?}");
    assert!(!out[1].contains("backup_archived"), "{out:#?}");
    assert!(!out[1].contains("runtime_actor_state"), "{out:#?}");
    Ok(())
}

/// Actor bound to a reference whose commitment is fenced (bound && !live).
#[test]
fn review_reference_bound_actor_of_fenced_reference_not_preserved() -> TestResult {
    let mut out = Vec::new();
    for candidate in [false, true] {
        super::tests::fixture(&format!("rv7-refactor-{candidate}"), |_, _, target, path, key| {
            let canary = "rv7-refactor-canary";
            let source = BackupDatabase::open(path, key)?;
            let hash: String = source.db.query_row(
                "SELECT reference_hash FROM object_retention_reference WHERE selector='wire'",
                [],
                |r| r.get(0),
            )?;
            source.db.execute(
                "INSERT INTO runtime_actor_state VALUES('attachment/ack-progress/x',?1)",
                params![serde_json::to_vec(&json!({"progress":canary}))?],
            )?;
            source.db.execute(
                "INSERT INTO object_reference_actor VALUES(?1,'attachment/ack-progress/x')",
                params![hash],
            )?;
            drop(source);
            target.db.execute(
                "INSERT INTO object_erasure_fence VALUES(?1) ON CONFLICT DO NOTHING",
                params![object_erasure_commitment("principal", "wire", "manifest")],
            )?;
            let r = merge(target, path, key, candidate);
            assert!(r.is_ok(), "restore failed: {r:?}");
            let hits = if r.is_ok() { residual(&target.db, canary)? } else { vec![] };
            assert!(hits.is_empty(), "residual in {hits:?}");
            out.push(format!("candidate={candidate} result={:?} residual={hits:?}", r.err()));
            Ok(())
        })?;
    }
    eprintln!("{out:#?}");
    assert!(
        !out[1].contains("runtime_actor_state") && !out[1].contains("backup_archived"),
        "{out:#?}"
    );
    Ok(())
}

/// A redacted copy must keep its message footprint so a deletion still erases it.
#[test]
fn review_redacted_copy_keeps_deleted_message_footprint() -> TestResult {
    let mut out = Vec::new();
    for candidate in [false, true] {
        for source_deleted in [false, true] {
            let root =
                crate::tests::temp_root(&format!("rv7-footprint-{candidate}-{source_deleted}"));
            let source_index = AccountIndex::open(root.join("source"))?;
            let local_index = AccountIndex::open(root.join("local"))?;
            source_index.create_account("acct", "own-root")?;
            local_index.create_account("acct", "own-root")?;
            let source = AccountDb::open(&source_index, "acct", &AccountDbKey::generate()?)?;
            let local = AccountDb::open(&local_index, "acct", &AccountDbKey::generate()?)?;
            for db in [&source, &local] {
                db.send_direct_message("thread", "message", "private-peer", b"private-body")?;
                db.persist_message_actor_state(
                    "message",
                    "message/origin/opaque-origin",
                    &json!({"sender":"private-peer","items":[{"object_id":"victim","manifest_hash":"vm"}]}),
                )?;
            }
            seed_message_copies(&source)?;
            if source_deleted {
                source.delete_direct_message("thread", "message", "local", "delete")?;
            } else {
                local.delete_direct_message("thread", "message", "local", "delete")?;
            }
            let path = root.join("incoming.db");
            let incoming = source.write_backup_snapshot(&path)?;
            let target = root.join("target.db");
            let snapshot = local.write_backup_snapshot(&target)?;
            let mut merged = BackupDatabase::open(&target, &snapshot.key)?;
            merged.db.execute(
                "INSERT INTO object_erasure_lookup VALUES(?1,'c') ON CONFLICT DO NOTHING",
                params![object_erasure_lookup("own-root", "victim")],
            )?;
            let r = merge(&mut merged, &path, &incoming.key, candidate);
            assert!(r.is_ok(), "restore failed: {r:?}");
            let hits = if r.is_ok() { residual(&merged.db, "private-peer")? } else { vec![] };
            assert!(hits.is_empty(), "residual in {hits:?}");
            out.push(format!("candidate={candidate} source_deleted={source_deleted} result={:?} residual={hits:?}", r.err()));
            drop(merged);
            drop(source);
            drop(local);
            std::fs::remove_dir_all(root)?;
        }
    }
    eprintln!("{out:#?}");
    for line in &out[2..] {
        assert!(!line.contains("actor_state"), "{out:#?}");
    }
    Ok(())
}

fn seed_message_copies(source: &AccountDb) -> TestResult {
    let db = &source.connection;
    let body = serde_json::to_vec(
        &json!({"message_id":"message","sender":"private-peer","items":[{"object_id":"victim","manifest_hash":"vm"}]}),
    )?;
    db.execute("INSERT INTO local_event_log VALUES('review-mixed-event','test','peer','device',999,999,1,NULL,?1,x'1234','verified','pending')", params![body])?;
    db.execute_batch("CREATE TABLE IF NOT EXISTS backup_archived_actor_state(source TEXT NOT NULL,state_kind TEXT NOT NULL,state_json BLOB NOT NULL,PRIMARY KEY(source,state_kind)); CREATE TABLE IF NOT EXISTS backup_archived_local_event AS SELECT 'old' AS source,* FROM local_event_log WHERE 0;")?;
    db.execute(
        "INSERT INTO backup_archived_actor_state VALUES('old','message/origin/transitive',?1)",
        params![body],
    )?;
    db.execute_batch("INSERT INTO backup_archived_local_event SELECT 'old',* FROM local_event_log WHERE event_id='review-mixed-event'; INSERT OR IGNORE INTO message_footprint VALUES('message','event','review-mixed-event'); INSERT OR IGNORE INTO message_footprint SELECT 'message','archived_actor',CAST(rowid AS TEXT) FROM backup_archived_actor_state WHERE state_kind='message/origin/transitive'; INSERT OR IGNORE INTO message_footprint SELECT 'message','archived_event',CAST(rowid AS TEXT) FROM backup_archived_local_event WHERE event_id='review-mixed-event';")?;
    Ok(())
}

#[test]
fn review_r3_sibling_binding_survives_archived_copy_exclusion() -> TestResult {
    let mut out = Vec::new();
    for candidate in [false, true] {
        super::tests::fixture(&format!("rv3-sibling-{candidate}"), |_, _, target, path, key| {
            let k = "attachment/progress/k";
            target.db.execute_batch("CREATE TABLE IF NOT EXISTS backup_archived_actor_state(source TEXT NOT NULL,state_kind TEXT NOT NULL,state_json BLOB NOT NULL,PRIMARY KEY(source,state_kind));")?;
            target.db.execute(
                "INSERT INTO runtime_actor_state VALUES(?1,?2)",
                params![k, serde_json::to_vec(&json!({"note":"live"}))?],
            )?;
            target.db.execute(
                "INSERT INTO backup_archived_actor_state VALUES('old',?1,?2)",
                params![k, serde_json::to_vec(&json!({"selector":"wire"}))?],
            )?;
            target.db.execute(
                "INSERT INTO object_payload_actor VALUES('unrelated-live-commitment',?1)",
                params![k],
            )?;
            target.db.execute(
                "INSERT INTO object_erasure_fence VALUES(?1) ON CONFLICT DO NOTHING",
                params![object_erasure_commitment("principal", "wire", "manifest")],
            )?;
            let r = if candidate {
                target.merge_backup_candidate(path, key, || Ok(())).map(|_| ())
            } else {
                target.merge_backup(path, key, || Ok(())).map(|_| ())
            };
            r?;
            let live: u64 = target.db.query_row(
                "SELECT count(*) FROM runtime_actor_state WHERE state_kind=?1",
                [k],
                |r| r.get(0),
            )?;
            let archived: u64 = target.db.query_row("SELECT count(*) FROM backup_archived_actor_state WHERE state_kind=?1 AND source='old'", [k], |r| r.get(0))?;
            let bound: u64 = target.db.query_row(
                "SELECT count(*) FROM object_payload_actor WHERE state_kind=?1",
                [k],
                |r| r.get(0),
            )?;
            assert_eq!(live, 1, "current copy must survive candidate={candidate}");
            if candidate {
                assert_eq!(archived, 0, "excluded candidate archive must be removed");
            }
            assert_eq!(bound, 1, "surviving current copy needs its binding candidate={candidate}");
            let source = BackupDatabase::open(path, key)?;
            source.db.execute(
                "INSERT INTO object_erasure_fence VALUES('unrelated-live-commitment')",
                [],
            )?;
            drop(source);
            merge(target, path, key, candidate)?;
            assert_eq!(
                target.db.query_row(
                    "SELECT count(*) FROM runtime_actor_state WHERE state_kind=?1",
                    [k],
                    |r| r.get::<_, u64>(0)
                )?,
                0,
                "later erasure must reach surviving copy candidate={candidate}"
            );
            out.push(format!("candidate={candidate} live={live} binding={bound}"));
            Ok(())
        })?;
    }
    eprintln!("{out:#?}");
    assert!(out.iter().all(|o| !o.contains("live=1") || o.contains("binding=1")), "{out:#?}");
    Ok(())
}
