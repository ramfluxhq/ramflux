// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Query plans and work counts, including the full 18,000-row window and deletion bindings.
use super::*;
use std::cell::Cell;
thread_local! { static CLEANUPS: Cell<usize> = const { Cell::new(0) }; }
fn trace(event: &rusqlite::trace::TraceEvent<'_>) {
    if let rusqlite::trace::TraceEvent::Stmt(_, sql) = event
        && sql.starts_with("DELETE FROM runtime_actor_state")
    {
        CLEANUPS.with(|count| count.set(count.get() + 1));
    }
}
#[test]
fn delivery_plans_search_indexes_and_one_copy_has_one_cleanup_step()
-> Result<(), Box<dyn std::error::Error>> {
    let (root, db) = crate::tests::test_db("own-copy-plans")?;
    db.write_transaction(|| {
        for prefix in &PREFIXES[..3] {
            for i in 0..18_000 {
                db.persist_message_actor_state(
                    "indexed-owner",
                    &format!("{prefix}{i:05}"),
                    &serde_json::json!({"expires_at":100+i,"acknowledged":true}),
                )?;
            }
        }
        Ok::<_, StorageError>(())
    })?;
    let cases: [(&str, Vec<rusqlite::types::Value>); 5] = [
        (EXPIRED, vec!["own-device/message-receipt/".to_owned().into(), 0.into(), 16.into()]),
        (VICTIMS, vec!["own-device/status/".to_owned().into(), 1.into()]),
        (DUE, vec![0.into(), 256.into()]),
        (USAGE, vec!["own-device/committed-packet/".to_owned().into()]),
        (
            "SELECT state_json FROM runtime_actor_state WHERE state_kind=?1",
            vec!["own-device/message-receipt/00001".to_owned().into()],
        ),
    ];
    for (sql, args) in cases {
        let mut query = db.connection.prepare(&format!("EXPLAIN QUERY PLAN {sql}"))?;
        let plan = query
            .query_map(
                args.iter()
                    .map(|value| value as &dyn rusqlite::ToSql)
                    .collect::<Vec<_>>()
                    .as_slice(),
                |row| row.get::<_, String>(3),
            )?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        println!("{sql}: {plan:?}");
        assert!(plan.iter().any(|line| line.contains("SEARCH")));
        assert!(
            !plan.iter().any(|line| line.contains("SCAN") || line.contains("TEMP B-TREE")),
            "unbounded plan: {plan:?}"
        );
    }
    db.connection.call(|connection| {
        connection.trace_v2(
            rusqlite::trace::TraceEventCodes::SQLITE_TRACE_STMT,
            Some(|event| trace(&event)),
        );
        CLEANUPS.with(|count| count.set(0));
        Ok(())
    })?;
    let (result, vm_steps) =
        db.measure_sqlite_vm_steps(|| db.maintain_own_copy_delivery(0, 18_000))?;
    result?;
    println!("maintenance at 18,000 rows x 3 prefixes: vm_steps={vm_steps}, budget=2000");
    assert!(vm_steps < 2000, "maintenance exceeded VM work budget: {vm_steps} >= 2000");
    db.persist_message_actor_state(
        "new-owner",
        "own-device/message-receipt/new",
        &serde_json::json!({"expires_at":99_999}),
    )?;
    let steps = db.connection.call(|connection| {
        connection.trace_v2(rusqlite::trace::TraceEventCodes::empty(), None);
        Ok(CLEANUPS.with(Cell::get))
    })?;
    println!("one copy at 18,000 rows: cleanup_steps={steps}");
    assert!(steps <= 1, "per-copy cleanup repeated {steps} times");
    assert_eq!(db.own_copy_actor_usage(PREFIXES[0])?.0, 18_000);
    assert_eq!(db.own_copy_actor_usage(PREFIXES[2])?.0, 18_000, "live proofs must survive the cap");
    assert!(
        db.actor_state_exists(&format!("{}00000", PREFIXES[1]))?,
        "status at the cap needs no reserved slot"
    );
    db.persist_message_actor_state(
        "new-owner",
        "own-device/status/new",
        &serde_json::json!({"expires_at":99_999,"completed":true}),
    )?;
    db.maintain_own_copy_delivery(0, 18_000)?;
    for key in [format!("{}00000", PREFIXES[0]), format!("{}00000", PREFIXES[1])] {
        assert!(!db.actor_state_exists(&key)?);
        let bindings: i64 = db.connection.query_row(
            "SELECT count(*) FROM message_copy_binding WHERE copy_id=?1",
            params![format!("actor:{key}")],
            |row| row.get(0),
        )?;
        let footprints: i64 = db.connection.query_row(
            "SELECT count(*) FROM message_footprint WHERE kind='actor' AND locator=?1",
            params![key],
            |row| row.get(0),
        )?;
        assert_eq!((bindings, footprints), (0, 0));
    }
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}
#[test]
fn due_queue_skips_parked_and_held_rows_and_counters_follow_rollback()
-> Result<(), Box<dyn std::error::Error>> {
    let (root, db) = crate::tests::test_db("own-copy-schedule")?;
    let row = serde_json::json!({"intent":{"created_at":100},"next_at":200,"packet":{},"targets":[{"device":"sibling","attempts":1,"next_at":200,"acknowledged":false}]});
    for i in 0..256 {
        db.persist_actor_state(&format!("own-device/send/{i:03}"), &row)?;
    }
    assert_eq!(db.due_own_copy_keys(199, 256)?, Vec::<String>::new());
    let mut held = row.clone();
    held["held"] = true.into();
    db.persist_actor_state("own-device/send/held", &held)?;
    assert_eq!(db.due_own_copy_keys(200, 256)?.len(), 256);
    let before = db.own_copy_actor_usage(PREFIXES[3])?;
    // A reopen must not backfill or double-charge an already indexed namespace.
    db.install_own_copy_schema()?;
    assert_eq!(db.own_copy_actor_usage(PREFIXES[3])?, before);
    let rolled_back: Result<(), StorageError> = db.write_transaction(|| {
        db.remove_actor_state("own-device/send/000")?;
        Err(StorageError::AuthorizationRejected)
    });
    assert!(rolled_back.is_err());
    assert_eq!(db.own_copy_actor_usage(PREFIXES[3])?, before);
    db.remove_actor_state("own-device/send/000")?;
    assert_eq!(db.own_copy_actor_usage(PREFIXES[3])?.0, before.0 - 1);
    assert_eq!(db.own_copy_actor_usage(PREFIXES[3])?, db.actor_state_usage(PREFIXES[3])?);
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn legacy_actor_rows_are_backfilled_once_and_expiry_cleanup_is_timer_gated()
-> Result<(), Box<dyn std::error::Error>> {
    let (root, db) = crate::tests::test_db("own-copy-upgrade")?;
    db.connection.call(|connection| {
        let names = connection
            .prepare(
                "SELECT name FROM sqlite_master WHERE type='trigger' AND name LIKE 'own_copy_%'",
            )?
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        for name in names {
            connection.execute_batch(&format!("DROP TRIGGER \"{name}\""))?;
        }
        connection
            .execute_batch("DROP TABLE runtime_own_copy_state; DROP TABLE runtime_own_copy_usage")
    })?;
    db.persist_actor_state(
        "own-device/send/legacy",
        &serde_json::json!({"intent":{"created_at":100},"next_at":300,"packet":null}),
    )?;
    db.persist_actor_state(
        "own-device/message-receipt/expired",
        &serde_json::json!({"expires_at":200}),
    )?;
    db.install_own_copy_schema()?;
    assert_eq!(db.due_own_copy_keys(299, 256)?, Vec::<String>::new());
    assert_eq!(db.due_own_copy_keys(300, 256)?, vec!["own-device/send/legacy"]);
    assert_eq!(db.own_copy_actor_usage(PREFIXES[0])?.0, 1);
    db.maintain_own_copy_delivery(200, 18_000)?;
    assert_eq!(db.own_copy_actor_usage(PREFIXES[0])?.0, 0);
    db.persist_actor_state(
        "own-device/message-receipt/late-expired",
        &serde_json::json!({"expires_at":200}),
    )?;
    db.maintain_own_copy_delivery(200, 18_000)?;
    assert!(
        db.actor_state_exists("own-device/message-receipt/late-expired")?,
        "cleanup repeats only after its timer or at capacity"
    );
    db.maintain_own_copy_delivery(201, 18_000)?;
    assert!(!db.actor_state_exists("own-device/message-receipt/late-expired")?);
    db.persist_actor_state(
        "own-device/status/expired",
        &serde_json::json!({"expires_at":100,"completed":false}),
    )?;
    db.persist_actor_state(
        "own-device/status/live",
        &serde_json::json!({"expires_at":2000,"completed":true}),
    )?;
    db.persist_actor_state(
        "surface/own_context_announced/legacy",
        &serde_json::json!({"expires_at":2000}),
    )?;
    db.maintain_own_copy_delivery(201, 2)?;
    assert!(!db.actor_state_exists("own-device/status/expired")?);
    assert!(!db.actor_state_exists("surface/own_context_announced/legacy")?);
    assert!(
        db.actor_state_exists("own-device/status/live")?,
        "expired rows free capacity before any live victim is chosen"
    );
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn status_write_then_cleanup_preserves_live_rows_when_one_expiry_frees_the_slot()
-> Result<(), Box<dyn std::error::Error>> {
    let (root, db) = crate::tests::test_db("own-copy-status-cap")?;
    for i in 0..4 {
        db.persist_message_actor_state(
            "live-owner",
            &format!("{}live-{i}", PREFIXES[1]),
            &serde_json::json!({"expires_at":1000+i,"completed":true}),
        )?;
    }
    db.persist_actor_state(
        &format!("{}expired", PREFIXES[1]),
        &serde_json::json!({"expires_at":0,"completed":false}),
    )?;
    assert_eq!(db.own_copy_actor_usage(PREFIXES[1])?.0, 5);
    db.maintain_own_copy_delivery(1, 4)?;
    assert_eq!(db.own_copy_actor_usage(PREFIXES[1])?.0, 4);
    for i in 0..4 {
        assert!(db.actor_state_exists(&format!("{}live-{i}", PREFIXES[1]))?);
    }
    assert!(!db.actor_state_exists(&format!("{}expired", PREFIXES[1]))?);
    // Without any expiry, a status write above the cap still needs one live eviction.
    db.persist_actor_state(
        &format!("{}new", PREFIXES[1]),
        &serde_json::json!({"expires_at":2000,"completed":true}),
    )?;
    db.maintain_own_copy_delivery(1, 4)?;
    assert_eq!(db.own_copy_actor_usage(PREFIXES[1])?.0, 4);
    assert!(!db.actor_state_exists(&format!("{}live-0", PREFIXES[1]))?);
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn full_expired_batch_defers_live_eviction_until_all_expired_rows_are_removed()
-> Result<(), Box<dyn std::error::Error>> {
    let (root, db) = crate::tests::test_db("own-copy-expired-batch")?;
    db.write_transaction(|| {
        for prefix in &PREFIXES[..2] {
            for i in 0..3 {
                db.persist_actor_state(
                    &format!("{prefix}live-{i}"),
                    &serde_json::json!({"expires_at":1000+i,"completed":true,"acknowledged":true}),
                )?;
            }
            for i in 0..20 {
                db.persist_actor_state(
                    &format!("{prefix}expired-{i:02}"),
                    &serde_json::json!({"expires_at":0,"completed":false,"acknowledged":false}),
                )?;
            }
        }
        Ok::<_, StorageError>(())
    })?;
    db.maintain_own_copy_delivery(1, 4)?;
    for prefix in &PREFIXES[..2] {
        assert_eq!(db.own_copy_actor_usage(prefix)?.0, 7);
        for i in 0..3 {
            assert!(
                db.actor_state_exists(&format!("{prefix}live-{i}"))?,
                "live victim while expired rows remain"
            );
        }
        assert!(db.actor_state_exists(&format!("{prefix}expired-19"))?);
    }
    db.maintain_own_copy_delivery(1, 4)?;
    for prefix in &PREFIXES[..2] {
        assert_eq!(db.own_copy_actor_usage(prefix)?.0, 3);
        assert!(!db.actor_state_exists(&format!("{prefix}expired-19"))?);
        for i in 0..3 {
            assert!(db.actor_state_exists(&format!("{prefix}live-{i}"))?);
        }
    }
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn configured_expiry_updates_due_index_and_rebuilds_legacy_projection_once()
-> Result<(), Box<dyn std::error::Error>> {
    let (root, db) = crate::tests::test_db("own-copy-configured-expiry")?;
    let legacy = serde_json::json!({"intent":{"created_at":100},"held":true,"next_at":9000});
    let mut configured = legacy.clone();
    configured["intent"]["expires_at"] = 7300.into();
    db.persist_actor_state("own-device/send/legacy", &legacy)?;
    db.persist_actor_state("own-device/send/configured", &configured)?;
    assert_eq!(db.due_own_copy_keys(700, 256)?, vec!["own-device/send/legacy"]);
    assert_eq!(db.due_own_copy_keys(7299, 256)?, vec!["own-device/send/legacy"]);
    assert_eq!(db.due_own_copy_keys(7300, 256)?.len(), 2);
    let usage = db.own_copy_actor_usage(PREFIXES[3])?;
    // Model an installed pre-parameter projection: old rows expired at created_at+600.
    // Keep the legacy payload literal; only the derived cache/trigger is obsolete.
    db.write_transaction(|| {
        db.connection.execute_batch("DROP TRIGGER own_copy_index_3_INSERT; DROP TRIGGER own_copy_index_3_UPDATE;
            CREATE TRIGGER own_copy_index_3_INSERT AFTER INSERT ON runtime_actor_state BEGIN SELECT 600; END;
            UPDATE runtime_own_copy_state SET expires_at=700,next_attempt_at=700 WHERE namespace='own-device/send/';")?;
        db.install_own_copy_schema()
    })?;
    assert_eq!(db.due_own_copy_keys(700, 256)?, vec!["own-device/send/legacy"]);
    assert_eq!(db.own_copy_actor_usage(PREFIXES[3])?, usage);
    db.install_own_copy_schema()?;
    assert_eq!(db.own_copy_actor_usage(PREFIXES[3])?, usage);
    assert_eq!(db.due_own_copy_keys(7300, 256)?.len(), 2);
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}
