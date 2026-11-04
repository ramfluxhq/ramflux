// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Worker bounds and failure isolation against real durable obligations.
use super::*;
use ramflux_node_core::{
    MigrationDrainEntry, MigrationDrainOutcome, MigrationDrainState, RouterRedbStore,
};
use ramflux_protocol::home_migration::{BacklogProgress, HomeRecord};
use std::sync::Arc;
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

pub(super) fn seed(path: &std::path::Path, count: u64) -> Result<u64> {
    let head = window_tests::fixture(path)?;
    let HomeRecord::Committed { authorization, commit_proof, .. } = head.record else {
        return Err("commit".into());
    };
    let now = commit_proof.body.forward_until - 100;
    let db = redb::Database::create(path)?;
    let tx = db.begin_write()?;
    for i in 1..=count {
        let row = MigrationDrainEntry {
            account_anchor: authorization.body.account_anchor.clone(),
            migration_id: authorization.body.migration_id.clone(),
            entry: ramflux_node_core::InboxEntry {
                inbox_seq: i,
                target_delivery_id: "moving".into(),
                envelope: migration_tests::envelope("moving", &format!("drain-{i}"))?,
            },
            retain_until: i64::try_from(now + 500)?,
            state: MigrationDrainState::Pending,
            attempts: 0,
            next_attempt: now,
        };
        let key = format!("delivery/v1/{}/{i:020}", ramflux_protocol::encode_base64url("moving"));
        tx.open_table(redb::TableDefinition::<&str, &[u8]>::new("migration_drain_entries_v1"))?
            .insert(key.as_str(), serde_json::to_vec(&row)?.as_slice())?;
    }
    let cursor = ramflux_node_core::MigrationBacklogCursor {
        account_anchor: authorization.body.account_anchor.clone(),
        migration_id: authorization.body.migration_id.clone(),
        target_delivery_id: "moving".into(),
        high_water: count,
        next_seq: 1,
        progress: BacklogProgress { scheduled: count, remaining: count, ..Default::default() },
    };
    let key = serde_json::to_string(&(
        &authorization.body.account_anchor,
        &authorization.body.migration_id,
        "moving",
    ))?;
    tx.open_table(redb::TableDefinition::<&str, &[u8]>::new("migration_backlog_cursor_v1"))?
        .insert(key.as_str(), serde_json::to_vec(&cursor)?.as_slice())?;
    tx.commit()?;
    Ok(now)
}

#[test]
fn drain_pages_at_most_64_entries_and_128_transitions_per_tick() -> Result {
    let dir = migration_tests::directory()?;
    let path = dir.0.join("bounded.redb");
    let now = seed(&path, 140)?;
    let store = RouterRedbStore::open(path)?;
    assert_eq!(store.migration_drain_work_page("")?.len(), 64);
    let mut position = String::new();
    let count = crate::migration_drain::tick(&store, &mut position, now, |_, _| {
        Ok(MigrationDrainOutcome::Held)
    })?;
    assert_eq!(count, 128);
    let count = crate::migration_drain::tick(&store, &mut position, now, |_, _| {
        Ok(MigrationDrainOutcome::Held)
    })?;
    assert_eq!(count, 12);
    assert_eq!(position, "");
    let page = store.migration_drain_page("moving", 0)?;
    assert!(page.iter().all(|r| r.attempts == 1));
    Ok(())
}

#[test]
fn drain_store_error_stops_tick_without_advancing_or_releasing() -> Result {
    let dir = migration_tests::directory()?;
    let path = dir.0.join("failure.redb");
    let now = seed(&path, 1)?;
    // A schema error at the mandatory window transaction occurs before transport or settlement.
    let db = redb::Database::create(&path)?;
    let tx = db.begin_write()?;
    tx.open_table(redb::TableDefinition::<&str, &str>::new("migration_window_closed_v1"))?
        .insert("wrong", "schema")?;
    tx.commit()?;
    drop(db);
    let store = RouterRedbStore::open(&path)?;
    let before = store.migration_drain_page("moving", 0)?;
    let mut position = String::new();
    let mut forwarded = false;
    assert!(
        crate::migration_drain::tick(&store, &mut position, now, |_, _| {
            forwarded = true;
            Ok(MigrationDrainOutcome::Held)
        })
        .is_err()
    );
    assert!(!forwarded);
    assert_eq!(position, "");
    assert_eq!(before, store.migration_drain_page("moving", 0)?);
    drop(store);
    let db = redb::Database::create(&path)?;
    let tx = db.begin_write()?;
    tx.delete_table(redb::TableDefinition::<&str, &str>::new("migration_window_closed_v1"))?;
    tx.commit()?;
    drop(db);
    let store = RouterRedbStore::open(path)?;
    assert_eq!(
        crate::migration_drain::tick(&store, &mut position, now, |_, _| Ok(
            MigrationDrainOutcome::Held
        ))?,
        1
    );
    Ok(())
}

#[test]
fn poison_entry_does_not_stop_later_entries_drain() -> Result {
    let _guard = window_tests::FORWARD_IO.lock().map_err(|_| "forward IO fixture lock")?;
    let dir = migration_tests::directory()?;
    let path = dir.0.join("poison.redb");
    let now = seed(&path, 2)?;
    let store = RouterRedbStore::open(path)?;
    let state = ramflux_node_core::RouterCore::new();
    let semaphore = Arc::new(tokio::sync::Semaphore::new(4));
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    let client = crate::router_runtime::LocalFederationForwardClient {
        url: format!("http://{}/forward", listener.local_addr()?),
        admin_token: None,
        source_node_id: "A".into(),
    };
    let server = std::thread::spawn(move || listener.accept());
    let mut attempted = 0;
    crate::migration_drain::tick(&store, &mut String::new(), now, |row, now| {
        let mut row = row.clone();
        if row.entry.inbox_seq == 1 {
            row.entry.envelope.signed.signature = "poison".into();
        }
        attempted += 1;
        crate::migration_drain::forward(
            &state,
            &store,
            AsyncForwardContext {
                client: Some(&client),
                semaphore: &semaphore,
                timeout: std::time::Duration::from_millis(100),
            },
            &row,
            now,
        )
    })?;
    assert_eq!(attempted, 2);
    drop(server.join().map_err(|_| "server panic")??);
    assert_eq!(store.migration_drain_page("moving", 0)?.len(), 2);
    Ok(())
}
