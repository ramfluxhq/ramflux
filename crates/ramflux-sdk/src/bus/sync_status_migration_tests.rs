// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Count actual legacy lookups and durable misses across writer and reader restarts.
use super::*;

fn legacy_samples() -> Result<(ramflux_test_support::TestPath, RamfluxClient), SdkError> {
    let root = ramflux_test_support::TestPath::new()
        .expect("test: allocate fixture directory")
        .child(format!(
            "rf-status-count-{}-{}",
            std::process::id(),
            SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |t| t.as_nanos())
        ));
    let mut client = RamfluxClient::new();
    client.open_account_index(&root)?;
    client.create_account("status-account", "Status")?;
    client.unlock_account("status-account", b"secret")?;
    let db = client.account_db()?;
    for key in ["sync/status", "sync/health"] {
        db.persist_actor_state(key, &json!({"state":"idle","last_run":7}))?;
    }
    db.write_transaction(|| {
        for n in 0..10000 {
            db.append_journal(&format!("other:{n}"), "conversation.changed", &json!({}), 1, None)?;
        }
        Ok::<_, SdkError>(())
    })?;
    Ok((root, client))
}

fn event_writes(db: &AccountDb) -> Result<usize, SdkError> {
    Ok(db
        .pending_outbox(256)?
        .iter()
        .filter(|row| {
            row.keys["state_kind"]
                .as_str()
                .is_some_and(|key| matches!(key, "sync/status/event" | "sync/health/event"))
        })
        .count())
}

#[tokio::test]
async fn coordinate_lookup_miss_is_persisted_once_across_reader_restarts() -> Result<(), SdkError> {
    let (root, mut client) = legacy_samples()?;
    let mut calls = BTreeMap::<String, usize>::new();
    {
        let db = client.account_db()?;
        assert_eq!(event_writes(db)?, 0);
        for _ in 0..32 {
            // Decorate real SQLite lookups, rather than substituting an empty result.
            initialize_coordinates_with(db, |topic| {
                *calls.entry(topic.into()).or_default() += 1;
                Ok(db.latest_journal_event(topic)?)
            })?;
        }
        assert_eq!(calls.get("sync.status"), Some(&1));
        assert_eq!(calls.get("node.health"), Some(&1));
        assert_eq!(event_writes(db)?, 2);
        assert_eq!(db.journal_bounds()?.head_seq, 10000);
        for key in ["sync/status/event", "sync/health/event"] {
            assert_eq!(db.load_actor_state::<Value>(key)?, Some(Value::Null));
        }
    }
    client = RamfluxClient::new();
    client.open_account_index(&root)?;
    client.unlock_account("status-account", b"secret")?;
    let db = client.account_db()?;
    initialize_coordinates_with(db, |topic| {
        *calls.entry(topic.into()).or_default() += 1;
        Ok(db.latest_journal_event(topic)?)
    })?;
    assert_eq!(calls.values().sum::<usize>(), 2);
    assert_eq!(event_writes(db)?, 2);
    // A later row exposes any reader that ignores the saved negative result.
    db.append_journal("late-status", "sync.status", &json!({"state":"connected"}), 8, None)?;
    for _ in 0..2 {
        let readers = crate::bus::readers::AccountReaders::start(db, None)?;
        for _ in 0..16 {
            let status = readers
                .request(LocalBusFrame::request(
                    "status",
                    Some("status-account".into()),
                    "sync",
                    "sync.status.get",
                    json!({}),
                ))
                .await?;
            assert!(status["sync_status"]["seq"].is_null());
            assert!(status["node_health"]["at"].is_null());
            assert_eq!(status["last_run"], 7);
            let page = readers
                .request(LocalBusFrame::request(
                    "page",
                    Some("status-account".into()),
                    "stream",
                    "stream.read",
                    json!({"since_seq":10000}),
                ))
                .await?;
            assert!(page.get("status").is_none());
        }
        readers.stop().await;
    }
    assert_eq!(event_writes(db)?, 2);
    assert_eq!(db.journal_bounds()?.head_seq, 10001);
    drop(client);
    Ok(())
}
