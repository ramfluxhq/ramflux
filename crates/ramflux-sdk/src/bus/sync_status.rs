// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Persisted status reductions keep poll timestamps out of the durable change stream.
use crate::prelude::*;
use serde_json::{Value, json};

/// Resolve upgrade coordinates once on the account writer, including a durable cache miss.
pub(super) fn initialize_coordinates(db: &AccountDb) -> Result<(), SdkError> {
    db.write_transaction(|| {
        for (storage, topic) in [("sync/status", "sync.status"), ("sync/health", "node.health")] {
            let key = format!("{storage}/event");
            if db.actor_state_exists(storage)? && !db.actor_state_exists(&key)? {
                let coordinates = db
                    .latest_journal_event(topic)?
                    .map_or(Value::Null, |event| json!({"seq":event.seq,"at":event.at}));
                db.persist_actor_state(&key, &coordinates)?;
            }
        }
        Ok(())
    })
}

#[cfg(test)]
pub(super) fn record(account: &LocalBusAccountState, state: &str, at: i64) -> Result<(), SdkError> {
    record_with_reason(account, state, at, None)
}

pub(super) fn record_with_reason(
    account: &LocalBusAccountState,
    state: &str,
    at: i64,
    reason: Option<&str>,
) -> Result<(), SdkError> {
    let db = account.client.account_db()?;
    db.write_transaction(|| {
        let tick = db
            .load_actor_state::<u64>("sync/tick")?
            .unwrap_or_default()
            .checked_add(1)
            .ok_or_else(|| SdkError::LocalBus("sync counter exhausted".into()))?;
        let node_id = db.load_actor_state::<Option<String>>("sync/node-id")?.flatten();
        let samples = [
            (
                "sync.status",
                "sync/status",
                json!({"state":state,"reason_code":reason,"unrouted":db.unrouted_count()?,"last_run":at}),
            ),
            (
                "node.health",
                "sync/health",
                json!({
                    "node_id":node_id,
                    "state":if state=="error" {"unavailable"}else{"connected"},
                    "transport":account.engine.as_ref().map(|e|e.active_transport_kind().wire_name()),
                    "last_run":at,
                }),
            ),
        ];
        for (topic, storage, body) in samples {
            let old = db.load_actor_state::<Value>(storage)?;
            if old.as_ref().is_none_or(|old| semantic(old) != semantic(&body)) {
                let event = db.append_journal(&format!("{topic}:{tick}"), topic, &body, at, None)?;
                db.persist_actor_state(&format!("{storage}/event"), &json!({"seq":event.seq,"at":event.at}))?;
            }
            // Latest samples remain durable/readable independently of journal transitions.
            db.persist_actor_state(storage, &body)?;
        }
        db.persist_actor_state("sync/tick", &tick)?;
        Ok(())
    })
}
fn semantic(body: &Value) -> Value {
    let mut stable = body.clone();
    if let Some(fields) = stable.as_object_mut() {
        fields.remove("last_run");
    }
    stable
}

/// Latest poll samples plus the durable coordinates of their last semantic transition.
pub(super) fn read(db: &AccountDb) -> Result<Value, SdkError> {
    let mut result = json!({"sync_status":null,"node_health":null,"last_run":null});
    for (field, storage, topic) in [
        ("sync_status", "sync/status", "sync.status"),
        ("node_health", "sync/health", "node.health"),
    ] {
        if let Some(body) = db.load_actor_state::<Value>(storage)? {
            let coordinates =
                if let Some(saved) = db.load_actor_state::<Value>(&format!("{storage}/event"))? {
                    saved
                } else {
                    // Upgrade existing samples without inventing a sequence or a new transition.
                    db.latest_journal_event(topic)?
                        .map_or(Value::Null, |event| json!({"seq":event.seq,"at":event.at}))
                };
            if field == "sync_status" {
                result["last_run"] = body["last_run"].clone();
            }
            result[field] = json!({"seq":coordinates["seq"],"at":coordinates["at"],"body":body});
        }
    }
    Ok(result)
}

pub(super) fn optional_manifest(path: &Path) -> Option<LocalBusPersistedAccount> {
    if !path.exists() {
        return None;
    }
    match read_local_bus_account_manifest(path) {
        Ok(manifest) => Some(manifest),
        Err(error) => {
            tracing::warn!(%error,"account manifest unavailable; optional node and display metadata omitted");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn pruned_upgrade_coordinates_are_cached_as_null_and_live_pages_skip_status()
    -> Result<(), SdkError> {
        let root = std::env::temp_dir().join(format!(
            "rf-status-miss-{}-{}",
            std::process::id(),
            now_unix_timestamp()
        ));
        let mut client = RamfluxClient::new();
        client.open_account_index(&root)?;
        client.create_account("status-account", "Status")?;
        client.unlock_account("status-account", b"secret")?;
        let db = client.account_db()?;
        for key in ["sync/status", "sync/health"] {
            db.persist_actor_state(key, &json!({"state":"idle","last_run":7}))?;
        }
        db.append_journal("unrelated", "message.received", &json!({}), 1, None)?;
        let readers = crate::bus::readers::AccountReaders::start(db)?;
        for key in ["sync/status/event", "sync/health/event"] {
            assert_eq!(db.load_actor_state::<Value>(key)?, Some(Value::Null));
        }
        // If a reader rescans instead of honoring the saved miss it would invent coordinates.
        db.append_journal("late-status", "sync.status", &json!({"state":"connected"}), 8, None)?;
        let head = db.journal_bounds()?.head_seq;
        for _ in 0..2 {
            let request = LocalBusFrame::request(
                "snapshot",
                Some("status-account".into()),
                "stream",
                "bus.subscribe",
                json!({"since_seq":0}),
            );
            let snapshot = readers.request(request).await?;
            assert!(snapshot["status"]["sync_status"]["seq"].is_null());
            assert!(snapshot["status"]["sync_status"]["at"].is_null());
            assert_eq!(snapshot["status"]["sync_status"]["body"]["last_run"], 7);
            let request = LocalBusFrame::request(
                "page",
                Some("status-account".into()),
                "stream",
                "stream.read",
                json!({"since_seq":0}),
            );
            let page = readers.request(request).await?;
            assert!(page.get("status").is_none());
            assert_eq!(page["events"].as_array().map(Vec::len), Some(2));
        }
        assert_eq!(db.journal_bounds()?.head_seq, head);
        readers.stop().await;
        let reopened = db.open_reader()?;
        assert_eq!(reopened.load_actor_state::<Value>("sync/status/event")?, Some(Value::Null));
        // Live pages do not attach samples when their saved coordinates change.
        db.persist_actor_state("sync/status/event", &json!({"seq":9,"at":8}))?;
        let page = crate::bus::subscription::read(
            &reopened,
            &LocalBusFrame::request("page", None, "stream", "stream.read", json!({"since_seq":0})),
        )?;
        assert!(page.get("status").is_none());
        drop(reopened);
        drop(client);
        std::fs::remove_dir_all(root)?;
        Ok(())
    }
}
