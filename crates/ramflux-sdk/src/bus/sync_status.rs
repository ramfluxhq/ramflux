// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Persisted status reductions keep poll timestamps out of the durable change stream.
use crate::prelude::*;
use serde_json::{Value, json};

pub(super) fn record(account: &LocalBusAccountState, state: &str, at: i64) -> Result<(), SdkError> {
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
                json!({"state":state,"unrouted":db.unrouted_count()?,"last_run":at}),
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
