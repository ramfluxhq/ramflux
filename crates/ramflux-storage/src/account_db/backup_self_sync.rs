// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Restore revision/erase floors before own replicated values; never restore send queues.
use super::backup_database::BackupDatabase;
use crate::StorageError;
use ramflux_protocol::message as g;
use rusqlite::{OptionalExtension, params};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

const STATE: &str = "self-sync/state/";
const FLOOR: &str = "self-sync/revision/";
const ERASE: &str = "self-sync/erase/";
type Order = g::identity::EventOrder;
type Pair = (u64, [u8; 32]);

fn invalid() -> StorageError {
    StorageError::AuthorizationRejected
}
fn revision(value: &Value) -> Result<u64, StorageError> {
    let revision = value
        .as_u64()
        .or_else(|| value.as_str().and_then(|text| text.parse().ok()))
        .ok_or_else(invalid)?;
    if revision == 0 || revision == u64::MAX {
        return Err(invalid());
    }
    Ok(revision)
}
fn conversation(value: &Value) -> Result<&str, StorageError> {
    value["conversation_id"].as_str().filter(|text| !text.is_empty()).ok_or_else(invalid)
}
fn rows(
    db: &rusqlite::Connection,
    database: &str,
    prefix: &str,
) -> Result<Vec<(String, Value)>, StorageError> {
    let admission = if database == "incoming" {
        " AND NOT EXISTS(SELECT 1 FROM backup_erased_copy e WHERE e.database_name='incoming' AND e.table_name='runtime_actor_state' AND e.row_id=r.rowid)"
    } else {
        ""
    };
    let mut statement = db.prepare(&format!("SELECT state_kind,state_json FROM {database}.runtime_actor_state r WHERE substr(state_kind,1,length(?1))=?1{admission} ORDER BY state_kind"))?;
    let rows = statement
        .query_map([prefix], |row| Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?)))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    rows.into_iter().map(|(key, bytes)| Ok((key, serde_json::from_slice(&bytes)?))).collect()
}
fn load(db: &rusqlite::Connection, key: &str) -> Result<Option<Value>, StorageError> {
    let bytes = db
        .query_row("SELECT state_json FROM runtime_actor_state WHERE state_kind=?1", [key], |row| {
            row.get::<_, Vec<u8>>(0)
        })
        .optional()?;
    bytes.map(|bytes| serde_json::from_slice(&bytes).map_err(StorageError::from)).transpose()
}
fn put(db: &rusqlite::Connection, key: &str, value: &Value) -> Result<(), StorageError> {
    let bytes = serde_json::to_vec(value)?;
    let updated = db.execute(
        "UPDATE runtime_actor_state SET state_json=?2 WHERE state_kind=?1",
        params![key, bytes],
    )?;
    if updated == 0 {
        db.execute(
            "INSERT INTO runtime_actor_state(state_kind,state_json) VALUES(?1,?2)",
            params![key, bytes],
        )?;
    }
    Ok(())
}
fn erase_set(db: &rusqlite::Connection) -> Result<BTreeSet<String>, StorageError> {
    rows(db, "main", ERASE)?
        .into_iter()
        .filter_map(|(_, value)| {
            value["erased"]
                .as_bool()
                .unwrap_or(false)
                .then(|| conversation(&value).map(str::to_owned))
        })
        .collect()
}

impl BackupDatabase {
    pub(super) fn merge_self_sync_floors(&self) -> Result<BTreeMap<String, u64>, StorageError> {
        let local = rows(&self.db, "main", FLOOR)?
            .into_iter()
            .map(|(key, value)| Ok((key, revision(&value["revision"])?)))
            .collect::<Result<BTreeMap<_, _>, StorageError>>()?;
        let source_scopes = rows(&self.db, "incoming", STATE)?
            .into_iter()
            .map(|(key, value)| Ok((key, state_pair(&value)?.0)))
            .collect::<Result<BTreeMap<_, _>, StorageError>>()?;
        for (key, mut value) in rows(&self.db, "incoming", FLOOR)? {
            conversation(&value)?;
            let incoming = revision(&value["revision"])?;
            if source_scopes
                .get(&key.replacen(FLOOR, STATE, 1))
                .is_none_or(|revision| *revision < incoming)
            {
                value["erased"] = json!(true);
            }
            let same_erased =
                local.get(&key) == Some(&incoming) && value["erased"].as_bool() == Some(true);
            if same_erased || local.get(&key).is_none_or(|floor| incoming > *floor) {
                value["revision"] = json!(format!("{incoming:020}"));
                put(&self.db, &key, &value)?;
            }
        }
        for (key, value) in rows(&self.db, "incoming", ERASE)? {
            conversation(&value)?;
            let erased = value["erased"].as_bool().ok_or_else(invalid)?;
            let current = load(&self.db, &key)?;
            if erased || current.is_none() {
                put(&self.db, &key, &value)?;
            }
        }
        self.erase_self_sync_restored_values()?;
        Ok(local)
    }

    pub(super) fn merge_self_sync_values(
        &self,
        local_floors: &BTreeMap<String, u64>,
    ) -> Result<(), StorageError> {
        let erased = erase_set(&self.db)?;
        for (key, incoming) in rows(&self.db, "incoming", STATE)? {
            let scoped = conversation(&incoming)?;
            if erased.contains(scoped) {
                continue;
            }
            let incoming_pair = state_pair(&incoming)?;
            let current = load(&self.db, &key)?;
            let floor_key = key.replacen(STATE, FLOOR, 1);
            if current.is_none()
                && local_floors.get(&floor_key).is_some_and(|floor| incoming_pair.0 <= *floor)
            {
                continue;
            }
            if let Some(floor) = load(&self.db, &floor_key)? {
                let stored_floor = revision(&floor["revision"])?;
                if (current.is_none() && incoming_pair.0 < stored_floor)
                    || (incoming_pair.0 <= stored_floor && floor["erased"].as_bool() == Some(true))
                {
                    continue;
                }
            }
            let mut winner = match current.as_ref() {
                Some(current) if state_pair(current)? >= incoming_pair => current.clone(),
                _ => incoming.clone(),
            };
            merge_read_registers(&self.db, scoped, &mut winner, current.as_ref(), &incoming)?;
            put(&self.db, &key, &winner)?;
            let floor = load(&self.db, &floor_key)?
                .map(|value| revision(&value["revision"]))
                .transpose()?
                .unwrap_or(0);
            let accepted = state_pair(&winner)?.0.max(floor);
            put(
                &self.db,
                &floor_key,
                &json!({"conversation_id":scoped,"revision":format!("{accepted:020}")}),
            )?;
        }
        self.erase_self_sync_restored_values()
    }

    fn erase_self_sync_restored_values(&self) -> Result<(), StorageError> {
        let erased = erase_set(&self.db)?;
        for prefix in [STATE, "self-sync/pending/", "self-sync/repair/"] {
            for (key, value) in rows(&self.db, "main", prefix)? {
                let mut forbidden = erased.contains(conversation(&value)?);
                if prefix == STATE
                    && let Some(floor) = load(&self.db, &key.replacen(STATE, FLOOR, 1))?
                {
                    forbidden |= floor["erased"].as_bool() == Some(true)
                        && state_pair(&value)?.0 <= revision(&floor["revision"])?;
                }
                if forbidden {
                    self.db
                        .execute("DELETE FROM runtime_actor_state WHERE state_kind=?1", [key])?;
                }
            }
        }
        self.db.execute(
            "DELETE FROM backup_archived_actor_state WHERE state_kind LIKE 'self-sync/%'",
            [],
        )?;
        Ok(())
    }
}

fn state_pair(value: &Value) -> Result<Pair, StorageError> {
    let exact: Vec<u8> = serde_json::from_value(value["exact_body"].clone())?;
    let decoded = g::self_sync::decode_stored_body(&exact).map_err(|_| invalid())?;
    let cached: g::SelfSync = serde_json::from_value(value["value"].clone())?;
    if decoded != cached {
        return Err(invalid());
    }
    let tie: [u8; 32] = serde_json::from_value(value["tie_break"].clone())?;
    if tie != g::self_sync::body_hash(&exact).map_err(|_| invalid())? {
        return Err(invalid());
    }
    Ok((decoded.revision, tie))
}

fn message_order(
    db: &rusqlite::Connection,
    reference: &g::MessageRef,
) -> Result<Option<Order>, StorageError> {
    let key =
        format!("routed/generated-identity/{}", ramflux_protocol::encode_base64url(&reference.id));
    let Some(value) = load(db, &key)? else {
        return Ok(None);
    };
    let identity: g::EventIdentity = serde_json::from_value(value)?;
    g::identity::verify(&identity).map_err(|_| invalid())?;
    if identity.id != reference.id
        || identity.conversation_id != reference.conversation_id
        || identity
            .author
            .as_ref()
            .is_none_or(|author| author.account_anchor != reference.author_anchor)
    {
        return Err(invalid());
    }
    Ok(Some(g::identity::order_key(&identity).map_err(|_| invalid())?))
}

fn merge_read_registers(
    db: &rusqlite::Connection,
    scope: &str,
    winner: &mut Value,
    current: Option<&Value>,
    incoming: &Value,
) -> Result<(), StorageError> {
    let mut marker: Option<(Order, g::MessageRef, Value)> = None;
    let mut pending: Option<(Pair, Value)> = None;
    for state in current.into_iter().chain(std::iter::once(incoming)) {
        if !state["read_marker"].is_null() {
            let reference: g::MessageRef = serde_json::from_value(state["read_marker"].clone())?;
            if reference.conversation_id != scope {
                return Err(invalid());
            }
            if let Some(order) = message_order(db, &reference)? {
                if marker.as_ref().is_none_or(|old| order > old.0) {
                    marker = Some((order, reference, state["read_marker_body"].clone()));
                }
            } else if !state["read_marker_body"].is_null() {
                let body = &state["read_marker_body"];
                let pair = (
                    revision(&body["revision"])?,
                    serde_json::from_value(body["tie_break"].clone())?,
                );
                let candidate = json!({"reference":reference,"revision":pair.0,"tie_break":pair.1,"exact_body":body["exact_body"]});
                if pending.as_ref().is_none_or(|old| pair > old.0) {
                    pending = Some((pair, candidate));
                }
            }
        }
        if !state["pending_read"].is_null() {
            let candidate = &state["pending_read"];
            let pair = (
                revision(&candidate["revision"])?,
                serde_json::from_value(candidate["tie_break"].clone())?,
            );
            if pending.as_ref().is_none_or(|old| pair > old.0) {
                pending = Some((pair, candidate.clone()));
            }
        }
    }
    winner["read_marker"] =
        marker.as_ref().map_or(Value::Null, |(_, reference, _)| json!(reference));
    winner["read_marker_body"] = marker.map_or(Value::Null, |(_, _, body)| body);
    winner["pending_read"] = pending.map_or(Value::Null, |(_, pending)| pending);
    refresh_references(scope, winner)
}

fn refresh_references(scope: &str, state: &mut Value) -> Result<(), StorageError> {
    let value: g::SelfSync = serde_json::from_value(state["value"].clone())?;
    let mut references = Vec::new();
    references.extend(value.read_through);
    references.extend(value.pin);
    if let Some(draft) = value.draft {
        references.extend(draft.reply_to);
    }
    for key in ["read_marker", "pending_read"] {
        let reference = if key == "pending_read" { &state[key]["reference"] } else { &state[key] };
        if !reference.is_null() {
            references.push(serde_json::from_value(reference.clone())?);
        }
    }
    let mut ids = BTreeSet::new();
    for reference in references {
        if reference.conversation_id != scope {
            return Err(invalid());
        }
        ids.insert(ramflux_protocol::encode_base64url(reference.id));
    }
    state["references"] =
        json!(ids.into_iter().map(|id| json!({"message_id":id})).collect::<Vec<_>>());
    Ok(())
}

pub(super) fn install(db: &rusqlite::Connection) -> rusqlite::Result<()> {
    // Avoid UPSERT here: SQLite propagates its conflict policy into nested capture triggers.
    db.execute_batch("DROP TRIGGER IF EXISTS self_sync_erasure_floor; CREATE TRIGGER self_sync_erasure_floor BEFORE DELETE ON runtime_actor_state WHEN OLD.state_kind LIKE 'self-sync/state/%' BEGIN
        UPDATE runtime_actor_state SET state_json=CAST(json_object('conversation_id',json_extract(CAST(OLD.state_json AS TEXT),'$.conversation_id'),'revision',max(json_extract(CAST(state_json AS TEXT),'$.revision'),substr('00000000000000000000'||json_extract(CAST(OLD.state_json AS TEXT),'$.value.revision'),-20)),'erased',json('true')) AS BLOB)
        WHERE state_kind='self-sync/revision/'||substr(OLD.state_kind,length('self-sync/state/')+1);
        INSERT INTO runtime_actor_state(state_kind,state_json)
        SELECT 'self-sync/revision/'||substr(OLD.state_kind,length('self-sync/state/')+1),CAST(json_object('conversation_id',json_extract(CAST(OLD.state_json AS TEXT),'$.conversation_id'),'revision',substr('00000000000000000000'||json_extract(CAST(OLD.state_json AS TEXT),'$.value.revision'),-20),'erased',json('true')) AS BLOB)
        WHERE NOT EXISTS(SELECT 1 FROM runtime_actor_state WHERE state_kind='self-sync/revision/'||substr(OLD.state_kind,length('self-sync/state/')+1));
        END;")
}
