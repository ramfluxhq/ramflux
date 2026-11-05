// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Project private restore copies from the same per-input admission decisions.
use crate::StorageError;
use rusqlite::{Connection, params};
use serde_json::Value;
use zeroize::Zeroizing;

fn refuse() -> StorageError {
    StorageError::ObjectOwnershipUnverified { schema_version: 13 }
}

pub(in crate::account_db) fn expression(table: &str, column: &str) -> String {
    if matches!(
        (table, column),
        ("runtime_actor_state" | "backup_archived_actor_state", "state_json")
            | ("local_event_log" | "backup_archived_local_event", "event_body")
    ) {
        format!(
            "COALESCE((SELECT body FROM main.backup_preserved_copy c WHERE c.table_name='{table}' AND c.row_id=r.rowid),r.{column})"
        )
    } else if matches!(table, "local_event_log" | "backup_archived_local_event")
        && column == "signature"
    {
        format!(
            "CASE WHEN EXISTS(SELECT 1 FROM main.backup_preserved_copy c WHERE c.table_name='{table}' AND c.row_id=r.rowid) THEN x'' ELSE r.signature END"
        )
    } else if matches!(table, "local_event_log" | "backup_archived_local_event")
        && column == "signature_status"
    {
        format!(
            "CASE WHEN EXISTS(SELECT 1 FROM main.backup_preserved_copy c WHERE c.table_name='{table}' AND c.row_id=r.rowid) THEN 'retired' ELSE r.signature_status END"
        )
    } else {
        format!("r.\"{}\"", column.replace('"', "\"\""))
    }
}

fn blocked(
    db: &Connection,
    root: &str,
    schema: &str,
    selector: &str,
    manifest: Option<&str>,
) -> Result<bool, StorageError> {
    super::placeholders::erased(db, root, selector, manifest, schema)
}

// Each rejected object removes its complete subvalue, including keys and provenance.
fn redact(
    db: &Connection,
    root: &str,
    schema: &str,
    value: &mut Value,
) -> Result<bool, StorageError> {
    let inner = value.get("reference").unwrap_or(value);
    if inner.get("object_id").is_some() && inner.get("manifest_hash").is_some() {
        let hash = ramflux_crypto::blake3_256_base64url(
            "ramflux.attachment.reference.v1",
            &ramflux_protocol::canonical_json_bytes(inner)?,
        );
        let side = if schema == "main" { "target" } else { "incoming" };
        let known:bool=db.query_row(&format!("SELECT EXISTS(SELECT 1 FROM {schema}.object_retention_reference WHERE reference_hash=?1)"),[&hash],|r|r.get(0))?;
        if !known && (value.get("reference").is_some() || inner.get("key_slot").is_some()) {
            let commitment = ramflux_crypto::object_erasure_commitment(
                root,
                inner["object_id"].as_str().ok_or_else(refuse)?,
                inner["manifest_hash"].as_str().ok_or_else(refuse)?,
            );
            // Input mappings only decode identities: side-specific keep/admission
            // and the merged fence set still dominate; incoming rows cannot grant target authority.
            let legacy:bool=db.query_row(&format!("SELECT EXISTS(SELECT 1 FROM backup_selector_admission a JOIN {schema}.object_index o ON o.object_id=a.selector WHERE a.side=?1 AND a.commitment=?2 AND a.decision='keep' AND o.tombstoned=1 AND length(o.ciphertext)=0 AND NOT EXISTS(SELECT 1 FROM {schema}.object_retention_reference r WHERE r.selector=a.selector))"),params![side,commitment],|r|r.get(0))?;
            let transport:bool=db.query_row(&format!("SELECT EXISTS(SELECT 1 FROM {schema}.object_retention_reference r JOIN {schema}.object_retention_payload p USING(commitment) JOIN backup_reference_admission a ON a.reference_hash=r.reference_hash AND a.side=?1 WHERE p.commitment=?2 AND r.selector=p.wire_id AND CAST(r.reference_json AS TEXT)='{{}}' AND NOT EXISTS(SELECT 1 FROM object_erasure_fence f WHERE f.commitment=p.commitment))"),params![side,commitment],|r|r.get(0))?;
            let minimal = inner.as_object().is_some_and(|fields| fields.len() == 2)
                && value.as_object().is_some_and(|fields| fields.len() == 1);
            if !minimal || !(legacy || transport) {
                return Err(refuse());
            }
        }
        let rejected:bool=db.query_row(&format!("SELECT EXISTS(SELECT 1 FROM {schema}.object_retention_reference r WHERE r.reference_hash=?1) AND NOT EXISTS(SELECT 1 FROM backup_reference_admission a WHERE a.side=?2 AND a.reference_hash=?1 AND NOT EXISTS(SELECT 1 FROM object_erasure_fence f WHERE f.commitment=a.commitment))"),params![hash,side],|r|r.get(0))?;
        if rejected {
            *value = Value::Null;
            return Ok(true);
        }
    }
    if let Some(id) =
        value.get("selector").or_else(|| value.get("object_id")).and_then(Value::as_str)
        && blocked(db, root, schema, id, value.get("manifest_hash").and_then(Value::as_str))?
    {
        *value = Value::Null;
        return Ok(true);
    }
    let mut changed = false;
    match value {
        Value::Array(items) => {
            for item in items.iter_mut() {
                changed |= redact(db, root, schema, item)?;
            }
            if changed {
                items.retain(|v| !v.is_null());
            }
        }
        Value::Object(fields) => {
            for item in fields.values_mut() {
                changed |= redact(db, root, schema, item)?;
            }
            if changed {
                fields.retain(|_, v| !v.is_null());
            }
        }
        _ => {}
    }
    Ok(changed)
}

pub(in crate::account_db) fn prepare(
    db: &Connection,
    root: &str,
    progress: &mut impl FnMut() -> Result<(), StorageError>,
) -> Result<(), StorageError> {
    db.execute_batch("CREATE TABLE backup_preserved_copy(table_name TEXT NOT NULL,row_id INTEGER NOT NULL,body BLOB NOT NULL,PRIMARY KEY(table_name,row_id));")?;
    for schema in ["main", "incoming"] {
        for (table, key, column) in [
            ("runtime_actor_state", "state_kind", "state_json"),
            ("backup_archived_actor_state", "state_kind", "state_json"),
            ("local_event_log", "event_id", "event_body"),
            ("backup_archived_local_event", "event_id", "event_body"),
        ] {
            let exists: bool = db.query_row(
                &format!("SELECT EXISTS(SELECT 1 FROM {schema}.sqlite_master WHERE name=?1)"),
                [table],
                |r| r.get(0),
            )?;
            if !exists {
                continue;
            }
            let mut query=db.prepare(&format!("SELECT rowid,{key},CASE WHEN length({column})<=1048576 THEN {column} END FROM {schema}.{table}"))?;
            let mut rows = query.query([])?;
            while let Some(row) = rows.next()? {
                progress()?;
                let id: i64 = row.get(0)?;
                let key: String = row.get(1)?;
                let actor = table.ends_with("actor_state");
                let relevant = !actor
                    || key.starts_with("attachment/")
                    || key.starts_with("directory/object/")
                    || key.starts_with("sync/attachment/")
                    || key.starts_with("own-device/");
                let bound_drop = actor && excluded_actor_binding(db, schema, &key)?;
                if bound_drop {
                    exclude_actor(db, schema, table, id)?;
                    continue;
                }
                let bytes = match row.get::<_, Option<Vec<u8>>>(2)? {
                    Some(bytes) => Zeroizing::new(bytes),
                    None if !relevant => continue,
                    None => return Err(refuse()),
                };
                let mut value: Value = match serde_json::from_slice(&bytes) {
                    Ok(value) => value,
                    Err(_) if !relevant => continue,
                    Err(_) => return Err(refuse()),
                };
                let mut drop_copy = false;
                if actor
                    && let Some(chunk) = key.strip_prefix("attachment/chunk/")
                    && let Some((identity, _)) = chunk.rsplit_once('/')
                    && let Some((wire, manifest)) = identity.rsplit_once('/')
                {
                    drop_copy = blocked(db, root, schema, wire, Some(manifest))?;
                }
                if actor {
                    if let Some(selector) = key
                        .strip_prefix("attachment/reference/")
                        .or_else(|| key.strip_prefix("directory/object/"))
                        .or_else(|| key.strip_prefix("sync/attachment/"))
                    {
                        drop_copy |= blocked(db, root, schema, selector, None)?;
                        if key.starts_with("attachment/reference/") {
                            let owned: bool = db.query_row(&format!("SELECT EXISTS(SELECT 1 FROM {schema}.object_retention_reference r JOIN {schema}.object_message_reference m USING(reference_hash) WHERE r.selector=?1)"), [selector], |r| r.get(0))?;
                            drop_copy |= !owned;
                        }
                    }
                    if key.starts_with("attachment/reference-by-")
                        && let Some(selector) = value.as_str()
                    {
                        drop_copy |= blocked(db, root, schema, selector, None)?;
                    }
                }
                let changed = if drop_copy { false } else { redact(db, root, schema, &mut value)? };
                drop_copy |= value.is_null();
                if drop_copy {
                    exclude_actor(db, schema, table, id)?;
                } else if changed {
                    let body = Zeroizing::new(serde_json::to_vec(&value)?);
                    if schema == "incoming" {
                        db.execute(
                            "INSERT INTO backup_preserved_copy VALUES(?1,?2,?3)",
                            params![table, id, body.as_slice()],
                        )?;
                    } else {
                        let retire =
                            if actor { "" } else { ",signature=x'',signature_status='retired'" };
                        db.execute(
                            &format!("UPDATE main.{table} SET {column}=?1{retire} WHERE rowid=?2"),
                            params![body.as_slice(), id],
                        )?;
                    }
                }
            }
        }
    }
    delete_excluded_target_copies(db)
}

fn delete_excluded_target_copies(db: &Connection) -> Result<(), StorageError> {
    // Keep input bindings until every current and archived copy has been classified.
    // Removing a current actor's binding earlier would hide its archived copies.
    db.execute_batch("CREATE TABLE main.backup_excluded_actor_kind(state_kind TEXT PRIMARY KEY);")?;
    let archived_exists: bool = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM main.sqlite_master WHERE name='backup_archived_actor_state')",
        [],
        |r| r.get(0),
    )?;
    for table in [
        "runtime_actor_state",
        "backup_archived_actor_state",
        "local_event_log",
        "backup_archived_local_event",
    ] {
        if !db.query_row(
            "SELECT EXISTS(SELECT 1 FROM main.sqlite_master WHERE name=?1)",
            [table],
            |r| r.get::<_, bool>(0),
        )? {
            continue;
        }
        if table.ends_with("actor_state") {
            db.execute(&format!("INSERT OR IGNORE INTO main.backup_excluded_actor_kind SELECT state_kind FROM main.{table} WHERE rowid IN (SELECT row_id FROM backup_erased_copy WHERE database_name='main' AND table_name=?1)"), [table])?;
        }
        db.execute(&format!("DELETE FROM main.{table} WHERE rowid IN (SELECT row_id FROM backup_erased_copy WHERE database_name='main' AND table_name=?1)"),[table])?;
    }
    // Bindings belong to the state kind, so either surviving target copy retains them.
    let archived_guard = if archived_exists {
        "AND NOT EXISTS(SELECT 1 FROM main.backup_archived_actor_state s WHERE s.state_kind=b.state_kind)"
    } else {
        ""
    };
    for binding in ["object_payload_actor", "object_reference_actor", "object_transport_actor"] {
        db.execute(&format!("DELETE FROM main.{binding} AS b WHERE state_kind IN (SELECT state_kind FROM main.backup_excluded_actor_kind) AND NOT EXISTS(SELECT 1 FROM main.runtime_actor_state s WHERE s.state_kind=b.state_kind) {archived_guard}"), [])?;
    }
    db.execute_batch("DROP TABLE main.backup_excluded_actor_kind;")?;
    Ok(())
}

#[cfg(test)]
pub(in crate::account_db) fn checkpoint(db: &Connection) -> Result<(), StorageError> {
    if db.query_row(
        "SELECT EXISTS(SELECT 1 FROM temp.sqlite_master WHERE name='backup_preservation_abort')",
        [],
        |r| r.get::<_, bool>(0),
    )? {
        assert!(
            db.query_row("SELECT count(*) FROM backup_archived_local_event", [], |r| r
                .get::<_, u64>(0))?
                > 0
        );
        return Err(StorageError::AuthorizationRejected);
    }
    Ok(())
}

// Retain the public scan_copies binding exclusions before any JSON projection.
fn excluded_actor_binding(db: &Connection, schema: &str, key: &str) -> Result<bool, StorageError> {
    let side = if schema == "main" { "target" } else { "incoming" };
    Ok(db.query_row(&format!(r"SELECT
        EXISTS(SELECT 1 FROM {schema}.object_transport_actor a JOIN main.object_erasure_fence f USING(commitment) WHERE a.state_kind=?1)
        OR EXISTS(SELECT 1 FROM {schema}.object_payload_actor a JOIN main.object_erasure_fence f USING(commitment) WHERE a.state_kind=?1)
        OR (EXISTS(SELECT 1 FROM {schema}.object_reference_actor WHERE state_kind=?1)
            AND NOT EXISTS(SELECT 1 FROM {schema}.object_reference_actor a JOIN backup_reference_admission r USING(reference_hash) WHERE a.state_kind=?1 AND r.side=?2 AND NOT EXISTS(SELECT 1 FROM object_erasure_fence f WHERE f.commitment=r.commitment)))"), params![key, side], |r| r.get(0))?)
}
fn exclude_actor(db: &Connection, schema: &str, table: &str, id: i64) -> Result<(), StorageError> {
    db.execute(
        "INSERT OR IGNORE INTO backup_erased_copy VALUES(?1,?2,?3)",
        params![schema, table, id],
    )?;
    Ok(())
}
