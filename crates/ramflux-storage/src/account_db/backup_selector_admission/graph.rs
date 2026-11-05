// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Bilateral authority and owner admission, before any restore graph writer.
use crate::StorageError;
use ramflux_crypto::blake3_256_base64url;
use rusqlite::{Connection, params};

pub(super) const CONFLICT: &str = r"
SELECT EXISTS(SELECT 1 FROM main.object_erasure_lookup l JOIN incoming.object_erasure_lookup r USING(lookup) WHERE l.commitment<>r.commitment)
OR EXISTS(SELECT 1 FROM main.object_retention_reference l JOIN incoming.object_retention_reference r USING(reference_hash) WHERE l.selector<>r.selector OR l.commitment<>r.commitment OR l.selector_lookup<>r.selector_lookup)
OR EXISTS(SELECT 1 FROM main.object_retention_reference l JOIN incoming.object_retention_reference r USING(selector_lookup) WHERE l.commitment<>r.commitment)
OR EXISTS(SELECT 1 FROM main.object_erasure_lookup l JOIN incoming.object_retention_reference r ON l.lookup=r.selector_lookup WHERE l.commitment<>r.commitment)
OR EXISTS(SELECT 1 FROM incoming.object_erasure_lookup l JOIN main.object_retention_reference r ON l.lookup=r.selector_lookup WHERE l.commitment<>r.commitment)";
pub(super) const FENCES: &str = r"
INSERT OR IGNORE INTO main.object_erasure_fence SELECT commitment FROM incoming.object_erasure_fence;
INSERT OR IGNORE INTO main.object_erasure_lookup SELECT lookup,commitment FROM incoming.object_erasure_lookup;
INSERT OR IGNORE INTO main.object_erasure_fence
WITH RECURSIVE retired(commitment) AS (
 SELECT commitment FROM main.object_erasure_fence UNION
 SELECT d.parent_commitment FROM (
 SELECT parent_commitment,child_commitment FROM main.object_payload_dependency UNION
 SELECT parent_commitment,child_commitment FROM incoming.object_payload_dependency
 ) d JOIN retired r ON r.commitment=d.child_commitment)
SELECT commitment FROM retired;
INSERT OR IGNORE INTO main.object_erasure_lookup
SELECT wire_lookup,commitment FROM main.object_retention_payload WHERE commitment IN (SELECT commitment FROM main.object_erasure_fence);
INSERT OR IGNORE INTO main.object_erasure_lookup
SELECT wire_lookup,commitment FROM incoming.object_retention_payload WHERE commitment IN (SELECT commitment FROM main.object_erasure_fence);
";
pub(in crate::account_db) fn classify(db: &Connection) -> Result<(), StorageError> {
    // Authenticated identities must agree even when one side would later be erased.
    let conflict: bool = db.query_row(CONFLICT, [], |r| r.get(0))?;
    if conflict {
        return Err(StorageError::ObjectOwnershipUnverified { schema_version: 13 });
    }
    db.execute_batch(FENCES)?;
    #[cfg(test)]
    checkpoint(db, "fence_union")?;
    // Both owner sets are inspected before decisions. These encrypted operation
    // rows contain only surviving edges; pending target cleanup is kept separate.
    for (schema, side) in [("main", "target"), ("incoming", "incoming")] {
        let mut query = db.prepare(&format!("SELECT r.reference_hash,m.message_id,r.selector,r.commitment FROM {schema}.object_retention_reference r JOIN {schema}.object_message_reference m USING(reference_hash)"))?;
        for row in query.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
            ))
        })? {
            let (hash, message, selector, commitment) = row?;
            classify_owner(db, side, &hash, &message, &selector, &commitment)?;
        }
    }
    for (schema, side) in [("main", "target"), ("incoming", "incoming")] {
        let mut query = db.prepare(&format!(
            "SELECT DISTINCT selector,commitment FROM {schema}.object_retention_reference"
        ))?;
        for row in query.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))? {
            let (selector, commitment) = row?;
            classify_selector(db, side, &selector, &commitment)?;
        }
    }
    #[cfg(test)]
    checkpoint(db, "graph_admission")?;
    Ok(())
}

// Point operations are shared by traversal and the isolated candidate work meter.
pub(super) const VETO: &str = "SELECT EXISTS(SELECT 1 FROM incoming.object_retention_reference r JOIN backup_lookup_origin o ON o.lookup=r.selector_lookup AND o.side='target' WHERE r.reference_hash=?1) AND NOT EXISTS(SELECT 1 FROM backup_reference_admission t WHERE t.side='target' AND t.selector=?2 AND t.commitment=?3)";
pub(super) const SELECTOR: &str = "INSERT INTO backup_selector_admission SELECT ?1,?2,?3,CASE WHEN EXISTS(SELECT 1 FROM backup_reference_admission a WHERE a.side=?1 AND a.selector=?2 AND a.commitment=?3) THEN 'keep' ELSE 'erase' END";

pub(super) fn classify_owner(
    db: &Connection,
    side: &str,
    hash: &str,
    message: &str,
    selector: &str,
    commitment: &str,
) -> Result<(), StorageError> {
    let local_deleted = deleted(db, "main", message)?;
    let incoming_deleted = deleted(db, "incoming", message)?;
    if side == "target" && !target_deleted(db, message)? && (local_deleted || incoming_deleted) {
        db.execute(
            "INSERT OR IGNORE INTO backup_target_delete VALUES(?1,?2,?3,?4)",
            params![hash, message, selector, commitment],
        )?;
    }
    let fenced: bool = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM object_erasure_fence WHERE commitment=?1)",
        [commitment],
        |r| r.get(0),
    )?;
    let vetoed = side == "incoming"
        && db.query_row(VETO, params![hash, selector, commitment], |r| r.get::<_, bool>(0))?;
    if !local_deleted && !incoming_deleted && !fenced && !vetoed {
        db.execute(
            "INSERT INTO backup_reference_admission VALUES(?1,?2,?3,?4,?5)",
            params![side, hash, message, selector, commitment],
        )?;
    }
    Ok(())
}

pub(super) fn classify_selector(
    db: &Connection,
    side: &str,
    selector: &str,
    commitment: &str,
) -> rusqlite::Result<()> {
    db.execute(SELECTOR, params![side, selector, commitment])?;
    Ok(())
}

pub(super) fn deleted(db: &Connection, schema: &str, message: &str) -> Result<bool, StorageError> {
    deleted_with_bindings(
        db,
        schema,
        message,
        "SELECT copy_id,message_id FROM main.message_copy_binding UNION ALL SELECT copy_id,message_id FROM incoming.message_copy_binding",
    )
}

// Read existing target deletion state only to decide whether pending work is needed.
// Admission restrictions above combine bindings from both inputs.
pub(in crate::account_db) fn target_deleted(
    db: &Connection,
    message: &str,
) -> Result<bool, StorageError> {
    deleted_with_bindings(
        db,
        "main",
        message,
        "SELECT copy_id,message_id FROM main.message_copy_binding",
    )
}

fn deleted_with_bindings(
    db: &Connection,
    schema: &str,
    message: &str,
    bindings: &str,
) -> Result<bool, StorageError> {
    let queries = super::restrictions::queries(schema, bindings);
    let projected: bool = db.query_row(&queries[0], [message], |r| r.get(0))?;
    let group_deleted: bool = db.query_row(&queries[1], [message], |r| r.get(0))?;
    if projected || group_deleted || marker(db, schema, message)? {
        return Ok(true);
    }
    // Resolve envelope aliases only through the caller's binding authority;
    // marker keys and rows always belong to the selected input schema.
    let mut query = db.prepare(&format!("SELECT substr(copy_id,10) FROM ({bindings}) WHERE message_id=?1 AND copy_id GLOB 'envelope:*'"))?;
    for envelope in query.query_map([message], |r| r.get::<_, String>(0))? {
        if marker(db, schema, &envelope?)? {
            return Ok(true);
        }
    }
    Ok(false)
}

fn marker(db: &Connection, schema: &str, id: &str) -> Result<bool, StorageError> {
    let legacy = blake3_256_base64url("ramflux.deleted-message.v1", id.as_bytes());
    let mut names = vec![format!("message/deleted/{legacy}")];
    for mac in super::super::mac_subkeys::input_macs(
        db,
        schema,
        b"ramflux/tombstone-key/v1",
        id.as_bytes(),
    )? {
        names.push(format!("message/deleted/{mac}"));
    }
    // An owner id can itself be the original envelope id.
    for mac in super::super::mac_subkeys::input_macs(
        db,
        schema,
        b"ramflux/deleted-envelope/v1",
        id.as_bytes(),
    )? {
        names.push(format!("message/deleted-envelope/{mac}"));
    }
    for name in names {
        if db.query_row(
            &format!(
                "SELECT EXISTS(SELECT 1 FROM {schema}.runtime_actor_state WHERE state_kind=?1)"
            ),
            [&name],
            |r| r.get::<_, bool>(0),
        )? {
            return Ok(true);
        }
    }
    Ok(false)
}

#[cfg(test)]
thread_local! {
    pub(super) static FAULT: std::cell::Cell<Option<&'static str>> = const { std::cell::Cell::new(None) };
}
#[cfg(test)]
fn checkpoint(db: &Connection, point: &str) -> Result<(), StorageError> {
    if FAULT.get() == Some(point) {
        // Ensure faults occur after real writes, rather than before the phase.
        let table = if point == "fence_union" {
            "object_erasure_lookup"
        } else {
            "backup_selector_admission"
        };
        assert!(
            db.query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get::<_, u64>(0))? > 0
        );
        return Err(StorageError::AuthorizationRejected);
    }
    Ok(())
}
