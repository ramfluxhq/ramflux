// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Bilateral authority and owner admission, before any restore graph writer.
use crate::StorageError;
use ramflux_crypto::blake3_256_base64url;
use rusqlite::{Connection, params};

pub(in crate::account_db) fn classify(db: &Connection) -> Result<(), StorageError> {
    // Authenticated identities must agree even when one side would later be erased.
    let conflict: bool = db.query_row(r"
SELECT EXISTS(SELECT 1 FROM main.object_erasure_lookup l JOIN incoming.object_erasure_lookup r USING(lookup) WHERE l.commitment<>r.commitment)
OR EXISTS(SELECT 1 FROM main.object_retention_reference l JOIN incoming.object_retention_reference r USING(reference_hash) WHERE l.selector<>r.selector OR l.commitment<>r.commitment OR l.selector_lookup<>r.selector_lookup)
OR EXISTS(SELECT 1 FROM main.object_retention_reference l JOIN incoming.object_retention_reference r USING(selector_lookup) WHERE l.commitment<>r.commitment)
OR EXISTS(SELECT 1 FROM main.object_erasure_lookup l JOIN incoming.object_retention_reference r ON l.lookup=r.selector_lookup WHERE l.commitment<>r.commitment)
OR EXISTS(SELECT 1 FROM incoming.object_erasure_lookup l JOIN main.object_retention_reference r ON l.lookup=r.selector_lookup WHERE l.commitment<>r.commitment)", [], |r| r.get(0))?;
    if conflict {
        return Err(StorageError::ObjectOwnershipUnverified { schema_version: 13 });
    }
    db.execute_batch(r"
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
")?;
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
            let local_deleted = deleted(db, "main", &message)?;
            let incoming_deleted = deleted(db, "incoming", &message)?;
            if side == "target" && !local_deleted && incoming_deleted {
                db.execute(
                    "INSERT OR IGNORE INTO backup_target_delete VALUES(?1,?2,?3,?4)",
                    params![hash, message, selector, commitment],
                )?;
            }
            let fenced: bool = db.query_row(
                "SELECT EXISTS(SELECT 1 FROM object_erasure_fence WHERE commitment=?1)",
                [&commitment],
                |r| r.get(0),
            )?;
            if !local_deleted && !incoming_deleted && !fenced {
                db.execute(
                    "INSERT INTO backup_reference_admission VALUES(?1,?2,?3,?4,?5)",
                    params![side, hash, message, selector, commitment],
                )?;
            }
        }
    }
    // Only pre-union target origin vetoes incoming same-identity owners. A
    // surviving target witness keeps a partial lookup live. Incoming-only
    // history may retain its own independently surviving owners.
    db.execute_batch(r"
DELETE FROM backup_reference_admission AS a WHERE side='incoming'
AND EXISTS(SELECT 1 FROM incoming.object_retention_reference r JOIN backup_lookup_origin o ON o.lookup=r.selector_lookup AND o.side='target' WHERE r.reference_hash=a.reference_hash)
AND NOT EXISTS(SELECT 1 FROM backup_reference_admission t WHERE t.side='target' AND t.selector=a.selector AND t.commitment=a.commitment);
INSERT INTO backup_selector_admission
SELECT 'target',r.selector,r.commitment,CASE WHEN EXISTS(SELECT 1 FROM backup_reference_admission a WHERE a.side='target' AND a.selector=r.selector AND a.commitment=r.commitment) THEN 'keep' ELSE 'erase' END FROM main.object_retention_reference r GROUP BY r.selector,r.commitment;
INSERT INTO backup_selector_admission
SELECT 'incoming',r.selector,r.commitment,CASE WHEN EXISTS(SELECT 1 FROM backup_reference_admission a WHERE a.side='incoming' AND a.selector=r.selector AND a.commitment=r.commitment) THEN 'keep' ELSE 'erase' END FROM incoming.object_retention_reference r GROUP BY r.selector,r.commitment;
")?;
    #[cfg(test)]
    checkpoint(db, "graph_admission")?;
    Ok(())
}

fn deleted(db: &Connection, schema: &str, message: &str) -> Result<bool, StorageError> {
    let projected: bool = db.query_row(
        &format!(
            r"SELECT
EXISTS(SELECT 1 FROM {schema}.direct_message_projection WHERE message_id=?1 AND deleted=1)
OR EXISTS(SELECT 1 FROM {schema}.message_tombstone_projection WHERE message_id=?1)
OR EXISTS(SELECT 1 FROM {schema}.group_message_tombstone_projection WHERE message_id=?1)"
        ),
        [message],
        |r| r.get(0),
    )?;
    let group_deleted: bool = db.query_row(&format!("SELECT EXISTS(SELECT 1 FROM {schema}.group_message_tombstone_projection t WHERE EXISTS(SELECT 1 FROM main.message_copy_binding b WHERE b.message_id=?1 AND b.copy_id='group:'||t.group_id||':'||t.message_id) OR EXISTS(SELECT 1 FROM incoming.message_copy_binding b WHERE b.message_id=?1 AND b.copy_id='group:'||t.group_id||':'||t.message_id))"), [message], |r|r.get(0))?;
    if projected || group_deleted || marker(db, schema, message)? {
        return Ok(true);
    }
    // A known owner may also be named by an envelope id. Examine bindings
    // from either graph, but match markers only against their own input's keys.
    let mut query = db.prepare("SELECT substr(copy_id,10) FROM main.message_copy_binding WHERE message_id=?1 AND copy_id GLOB 'envelope:*' UNION SELECT substr(copy_id,10) FROM incoming.message_copy_binding WHERE message_id=?1 AND copy_id GLOB 'envelope:*'")?;
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
