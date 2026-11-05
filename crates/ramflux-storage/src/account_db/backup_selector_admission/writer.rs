// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Import the classified graph without transiently creating unowned references.
use crate::StorageError;
use rusqlite::{Connection, params};
use serde_json::Value;

pub(in crate::account_db) fn merge(db: &Connection) -> Result<(), StorageError> {
    db.execute_batch("CREATE TEMP TABLE IF NOT EXISTS backup_erased_copy(database_name TEXT NOT NULL,table_name TEXT NOT NULL,row_id INTEGER NOT NULL,PRIMARY KEY(database_name,table_name,row_id));")?;
    db.execute_batch(r"
INSERT INTO object_retention_payload(commitment,wire_id,manifest_hash,wire_lookup,retention_class,hold_expires_at)
SELECT p.commitment,p.wire_id,p.manifest_hash,p.wire_lookup,p.retention_class,p.hold_expires_at FROM incoming.object_retention_payload p
WHERE NOT EXISTS(SELECT 1 FROM object_erasure_fence f WHERE f.commitment=p.commitment)
ON CONFLICT DO NOTHING;
INSERT INTO object_retention_reference
SELECT r.* FROM incoming.object_retention_reference r
WHERE EXISTS(SELECT 1 FROM backup_reference_admission a
 WHERE a.side='incoming' AND a.reference_hash=r.reference_hash
 AND a.selector=r.selector AND a.commitment=r.commitment
 AND NOT EXISTS(SELECT 1 FROM object_erasure_fence f WHERE f.commitment=a.commitment))
ON CONFLICT DO NOTHING;
INSERT INTO object_message_reference
SELECT m.* FROM incoming.object_message_reference m
WHERE EXISTS(SELECT 1 FROM backup_reference_admission a
 WHERE a.side='incoming' AND a.reference_hash=m.reference_hash AND a.message_id=m.message_id
 AND NOT EXISTS(SELECT 1 FROM object_erasure_fence f WHERE f.commitment=a.commitment))
ON CONFLICT DO NOTHING;
INSERT INTO object_payload_actor
SELECT a.* FROM incoming.object_payload_actor a
WHERE NOT EXISTS(SELECT 1 FROM object_erasure_fence f WHERE f.commitment=a.commitment)
AND NOT EXISTS(SELECT 1 FROM incoming.runtime_actor_state r JOIN backup_erased_copy e ON e.database_name='incoming' AND e.table_name='runtime_actor_state' AND e.row_id=r.rowid WHERE r.state_kind=a.state_kind)
ON CONFLICT DO NOTHING;
INSERT INTO object_payload_dependency
SELECT d.* FROM incoming.object_payload_dependency d
WHERE NOT EXISTS(SELECT 1 FROM object_erasure_fence f WHERE f.commitment IN (d.parent_commitment,d.child_commitment))
ON CONFLICT DO NOTHING;
INSERT INTO object_transport_actor
SELECT a.* FROM incoming.object_transport_actor a
WHERE NOT EXISTS(SELECT 1 FROM object_erasure_fence f WHERE f.commitment=a.commitment)
AND NOT EXISTS(SELECT 1 FROM incoming.runtime_actor_state r JOIN backup_erased_copy e ON e.database_name='incoming' AND e.table_name='runtime_actor_state' AND e.row_id=r.rowid WHERE r.state_kind=a.state_kind)
ON CONFLICT DO NOTHING;
INSERT INTO message_copy_binding
SELECT 'object:'||a.selector,a.message_id FROM backup_reference_admission a
WHERE a.side='incoming'
AND NOT EXISTS(SELECT 1 FROM object_erasure_fence f WHERE f.commitment=a.commitment)
ON CONFLICT DO NOTHING;
INSERT INTO message_copy_binding
SELECT 'object:'||p.wire_id,a.message_id FROM backup_reference_admission a
JOIN incoming.object_retention_payload p ON p.commitment=a.commitment
WHERE a.side='incoming'
AND NOT EXISTS(SELECT 1 FROM object_erasure_fence f WHERE f.commitment=a.commitment)
ON CONFLICT DO NOTHING;

")?;
    super::replacements::merge(db)?;
    import_reference_actors(db)
}

// Only the two SDK reference-actor producers authorize these keys. Arbitrary
// archive associations cannot create ownership over another selector's actor.
fn authorized_actor(key: &str, stored: &Value) -> Result<bool, StorageError> {
    let reference = stored.get("reference").unwrap_or(stored);
    if let Some(slot) = reference.get("key_slot")
        && slot.is_object()
        && slot.get("object_id").and_then(Value::as_str)
            == reference.get("object_id").and_then(Value::as_str)
    {
        let slot_hash = ramflux_crypto::blake3_256_base64url(
            "ramflux.received.slot.selector.v2",
            &ramflux_protocol::canonical_json_bytes(slot)?,
        );
        if key == format!("attachment/reference-by-slot/{slot_hash}") {
            return Ok(true);
        }
    }
    let hash = ramflux_crypto::blake3_256_base64url(
        "ramflux.attachment.ack.progress.v1",
        &ramflux_protocol::canonical_json_bytes(reference)?,
    );
    let prefix = format!("attachment/ack/{hash}/");
    let Some(index) = key.strip_prefix(&prefix) else { return Ok(false) };
    let Ok(number) = index.parse::<u32>() else { return Ok(false) };
    Ok(index == number.to_string()
        && reference
            .get("total_chunks")
            .and_then(Value::as_u64)
            .is_some_and(|total| u64::from(number) < total && total <= 4096))
}

fn import_reference_actors(db: &Connection) -> Result<(), StorageError> {
    let mut query = db.prepare(
        r"
SELECT a.reference_hash,a.state_kind,r.reference_json,d.message_id,d.commitment
FROM incoming.object_reference_actor a
JOIN incoming.object_retention_reference r USING(reference_hash)
JOIN backup_reference_admission d ON d.side='incoming' AND d.reference_hash=r.reference_hash
WHERE NOT EXISTS(SELECT 1 FROM object_erasure_fence f WHERE f.commitment=d.commitment)
",
    )?;
    let mut rows = query.query([])?;
    while let Some(row) = rows.next()? {
        let hash: String = row.get(0)?;
        let key: String = row.get(1)?;
        let bytes = zeroize::Zeroizing::new(row.get::<_, Vec<u8>>(2)?);
        let reference: Value = serde_json::from_slice(&bytes)
            .map_err(|_| StorageError::ObjectOwnershipUnverified { schema_version: 13 })?;
        if !authorized_actor(&key, &reference)? {
            continue;
        }
        let message: String = row.get(3)?;
        let commitment: String = row.get(4)?;
        db.execute("INSERT INTO object_reference_actor SELECT ?1,?2 WHERE NOT EXISTS(SELECT 1 FROM object_erasure_fence WHERE commitment=?3) ON CONFLICT DO NOTHING", params![hash,key,commitment])?;
        db.execute("INSERT INTO message_footprint SELECT ?1,'actor',?2 WHERE NOT EXISTS(SELECT 1 FROM object_erasure_fence WHERE commitment=?3) ON CONFLICT DO NOTHING", params![message,key,commitment])?;
    }
    Ok(())
}

#[cfg(test)]
thread_local! {
    pub(super) static FENCE_BEFORE_WRITE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[cfg(test)]
pub(in crate::account_db) fn late_fence_checkpoint(db: &Connection) -> rusqlite::Result<()> {
    if FENCE_BEFORE_WRITE.replace(false) {
        // Model a fence produced by the preceding object-erasure step after admission.
        db.execute_batch("INSERT INTO object_erasure_fence SELECT commitment FROM backup_reference_admission WHERE side='incoming' ON CONFLICT DO NOTHING;")?;
    }
    Ok(())
}
