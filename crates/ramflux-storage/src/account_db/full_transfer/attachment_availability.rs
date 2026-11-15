// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Present source ciphertext needs an ordinary durable remote-upload receipt, never absence.
use crate::{StorageError, database::Connection};
use rusqlite::params;

const PAGE: usize = 64;
const LOCAL: &str = "o.tombstoned=0 AND NOT EXISTS(SELECT 1 FROM object_retention_payload p WHERE p.wire_id=o.object_id AND CAST(p.manifest_hash AS BLOB)=CAST(o.manifest_hash AS BLOB) AND p.owner_count=0 AND p.hold_expires_at IS NOT NULL AND p.hold_expires_at<=unixepoch()) AND (length(o.ciphertext)>0 OR EXISTS(SELECT 1 FROM object_chunk c WHERE c.object_id=o.object_id AND length(c.local_path)>0))";
struct Object {
    id: String,
    manifest: Vec<u8>,
}
fn invalid() -> StorageError {
    StorageError::PairingField("UnsupportedRecord")
}
fn page(snapshot: &Connection, after: Option<&str>) -> Result<Vec<Object>, StorageError> {
    let after = after.map(str::to_owned);
    Ok(snapshot.call(move |db| {
        let mut query = db.prepare(&format!("SELECT CASE WHEN length(CAST(o.object_id AS BLOB)) BETWEEN 1 AND 256 THEN o.object_id END,CASE WHEN length(CAST(o.manifest_hash AS BLOB))=43 THEN CAST(o.manifest_hash AS BLOB) END FROM object_index o WHERE {LOCAL} AND (?1 IS NULL OR o.object_id>?1) ORDER BY o.object_id LIMIT 64"))?;
        query.query_map(params![after], |row| Ok(Object { id: row.get(0)?, manifest: row.get(1)? }))?.collect()
    })?)
}
/// Recheck the exact snapshot's identities against the ordinary writer's latest receipts.
/// A later authorized upload may unblock a frozen J6 tail without changing that cut.
pub(super) fn require(snapshot: &Connection, live: &Connection) -> Result<(), StorageError> {
    let mut after = None;
    loop {
        let objects = page(snapshot, after.as_deref())?;
        for object in &objects {
            if object.id.is_empty() || object.id.len() > 256 || object.manifest.len() != 43 {
                return Err(invalid());
            }
            let remote:bool=live.query_row("SELECT EXISTS(SELECT 1 FROM object_transfer_state t WHERE t.object_id=?1 AND CAST(t.manifest_hash AS BLOB)=?2 AND t.state='complete' AND t.direction IN ('upload','download') AND length(t.relay_endpoint)>0 AND t.expires_at>unixepoch() AND t.total_chunks>0 AND t.done_bytes=t.total_bytes AND t.total_bytes>0)",params![object.id,object.manifest],|row|row.get(0))?;
            if !remote {
                return Err(StorageError::PairingField("AttachmentNotRemote"));
            }
        }
        if objects.len() < PAGE {
            return Ok(());
        }
        after = objects.last().map(|object| object.id.clone());
    }
}

#[cfg(test)]
mod tests;
