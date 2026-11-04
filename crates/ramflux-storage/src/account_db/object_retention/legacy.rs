// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Resumable metadata discovery never infers imported ownership from a missing reference.
use super::*;
use rusqlite::Connection;

const ROW_BUDGET: usize = 256;
const BYTE_BUDGET: usize = 1024 * 1024;
const MAX_PAYLOAD: i64 = 16 * 1024 * 1024 + 16;
const COMPLETE: i64 = 5;
#[derive(serde::Deserialize)]
struct LegacyDirectory {
    message_id: Option<String>,
    manifest_hash: Option<String>,
}
struct LegacyActorMetadata {
    row_id: i64,
    kind: Option<String>,
    size: i64,
    encoded: Option<Vec<u8>>,
}
#[derive(serde::Deserialize)]
struct LegacyReference {
    reference: Option<Value>,
}

impl AccountDb {
    /// # Errors
    /// Reclaims at most one expired hold without advancing the per-open metadata discovery cursor.
    pub fn maintain_expired_object_holds(&self) -> Result<(), StorageError> {
        let now = self.now_unix();
        self.write_transaction(|| {
            self.connection.call(move |db| Ok(reclaim_one(db, now, false)))?
        })
    }

    /// # Errors
    /// Performs one bounded discovery page and at most one measured orphan reclamation.
    pub fn maintain_object_retention(&self) -> Result<(), StorageError> {
        let now = self.now_unix();
        let complete = self.write_transaction(|| step(self))?;
        // Reclamation remains a separate bounded writer phase after discovery commits.
        if complete {
            self.write_transaction(|| {
                self.connection.call(move |db| Ok(reclaim_one(db, now, true)))?
            })?;
        }
        Ok(())
    }
}

fn step(account: &AccountDb) -> Result<bool, StorageError> {
    let db = &account.connection;
    let root = &account.principal_commitment;
    let (mut phase, mut cursor): (i64, i64) = db.query_row(
        "SELECT phase,cursor FROM object_retention_upgrade WHERE singleton=1",
        [],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    let mut rows = 0_usize;
    let mut bytes = 0_usize;
    while phase < COMPLETE && rows < ROW_BUDGET && bytes < BYTE_BUDGET {
        if phase == 0 {
            let row: Option<(i64,Option<String>,Option<String>,i64)> = db.query_row("SELECT rowid,CASE WHEN length(CAST(object_id AS BLOB))+COALESCE(length(CAST(manifest_hash AS BLOB)),0)<=?2 THEN object_id END,CASE WHEN length(CAST(object_id AS BLOB))+COALESCE(length(CAST(manifest_hash AS BLOB)),0)<=?2 THEN CAST(manifest_hash AS TEXT) END,length(CAST(object_id AS BLOB))+COALESCE(length(CAST(manifest_hash AS BLOB)),0) FROM object_index WHERE rowid>?1 ORDER BY rowid LIMIT 1", params![cursor,BYTE_BUDGET-bytes], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).optional()?;
            let Some((id, wire, manifest, size)) = row else {
                phase += 1;
                cursor = 0;
                continue;
            };
            if wire.is_none() && size <= i64::try_from(BYTE_BUDGET).unwrap_or(i64::MAX) {
                break;
            }
            if let (Some(wire), Some(manifest)) = (wire, manifest) {
                bytes += wire.len() + manifest.len();
                db.execute("INSERT INTO object_retention_payload(commitment,wire_id,manifest_hash,wire_lookup,retention_class) VALUES(?1,?2,?3,?4,'legacy') ON CONFLICT DO NOTHING",params![object_erasure_commitment(root,&wire,&manifest),wire,manifest,object_erasure_lookup(root,&wire)])?;
            }
            cursor = id;
            rows += 1;
            continue;
        }
        let archive = phase == 2 || phase == 4;
        let directory = phase <= 2;
        let table = if archive { "backup_archived_actor_state" } else { "runtime_actor_state" };
        if archive
            && !db.query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1)",
                params![table],
                |row| row.get::<_, bool>(0),
            )?
        {
            phase += 1;
            cursor = 0;
            continue;
        }
        let prefix = if directory { "directory/object/*" } else { "attachment/reference/*" };
        let row: Option<LegacyActorMetadata> = db.query_row(&format!("SELECT rowid,CASE WHEN state_kind GLOB ?3 AND length(CAST(state_kind AS BLOB))+length(state_json)<=?2 THEN state_kind END,CASE WHEN state_kind GLOB ?3 THEN length(CAST(state_kind AS BLOB))+length(state_json) ELSE 0 END,CASE WHEN state_kind GLOB ?3 AND length(CAST(state_kind AS BLOB))+length(state_json)<=?2 THEN state_json END FROM {table} WHERE rowid>?1 ORDER BY rowid LIMIT 1"),params![cursor,BYTE_BUDGET-bytes,prefix], |r|Ok(LegacyActorMetadata { row_id:r.get(0)?,kind:r.get(1)?,size:r.get(2)?,encoded:r.get(3)? })).optional()?;
        let Some(LegacyActorMetadata { row_id: id, kind, size, encoded }) = row else {
            phase += 1;
            cursor = 0;
            continue;
        };
        if size > 0 && encoded.is_none() && size <= i64::try_from(BYTE_BUDGET).unwrap_or(i64::MAX) {
            break;
        }
        cursor = id;
        rows += 1;
        let (Some(kind), Some(encoded)) = (kind, encoded) else { continue };
        bytes += kind.len() + encoded.len();
        let encoded = zeroize::Zeroizing::new(encoded);
        if directory {
            if let Ok(value) = serde_json::from_slice::<LegacyDirectory>(&encoded)
                && let (Some(message), Some(manifest)) = (value.message_id, value.manifest_hash)
            {
                db.execute("INSERT INTO object_legacy_reference_context(selector,message_id,manifest_hash,metadata_json) VALUES(?1,?2,?3,?4) ON CONFLICT(selector) DO NOTHING",params![kind.trim_start_matches("directory/object/"),message,manifest,encoded.as_slice()])?;
            }
        } else if let Ok(value) = serde_json::from_slice::<LegacyReference>(&encoded)
            && let Some(reference) = value.reference
        {
            discover_reference(account, &kind, &reference, &encoded)?;
        } else {
            db.execute("UPDATE object_retention_upgrade SET unsafe_references=unsafe_references+1 WHERE singleton=1",[])?;
        }
    }
    db.execute("UPDATE object_retention_upgrade SET phase=?1,cursor=?2,rows_scanned=rows_scanned+?3,decoded_bytes=decoded_bytes+?4 WHERE singleton=1",params![phase,cursor,rows,bytes])?;
    if phase == COMPLETE {
        db.execute("DELETE FROM object_legacy_reference_context", [])?;
    }
    Ok(phase == COMPLETE)
}

fn discover_reference(
    account: &AccountDb,
    key: &str,
    value: &Value,
    encoded: &[u8],
) -> Result<(), StorageError> {
    let db = &account.connection;
    let reference = value;
    let (Some(wire), Some(manifest)) = (
        reference.get("object_id").and_then(Value::as_str),
        reference.get("manifest_hash").and_then(Value::as_str),
    ) else {
        return Ok(());
    };
    let selector = key.trim_start_matches("attachment/reference/");
    let context: Option<(String,String,Vec<u8>)> = db.query_row("SELECT message_id,manifest_hash,metadata_json FROM object_legacy_reference_context WHERE selector=?1",params![selector],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional()?;
    let Some((message, expected, metadata)) = context else {
        // A private archive may not install a reference whose ownership cannot be reconstructed.
        db.execute("UPDATE object_retention_upgrade SET unsafe_references=unsafe_references+1 WHERE singleton=1",[])?;
        return Ok(());
    };
    if expected != manifest {
        return Ok(());
    }
    // Discovery needs a reconstructible live projection as well as the common
    // admission checks. Reject before registration can insert a payload or edge.
    let live: bool = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM direct_message_projection WHERE message_id=?1 AND deleted=0)",
        params![message],
        |row| row.get(0),
    )?;
    if !live || account.message_is_deleted(&message)? {
        db.execute("UPDATE object_retention_upgrade SET unsafe_references=unsafe_references+1 WHERE singleton=1", [])?;
        return Ok(());
    }
    let hash = ramflux_crypto::blake3_256_base64url(
        "ramflux.attachment.reference.v1",
        &ramflux_protocol::canonical_json_bytes(reference)?,
    );
    let reference: Value = serde_json::from_slice(encoded)?;
    let metadata: Value = serde_json::from_slice(&metadata)?;
    match account.register_object_reference(
        ObjectReferenceAdmission::ArchiveDiscovery,
        &ObjectReferenceOwner {
            reference_hash: &hash,
            wire_id: wire,
            manifest_hash: manifest,
            selector,
            message_id: &message,
            reference: &reference,
            metadata: &metadata,
        },
    ) {
        // Historical erasure is an expected skipped candidate; storage faults
        // still abort the page, including its cursor and budget accounting.
        Err(StorageError::ObjectErased) => Ok(()),
        result => result,
    }
}

fn reclaim_one(db: &Connection, now: i64, discovery_complete: bool) -> Result<(), StorageError> {
    db.execute("DELETE FROM object_erasure_work", [])?;
    // Keep revocation fences until the private reference is explicitly retired. These
    // probes use the wire/selector and actor-key indexes; no reference JSON is decoded.
    db.execute(r"
        INSERT INTO object_erasure_work
        SELECT p.commitment,p.wire_id,p.manifest_hash FROM object_retention_payload p
        LEFT JOIN object_index o ON o.object_id=p.wire_id AND CAST(o.manifest_hash AS TEXT)=p.manifest_hash
        WHERE ((p.retention_class='imported' AND ?3 AND p.owner_count=0)
            OR (p.retention_class='pre_send' AND p.hold_expires_at<=?1 AND p.owner_count=0)
            OR (p.retention_class='transport' AND p.hold_expires_at<=?1))
        AND NOT (
            EXISTS(SELECT 1 FROM object_index revoked WHERE revoked.object_id=p.wire_id AND revoked.tombstoned=1)
            AND (EXISTS(SELECT 1 FROM runtime_actor_state a WHERE a.state_kind='attachment/reference/'||p.wire_id)
                OR EXISTS(SELECT 1 FROM object_retention_reference r
                    JOIN runtime_actor_state a ON a.state_kind='attachment/reference/'||r.selector
                    WHERE r.commitment=p.commitment))
        )
        AND NOT EXISTS(SELECT 1 FROM object_retention_reference r
            JOIN object_index revoked ON revoked.object_id=r.selector AND revoked.tombstoned=1
            JOIN runtime_actor_state a ON a.state_kind='attachment/reference/'||r.selector
            WHERE r.commitment=p.commitment)
        AND COALESCE(length(o.ciphertext),0)<=?2 AND COALESCE(length(o.object_body),0)<=?2
        ORDER BY p.commitment LIMIT 1", params![now,MAX_PAYLOAD,discovery_complete])?;
    let inconsistent:bool=db.query_row("SELECT EXISTS(SELECT 1 FROM object_erasure_work w JOIN object_retention_payload p USING(commitment) WHERE p.retention_class<>'transport' AND EXISTS(SELECT 1 FROM object_retention_reference r JOIN object_message_reference m USING(reference_hash) WHERE r.commitment=w.commitment))",[],|r|r.get(0))?;
    if inconsistent {
        return Err(StorageError::ObjectOwnershipUnverified { schema_version: 12 });
    }
    db.execute_batch(&schema::payload_erasure_body(db)?)?;
    Ok(())
}
