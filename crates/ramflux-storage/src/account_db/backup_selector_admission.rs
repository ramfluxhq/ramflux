// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Encrypted, transaction-scoped restore admission state and authenticated input checks.
use crate::StorageError;
use ramflux_crypto::{blake3_256_base64url, object_erasure_commitment, object_erasure_lookup};
use rusqlite::{Connection, params};
use serde_json::Value;

const TABLES: [&str; 4] = [
    "backup_reference_admission",
    "backup_selector_admission",
    "backup_lookup_origin",
    "backup_target_delete",
];

pub(super) fn is_scratch(table: &str) -> bool {
    TABLES.contains(&table)
}

pub(super) fn drop_scratch(db: &Connection) -> rusqlite::Result<()> {
    for table in TABLES {
        db.execute_batch(&format!("DROP TABLE IF EXISTS main.{table}"))?;
    }
    Ok(())
}

pub(super) fn prepare(db: &Connection) -> Result<(), StorageError> {
    let root: String = db.query_row(
        "SELECT principal_commitment FROM runtime_account_identity WHERE singleton=1",
        [],
        |r| r.get(0),
    )?;
    for database in ["main", "incoming"] {
        validate(db, database, &root)?;
    }
    db.execute_batch(r"
CREATE TABLE main.backup_reference_admission(side TEXT NOT NULL,reference_hash TEXT NOT NULL,message_id TEXT NOT NULL,selector TEXT NOT NULL,commitment TEXT NOT NULL,PRIMARY KEY(side,reference_hash,message_id));
CREATE INDEX main.backup_reference_selector ON backup_reference_admission(side,selector,commitment);
CREATE INDEX main.backup_reference_commitment ON backup_reference_admission(side,commitment,reference_hash);
CREATE TABLE main.backup_selector_admission(side TEXT NOT NULL,selector TEXT NOT NULL,commitment TEXT NOT NULL,decision TEXT NOT NULL CHECK(decision IN ('keep','erase','unowned_legacy')),PRIMARY KEY(side,selector,commitment));
CREATE TABLE main.backup_lookup_origin(side TEXT NOT NULL,lookup TEXT NOT NULL,commitment TEXT NOT NULL,PRIMARY KEY(side,lookup));
CREATE INDEX main.backup_lookup_side ON backup_lookup_origin(lookup,side);
CREATE TABLE main.backup_target_delete(reference_hash TEXT NOT NULL,message_id TEXT NOT NULL,selector TEXT NOT NULL,commitment TEXT NOT NULL,PRIMARY KEY(reference_hash,message_id));
CREATE INDEX main.backup_target_selector ON backup_target_delete(selector,commitment);
CREATE INDEX main.backup_target_message ON backup_target_delete(message_id,reference_hash);
INSERT INTO main.backup_lookup_origin SELECT 'target',lookup,commitment FROM main.object_erasure_lookup;
INSERT INTO main.backup_lookup_origin SELECT 'incoming',lookup,commitment FROM incoming.object_erasure_lookup;
")?;
    Ok(())
}

fn validate(db: &Connection, database: &str, root: &str) -> Result<(), StorageError> {
    let refuse = || StorageError::ObjectOwnershipUnverified { schema_version: 13 };
    let input_root: String = db.query_row(
        &format!(
            "SELECT principal_commitment FROM {database}.runtime_account_identity WHERE singleton=1"
        ),
        [],
        |r| r.get(0),
    )?;
    if input_root != root {
        return Err(StorageError::AuthorizationRejected);
    }
    let version: i64 = db.query_row(
        &format!("SELECT MAX(schema_version) FROM {database}.schema_migration"),
        [],
        |r| r.get(0),
    )?;
    if version > crate::schema_object_erasure::VERSION {
        return Err(StorageError::AccountSchemaTooNew {
            schema_version: version,
            supported: crate::schema_object_erasure::VERSION,
        });
    }
    let (checksum, sentinel) = match version {
        12 => {
            (crate::schema_object_erasure::V12_CHECKSUM, crate::schema_object_erasure::V12_SENTINEL)
        }
        13 => (crate::schema_object_erasure::CHECKSUM, crate::schema_object_erasure::SENTINEL),
        _ => return Err(refuse()),
    };
    let valid: bool = db.query_row(&format!("SELECT EXISTS(SELECT 1 FROM {database}.schema_migration WHERE schema_version=?1 AND checksum=?2) AND EXISTS(SELECT 1 FROM {database}.schema_migration WHERE schema_version=1 AND checksum=?3)"), params![version, checksum, sentinel], |r| r.get(0))?;
    if !valid {
        return Err(refuse());
    }
    validate_graph(db, database, root)
}

fn validate_graph(db: &Connection, database: &str, root: &str) -> Result<(), StorageError> {
    let refuse = || StorageError::ObjectOwnershipUnverified { schema_version: 13 };
    let mut payloads = db.prepare(&format!("SELECT commitment,wire_id,manifest_hash,wire_lookup FROM {database}.object_retention_payload"))?;
    for row in payloads.query_map([], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, String>(2)?,
            r.get::<_, String>(3)?,
        ))
    })? {
        let (commitment, wire, manifest, lookup) = row?;
        if commitment != object_erasure_commitment(root, &wire, &manifest)
            || lookup != object_erasure_lookup(root, &wire)
        {
            return Err(refuse());
        }
    }
    let invalid: bool = db.query_row(&format!(r"SELECT
EXISTS(SELECT 1 FROM {database}.object_retention_reference r WHERE NOT EXISTS(SELECT 1 FROM {database}.object_retention_payload p WHERE p.commitment=r.commitment) OR NOT EXISTS(SELECT 1 FROM {database}.object_message_reference m WHERE m.reference_hash=r.reference_hash)) OR
EXISTS(SELECT 1 FROM {database}.object_message_reference m WHERE NOT EXISTS(SELECT 1 FROM {database}.object_retention_reference r WHERE r.reference_hash=m.reference_hash) OR NOT EXISTS(SELECT 1 FROM {database}.direct_message_projection p WHERE p.message_id=m.message_id)) OR
EXISTS(SELECT 1 FROM {database}.object_payload_dependency d WHERE NOT EXISTS(SELECT 1 FROM {database}.object_retention_payload p WHERE p.commitment=d.parent_commitment AND p.retention_class='transport') OR NOT EXISTS(SELECT 1 FROM {database}.object_retention_payload p WHERE p.commitment=d.child_commitment)) OR
EXISTS(SELECT 1 FROM {database}.object_reference_actor a WHERE NOT EXISTS(SELECT 1 FROM {database}.object_retention_reference r WHERE r.reference_hash=a.reference_hash)) OR
EXISTS(SELECT 1 FROM {database}.object_erasure_lookup l JOIN {database}.object_retention_reference r ON r.selector_lookup=l.lookup WHERE r.commitment<>l.commitment) OR
EXISTS(SELECT 1 FROM {database}.object_erasure_lookup l JOIN {database}.object_retention_payload p ON p.wire_lookup=l.lookup WHERE p.commitment<>l.commitment)
"), [], |r| r.get(0))?;
    if invalid {
        return Err(refuse());
    }
    let mut references = db.prepare(&format!("SELECT r.reference_hash,r.selector,r.selector_lookup,r.reference_json,p.wire_id,p.manifest_hash,m.message_id,m.metadata_json FROM {database}.object_retention_reference r JOIN {database}.object_retention_payload p USING(commitment) JOIN {database}.object_message_reference m USING(reference_hash)"))?;
    let mut rows = references.query([])?;
    while let Some(row) = rows.next()? {
        let hash: String = row.get(0)?;
        let selector: String = row.get(1)?;
        let lookup: String = row.get(2)?;
        let bytes: Vec<u8> = row.get(3)?;
        let wire: String = row.get(4)?;
        let manifest: String = row.get(5)?;
        let message: String = row.get(6)?;
        let metadata: Vec<u8> = row.get(7)?;
        let value: Value = serde_json::from_slice(&bytes).map_err(|_| refuse())?;
        let metadata: Value = serde_json::from_slice(&metadata).map_err(|_| refuse())?;
        let expected = if value == serde_json::json!({}) {
            if selector != wire || metadata != serde_json::json!({}) {
                return Err(refuse());
            }
            blake3_256_base64url(
                "ramflux.object.transport.owner.v1",
                &ramflux_protocol::canonical_json_bytes(&(&wire, &manifest, &message))?,
            )
        } else {
            let inner = value.get("reference").unwrap_or(&value);
            if inner.get("object_id").and_then(Value::as_str) != Some(&wire)
                || inner.get("manifest_hash").and_then(Value::as_str) != Some(&manifest)
                || metadata
                    .get("message_id")
                    .and_then(Value::as_str)
                    .is_some_and(|id| id != message)
                || metadata
                    .get("manifest_hash")
                    .and_then(Value::as_str)
                    .is_some_and(|id| id != manifest)
            {
                return Err(refuse());
            }
            blake3_256_base64url(
                "ramflux.attachment.reference.v1",
                &ramflux_protocol::canonical_json_bytes(inner)?,
            )
        };
        if hash != expected || lookup != object_erasure_lookup(root, &selector) {
            return Err(refuse());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
