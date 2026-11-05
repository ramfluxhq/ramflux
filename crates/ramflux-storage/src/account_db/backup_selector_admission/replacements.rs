// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Exact standalone replacement receipts never authorize private aliases.
use crate::StorageError;
use rusqlite::{Connection, OptionalExtension};
use std::io::Read;

pub(in crate::account_db) fn checked(
    db: &Connection,
    schema: &str,
    commitment: &str,
) -> Result<bool, StorageError> {
    let row: Option<(i64,String)> = db.query_row(&format!("SELECT o.rowid,p.manifest_hash FROM {schema}.object_identity_replacement x JOIN {schema}.object_retention_payload p USING(commitment) JOIN {schema}.object_index o ON o.object_id=p.wire_id AND CAST(o.manifest_hash AS TEXT)=p.manifest_hash WHERE x.commitment=?1 AND p.retention_class='standalone' AND o.tombstoned=0 AND length(o.ciphertext)>0 AND NOT EXISTS(SELECT 1 FROM main.object_erasure_fence f WHERE f.commitment=x.commitment)"),[commitment],|r|Ok((r.get(0)?,r.get(1)?))).optional()?;
    let Some((id, manifest)) = row else { return Ok(false) };
    let mut blob = db.blob_open(schema, "object_index", "ciphertext", id, true)?;
    let mut hasher =
        ramflux_crypto::Blake3DomainHasher::new(ramflux_protocol::domain::OBJECT_MANIFEST);
    let mut buffer = [0; 8192];
    loop {
        let count = blob.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Ok(hasher.finalize_base64url() == manifest)
}

pub(super) fn merge(db: &Connection) -> Result<(), StorageError> {
    let mut query=db.prepare("SELECT commitment FROM incoming.object_identity_replacement x WHERE NOT EXISTS(SELECT 1 FROM backup_erased_copy e JOIN incoming.object_index o ON o.rowid=e.row_id JOIN incoming.object_retention_payload p ON p.wire_id=o.object_id AND p.commitment=x.commitment WHERE e.database_name='incoming' AND e.table_name='object_index')")?;
    for row in query.query_map([], |r| r.get::<_, String>(0))? {
        let commitment = row?;
        if checked(db, "incoming", &commitment)? {
            db.execute(
                "INSERT INTO object_identity_replacement VALUES(?1) ON CONFLICT DO NOTHING",
                [commitment],
            )?;
        }
    }
    Ok(())
}
