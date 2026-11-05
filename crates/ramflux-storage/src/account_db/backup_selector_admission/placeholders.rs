// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Resolve placeholder identity on unfiltered inputs before exclusion or wire arbitration.
use super::super::object_retention::selector_admission::{
    identity_query, resolve_admitted_identity,
};
use crate::StorageError;
use ramflux_crypto::{object_erasure_commitment, object_erasure_lookup};
use rusqlite::{Connection, OptionalExtension, params};

pub(in crate::account_db) fn active(db: &Connection) -> rusqlite::Result<bool> {
    db.query_row(
        "SELECT EXISTS(SELECT 1 FROM main.sqlite_master WHERE name='backup_selector_admission')",
        [],
        |r| r.get(0),
    )
}

pub(in crate::account_db) fn classify(db: &Connection, root: &str) -> Result<(), StorageError> {
    for (schema, side) in [("main", "target"), ("incoming", "incoming")] {
        let mut query = db.prepare(&format!("SELECT rowid,object_id,CAST(manifest_hash AS TEXT) FROM {schema}.object_index WHERE tombstoned=1 AND length(ciphertext)=0 AND chunk_count=0"))?;
        let mut rows = query.query([])?;
        while let Some(row) = rows.next()? {
            let id: i64 = row.get(0)?;
            let selector: String = row.get(1)?;
            let manifest: String = row.get(2)?;
            // Input bytes stay untouched: merge_objects retains this flag through arbitration.
            let original_legacy_zero = manifest.as_bytes() == [0_u8; 32];
            let mut mapping = db.prepare(&format!("SELECT DISTINCT p.wire_id,p.manifest_hash,r.commitment FROM {schema}.object_retention_reference r JOIN {schema}.object_retention_payload p USING(commitment) WHERE r.selector=?1"))?;
            let identities = mapping
                .query_map([&selector], |r| {
                    Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            if identities.len() > 1
                || identities
                    .first()
                    .is_some_and(|(_, m, _)| !original_legacy_zero && m != &manifest)
            {
                return Err(StorageError::ObjectOwnershipUnverified { schema_version: 13 });
            }
            let Some((_, _, commitment)) = identities.first() else {
                // No authenticated mapping: omit without inventing a payload fence or lookup.
                db.execute(
                    "INSERT OR IGNORE INTO backup_erased_copy VALUES(?1,'object_index',?2)",
                    params![schema, id],
                )?;
                db.execute("INSERT OR REPLACE INTO backup_selector_admission VALUES(?1,?2,'','unowned_legacy')",params![side,selector])?;
                continue;
            };
            let keep: bool = db.query_row("SELECT EXISTS(SELECT 1 FROM backup_selector_admission WHERE side=?1 AND selector=?2 AND commitment=?3 AND decision='keep')",params![side,selector,commitment],|r|r.get(0))?;
            let pending_target: bool = side == "target" && db.query_row("SELECT EXISTS(SELECT 1 FROM backup_target_delete WHERE selector=?1 AND commitment=?2) AND NOT EXISTS(SELECT 1 FROM object_erasure_fence WHERE commitment=?2)",params![selector,commitment],|r|r.get(0))?;
            if !keep && !pending_target {
                db.execute(
                    "INSERT OR IGNORE INTO object_erasure_lookup VALUES(?1,?2)",
                    params![object_erasure_lookup(root, &selector), commitment],
                )?;
                db.execute(
                    "INSERT OR IGNORE INTO backup_erased_copy VALUES(?1,'object_index',?2)",
                    params![schema, id],
                )?;
            }
        }
    }
    // Retire the rejected placeholder's direct provenance alongside its row.
    // Broader shared graph/actor writers are governed by later admission stages.
    for (schema, side) in [("main", "target"), ("incoming", "incoming")] {
        db.execute(&format!("INSERT OR IGNORE INTO backup_erased_copy SELECT ?1,'message_copy_binding',b.rowid FROM {schema}.message_copy_binding b JOIN backup_selector_admission a ON b.copy_id='object:'||a.selector WHERE a.side=?2 AND a.decision<>'keep' AND NOT (a.side='target' AND EXISTS(SELECT 1 FROM backup_target_delete t WHERE t.selector=a.selector AND t.commitment=a.commitment) AND NOT EXISTS(SELECT 1 FROM object_erasure_fence f WHERE f.commitment=a.commitment))"),params![schema,side])?;
        db.execute(&format!("INSERT OR IGNORE INTO backup_erased_copy SELECT ?1,'message_footprint',f.rowid FROM {schema}.message_footprint f JOIN backup_selector_admission a ON f.kind='revocation_selector' AND json_extract(f.locator,'$.selector')=a.selector WHERE a.side=?2 AND a.decision<>'keep' AND NOT (a.side='target' AND EXISTS(SELECT 1 FROM backup_target_delete t WHERE t.selector=a.selector AND t.commitment=a.commitment) AND NOT EXISTS(SELECT 1 FROM object_erasure_fence f WHERE f.commitment=a.commitment))"),params![schema,side])?;
    }
    db.execute_batch("DELETE FROM main.message_copy_binding WHERE rowid IN (SELECT row_id FROM backup_erased_copy WHERE database_name='main' AND table_name='message_copy_binding'); DELETE FROM main.message_footprint WHERE rowid IN (SELECT row_id FROM backup_erased_copy WHERE database_name='main' AND table_name='message_footprint');")?;
    // Placeholder removal is selector work. Never seed payload work with its alias.
    db.execute_batch("DELETE FROM main.object_index WHERE tombstoned=1 AND length(ciphertext)=0 AND chunk_count=0 AND rowid IN (SELECT row_id FROM backup_erased_copy WHERE database_name='main' AND table_name='object_index');")?;
    Ok(())
}

pub(in crate::account_db) fn erased(
    db: &Connection,
    root: &str,
    selector: &str,
    manifest: Option<&str>,
    schema: &str,
) -> Result<bool, StorageError> {
    let side = if schema == "main" { "target" } else { "incoming" };
    let rows = db
        .prepare(&identity_query(schema))?
        .query_map([selector], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let admitted = resolve_admitted_identity(rows, None, |wire, identity_manifest, message| {
        let commitment = object_erasure_commitment(root, wire, identity_manifest);
        Ok(db.query_row("SELECT EXISTS(SELECT 1 FROM backup_reference_admission WHERE side=?1 AND selector=?2 AND commitment=?3 AND message_id=?4) AND NOT EXISTS(SELECT 1 FROM object_erasure_fence WHERE commitment=?3)",params![side,selector,commitment,message],|r|r.get(0))?)
    })?;
    if admitted.is_some() {
        return Ok(false);
    }
    let rejected: bool = db.query_row("SELECT EXISTS(SELECT 1 FROM backup_selector_admission WHERE side=?1 AND selector=?2 AND decision<>'keep') OR EXISTS(SELECT 1 FROM object_erasure_lookup WHERE lookup=?3)",params![side,selector,object_erasure_lookup(root,selector)],|r|r.get(0))?;
    if rejected {
        return Ok(true);
    }
    let current = match manifest {
        Some(value) => Some(value.to_owned()),
        None => db.query_row(&format!("SELECT CAST(manifest_hash AS TEXT) FROM {schema}.object_index WHERE object_id=?1"),[selector],|r|r.get::<_,String>(0)).optional()?,
    };
    if let Some(manifest) = current {
        return Ok(db.query_row(
            "SELECT EXISTS(SELECT 1 FROM object_erasure_fence WHERE commitment=?1)",
            [object_erasure_commitment(root, selector, &manifest)],
            |r| r.get(0),
        )?);
    }
    Ok(false)
}
