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
            let mut mapping = db.prepare_cached(&format!("SELECT DISTINCT p.wire_id,p.manifest_hash,r.commitment FROM {schema}.object_retention_reference r JOIN {schema}.object_retention_payload p USING(commitment) WHERE r.selector=?1"))?;
            let mut identities = mapping
                .query_map([&selector], |r| {
                    Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            let mut inherited = false;
            if identities.is_empty() && side == "incoming" {
                let (other_schema, other_side) = ("main", "target");
                let mut other = db.prepare_cached(&format!("SELECT DISTINCT p.wire_id,p.manifest_hash,r.commitment FROM {other_schema}.object_retention_reference r JOIN {other_schema}.object_retention_payload p USING(commitment) JOIN backup_reference_admission a ON a.side=?2 AND a.reference_hash=r.reference_hash WHERE r.selector=?1 AND EXISTS(SELECT 1 FROM backup_selector_admission s WHERE s.side=a.side AND s.selector=r.selector AND s.commitment=r.commitment AND s.decision='keep')"))?;
                identities = other
                    .query_map(params![selector, other_side], |r| {
                        Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?))
                    })?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                inherited = !identities.is_empty();
            }
            if identities.is_empty()
                && side == "target"
                && let Some(identity) = legacy_target_identity(db, root, &selector, &manifest)?
            {
                identities.push(identity);
                inherited = true;
            }
            if identities.len() > 1
                || identities
                    .first()
                    .is_some_and(|(_, m, _)| !original_legacy_zero && m != &manifest)
            {
                return Err(StorageError::ObjectOwnershipUnverified { schema_version: 13 });
            }
            let Some((_, _, commitment)) = identities.first() else {
                omit_unresolved_placeholder(db, schema, side, id, &selector)?;
                continue;
            };
            if inherited {
                db.execute(
                    "INSERT OR REPLACE INTO backup_selector_admission VALUES(?1,?2,?3,'keep')",
                    params![side, selector, commitment],
                )?;
            }
            let keep: bool = db.query_row("SELECT EXISTS(SELECT 1 FROM backup_selector_admission WHERE side=?1 AND selector=?2 AND commitment=?3 AND decision='keep')",params![side,selector,commitment],|r|r.get(0))?;
            if keep && original_legacy_zero && side == "target" {
                db.execute("UPDATE main.object_index SET manifest_hash=?1,chunk_manifest_hash=?1 WHERE rowid=?2", params![identities[0].1.as_bytes(),id])?;
            }
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
        db.execute(&format!("INSERT OR IGNORE INTO backup_erased_copy SELECT ?1,'message_copy_binding',b.rowid FROM {schema}.message_copy_binding b JOIN backup_selector_admission a ON b.copy_id='object:'||a.selector WHERE a.side=?2 AND a.decision<>'keep' AND NOT EXISTS(SELECT 1 FROM backup_selector_admission a2 WHERE a2.side=a.side AND a2.selector=a.selector AND a2.decision='keep') AND NOT (a.side='target' AND EXISTS(SELECT 1 FROM backup_target_delete t WHERE t.selector=a.selector AND t.commitment=a.commitment) AND NOT EXISTS(SELECT 1 FROM object_erasure_fence f WHERE f.commitment=a.commitment))"),params![schema,side])?;
        db.execute(&format!("INSERT OR IGNORE INTO backup_erased_copy SELECT ?1,'message_footprint',f.rowid FROM {schema}.message_footprint f JOIN backup_selector_admission a ON f.kind='revocation_selector' AND json_extract(f.locator,'$.selector')=a.selector WHERE a.side=?2 AND a.decision<>'keep' AND NOT EXISTS(SELECT 1 FROM backup_selector_admission a2 WHERE a2.side=a.side AND a2.selector=a.selector AND a2.decision='keep') AND NOT (a.side='target' AND EXISTS(SELECT 1 FROM backup_target_delete t WHERE t.selector=a.selector AND t.commitment=a.commitment) AND NOT EXISTS(SELECT 1 FROM object_erasure_fence f WHERE f.commitment=a.commitment))"),params![schema,side])?;
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
    if let Some((wire, admitted_manifest)) = admitted {
        if let Some(copy_manifest) = manifest.filter(|value| *value != admitted_manifest) {
            return Ok(db.query_row(
                "SELECT EXISTS(SELECT 1 FROM object_erasure_fence WHERE commitment=?1)",
                [object_erasure_commitment(root, &wire, copy_manifest)],
                |r| r.get(0),
            )?);
        }
        return Ok(false);
    }
    let replacement_manifest = match manifest {
        Some(value) => Some(value.to_owned()),
        None => db.query_row(&format!("SELECT CAST(manifest_hash AS TEXT) FROM {schema}.object_index WHERE object_id=?1"),[selector],|r|r.get::<_,String>(0)).optional()?,
    };
    if let Some(value) = replacement_manifest
        && super::replacements::checked(
            db,
            schema,
            &object_erasure_commitment(root, selector, &value),
        )?
    {
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

// The live G2 legacy path enrolls this witness without a retention edge.
fn legacy_target_identity(
    db: &Connection,
    root: &str,
    selector: &str,
    manifest: &str,
) -> Result<Option<(String, String, String)>, StorageError> {
    let mut values = Vec::new();
    for key in [format!("attachment/reference/{selector}"), format!("directory/object/{selector}")]
    {
        let bytes: Option<Option<Vec<u8>>> = db.query_row("SELECT CASE WHEN length(state_json)<=1048576 THEN state_json END FROM main.runtime_actor_state WHERE state_kind=?1", [key], |r| r.get(0)).optional()?;
        let Some(bytes) = bytes else {
            return registered_target_identity(db, root, selector, manifest);
        };
        let bytes = zeroize::Zeroizing::new(bytes.ok_or(StorageError::AuthorizationRejected)?);
        values.push(
            serde_json::from_slice::<serde_json::Value>(&bytes)
                .map_err(|_| StorageError::AuthorizationRejected)?,
        );
    }
    let actor = &values[0]["reference"];
    let record = &values[1];
    let (Some(wire), Some(actor_manifest), Some(owner), Some(message)) = (
        actor["object_id"].as_str(),
        actor["manifest_hash"].as_str(),
        record["owner"].as_str(),
        record["message_id"].as_str(),
    ) else {
        return Ok(None);
    };
    if wire.is_empty()
        || owner.is_empty()
        || actor_manifest.is_empty()
        || actor_manifest.bytes().all(|b| b == 0)
        || actor_manifest != manifest
        || record["manifest_hash"].as_str().is_some_and(|m| m != manifest)
        || super::graph::target_deleted(db, message)?
    {
        return Ok(None);
    }
    let commitment = object_erasure_commitment(root, wire, manifest);
    let witnessed: bool = db.query_row("SELECT EXISTS(SELECT 1 FROM main.message_footprint f JOIN main.message_copy_binding b ON b.message_id=f.message_id AND b.copy_id='object:'||?1 WHERE f.message_id=?2 AND f.kind='revocation_selector' AND json_extract(f.locator,'$.selector')=?1 AND json_extract(f.locator,'$.wire')=?3 AND json_extract(f.locator,'$.manifest')=?4 AND json_extract(f.locator,'$.commitment')=?5) AND NOT EXISTS(SELECT 1 FROM object_erasure_fence WHERE commitment=?5) AND NOT EXISTS(SELECT 1 FROM object_erasure_lookup WHERE lookup=?6)", params![selector,message,wire,manifest,commitment,object_erasure_lookup(root,selector)], |r| r.get(0))?;
    Ok(witnessed.then(|| (wire.to_owned(), manifest.to_owned(), commitment)))
}

fn omit_unresolved_placeholder(
    db: &Connection,
    schema: &str,
    side: &str,
    id: i64,
    selector: &str,
) -> Result<(), StorageError> {
    // Restrictions belong to both inputs; ordinary copy provenance is not a veto.
    let registered: bool = db.query_row(&format!("SELECT EXISTS(SELECT 1 FROM {schema}.message_footprint f WHERE f.kind='revocation_selector' AND CAST(json_extract(f.locator,'$.selector') AS TEXT)=?1)"), [selector], |r|r.get(0))?;
    if registered {
        return Err(StorageError::ObjectOwnershipUnverified { schema_version: 13 });
    }
    // Bare unresolved placeholders have no restriction to preserve.
    db.execute(
        "INSERT OR IGNORE INTO backup_erased_copy VALUES(?1,'object_index',?2)",
        params![schema, id],
    )?;
    db.execute(
        "INSERT OR REPLACE INTO backup_selector_admission VALUES(?1,?2,'','unowned_legacy')",
        params![side, selector],
    )?;
    Ok(())
}

// A fresh-normalized target retains its registered restriction but no unowned actor.
// Every identity and owner read here belongs to the target; unioned fences only veto.
fn registered_target_identity(
    db: &Connection,
    root: &str,
    selector: &str,
    manifest: &str,
) -> Result<Option<(String, String, String)>, StorageError> {
    let mut query = db.prepare("SELECT DISTINCT json_extract(f.locator,'$.wire'),json_extract(f.locator,'$.manifest'),json_extract(f.locator,'$.commitment'),b.message_id FROM main.message_footprint f JOIN main.message_copy_binding b ON b.message_id=f.message_id AND b.copy_id='object:'||?1 WHERE f.kind='revocation_selector' AND CAST(json_extract(f.locator,'$.selector') AS TEXT)=?1")?;
    let mut identity = None;
    for row in query.query_map([selector], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, String>(2)?,
            r.get::<_, String>(3)?,
        ))
    })? {
        let (wire, known_manifest, commitment, message) = row?;
        if wire.is_empty()
            || known_manifest.is_empty()
            || commitment != object_erasure_commitment(root, &wire, &known_manifest)
            || (manifest.as_bytes() != [0_u8; 32] && manifest != known_manifest)
        {
            return Err(StorageError::ObjectOwnershipUnverified { schema_version: 13 });
        }
        if super::graph::target_deleted(db, &message)? {
            continue;
        }
        let vetoed: bool = db.query_row("SELECT EXISTS(SELECT 1 FROM object_erasure_fence WHERE commitment=?1) OR EXISTS(SELECT 1 FROM object_erasure_lookup WHERE lookup=?2)", params![commitment,object_erasure_lookup(root,selector)], |r|r.get(0))?;
        if vetoed {
            continue;
        }
        let candidate = (wire, known_manifest, commitment);
        if identity.as_ref().is_some_and(|old| old != &candidate) {
            return Err(StorageError::ObjectOwnershipUnverified { schema_version: 13 });
        }
        identity = Some(candidate);
    }
    Ok(identity)
}
