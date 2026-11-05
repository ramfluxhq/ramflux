// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Resolve placeholder identity on unfiltered inputs before exclusion or wire arbitration.
use super::super::object_retention::selector_admission::{
    identity_query, resolve_admitted_identity,
};
use crate::StorageError;
use ramflux_crypto::{object_erasure_commitment, object_erasure_lookup};
use rusqlite::{Connection, OptionalExtension, params};

type Identity = (String, String, String);

enum TargetWitness {
    Resolved(Identity),
    Vetoed(Identity),
    Unresolved,
}

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
            let mut vetoed = false;
            if identities.is_empty() && side == "incoming" {
                identities = inherited_references(db, &selector)?;
                inherited = !identities.is_empty();
                if inherited
                    && registered(db, "incoming", &selector)?
                    && (identities.len() != 1
                        || !incoming_matches_target(db, &selector, &identities[0], true)?)
                {
                    return Err(refuse());
                }
            }
            if identities.is_empty() {
                let witness = legacy_target_identity(db, root, &selector, &manifest)?;
                let applicable = side == "target"
                    || match &witness {
                        TargetWitness::Resolved(id) => {
                            incoming_matches_target(db, &selector, id, true)?
                        }
                        TargetWitness::Vetoed(id) => {
                            incoming_matches_target(db, &selector, id, false)?
                        }
                        TargetWitness::Unresolved => false,
                    };
                if applicable {
                    match witness {
                        TargetWitness::Resolved(id) => {
                            identities.push(id);
                            inherited = true;
                        }
                        TargetWitness::Vetoed(id) => {
                            identities.push(id);
                            vetoed = true;
                        }
                        TargetWitness::Unresolved => {}
                    }
                }
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
            if vetoed {
                db.execute(
                    "INSERT OR REPLACE INTO backup_selector_admission VALUES(?1,?2,?3,'erase')",
                    params![side, selector, commitment],
                )?;
            }
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
) -> Result<TargetWitness, StorageError> {
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
        return Ok(TargetWitness::Unresolved);
    };
    if wire.is_empty()
        || owner.is_empty()
        || actor_manifest.is_empty()
        || actor_manifest.bytes().all(|b| b == 0)
        || (manifest.as_bytes() != [0_u8; 32] && actor_manifest != manifest)
        || record["manifest_hash"].as_str().is_some_and(|m| m != actor_manifest)
    {
        return Ok(TargetWitness::Unresolved);
    }
    let commitment = object_erasure_commitment(root, wire, actor_manifest);
    let witnessed: bool = db.query_row("SELECT EXISTS(SELECT 1 FROM main.message_footprint f JOIN main.message_copy_binding b ON b.message_id=f.message_id AND b.copy_id='object:'||?1 WHERE f.message_id=?2 AND f.kind='revocation_selector' AND json_extract(f.locator,'$.selector')=?1 AND json_extract(f.locator,'$.wire')=?3 AND json_extract(f.locator,'$.manifest')=?4 AND json_extract(f.locator,'$.commitment')=?5)", params![selector,message,wire,actor_manifest,commitment], |r| r.get(0))?;
    if !witnessed {
        return Ok(TargetWitness::Unresolved);
    }
    registered_target_identity(db, root, selector, manifest)
}

fn omit_unresolved_placeholder(
    db: &Connection,
    schema: &str,
    side: &str,
    id: i64,
    selector: &str,
) -> Result<(), StorageError> {
    // Restrictions belong to both inputs; ordinary copy provenance is not a veto.
    if registered(db, schema, selector)? {
        return Err(refuse());
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
) -> Result<TargetWitness, StorageError> {
    let mut query = db.prepare("SELECT DISTINCT json_extract(f.locator,'$.wire'),json_extract(f.locator,'$.manifest'),json_extract(f.locator,'$.commitment'),b.message_id FROM main.message_footprint f JOIN main.message_copy_binding b ON b.message_id=f.message_id AND b.copy_id='object:'||?1 WHERE f.kind='revocation_selector' AND CAST(json_extract(f.locator,'$.selector') AS TEXT)=?1")?;
    let mut identity = None;
    let mut surviving_owner = false;
    for row in query.query_map([selector], |r| {
        Ok((optional_text(r, 0)?, optional_text(r, 1)?, optional_text(r, 2)?, optional_text(r, 3)?))
    })? {
        let (Some(wire), Some(known_manifest), Some(commitment), Some(message)) = row? else {
            return Err(refuse());
        };
        if wire.is_empty()
            || known_manifest.is_empty()
            || commitment != object_erasure_commitment(root, &wire, &known_manifest)
            || (manifest.as_bytes() != [0_u8; 32] && manifest != known_manifest)
        {
            return Err(StorageError::ObjectOwnershipUnverified { schema_version: 13 });
        }
        surviving_owner |= !owner_vetoed(db, root, selector, &commitment, &message)?;
        let candidate = (wire, known_manifest, commitment);
        if identity.as_ref().is_some_and(|old| old != &candidate) {
            return Err(StorageError::ObjectOwnershipUnverified { schema_version: 13 });
        }
        identity = Some(candidate);
    }
    Ok(match identity {
        Some(id) if surviving_owner => TargetWitness::Resolved(id),
        Some(id) => TargetWitness::Vetoed(id),
        None => TargetWitness::Unresolved,
    })
}

fn refuse() -> StorageError {
    StorageError::ObjectOwnershipUnverified { schema_version: 13 }
}

fn optional_text(row: &rusqlite::Row<'_>, column: usize) -> rusqlite::Result<Option<String>> {
    match row.get(column) {
        Err(rusqlite::Error::InvalidColumnType(..)) => Ok(None),
        value => value,
    }
}

fn registered(db: &Connection, schema: &str, selector: &str) -> rusqlite::Result<bool> {
    db.query_row(&format!("SELECT EXISTS(SELECT 1 FROM {schema}.message_footprint WHERE kind='revocation_selector' AND CAST(json_extract(locator,'$.selector') AS TEXT)=?1)"),[selector],|r|r.get(0))
}

fn owner_vetoed(
    db: &Connection,
    root: &str,
    selector: &str,
    commitment: &str,
    message: &str,
) -> Result<bool, StorageError> {
    // Target authority uses only its own owner links. Incoming deletion rows may add a veto.
    Ok(super::graph::target_deleted(db,message)? || super::graph::deleted(db,"incoming",message)? || db.query_row("SELECT EXISTS(SELECT 1 FROM object_erasure_fence WHERE commitment=?1) OR EXISTS(SELECT 1 FROM object_erasure_lookup WHERE lookup=?2)",params![commitment,object_erasure_lookup(root,selector)],|r|r.get::<_,bool>(0))?)
}

fn inherited_references(db: &Connection, selector: &str) -> Result<Vec<Identity>, StorageError> {
    Ok(db.prepare("SELECT DISTINCT p.wire_id,p.manifest_hash,r.commitment FROM main.object_retention_reference r JOIN main.object_retention_payload p USING(commitment) JOIN backup_reference_admission a ON a.side='target' AND a.reference_hash=r.reference_hash WHERE r.selector=?1 AND EXISTS(SELECT 1 FROM backup_selector_admission s WHERE s.side=a.side AND s.selector=r.selector AND s.commitment=r.commitment AND s.decision='keep')")?
        .query_map([selector],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?)))?.collect::<rusqlite::Result<Vec<_>>>()?)
}

fn incoming_matches_target(
    db: &Connection,
    selector: &str,
    id: &Identity,
    grant: bool,
) -> Result<bool, StorageError> {
    let mut query = db.prepare("SELECT json_extract(locator,'$.wire'),json_extract(locator,'$.manifest'),json_extract(locator,'$.commitment'),message_id FROM incoming.message_footprint WHERE kind='revocation_selector' AND CAST(json_extract(locator,'$.selector') AS TEXT)=?1")?;
    let mut any = false;
    for row in query.query_map([selector], |r| {
        Ok((optional_text(r, 0)?, optional_text(r, 1)?, optional_text(r, 2)?, optional_text(r, 3)?))
    })? {
        let (Some(wire), Some(manifest), Some(commitment), Some(owner)) = row? else {
            return Err(refuse());
        };
        if (&wire, &manifest, &commitment) != (&id.0, &id.1, &id.2) {
            return Ok(false);
        }
        let owns: bool = db.query_row("SELECT EXISTS(SELECT 1 FROM incoming.message_copy_binding WHERE copy_id='object:'||?1 AND message_id=?2) AND (EXISTS(SELECT 1 FROM main.message_footprint f JOIN main.message_copy_binding b ON b.message_id=f.message_id AND b.copy_id='object:'||?1 WHERE f.kind='revocation_selector' AND f.message_id=?2 AND json_extract(f.locator,'$.selector')=?1 AND json_extract(f.locator,'$.wire')=?3 AND json_extract(f.locator,'$.manifest')=?4 AND json_extract(f.locator,'$.commitment')=?5) OR EXISTS(SELECT 1 FROM backup_reference_admission WHERE side='target' AND message_id=?2 AND selector=?1 AND commitment=?5))",params![selector,owner,wire,manifest,commitment],|r|r.get(0))?;
        if !owns
            || (grant
                && (super::graph::target_deleted(db, &owner)?
                    || super::graph::deleted(db, "incoming", &owner)?))
        {
            return Ok(false);
        }
        any = true;
    }
    Ok(any)
}
