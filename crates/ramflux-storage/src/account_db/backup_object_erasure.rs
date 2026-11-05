// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Merge portable fences before any incoming object, private reference or archive copy.
use super::backup_database::BackupDatabase;
use crate::StorageError;
use ramflux_crypto::{object_erasure_commitment, object_erasure_lookup};
use rusqlite::{Connection, OptionalExtension, params};

impl BackupDatabase {
    pub(super) fn merge_object_erasure(
        &self,
        progress: &mut impl FnMut() -> Result<(), StorageError>,
    ) -> Result<(), StorageError> {
        let root: String = self.db.query_row(
            "SELECT principal_commitment FROM runtime_account_identity WHERE singleton=1",
            [],
            |r| r.get(0),
        )?;
        let source_root: String = self.db.query_row(
            "SELECT principal_commitment FROM incoming.runtime_account_identity WHERE singleton=1",
            [],
            |r| r.get(0),
        )?;
        if root != source_root {
            return Err(StorageError::AuthorizationRejected);
        }
        self.db.execute_batch("CREATE TEMP TABLE IF NOT EXISTS backup_erased_copy(database_name TEXT NOT NULL,table_name TEXT NOT NULL,row_id INTEGER NOT NULL,PRIMARY KEY(database_name,table_name,row_id)); DELETE FROM backup_erased_copy;")?;
        let input_version: i64 = self.db.query_row(
            "SELECT COALESCE(MAX(schema_version),0) FROM incoming.schema_migration",
            [],
            |r| r.get(0),
        )?;
        if input_version > super::mac_subkeys::VERSION {
            return Err(StorageError::AccountSchemaTooNew {
                schema_version: input_version,
                supported: super::mac_subkeys::VERSION,
            });
        }
        let modern = exists(&self.db, "incoming", "object_erasure_fence")?;
        if modern {
            let version: i64 = self.db.query_row(
                "SELECT MAX(schema_version) FROM incoming.schema_migration",
                [],
                |r| r.get(0),
            )?;
            if version > super::mac_subkeys::VERSION {
                return Err(StorageError::AccountSchemaTooNew {
                    schema_version: version,
                    supported: super::mac_subkeys::VERSION,
                });
            }
            let checksum: Option<String> = self
                .db
                .query_row(
                    "SELECT checksum FROM incoming.schema_migration WHERE schema_version=?1",
                    [version.min(13)],
                    |r| r.get(0),
                )
                .optional()?;
            if checksum.as_deref()
                != Some(if version == 12 {
                    crate::schema_object_erasure::V12_CHECKSUM
                } else {
                    crate::schema_object_erasure::CHECKSUM
                })
            {
                return Err(StorageError::ObjectOwnershipUnverified { schema_version: version });
            }
            self.db.execute_batch("INSERT INTO object_erasure_fence SELECT commitment FROM incoming.object_erasure_fence WHERE 1 ON CONFLICT DO NOTHING; INSERT INTO object_erasure_lookup SELECT lookup,commitment FROM incoming.object_erasure_lookup WHERE 1 ON CONFLICT DO NOTHING;")?;
            let unsafe_references:bool=self.db.query_row("SELECT EXISTS(SELECT 1 FROM incoming.runtime_actor_state a WHERE a.state_kind GLOB 'attachment/reference/*' AND NOT EXISTS(SELECT 1 FROM incoming.object_retention_reference r JOIN incoming.object_message_reference m USING(reference_hash) WHERE r.selector=substr(a.state_kind,22)))",[],|r|r.get(0))?;
            if unsafe_references {
                return Err(StorageError::ObjectOwnershipUnverified { schema_version: version });
            }
            validate_payload_identities(&self.db, &root)?;
            let invalid:bool=self.db.query_row("SELECT EXISTS(SELECT 1 FROM incoming.object_payload_dependency d JOIN incoming.object_retention_payload p ON p.commitment=d.parent_commitment WHERE p.retention_class<>'transport')",[],|r|r.get(0))?;
            if invalid {
                return Err(StorageError::AuthorizationRejected);
            }
            self.db.execute_batch("INSERT INTO object_erasure_fence WITH RECURSIVE retired(commitment) AS (SELECT commitment FROM object_erasure_fence UNION SELECT d.parent_commitment FROM (SELECT * FROM main.object_payload_dependency UNION SELECT * FROM incoming.object_payload_dependency) d JOIN retired r ON r.commitment=d.child_commitment) SELECT r.commitment FROM retired r WHERE EXISTS(SELECT 1 FROM main.object_retention_payload p WHERE p.commitment=r.commitment AND p.retention_class='transport') OR EXISTS(SELECT 1 FROM incoming.object_retention_payload p WHERE p.commitment=r.commitment AND p.retention_class='transport') ON CONFLICT DO NOTHING; INSERT INTO object_erasure_lookup SELECT wire_lookup,commitment FROM incoming.object_retention_payload WHERE commitment IN (SELECT commitment FROM object_erasure_fence) ON CONFLICT DO NOTHING;")?;
        } else {
            let references:bool=self.db.query_row("SELECT EXISTS(SELECT 1 FROM incoming.runtime_actor_state WHERE state_kind GLOB 'attachment/reference/*')",[],|r|r.get(0))?;
            if references {
                return Err(StorageError::ObjectOwnershipUnverified { schema_version: 11 });
            }
        }
        for database in ["main", "incoming"] {
            scan_objects(&self.db, database, &root, progress)?;
            for (table, key, column) in [
                ("runtime_actor_state", "state_kind", "state_json"),
                ("backup_archived_actor_state", "state_kind", "state_json"),
                ("local_event_log", "event_id", "event_body"),
                ("backup_archived_local_event", "event_id", "event_body"),
            ] {
                if exists(&self.db, database, table)? {
                    scan_copies(
                        &self.db,
                        database,
                        ObjectCopyStore { table, key, column },
                        &root,
                        progress,
                    )?;
                }
            }
            if exists(&self.db, database, "backup_missing_attachment")? {
                let mut query = self.db.prepare(&format!(
                    "SELECT rowid,selector,manifest_hash FROM {database}.backup_missing_attachment"
                ))?;
                for row in query.query_map([], |r| {
                    Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?))
                })? {
                    let (id, selector, manifest) = row?;
                    if erased(&self.db, &root, &selector, Some(&manifest), database)? {
                        exclude(&self.db, database, "backup_missing_attachment", id)?;
                    }
                }
            }
        }
        for table in [
            "object_manifest",
            "object_key_slot",
            "object_chunk",
            "object_transfer_state",
            "object_operation",
            "object_share_grant_projection",
            "object_tombstone",
        ] {
            if exists(&self.db, "incoming", table)? {
                let column = if table == "object_tombstone" { "target_id" } else { "object_id" };
                self.db.execute(&format!("INSERT INTO backup_erased_copy SELECT 'incoming',?1,r.rowid FROM incoming.{table} r WHERE r.{column} IN (SELECT o.object_id FROM incoming.object_index o JOIN backup_erased_copy e ON e.database_name='incoming' AND e.table_name='object_index' AND e.row_id=o.rowid) ON CONFLICT DO NOTHING"),[table])?;
            }
        }
        for table in ["object_operation", "object_transfer_state", "object_manifest"] {
            if exists(&self.db, "incoming", table)? {
                let mut query = self.db.prepare(&format!(
                    "SELECT rowid,object_id,CAST(manifest_hash AS TEXT) FROM incoming.{table}"
                ))?;
                for row in query.query_map([], |r| {
                    Ok((
                        r.get::<_, i64>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, Option<String>>(2)?,
                    ))
                })? {
                    let (id, wire, manifest) = row?;
                    if erased(&self.db, &root, &wire, manifest.as_deref(), "incoming")? {
                        exclude(&self.db, "incoming", table, id)?;
                    }
                }
            }
        }
        self.db.execute_batch("DELETE FROM object_erasure_work;")?;
        let mut rows=self.db.prepare("SELECT o.object_id,CAST(o.manifest_hash AS TEXT) FROM object_index o JOIN backup_erased_copy e ON e.database_name='main' AND e.table_name='object_index' AND e.row_id=o.rowid")?;
        for row in rows.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))? {
            let (wire, manifest) = row?;
            let digest = object_erasure_commitment(&root, &wire, &manifest);
            self.db.execute("INSERT INTO object_retention_payload(commitment,wire_id,manifest_hash,wire_lookup,retention_class) VALUES(?1,?2,?3,?4,'legacy') ON CONFLICT DO NOTHING",params![digest,wire,manifest,object_erasure_lookup(&root,&wire)])?;
            self.db.execute(
                "INSERT INTO object_erasure_work VALUES(?1,?2,?3) ON CONFLICT DO NOTHING",
                params![digest, wire, manifest],
            )?;
        }
        self.db.execute_batch("DELETE FROM object_message_reference WHERE reference_hash IN (SELECT reference_hash FROM object_retention_reference WHERE commitment IN (SELECT commitment FROM object_erasure_fence)); DELETE FROM object_retention_reference WHERE commitment IN (SELECT commitment FROM object_erasure_fence);")?;
        self.db.execute_batch(&super::object_retention::payload_erasure_body(&self.db)?)?;
        for table in [
            "runtime_actor_state",
            "backup_archived_actor_state",
            "local_event_log",
            "backup_archived_local_event",
            "backup_missing_attachment",
        ] {
            if exists(&self.db, "main", table)? {
                self.db.execute(&format!("DELETE FROM {table} WHERE rowid IN (SELECT row_id FROM backup_erased_copy WHERE database_name='main' AND table_name=?1)"),[table])?;
            }
        }
        if modern {
            merge_graph(&self.db)?;
        }
        Ok(())
    }
}

fn exists(db: &Connection, database: &str, table: &str) -> rusqlite::Result<bool> {
    db.query_row(
        &format!(
            "SELECT EXISTS(SELECT 1 FROM {database}.sqlite_master WHERE type='table' AND name=?1)"
        ),
        [table],
        |r| r.get(0),
    )
}
fn exclude(db: &Connection, database: &str, table: &str, id: i64) -> rusqlite::Result<()> {
    db.execute(
        "INSERT INTO backup_erased_copy VALUES(?1,?2,?3) ON CONFLICT DO NOTHING",
        params![database, table, id],
    )?;
    Ok(())
}
fn fenced(db: &Connection, digest: &str) -> rusqlite::Result<bool> {
    db.query_row(
        "SELECT EXISTS(SELECT 1 FROM object_erasure_fence WHERE commitment=?1)",
        [digest],
        |r| r.get(0),
    )
}
fn erased(
    db: &Connection,
    root: &str,
    selector: &str,
    manifest: Option<&str>,
    database: &str,
) -> Result<bool, StorageError> {
    if let Some(manifest) = manifest
        && fenced(db, &object_erasure_commitment(root, selector, manifest))?
    {
        return Ok(true);
    }
    let payload: Option<(String, String)> = if exists(db, database, "object_retention_reference")? {
        db.query_row(&format!("SELECT p.wire_id,p.manifest_hash FROM {database}.object_retention_reference r JOIN {database}.object_retention_payload p USING(commitment) WHERE r.selector=?1 AND (?2 IS NULL OR p.manifest_hash=?2) ORDER BY r.reference_hash LIMIT 1"),params![selector,manifest],|r|Ok((r.get(0)?,r.get(1)?))).optional()?
    } else {
        None
    };
    if let Some((wire, manifest)) = payload {
        return Ok(fenced(db, &object_erasure_commitment(root, &wire, &manifest))?);
    }
    let current: Option<String> = db
        .query_row(
            &format!(
                "SELECT CAST(manifest_hash AS TEXT) FROM {database}.object_index WHERE object_id=?1"
            ),
            [selector],
            |r| r.get(0),
        )
        .optional()?;
    if let Some(current) = current {
        return Ok(fenced(db, &object_erasure_commitment(root, selector, &current))?);
    }
    let lookup = object_erasure_lookup(root, selector);
    Ok(db.query_row(
        "SELECT EXISTS(SELECT 1 FROM object_erasure_lookup WHERE lookup=?1)",
        [lookup],
        |r| r.get(0),
    )?)
}
fn scan_objects(
    db: &Connection,
    database: &str,
    root: &str,
    progress: &mut impl FnMut() -> Result<(), StorageError>,
) -> Result<(), StorageError> {
    let mut query = db.prepare(&format!(
        "SELECT rowid,object_id,CAST(manifest_hash AS TEXT) FROM {database}.object_index"
    ))?;
    for row in query.query_map([], |r| {
        Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?))
    })? {
        progress()?;
        let (id, wire, manifest) = row?;
        let digest = object_erasure_commitment(root, &wire, &manifest);
        if fenced(db, &digest)? {
            exclude(db, database, "object_index", id)?;
        } else if database == "incoming" {
            let lookup = object_erasure_lookup(root, &wire);
            let reused: bool = db.query_row(
                "SELECT EXISTS(SELECT 1 FROM object_erasure_lookup WHERE lookup=?1)",
                [lookup],
                |r| r.get(0),
            )?;
            let explicit=exists(db,"incoming","object_identity_replacement")? && db.query_row("SELECT EXISTS(SELECT 1 FROM incoming.object_identity_replacement WHERE commitment=?1)",[digest],|r|r.get::<_,bool>(0))?;
            if reused && !explicit {
                return Err(StorageError::ObjectIdentityConflict);
            }
        }
    }
    Ok(())
}
#[derive(Clone, Copy)]
struct ObjectCopyStore<'a> {
    table: &'a str,
    key: &'a str,
    column: &'a str,
}
fn scan_copies(
    db: &Connection,
    database: &str,
    store: ObjectCopyStore<'_>,
    root: &str,
    progress: &mut impl FnMut() -> Result<(), StorageError>,
) -> Result<(), StorageError> {
    let ObjectCopyStore { table, key, column } = store;
    let mut query=db.prepare(&format!("SELECT rowid,{key},CASE WHEN length({column})<=1048576 THEN {column} END FROM {database}.{table}"))?;
    for row in query.query_map([], |r| {
        Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?, r.get::<_, Option<Vec<u8>>>(2)?))
    })? {
        progress()?;
        let (id, key, bytes) = row?;
        let bytes = bytes.map(zeroize::Zeroizing::new);
        let mut drop_copy = false;
        if let Some(chunk) = key.strip_prefix("attachment/chunk/")
            && let Some((wire_manifest, _)) = chunk.rsplit_once('/')
            && let Some((wire, manifest)) = wire_manifest.rsplit_once('/')
        {
            drop_copy = fenced(db, &object_erasure_commitment(root, wire, manifest))?;
        }
        if table.ends_with("actor_state") && exists(db, database, "object_transport_actor")? {
            let retired:bool=db.query_row(&format!("SELECT EXISTS(SELECT 1 FROM {database}.object_transport_actor a JOIN object_erasure_fence f USING(commitment) WHERE a.state_kind=?1)"),[&key],|r|r.get(0))?;
            drop_copy |= retired;
        }
        if table.ends_with("actor_state") && exists(db, database, "object_reference_actor")? {
            let bound:bool=db.query_row(&format!("SELECT EXISTS(SELECT 1 FROM {database}.object_reference_actor WHERE state_kind=?1)"),[&key],|r|r.get(0))?;
            let live:bool=db.query_row(&format!("SELECT EXISTS(SELECT 1 FROM {database}.object_reference_actor a JOIN {database}.object_retention_reference r USING(reference_hash) WHERE a.state_kind=?1 AND NOT EXISTS(SELECT 1 FROM object_erasure_fence f WHERE f.commitment=r.commitment))"),[&key],|r|r.get(0))?;
            drop_copy |= bound && !live;
        }
        if let Some(bytes) = bytes {
            if let Ok(references) = super::backup_object_metadata::references(&bytes) {
                for (wire, manifest) in references {
                    drop_copy |= erased(db, root, &wire, manifest.as_deref(), database)?;
                }
            }
            if let Some(selector) = key
                .strip_prefix("directory/object/")
                .or_else(|| key.strip_prefix("sync/attachment/"))
            {
                drop_copy |= erased(db, root, selector, None, database)?;
            }
            if key.starts_with("attachment/reference-by-")
                && let Ok(selector) = serde_json::from_slice::<String>(&bytes)
            {
                drop_copy |= erased(db, root, &selector, None, database)?;
            }
        }
        if drop_copy {
            exclude(db, database, table, id)?;
        }
    }
    Ok(())
}
fn validate_payload_identities(db: &Connection, root: &str) -> Result<(), StorageError> {
    let mut query = db.prepare(
        "SELECT commitment,wire_id,manifest_hash FROM incoming.object_retention_payload",
    )?;
    for row in query.query_map([], |r| {
        Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?))
    })? {
        let (digest, wire, manifest) = row?;
        if digest != object_erasure_commitment(root, &wire, &manifest) {
            return Err(StorageError::AuthorizationRejected);
        }
    }
    Ok(())
}
fn merge_graph(db: &Connection) -> Result<(), StorageError> {
    db.execute_batch("INSERT INTO object_retention_payload(commitment,wire_id,manifest_hash,wire_lookup,retention_class,hold_expires_at) SELECT commitment,wire_id,manifest_hash,wire_lookup,retention_class,hold_expires_at FROM incoming.object_retention_payload p WHERE NOT EXISTS(SELECT 1 FROM object_erasure_fence f WHERE f.commitment=p.commitment) ON CONFLICT(commitment) DO NOTHING;
      INSERT INTO object_retention_reference SELECT * FROM incoming.object_retention_reference r WHERE NOT EXISTS(SELECT 1 FROM object_erasure_fence f WHERE f.commitment=r.commitment) ON CONFLICT DO NOTHING;
      INSERT INTO object_message_reference SELECT * FROM incoming.object_message_reference m WHERE EXISTS(SELECT 1 FROM object_retention_reference r WHERE r.reference_hash=m.reference_hash) AND NOT EXISTS(SELECT 1 FROM direct_message_projection p WHERE p.message_id=m.message_id AND p.deleted=1) AND NOT EXISTS(SELECT 1 FROM incoming.direct_message_projection p WHERE p.message_id=m.message_id AND p.deleted=1) ON CONFLICT DO NOTHING;
      INSERT INTO object_payload_actor SELECT * FROM incoming.object_payload_actor a WHERE NOT EXISTS(SELECT 1 FROM object_erasure_fence f WHERE f.commitment=a.commitment) ON CONFLICT DO NOTHING;
      INSERT INTO object_reference_actor SELECT * FROM incoming.object_reference_actor a WHERE EXISTS(SELECT 1 FROM object_retention_reference r WHERE r.reference_hash=a.reference_hash) ON CONFLICT DO NOTHING;
      INSERT INTO object_payload_dependency SELECT * FROM incoming.object_payload_dependency d WHERE NOT EXISTS(SELECT 1 FROM object_erasure_fence f WHERE f.commitment IN (d.parent_commitment,d.child_commitment)) ON CONFLICT DO NOTHING;
      INSERT INTO object_transport_actor SELECT * FROM incoming.object_transport_actor a WHERE NOT EXISTS(SELECT 1 FROM object_erasure_fence f WHERE f.commitment=a.commitment) ON CONFLICT DO NOTHING;
      INSERT INTO object_identity_replacement SELECT * FROM incoming.object_identity_replacement WHERE 1 ON CONFLICT DO NOTHING;")?;
    Ok(())
}
