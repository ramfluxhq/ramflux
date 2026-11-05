// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Private restore origin survives schema-only upgrades and interrupted opens.
use super::{BackupInputObservation, StorageError};
use rusqlite::Connection;

pub(super) fn retain(db: &Connection, version: i64) -> Result<(), StorageError> {
    db.execute_batch("CREATE TABLE IF NOT EXISTS main.backup_input_origin(singleton INTEGER PRIMARY KEY CHECK(singleton=1),schema_version INTEGER NOT NULL);")?;
    db.execute("INSERT INTO main.backup_input_origin VALUES(1,?1) ON CONFLICT(singleton) DO UPDATE SET schema_version=excluded.schema_version", [version])?;
    Ok(())
}

pub(super) fn capture(
    db: &Connection,
    preserve: bool,
) -> Result<BackupInputObservation, StorageError> {
    let physical: i64 =
        db.query_row("SELECT MAX(schema_version) FROM schema_migration", [], |r| r.get(0))?;
    let exists: bool = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name='backup_input_origin')",
        [],
        |r| r.get(0),
    )?;
    let schema_version = if exists {
        db.query_row("SELECT schema_version FROM backup_input_origin WHERE singleton=1", [], |r| {
            r.get(0)
        })?
    } else {
        physical
    };
    if schema_version > physical || schema_version < 1 {
        return Err(StorageError::AuthorizationRejected);
    }
    let counts = super::super::backup::read_counts(db)?;
    let tables: u64 = db.query_row("SELECT count(*) FROM sqlite_master WHERE type='table' AND name IN ('object_retention_reference','object_message_reference')", [], |r|r.get(0))?;
    let sql = if tables == 2 {
        "SELECT count(*) FROM runtime_actor_state a WHERE a.state_kind GLOB 'attachment/reference/*' AND NOT EXISTS(SELECT 1 FROM object_retention_reference r JOIN object_message_reference m USING(reference_hash) WHERE r.selector=substr(a.state_kind,22))"
    } else {
        "SELECT count(*) FROM runtime_actor_state WHERE state_kind GLOB 'attachment/reference/*'"
    };
    let unowned_legacy_actor_count = db.query_row(sql, [], |r| r.get(0))?;
    if preserve {
        retain(db, schema_version)?;
    }
    Ok(BackupInputObservation { counts, unowned_legacy_actor_count, schema_version })
}
