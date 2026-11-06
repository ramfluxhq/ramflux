// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! The version-one checksum sentinel also stops writers that ignore future migration rows.
use crate::StorageError;
use rusqlite::{Connection, OptionalExtension, params};

pub(crate) const VERSION: i64 = 13;
pub(crate) const CHECKSUM: &str = "2026-11-05-selector-lifecycle-v13";
pub(crate) const SENTINEL: &str = "2026-06-14-account-core-v1;writer-floor=13;object-erasure-v1";

pub(crate) const V12_CHECKSUM: &str = "2026-11-02-object-ownership-erasure-v1";
pub(crate) const V12_SENTINEL: &str =
    "2026-06-14-account-core-v1;writer-floor=12;object-erasure-v1";

pub(crate) fn validate(db: &Connection) -> Result<(), StorageError> {
    let newest: i64 =
        db.query_row("SELECT COALESCE(MAX(schema_version),0) FROM schema_migration", [], |row| {
            row.get(0)
        })?;
    if newest > crate::account_db::receive::schema_version() {
        return Err(StorageError::AccountSchemaTooNew {
            schema_version: newest,
            supported: crate::account_db::receive::schema_version(),
        });
    }
    crate::account_db::receive::schema::validate(db, newest)?;
    let first: Option<String> = db
        .query_row("SELECT checksum FROM schema_migration WHERE schema_version=1", [], |row| {
            row.get(0)
        })
        .optional()?;
    let expected_sentinel = if newest == 12 { V12_SENTINEL } else { SENTINEL };
    if newest >= 12 && first.as_deref() != Some(expected_sentinel) {
        return Err(StorageError::MigrationChecksumMismatch {
            schema_version: 1,
            expected: expected_sentinel.into(),
            actual: first.clone().unwrap_or_default(),
        });
    }
    if newest >= 12 {
        for table in [
            "account_erasure_generation",
            "object_erasure_fence",
            "object_erasure_lookup",
            "object_retention_payload",
            "object_retention_reference",
            "object_message_reference",
            "object_payload_actor",
            "object_reference_actor",
            "object_runtime_response",
            "object_payload_dependency",
            "object_transport_actor",
            "object_identity_replacement",
            "object_retention_upgrade",
        ] {
            let present: bool = db.query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1)",
                [table],
                |r| r.get(0),
            )?;
            if !present {
                return Err(StorageError::ObjectOwnershipUnverified { schema_version: VERSION });
            }
        }
    }
    for (version, checksum) in [(12, V12_CHECKSUM), (VERSION, CHECKSUM)] {
        let sentinel_requires_version = match first.as_deref() {
            Some(SENTINEL) => true,
            Some(V12_SENTINEL) => version == 12,
            _ => false,
        };
        if newest < version && !sentinel_requires_version {
            continue;
        }
        let actual: Option<String> = db
            .query_row(
                "SELECT checksum FROM schema_migration WHERE schema_version=?1",
                [version],
                |row| row.get(0),
            )
            .optional()?;
        if actual.as_deref() != Some(checksum) {
            return Err(StorageError::MigrationChecksumMismatch {
                schema_version: version,
                expected: checksum.into(),
                actual: actual.unwrap_or_default(),
            });
        }
    }
    Ok(())
}

pub(crate) fn install_sentinel(db: &Connection) -> Result<(), StorageError> {
    let first: String =
        db.query_row("SELECT checksum FROM schema_migration WHERE schema_version=1", [], |row| {
            row.get(0)
        })?;
    if first != "2026-06-14-account-core-v1" && first != V12_SENTINEL && first != SENTINEL {
        return Err(StorageError::MigrationChecksumMismatch {
            schema_version: 1,
            expected: "2026-06-14-account-core-v1".into(),
            actual: first,
        });
    }
    db.execute("UPDATE schema_migration SET checksum=?1 WHERE schema_version=1", [SENTINEL])?;
    Ok(())
}

/// Private archives use the same floor before any payload/actor import.
pub(crate) fn upgrade_private(db: &crate::database::Connection) -> Result<(), StorageError> {
    db.call(|raw| Ok(validate(raw)))??;
    let current: bool = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM schema_migration WHERE schema_version=?1 AND checksum=?2)",
        params![VERSION, CHECKSUM],
        |r| r.get(0),
    )?;
    if current {
        return Ok(());
    }
    let transaction = db.immediate_transaction()?;
    let has_v12: bool = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM schema_migration WHERE schema_version=12)",
        [],
        |r| r.get(0),
    )?;
    db.execute_batch(crate::account_db::object_retention::SCHEMA)?;
    if !has_v12 {
        db.execute("INSERT INTO schema_migration VALUES(12,?1,'v1-object-erasure',?2,'portable attachment erasure writer floor')", params![crate::unix_now(), V12_CHECKSUM])?;
    }
    rebuild_triggers(db)?;
    db.call(|raw| Ok(install_sentinel(raw)))??;
    db.execute("INSERT INTO schema_migration VALUES(?1,?2,'v1-object-erasure',?3,'portable attachment erasure writer floor')",params![VERSION,crate::unix_now(),CHECKSUM])?;
    transaction.commit()?;
    Ok(())
}

/// Install the generated erasure bodies before publishing the new writer floor.
pub(crate) fn rebuild_triggers(db: &crate::database::Connection) -> Result<(), StorageError> {
    let runtime_exists: bool = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='runtime_outbox')",
        [],
        |r| r.get(0),
    )?;
    // Fresh databases install runtime and its triggers before the first account operation.
    if !runtime_exists {
        return Ok(());
    }
    db.call(|raw| {
        crate::account_db::object_retention::install(raw)?;
        crate::account_db::message_footprint::install(raw)
    })?;
    Ok(())
}
