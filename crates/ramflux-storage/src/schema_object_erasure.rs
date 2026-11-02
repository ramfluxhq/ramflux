// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! The version-one checksum sentinel also stops writers that ignore future migration rows.
use crate::StorageError;
use rusqlite::{Connection, OptionalExtension, params};

pub(crate) const VERSION: i64 = 12;
pub(crate) const CHECKSUM: &str = "2026-11-02-object-ownership-erasure-v1";
pub(crate) const SENTINEL: &str = "2026-06-14-account-core-v1;writer-floor=12;object-erasure-v1";

pub(crate) fn validate(db: &Connection) -> Result<(), StorageError> {
    let newest: i64 =
        db.query_row("SELECT COALESCE(MAX(schema_version),0) FROM schema_migration", [], |row| {
            row.get(0)
        })?;
    if newest > VERSION {
        return Err(StorageError::AccountSchemaTooNew {
            schema_version: newest,
            supported: VERSION,
        });
    }
    let first: Option<String> = db
        .query_row("SELECT checksum FROM schema_migration WHERE schema_version=1", [], |row| {
            row.get(0)
        })
        .optional()?;
    if newest == VERSION && first.as_deref() != Some(SENTINEL) {
        return Err(StorageError::MigrationChecksumMismatch {
            schema_version: 1,
            expected: SENTINEL.into(),
            actual: first.clone().unwrap_or_default(),
        });
    }
    if newest == VERSION {
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
    if first.as_deref() == Some(SENTINEL) {
        let actual: Option<String> = db
            .query_row(
                "SELECT checksum FROM schema_migration WHERE schema_version=?1",
                [VERSION],
                |row| row.get(0),
            )
            .optional()?;
        if actual.as_deref() != Some(CHECKSUM) {
            return Err(StorageError::MigrationChecksumMismatch {
                schema_version: VERSION,
                expected: CHECKSUM.into(),
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
    if first != "2026-06-14-account-core-v1" && first != SENTINEL {
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
pub(crate) fn upgrade_private(db: &Connection) -> Result<(), StorageError> {
    validate(db)?;
    let current: bool = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM schema_migration WHERE schema_version=?1 AND checksum=?2)",
        params![VERSION, CHECKSUM],
        |r| r.get(0),
    )?;
    if current {
        return Ok(());
    }
    let transaction = db.unchecked_transaction()?;
    db.execute_batch(crate::account_db::object_retention::SCHEMA)?;
    install_sentinel(db)?;
    db.execute("INSERT INTO schema_migration VALUES(?1,?2,'v1-object-erasure',?3,'portable attachment erasure writer floor')",params![VERSION,crate::unix_now(),CHECKSUM])?;
    transaction.commit()?;
    Ok(())
}
