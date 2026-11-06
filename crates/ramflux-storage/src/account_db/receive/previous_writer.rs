// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Frozen c7bc48bd schema admission, with the historical MAC writer floor resolved to 14.
use crate::StorageError;
use rusqlite::{Connection, OptionalExtension};

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
    if newest > 14 {
        return Err(StorageError::AccountSchemaTooNew { schema_version: newest, supported: 14 });
    }
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
