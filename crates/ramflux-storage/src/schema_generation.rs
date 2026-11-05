// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Read-only generation admission before any application schema or migration access.

use crate::{StorageError, database::Connection};
use ramflux_protocol::schema_profile::ACTIVE_STORAGE_GENERATION;

pub(crate) fn validate(db: &rusqlite::Connection) -> Result<(), StorageError> {
    let generation = db.query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))?;
    require(generation)
}

pub(crate) fn require(generation: i64) -> Result<(), StorageError> {
    if generation != ACTIVE_STORAGE_GENERATION {
        return Err(StorageError::SchemaResetRequired {
            generation,
            supported: ACTIVE_STORAGE_GENERATION,
        });
    }
    Ok(())
}

pub(crate) fn validate_worker(db: &Connection) -> Result<(), StorageError> {
    db.call(|raw| Ok(validate(raw)))??;
    Ok(())
}

#[cfg(test)]
mod tests;
