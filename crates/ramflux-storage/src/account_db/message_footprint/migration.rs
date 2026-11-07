// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Completes registration of pre-fix replay and envelope copies before an account is usable.
//!
//! Candidates are `legacy/replay/*` rows or any row holding a complete envelope that has no
//! footprint at its locator. Work runs in rowid-ordered chunks, one transaction each, with a
//! persisted cursor per table, and ends with a completion marker.
use super::AccountDb;
use crate::StorageError;
use rusqlite::{Connection, params};

const MARKER: &str = "footprint_replay_migration:v1";
const CHUNK: usize = 1024;
const END: i64 = i64::MAX;

struct Store {
    table: &'static str,
    kind: &'static str,
    locator: &'static str,
}

const STORES: [Store; 2] = [
    Store { table: "runtime_actor_state", kind: "actor", locator: "t.state_kind" },
    Store {
        table: "backup_archived_actor_state",
        kind: "archived_actor",
        locator: "CAST(t.rowid AS TEXT)",
    },
];

fn cursor_name(store: &Store) -> String {
    format!("{MARKER}:{}", store.table)
}

fn checkpoint(db: &Connection, name: &str) -> rusqlite::Result<Option<String>> {
    use rusqlite::OptionalExtension;
    db.query_row(
        "SELECT value FROM message_footprint_migration WHERE name=?1",
        params![name],
        |row| row.get(0),
    )
    .optional()
}

fn write_checkpoint(db: &Connection, name: &str, value: &str) -> rusqlite::Result<()> {
    db.execute(
        "INSERT INTO message_footprint_migration(name,value) VALUES(?1,?2) \
         ON CONFLICT(name) DO UPDATE SET value=excluded.value",
        params![name, value],
    )?;
    Ok(())
}

/// True when the completing migration has finished for this database.
///
/// # Errors
/// Returns SQLite errors.
pub(crate) fn is_complete(db: &Connection) -> rusqlite::Result<bool> {
    Ok(checkpoint(db, MARKER)?.as_deref() == Some("complete"))
}

fn conversion(error: serde_json::Error) -> rusqlite::Error {
    rusqlite::Error::ToSqlConversionFailure(Box::new(error))
}

/// Pending candidate rows in rowid order; the rowid only pages the scan.
fn candidates(
    db: &Connection,
    store: &Store,
    after: i64,
    limit: usize,
) -> rusqlite::Result<Vec<(i64, String, Vec<u8>)>> {
    let envelope = super::schema::envelope_sql_for("t.state_json");
    let mut query = db.prepare(&format!(
        "SELECT t.rowid,t.state_kind,CAST(t.state_json AS BLOB) FROM {table} t \
         WHERE t.rowid>?1 AND (t.state_kind GLOB 'legacy/replay/*' OR COALESCE({envelope},0)) \
         AND NOT EXISTS(SELECT 1 FROM message_footprint f WHERE f.kind=?2 AND f.locator={locator}) \
         ORDER BY t.rowid LIMIT ?3",
        table = store.table,
        locator = store.locator
    ))?;
    let limit = i64::try_from(limit).unwrap_or(i64::MAX);
    let rows = query.query_map(params![after, store.kind, limit], |row| {
        Ok((row.get(0)?, row.get(1)?, row.get(2)?))
    })?;
    rows.collect()
}

/// Registers one candidate. Archived rows fire the renewed trigger with a self-update; live rows
/// stage the same registration the runtime writer would have made, then re-fire a deleted owner.
fn register_row(
    db: &Connection,
    store: &Store,
    rowid: i64,
    key: &str,
    body: &[u8],
) -> rusqlite::Result<()> {
    if store.kind == "archived_actor" {
        db.execute(
            "UPDATE backup_archived_actor_state SET state_json=state_json WHERE rowid=?1",
            params![rowid],
        )?;
        return Ok(());
    }
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(body) else { return Ok(()) };
    if !super::admits(key, &value) {
        return Ok(());
    }
    let registration = super::actor_registration(key, &value);
    db.execute(
        super::STAGE_ACTOR,
        params![
            key,
            serde_json::to_string(&registration.message_ids).map_err(conversion)?,
            serde_json::to_string(&registration.copy_ids).map_err(conversion)?,
            serde_json::to_string(&registration.bindings).map_err(conversion)?,
        ],
    )?;
    db.execute(super::FENCE_OUTBOX, params![key])?;
    db.execute(super::FENCE_PROJECTION, params![key])?;
    Ok(())
}

#[cfg(test)]
fn test_visit(db: &Connection, store: &Store, rowid: i64) -> rusqlite::Result<()> {
    if super::schema::exists(db, "footprint_migration_test_visits")? {
        db.execute(
            "INSERT INTO footprint_migration_test_visits VALUES(?1,?2)",
            params![store.table, rowid],
        )?;
    }
    Ok(())
}

#[cfg(test)]
fn test_stop(db: &Connection, chunks: i64) -> rusqlite::Result<()> {
    if super::schema::exists(db, "footprint_migration_test_stop")? {
        let limit: i64 =
            db.query_row("SELECT chunks FROM footprint_migration_test_stop", [], |r| r.get(0))?;
        if chunks >= limit {
            // One-shot: the next open resumes instead of stopping again.
            db.execute_batch("DROP TABLE footprint_migration_test_stop")?;
            return Err(rusqlite::Error::InvalidQuery);
        }
    }
    Ok(())
}

/// Runs the migration to completion; a no-op once the marker exists.
///
/// # Errors
/// Returns SQLite errors; the persisted cursors let the next call resume.
pub(crate) fn complete(db: &Connection) -> rusqlite::Result<()> {
    if is_complete(db)? {
        return Ok(());
    }
    let stores: Vec<&Store> = STORES
        .iter()
        .filter(|store| super::schema::exists(db, store.table).unwrap_or(false))
        .collect();
    #[cfg(test)]
    let mut chunks = 0_i64;
    for (index, store) in stores.iter().enumerate() {
        let last_store = index + 1 == stores.len();
        let name = cursor_name(store);
        loop {
            let transaction = db.unchecked_transaction()?;
            let cursor = checkpoint(db, &name)?.and_then(|v| v.parse::<i64>().ok()).unwrap_or(0);
            if cursor == END {
                transaction.commit()?;
                break;
            }
            let rows = candidates(db, store, cursor, CHUNK)?;
            for (rowid, key, body) in &rows {
                #[cfg(test)]
                test_visit(db, store, *rowid)?;
                register_row(db, store, *rowid, key, body)?;
            }
            let finished = rows.len() < CHUNK;
            let next = if finished { END } else { rows.last().map_or(END, |row| row.0) };
            write_checkpoint(db, &name, &next.to_string())?;
            if finished && last_store {
                write_checkpoint(db, MARKER, "complete")?;
            }
            transaction.commit()?;
            #[cfg(test)]
            {
                chunks += 1;
                test_stop(db, chunks)?;
            }
            if finished {
                break;
            }
        }
    }
    if !is_complete(db)? {
        write_checkpoint(db, MARKER, "complete")?;
    }
    Ok(())
}

/// Starts recording, by primary key, every `runtime_actor_state` row the merge inserts or
/// rewrites. Work is bounded by the merge's own writes, never by local history.
///
/// # Errors
/// Returns `FootprintMigrationIncomplete` without the marker, or SQLite errors.
pub(crate) fn begin_merge(db: &Connection) -> Result<(), StorageError> {
    if !is_complete(db)? {
        return Err(StorageError::FootprintMigrationIncomplete);
    }
    end_merge_tracking(db)?;
    db.execute_batch(
        "CREATE TEMP TABLE IF NOT EXISTS footprint_merge_imported(
            row_key TEXT NOT NULL UNIQUE);
         DELETE FROM temp.footprint_merge_imported;
         CREATE TEMP TRIGGER footprint_merge_track_insert AFTER INSERT ON main.runtime_actor_state
         BEGIN INSERT OR IGNORE INTO footprint_merge_imported VALUES(NEW.state_kind); END;
         CREATE TEMP TRIGGER footprint_merge_track_update
         AFTER UPDATE OF state_json ON main.runtime_actor_state
         BEGIN INSERT OR IGNORE INTO footprint_merge_imported VALUES(NEW.state_kind); END;",
    )?;
    Ok(())
}

fn end_merge_tracking(db: &Connection) -> rusqlite::Result<()> {
    db.execute_batch(
        "DROP TRIGGER IF EXISTS temp.footprint_merge_track_insert;
         DROP TRIGGER IF EXISTS temp.footprint_merge_track_update;",
    )
}

/// Registers every recorded row that still holds an unregistered candidate. Archived copies
/// are registered by the archive triggers (renewed before the first write) and by relocation.
/// Runs unbounded inside the merge transaction, after relocation and before tombstones.
///
/// # Errors
/// Returns SQLite errors.
pub(crate) fn register_imported(db: &Connection) -> rusqlite::Result<()> {
    let armed: bool = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_temp_master WHERE type='table' AND name='footprint_merge_imported')",
        [],
        |row| row.get(0),
    )?;
    if !armed {
        return Ok(());
    }
    end_merge_tracking(db)?;
    let store = &STORES[0];
    let envelope = super::schema::envelope_sql_for("t.state_json");
    let mut after = 0_i64;
    loop {
        let mut query = db.prepare(&format!(
            "SELECT m.rowid,t.state_kind,CAST(t.state_json AS BLOB) \
             FROM temp.footprint_merge_imported m JOIN main.runtime_actor_state t ON t.state_kind=m.row_key \
             WHERE m.rowid>?1 AND (t.state_kind GLOB 'legacy/replay/*' OR COALESCE({envelope},0)) \
             AND NOT EXISTS(SELECT 1 FROM message_footprint f WHERE f.kind='actor' AND f.locator=t.state_kind) \
             ORDER BY m.rowid LIMIT ?2"
        ))?;
        let limit = i64::try_from(CHUNK).unwrap_or(i64::MAX);
        let rows: Vec<(i64, String, Vec<u8>)> = query
            .query_map(params![after, limit], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?
            .collect::<rusqlite::Result<_>>()?;
        for (_, key, body) in &rows {
            register_row(db, store, 0, key, body)?;
        }
        match rows.last() {
            Some(last) if rows.len() == CHUNK => after = last.0,
            _ => break,
        }
    }
    Ok(())
}

impl AccountDb {
    pub(in crate::account_db) fn complete_footprint_migration(&self) -> Result<(), StorageError> {
        self.connection.call(|raw| complete(raw))?;
        Ok(())
    }

    /// Refuses deletion on a database whose footprint migration has not completed.
    pub(in crate::account_db) fn require_footprint_migration(&self) -> Result<(), StorageError> {
        let complete: bool = self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM message_footprint_migration WHERE name=?1 AND value='complete')",
            params![MARKER],
            |row| row.get(0),
        )?;
        if complete { Ok(()) } else { Err(StorageError::FootprintMigrationIncomplete) }
    }
}
