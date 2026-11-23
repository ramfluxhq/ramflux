// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Clean copy of a backup snapshot through the shared hardened open.
//! The attacker file is read only after `open_verified::harden`. Rows are inserted into a
//! database this binary migrated. The original path is replaced only after that copy commits.
use super::transfer_export::open_verified::{self, Budget};
use crate::{AccountDbKey, StorageError};
use rusqlite::Connection;
use rusqlite::config::DbConfig;
use rusqlite::hooks::AuthContext;
use rusqlite::limits::Limit;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
use std::time::Duration;
use zeroize::Zeroizing;

const BACKUP_SQLITE_CAP: u64 = 1 << 30;
const OPEN_DEADLINE: Duration = Duration::from_secs(60);
const COPY_DEADLINE: Duration = Duration::from_secs(300);
const PROGRESS_CALLS_BASE: u64 = 100_000;
const PROGRESS_CALLS_PER_PAGE: u64 = 4096;

struct Source {
    db: Connection,
    phase: Arc<AtomicU8>,
    budget: Arc<Budget>,
    pages: u64,
    copy: Vec<String>,
}

impl Drop for Source {
    fn drop(&mut self) {
        self.phase.store(open_verified::PHASE_CLOSED, Ordering::SeqCst);
    }
}

/// Replaces `path` with a row copy keyed by `key`. On failure the original file stays.
/// # Errors
/// `TransferExportRefused(step)` for `size`, `sidecar`, `open`, `harden`, `key`,
/// `schema_load`, `schema`, `quick_check`, or `rows`.
pub(crate) fn replace_with_clean_copy(path: &Path, key: &AccountDbKey) -> Result<(), StorageError> {
    let pages = open_verified::checked_size(path, BACKUP_SQLITE_CAP)?;
    let clean = prepare_clean(path)?;
    let copied = copy_into_clean(path, &clean, key, pages);
    if copied.is_err() {
        let _ = std::fs::remove_file(&clean);
    }
    copied
}

fn copy_into_clean(
    path: &Path,
    clean: &Path,
    key: &AccountDbKey,
    pages: u64,
) -> Result<(), StorageError> {
    migrate_clean(clean, key)?;
    let mut dest = open_clean(clean, key)?;
    let reference = reference_tables(&dest)?;
    let source = open_source(path, key, pages, &reference)?;
    copy_tables(&source, &mut dest)?;
    drop(source);
    drop(dest);
    publish(path, clean)
}

fn prepare_clean(path: &Path) -> Result<PathBuf, StorageError> {
    let clean = path.with_extension("clean");
    if clean == path {
        return Err(open_verified::refused("open"));
    }
    match std::fs::symlink_metadata(&clean) {
        Ok(metadata) if metadata.is_file() => {
            std::fs::remove_file(&clean).map_err(|_| open_verified::refused("open"))?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Ok(_) | Err(_) => return Err(open_verified::refused("open")),
    }
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    options.open(&clean).map_err(|_| open_verified::refused("open"))?;
    Ok(clean)
}

fn migrate_clean(path: &Path, key: &AccountDbKey) -> Result<(), StorageError> {
    let connection = crate::database::Connection::open(path)?;
    crate::encryption::apply_key(&connection, key)?;
    crate::schema::migrate_account_db(&connection)?;
    // Runtime tables are not migrations. Install the product definitions before the
    // copy list is read so their rows, including runtime_actor_state, move into this file.
    super::runtime::install_backup_schema(&connection)?;
    // This file is a new database. The generation is the schema just installed.
    // The source header is not copied, so a clean export would otherwise stay at 0.
    connection.execute_batch(&format!(
        "PRAGMA user_version={};",
        ramflux_protocol::schema_profile::ACTIVE_STORAGE_GENERATION,
    ))?;
    Ok(())
}

fn open_clean(path: &Path, key: &AccountDbKey) -> Result<Connection, StorageError> {
    let db = Connection::open(path).map_err(|error| open_verified::refused_by("open", &error))?;
    db.execute_batch(&key_pragma(key)).map_err(|error| open_verified::refused_by("key", &error))?;
    let enabled = db
        .set_db_config(DbConfig::SQLITE_DBCONFIG_ENABLE_TRIGGER, false)
        .map_err(|error| open_verified::refused_by("harden", &error))?;
    if enabled {
        return Err(open_verified::refused("harden"));
    }
    db.execute_batch(
        "PRAGMA foreign_keys=OFF; PRAGMA journal_mode=DELETE; PRAGMA secure_delete=ON;",
    )
    .map_err(|error| open_verified::refused_by("harden", &error))?;
    Ok(db)
}

fn open_source(
    path: &Path,
    key: &AccountDbKey,
    pages: u64,
    reference: &[String],
) -> Result<Source, StorageError> {
    let budget = Budget::new();
    budget.reset(progress_calls(pages), OPEN_DEADLINE);
    let mut db = open_verified::harden(path, &backup_limits()?, &budget)?;
    let phase = Arc::new(AtomicU8::new(open_verified::PHASE_KEY));
    let gate = Arc::clone(&phase);
    let tables = reference.to_vec();
    db.authorizer(Some(move |context: AuthContext<'_>| {
        open_verified::authorize(&gate, &tables, &context)
    }))
    .map_err(|error| open_verified::refused_by("harden", &error))?;
    db.execute_batch(&key_pragma(key)).map_err(|error| open_verified::refused_by("key", &error))?;
    phase.store(open_verified::PHASE_SCHEMA, Ordering::SeqCst);
    let objects = schema_objects(&db)?;
    super::backup_schema_budget::require_known(&objects)?;
    let copy = tables_to_copy(reference, &objects)?;
    phase.store(open_verified::PHASE_QUICK_CHECK, Ordering::SeqCst);
    open_verified::quick_check(&db)?;
    Ok(Source { db, phase, budget, pages, copy })
}

fn backup_limits() -> Result<open_verified::EngineLimits, StorageError> {
    Ok(super::backup_schema_budget::budget()?.limits)
}

fn progress_calls(pages: u64) -> u64 {
    PROGRESS_CALLS_BASE.saturating_add(pages.saturating_mul(PROGRESS_CALLS_PER_PAGE))
}

fn key_pragma(key: &AccountDbKey) -> Zeroizing<String> {
    Zeroizing::new(format!("PRAGMA key=\"x'{}'\";", Zeroizing::new(key.sqlcipher_hex()).as_str()))
}

fn schema_objects(db: &Connection) -> Result<Vec<(String, String, Option<String>)>, StorageError> {
    let mut statement = db
        .prepare("SELECT type,name,sql FROM sqlite_schema")
        .map_err(|error| open_verified::refused_by("schema_load", &error))?;
    let rows = statement
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
        .map_err(|error| open_verified::refused_by("schema_load", &error))?;
    rows.collect::<Result<Vec<_>, _>>()
        .map_err(|error| open_verified::refused_by("schema_load", &error))
}

fn tables_to_copy(
    reference: &[String],
    objects: &[(String, String, Option<String>)],
) -> Result<Vec<String>, StorageError> {
    let mut copy = Vec::new();
    for name in reference {
        match objects.iter().find(|object| object.1 == *name) {
            Some(object) if object.0 == "view" => return Err(open_verified::refused("schema")),
            Some(object) if object.0 == "table" && !is_virtual(object.2.as_deref()) => {
                copy.push(name.clone());
            }
            _ => {}
        }
    }
    Ok(copy)
}

fn is_virtual(sql: Option<&str>) -> bool {
    let Some(sql) = sql else { return false };
    sql.trim_start()
        .as_bytes()
        .get(..14)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(b"CREATE VIRTUAL"))
}

fn reference_tables(dest: &Connection) -> Result<Vec<String>, StorageError> {
    let mut statement = dest
        .prepare(
            "SELECT name,sql FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name",
        )
        .map_err(|error| open_verified::refused_by("schema", &error))?;
    let rows = statement
        .query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?)))
        .map_err(|error| open_verified::refused_by("schema", &error))?;
    let mut names = Vec::new();
    for row in rows {
        let (name, sql) = row.map_err(|error| open_verified::refused_by("schema", &error))?;
        if is_virtual(sql.as_deref()) {
            continue;
        }
        quoted(&name)?;
        names.push(name);
    }
    Ok(names)
}

fn copy_tables(source: &Source, dest: &mut Connection) -> Result<(), StorageError> {
    source.budget.reset(progress_calls(source.pages), COPY_DEADLINE);
    source
        .db
        .set_limit(Limit::SQLITE_LIMIT_LENGTH, super::backup_schema_budget::budget()?.row_cell)
        .map_err(|error| open_verified::refused_by("harden", &error))?;
    let tx = dest.transaction().map_err(|error| open_verified::refused_by("rows", &error))?;
    for table in &source.copy {
        copy_table(&source.db, &source.phase, &tx, table)?;
    }
    tx.commit().map_err(|error| open_verified::refused_by("rows", &error))?;
    Ok(())
}

fn copy_table(
    source: &Connection,
    phase: &AtomicU8,
    dest: &Connection,
    table: &str,
) -> Result<(), StorageError> {
    phase.store(open_verified::PHASE_COLUMNS, Ordering::SeqCst);
    let source_columns = plain_columns(source, table)?;
    let dest_columns = plain_columns(dest, table)?;
    let shared = shared_columns(&dest_columns, &source_columns);
    if shared.is_empty() && !dest_columns.is_empty() && !source_columns.is_empty() {
        return Err(open_verified::refused("schema"));
    }
    if shared.is_empty() {
        return Ok(());
    }
    phase.store(open_verified::PHASE_ROWS, Ordering::SeqCst);
    insert_rows(source, dest, table, &shared)
}

fn plain_columns(db: &Connection, table: &str) -> Result<Vec<String>, StorageError> {
    let sql = format!("PRAGMA table_xinfo({})", quoted(table)?);
    let mut statement =
        db.prepare(&sql).map_err(|error| open_verified::refused_by("schema", &error))?;
    let rows = statement
        .query_map([], |row| Ok((row.get::<_, String>(1)?, row.get::<_, i64>(6)?)))
        .map_err(|error| open_verified::refused_by("schema", &error))?;
    let mut names = Vec::new();
    for row in rows {
        let (name, hidden) = row.map_err(|error| open_verified::refused_by("schema", &error))?;
        if hidden == 0 {
            quoted(&name)?;
            names.push(name);
        }
    }
    Ok(names)
}

fn shared_columns(dest: &[String], source: &[String]) -> Vec<String> {
    dest.iter()
        .filter(|name| source.iter().any(|source_name| source_name == *name))
        .cloned()
        .collect()
}

fn insert_rows(
    source: &Connection,
    dest: &Connection,
    table: &str,
    columns: &[String],
) -> Result<(), StorageError> {
    let quoted_table = quoted(table)?;
    let list = columns.iter().map(|name| quoted(name)).collect::<Result<Vec<_>, _>>()?.join(",");
    dest.execute(&format!("DELETE FROM {quoted_table}"), [])
        .map_err(|error| open_verified::refused_by("rows", &error))?;
    let select = format!("SELECT {list} FROM {quoted_table}");
    let placeholders =
        (1..=columns.len()).map(|index| format!("?{index}")).collect::<Vec<_>>().join(",");
    let insert = format!("INSERT INTO {quoted_table} ({list}) VALUES ({placeholders})");
    let mut query =
        source.prepare(&select).map_err(|error| open_verified::refused_by("rows", &error))?;
    let mut rows = query.query([]).map_err(|error| open_verified::refused_by("rows", &error))?;
    let mut statement =
        dest.prepare(&insert).map_err(|error| open_verified::refused_by("rows", &error))?;
    while let Some(row) = rows.next().map_err(|error| open_verified::refused_by("rows", &error))? {
        let mut values = Vec::new();
        for index in 0..columns.len() {
            values.push(
                row.get::<_, rusqlite::types::Value>(index)
                    .map_err(|error| open_verified::refused_by("rows", &error))?,
            );
        }
        statement
            .execute(rusqlite::params_from_iter(values.iter()))
            .map_err(|error| open_verified::refused_by("rows", &error))?;
    }
    Ok(())
}

fn quoted(name: &str) -> Result<String, StorageError> {
    let mut bytes = name.bytes();
    let Some(first) = bytes.next() else {
        return Err(open_verified::refused("schema"));
    };
    if !first.is_ascii_alphabetic() && first != b'_' {
        return Err(open_verified::refused("schema"));
    }
    if bytes.any(|byte| !byte.is_ascii_alphanumeric() && byte != b'_') {
        return Err(open_verified::refused("schema"));
    }
    Ok(format!("\"{name}\""))
}

fn publish(path: &Path, clean: &Path) -> Result<(), StorageError> {
    crate::sync_path::sync_path(clean).map_err(|_| open_verified::refused("rows"))?;
    let metadata = std::fs::symlink_metadata(path).map_err(|_| open_verified::refused("size"))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(open_verified::refused("size"));
    }
    super::transfer_export::builder::require_no_sidecar_files(clean)?;
    std::fs::rename(clean, path).map_err(|_| open_verified::refused("open"))?;
    if let Some(parent) = path.parent() {
        let _ = crate::sync_path::sync_path(parent);
    }
    Ok(())
}
