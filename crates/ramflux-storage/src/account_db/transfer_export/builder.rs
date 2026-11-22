// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! `TransferExport`: the one builder shared by A's export and B's clean copy. It creates a
//! fresh database from the canonical export DDL and copies only declared rows through the
//! declared column lists with plain `INSERT`, checking every storage class and re-serializing
//! every typed body. A table that is not on the export list is never read.
use super::bodies::{self, ActorCodec};
use super::classification::{ACTOR_EXCLUDED, ACTOR_EXPORTED};
use super::contract::{Cell, Class, Column, RowFilter, Table, canonical_ddl};
use super::tables::EXPORT_TABLES;
use crate::{AccountDbKey, StorageError};
use rusqlite::types::{Value, ValueRef};
use rusqlite::{Connection, OpenFlags};
use std::collections::BTreeSet;
use std::path::Path;
use zeroize::Zeroizing;

/// Which device reads the source rows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Side {
    /// A's own pinned cut: filtered rows are skipped, an unclassified namespace refuses.
    Account,
    /// B's verified handle on a received file: any row outside the contract refuses.
    Received,
}

/// What one build wrote.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Built {
    pub(crate) rows: u64,
    pub(crate) bytes: u64,
    /// Rows written per declared table, in export order.
    pub(crate) tables: Vec<(&'static str, u64)>,
}

/// Classification of one `runtime_actor_state` kind.
enum Kind {
    Exported(ActorCodec),
    Excluded,
    Unknown,
}

fn refused(step: &'static str) -> StorageError {
    StorageError::TransferExportRefused(step)
}

/// The exact exported namespace of a kind: the prefix plus one non-empty identifier
/// segment. A deeper path under an exported prefix is on neither list.
fn classify(kind: &str) -> Kind {
    for namespace in ACTOR_EXPORTED {
        if let Some(rest) = kind.strip_prefix(namespace.prefix) {
            return if rest.is_empty() || rest.contains('/') {
                Kind::Unknown
            } else {
                Kind::Exported(namespace.codec)
            };
        }
    }
    if ACTOR_EXCLUDED.iter().any(|(prefix, _)| kind.starts_with(prefix)) {
        Kind::Excluded
    } else {
        Kind::Unknown
    }
}

/// Category name of an unknown kind for the log: its first two segments, never the id.
fn category(kind: &str) -> String {
    let mut parts = kind.splitn(3, '/');
    let head = parts.next().unwrap_or_default();
    let second = parts.next().unwrap_or_default();
    let shown: String = format!("{head}/{second}").chars().take(64).collect();
    shown
}

/// Opens a new private file for a build. The file must not exist.
/// # Errors
/// Refuses an existing path, symlink or a key/pragma failure.
pub(crate) fn create_target(path: &Path, key: &AccountDbKey) -> Result<Connection, StorageError> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    drop(options.open(path)?);
    let db = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_NOFOLLOW
            | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    let pragma = Zeroizing::new(format!(
        "PRAGMA key=\"x'{}'\";",
        Zeroizing::new(key.sqlcipher_hex()).as_str()
    ));
    db.execute_batch(&pragma)?;
    let mode: String = db.query_row("PRAGMA journal_mode=OFF", [], |row| row.get(0))?;
    if !mode.eq_ignore_ascii_case("off") {
        return Err(refused("journal_mode"));
    }
    db.execute_batch("PRAGMA temp_store=MEMORY; PRAGMA foreign_keys=OFF;")?;
    for statement in canonical_ddl() {
        db.execute_batch(&statement)?;
    }
    Ok(db)
}

/// Requires that a finished export file is a single main file with no journal of any kind.
/// # Errors
/// Refuses a non-off journal mode or any sidecar file.
pub(crate) fn require_no_sidecar(db: &Connection, path: &Path) -> Result<(), StorageError> {
    let mode: String = db.query_row("PRAGMA journal_mode", [], |row| row.get(0))?;
    if !mode.eq_ignore_ascii_case("off") {
        return Err(refused("journal_mode"));
    }
    require_no_sidecar_files(path)
}

/// Requires that no `-wal`, `-shm` or `-journal` file exists beside `path`.
/// # Errors
/// Refuses when any sidecar exists.
pub(crate) fn require_no_sidecar_files(path: &Path) -> Result<(), StorageError> {
    for suffix in ["-wal", "-shm", "-journal"] {
        let mut name = path.as_os_str().to_owned();
        name.push(suffix);
        if std::fs::symlink_metadata(Path::new(&name)).is_ok() {
            return Err(refused("sidecar"));
        }
    }
    Ok(())
}

/// Copies every declared table from `source` into a fresh canonical file at `target`.
/// # Errors
/// `PairingField("UnsupportedRecord")` when A holds an unclassified actor namespace (names
/// are logged, never values); `TransferExportRefused(step)` for any other contract breach;
/// SQL and I/O errors. The caller discards `target` on any error.
pub(crate) fn build(
    source: &Connection,
    side: Side,
    target: &Path,
    key: &AccountDbKey,
) -> Result<Built, StorageError> {
    let mut dest = create_target(target, key)?;
    let mut unknown = BTreeSet::new();
    let mut built = Built::default();
    let transaction = dest.transaction()?;
    for table in EXPORT_TABLES {
        let rows = copy_table(source, &transaction, table, side, &mut unknown)?;
        built.rows += rows;
        built.tables.push((table.name, rows));
    }
    if !unknown.is_empty() {
        for name in &unknown {
            tracing::warn!(namespace = %name, "transfer export refused an unclassified actor namespace");
        }
        return Err(StorageError::PairingField("UnsupportedRecord"));
    }
    transaction.commit()?;
    require_no_sidecar(&dest, target)?;
    dest.close().map_err(|(_, error)| error)?;
    require_no_sidecar_files(target)?;
    built.bytes = std::fs::symlink_metadata(target)?.len();
    Ok(built)
}

fn quoted_list(columns: &[Column]) -> String {
    columns.iter().map(|column| format!("\"{}\"", column.name)).collect::<Vec<_>>().join(",")
}

/// A's source may lack a lazily created table (no rows); a present table must hold every
/// declared column (no legacy shapes before v1).
fn source_has_table(source: &Connection, table: &Table) -> Result<bool, StorageError> {
    let exists: bool = source.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' AND name=?1)",
        [table.name],
        |row| row.get(0),
    )?;
    if !exists {
        return Ok(false);
    }
    let mut statement = source.prepare(&format!("PRAGMA table_info(\"{}\")", table.name))?;
    let live: BTreeSet<String> =
        statement.query_map([], |row| row.get::<_, String>(1))?.collect::<rusqlite::Result<_>>()?;
    if table.columns.iter().any(|column| !live.contains(column.name)) {
        return Err(refused("missing_source_column"));
    }
    Ok(true)
}

fn copy_table(
    source: &Connection,
    dest: &Connection,
    table: &Table,
    side: Side,
    unknown: &mut BTreeSet<String>,
) -> Result<u64, StorageError> {
    if side == Side::Account && !source_has_table(source, table)? {
        return Ok(0);
    }
    let columns = quoted_list(table.columns);
    let mut read = source.prepare(&format!("SELECT {columns} FROM \"{}\"", table.name))?;
    let marks: Vec<String> = (1..=table.columns.len()).map(|index| format!("?{index}")).collect();
    let mut write = dest.prepare(&format!(
        "INSERT INTO \"{}\"({columns}) VALUES({})",
        table.name,
        marks.join(",")
    ))?;
    let mut rows = read.query([])?;
    let mut copied = 0_u64;
    while let Some(row) = rows.next()? {
        let actor = match table.filter {
            RowFilter::All => None,
            RowFilter::ActorNamespaces => match actor_row(row, side, unknown)? {
                Some(codec) => Some(codec),
                None => continue,
            },
        };
        let mut values = Vec::with_capacity(table.columns.len());
        for (index, column) in table.columns.iter().enumerate() {
            values.push(checked(row.get_ref(index)?, column, side, actor)?);
        }
        write.execute(rusqlite::params_from_iter(values.iter())).map_err(|error| {
            match error.sqlite_error_code() {
                Some(rusqlite::ErrorCode::ConstraintViolation) => refused("constraint"),
                _ => StorageError::Sqlite(error),
            }
        })?;
        copied += 1;
    }
    Ok(copied)
}

/// Classifies one `runtime_actor_state` row by its kind (column 0). `None` skips the row.
fn actor_row(
    row: &rusqlite::Row<'_>,
    side: Side,
    unknown: &mut BTreeSet<String>,
) -> Result<Option<ActorCodec>, StorageError> {
    let ValueRef::Text(raw) = row.get_ref(0)? else {
        return Err(refused("storage_class"));
    };
    let kind = std::str::from_utf8(raw).map_err(|_| refused("storage_class"))?;
    match (classify(kind), side) {
        (Kind::Exported(codec), _) => Ok(Some(codec)),
        (Kind::Excluded, Side::Account) => Ok(None),
        (Kind::Unknown, Side::Account) => {
            unknown.insert(category(kind));
            Ok(None)
        }
        (Kind::Excluded | Kind::Unknown, Side::Received) => Err(refused("filtered_row")),
    }
}

/// One declared cell: exact storage class, then the body rule.
fn checked(
    value: ValueRef<'_>,
    column: &Column,
    side: Side,
    actor: Option<ActorCodec>,
) -> Result<Value, StorageError> {
    if let ValueRef::Null = value {
        return if column.nullable { Ok(Value::Null) } else { Err(refused("storage_class")) };
    }
    match (column.cell, value) {
        (
            Cell::Plain(Class::Integer) | Cell::UserContent(Class::Integer),
            ValueRef::Integer(number),
        ) => Ok(Value::Integer(number)),
        (Cell::Plain(Class::Text) | Cell::UserContent(Class::Text), ValueRef::Text(text)) => {
            let text = std::str::from_utf8(text).map_err(|_| refused("storage_class"))?;
            Ok(Value::Text(text.to_owned()))
        }
        (Cell::Plain(Class::Blob) | Cell::UserContent(Class::Blob), ValueRef::Blob(bytes)) => {
            Ok(Value::Blob(bytes.to_vec()))
        }
        (Cell::Body(codec), ValueRef::Blob(bytes)) => {
            Ok(Value::Blob(bodies::canonical(codec, actor, bytes)?))
        }
        // A's own writers store some JSON bodies as TEXT; the export always holds BLOB.
        (Cell::Body(codec), ValueRef::Text(bytes)) if side == Side::Account => {
            Ok(Value::Blob(bodies::canonical(codec, actor, bytes)?))
        }
        _ => Err(refused("storage_class")),
    }
}
