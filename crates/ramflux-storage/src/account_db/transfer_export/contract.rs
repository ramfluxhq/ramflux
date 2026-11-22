// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! The export contract: declared tables and columns, the canonical DDL generated from them,
//! and the contract digest that both devices compare before any byte is merged.
use super::classification::{ACTOR_EXCLUDED, ACTOR_EXPORTED, EXCLUDED_COLUMNS, EXCLUDED_TABLES};
use super::tables::EXPORT_TABLES;
use crate::StorageError;

/// SQLite storage class a declared column must hold, enforced on every insert (STRICT).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Class {
    Integer,
    Text,
    Blob,
}

impl Class {
    pub(crate) const fn sql(self) -> &'static str {
        match self {
            Self::Integer => "INTEGER",
            Self::Text => "TEXT",
            Self::Blob => "BLOB",
        }
    }
}

/// How a declared column's value is checked before it is written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Cell {
    /// A scalar of exactly this class (identifiers, counters, flags, timestamps).
    Plain(Class),
    /// Closed category (b): message plaintext, edit text or attachment ciphertext only.
    UserContent(Class),
    /// A JSON body with a typed declaration, re-serialized canonically on both devices.
    Body(super::bodies::BodyCodec),
}

impl Cell {
    pub(crate) const fn class(self) -> Class {
        match self {
            Self::Plain(class) | Self::UserContent(class) => class,
            Self::Body(_) => Class::Blob,
        }
    }
}

/// One declared column of an exported table.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Column {
    pub(crate) name: &'static str,
    pub(crate) cell: Cell,
    pub(crate) nullable: bool,
}

/// Which rows of a declared table may leave A.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RowFilter {
    /// Every row.
    All,
    /// Only `runtime_actor_state` rows whose kind is an exported exact namespace.
    ActorNamespaces,
}

/// One entry of the compiled export list.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Table {
    pub(crate) name: &'static str,
    pub(crate) key: &'static [&'static str],
    pub(crate) columns: &'static [Column],
    pub(crate) filter: RowFilter,
    /// True when B's install rewrites the row, so the tail compares the source digest.
    pub(crate) transformed: bool,
}

const CONTRACT_DOMAIN: &str = "ramflux.transfer.export.contract.v1";

/// Final `CREATE TABLE` text of one declared table: STRICT, WITHOUT ROWID, natural key.
pub(crate) fn create_table_sql(table: &Table) -> String {
    let mut sql = format!("CREATE TABLE \"{}\"(", table.name);
    for column in table.columns {
        sql.push('"');
        sql.push_str(column.name);
        sql.push_str("\" ");
        sql.push_str(column.cell.class().sql());
        if !column.nullable {
            sql.push_str(" NOT NULL");
        }
        sql.push(',');
    }
    sql.push_str("PRIMARY KEY(");
    let key: Vec<String> = table.key.iter().map(|name| format!("\"{name}\"")).collect();
    sql.push_str(&key.join(","));
    sql.push_str(")) STRICT, WITHOUT ROWID");
    sql
}

/// The whole canonical export schema, in creation order. No ALTER, trigger, view or
/// virtual table can appear: the builder executes only these statements.
pub(crate) fn canonical_ddl() -> Vec<String> {
    EXPORT_TABLES.iter().map(create_table_sql).collect()
}

/// One canonical `sqlite_schema` row: `type`, `name`, `tbl_name`, `sql`.
pub(crate) type SchemaRow = (String, String, String, Option<String>);

/// Reads the `sqlite_schema` rows of a connection in storage order.
/// # Errors
/// Returns SQL errors.
pub(crate) fn schema_rows(db: &rusqlite::Connection) -> Result<Vec<SchemaRow>, StorageError> {
    let mut statement = db.prepare("SELECT type,name,tbl_name,sql FROM sqlite_schema")?;
    let rows =
        statement.query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)))?;
    Ok(rows.collect::<rusqlite::Result<Vec<SchemaRow>>>()?)
}

/// The schema rows this binary's builder creates, read from an in-memory build.
/// # Errors
/// Returns SQL errors.
pub(crate) fn canonical_schema_rows() -> Result<Vec<SchemaRow>, StorageError> {
    let db = rusqlite::Connection::open_in_memory()?;
    for statement in canonical_ddl() {
        db.execute_batch(&statement)?;
    }
    schema_rows(&db)
}

fn put(hasher: &mut blake3::Hasher, bytes: &[u8]) {
    hasher.update(&(bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
}

fn put_str(hasher: &mut blake3::Hasher, value: &str) {
    put(hasher, value.as_bytes());
}

/// BLAKE3 over the canonical schema rows, the export list (table, key, columns with storage
/// classes and cell rules, row filter, transform flag), the exact actor namespace lists,
/// the body-declaration versions and the SQLite/SQLCipher engine versions (A2).
/// # Errors
/// Returns SQL errors while building the in-memory reference schema.
pub(crate) fn export_contract_digest() -> Result<[u8; 32], StorageError> {
    let mut hasher = blake3::Hasher::new_derive_key(CONTRACT_DOMAIN);
    put_str(&mut hasher, rusqlite::version());
    put_str(&mut hasher, if cfg!(feature = "sqlcipher") { "sqlcipher" } else { "plain" });
    let rows = canonical_schema_rows()?;
    put(&mut hasher, &(rows.len() as u64).to_be_bytes());
    for (kind, name, table, sql) in &rows {
        put_str(&mut hasher, kind);
        put_str(&mut hasher, name);
        put_str(&mut hasher, table);
        put_str(&mut hasher, sql.as_deref().unwrap_or(""));
    }
    put(&mut hasher, &(EXPORT_TABLES.len() as u64).to_be_bytes());
    for table in EXPORT_TABLES {
        put_str(&mut hasher, table.name);
        put_str(&mut hasher, &table.key.join(","));
        put_str(&mut hasher, &format!("{:?}/{}", table.filter, table.transformed));
        for column in table.columns {
            put_str(&mut hasher, column.name);
            put_str(&mut hasher, &format!("{:?}/{}", column.cell, column.nullable));
        }
    }
    for namespace in ACTOR_EXPORTED {
        put_str(&mut hasher, namespace.prefix);
        put_str(&mut hasher, &format!("{:?}", namespace.codec));
        put(&mut hasher, &namespace.codec.version().to_be_bytes());
    }
    for (prefix, _) in ACTOR_EXCLUDED {
        put_str(&mut hasher, prefix);
    }
    for (table, _) in EXCLUDED_TABLES {
        put_str(&mut hasher, table);
    }
    for (table, column, _) in EXCLUDED_COLUMNS {
        put_str(&mut hasher, table);
        put_str(&mut hasher, column);
    }
    for codec in super::bodies::BodyCodec::ALL {
        put_str(&mut hasher, &format!("{codec:?}"));
        put(&mut hasher, &codec.version().to_be_bytes());
    }
    Ok(*hasher.finalize().as_bytes())
}
