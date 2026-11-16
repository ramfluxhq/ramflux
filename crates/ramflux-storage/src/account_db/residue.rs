// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Read-only plaintext-residue scan of an already unlocked account database.
//! Results are locations and counts. Cell bytes never leave SQLite.

use super::AccountDb;
use crate::StorageError;
use rusqlite::OptionalExtension;
use sha2::Digest;
use std::time::Instant;
use zeroize::Zeroize;

const MAX_MARKER_BYTES: usize = 4096;
const MAX_TABLES: usize = 512;
const MAX_COLUMNS: usize = 128;
const MAX_HITS: usize = 10_000;
const MAX_LOCATIONS: usize = 32;

/// One matching column in a scanned table. The cell value is not included.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResidueHit {
    pub rowid: Option<i64>,
    pub column: String,
}

/// Every user table the scan opened, including tables with no hits.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResidueTable {
    pub name: String,
    pub hits: u64,
    pub truncated: bool,
    pub locations: Vec<ResidueHit>,
}

/// Tables scanned through a query-only connection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResidueScan {
    pub tables: Vec<ResidueTable>,
    pub hits: u64,
    pub truncated: bool,
}

/// Marker bytes plus their UTF-16 encodings and raw SHA-256 and BLAKE3 digests.
///
/// # Errors
/// Returns an error when the marker is empty or longer than 4096 bytes.
#[must_use = "discarding residue needles drops the scan inputs"]
pub fn residue_needles(marker: &[u8]) -> Result<Vec<Vec<u8>>, StorageError> {
    if marker.is_empty() {
        return Err(StorageError::Integrity("residue marker is empty"));
    }
    if marker.len() > MAX_MARKER_BYTES {
        return Err(StorageError::Integrity("residue marker exceeds 4096 bytes"));
    }
    let mut needles = Vec::with_capacity(6);
    push_needle(&mut needles, marker.to_vec());
    if let Ok(text) = std::str::from_utf8(marker) {
        push_needle(&mut needles, utf16(text, u16::to_le_bytes));
        push_needle(&mut needles, utf16(text, u16::to_be_bytes));
    }
    push_needle(&mut needles, sha2::Sha256::digest(marker).to_vec());
    push_needle(&mut needles, blake3::hash(marker).as_bytes().to_vec());
    Ok(needles)
}

fn utf16(text: &str, encode: impl Fn(u16) -> [u8; 2]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for unit in text.encode_utf16() {
        bytes.extend(encode(unit));
    }
    bytes
}

fn push_needle(needles: &mut Vec<Vec<u8>>, needle: Vec<u8>) {
    if needle.is_empty() || needles.iter().any(|existing| existing == &needle) {
        return;
    }
    needles.push(needle);
}

impl AccountDb {
    /// Scans every account table through a new query-only connection.
    ///
    /// The caller must already hold the unlocked database. Blob and FTS shadow
    /// tables are included. Virtual tables that cannot be read are still listed
    /// after their content and shadow tables are scanned.
    ///
    /// # Errors
    /// Returns an error when the marker, a table name, the deadline, or a
    /// required read fails. A SQLite lock is returned as a storage error.
    #[must_use = "discarding the residue scan hides plaintext hits"]
    pub fn scan_plaintext_residue(
        &self,
        marker: &[u8],
        deadline: Instant,
    ) -> Result<ResidueScan, StorageError> {
        let needles = NeedleSet(residue_needles(marker)?);
        if Instant::now() >= deadline {
            return Err(StorageError::Integrity("residue scan exceeded its deadline"));
        }
        let reader = self.open_query_only_connection()?;
        let tables = table_list(&reader)?;
        let mut report = Vec::with_capacity(tables.len());
        let mut hits = 0u64;
        let mut truncated = false;
        for table in tables {
            if Instant::now() >= deadline {
                return Err(StorageError::Integrity("residue scan exceeded its deadline"));
            }
            let scanned = scan_table(&reader, &table, &needles.0)?;
            hits = hits.saturating_add(scanned.hits);
            truncated |= scanned.truncated;
            report.push(scanned);
        }
        Ok(ResidueScan { tables: report, hits, truncated })
    }
}

struct NeedleSet(Vec<Vec<u8>>);

impl Drop for NeedleSet {
    fn drop(&mut self) {
        for needle in &mut self.0 {
            needle.zeroize();
        }
    }
}

struct ListedTable {
    name: String,
    virtual_table: bool,
}

fn table_list(reader: &crate::database::Connection) -> Result<Vec<ListedTable>, StorageError> {
    let rows = reader.rows(
        "SELECT name, sql FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name LIMIT 513",
        [],
    )?;
    if rows.len() > MAX_TABLES {
        return Err(StorageError::Integrity("residue scan table count exceeds 512"));
    }
    let mut tables = Vec::with_capacity(rows.len());
    for row in &rows {
        let name: String = row.get(0)?;
        if !safe_ident(&name) {
            return Err(StorageError::Integrity("residue scan refused an unsafe table name"));
        }
        let sql: Option<String> = row.get(1)?;
        let virtual_table = sql.as_deref().is_some_and(|sql| {
            sql.get(.."CREATE VIRTUAL".len())
                .is_some_and(|prefix| prefix.eq_ignore_ascii_case("CREATE VIRTUAL"))
        });
        tables.push(ListedTable { name, virtual_table });
    }
    Ok(tables)
}

fn scan_table(
    reader: &crate::database::Connection,
    table: &ListedTable,
    needles: &[Vec<u8>],
) -> Result<ResidueTable, StorageError> {
    let columns = columns(reader, &table.name)?;
    if columns.is_empty() || needles.is_empty() {
        return Ok(empty_table(&table.name));
    }
    let has_rowid = table_has_rowid(reader, &table.name)?;
    let sql = match_sql(&table.name, &columns, needles.len(), has_rowid);
    let params: Vec<&dyn rusqlite::ToSql> =
        needles.iter().map(|needle| needle as &dyn rusqlite::ToSql).collect();
    let rows = match reader.rows(&sql, params.as_slice()) {
        Ok(rows) => rows,
        Err(error) if table.virtual_table => {
            let _ = error;
            return Ok(empty_table(&table.name));
        }
        Err(error) => return Err(error.into()),
    };
    let mut scanned = empty_table(&table.name);
    scanned.truncated = rows.len() > MAX_HITS;
    for row in rows.iter().take(MAX_HITS) {
        let rowid = if has_rowid { Some(row.get::<_, i64>(0)?) } else { None };
        let first = usize::from(has_rowid);
        for (index, column) in columns.iter().enumerate() {
            let flag: i64 = row.get(first + index)?;
            if flag == 0 {
                continue;
            }
            scanned.hits = scanned.hits.saturating_add(1);
            if scanned.locations.len() < MAX_LOCATIONS {
                scanned.locations.push(ResidueHit { rowid, column: (*column).clone() });
            } else {
                scanned.truncated = true;
            }
        }
    }
    Ok(scanned)
}

fn empty_table(name: &str) -> ResidueTable {
    ResidueTable { name: name.to_owned(), hits: 0, truncated: false, locations: Vec::new() }
}

fn columns(reader: &crate::database::Connection, table: &str) -> Result<Vec<String>, StorageError> {
    let rows = reader.rows(
        "SELECT name FROM pragma_table_info(?1) ORDER BY cid LIMIT 129",
        rusqlite::params![table],
    )?;
    if rows.len() > MAX_COLUMNS {
        return Err(StorageError::Integrity("residue scan column count exceeds 128"));
    }
    let mut names = Vec::with_capacity(rows.len());
    for row in &rows {
        let name: String = row.get(0)?;
        if !safe_ident(&name) {
            return Err(StorageError::Integrity("residue scan refused an unsafe column name"));
        }
        names.push(name);
    }
    Ok(names)
}

fn table_has_rowid(
    reader: &crate::database::Connection,
    table: &str,
) -> Result<bool, StorageError> {
    let without: Option<i64> = reader
        .query_row(
            "SELECT wr FROM pragma_table_list WHERE schema='main' AND name=?1",
            rusqlite::params![table],
            |row| row.get(0),
        )
        .optional()?;
    Ok(without != Some(1))
}

fn match_sql(table: &str, columns: &[String], needles: usize, has_rowid: bool) -> String {
    let mut sql = String::from("SELECT ");
    if has_rowid {
        sql.push_str("rowid");
    }
    for column in columns {
        if has_rowid || !sql.ends_with("SELECT ") {
            sql.push_str(", ");
        }
        sql.push_str("CASE WHEN ");
        push_match(&mut sql, column, needles);
        sql.push_str(" THEN 1 ELSE 0 END");
    }
    sql.push_str(" FROM \"");
    sql.push_str(table);
    sql.push_str("\" WHERE ");
    for (index, column) in columns.iter().enumerate() {
        if index > 0 {
            sql.push_str(" OR ");
        }
        push_match(&mut sql, column, needles);
    }
    sql.push_str(" LIMIT 10001");
    sql
}

fn push_match(sql: &mut String, column: &str, needles: usize) {
    for index in 1..=needles {
        if index > 1 {
            sql.push_str(" OR ");
        }
        sql.push_str("instr(CAST(\"");
        sql.push_str(column);
        sql.push_str("\" AS BLOB), ?");
        sql.push_str(&index.to_string());
        sql.push_str(")>0");
    }
}

fn safe_ident(name: &str) -> bool {
    let mut bytes = name.bytes();
    match bytes.next() {
        Some(b'A'..=b'Z' | b'a'..=b'z' | b'_') => {}
        _ => return false,
    }
    bytes.all(|byte| matches!(byte, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'_'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account_db::local_search::{
        SearchActivation, SearchControl, SearchDependency, SearchKind, SearchSource,
    };
    use crate::{AccountDbKey, AccountIndex, DirectMessageWrite, MessageMetadata};

    const MARKER: &[u8] = b"b11canarymarker";

    fn open() -> (tempfile::TempDir, AccountDb) {
        let directory = tempfile::tempdir().expect("test: temp dir");
        let index = AccountIndex::open(directory.path()).expect("test: index");
        index.create_account("acct", "principal").expect("test: account");
        let db = AccountDb::open(&index, "acct", &AccountDbKey::from_bytes([9; 32]))
            .expect("test: database");
        db.enable_runtime().expect("test: runtime");
        (directory, db)
    }

    fn plant(db: &AccountDb, body: &[u8]) {
        db.import_direct_message_projection(DirectMessageWrite {
            conversation_id: "thread",
            message_id: "message-1",
            sender_id: "sender",
            encrypted_body: body,
            metadata: &MessageMetadata::default(),
            created_at: 1,
        })
        .expect("test: projection");
        db.store_message_content("thread", "message-1", MARKER).expect("test: content");
        let activation = SearchActivation::testing();
        let _watch = db.search_prepare(&activation).expect("test: search");
        let control = SearchControl::new();
        let revision = db.search_revision(&activation, &control).expect("test: revision");
        db.search_replace(
            &activation,
            SearchSource {
                kind: SearchKind::Message,
                source_ref: "message-1".into(),
                source_key: "message-1".into(),
                conversation_id: "thread".into(),
                message_id: Some("message-1".into()),
                revision: 1,
                timestamp: 1,
                expires_at: None,
                text: std::str::from_utf8(MARKER).expect("test: marker text").into(),
                dependencies: vec![SearchDependency {
                    table: "runtime_message_content".into(),
                    key: "message-1".into(),
                }],
            },
            revision,
            &control,
        )
        .expect("test: search replace");
    }

    fn scan(db: &AccountDb) -> ResidueScan {
        db.scan_plaintext_residue(MARKER, Instant::now() + std::time::Duration::from_secs(5))
            .expect("test: scan")
    }

    fn erase(db: &AccountDb) {
        db.delete_direct_message("thread", "message-1", "local", "tombstone-1")
            .expect("test: delete");
        db.write_transaction(|| db.retire_message_payload_copies("message-1", &[]))
            .expect("test: retire");
    }

    #[test]
    fn needles_cover_utf16_and_raw_hashes() {
        let needles = residue_needles(MARKER).expect("test: needles");
        assert!(needles.iter().any(|needle| needle.as_slice() == MARKER), "raw marker bytes");
        let mut utf16_le = Vec::new();
        for unit in "b11canarymarker".encode_utf16() {
            utf16_le.extend(unit.to_le_bytes());
        }
        assert!(needles.iter().any(|needle| needle == &utf16_le), "utf-16le form");
        let sha = sha2::Sha256::digest(MARKER);
        assert!(needles.iter().any(|needle| needle.as_slice() == sha.as_slice()), "raw sha-256");
        let blake = blake3::hash(MARKER);
        assert!(needles.iter().any(|needle| needle.as_slice() == blake.as_bytes()), "raw blake3");
        assert!(residue_needles(b"").is_err(), "empty marker is refused");
    }

    #[test]
    fn unerased_message_marker_is_found() {
        let (_dir, db) = open();
        let mut utf16_le = Vec::new();
        for unit in "b11canarymarker".encode_utf16() {
            utf16_le.extend(unit.to_le_bytes());
        }
        plant(&db, &utf16_le);
        let report = scan(&db);
        assert!(!report.truncated, "control scan must finish");
        assert!(report.hits > 0, "control message must be visible to the scan");
        assert!(
            report.tables.iter().any(|table| {
                table.name == "runtime_message_content"
                    && table.locations.iter().any(|hit| hit.column == "body")
            }),
            "plaintext body must be located without returning its bytes"
        );
        assert!(
            report.tables.iter().any(|table| {
                table.name == "direct_message_projection"
                    && table.locations.iter().any(|hit| hit.column == "encrypted_body")
            }),
            "utf-16 form in the projection must be located"
        );
        assert!(
            report.tables.iter().any(|table| table.name.starts_with("local_search_")),
            "fts and search tables must be included in the scan"
        );
        let json = format!("{report:?}");
        assert!(!json.contains("b11canarymarker"), "report must not contain the marker");
    }

    #[test]
    fn erased_message_marker_scan_finds_no_hits() {
        let (_dir, db) = open();
        plant(&db, MARKER);
        erase(&db);
        let report = scan(&db);
        assert!(!report.truncated, "erase scan must finish");
        assert_eq!(report.hits, 0, "erased message leaves no marker, utf-16 form, or raw hash");
        assert!(
            report.tables.iter().any(|table| table.name == "runtime_message_content"),
            "content table must still be listed"
        );
    }

    #[test]
    fn delayed_own_copy_after_erase_scan_finds_no_hits() {
        let (_dir, db) = open();
        plant(&db, MARKER);
        erase(&db);
        db.import_direct_message_projection(DirectMessageWrite {
            conversation_id: "thread",
            message_id: "message-1",
            sender_id: "sender",
            encrypted_body: MARKER,
            metadata: &MessageMetadata::default(),
            created_at: 2,
        })
        .expect("test: delayed import");
        db.store_message_content("thread", "message-1", MARKER).expect("test: delayed content");
        let report = scan(&db);
        assert!(!report.truncated, "delayed own-copy scan must finish");
        assert_eq!(
            report.hits, 0,
            "a delayed own-copy that arrives after erasure must stay absent"
        );
    }
}
