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

/// Whether a table was read, or its query failed closed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResidueTableStatus {
    /// The table was queried. `hits` is `Some`.
    Scanned,
    /// A virtual table could not be queried. This is not a zero-hit result.
    Unscannable,
}

impl ResidueTableStatus {
    /// The JSON token for this table status.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Scanned => "scanned",
            Self::Unscannable => "unscannable",
        }
    }
}

/// Whether the scan can be treated as a complete absence proof.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResidueScanStatus {
    /// Every table was read, nothing matched, and the result is not truncated.
    Clean,
    /// Every required table was read and at least one needle matched.
    Residue,
    /// A read stopped at its hit or row cap.
    Truncated,
    /// At least one virtual table could not be queried.
    Unscannable,
}

impl ResidueScanStatus {
    /// The JSON token for this status.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Clean => "clean",
            Self::Residue => "residue",
            Self::Truncated => "truncated",
            Self::Unscannable => "unscannable",
        }
    }

    /// Keeps the stronger reason a scan is not a clean absence proof.
    #[must_use]
    pub fn merge(self, other: Self) -> Self {
        use ResidueScanStatus::{Clean, Residue, Truncated, Unscannable};
        match (self, other) {
            (Unscannable, _) | (_, Unscannable) => Unscannable,
            (Truncated, _) | (_, Truncated) => Truncated,
            (Residue, _) | (_, Residue) => Residue,
            (Clean, Clean) => Clean,
        }
    }
}

/// Every user table the scan considered, including tables with no hits.
///
/// A [`ResidueTableStatus::Unscannable`] table has `hits: None`. It must not
/// be reported as zero hits.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResidueTable {
    pub name: String,
    pub status: ResidueTableStatus,
    pub hits: Option<u64>,
    pub truncated: bool,
    pub locations: Vec<ResidueHit>,
}

/// Tables scanned through a query-only connection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResidueScan {
    pub tables: Vec<ResidueTable>,
    pub hits: u64,
    pub status: ResidueScanStatus,
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
    /// tables are included. A virtual table whose query fails is
    /// [`ResidueTableStatus::Unscannable`] and the scan status is not
    /// [`ResidueScanStatus::Clean`].
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
        let mut status = ResidueScanStatus::Clean;
        for table in tables {
            if Instant::now() >= deadline {
                return Err(StorageError::Integrity("residue scan exceeded its deadline"));
            }
            let scanned = scan_table(&reader, &table, &needles.0)?;
            match (scanned.status, scanned.hits) {
                (ResidueTableStatus::Unscannable, _) | (ResidueTableStatus::Scanned, None) => {
                    status = status.merge(ResidueScanStatus::Unscannable);
                }
                (ResidueTableStatus::Scanned, Some(table_hits)) => {
                    hits = hits.saturating_add(table_hits);
                    if table_hits > 0 {
                        status = status.merge(ResidueScanStatus::Residue);
                    }
                    if scanned.truncated {
                        truncated = true;
                        status = status.merge(ResidueScanStatus::Truncated);
                    }
                }
            }
            report.push(scanned);
        }
        Ok(ResidueScan { tables: report, hits, status, truncated })
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
    let columns = match columns(reader, &table.name) {
        Ok(columns) => columns,
        Err(_) if table.virtual_table => return Ok(unscannable_table(&table.name)),
        Err(error) => return Err(error),
    };
    if columns.is_empty() || needles.is_empty() {
        return Ok(empty_table(&table.name));
    }
    let has_rowid = match table_has_rowid(reader, &table.name) {
        Ok(has_rowid) => has_rowid,
        Err(_) if table.virtual_table => return Ok(unscannable_table(&table.name)),
        Err(error) => return Err(error),
    };
    let sql = match_sql(&table.name, &columns, needles.len(), has_rowid);
    let params: Vec<&dyn rusqlite::ToSql> =
        needles.iter().map(|needle| needle as &dyn rusqlite::ToSql).collect();
    let rows = match reader.rows(&sql, params.as_slice()) {
        Ok(rows) => rows,
        Err(_) if table.virtual_table => return Ok(unscannable_table(&table.name)),
        Err(error) => return Err(error.into()),
    };
    let mut scanned = empty_table(&table.name);
    scanned.truncated = rows.len() > MAX_HITS;
    let mut table_hits = 0u64;
    for row in rows.iter().take(MAX_HITS) {
        let rowid = if has_rowid { Some(row.get::<_, i64>(0)?) } else { None };
        let first = usize::from(has_rowid);
        for (index, column) in columns.iter().enumerate() {
            let flag: i64 = row.get(first + index)?;
            if flag == 0 {
                continue;
            }
            table_hits = table_hits.saturating_add(1);
            if scanned.locations.len() < MAX_LOCATIONS {
                scanned.locations.push(ResidueHit { rowid, column: (*column).clone() });
            } else {
                scanned.truncated = true;
            }
        }
    }
    scanned.hits = Some(table_hits);
    Ok(scanned)
}

fn empty_table(name: &str) -> ResidueTable {
    ResidueTable {
        name: name.to_owned(),
        status: ResidueTableStatus::Scanned,
        hits: Some(0),
        truncated: false,
        locations: Vec::new(),
    }
}

fn unscannable_table(name: &str) -> ResidueTable {
    ResidueTable {
        name: name.to_owned(),
        status: ResidueTableStatus::Unscannable,
        hits: None,
        truncated: false,
        locations: Vec::new(),
    }
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

    fn project(db: &AccountDb, message_id: &str, body: &[u8]) {
        db.import_direct_message_projection(DirectMessageWrite {
            conversation_id: "thread",
            message_id,
            sender_id: "sender",
            encrypted_body: body,
            metadata: &MessageMetadata::default(),
            created_at: 1,
        })
        .expect("test: projection");
    }

    fn plant(db: &AccountDb, body: &[u8]) {
        project(db, "message-1", body);
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
        let mut little_endian = Vec::new();
        for unit in "b11canarymarker".encode_utf16() {
            little_endian.extend(unit.to_le_bytes());
        }
        assert!(needles.iter().any(|needle| needle == &little_endian), "utf-16le form");
        let mut big_endian = Vec::new();
        for unit in "b11canarymarker".encode_utf16() {
            big_endian.extend(unit.to_be_bytes());
        }
        assert!(needles.iter().any(|needle| needle == &big_endian), "utf-16be form");
        let sha = sha2::Sha256::digest(MARKER);
        assert!(needles.iter().any(|needle| needle.as_slice() == sha.as_slice()), "raw sha-256");
        let blake = blake3::hash(MARKER);
        assert!(needles.iter().any(|needle| needle.as_slice() == blake.as_bytes()), "raw blake3");
        assert!(residue_needles(b"").is_err(), "empty marker is refused");
    }

    fn assert_absent(report: &ResidueScan) {
        assert!(!report.truncated, "absence scan must finish");
        assert_eq!(report.hits, 0, "scanned tables must not count a hit");
        assert!(
            matches!(report.status, ResidueScanStatus::Clean | ResidueScanStatus::Unscannable),
            "absence is clean or honestly unscannable, got {:?}",
            report.status
        );
        for table in &report.tables {
            match table.status {
                ResidueTableStatus::Scanned => {
                    assert_eq!(table.hits, Some(0), "{} must not invent hits", table.name);
                    assert_eq!(table.locations.len(), 0, "{} locations must be empty", table.name);
                }
                ResidueTableStatus::Unscannable => {
                    assert_eq!(table.hits, None, "{} must not report zero hits", table.name);
                    assert_eq!(table.locations.len(), 0, "{} locations must be empty", table.name);
                }
            }
        }
    }

    #[test]
    fn unerased_message_marker_is_found() {
        let (_dir, db) = open();
        let marker = std::str::from_utf8(MARKER).expect("test: marker text");
        let little_endian = utf16(marker, u16::to_le_bytes);
        let big_endian = utf16(marker, u16::to_be_bytes);
        plant(&db, &little_endian);
        project(&db, "message-be", &big_endian);
        project(&db, "message-sha", sha2::Sha256::digest(MARKER).as_slice());
        project(&db, "message-blake", blake3::hash(MARKER).as_bytes());
        let report = scan(&db);
        assert!(!report.truncated, "control scan must finish");
        assert!(report.hits > 0, "control message must be visible to the scan");
        assert!(
            matches!(report.status, ResidueScanStatus::Residue | ResidueScanStatus::Unscannable),
            "a located marker is not a clean scan, got {:?}",
            report.status
        );
        assert!(
            report.tables.iter().any(|table| {
                table.name == "runtime_message_content"
                    && table.status == ResidueTableStatus::Scanned
                    && table.locations.iter().any(|hit| hit.column == "body")
            }),
            "plaintext body must be located without returning its bytes"
        );
        let encrypted = report
            .tables
            .iter()
            .find(|table| table.name == "direct_message_projection")
            .and_then(|table| {
                (table.status == ResidueTableStatus::Scanned).then_some(
                    table.locations.iter().filter(|hit| hit.column == "encrypted_body").count(),
                )
            })
            .unwrap_or(0);
        assert!(
            encrypted >= 4,
            "utf-16le, utf-16be, sha-256, and blake3 must be located, got {encrypted}"
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
        assert_absent(&report);
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
        assert_absent(&scan(&db));
    }

    #[test]
    fn failed_virtual_table_is_unscannable_not_zero_hits() {
        let (_dir, db) = open();
        db.connection
            .execute_batch(
                "CREATE VIRTUAL TABLE residue_probe USING fts5(body, content='residue_missing', content_rowid='id')",
            )
            .expect("test: virtual table");
        let report = scan(&db);
        let probe = report
            .tables
            .iter()
            .find(|table| table.name == "residue_probe")
            .expect("test: probe listed");
        assert_eq!(probe.status, ResidueTableStatus::Unscannable);
        assert_eq!(probe.hits, None, "a failed virtual table must not report zero hits");
        assert_eq!(probe.locations.len(), 0);
        assert_eq!(report.status, ResidueScanStatus::Unscannable);
        let content = report
            .tables
            .iter()
            .find(|table| table.name == "runtime_message_content")
            .expect("test: content");
        assert_eq!(content.status, ResidueTableStatus::Scanned);
        assert_eq!(content.hits, Some(0));
    }
}
