// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Closed SQL text codecs exercise actual SQLite types and independent stream admission.
use super::*;
use crate::account_db::full_transfer::{CellRule, CodecRule, FieldRule, MergeRule};
use ramflux_protocol::custody::pairing::full_transfer::{Disposition, read_record_header};
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
static CELLS: [CellRule; 4] = [
    CellRule { name: "id", nullable: false, cell_type: CellType::Utf8 },
    CellRule { name: "state", nullable: true, cell_type: CellType::Utf8 },
    CellRule { name: "note", nullable: false, cell_type: CellType::Utf8 },
    CellRule { name: "revision", nullable: false, cell_type: CellType::I64 },
];
const fn field(name: &'static str, nullable: bool, codec: CodecRule) -> FieldRule {
    FieldRule {
        name,
        nullable,
        disposition: Disposition::Transfer,
        merge: MergeRule::Immutable,
        codec,
    }
}
static FIELDS: [FieldRule; 4] = [
    field(
        "id",
        false,
        CodecRule::SqlText { min_bytes: U64(1), max_bytes: U64(256), nullable: false },
    ),
    field("state", true, CodecRule::SqlEnum { values: &["blocked", "declined"], nullable: true }),
    field(
        "note",
        false,
        CodecRule::SqlText { min_bytes: U64(0), max_bytes: U64(32_768), nullable: false },
    ),
    field(
        "revision",
        false,
        CodecRule::SqlI64 { min: "0", max: "9223372036854775807", nullable: false },
    ),
];
const RULE: FamilyRule = FamilyRule {
    id: "sql/metadata_vector",
    selector: FamilySelector::Table("metadata_vector"),
    codec_version: U64(1),
    disposition: Disposition::Transfer,
    excluded: &[],
    key: &["id"],
    merge: MergeRule::Immutable,
    restrictive: false,
    cells: &CELLS,
    codec: &FIELDS,
    key_grammar_version: U64(1),
    restrictive_projection: &[],
};
fn encode(db: &rusqlite::Connection, output: &mut Vec<u8>) -> Result<u64, StorageError> {
    db.query_row("SELECT id,state,note,revision FROM metadata_vector", [], |row| {
        Ok(write_full_scalar_sql_row(&RULE, row, output))
    })?
}
#[test]
fn pairing_full_sql_metadata_round_trip_borrows_large_utf8_and_nullable_enum() -> TestResult {
    let db = rusqlite::Connection::open_in_memory()?;
    db.execute_batch(
        "CREATE TABLE metadata_vector(id TEXT,state TEXT,note TEXT,revision INTEGER);",
    )?;
    let note = "€".repeat(7000);
    db.execute("INSERT INTO metadata_vector VALUES('row','blocked',?1,42)", [&note])?;
    let mut bytes = Vec::new();
    assert_eq!(
        encode(&db, &mut bytes)?,
        bytes.len() as u64,
        "test: variable SQL cells changed encoded byte accounting"
    );
    let mut input = bytes.as_slice();
    let header = read_record_header(&mut input)?.ok_or("test: metadata header missing")?;
    let mut copied = Vec::new();
    copy_full_scalar_record(&RULE, &header, &mut input, &mut copied)?;
    let mut expected = b"rowblocked".to_vec();
    expected.extend_from_slice(note.as_bytes());
    expected.extend_from_slice(&42_i64.to_be_bytes());
    assert_eq!(copied, expected, "test: UTF-8 streaming altered field boundaries or exact values");
    assert!(input.is_empty(), "test: SQL metadata left unchecked bytes");
    db.execute("UPDATE metadata_vector SET state=NULL,note=''", [])?;
    let mut bytes = Vec::new();
    encode(&db, &mut bytes)?;
    let mut input = bytes.as_slice();
    let header = read_record_header(&mut input)?.ok_or("test: nullable header missing")?;
    copy_full_scalar_record(&RULE, &header, &mut input, &mut std::io::sink())?;
    assert_eq!(
        header.cell_types.get(1),
        Some(&CellType::Null),
        "test: SQL NULL became a token or an empty text value"
    );
    Ok(())
}
#[test]
fn pairing_full_sql_metadata_rejects_unknown_same_width_token_before_output() -> TestResult {
    let db = rusqlite::Connection::open_in_memory()?;
    db.execute_batch(
        "CREATE TABLE metadata_vector(id TEXT,state TEXT,note TEXT,revision INTEGER);
        INSERT INTO metadata_vector VALUES('row','granted','',1);",
    )?;
    let mut bytes = Vec::new();
    assert!(
        matches!(encode(&db, &mut bytes), Err(StorageError::PairingField("UnsupportedRecord"))),
        "test: closed SQL state accepted an unknown token of a valid width"
    );
    assert!(bytes.is_empty(), "test: source emitted bytes before semantic enum rejection");
    db.execute("UPDATE metadata_vector SET state='blocked'", [])?;
    encode(&db, &mut bytes)?;
    let mut input = bytes.as_slice();
    let header = read_record_header(&mut input)?.ok_or("test: source header missing")?;
    let mut bad = input.to_vec();
    bad.get_mut(3..10).ok_or("test: enum fixture range")?.copy_from_slice(b"granted");
    assert!(
        copy_full_scalar_record(&RULE, &header, &mut bad.as_slice(), &mut std::io::sink()).is_err(),
        "test: independent receiver accepted an unknown plain SQL state"
    );
    Ok(())
}
