// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::{catalog::*, scalar::copy_full_scalar_record};
use ramflux_protocol::custody::pairing::full_transfer::{CellType, *};
use std::io::{Cursor, Read, Write};
use zeroize::Zeroizing;
type TestResult = Result<(), Box<dyn std::error::Error>>;
const CELLS: [CellRule; 2] = [
    CellRule { name: "row_id", nullable: false, cell_type: CellType::I64 },
    CellRule { name: "body", nullable: true, cell_type: CellType::Bytes },
];
const FIELDS: [FieldRule; 2] = [
    FieldRule {
        name: "row_id",
        nullable: false,
        disposition: Disposition::Transfer,
        merge: MergeRule::Immutable,
        codec: CodecRule::Scalar { cell_type: CellType::I64 },
    },
    FieldRule {
        name: "body",
        nullable: true,
        disposition: Disposition::Transfer,
        merge: MergeRule::Immutable,
        codec: CodecRule::Scalar { cell_type: CellType::Bytes },
    },
];
const RULE: FamilyRule = FamilyRule {
    cells: &CELLS,
    codec_version: U64(1),
    disposition: Disposition::Transfer,
    excluded: &[],
    id: "sql/scalar_fixture",
    key: &["row_id"],
    merge: MergeRule::Immutable,
    restrictive: false,
    selector: FamilySelector::Table("scalar_fixture"),
    codec: &FIELDS,
    key_grammar_version: U64(1),
    restrictive_projection: &[],
};

#[test]
fn pairing_full_erasure_scalar_codecs_check_actual_hash_formats_and_absent_keys() -> TestResult {
    let commitment = ramflux_crypto::object_erasure_commitment("root", "wire", "manifest");
    for (table, kind, value) in [
        ("object_erasure_fence", CellType::Utf8, commitment.as_bytes().to_vec()),
        ("object_identity_replacement", CellType::Utf8, commitment.as_bytes().to_vec()),
        ("object_segment_reference_veto", CellType::Bytes, vec![17; 32]),
    ] {
        let rule = super::full_transfer_catalog()
            .iter()
            .find(|rule| matches!(rule.selector,FamilySelector::Table(name) if name==table))
            .ok_or("rule")?;
        assert_eq!(rule.codec_version, U64(2));
        rule.require_typed_codec().map_err(|error| format!("{table} declaration: {error}"))?;
        let mut header = RecordHeader {
            family: rule.id.into(),
            codec_version: rule.codec_version,
            key: if rule.key.is_empty() {
                encode_keyless_row_key([(kind, value.as_slice())], 0)?.to_string()
            } else {
                encode_stable_key([(kind, value.as_slice())])?.to_string()
            },
            op: RecordOp::Put,
            cell_types: vec![kind],
            cell_lengths: vec![U64(value.len() as u64)],
        };
        let mut output = Zeroizing::new(Vec::new());
        copy_full_scalar_record(rule, &header, &mut value.as_slice(), &mut *output)
            .map_err(|error| format!("{table} put: {error}"))?;
        assert_eq!(output.as_slice(), value.as_slice());
        header.op = RecordOp::Absent;
        header.cell_types.clear();
        header.cell_lengths.clear();
        copy_full_scalar_record(rule, &header, &mut [].as_slice(), &mut std::io::sink())
            .map_err(|error| format!("{table} absent: {error}"))?;
        for invalid in [vec![], vec![b'A'; 31], vec![b'A'; 44]] {
            header.key = encode_stable_key([(kind, invalid.as_slice())])?.to_string();
            assert!(
                copy_full_scalar_record(rule, &header, &mut [].as_slice(), &mut std::io::sink())
                    .is_err()
            );
        }
        if kind == CellType::Utf8 {
            let mut noncanonical = ramflux_protocol::encode_base64url([0; 32]).into_bytes();
            noncanonical[42] = b'B';
            header.key = encode_stable_key([(kind, noncanonical.as_slice())])?.to_string();
            assert!(
                copy_full_scalar_record(rule, &header, &mut [].as_slice(), &mut std::io::sink())
                    .is_err()
            );
        }
        header.key = encode_stable_key([(CellType::Null, [].as_slice())])?.to_string();
        assert!(
            copy_full_scalar_record(rule, &header, &mut [].as_slice(), &mut std::io::sink())
                .is_err()
        );
    }
    Ok(())
}

#[test]
fn pairing_full_erasure_generation_is_nonnegative_and_singleton_key_is_exact() -> TestResult {
    let rule = super::full_transfer_catalog()
        .iter()
        .find(|rule| rule.id == "sql/account_erasure_generation")
        .ok_or("generation rule")?;
    rule.require_typed_codec()?;
    for (singleton, generation, valid) in
        [(1_i64, 0_i64, true), (1, i64::MAX, true), (1, -1, false), (2, 0, false)]
    {
        let mut bytes = Zeroizing::new(singleton.to_be_bytes().to_vec());
        bytes.extend_from_slice(&generation.to_be_bytes());
        let header = RecordHeader {
            family: rule.id.into(),
            codec_version: U64(2),
            key: encode_stable_key([(CellType::I64, singleton.to_be_bytes().as_slice())])?
                .to_string(),
            op: RecordOp::Put,
            cell_types: vec![CellType::I64; 2],
            cell_lengths: vec![U64(8); 2],
        };
        assert_eq!(
            copy_full_scalar_record(rule, &header, &mut bytes.as_slice(), &mut std::io::sink())
                .is_ok(),
            valid
        );
        let absent = RecordHeader {
            op: RecordOp::Absent,
            cell_types: vec![],
            cell_lengths: vec![],
            ..header
        };
        assert_eq!(
            copy_full_scalar_record(rule, &absent, &mut [].as_slice(), &mut std::io::sink())
                .is_ok(),
            singleton == 1
        );
    }
    Ok(())
}
fn header(key: String, body: usize) -> RecordHeader {
    RecordHeader {
        family: RULE.id.into(),
        codec_version: U64(1),
        key,
        op: RecordOp::Put,
        cell_types: vec![CellType::I64, CellType::Bytes],
        cell_lengths: vec![U64(8), U64(body as u64)],
    }
}
#[derive(Default)]
struct BoundedSink {
    count: usize,
    largest: usize,
}
impl Write for BoundedSink {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.largest = self.largest.max(bytes.len());
        self.count += bytes.len();
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
#[test]
fn pairing_full_scalar_record_checks_compiled_cells_and_body_key_with_bounded_copy() -> TestResult {
    let integer = 7_i64.to_be_bytes();
    let body = Zeroizing::new(vec![92; 40001]);
    let key = encode_stable_key([(CellType::I64, integer.as_slice())])?;
    let h = header(key.to_string(), body.len());
    let mut input = Zeroizing::new(integer.to_vec());
    input.extend_from_slice(&body);
    let mut sink = BoundedSink::default();
    copy_full_scalar_record(&RULE, &h, &mut Cursor::new(input.as_slice()), &mut sink)?;
    assert_eq!(sink.count, input.len());
    assert!(sink.largest <= 16384);
    let wrong = header(
        encode_stable_key([(CellType::I64, 8_i64.to_be_bytes().as_slice())])?.to_string(),
        body.len(),
    );
    assert!(
        copy_full_scalar_record(
            &RULE,
            &wrong,
            &mut Cursor::new(input.as_slice()),
            &mut std::io::sink()
        )
        .is_err(),
        "header key does not bind its actual body cells"
    );
    let mut wrong = h.clone();
    wrong.cell_types[0] = CellType::Utf8;
    assert!(
        copy_full_scalar_record(
            &RULE,
            &wrong,
            &mut Cursor::new(input.as_slice()),
            &mut std::io::sink()
        )
        .is_err()
    );
    let mut nullable = h.clone();
    nullable.cell_types[1] = CellType::Null;
    nullable.cell_lengths[1] = U64(0);
    copy_full_scalar_record(&RULE, &nullable, &mut Cursor::new(integer), &mut std::io::sink())?;
    Ok(())
}
#[test]
fn pairing_full_scalar_keyless_record_binds_all_cells_and_preserves_occurrences() -> TestResult {
    let rule = FamilyRule { key: &[], ..RULE };
    let integer = (-2_i64).to_be_bytes();
    let body = b"same row twice";
    let mut input = Zeroizing::new(integer.to_vec());
    input.extend_from_slice(body);
    let mut keys = Vec::new();
    for occurrence in [0, 1] {
        let key = encode_keyless_row_key(
            [(CellType::I64, integer.as_slice()), (CellType::Bytes, body.as_slice())],
            occurrence,
        )?;
        let h = header(key.to_string(), body.len());
        copy_full_scalar_record(
            &rule,
            &h,
            &mut Cursor::new(input.as_slice()),
            &mut std::io::sink(),
        )?;
        let mut changed = Zeroizing::new(input.to_vec());
        changed[8] ^= 1;
        assert!(
            copy_full_scalar_record(
                &rule,
                &h,
                &mut Cursor::new(changed.as_slice()),
                &mut std::io::sink()
            )
            .is_err()
        );
        keys.push(key);
    }
    assert_ne!(keys[0].as_str(), keys[1].as_str());
    Ok(())
}
struct NoRead;
impl Read for NoRead {
    fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
        Err(std::io::Error::other("BODY_MUST_NOT_BE_READ"))
    }
}
#[test]
fn pairing_full_scalar_requires_owner_refuses_before_reading_any_value_including_null() -> TestResult
{
    static UNOWNED: [FieldRule; 2] = [
        FieldRule {
            codec: CodecRule::RequiresOwner { owner: "scalar_fixture", cell_type: CellType::I64 },
            ..FIELDS[0]
        },
        FIELDS[1],
    ];
    static NULL_OWNER: [FieldRule; 2] = [
        FIELDS[0],
        FieldRule {
            codec: CodecRule::RequiresOwner {
                owner: "scalar_fixture/body",
                cell_type: CellType::Bytes,
            },
            ..FIELDS[1]
        },
    ];
    let rule = FamilyRule { codec: &UNOWNED, ..RULE };
    let h = header(
        encode_stable_key([(CellType::I64, 7_i64.to_be_bytes().as_slice())])?.to_string(),
        0,
    );
    assert!(matches!(
        copy_full_scalar_record(&rule, &h, &mut NoRead, &mut std::io::sink()),
        Err(crate::StorageError::PairingField("UnsupportedRecord"))
    ));
    let rule = FamilyRule { codec: &NULL_OWNER, ..RULE };
    let mut null = h;
    null.cell_types[1] = CellType::Null;
    assert!(
        matches!(
            copy_full_scalar_record(
                &rule,
                &null,
                &mut Cursor::new(7_i64.to_be_bytes()),
                &mut std::io::sink()
            ),
            Err(crate::StorageError::PairingField("UnsupportedRecord"))
        ),
        "null is not permission to bypass an incomplete typed owner"
    );
    Ok(())
}

#[test]
fn pairing_full_sql_source_rows_use_actual_types_and_refuse_before_output() -> TestResult {
    let db = rusqlite::Connection::open_in_memory()?;
    let commitment = ramflux_crypto::object_erasure_commitment("root", "wire", "manifest");
    for (table, declaration, value) in [
        ("object_erasure_fence", "TEXT", rusqlite::types::Value::Text(commitment.clone())),
        ("object_identity_replacement", "TEXT", rusqlite::types::Value::Text(commitment.clone())),
        ("object_segment_reference_veto", "BLOB", rusqlite::types::Value::Blob(vec![3; 32])),
    ] {
        let rule = super::full_transfer_catalog()
            .iter()
            .find(|rule| matches!(rule.selector, FamilySelector::Table(name) if name == table))
            .ok_or("rule")?;
        let column = rule.cells[0].name;
        db.execute_batch(&format!("CREATE TABLE {table}({column} {declaration})"))?;
        db.execute(&format!("INSERT INTO {table} VALUES(?1)"), [&value])?;
        let mut query = db.prepare(&format!("SELECT {column} FROM {table}"))?;
        let mut rows = query.query([])?;
        let mut output = Zeroizing::new(Vec::new());
        let count =
            super::write_full_scalar_sql_row(rule, rows.next()?.ok_or("row")?, &mut *output)?;
        assert_eq!(count, output.len() as u64);
        let mut input = output.as_slice();
        let header = read_record_header(&mut input)?.ok_or("header")?;
        assert_eq!(header.family, rule.id);
        copy_full_scalar_record(rule, &header, &mut input, &mut std::io::sink())?;
        assert_eq!(input, b"");
        drop(rows);
        // SQLite affinity does not make a TEXT/BLOB owner interchangeable.
        db.execute(
            &format!("UPDATE {table} SET {column}=?1"),
            [rusqlite::types::Value::Integer(7)],
        )?;
        let mut rows = query.query([])?;
        output.clear();
        assert!(
            super::write_full_scalar_sql_row(rule, rows.next()?.ok_or("bad row")?, &mut *output)
                .is_err()
        );
        assert!(output.is_empty());
    }
    let rule = super::full_transfer_catalog()
        .iter()
        .find(|rule| rule.id == "sql/account_erasure_generation")
        .ok_or("generation")?;
    db.execute_batch("CREATE TABLE account_erasure_generation(singleton INTEGER,generation INTEGER); INSERT INTO account_erasure_generation VALUES(1,8)")?;
    for (sql, valid) in [
        ("SELECT singleton,generation FROM account_erasure_generation", true),
        ("SELECT generation,singleton FROM account_erasure_generation", false),
        ("SELECT 2 AS singleton,8 AS generation", false),
        ("SELECT 1 AS singleton,-1 AS generation", false),
        ("SELECT 1 AS singleton,NULL AS generation", false),
        ("SELECT 1 AS singleton,1.0 AS generation", false),
    ] {
        let mut query = db.prepare(sql)?;
        let mut rows = query.query([])?;
        let mut output = Zeroizing::new(Vec::new());
        let result =
            super::write_full_scalar_sql_row(rule, rows.next()?.ok_or("row")?, &mut *output);
        assert_eq!(result.is_ok(), valid, "{sql}");
        assert_eq!(output.is_empty(), !valid);
    }
    Ok(())
}

#[test]
fn pairing_full_sql_erasure_links_validate_both_columns_and_composite_absent_keys() -> TestResult {
    let db = rusqlite::Connection::open_in_memory()?;
    let lookup = ramflux_crypto::object_erasure_lookup("root", "wire");
    let commitment = ramflux_crypto::object_erasure_commitment("root", "wire", "manifest");
    for (family, first, second) in [
        ("sql/object_erasure_lookup", lookup.as_str(), commitment.as_str()),
        ("sql/object_payload_dependency", commitment.as_str(), lookup.as_str()),
    ] {
        let rule =
            super::full_transfer_catalog().iter().find(|rule| rule.id == family).ok_or("rule")?;
        assert_eq!(rule.codec_version, U64(2));
        let mut query = db.prepare(&format!(
            "SELECT ?1 AS {},?2 AS {}",
            rule.cells[0].name, rule.cells[1].name
        ))?;
        let mut rows = query.query([first, second])?;
        let mut output = Zeroizing::new(Vec::new());
        super::write_full_scalar_sql_row(rule, rows.next()?.ok_or("row")?, &mut *output)?;
        let mut input = output.as_slice();
        let header = read_record_header(&mut input)?.ok_or("header")?;
        copy_full_scalar_record(rule, &header, &mut input, &mut std::io::sink())?;
        assert_eq!(input, b"");
        let expected = if rule.key.len() == 2 {
            encode_stable_key([
                (CellType::Utf8, first.as_bytes()),
                (CellType::Utf8, second.as_bytes()),
            ])?
        } else {
            encode_stable_key([(CellType::Utf8, first.as_bytes())])?
        };
        assert_eq!(header.key, expected.as_str());
        let mut absent = RecordHeader {
            op: RecordOp::Absent,
            cell_types: vec![],
            cell_lengths: vec![],
            ..header
        };
        copy_full_scalar_record(rule, &absent, &mut [].as_slice(), &mut std::io::sink())?;
        if rule.key.len() == 2 {
            absent.key = encode_stable_key([(CellType::Utf8, first.as_bytes())])?.to_string();
            assert!(
                copy_full_scalar_record(rule, &absent, &mut [].as_slice(), &mut std::io::sink())
                    .is_err()
            );
        }
        drop(rows);
        let mut noncanonical = ramflux_protocol::encode_base64url([0; 32]).into_bytes();
        noncanonical[42] = b'B';
        let noncanonical = std::str::from_utf8(&noncanonical)?;
        for values in [[noncanonical, second], [first, noncanonical]] {
            let mut rows = query.query(values)?;
            output.clear();
            assert!(
                super::write_full_scalar_sql_row(rule, rows.next()?.ok_or("row")?, &mut *output)
                    .is_err()
            );
            assert!(output.is_empty());
        }
    }
    Ok(())
}

#[test]
fn pairing_full_sql_mac_subkeys_require_their_exact_bundle_id_and_exclude_current_flag()
-> TestResult {
    let db = rusqlite::Connection::open_in_memory()?;
    let rule = super::full_transfer_catalog()
        .iter()
        .find(|rule| rule.id == "sql/account_mac_bundle/portable")
        .ok_or("MAC rule")?;
    let keys = Zeroizing::new([165_u8; 192]);
    let id = super::super::mac_subkeys::bundle_id(keys.as_slice());
    assert_eq!(id, "mnymtMasQSG9iueQpJZpmop3htW8Uo5fgM2n-4N1QT4"); // Independent Python hashlib.sha256 vector.
    let mut query = db.prepare("SELECT ?1 AS bundle_id,?2 AS subkeys")?;
    let mut rows = query.query(rusqlite::params![id, keys.as_slice()])?;
    let mut output = Zeroizing::new(Vec::new());
    super::write_full_scalar_sql_row(rule, rows.next()?.ok_or("row")?, &mut *output)?;
    let mut input = output.as_slice();
    let header = read_record_header(&mut input)?.ok_or("header")?;
    assert_eq!(header.cell_types, [CellType::Utf8, CellType::Bytes]);
    assert_eq!(input.len(), 43 + 192);
    assert_eq!(&input[43..], keys.as_slice());
    copy_full_scalar_record(rule, &header, &mut input, &mut std::io::sink())?;
    assert_eq!(input, b"");
    drop(rows);
    let mut changed = Zeroizing::new(*keys);
    changed[191] ^= 1;
    let foreign_id = ramflux_protocol::encode_base64url([0; 32]);
    for (identifier, secret) in [
        (id.as_str(), changed.as_slice()),
        (id.as_str(), &keys[..191]),
        (foreign_id.as_str(), keys.as_slice()),
    ] {
        let mut rows = query.query(rusqlite::params![identifier, secret])?;
        output.clear();
        assert!(
            super::write_full_scalar_sql_row(rule, rows.next()?.ok_or("bad row")?, &mut *output)
                .is_err()
        );
        assert!(output.is_empty());
    }
    let mut extra = db.prepare("SELECT ?1 AS bundle_id,?2 AS subkeys,1 AS is_current")?;
    let mut rows = extra.query(rusqlite::params![id, keys.as_slice()])?;
    output.clear();
    assert!(
        super::write_full_scalar_sql_row(rule, rows.next()?.ok_or("extra row")?, &mut *output)
            .is_err()
    );
    assert!(output.is_empty());
    Ok(())
}
