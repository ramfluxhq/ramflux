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
