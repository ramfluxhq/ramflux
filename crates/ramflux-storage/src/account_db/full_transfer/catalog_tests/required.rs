// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Independent recursive catalog/cell vectors and actual repeated SQLite REAL values.
//! These grammar fixtures add no production T owner or incomplete-source admission.
use super::{
    CHANGED_HISTORY_CODEC, CHANGED_VETO_CODEC, CellRule, CellType, CodecRule, DENIAL, Disposition,
    FamilyRule, FamilySelector, FieldRule, HISTORY, MergeRule, TestResult, U64, encode_base64url,
    full_census_hash,
};
use ramflux_protocol::custody::pairing::{
    WireError,
    full_transfer::{RecordHeader, RecordOp, encode_keyless_row_key, encode_stable_key},
};
const KINDS: [CellType; 5] =
    [CellType::Null, CellType::I64, CellType::F64, CellType::Utf8, CellType::Bytes];
const NAMES: [&str; 5] = ["n", "i", "r", "t", "b"];
const fn cell(index: usize) -> CellRule {
    CellRule {
        name: NAMES[index],
        nullable: index == 0,
        cell_type: if index == 0 { CellType::Bytes } else { KINDS[index] },
    }
}
const fn codec(index: usize) -> FieldRule {
    FieldRule {
        name: NAMES[index],
        nullable: index == 0,
        disposition: Disposition::Transfer,
        merge: MergeRule::Immutable,
        codec: CodecRule::Scalar {
            cell_type: if index == 0 { CellType::Bytes } else { KINDS[index] },
        },
    }
}
static CELLS: [CellRule; 5] = [cell(0), cell(1), cell(2), cell(3), cell(4)];
static CODECS: [FieldRule; 5] = [codec(0), codec(1), codec(2), codec(3), codec(4)];
const FIVE: FamilyRule = FamilyRule {
    id: "sql/five_cell_vector",
    selector: FamilySelector::Table("five_cell_vector"),
    key: &[],
    cells: &CELLS,
    codec: &CODECS,
    merge: MergeRule::Immutable,
    ..HISTORY
};
static REAL_CELL: [CellRule; 1] = [cell(2)];
static REAL_CODEC: [FieldRule; 1] = [codec(2)];
const REAL: FamilyRule = FamilyRule {
    id: "sql/repeated_real",
    selector: FamilySelector::Table("repeated_real"),
    cells: &REAL_CELL,
    codec: &REAL_CODEC,
    ..FIVE
};

#[test]
fn pairing_full_recursive_catalog_and_keys_are_pinned() -> TestResult {
    let changed_history = FamilyRule { codec: &CHANGED_HISTORY_CODEC, ..HISTORY };
    let changed_veto = FamilyRule { codec: &CHANGED_VETO_CODEC, ..DENIAL };
    // These semantic assertions precede the pinned hashes so the required BtF
    // detects omitted recursive operands, rather than only a fixture mismatch.
    assert_ne!(
        HISTORY.rule_hash()?,
        changed_history.rule_hash()?,
        "recursive exclusion descriptor was omitted from rule_hash"
    );
    assert_ne!(
        DENIAL.rule_hash()?,
        changed_veto.rule_hash()?,
        "recursive merge descriptor was omitted from rule_hash"
    );
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../../ramflux-protocol/fixtures/full_transfer/catalog.json"
    ))?;
    assert_eq!(
        encode_base64url(full_census_hash(&[HISTORY, DENIAL])?),
        fixture["census_hash"].as_str().ok_or("census vector")?
    );
    assert_eq!(
        encode_base64url(changed_history.rule_hash()?),
        fixture["changed_nested_disposition_hash"].as_str().ok_or("nested exclusion vector")?
    );
    assert_eq!(
        encode_base64url(changed_veto.rule_hash()?),
        fixture["changed_nested_merge_hash"].as_str().ok_or("nested merge vector")?
    );
    let (_, mut manifest, _) = super::super::stage_tests::fixture()?;
    manifest.manifest.families = vec![HISTORY.manifest_family()?, DENIAL.manifest_family()?];
    manifest.manifest.census_hash = encode_base64url(full_census_hash(&[HISTORY, DENIAL])?);
    manifest.manifest.chunks_root = encode_base64url(
        ramflux_protocol::custody::pairing::full_transfer::RootHasher::new(0)?.finish()?,
    );
    manifest.manifest.total_bytes = U64(0);
    manifest.manifest.chunk_count = U64(0);
    manifest.manifest.validate_catalog(&manifest.manifest.families, false)?;
    for rules in [[changed_history, DENIAL], [HISTORY, changed_veto]] {
        let expected =
            rules.iter().map(FamilyRule::manifest_family).collect::<Result<Vec<_>, _>>()?;
        assert_eq!(
            manifest.manifest.validate_catalog(&expected, false),
            Err(WireError::Field("SchemaMismatch")),
            "changed recursive semantics were silently interpreted"
        );
        assert_ne!(full_census_hash(&rules)?, full_census_hash(&[HISTORY, DENIAL])?);
    }
    let reverse = vec![DENIAL.manifest_family()?];
    manifest.manifest.families = reverse;
    manifest
        .manifest
        .validate_catalog(&[HISTORY.manifest_family()?, DENIAL.manifest_family()?], true)?;
    assert!(
        manifest
            .manifest
            .validate_catalog(&[HISTORY.manifest_family()?, DENIAL.manifest_family()?], false)
            .is_err(),
        "split restrictive projection became full history"
    );
    five_cell_vectors()?;
    repeated_real_rows()?;
    Ok(())
}
fn hex(value: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if !value.len().is_multiple_of(2) {
        return Err("odd vector hex".into());
    }
    (0..value.len())
        .step_by(2)
        .map(|index| Ok(u8::from_str_radix(&value[index..index + 2], 16)?))
        .collect()
}
fn five_cell_vectors() -> TestResult {
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../../ramflux-protocol/fixtures/full_transfer/keys.json"
    ))?;
    let cells = fixture["cells"]
        .as_array()
        .ok_or("cells")?
        .iter()
        .map(|cell| hex(cell["hex"].as_str().ok_or("hex")?))
        .collect::<Result<Vec<_>, _>>()?;
    let stable = encode_stable_key(KINDS.into_iter().zip(cells.iter().map(Vec::as_slice)))?;
    assert_eq!(stable.as_str(), fixture["stable_key"].as_str().ok_or("stable key")?);
    let body = cells.concat();
    for vector in fixture["occurrences"].as_array().ok_or("occurrences")? {
        let occurrence = u32::try_from(vector["occurrence"].as_u64().ok_or("occurrence")?)?;
        let key = encode_keyless_row_key(
            KINDS.into_iter().zip(cells.iter().map(Vec::as_slice)),
            occurrence,
        )?;
        assert_eq!(key.as_str(), vector["key"].as_str().ok_or("key vector")?);
        let header = RecordHeader {
            family: FIVE.id.into(),
            codec_version: FIVE.codec_version,
            key: key.to_string(),
            op: RecordOp::Put,
            cell_types: KINDS.to_vec(),
            cell_lengths: cells.iter().map(|bytes| U64(bytes.len() as u64)).collect(),
        };
        let mut output = Vec::new();
        super::super::copy_full_scalar_record(&FIVE, &header, &mut body.as_slice(), &mut output)?;
        assert_eq!(output, body);
        let mut altered = body.clone();
        *altered.get_mut(8).ok_or("REAL vector cell")? ^= 0x80; // -0.0 -> +0.0 changes the raw REAL cell/key.
        assert!(
            super::super::copy_full_scalar_record(
                &FIVE,
                &header,
                &mut altered.as_slice(),
                &mut std::io::sink()
            )
            .is_err(),
            "F64 bit identity was lost"
        );
    }
    Ok(())
}
fn repeated_real_rows() -> TestResult {
    let db = rusqlite::Connection::open_in_memory()?;
    db.execute_batch(
        "CREATE TABLE repeated_real(r REAL); INSERT INTO repeated_real VALUES(1.25),(1.25)",
    )?;
    let mut statement = db.prepare("SELECT r FROM repeated_real")?;
    let mut rows = statement.query([])?;
    let domain = b"ramflux.pairing.full.rowkey.v1";
    let mut seen = Vec::new();
    while let Some(row) = rows.next()? {
        let rusqlite::types::ValueRef::Real(real) = row.get_ref(0)? else {
            return Err("actual REAL row".into());
        };
        assert_eq!(real.to_bits(), 0x3ff4_0000_0000_0000);
        let bytes = real.to_be_bytes();
        // Independent framing, with the actual REAL bytes and no rowid/stable-key shortcut.
        let mut framed = u32::try_from(domain.len())?.to_be_bytes().to_vec();
        framed.extend_from_slice(domain);
        framed.push(2);
        framed.extend_from_slice(&8_u32.to_be_bytes());
        framed.extend_from_slice(&bytes);
        let mut expected = blake3::hash(&framed).as_bytes().to_vec();
        expected.extend_from_slice(&u32::try_from(seen.len())?.to_be_bytes());
        let key = encode_keyless_row_key(
            [(CellType::F64, bytes.as_slice())],
            u32::try_from(seen.len())?,
        )?;
        assert_eq!(key.as_str(), encode_base64url(expected));
        let header = RecordHeader {
            family: REAL.id.into(),
            codec_version: REAL.codec_version,
            key: key.to_string(),
            op: RecordOp::Put,
            cell_types: vec![CellType::F64],
            cell_lengths: vec![U64(8)],
        };
        super::super::copy_full_scalar_record(
            &REAL,
            &header,
            &mut bytes.as_slice(),
            &mut std::io::sink(),
        )?;
        seen.push(key);
    }
    assert_eq!(seen.len(), 2);
    assert_ne!(
        seen.first().ok_or("first REAL occurrence")?.as_str(),
        seen.get(1).ok_or("second REAL occurrence")?.as_str(),
        "duplicate REAL rows collapsed"
    );
    Ok(())
}
