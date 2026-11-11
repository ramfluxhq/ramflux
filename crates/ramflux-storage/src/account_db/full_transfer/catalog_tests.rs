// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::catalog::*;
use ramflux_protocol::{
    canonical_json_bytes,
    custody::pairing::full_transfer::{CellType, Disposition, U64},
    encode_base64url,
};
type TestResult = Result<(), Box<dyn std::error::Error>>;
const fn field(
    name: &'static str,
    disposition: Disposition,
    merge: MergeRule,
    codec: CodecRule,
) -> FieldRule {
    FieldRule { name, nullable: false, disposition, merge, codec }
}
const NOTE: FieldRule = field(
    "note",
    Disposition::Transfer,
    MergeRule::PreferLocal,
    CodecRule::Scalar { cell_type: CellType::Utf8 },
);
const SECRET: FieldRule = field(
    "private_seed",
    Disposition::Exclude,
    MergeRule::Immutable,
    CodecRule::EncodedBytes { decoded_bytes: Some(U64(32)) },
);
const VETO: FieldRule =
    field("veto", Disposition::Transfer, MergeRule::RestrictUnion, CodecRule::DecimalU64);
static HISTORY_FIELDS: [FieldRule; 3] =
    [NOTE, SECRET, FieldRule { disposition: Disposition::Exclude, ..VETO }];
static VETO_FIELDS: [FieldRule; 3] =
    [FieldRule { disposition: Disposition::Exclude, ..NOTE }, SECRET, VETO];
static CHANGED_HISTORY_FIELDS: [FieldRule; 3] = [
    NOTE,
    FieldRule { disposition: Disposition::Transfer, ..SECRET },
    FieldRule { disposition: Disposition::Exclude, ..VETO },
];
static CHANGED_VETO_FIELDS: [FieldRule; 3] = [
    FieldRule { disposition: Disposition::Exclude, ..NOTE },
    SECRET,
    FieldRule { merge: MergeRule::PreferLocal, ..VETO },
];
const ID: FieldRule = field(
    "row_id",
    Disposition::Transfer,
    MergeRule::Immutable,
    CodecRule::Scalar { cell_type: CellType::I64 },
);
const fn body(fields: &'static [FieldRule], merge: MergeRule) -> FieldRule {
    field("body", Disposition::Transfer, merge, CodecRule::Object { fields })
}
static HISTORY_CODEC: [FieldRule; 2] = [ID, body(&HISTORY_FIELDS, MergeRule::InertHistory)];
static VETO_CODEC: [FieldRule; 2] = [ID, body(&VETO_FIELDS, MergeRule::RestrictUnion)];
static CHANGED_HISTORY_CODEC: [FieldRule; 2] =
    [ID, body(&CHANGED_HISTORY_FIELDS, MergeRule::InertHistory)];
static CHANGED_VETO_CODEC: [FieldRule; 2] =
    [ID, body(&CHANGED_VETO_FIELDS, MergeRule::RestrictUnion)];
static CELLS: [CellRule; 2] = [
    CellRule { name: "row_id", nullable: false, cell_type: CellType::I64 },
    CellRule { name: "body", nullable: false, cell_type: CellType::Utf8 },
];
const HISTORY: FamilyRule = FamilyRule {
    cells: &CELLS,
    codec_version: U64(1),
    disposition: Disposition::Transfer,
    excluded: &[],
    id: "sql/catalog_vector/history",
    key: &["row_id"],
    merge: MergeRule::InertHistory,
    restrictive: false,
    selector: FamilySelector::Table("catalog_vector"),
    codec: &HISTORY_CODEC,
    key_grammar_version: U64(1),
    restrictive_projection: &[],
};
const DENIAL: FamilyRule = FamilyRule {
    id: "sql/catalog_vector/veto",
    codec: &VETO_CODEC,
    merge: MergeRule::RestrictUnion,
    restrictive: true,
    restrictive_projection: &["/body/veto"],
    ..HISTORY
};
#[test]
fn pairing_full_recursive_rule_hashes_pin_nested_disposition_merge_and_projection() -> TestResult {
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../ramflux-protocol/fixtures/full_transfer/catalog.json"
    ))?;
    for (index, rule) in [HISTORY, DENIAL].iter().enumerate() {
        assert_eq!(serde_json::to_value(rule)?, fixture["rules"][index]);
        assert_eq!(
            encode_base64url(rule.rule_hash()?),
            fixture["rule_hashes"][index].as_str().ok_or("rule hash")?
        );
        assert_eq!(rule.manifest_family()?.rule_hash, encode_base64url(rule.rule_hash()?));
    }
    assert_eq!(
        encode_base64url(full_census_hash(&[HISTORY, DENIAL])?),
        fixture["census_hash"].as_str().ok_or("census hash")?
    );
    let changed = FamilyRule { codec: &CHANGED_HISTORY_CODEC, ..HISTORY };
    assert_ne!(
        changed.rule_hash()?,
        HISTORY.rule_hash()?,
        "nested exclusion was omitted from the commitment"
    );
    assert_eq!(
        encode_base64url(changed.rule_hash()?),
        fixture["changed_nested_disposition_hash"].as_str().ok_or("nested disposition")?
    );
    let changed = FamilyRule { codec: &CHANGED_VETO_CODEC, ..DENIAL };
    assert_ne!(
        changed.rule_hash()?,
        DENIAL.rule_hash()?,
        "nested merge was omitted from the commitment"
    );
    assert_eq!(
        encode_base64url(changed.rule_hash()?),
        fixture["changed_nested_merge_hash"].as_str().ok_or("nested merge")?
    );
    assert_ne!(full_census_hash(&[HISTORY, changed])?, full_census_hash(&[HISTORY, DENIAL])?);
    assert!(full_census_hash(&[DENIAL, HISTORY]).is_err());
    assert!(full_census_hash(&[HISTORY, HISTORY]).is_err());
    assert!(full_census_hash(&[]).is_err());
    let bytes = canonical_json_bytes(&HISTORY)?;
    assert!(
        bytes.windows(b"private_seed".len()).any(|window| window == b"private_seed"),
        "schema exclusion names are hash operands, never dropped along with the excluded values"
    );
    Ok(())
}
#[test]
fn pairing_full_recursive_rule_refuses_unknown_fields_keys_and_unbounded_descriptors() {
    static RECURSIVE: CodecRule = CodecRule::Array { element: &RECURSIVE };
    static CYCLE: [FieldRule; 2] = [
        ID,
        field(
            "body",
            Disposition::Transfer,
            MergeRule::Immutable,
            CodecRule::Array { element: &RECURSIVE },
        ),
    ];
    let invalid = [
        FamilyRule { codec: &CYCLE, ..HISTORY },
        FamilyRule { key: &["private_seed"], ..HISTORY },
        FamilyRule { key: &["row_id", "row_id"], ..HISTORY },
        FamilyRule { excluded: &["row_id"], ..HISTORY },
        FamilyRule { codec: &[], ..HISTORY },
        FamilyRule { selector: FamilySelector::Table("another_table"), ..HISTORY },
        FamilyRule { restrictive_projection: &["/body/private_seed"], ..DENIAL },
        FamilyRule { restrictive_projection: &["/body/unknown"], ..DENIAL },
        FamilyRule { restrictive_projection: &["/body/veto"], ..HISTORY },
        FamilyRule { key_grammar_version: U64(2), ..HISTORY },
    ];
    for rule in invalid {
        assert!(rule.rule_hash().is_err());
    }
}
