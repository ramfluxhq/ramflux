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

#[test]
fn pairing_full_schema_inspection_refuses_incomplete_catalog_and_changed_columns() -> TestResult {
    use crate::{StorageError, database::Connection};
    static RULES: [FamilyRule; 2] = [HISTORY, DENIAL];
    let (root, actual) = crate::tests::test_db("full-schema-inspection")?;
    assert!(
        matches!(
            actual.inspect_full_transfer_schema(&RULES),
            Err(StorageError::PairingField("UnsupportedRecord"))
        ),
        "a partial catalog cannot inspect an actual production account as complete"
    );
    let fixture = Connection::open(root.join("schema-only-fixture.db"))?;
    fixture.execute_batch("CREATE TABLE catalog_vector(row_id INTEGER NOT NULL,body TEXT NOT NULL); INSERT INTO catalog_vector VALUES(1,'{}');")?;
    let census = super::inventory::inspect(&fixture, &RULES)?;
    assert_eq!(census.census_hash, full_census_hash(&RULES)?);
    assert_eq!(
        census.families.iter().map(|family| family.source_rows.0).collect::<Vec<_>>(),
        vec![1, 1]
    );
    assert!(
        census
            .families
            .iter()
            .all(|family| family.portable_records.0 == 0 && family.encoded_bytes.0 == 0),
        "schema counts do not certify unvalidated logical rows"
    );
    fixture.execute_batch("ALTER TABLE catalog_vector ADD COLUMN private_seed BLOB;")?;
    assert!(matches!(
        super::inventory::inspect(&fixture, &RULES),
        Err(StorageError::PairingField("SchemaMismatch"))
    ));
    fixture.execute_batch("CREATE TABLE unclassified_local_credentials(secret BLOB);")?;
    assert!(matches!(
        super::inventory::inspect(&fixture, &RULES),
        Err(StorageError::PairingField("UnsupportedRecord"))
    ));
    Ok(())
}

#[test]
fn pairing_full_fresh_catalog_covers_all_tables_and_refuses_unimplemented_value_owners()
-> TestResult {
    use super::catalog::full_transfer_catalog;
    use crate::StorageError;
    let (_root, db) = crate::tests::test_db("fresh-catalog-coverage")?;
    db.connection.execute(
        "INSERT INTO runtime_actor_state(state_kind,state_json) VALUES(?1,?2)",
        rusqlite::params!["full-transfer-unimplemented-owner", "{}"],
    )?;
    let rules = full_transfer_catalog();
    assert_eq!(rules.len(), 162);
    let census = match db.inspect_full_transfer_schema(rules) {
        Ok(census) => census,
        Err(error) => {
            for rule in rules {
                if let FamilySelector::Table(table) = rule.selector {
                    super::inventory::validate_columns(&db.connection, table, rule)
                        .map_err(|error| format!("compiled table {}: {error}", rule.id))?;
                }
            }
            return Err(error.into());
        }
    };
    let tables = rules
        .iter()
        .filter_map(|rule| match rule.selector {
            FamilySelector::Table(table) => Some(table),
            FamilySelector::ActorPrefix(_) => None,
        })
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(tables.len(), 156);
    assert!(
        matches!(
            census.require_typed_owners(rules),
            Err(StorageError::PairingField("UnsupportedRecord"))
        ),
        "complete table coverage cannot authorize copying a row whose typed owner is incomplete"
    );
    for table in
        ["pairing_floor", "pairing_live", "pairing_head", "pairing_adoption", "pairing_terminal"]
    {
        assert!(
            rules
                .iter()
                .filter(|rule| matches!(rule.selector,FamilySelector::Table(name) if name==table))
                .all(|rule| rule.disposition != Disposition::Transfer),
            "local native publication/issuer authority became portable"
        );
    }
    for (id, excluded) in [
        ("sql/object_index/portable", "ciphertext"),
        ("sql/object_chunk/portable", "local_path"),
        ("sql/object_chunk/portable", "chunk_state"),
        ("sql/guardian_recovery_share_projection/portable", "share_value"),
        ("sql/account_mac_bundle/portable", "is_current"),
    ] {
        let rule = rules.iter().find(|rule| rule.id == id).ok_or("family")?;
        assert!(rule.excluded.contains(&excluded));
        assert!(!rule.cells.iter().any(|cell| cell.name == excluded));
    }
    db.connection
        .execute_batch("CREATE TABLE newly_persisted_unclassified_family(secret BLOB);")?;
    assert!(matches!(
        db.inspect_full_transfer_schema(rules),
        Err(StorageError::PairingField("UnsupportedRecord"))
    ));
    Ok(())
}

#[test]
fn pairing_full_baseline_catalog_rule_and_census_hashes_match_independent_vectors() -> TestResult {
    let declarations: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../ramflux-protocol/fixtures/full_transfer/catalog-baseline-rules.json"
    ))?;
    let vectors: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../ramflux-protocol/fixtures/full_transfer/catalog-baseline-vectors.json"
    ))?;
    let rules = super::catalog::full_transfer_catalog();
    assert_eq!(declarations.as_array().ok_or("declarations")?.len(), rules.len());
    assert_eq!(vectors["rule_hashes"].as_array().ok_or("hashes")?.len(), rules.len());
    for (index, rule) in rules.iter().enumerate() {
        assert_eq!(
            serde_json::to_value(rule)?,
            declarations[index],
            "compiled declaration differs from independently hashed input: {}",
            rule.id
        );
        assert_eq!(rule.id, vectors["rule_hashes"][index]["id"].as_str().ok_or("id")?);
        assert_eq!(
            encode_base64url(rule.rule_hash()?),
            vectors["rule_hashes"][index]["hash"].as_str().ok_or("hash")?,
            "rule hash {}",
            rule.id
        );
    }
    assert_eq!(
        encode_base64url(full_census_hash(rules)?),
        vectors["census_hash"].as_str().ok_or("census")?
    );
    Ok(())
}

#[test]
fn pairing_full_local_migration_actor_checks_exact_kind_and_boolean_bytes() -> TestResult {
    let (_root, db) = crate::tests::test_db("full-local-migration-actor")?;
    let kind = crate::account_db::safety_verification::LEGACY_SAFETY_VERIFICATION_MARKER;
    db.connection.execute(
        "INSERT OR REPLACE INTO runtime_actor_state VALUES(?1,?2)",
        rusqlite::params![kind, b"true".as_slice()],
    )?;
    for invalid in [b"{}".as_slice(), b"true ", b"false ", b"\"true\""] {
        db.connection.execute(
            "UPDATE runtime_actor_state SET state_json=?1 WHERE state_kind=?2",
            rusqlite::params![invalid, kind],
        )?;
        assert!(matches!(
            db.inspect_full_transfer_schema(full_transfer_catalog()),
            Err(crate::StorageError::PairingField("UnsupportedRecord"))
        ));
    }
    db.connection.execute(
        "UPDATE runtime_actor_state SET state_json=?1 WHERE state_kind=?2",
        rusqlite::params![b"true".as_slice(), kind],
    )?;
    let schema = db.inspect_full_transfer_schema(full_transfer_catalog())?;
    schema.require_typed_owners(full_transfer_catalog())?;
    db.connection.execute(
        "INSERT INTO runtime_actor_state VALUES(?1,?2)",
        rusqlite::params![format!("{kind}/unknown"), b"true".as_slice()],
    )?;
    let schema = db.inspect_full_transfer_schema(full_transfer_catalog())?;
    assert!(matches!(
        schema.require_typed_owners(full_transfer_catalog()),
        Err(crate::StorageError::PairingField("UnsupportedRecord"))
    ));
    Ok(())
}

#[test]
fn pairing_full_local_group_upgrade_marker_is_exact_canonical_integer_metadata() -> TestResult {
    let (_root, db) = crate::tests::test_db("full-local-group-upgrade")?;
    for invalid in
        [b"{}".as_slice(), b"null", b"01", b"1.0", b"1e1", b"\"1\"", b"9223372036854775808"]
    {
        db.connection.execute("UPDATE runtime_actor_state SET state_json=?1 WHERE state_kind='group-message/upgrade-start'",rusqlite::params![invalid])?;
        assert!(matches!(
            db.inspect_full_transfer_schema(full_transfer_catalog()),
            Err(crate::StorageError::PairingField("UnsupportedRecord"))
        ));
    }
    db.connection.execute("UPDATE runtime_actor_state SET state_json=?1 WHERE state_kind='group-message/upgrade-start'",rusqlite::params![b"100".as_slice()])?;
    db.inspect_full_transfer_schema(full_transfer_catalog())?
        .require_typed_owners(full_transfer_catalog())?;
    db.connection.execute(
        "INSERT INTO runtime_actor_state VALUES('group-message/upgrade-start/unknown',?1)",
        rusqlite::params![b"100".as_slice()],
    )?;
    assert!(matches!(
        db.inspect_full_transfer_schema(full_transfer_catalog())?
            .require_typed_owners(full_transfer_catalog()),
        Err(crate::StorageError::PairingField("UnsupportedRecord"))
    ));
    Ok(())
}
