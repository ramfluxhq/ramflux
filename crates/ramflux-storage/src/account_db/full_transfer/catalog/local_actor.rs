// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Exact local migration markers. Unknown descendants are never excluded by prefix.
use super::{
    CellType, CodecRule, Disposition, FamilyRule, FamilySelector, FieldRule, MergeRule, U64,
};
use crate::{StorageError, database::Connection};
use rusqlite::OptionalExtension as _;

const SAFETY: &str = crate::account_db::safety_verification::LEGACY_SAFETY_VERIFICATION_MARKER;
const GROUP: &str = "group-message/upgrade-start";
const fn local_rule(
    id: &'static str,
    kind: &'static str,
    fields: &'static [FieldRule],
) -> FamilyRule {
    FamilyRule {
        id,
        selector: FamilySelector::ActorPrefix(kind),
        codec_version: U64(1),
        key_grammar_version: U64(1),
        disposition: Disposition::Rebuild,
        merge: MergeRule::PreferLocal,
        restrictive: false,
        restrictive_projection: &[],
        key: &[],
        cells: &[],
        excluded: &["state_kind", "state_json"],
        codec: fields,
    }
}
const fn field(name: &'static str, codec: CodecRule) -> FieldRule {
    FieldRule {
        name,
        nullable: false,
        disposition: Disposition::Rebuild,
        merge: MergeRule::PreferLocal,
        codec,
    }
}
pub(super) const GROUP_RULE: FamilyRule = local_rule(
    "actor/group-message/upgrade-start",
    GROUP,
    &[
        field("state_kind", CodecRule::Enum { values: &[GROUP] }),
        field("state_json", CodecRule::Scalar { cell_type: CellType::I64 }),
    ],
);
pub(super) const SAFETY_RULE: FamilyRule = local_rule(
    "actor/identity/safety-verification-migration/v1",
    SAFETY,
    &[
        field("state_kind", CodecRule::Enum { values: &[SAFETY] }),
        field("state_json", CodecRule::Boolean),
    ],
);
fn unsupported() -> StorageError {
    StorageError::PairingField("UnsupportedRecord")
}
fn exact(rule: &FamilyRule, expected: &FamilyRule) -> Result<bool, StorageError> {
    Ok(rule.id == expected.id && rule.rule_hash()? == expected.rule_hash()?)
}
pub(in crate::account_db::full_transfer) fn rows(
    input: &Connection,
    rule: &FamilyRule,
    table_exists: bool,
) -> Result<u64, StorageError> {
    let (kind, limit, boolean) = if exact(rule, &GROUP_RULE)? {
        (GROUP, 20, false)
    } else if exact(rule, &SAFETY_RULE)? {
        (SAFETY, 5, true)
    } else {
        return Err(unsupported());
    };
    if !table_exists {
        return Ok(0);
    }
    let count: u64 = input.query_row(
        "SELECT count(*) FROM runtime_actor_state WHERE state_kind=?1",
        rusqlite::params![kind],
        |row| row.get(0),
    )?;
    if count > 1 {
        return Err(unsupported());
    }
    let oversized:bool=input.query_row("SELECT EXISTS(SELECT 1 FROM runtime_actor_state WHERE state_kind=?1 AND length(state_json)>?2)",rusqlite::params![kind,limit],|row|row.get(0))?;
    if oversized {
        return Err(unsupported());
    }
    let valid = input.call(move |db| {
        db.query_row(
            "SELECT state_json FROM runtime_actor_state WHERE state_kind=?1",
            rusqlite::params![kind],
            |row| {
                let valid = match row.get_ref(0)? {
                    rusqlite::types::ValueRef::Blob(bytes) if boolean => {
                        matches!(bytes, b"true" | b"false")
                    }
                    rusqlite::types::ValueRef::Blob(bytes) => std::str::from_utf8(bytes)
                        .ok()
                        .and_then(|text| text.parse::<i64>().ok())
                        .is_some_and(|value| value.to_string().as_bytes() == bytes),
                    _ => false,
                };
                Ok(valid)
            },
        )
        .optional()
    })?;
    match valid {
        Some(true) => Ok(1),
        None => Ok(0),
        Some(false) => Err(unsupported()),
    }
}
pub(in crate::account_db::full_transfer) fn unprojected_rows(
    input: &Connection,
    rules: &[FamilyRule],
) -> Result<u64, StorageError> {
    let group = rules
        .iter()
        .find(|rule| rule.id == GROUP_RULE.id)
        .map(|rule| exact(rule, &GROUP_RULE))
        .transpose()?
        .unwrap_or(false);
    let safety = rules
        .iter()
        .find(|rule| rule.id == SAFETY_RULE.id)
        .map(|rule| exact(rule, &SAFETY_RULE))
        .transpose()?
        .unwrap_or(false);
    Ok(input.query_row("SELECT count(*) FROM runtime_actor_state WHERE NOT ((?1 AND state_kind=?2) OR (?3 AND state_kind=?4))",rusqlite::params![group,GROUP,safety,SAFETY],|row|row.get(0))?)
}
