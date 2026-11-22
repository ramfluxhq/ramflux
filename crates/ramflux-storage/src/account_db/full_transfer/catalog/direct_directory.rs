// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! One closed public directory projection, disjoint from unknown/local actor variants.
use super::{
    CellRule, CellType, CodecRule, Disposition, FamilyRule, FamilySelector, FieldRule, MergeRule,
    SqlProjection, U64,
};
pub(super) const RULE: FamilyRule = FamilyRule {
    id: super::super::conversation_directory::FAMILY,
    selector: FamilySelector::Table("runtime_actor_state"),
    codec_version: U64(1),
    key_grammar_version: U64(1),
    disposition: Disposition::Transfer,
    merge: MergeRule::PreferLocal,
    restrictive: false,
    restrictive_projection: &[],
    key: &["state_kind"],
    cells: &[
        CellRule { name: "state_kind", nullable: true, cell_type: CellType::Utf8 },
        CellRule { name: "state_json", nullable: false, cell_type: CellType::Bytes },
    ],
    excluded: &[],
    codec: &[
        FieldRule {
            name: "state_kind",
            nullable: true,
            disposition: Disposition::Transfer,
            merge: MergeRule::Immutable,
            codec: CodecRule::SqlText { min_bytes: U64(1), max_bytes: U64(256), nullable: false },
        },
        FieldRule {
            name: "state_json",
            nullable: false,
            disposition: Disposition::Transfer,
            merge: MergeRule::PreferLocal,
            codec: CodecRule::SqlJsonProjection {
                projection: SqlProjection::DirectConversationMetadataV1,
                fields: super::super::conversation_directory::FIELDS,
            },
        },
    ],
};
