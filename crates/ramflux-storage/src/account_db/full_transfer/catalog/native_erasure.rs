// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Restrictive body-free native erasure projection; both original ids survive absence.
use super::{
    CellRule, CellType, CodecRule, Disposition, FamilyRule, FamilySelector, FieldRule, MergeRule,
    U64,
};
pub(super) const RULE: FamilyRule = table_rule!(
    "sql/runtime_native_erasure",
    "runtime_native_erasure",
    Transfer,
    RestrictUnion,
    true,
    ["original_id", "current_id"],
    [
        (
            "original_id",
            Utf8,
            false,
            Transfer,
            Immutable,
            CodecRule::SqlBase64 { decoded_bytes: U64(32), nullable: false }
        ),
        (
            "current_id",
            Utf8,
            false,
            Transfer,
            Immutable,
            CodecRule::SqlBase64 { decoded_bytes: U64(32), nullable: false }
        ),
        (
            "conversation_id",
            Utf8,
            false,
            Transfer,
            Immutable,
            CodecRule::SqlText { min_bytes: U64(46), max_bytes: U64(46), nullable: false }
        )
    ]
);
