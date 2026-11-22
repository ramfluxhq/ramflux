// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! The selected historical proof is B-local derived state, never imported authority.
use super::{CodecRule, Disposition, FamilyRule, FamilySelector, FieldRule, MergeRule, U64};
pub(super) const RULE: FamilyRule = table_rule!(
    "sql/runtime_native_history_selection",
    "runtime_native_history_selection",
    Rebuild,
    PreferLocal,
    false,
    [],
    [
        (
            "message_id",
            Utf8,
            false,
            Rebuild,
            PreferLocal,
            CodecRule::SqlBase64 { decoded_bytes: U64(32), nullable: false }
        ),
        (
            "evidence_class",
            Utf8,
            false,
            Rebuild,
            PreferLocal,
            CodecRule::SqlEnum { values: &["received", "authored", "own_copy"], nullable: false }
        ),
        (
            "current_id",
            Bytes,
            false,
            Rebuild,
            PreferLocal,
            CodecRule::SqlBytes { length: U64(32), nullable: false }
        ),
        (
            "body_hash",
            Bytes,
            false,
            Rebuild,
            PreferLocal,
            CodecRule::SqlBytes { length: U64(32), nullable: false }
        )
    ]
);
