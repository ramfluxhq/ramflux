// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Automatic history attempts belong only to the local device.
use super::{
    CellType, CodecRule, Disposition, FamilyRule, FamilySelector, FieldRule, MergeRule, U64,
};
pub(super) const RULE: FamilyRule = table_rule!(
    "sql/pairing_own_sync",
    "pairing_own_sync",
    Exclude,
    PreferLocal,
    false,
    [],
    [
        (
            "operation_id",
            Utf8,
            false,
            Exclude,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "fingerprint",
            Utf8,
            false,
            Exclude,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "response_json",
            Utf8,
            false,
            Exclude,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "operation_kind",
            Utf8,
            false,
            Exclude,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        )
    ]
);
