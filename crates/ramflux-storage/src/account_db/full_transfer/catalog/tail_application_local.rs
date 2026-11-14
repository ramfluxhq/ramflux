// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Device-local tail ownership and application cursors never enter another device.
use super::*;
pub(super) const APPLY: FamilyRule = table_rule!(
    "sql/pairing_full_tail_apply",
    "pairing_full_tail_apply",
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
            "generation_nonce",
            Utf8,
            false,
            Exclude,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "stage_digest",
            Bytes,
            false,
            Exclude,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Bytes }
        ),
        (
            "source_owner",
            Utf8,
            false,
            Exclude,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "tail_hash",
            Utf8,
            true,
            Exclude,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        ("phase", I64, false, Exclude, PreferLocal, CodecRule::Scalar { cell_type: CellType::I64 }),
        (
            "next_record",
            I64,
            false,
            Exclude,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
        (
            "tail_status",
            Utf8,
            false,
            Exclude,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
    ]
);
pub(super) const DEPENDENCY: FamilyRule = table_rule!(
    "sql/pairing_full_tail_dependency",
    "pairing_full_tail_dependency",
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
        ("owner", I64, false, Exclude, PreferLocal, CodecRule::Scalar { cell_type: CellType::I64 }),
        (
            "parent_commitment",
            Utf8,
            false,
            Exclude,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "child_commitment",
            Utf8,
            false,
            Exclude,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
    ]
);
