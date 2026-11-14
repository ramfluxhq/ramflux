// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Full-transfer SQL family declarations for progress.
use super::{
    CellRule, CellType, CodecRule, Disposition, FamilyRule, FamilySelector, FieldRule, MergeRule,
    U64,
};

pub(super) const RULE_29: FamilyRule = table_rule!(
    "sql/cursor_checkpoint",
    "cursor_checkpoint",
    Exclude,
    PreferLocal,
    false,
    [],
    [
        (
            "cursor_id",
            Utf8,
            true,
            Exclude,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "device_id",
            Utf8,
            false,
            Exclude,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "inbox_seq",
            I64,
            false,
            Exclude,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
        (
            "last_envelope_id",
            Utf8,
            true,
            Exclude,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "updated_at",
            I64,
            false,
            Exclude,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
    ]
);

pub(super) const RULE_59: FamilyRule = table_rule!(
    "sql/lineage_checkpoint",
    "lineage_checkpoint",
    Transfer,
    Immutable,
    false,
    ["checkpoint_id"],
    [
        (
            "checkpoint_id",
            Utf8,
            true,
            Transfer,
            Immutable,
            CodecRule::RequiresOwner { owner: "lineage_checkpoint", cell_type: CellType::Utf8 }
        ),
        (
            "lineage_head",
            Utf8,
            false,
            Transfer,
            Immutable,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "device_id",
            Utf8,
            false,
            Transfer,
            Immutable,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "device_epoch",
            I64,
            false,
            Transfer,
            Immutable,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
        (
            "checkpoint_hash",
            Bytes,
            false,
            Transfer,
            Immutable,
            CodecRule::Scalar { cell_type: CellType::Bytes }
        ),
        (
            "created_at",
            I64,
            false,
            Transfer,
            Immutable,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
    ]
);

pub(super) const RULE_113: FamilyRule = table_rule!(
    "sql/projection_checkpoint",
    "projection_checkpoint",
    Rebuild,
    PreferLocal,
    false,
    [],
    [
        (
            "projection_name",
            Utf8,
            true,
            Rebuild,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "projection_version",
            I64,
            false,
            Rebuild,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
        (
            "last_event_id",
            Utf8,
            true,
            Rebuild,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "checkpoint_hash",
            Bytes,
            true,
            Rebuild,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Bytes }
        ),
        (
            "updated_at",
            I64,
            false,
            Rebuild,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
    ]
);

pub(super) const RULE_152: FamilyRule = table_rule!(
    "sql/schema_migration",
    "schema_migration",
    Rebuild,
    PreferLocal,
    false,
    [],
    [
        (
            "schema_version",
            I64,
            true,
            Rebuild,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
        (
            "applied_at",
            I64,
            false,
            Rebuild,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
        (
            "app_version",
            Utf8,
            false,
            Rebuild,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "checksum",
            Utf8,
            false,
            Rebuild,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "notes",
            Utf8,
            true,
            Rebuild,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
    ]
);

pub(super) const RULE_158: FamilyRule = table_rule!(
    "sql/sync_checkpoint",
    "sync_checkpoint",
    Exclude,
    PreferLocal,
    false,
    [],
    [
        (
            "checkpoint_id",
            Utf8,
            true,
            Exclude,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "sync_scope",
            Utf8,
            false,
            Exclude,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "cursor_id",
            Utf8,
            true,
            Exclude,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "checkpoint_body",
            Bytes,
            false,
            Exclude,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Bytes }
        ),
        (
            "checkpoint_hash",
            Bytes,
            false,
            Exclude,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Bytes }
        ),
        (
            "updated_at",
            I64,
            false,
            Exclude,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
    ]
);
