// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Full-transfer SQL family declarations for receive.
use super::{
    CellRule, CellType, CodecRule, Disposition, FamilyRule, FamilySelector, FieldRule, MergeRule,
    U64,
};

pub(super) const RULE_120: FamilyRule = table_rule!(
    "sql/receive_erased_input",
    "receive_erased_input",
    Transfer,
    RestrictUnion,
    true,
    ["selector"],
    [
        (
            "selector",
            Utf8,
            false,
            Transfer,
            Immutable,
            CodecRule::RequiresOwner { owner: "receive_erased_input", cell_type: CellType::Utf8 }
        ),
        (
            "bundle_id",
            Utf8,
            false,
            Transfer,
            RestrictUnion,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "expires_at",
            I64,
            false,
            Transfer,
            RestrictUnion,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
    ]
);

pub(super) const RULE_121: FamilyRule = table_rule!(
    "sql/rejected_inbox_projection",
    "rejected_inbox_projection",
    Transfer,
    Immutable,
    false,
    ["message_id"],
    [
        (
            "conversation_id",
            Utf8,
            false,
            Transfer,
            Immutable,
            CodecRule::RequiresOwner {
                owner: "rejected_inbox_projection",
                cell_type: CellType::Utf8
            }
        ),
        (
            "message_id",
            Utf8,
            true,
            Transfer,
            Immutable,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "sender_id",
            Utf8,
            false,
            Transfer,
            Immutable,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "reason",
            Utf8,
            false,
            Transfer,
            Immutable,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "rejected_at",
            I64,
            false,
            Transfer,
            Immutable,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
    ]
);

pub(super) const RULE_136: FamilyRule = table_rule!(
    "sql/runtime_inbox_changes",
    "runtime_inbox_changes",
    Exclude,
    PreferLocal,
    false,
    [],
    [
        (
            "kind",
            Utf8,
            false,
            Exclude,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "subject",
            Utf8,
            false,
            Exclude,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "revision",
            I64,
            false,
            Exclude,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
    ]
);

pub(super) const RULE_137: FamilyRule = table_rule!(
    "sql/runtime_inbox_dead_letter",
    "runtime_inbox_dead_letter",
    Transfer,
    InertHistory,
    false,
    ["envelope_key"],
    [
        (
            "envelope_key",
            Utf8,
            true,
            Transfer,
            Immutable,
            CodecRule::RequiresOwner {
                owner: "runtime_inbox_dead_letter",
                cell_type: CellType::Utf8
            }
        ),
        (
            "entry_json",
            Bytes,
            false,
            Transfer,
            InertHistory,
            CodecRule::Scalar { cell_type: CellType::Bytes }
        ),
        (
            "error_code",
            Utf8,
            false,
            Transfer,
            InertHistory,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "received_at",
            I64,
            false,
            Transfer,
            InertHistory,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
    ]
);

pub(super) const RULE_138: FamilyRule = table_rule!(
    "sql/runtime_inbox_policy",
    "runtime_inbox_policy",
    Exclude,
    PreferLocal,
    false,
    [],
    [
        (
            "envelope_key",
            Utf8,
            true,
            Exclude,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "source",
            Utf8,
            false,
            Exclude,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "trusted",
            I64,
            false,
            Exclude,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
        (
            "first_seen",
            I64,
            false,
            Exclude,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
        (
            "expires_at",
            I64,
            false,
            Exclude,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
        (
            "attempts",
            I64,
            false,
            Exclude,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
        (
            "failure_class",
            Utf8,
            false,
            Exclude,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "subject",
            Utf8,
            false,
            Exclude,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "last_redrive",
            I64,
            false,
            Exclude,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
        (
            "last_revision",
            I64,
            false,
            Exclude,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
    ]
);

pub(super) const RULE_139: FamilyRule = table_rule!(
    "sql/runtime_inbox_recovery",
    "runtime_inbox_recovery",
    Exclude,
    PreferLocal,
    false,
    [],
    [
        (
            "singleton",
            I64,
            true,
            Exclude,
            PreferLocal,
            CodecRule::SqlI64 { min: "1", max: "1", nullable: false }
        ),
        (
            "revision",
            I64,
            false,
            Exclude,
            PreferLocal,
            CodecRule::SqlI64 { min: "0", max: "9223372036854775807", nullable: false }
        ),
    ]
);

pub(super) const RULE_140: FamilyRule = table_rule!(
    "sql/runtime_inbox_retry",
    "runtime_inbox_retry",
    Transfer,
    InertHistory,
    false,
    ["envelope_key"],
    [
        (
            "envelope_key",
            Utf8,
            true,
            Transfer,
            Immutable,
            CodecRule::RequiresOwner { owner: "runtime_inbox_retry", cell_type: CellType::Utf8 }
        ),
        (
            "entry_json",
            Bytes,
            false,
            Transfer,
            InertHistory,
            CodecRule::Scalar { cell_type: CellType::Bytes }
        ),
        (
            "attempts",
            I64,
            false,
            Transfer,
            InertHistory,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
        (
            "next_at",
            I64,
            false,
            Transfer,
            InertHistory,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
        (
            "created_at",
            I64,
            false,
            Transfer,
            InertHistory,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
    ]
);
