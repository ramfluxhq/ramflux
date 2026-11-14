// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Full-transfer SQL family declarations for receipts.
use super::{
    CellRule, CellType, CodecRule, Disposition, FamilyRule, FamilySelector, FieldRule, MergeRule,
    U64,
};

pub(super) const RULE_5: FamilyRule = table_rule!(
    "sql/ack_state",
    "ack_state",
    Exclude,
    PreferLocal,
    false,
    [],
    [
        (
            "ack_id",
            Utf8,
            true,
            Exclude,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "envelope_id",
            Utf8,
            false,
            Exclude,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "receiver_device_id",
            Utf8,
            false,
            Exclude,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "cursor_after",
            Utf8,
            true,
            Exclude,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "received_at",
            I64,
            false,
            Exclude,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
    ]
);

pub(super) const RULE_58: FamilyRule = table_rule!(
    "sql/legacy_receipt_projection",
    "legacy_receipt_projection",
    Transfer,
    CursorMax,
    false,
    [],
    [
        (
            "receipt_id",
            Utf8,
            true,
            Transfer,
            CursorMax,
            CodecRule::RequiresOwner {
                owner: "legacy_receipt_projection",
                cell_type: CellType::Utf8
            }
        ),
        (
            "conversation_id",
            Utf8,
            true,
            Transfer,
            CursorMax,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "message_id",
            Utf8,
            true,
            Transfer,
            CursorMax,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "receipt_type",
            Utf8,
            true,
            Transfer,
            CursorMax,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "actor_device_id",
            Utf8,
            true,
            Transfer,
            CursorMax,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "created_at",
            I64,
            true,
            Transfer,
            CursorMax,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
    ]
);

pub(super) const RULE_74: FamilyRule = table_rule!(
    "sql/nack_state",
    "nack_state",
    Exclude,
    PreferLocal,
    false,
    [],
    [
        (
            "nack_id",
            Utf8,
            true,
            Exclude,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "envelope_id",
            Utf8,
            false,
            Exclude,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "receiver_device_id",
            Utf8,
            false,
            Exclude,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "reason",
            Utf8,
            false,
            Exclude,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "retry_after",
            I64,
            true,
            Exclude,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
        (
            "received_at",
            I64,
            false,
            Exclude,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
    ]
);

pub(super) const RULE_118: FamilyRule = table_rule!(
    "sql/receipt_identity_upgrade",
    "receipt_identity_upgrade",
    Rebuild,
    PreferLocal,
    false,
    [],
    [(
        "singleton",
        I64,
        true,
        Rebuild,
        PreferLocal,
        CodecRule::Scalar { cell_type: CellType::I64 }
    ),]
);

pub(super) const RULE_119: FamilyRule = table_rule!(
    "sql/receipt_projection",
    "receipt_projection",
    Transfer,
    CursorMax,
    false,
    ["receipt_id"],
    [
        (
            "receipt_id",
            Utf8,
            true,
            Transfer,
            Immutable,
            CodecRule::RequiresOwner { owner: "receipt_projection", cell_type: CellType::Utf8 }
        ),
        (
            "conversation_id",
            Utf8,
            false,
            Transfer,
            CursorMax,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "message_id",
            Utf8,
            true,
            Transfer,
            CursorMax,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "receipt_type",
            Utf8,
            false,
            Transfer,
            CursorMax,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "actor_device_id",
            Utf8,
            false,
            Transfer,
            CursorMax,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "created_at",
            I64,
            false,
            Transfer,
            CursorMax,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
    ]
);

pub(super) const RULE_127: FamilyRule = table_rule!(
    "sql/runtime_ack",
    "runtime_ack",
    Exclude,
    PreferLocal,
    false,
    [],
    [(
        "envelope_id",
        Utf8,
        true,
        Exclude,
        PreferLocal,
        CodecRule::Scalar { cell_type: CellType::Utf8 }
    ),]
);

pub(super) const RULE_149: FamilyRule = table_rule!(
    "sql/runtime_receipt_retention",
    "runtime_receipt_retention",
    Rebuild,
    PreferLocal,
    false,
    [],
    [
        (
            "state_kind",
            Utf8,
            true,
            Rebuild,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        ("at", I64, false, Rebuild, PreferLocal, CodecRule::Scalar { cell_type: CellType::I64 }),
    ]
);

pub(super) const RULE_150: FamilyRule = table_rule!(
    "sql/runtime_scoped_ack",
    "runtime_scoped_ack",
    Exclude,
    PreferLocal,
    false,
    [],
    [
        (
            "receiver",
            Utf8,
            false,
            Exclude,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "target",
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
    ]
);
