// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Full-transfer SQL family declarations for runtime.
use super::{
    CellRule, CellType, CodecRule, Disposition, FamilyRule, FamilySelector, FieldRule, MergeRule,
    U64,
};

pub(super) const RULE_105: FamilyRule = table_rule!(
    "sql/outbox_queue",
    "outbox_queue",
    Transfer,
    InertHistory,
    false,
    ["outbox_id"],
    [
        (
            "outbox_id",
            Utf8,
            true,
            Transfer,
            Immutable,
            CodecRule::RequiresOwner { owner: "outbox_queue", cell_type: CellType::Utf8 }
        ),
        (
            "envelope_id",
            Utf8,
            false,
            Transfer,
            InertHistory,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "target_delivery_id",
            Utf8,
            false,
            Transfer,
            InertHistory,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "delivery_class",
            Utf8,
            false,
            Transfer,
            InertHistory,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "encrypted_envelope",
            Bytes,
            false,
            Transfer,
            InertHistory,
            CodecRule::Scalar { cell_type: CellType::Bytes }
        ),
        (
            "state",
            Utf8,
            false,
            Transfer,
            InertHistory,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "retry_count",
            I64,
            false,
            Transfer,
            InertHistory,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
        (
            "next_retry_at",
            I64,
            true,
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
        (
            "updated_at",
            I64,
            false,
            Transfer,
            InertHistory,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
    ]
);

pub(super) const RULE_128: FamilyRule = table_rule!(
    "sql/runtime_actor_state",
    "runtime_actor_state",
    Transfer,
    InertHistory,
    false,
    ["state_kind"],
    [
        (
            "state_kind",
            Utf8,
            true,
            Transfer,
            Immutable,
            CodecRule::RequiresOwner { owner: "runtime_actor_state", cell_type: CellType::Utf8 }
        ),
        (
            "state_json",
            Bytes,
            false,
            Transfer,
            InertHistory,
            CodecRule::Scalar { cell_type: CellType::Bytes }
        ),
    ]
);

pub(super) const RULE_141: FamilyRule = table_rule!(
    "sql/runtime_journal",
    "runtime_journal",
    Transfer,
    InertHistory,
    false,
    ["seq"],
    [
        (
            "seq",
            I64,
            true,
            Transfer,
            Immutable,
            CodecRule::RequiresOwner { owner: "runtime_journal", cell_type: CellType::I64 }
        ),
        ("at", I64, false, Transfer, InertHistory, CodecRule::Scalar { cell_type: CellType::I64 }),
        (
            "topic",
            Utf8,
            false,
            Transfer,
            InertHistory,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "body_json",
            Bytes,
            false,
            Transfer,
            InertHistory,
            CodecRule::Scalar { cell_type: CellType::Bytes }
        ),
        (
            "source_key",
            Utf8,
            false,
            Transfer,
            InertHistory,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "sticky",
            I64,
            false,
            Transfer,
            InertHistory,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
        (
            "acknowledged",
            I64,
            false,
            Transfer,
            InertHistory,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
        (
            "subject",
            Utf8,
            true,
            Transfer,
            InertHistory,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
    ]
);

pub(super) const RULE_142: FamilyRule = table_rule!(
    "sql/runtime_journal_bounds",
    "runtime_journal_bounds",
    Rebuild,
    PreferLocal,
    false,
    [],
    [
        (
            "singleton",
            I64,
            true,
            Rebuild,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
        (
            "head_seq",
            I64,
            false,
            Rebuild,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
        (
            "pruned_through",
            I64,
            false,
            Rebuild,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
    ]
);

pub(super) const RULE_144: FamilyRule = table_rule!(
    "sql/runtime_operation",
    "runtime_operation",
    Transfer,
    InertHistory,
    false,
    ["operation_id"],
    [
        (
            "operation_id",
            Utf8,
            true,
            Transfer,
            Immutable,
            CodecRule::RequiresOwner { owner: "runtime_operation", cell_type: CellType::Utf8 }
        ),
        (
            "fingerprint",
            Utf8,
            false,
            Transfer,
            InertHistory,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "response_json",
            Utf8,
            true,
            Transfer,
            InertHistory,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "operation_kind",
            Utf8,
            true,
            Transfer,
            InertHistory,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
    ]
);

pub(super) const RULE_145: FamilyRule = table_rule!(
    "sql/runtime_outbox",
    "runtime_outbox",
    Rebuild,
    PreferLocal,
    false,
    [],
    [
        (
            "sequence",
            I64,
            true,
            Rebuild,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
        (
            "table_name",
            Utf8,
            false,
            Rebuild,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "change_kind",
            Utf8,
            false,
            Rebuild,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "row_id",
            I64,
            false,
            Rebuild,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
        (
            "published",
            I64,
            false,
            Rebuild,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
        (
            "keys_json",
            Utf8,
            true,
            Rebuild,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "actor_state_kind",
            Utf8,
            true,
            Rebuild,
            PreferLocal,
            CodecRule::Generated {
                cell_type: CellType::Utf8,
                hidden: 2,
                expression: "CASE WHEN table_name='runtime_actor_state' THEN json_extract(keys_json,'$.state_kind') END"
            }
        ),
    ]
);

pub(super) const RULE_146: FamilyRule = table_rule!(
    "sql/runtime_own_copy_state",
    "runtime_own_copy_state",
    Exclude,
    PreferLocal,
    false,
    [],
    [
        (
            "state_kind",
            Utf8,
            true,
            Exclude,
            PreferLocal,
            CodecRule::RequiresOwner { owner: "runtime_own_copy_state", cell_type: CellType::Utf8 }
        ),
        (
            "namespace",
            Utf8,
            false,
            Exclude,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        ("bytes", I64, false, Exclude, PreferLocal, CodecRule::Scalar { cell_type: CellType::I64 }),
        (
            "expires_at",
            I64,
            false,
            Exclude,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
        (
            "completed",
            I64,
            false,
            Exclude,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
        (
            "next_attempt_at",
            I64,
            true,
            Exclude,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
    ]
);

pub(super) const RULE_147: FamilyRule = table_rule!(
    "sql/runtime_own_copy_usage",
    "runtime_own_copy_usage",
    Exclude,
    PreferLocal,
    false,
    [],
    [
        (
            "namespace",
            Utf8,
            true,
            Exclude,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        ("rows", I64, false, Exclude, PreferLocal, CodecRule::Scalar { cell_type: CellType::I64 }),
        ("bytes", I64, false, Exclude, PreferLocal, CodecRule::Scalar { cell_type: CellType::I64 }),
        (
            "next_cleanup_at",
            I64,
            false,
            Exclude,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
    ]
);

pub(super) const RULE_148: FamilyRule = table_rule!(
    "sql/runtime_privacy_maintenance",
    "runtime_privacy_maintenance",
    Rebuild,
    PreferLocal,
    false,
    [],
    [
        (
            "singleton",
            I64,
            true,
            Rebuild,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
        (
            "erasure_pending",
            I64,
            false,
            Rebuild,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
    ]
);
