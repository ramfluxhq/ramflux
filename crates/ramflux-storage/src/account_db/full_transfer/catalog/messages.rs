// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Full-transfer SQL family declarations for messages.
use super::{
    CellRule, CellType, CodecRule, Disposition, FamilyRule, FamilySelector, FieldRule, MergeRule,
    U64,
};

pub(super) const RULE_66: FamilyRule = table_rule!(
    "sql/message_copy_binding",
    "message_copy_binding",
    Rebuild,
    PreferLocal,
    false,
    [],
    [
        (
            "copy_id",
            Utf8,
            false,
            Rebuild,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "message_id",
            Utf8,
            false,
            Rebuild,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
    ]
);

pub(super) const RULE_67: FamilyRule = table_rule!(
    "sql/message_footprint",
    "message_footprint",
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
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "kind",
            Utf8,
            false,
            Rebuild,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "locator",
            Utf8,
            false,
            Rebuild,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
    ]
);

pub(super) const RULE_68: FamilyRule = table_rule!(
    "sql/message_footprint_actor_stage",
    "message_footprint_actor_stage",
    Rebuild,
    PreferLocal,
    false,
    [],
    [
        (
            "state_kind",
            Utf8,
            false,
            Rebuild,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "message_ids_json",
            Utf8,
            false,
            Rebuild,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "copy_ids_json",
            Utf8,
            false,
            Rebuild,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "bindings_json",
            Utf8,
            false,
            Rebuild,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
    ]
);

pub(super) const RULE_69: FamilyRule = table_rule!(
    "sql/message_footprint_journal_stage",
    "message_footprint_journal_stage",
    Rebuild,
    PreferLocal,
    false,
    [],
    [
        ("seq", I64, false, Rebuild, PreferLocal, CodecRule::Scalar { cell_type: CellType::I64 }),
        (
            "body_json",
            Bytes,
            false,
            Rebuild,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Bytes }
        ),
    ]
);

pub(super) const RULE_70: FamilyRule = table_rule!(
    "sql/message_footprint_migration",
    "message_footprint_migration",
    Rebuild,
    PreferLocal,
    false,
    [],
    [
        (
            "name",
            Utf8,
            false,
            Rebuild,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "value",
            Utf8,
            false,
            Rebuild,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
    ]
);

pub(super) const RULE_71: FamilyRule = table_rule!(
    "sql/message_footprint_outbox_stage",
    "message_footprint_outbox_stage",
    Rebuild,
    PreferLocal,
    false,
    [],
    [
        (
            "sequence",
            I64,
            false,
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
            "keys_json",
            Utf8,
            false,
            Rebuild,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
    ]
);

pub(super) const RULE_72: FamilyRule = table_rule!(
    "sql/message_projection",
    "message_projection",
    Transfer,
    Immutable,
    false,
    ["message_id"],
    [
        (
            "message_id",
            Utf8,
            true,
            Transfer,
            Immutable,
            CodecRule::RequiresOwner { owner: "message_projection", cell_type: CellType::Utf8 }
        ),
        (
            "conversation_id",
            Utf8,
            false,
            Transfer,
            Immutable,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "sender_device_id",
            Utf8,
            false,
            Transfer,
            Immutable,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "event_id",
            Utf8,
            false,
            Transfer,
            Immutable,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "body_cipher",
            Bytes,
            false,
            Transfer,
            Immutable,
            CodecRule::Scalar { cell_type: CellType::Bytes }
        ),
        (
            "edit_counter",
            I64,
            false,
            Transfer,
            Immutable,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
        (
            "deleted_at",
            I64,
            true,
            Transfer,
            Immutable,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
        (
            "event_tombstone_id",
            Utf8,
            true,
            Transfer,
            Immutable,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "created_at",
            I64,
            false,
            Transfer,
            Immutable,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
        (
            "updated_at",
            I64,
            false,
            Transfer,
            Immutable,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
    ]
);

pub(super) const RULE_73: FamilyRule = table_rule!(
    "sql/message_tombstone_projection",
    "message_tombstone_projection",
    Transfer,
    RestrictUnion,
    true,
    ["tombstone_id"],
    [
        (
            "tombstone_id",
            Utf8,
            true,
            Transfer,
            Immutable,
            CodecRule::RequiresOwner {
                owner: "message_tombstone_projection",
                cell_type: CellType::Utf8
            }
        ),
        (
            "conversation_id",
            Utf8,
            false,
            Transfer,
            RestrictUnion,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "message_id",
            Utf8,
            false,
            Transfer,
            RestrictUnion,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "delete_scope",
            Utf8,
            false,
            Transfer,
            RestrictUnion,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "created_at",
            I64,
            false,
            Transfer,
            RestrictUnion,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
    ]
);

pub(super) const RULE_143: FamilyRule = table_rule!(
    "sql/runtime_message_content",
    "runtime_message_content",
    Transfer,
    Immutable,
    false,
    ["message_id"],
    [
        (
            "message_id",
            Utf8,
            true,
            Transfer,
            Immutable,
            CodecRule::RequiresOwner {
                owner: "runtime_message_content",
                cell_type: CellType::Utf8
            }
        ),
        (
            "conversation_id",
            Utf8,
            false,
            Transfer,
            Immutable,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "body",
            Bytes,
            false,
            Transfer,
            Immutable,
            CodecRule::Scalar { cell_type: CellType::Bytes }
        ),
    ]
);
