// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Full-transfer SQL family declarations for conversations.
use super::{
    CellRule, CellType, CodecRule, Disposition, FamilyRule, FamilySelector, FieldRule, MergeRule,
    U64,
};

pub(super) const RULE_22: FamilyRule = table_rule!(
    "sql/conversation_delivery_state",
    "conversation_delivery_state",
    Transfer,
    CursorMax,
    false,
    ["conversation_id", "receiver_device_id"],
    [
        (
            "conversation_id",
            Utf8,
            false,
            Transfer,
            Immutable,
            CodecRule::RequiresOwner {
                owner: "conversation_delivery_state",
                cell_type: CellType::Utf8
            }
        ),
        (
            "receiver_device_id",
            Utf8,
            false,
            Transfer,
            Immutable,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "delivered_through_message_id",
            Utf8,
            false,
            Transfer,
            CursorMax,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "delivered_at",
            I64,
            false,
            Transfer,
            CursorMax,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
        (
            "ttl_seconds",
            I64,
            false,
            Transfer,
            CursorMax,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
    ]
);

pub(super) const RULE_23: FamilyRule = table_rule!(
    "sql/conversation_disappearing_policy",
    "conversation_disappearing_policy",
    Transfer,
    PreferLocal,
    false,
    ["conversation_id"],
    [
        (
            "conversation_id",
            Utf8,
            true,
            Transfer,
            Immutable,
            CodecRule::RequiresOwner {
                owner: "conversation_disappearing_policy",
                cell_type: CellType::Utf8
            }
        ),
        (
            "timer_seconds",
            I64,
            false,
            Transfer,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
        (
            "countdown_mode",
            Utf8,
            false,
            Transfer,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "scope",
            Utf8,
            false,
            Transfer,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "updated_at",
            I64,
            false,
            Transfer,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
    ]
);

pub(super) const RULE_24: FamilyRule = table_rule!(
    "sql/conversation_list_state",
    "conversation_list_state",
    Transfer,
    PreferLocal,
    false,
    ["conversation_id"],
    [
        (
            "conversation_id",
            Utf8,
            true,
            Transfer,
            Immutable,
            CodecRule::RequiresOwner {
                owner: "conversation_list_state",
                cell_type: CellType::Utf8
            }
        ),
        (
            "archived",
            I64,
            false,
            Transfer,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
        (
            "pin_order",
            I64,
            true,
            Transfer,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
        (
            "mute_until",
            I64,
            true,
            Transfer,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
        (
            "hidden_at",
            I64,
            true,
            Transfer,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
        (
            "cleared_at",
            I64,
            true,
            Transfer,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
        (
            "updated_at",
            I64,
            false,
            Transfer,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
    ]
);

pub(super) const RULE_25: FamilyRule = table_rule!(
    "sql/conversation_projection",
    "conversation_projection",
    Transfer,
    Revision,
    false,
    ["conversation_id"],
    [
        (
            "conversation_id",
            Utf8,
            true,
            Transfer,
            Immutable,
            CodecRule::RequiresOwner {
                owner: "conversation_projection",
                cell_type: CellType::Utf8
            }
        ),
        (
            "conversation_kind",
            Utf8,
            false,
            Transfer,
            Revision,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "root_ref",
            Utf8,
            true,
            Transfer,
            Revision,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "hidden_at",
            I64,
            true,
            Transfer,
            Revision,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
        (
            "archived_at",
            I64,
            true,
            Transfer,
            Revision,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
        (
            "pinned_order",
            I64,
            true,
            Transfer,
            Revision,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
        (
            "muted_until",
            I64,
            true,
            Transfer,
            Revision,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
        (
            "cleared_at",
            I64,
            true,
            Transfer,
            Revision,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
        (
            "projection_version",
            I64,
            false,
            Transfer,
            Revision,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
        (
            "updated_at",
            I64,
            false,
            Transfer,
            Revision,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
    ]
);

pub(super) const RULE_26: FamilyRule = table_rule!(
    "sql/conversation_read_state",
    "conversation_read_state",
    Transfer,
    CursorMax,
    false,
    ["conversation_id", "reader_id"],
    [
        (
            "conversation_id",
            Utf8,
            false,
            Transfer,
            Immutable,
            CodecRule::RequiresOwner {
                owner: "conversation_read_state",
                cell_type: CellType::Utf8
            }
        ),
        (
            "reader_id",
            Utf8,
            false,
            Transfer,
            Immutable,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "read_through_message_id",
            Utf8,
            false,
            Transfer,
            CursorMax,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "read_at",
            I64,
            false,
            Transfer,
            CursorMax,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
    ]
);

pub(super) const RULE_27: FamilyRule = table_rule!(
    "sql/conversation_tombstone",
    "conversation_tombstone",
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
            CodecRule::RequiresOwner { owner: "conversation_tombstone", cell_type: CellType::Utf8 }
        ),
        (
            "target_id",
            Utf8,
            false,
            Transfer,
            RestrictUnion,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "target_kind",
            Utf8,
            false,
            Transfer,
            RestrictUnion,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "actor_device_id",
            Utf8,
            false,
            Transfer,
            RestrictUnion,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "reason",
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
        (
            "causal_event_id",
            Utf8,
            true,
            Transfer,
            RestrictUnion,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "signature",
            Bytes,
            false,
            Transfer,
            RestrictUnion,
            CodecRule::Scalar { cell_type: CellType::Bytes }
        ),
    ]
);

pub(super) const RULE_28: FamilyRule = table_rule!(
    "sql/conversation_unread_marker",
    "conversation_unread_marker",
    Transfer,
    CursorMax,
    false,
    ["conversation_id", "marker_owner"],
    [
        (
            "conversation_id",
            Utf8,
            false,
            Transfer,
            Immutable,
            CodecRule::RequiresOwner {
                owner: "conversation_unread_marker",
                cell_type: CellType::Utf8
            }
        ),
        (
            "marker_owner",
            Utf8,
            false,
            Transfer,
            Immutable,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "message_id",
            Utf8,
            false,
            Transfer,
            CursorMax,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "marker_epoch",
            I64,
            false,
            Transfer,
            CursorMax,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
        ("active", I64, false, Transfer, CursorMax, CodecRule::Scalar { cell_type: CellType::I64 }),
        (
            "updated_at",
            I64,
            false,
            Transfer,
            CursorMax,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
    ]
);

pub(super) const RULE_34: FamilyRule = table_rule!(
    "sql/direct_message_projection",
    "direct_message_projection",
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
                owner: "direct_message_projection",
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
            "encrypted_body",
            Bytes,
            false,
            Transfer,
            Immutable,
            CodecRule::Scalar { cell_type: CellType::Bytes }
        ),
        (
            "metadata_json",
            Bytes,
            false,
            Transfer,
            Immutable,
            CodecRule::Scalar { cell_type: CellType::Bytes }
        ),
        (
            "deleted",
            I64,
            false,
            Transfer,
            Immutable,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
        ("is_own", I64, false, Transfer, Immutable, CodecRule::Scalar { cell_type: CellType::I64 }),
        (
            "scrub_version",
            I64,
            false,
            Transfer,
            Immutable,
            CodecRule::Scalar { cell_type: CellType::I64 }
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

pub(super) const RULE_53: FamilyRule = table_rule!(
    "sql/legacy_conversation_delivery_state",
    "legacy_conversation_delivery_state",
    Transfer,
    CursorMax,
    false,
    [],
    [
        (
            "conversation_id",
            Utf8,
            true,
            Transfer,
            CursorMax,
            CodecRule::RequiresOwner {
                owner: "legacy_conversation_delivery_state",
                cell_type: CellType::Utf8
            }
        ),
        (
            "receiver_device_id",
            Utf8,
            true,
            Transfer,
            CursorMax,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "delivered_through_message_id",
            Utf8,
            true,
            Transfer,
            CursorMax,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "delivered_at",
            I64,
            true,
            Transfer,
            CursorMax,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
        (
            "ttl_seconds",
            I64,
            true,
            Transfer,
            CursorMax,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
    ]
);

pub(super) const RULE_54: FamilyRule = table_rule!(
    "sql/legacy_conversation_read_state",
    "legacy_conversation_read_state",
    Transfer,
    CursorMax,
    false,
    [],
    [
        (
            "conversation_id",
            Utf8,
            true,
            Transfer,
            CursorMax,
            CodecRule::RequiresOwner {
                owner: "legacy_conversation_read_state",
                cell_type: CellType::Utf8
            }
        ),
        (
            "reader_id",
            Utf8,
            true,
            Transfer,
            CursorMax,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "read_through_message_id",
            Utf8,
            true,
            Transfer,
            CursorMax,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        ("read_at", I64, true, Transfer, CursorMax, CodecRule::Scalar { cell_type: CellType::I64 }),
    ]
);

pub(super) const RULE_55: FamilyRule = table_rule!(
    "sql/legacy_conversation_unread_marker",
    "legacy_conversation_unread_marker",
    Transfer,
    CursorMax,
    false,
    [],
    [
        (
            "conversation_id",
            Utf8,
            true,
            Transfer,
            CursorMax,
            CodecRule::RequiresOwner {
                owner: "legacy_conversation_unread_marker",
                cell_type: CellType::Utf8
            }
        ),
        (
            "marker_owner",
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
            "marker_epoch",
            I64,
            true,
            Transfer,
            CursorMax,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
        ("active", I64, true, Transfer, CursorMax, CodecRule::Scalar { cell_type: CellType::I64 }),
        (
            "updated_at",
            I64,
            true,
            Transfer,
            CursorMax,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
    ]
);
