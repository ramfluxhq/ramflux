// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Full-transfer SQL family declarations for groups.
use super::{
    CellRule, CellType, CodecRule, Disposition, FamilyRule, FamilySelector, FieldRule, MergeRule,
    U64,
};

pub(super) const RULE_39: FamilyRule = table_rule!(
    "sql/group_ban_projection",
    "group_ban_projection",
    Transfer,
    RestrictUnion,
    true,
    ["group_id", "member_id"],
    [
        (
            "group_id",
            Utf8,
            false,
            Transfer,
            Immutable,
            CodecRule::RequiresOwner { owner: "group_ban_projection", cell_type: CellType::Utf8 }
        ),
        (
            "member_id",
            Utf8,
            false,
            Transfer,
            Immutable,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "ban_id",
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
            "banned_epoch",
            I64,
            false,
            Transfer,
            RestrictUnion,
            CodecRule::Scalar { cell_type: CellType::I64 }
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
            "active",
            I64,
            false,
            Transfer,
            RestrictUnion,
            CodecRule::Scalar { cell_type: CellType::I64 }
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

pub(super) const RULE_40: FamilyRule = table_rule!(
    "sql/group_control_event_seen",
    "group_control_event_seen",
    Transfer,
    Immutable,
    false,
    ["group_id", "event_id"],
    [
        (
            "group_id",
            Utf8,
            false,
            Transfer,
            Immutable,
            CodecRule::RequiresOwner {
                owner: "group_control_event_seen",
                cell_type: CellType::Utf8
            }
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
            "event_kind",
            Utf8,
            false,
            Transfer,
            Immutable,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "actor_device_id",
            Utf8,
            false,
            Transfer,
            Immutable,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "target_member_id",
            Utf8,
            false,
            Transfer,
            Immutable,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "previous_epoch",
            I64,
            false,
            Transfer,
            Immutable,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
        (
            "new_group_epoch",
            I64,
            false,
            Transfer,
            Immutable,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
        (
            "applied_at",
            I64,
            false,
            Transfer,
            Immutable,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
    ]
);

pub(super) const RULE_41: FamilyRule = table_rule!(
    "sql/group_invite_projection",
    "group_invite_projection",
    Transfer,
    Immutable,
    false,
    ["group_id", "invite_id"],
    [
        (
            "group_id",
            Utf8,
            false,
            Transfer,
            Immutable,
            CodecRule::RequiresOwner {
                owner: "group_invite_projection",
                cell_type: CellType::Utf8
            }
        ),
        (
            "invite_id",
            Utf8,
            false,
            Transfer,
            Immutable,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "invitee_identity",
            Utf8,
            false,
            Transfer,
            Immutable,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "invitee_signing_public_key",
            Utf8,
            false,
            Transfer,
            Immutable,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "invited_role",
            Utf8,
            false,
            Transfer,
            Immutable,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "inviter_device_id",
            Utf8,
            false,
            Transfer,
            Immutable,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "invite_epoch",
            I64,
            false,
            Transfer,
            Immutable,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
        (
            "expires_at",
            I64,
            false,
            Transfer,
            Immutable,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
        (
            "state",
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

pub(super) const RULE_42: FamilyRule = table_rule!(
    "sql/group_member_device_key",
    "group_member_device_key",
    Transfer,
    Immutable,
    false,
    ["group_id", "member_id"],
    [
        (
            "group_id",
            Utf8,
            false,
            Transfer,
            Immutable,
            CodecRule::RequiresOwner {
                owner: "group_member_device_key",
                cell_type: CellType::Utf8
            }
        ),
        (
            "member_id",
            Utf8,
            false,
            Transfer,
            Immutable,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "device_signing_public_key",
            Utf8,
            false,
            Transfer,
            Immutable,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "verified_at",
            I64,
            false,
            Transfer,
            Immutable,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
        (
            "raw_device_id",
            Utf8,
            true,
            Transfer,
            Immutable,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "principal_commitment",
            Utf8,
            true,
            Transfer,
            Immutable,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "member_principal_id",
            Utf8,
            true,
            Transfer,
            Immutable,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
    ]
);

pub(super) const RULE_43: FamilyRule = table_rule!(
    "sql/group_member_projection",
    "group_member_projection",
    Transfer,
    Revision,
    false,
    ["group_id", "member_principal_id"],
    [
        (
            "group_id",
            Utf8,
            false,
            Transfer,
            Immutable,
            CodecRule::RequiresOwner {
                owner: "group_member_projection",
                cell_type: CellType::Utf8
            }
        ),
        (
            "member_principal_id",
            Utf8,
            false,
            Transfer,
            Immutable,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "member_id",
            Utf8,
            true,
            Transfer,
            Revision,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        ("role", Utf8, false, Transfer, Revision, CodecRule::Scalar { cell_type: CellType::Utf8 }),
        (
            "joined_epoch",
            I64,
            false,
            Transfer,
            Revision,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
        (
            "removed_epoch",
            I64,
            true,
            Transfer,
            Revision,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
        ("active", I64, false, Transfer, Revision, CodecRule::Scalar { cell_type: CellType::I64 }),
        (
            "updated_at",
            I64,
            false,
            Transfer,
            Revision,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
        (
            "principal_commitment",
            Utf8,
            true,
            Transfer,
            Revision,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
    ]
);

pub(super) const RULE_44: FamilyRule = table_rule!(
    "sql/group_message_tombstone_projection",
    "group_message_tombstone_projection",
    Transfer,
    RestrictUnion,
    true,
    ["group_id", "message_id"],
    [
        (
            "group_id",
            Utf8,
            false,
            Transfer,
            Immutable,
            CodecRule::RequiresOwner {
                owner: "group_message_tombstone_projection",
                cell_type: CellType::Utf8
            }
        ),
        (
            "message_id",
            Utf8,
            false,
            Transfer,
            Immutable,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "tombstone_id",
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
            "delete_scope",
            Utf8,
            false,
            Transfer,
            RestrictUnion,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "deleted_epoch",
            I64,
            false,
            Transfer,
            RestrictUnion,
            CodecRule::Scalar { cell_type: CellType::I64 }
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
            "deleted_at",
            I64,
            false,
            Transfer,
            RestrictUnion,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
    ]
);

pub(super) const RULE_45: FamilyRule = table_rule!(
    "sql/group_pending_undecrypted",
    "group_pending_undecrypted",
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
                owner: "group_pending_undecrypted",
                cell_type: CellType::Utf8
            }
        ),
        (
            "group_id",
            Utf8,
            false,
            Transfer,
            Immutable,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
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
            "group_key_epoch",
            I64,
            false,
            Transfer,
            Immutable,
            CodecRule::Scalar { cell_type: CellType::I64 }
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
            "inbox_seq",
            I64,
            false,
            Transfer,
            Immutable,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
        (
            "envelope_json",
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

pub(super) const RULE_46: FamilyRule = table_rule!(
    "sql/group_projection",
    "group_projection",
    Transfer,
    Revision,
    false,
    ["group_id"],
    [
        (
            "group_id",
            Utf8,
            true,
            Transfer,
            Immutable,
            CodecRule::RequiresOwner { owner: "group_projection", cell_type: CellType::Utf8 }
        ),
        (
            "group_epoch",
            I64,
            false,
            Transfer,
            Revision,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
        ("role", Utf8, true, Transfer, Revision, CodecRule::Scalar { cell_type: CellType::Utf8 }),
        (
            "notification_state",
            Utf8,
            true,
            Transfer,
            Revision,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "max_members",
            I64,
            false,
            Transfer,
            Revision,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
        (
            "new_member_history",
            Utf8,
            false,
            Transfer,
            Revision,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "deleted_at",
            I64,
            true,
            Transfer,
            Revision,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
        (
            "created_at",
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

pub(super) const RULE_47: FamilyRule = table_rule!(
    "sql/group_sender_identity_upgrade",
    "group_sender_identity_upgrade",
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

pub(super) const RULE_48: FamilyRule = table_rule!(
    "sql/group_sender_key_counter_seen",
    "group_sender_key_counter_seen",
    Transfer,
    CursorMax,
    false,
    ["group_id", "group_key_epoch", "sender_id", "counter"],
    [
        (
            "group_id",
            Utf8,
            false,
            Transfer,
            Immutable,
            CodecRule::RequiresOwner {
                owner: "group_sender_key_counter_seen",
                cell_type: CellType::Utf8
            }
        ),
        (
            "group_key_epoch",
            I64,
            false,
            Transfer,
            Immutable,
            CodecRule::Scalar { cell_type: CellType::I64 }
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
            "counter",
            I64,
            false,
            Transfer,
            Immutable,
            CodecRule::Scalar { cell_type: CellType::I64 }
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
            "seen_at",
            I64,
            false,
            Transfer,
            CursorMax,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
    ]
);

pub(super) const RULE_56: FamilyRule = table_rule!(
    "sql/legacy_group_member_device_key",
    "legacy_group_member_device_key",
    Transfer,
    Immutable,
    false,
    [],
    [
        (
            "group_id",
            Utf8,
            true,
            Transfer,
            Immutable,
            CodecRule::RequiresOwner {
                owner: "legacy_group_member_device_key",
                cell_type: CellType::Utf8
            }
        ),
        (
            "member_id",
            Utf8,
            true,
            Transfer,
            Immutable,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "device_signing_public_key",
            Utf8,
            true,
            Transfer,
            Immutable,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "verified_at",
            I64,
            true,
            Transfer,
            Immutable,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
        (
            "raw_device_id",
            Utf8,
            true,
            Transfer,
            Immutable,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "principal_commitment",
            Utf8,
            true,
            Transfer,
            Immutable,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "member_principal_id",
            Utf8,
            true,
            Transfer,
            Immutable,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
    ]
);

pub(super) const RULE_57: FamilyRule = table_rule!(
    "sql/legacy_group_sender_key_counter_seen",
    "legacy_group_sender_key_counter_seen",
    Transfer,
    CursorMax,
    false,
    [],
    [
        (
            "group_id",
            Utf8,
            true,
            Transfer,
            CursorMax,
            CodecRule::RequiresOwner {
                owner: "legacy_group_sender_key_counter_seen",
                cell_type: CellType::Utf8
            }
        ),
        (
            "group_key_epoch",
            I64,
            true,
            Transfer,
            CursorMax,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
        (
            "sender_id",
            Utf8,
            true,
            Transfer,
            CursorMax,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        ("counter", I64, true, Transfer, CursorMax, CodecRule::Scalar { cell_type: CellType::I64 }),
        (
            "message_id",
            Utf8,
            true,
            Transfer,
            CursorMax,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        ("seen_at", I64, true, Transfer, CursorMax, CodecRule::Scalar { cell_type: CellType::I64 }),
    ]
);

pub(super) const RULE_122: FamilyRule = table_rule!(
    "sql/root_group_control_event_seen",
    "root_group_control_event_seen",
    Transfer,
    Immutable,
    false,
    ["group_id", "actor_identity", "event_id"],
    [
        (
            "group_id",
            Utf8,
            false,
            Transfer,
            Immutable,
            CodecRule::RequiresOwner {
                owner: "root_group_control_event_seen",
                cell_type: CellType::Utf8
            }
        ),
        (
            "actor_identity",
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
            "event_kind",
            Utf8,
            false,
            Transfer,
            Immutable,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "actor_device_id",
            Utf8,
            false,
            Transfer,
            Immutable,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "target_member_id",
            Utf8,
            false,
            Transfer,
            Immutable,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "previous_epoch",
            I64,
            false,
            Transfer,
            Immutable,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
        (
            "new_group_epoch",
            I64,
            false,
            Transfer,
            Immutable,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
        (
            "applied_at",
            I64,
            false,
            Transfer,
            Immutable,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
    ]
);

pub(super) const RULE_123: FamilyRule = table_rule!(
    "sql/root_group_invite_identity",
    "root_group_invite_identity",
    Transfer,
    Immutable,
    false,
    ["group_id", "invite_id"],
    [
        (
            "group_id",
            Utf8,
            false,
            Transfer,
            Immutable,
            CodecRule::RequiresOwner {
                owner: "root_group_invite_identity",
                cell_type: CellType::Utf8
            }
        ),
        (
            "invite_id",
            Utf8,
            false,
            Transfer,
            Immutable,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "expected_root",
            Utf8,
            false,
            Transfer,
            Immutable,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "device_name",
            Utf8,
            false,
            Transfer,
            Immutable,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
    ]
);

pub(super) const RULE_124: FamilyRule = table_rule!(
    "sql/root_group_sender_key_counter_seen",
    "root_group_sender_key_counter_seen",
    Transfer,
    CursorMax,
    false,
    ["group_id", "group_key_epoch", "sender_reference", "session_id", "counter"],
    [
        (
            "group_id",
            Utf8,
            false,
            Transfer,
            Immutable,
            CodecRule::RequiresOwner {
                owner: "root_group_sender_key_counter_seen",
                cell_type: CellType::Utf8
            }
        ),
        (
            "group_key_epoch",
            I64,
            false,
            Transfer,
            Immutable,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
        (
            "sender_reference",
            Utf8,
            false,
            Transfer,
            Immutable,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "session_id",
            Utf8,
            false,
            Transfer,
            Immutable,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "counter",
            I64,
            false,
            Transfer,
            Immutable,
            CodecRule::Scalar { cell_type: CellType::I64 }
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
            "seen_at",
            I64,
            false,
            Transfer,
            CursorMax,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
    ]
);

pub(super) const RULE_155: FamilyRule = table_rule!(
    "sql/shared_group_floor_generation",
    "shared_group_floor_generation",
    Rebuild,
    PreferLocal,
    false,
    [],
    [(
        "group_id",
        Utf8,
        false,
        Rebuild,
        PreferLocal,
        CodecRule::Scalar { cell_type: CellType::Utf8 }
    ),]
);

pub(super) const RULE_156: FamilyRule = table_rule!(
    "sql/shared_group_member_projection",
    "shared_group_member_projection",
    Transfer,
    Immutable,
    false,
    ["group_id", "root_commitment", "device_id"],
    [
        (
            "group_id",
            Utf8,
            false,
            Transfer,
            Immutable,
            CodecRule::RequiresOwner {
                owner: "shared_group_member_projection",
                cell_type: CellType::Utf8
            }
        ),
        (
            "root_commitment",
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
            "principal_id",
            Utf8,
            false,
            Transfer,
            Immutable,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "declared_signing_key",
            Utf8,
            false,
            Transfer,
            Immutable,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "current_signing_key",
            Utf8,
            false,
            Transfer,
            Immutable,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "target_delivery_id",
            Utf8,
            false,
            Transfer,
            Immutable,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        ("role", Utf8, false, Transfer, Immutable, CodecRule::Scalar { cell_type: CellType::Utf8 }),
        (
            "joined_epoch",
            I64,
            false,
            Transfer,
            Immutable,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
        ("active", I64, false, Transfer, Immutable, CodecRule::Scalar { cell_type: CellType::I64 }),
    ]
);

pub(super) const RULE_157: FamilyRule = table_rule!(
    "sql/shared_group_removal_floor",
    "shared_group_removal_floor",
    Transfer,
    RestrictUnion,
    true,
    ["group_id", "root_commitment", "device_id"],
    [
        (
            "group_id",
            Utf8,
            false,
            Transfer,
            Immutable,
            CodecRule::RequiresOwner {
                owner: "shared_group_removal_floor",
                cell_type: CellType::Utf8
            }
        ),
        (
            "root_commitment",
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
            "epoch",
            I64,
            false,
            Transfer,
            RestrictUnion,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
    ]
);
