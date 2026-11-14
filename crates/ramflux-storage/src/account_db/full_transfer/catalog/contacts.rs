// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Full-transfer SQL family declarations for contacts.
use super::{
    CellRule, CellType, CodecRule, Disposition, FamilyRule, FamilySelector, FieldRule, MergeRule,
    U64,
};

pub(super) const RULE_10: FamilyRule = table_rule!(
    "sql/contact_link_decision",
    "contact_link_decision",
    Transfer,
    RestrictUnion,
    true,
    ["link_id"],
    [
        (
            "link_id",
            Utf8,
            true,
            Transfer,
            Immutable,
            CodecRule::RequiresOwner { owner: "contact_link_decision", cell_type: CellType::Utf8 }
        ),
        (
            "state",
            Utf8,
            false,
            Transfer,
            RestrictUnion,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "decided_at",
            I64,
            false,
            Transfer,
            RestrictUnion,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
    ]
);

pub(super) const RULE_11: FamilyRule = table_rule!(
    "sql/contact_message_fence_retention",
    "contact_message_fence_retention",
    Transfer,
    RestrictUnion,
    true,
    ["sender_identity", "message_id"],
    [
        (
            "sender_identity",
            Utf8,
            false,
            Transfer,
            Immutable,
            CodecRule::RequiresOwner {
                owner: "contact_message_fence_retention",
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
            "until",
            I64,
            false,
            Transfer,
            RestrictUnion,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
    ]
);

pub(super) const RULE_12: FamilyRule = table_rule!(
    "sql/contact_message_request",
    "contact_message_request",
    Transfer,
    Immutable,
    false,
    ["sender_identity", "message_id"],
    [
        (
            "contact_identity_commitment",
            Utf8,
            false,
            Transfer,
            Immutable,
            CodecRule::RequiresOwner {
                owner: "contact_message_request",
                cell_type: CellType::Utf8
            }
        ),
        (
            "sender_identity",
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
            "message_json",
            Bytes,
            false,
            Transfer,
            Immutable,
            CodecRule::Scalar { cell_type: CellType::Bytes }
        ),
        (
            "byte_count",
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
            "created_at",
            I64,
            false,
            Transfer,
            Immutable,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
    ]
);

pub(super) const RULE_13: FamilyRule = table_rule!(
    "sql/contact_message_request_fence",
    "contact_message_request_fence",
    Transfer,
    RestrictUnion,
    true,
    ["sender_identity", "message_id"],
    [
        (
            "sender_identity",
            Utf8,
            false,
            Transfer,
            Immutable,
            CodecRule::RequiresOwner {
                owner: "contact_message_request_fence",
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
    ]
);

pub(super) const RULE_14: FamilyRule = table_rule!(
    "sql/contact_request_authority_floor",
    "contact_request_authority_floor",
    Transfer,
    RestrictUnion,
    true,
    ["root"],
    [
        (
            "root",
            Utf8,
            true,
            Transfer,
            Immutable,
            CodecRule::RequiresOwner {
                owner: "contact_request_authority_floor",
                cell_type: CellType::Utf8
            }
        ),
        (
            "epoch",
            I64,
            false,
            Transfer,
            RestrictUnion,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
        (
            "record_hash",
            Utf8,
            false,
            Transfer,
            RestrictUnion,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "until",
            I64,
            false,
            Transfer,
            RestrictUnion,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
    ]
);

pub(super) const RULE_15: FamilyRule = table_rule!(
    "sql/contact_request_decision",
    "contact_request_decision",
    Transfer,
    RestrictUnion,
    true,
    ["root"],
    [
        (
            "root",
            Utf8,
            true,
            Transfer,
            Immutable,
            CodecRule::RequiresOwner {
                owner: "contact_request_decision",
                cell_type: CellType::Utf8
            }
        ),
        (
            "state",
            Utf8,
            false,
            Transfer,
            RestrictUnion,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "decided_at",
            I64,
            false,
            Transfer,
            RestrictUnion,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
    ]
);

pub(super) const RULE_16: FamilyRule = table_rule!(
    "sql/contact_request_delivery",
    "contact_request_delivery",
    Transfer,
    Immutable,
    false,
    ["request_id", "recipient_identity"],
    [
        (
            "request_id",
            Utf8,
            false,
            Transfer,
            Immutable,
            CodecRule::RequiresOwner {
                owner: "contact_request_delivery",
                cell_type: CellType::Utf8
            }
        ),
        (
            "recipient_identity",
            Utf8,
            false,
            Transfer,
            Immutable,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "material_hash",
            Utf8,
            false,
            Transfer,
            Immutable,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "submitted_at",
            I64,
            false,
            Transfer,
            Immutable,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
    ]
);

pub(super) const RULE_17: FamilyRule = table_rule!(
    "sql/contact_request_fence",
    "contact_request_fence",
    Transfer,
    RestrictUnion,
    true,
    ["root"],
    [
        (
            "root",
            Utf8,
            true,
            Transfer,
            Immutable,
            CodecRule::RequiresOwner { owner: "contact_request_fence", cell_type: CellType::Utf8 }
        ),
        (
            "state",
            Utf8,
            false,
            Transfer,
            RestrictUnion,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "until",
            I64,
            false,
            Transfer,
            RestrictUnion,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
    ]
);

pub(super) const RULE_18: FamilyRule = table_rule!(
    "sql/contact_request_projection",
    "contact_request_projection",
    Transfer,
    Immutable,
    false,
    ["contact_identity_commitment", "direction"],
    [
        (
            "contact_identity_commitment",
            Utf8,
            false,
            Transfer,
            Immutable,
            CodecRule::RequiresOwner {
                owner: "contact_request_projection",
                cell_type: CellType::Utf8
            }
        ),
        (
            "direction",
            Utf8,
            false,
            Transfer,
            Immutable,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "request_id",
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
            "link_id",
            Utf8,
            false,
            Transfer,
            Immutable,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
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
            "request_json",
            Bytes,
            false,
            Transfer,
            Immutable,
            CodecRule::Scalar { cell_type: CellType::Bytes }
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
            "updated_at",
            I64,
            false,
            Transfer,
            Immutable,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
    ]
);

pub(super) const RULE_19: FamilyRule = table_rule!(
    "sql/contact_request_rate",
    "contact_request_rate",
    Exclude,
    PreferLocal,
    false,
    [],
    [
        (
            "bucket",
            Utf8,
            true,
            Exclude,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "window_end",
            I64,
            false,
            Exclude,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
        ("count", I64, false, Exclude, PreferLocal, CodecRule::Scalar { cell_type: CellType::I64 }),
    ]
);

pub(super) const RULE_20: FamilyRule = table_rule!(
    "sql/contact_request_retirement",
    "contact_request_retirement",
    Transfer,
    RestrictUnion,
    true,
    ["root", "direction"],
    [
        (
            "root",
            Utf8,
            false,
            Transfer,
            Immutable,
            CodecRule::RequiresOwner {
                owner: "contact_request_retirement",
                cell_type: CellType::Utf8
            }
        ),
        (
            "direction",
            Utf8,
            false,
            Transfer,
            Immutable,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "next_at",
            I64,
            false,
            Transfer,
            RestrictUnion,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
    ]
);

pub(super) const RULE_21: FamilyRule = table_rule!(
    "sql/contact_verification_projection",
    "contact_verification_projection",
    Transfer,
    Revision,
    false,
    ["contact_identity_commitment"],
    [
        (
            "contact_identity_commitment",
            Utf8,
            true,
            Transfer,
            Immutable,
            CodecRule::RequiresOwner {
                owner: "contact_verification_projection",
                cell_type: CellType::Utf8
            }
        ),
        (
            "verification_state",
            Utf8,
            false,
            Transfer,
            Revision,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "safety_number_hash",
            Utf8,
            false,
            Transfer,
            Revision,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "verified_device_set_hash",
            Utf8,
            false,
            Transfer,
            Revision,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "verified_lineage_head",
            Utf8,
            false,
            Transfer,
            Revision,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "verified_at",
            I64,
            false,
            Transfer,
            Revision,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
        (
            "verified_by_device_id",
            Utf8,
            false,
            Transfer,
            Revision,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "last_change_event_id",
            Utf8,
            true,
            Transfer,
            Revision,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "last_change_seen_at",
            I64,
            true,
            Transfer,
            Revision,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
        (
            "kt_tree_size",
            I64,
            true,
            Transfer,
            Revision,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
        (
            "kt_tree_root_hash",
            Utf8,
            true,
            Transfer,
            Revision,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "kt_leaf_index",
            I64,
            true,
            Transfer,
            Revision,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
        (
            "last_gossip_lineage_head",
            Utf8,
            true,
            Transfer,
            Revision,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
    ]
);

pub(super) const RULE_37: FamilyRule = table_rule!(
    "sql/friend_link_projection",
    "friend_link_projection",
    Transfer,
    Revision,
    false,
    ["link_id"],
    [
        (
            "link_id",
            Utf8,
            true,
            Transfer,
            Immutable,
            CodecRule::RequiresOwner { owner: "friend_link_projection", cell_type: CellType::Utf8 }
        ),
        (
            "requester_id",
            Utf8,
            false,
            Transfer,
            Revision,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "target_id",
            Utf8,
            false,
            Transfer,
            Revision,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        ("state", Utf8, false, Transfer, Revision, CodecRule::Scalar { cell_type: CellType::Utf8 }),
        (
            "remove_scope",
            Utf8,
            true,
            Transfer,
            Revision,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        ("blocked", I64, false, Transfer, Revision, CodecRule::Scalar { cell_type: CellType::I64 }),
        (
            "capability_revoked_at",
            I64,
            true,
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

pub(super) const RULE_38: FamilyRule = table_rule!(
    "sql/friend_projection",
    "friend_projection",
    Transfer,
    Revision,
    false,
    ["link_id"],
    [
        (
            "link_id",
            Utf8,
            true,
            Transfer,
            Immutable,
            CodecRule::RequiresOwner { owner: "friend_projection", cell_type: CellType::Utf8 }
        ),
        (
            "peer_principal_id",
            Utf8,
            false,
            Transfer,
            Revision,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "link_state",
            Utf8,
            false,
            Transfer,
            Revision,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "capability_id",
            Utf8,
            true,
            Transfer,
            Revision,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "blocked_at",
            I64,
            true,
            Transfer,
            Revision,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
        (
            "removed_at",
            I64,
            true,
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
