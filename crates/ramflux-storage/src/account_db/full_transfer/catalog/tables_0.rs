// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::{
    CellRule, CellType, CodecRule, Disposition, FamilyRule, FamilySelector, FieldRule, MergeRule,
    U64,
};

pub(super) const RULE_0: FamilyRule = table_rule!(
    "sql/a2ui_surface_cache",
    "a2ui_surface_cache",
    Rebuild,
    PreferLocal,
    false,
    [],
    [
        (
            "surface_id",
            Utf8,
            true,
            Rebuild,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "surface_hash",
            Bytes,
            false,
            Rebuild,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Bytes }
        ),
        (
            "control_session_id",
            Utf8,
            true,
            Rebuild,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "correlation_id",
            Utf8,
            false,
            Rebuild,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "encrypted_surface_payload",
            Bytes,
            false,
            Rebuild,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Bytes }
        ),
        (
            "expires_at",
            I64,
            false,
            Rebuild,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
        (
            "created_at",
            I64,
            false,
            Rebuild,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
    ]
);
pub(super) const RULE_1: FamilyRule = table_rule!(
    "sql/account_erasure_generation",
    "account_erasure_generation",
    Transfer,
    RestrictUnion,
    true,
    ["singleton"],
    [
        (
            "singleton",
            I64,
            true,
            Transfer,
            Immutable,
            CodecRule::SqlI64 { min: "1", max: "1", nullable: false }
        ),
        (
            "generation",
            I64,
            false,
            Transfer,
            RestrictUnion,
            CodecRule::SqlI64 { min: "0", max: "9223372036854775807", nullable: false }
        ),
    ]
);
pub(super) const RULE_2: FamilyRule = table_rule!(
    "sql/account_key_check",
    "account_key_check",
    Rebuild,
    PreferLocal,
    false,
    [],
    [
        (
            "singleton_id",
            I64,
            true,
            Rebuild,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
        (
            "key_fingerprint",
            Utf8,
            false,
            Rebuild,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
    ]
);
pub(super) const RULE_3: FamilyRule = table_rule!(
    "sql/account_mac_bundle/local",
    "account_mac_bundle",
    Exclude,
    PreferLocal,
    false,
    [],
    [
        (
            "bundle_id",
            Utf8,
            true,
            Exclude,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "subkeys",
            Bytes,
            false,
            Exclude,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Bytes }
        ),
        (
            "is_current",
            I64,
            false,
            Exclude,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
    ]
);
pub(super) const RULE_4: FamilyRule = table_rule!(
    "sql/account_mac_bundle/portable",
    "account_mac_bundle",
    Transfer,
    ImportedBundle,
    true,
    ["bundle_id"],
    [
        (
            "bundle_id",
            Utf8,
            true,
            Transfer,
            Immutable,
            CodecRule::SqlBase64 { decoded_bytes: U64(32), nullable: false }
        ),
        ("subkeys", Bytes, false, Transfer, ImportedBundle, CodecRule::SqlMacSubkeys),
        (
            "is_current",
            I64,
            false,
            Exclude,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
    ]
);
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
pub(super) const RULE_6: FamilyRule = table_rule!(
    "sql/audit_log",
    "audit_log",
    Transfer,
    InertHistory,
    false,
    ["audit_id"],
    [
        (
            "audit_id",
            Utf8,
            true,
            Transfer,
            Immutable,
            CodecRule::RequiresOwner { owner: "audit_log", cell_type: CellType::Utf8 }
        ),
        (
            "audit_type",
            Utf8,
            false,
            Transfer,
            InertHistory,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "actor_device_id",
            Utf8,
            false,
            Transfer,
            InertHistory,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "subject_hash",
            Bytes,
            true,
            Transfer,
            InertHistory,
            CodecRule::Scalar { cell_type: CellType::Bytes }
        ),
        (
            "redacted_summary",
            Utf8,
            false,
            Transfer,
            InertHistory,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
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
            "audit_body",
            Bytes,
            true,
            Transfer,
            InertHistory,
            CodecRule::Scalar { cell_type: CellType::Bytes }
        ),
    ]
);
pub(super) const RULE_7: FamilyRule = table_rule!(
    "sql/bot_install_grant",
    "bot_install_grant",
    Transfer,
    InertHistory,
    false,
    ["grant_id"],
    [
        (
            "grant_id",
            Utf8,
            true,
            Transfer,
            Immutable,
            CodecRule::RequiresOwner { owner: "bot_install_grant", cell_type: CellType::Utf8 }
        ),
        (
            "bot_identity_commitment",
            Utf8,
            false,
            Transfer,
            InertHistory,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "bot_manifest_hash",
            Bytes,
            false,
            Transfer,
            InertHistory,
            CodecRule::Scalar { cell_type: CellType::Bytes }
        ),
        (
            "installer_identity",
            Utf8,
            false,
            Transfer,
            InertHistory,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "installer_device_id",
            Utf8,
            false,
            Transfer,
            InertHistory,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "scope_json",
            Bytes,
            false,
            Transfer,
            InertHistory,
            CodecRule::Scalar { cell_type: CellType::Bytes }
        ),
        (
            "conversation_id",
            Utf8,
            true,
            Transfer,
            InertHistory,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "group_id",
            Utf8,
            true,
            Transfer,
            InertHistory,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "expires_at",
            I64,
            false,
            Transfer,
            InertHistory,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
        (
            "signature",
            Bytes,
            false,
            Transfer,
            InertHistory,
            CodecRule::Scalar { cell_type: CellType::Bytes }
        ),
        (
            "revoked_at",
            I64,
            true,
            Transfer,
            InertHistory,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
        (
            "revocation_event_id",
            Utf8,
            true,
            Transfer,
            InertHistory,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "grant_hash",
            Utf8,
            true,
            Transfer,
            InertHistory,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "grant_body",
            Bytes,
            true,
            Transfer,
            InertHistory,
            CodecRule::Scalar { cell_type: CellType::Bytes }
        ),
        (
            "consent_member_ids_json",
            Bytes,
            true,
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
            "created_at",
            I64,
            false,
            Transfer,
            InertHistory,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
    ]
);
pub(super) const RULE_8: FamilyRule = table_rule!(
    "sql/bot_manifest_cache",
    "bot_manifest_cache",
    Rebuild,
    PreferLocal,
    false,
    [],
    [
        (
            "bot_identity_commitment",
            Utf8,
            false,
            Rebuild,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "bot_manifest_hash",
            Bytes,
            true,
            Rebuild,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Bytes }
        ),
        (
            "actor_type",
            Utf8,
            false,
            Rebuild,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "display_name",
            Utf8,
            false,
            Rebuild,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "home_node",
            Utf8,
            false,
            Rebuild,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "owner_identity_commitment",
            Utf8,
            false,
            Rebuild,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "hosting_model",
            Utf8,
            false,
            Rebuild,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "capabilities_json",
            Bytes,
            false,
            Rebuild,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Bytes }
        ),
        (
            "permissions_json",
            Bytes,
            false,
            Rebuild,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Bytes }
        ),
        (
            "safety_disclosure_json",
            Bytes,
            false,
            Rebuild,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Bytes }
        ),
        (
            "manifest_body",
            Bytes,
            false,
            Rebuild,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Bytes }
        ),
        (
            "signature_by_bot_identity",
            Bytes,
            false,
            Rebuild,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Bytes }
        ),
        (
            "expires_at",
            I64,
            true,
            Rebuild,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
        (
            "cached_at",
            I64,
            false,
            Rebuild,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
    ]
);
pub(super) const RULE_9: FamilyRule = table_rule!(
    "sql/bot_trust_pin",
    "bot_trust_pin",
    Transfer,
    InertHistory,
    false,
    ["bot_identity_commitment"],
    [
        (
            "bot_identity_commitment",
            Utf8,
            true,
            Transfer,
            Immutable,
            CodecRule::RequiresOwner { owner: "bot_trust_pin", cell_type: CellType::Utf8 }
        ),
        (
            "bot_public_key",
            Utf8,
            false,
            Transfer,
            InertHistory,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "signing_key_id",
            Utf8,
            false,
            Transfer,
            InertHistory,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "trust_source",
            Utf8,
            false,
            Transfer,
            InertHistory,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "pinned_at",
            I64,
            false,
            Transfer,
            InertHistory,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
    ]
);
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
pub(super) const RULE_30: FamilyRule = table_rule!(
    "sql/device_directory",
    "device_directory",
    Transfer,
    Immutable,
    false,
    ["device_id"],
    [
        (
            "device_id",
            Utf8,
            true,
            Transfer,
            Immutable,
            CodecRule::RequiresOwner { owner: "device_directory", cell_type: CellType::Utf8 }
        ),
        (
            "principal_commitment",
            Utf8,
            false,
            Transfer,
            Immutable,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "source",
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
    ]
);
pub(super) const RULE_31: FamilyRule = table_rule!(
    "sql/device_identity",
    "device_identity",
    Transfer,
    Immutable,
    false,
    ["device_id"],
    [
        (
            "device_id",
            Utf8,
            true,
            Transfer,
            Immutable,
            CodecRule::RequiresOwner { owner: "device_identity", cell_type: CellType::Utf8 }
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
            "principal_commitment",
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
            "branch_proof_hash",
            Bytes,
            false,
            Transfer,
            Immutable,
            CodecRule::Scalar { cell_type: CellType::Bytes }
        ),
        (
            "capability_scope_json",
            Utf8,
            false,
            Transfer,
            Immutable,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "client_mode",
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
pub(super) const RULE_32: FamilyRule = table_rule!(
    "sql/device_inbox_cursor",
    "device_inbox_cursor",
    Exclude,
    PreferLocal,
    false,
    [],
    [
        (
            "device_id",
            Utf8,
            true,
            Exclude,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "cursor_id",
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
            "lamport_time",
            I64,
            false,
            Exclude,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::I64 }
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
pub(super) const RULE_33: FamilyRule = table_rule!(
    "sql/device_namespace_upgrade",
    "device_namespace_upgrade",
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
pub(super) const RULE_35: FamilyRule = table_rule!(
    "sql/event_causal_dependency",
    "event_causal_dependency",
    Transfer,
    Immutable,
    false,
    ["event_id", "depends_on_event_id"],
    [
        (
            "event_id",
            Utf8,
            false,
            Transfer,
            Immutable,
            CodecRule::RequiresOwner {
                owner: "event_causal_dependency",
                cell_type: CellType::Utf8
            }
        ),
        (
            "depends_on_event_id",
            Utf8,
            false,
            Transfer,
            Immutable,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "dependency_state",
            Utf8,
            false,
            Transfer,
            Immutable,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
    ]
);
pub(super) const RULE_36: FamilyRule = table_rule!(
    "sql/event_tombstone",
    "event_tombstone",
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
            CodecRule::RequiresOwner { owner: "event_tombstone", cell_type: CellType::Utf8 }
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
