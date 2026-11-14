// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Full-transfer SQL family declarations for objects.
use super::{
    CellRule, CellType, CodecRule, Disposition, FamilyRule, FamilySelector, FieldRule, MergeRule,
    U64,
};

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

pub(super) const RULE_75: FamilyRule = table_rule!(
    "sql/object_chunk/local",
    "object_chunk",
    Exclude,
    PreferLocal,
    false,
    [],
    [
        (
            "chunk_id",
            Utf8,
            true,
            Exclude,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "object_id",
            Utf8,
            false,
            Exclude,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "chunk_index",
            I64,
            false,
            Exclude,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
        (
            "chunk_cipher_hash",
            Bytes,
            false,
            Exclude,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Bytes }
        ),
        (
            "chunk_plain_hash",
            Bytes,
            true,
            Exclude,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Bytes }
        ),
        (
            "cipher_size",
            I64,
            false,
            Exclude,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
        (
            "local_path",
            Utf8,
            true,
            Exclude,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "chunk_state",
            Utf8,
            false,
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

pub(super) const RULE_76: FamilyRule = table_rule!(
    "sql/object_chunk/portable",
    "object_chunk",
    Transfer,
    Immutable,
    false,
    ["chunk_id"],
    [
        (
            "chunk_id",
            Utf8,
            true,
            Transfer,
            Immutable,
            CodecRule::RequiresOwner { owner: "object_chunk", cell_type: CellType::Utf8 }
        ),
        (
            "object_id",
            Utf8,
            false,
            Transfer,
            Immutable,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "chunk_index",
            I64,
            false,
            Transfer,
            Immutable,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
        (
            "chunk_cipher_hash",
            Bytes,
            false,
            Transfer,
            Immutable,
            CodecRule::Scalar { cell_type: CellType::Bytes }
        ),
        (
            "chunk_plain_hash",
            Bytes,
            true,
            Transfer,
            Immutable,
            CodecRule::Scalar { cell_type: CellType::Bytes }
        ),
        (
            "cipher_size",
            I64,
            false,
            Transfer,
            Immutable,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
        (
            "local_path",
            Utf8,
            true,
            Exclude,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "chunk_state",
            Utf8,
            false,
            Exclude,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
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

pub(super) const RULE_77: FamilyRule = table_rule!(
    "sql/object_erasure_fence",
    "object_erasure_fence",
    Transfer,
    RestrictUnion,
    true,
    ["commitment"],
    [(
        "commitment",
        Utf8,
        false,
        Transfer,
        Immutable,
        CodecRule::SqlBase64 { decoded_bytes: U64(32), nullable: false }
    ),]
);

pub(super) const RULE_78: FamilyRule = table_rule!(
    "sql/object_erasure_lookup",
    "object_erasure_lookup",
    Transfer,
    RestrictUnion,
    true,
    ["lookup"],
    [
        (
            "lookup",
            Utf8,
            true,
            Transfer,
            Immutable,
            CodecRule::SqlBase64 { decoded_bytes: U64(32), nullable: false }
        ),
        (
            "commitment",
            Utf8,
            false,
            Transfer,
            RestrictUnion,
            CodecRule::SqlBase64 { decoded_bytes: U64(32), nullable: false }
        ),
    ]
);

pub(super) const RULE_79: FamilyRule = table_rule!(
    "sql/object_erasure_work",
    "object_erasure_work",
    Rebuild,
    PreferLocal,
    false,
    [],
    [
        (
            "commitment",
            Utf8,
            true,
            Rebuild,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "wire_id",
            Utf8,
            false,
            Rebuild,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "manifest_hash",
            Utf8,
            false,
            Rebuild,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
    ]
);

pub(super) const RULE_80: FamilyRule = table_rule!(
    "sql/object_identity_replacement",
    "object_identity_replacement",
    Transfer,
    RestrictUnion,
    true,
    ["commitment"],
    [(
        "commitment",
        Utf8,
        true,
        Transfer,
        Immutable,
        CodecRule::SqlBase64 { decoded_bytes: U64(32), nullable: false }
    ),]
);

pub(super) const RULE_81: FamilyRule = table_rule!(
    "sql/object_index/local",
    "object_index",
    Exclude,
    PreferLocal,
    false,
    [],
    [
        (
            "object_id",
            Utf8,
            true,
            Exclude,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "chunk_manifest_hash",
            Bytes,
            false,
            Exclude,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Bytes }
        ),
        (
            "object_created_group_key_epoch",
            I64,
            true,
            Exclude,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
        (
            "object_state",
            Utf8,
            false,
            Exclude,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "total_cipher_size",
            I64,
            false,
            Exclude,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
        (
            "chunk_count",
            I64,
            false,
            Exclude,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
        (
            "created_at",
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
        (
            "manifest_hash",
            Bytes,
            true,
            Exclude,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Bytes }
        ),
        (
            "nonce",
            Utf8,
            true,
            Exclude,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "ciphertext",
            Bytes,
            true,
            Exclude,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Bytes }
        ),
        (
            "plaintext_hash",
            Utf8,
            true,
            Exclude,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "tombstoned",
            I64,
            false,
            Exclude,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
        (
            "backup_excluded",
            I64,
            false,
            Exclude,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
        (
            "object_content_key",
            Bytes,
            true,
            Exclude,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Bytes }
        ),
        (
            "object_body",
            Bytes,
            true,
            Exclude,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Bytes }
        ),
    ]
);

pub(super) const RULE_82: FamilyRule = table_rule!(
    "sql/object_index/portable",
    "object_index",
    Transfer,
    Immutable,
    false,
    ["object_id"],
    [
        (
            "object_id",
            Utf8,
            true,
            Transfer,
            Immutable,
            CodecRule::RequiresOwner { owner: "object_index", cell_type: CellType::Utf8 }
        ),
        (
            "chunk_manifest_hash",
            Bytes,
            false,
            Transfer,
            Immutable,
            CodecRule::Scalar { cell_type: CellType::Bytes }
        ),
        (
            "object_created_group_key_epoch",
            I64,
            true,
            Transfer,
            Immutable,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
        (
            "object_state",
            Utf8,
            false,
            Transfer,
            Immutable,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "total_cipher_size",
            I64,
            false,
            Transfer,
            Immutable,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
        (
            "chunk_count",
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
        (
            "updated_at",
            I64,
            false,
            Transfer,
            Immutable,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
        (
            "manifest_hash",
            Bytes,
            true,
            Transfer,
            Immutable,
            CodecRule::Scalar { cell_type: CellType::Bytes }
        ),
        ("nonce", Utf8, true, Transfer, Immutable, CodecRule::Scalar { cell_type: CellType::Utf8 }),
        (
            "ciphertext",
            Bytes,
            true,
            Exclude,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Bytes }
        ),
        (
            "plaintext_hash",
            Utf8,
            true,
            Transfer,
            Immutable,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "tombstoned",
            I64,
            false,
            Transfer,
            Immutable,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
        (
            "backup_excluded",
            I64,
            false,
            Transfer,
            Immutable,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
        (
            "object_content_key",
            Bytes,
            true,
            Transfer,
            Immutable,
            CodecRule::Scalar { cell_type: CellType::Bytes }
        ),
        (
            "object_body",
            Bytes,
            true,
            Transfer,
            Immutable,
            CodecRule::Scalar { cell_type: CellType::Bytes }
        ),
    ]
);

pub(super) const RULE_83: FamilyRule = table_rule!(
    "sql/object_key_slot",
    "object_key_slot",
    Transfer,
    Immutable,
    false,
    ["slot_id"],
    [
        (
            "slot_id",
            Utf8,
            true,
            Transfer,
            Immutable,
            CodecRule::RequiresOwner { owner: "object_key_slot", cell_type: CellType::Utf8 }
        ),
        (
            "object_id",
            Utf8,
            false,
            Transfer,
            Immutable,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "recipient_kind",
            Utf8,
            false,
            Transfer,
            Immutable,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "recipient_id_hash",
            Bytes,
            false,
            Transfer,
            Immutable,
            CodecRule::Scalar { cell_type: CellType::Bytes }
        ),
        (
            "group_key_epoch",
            I64,
            true,
            Transfer,
            Immutable,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
        (
            "wrapped_key",
            Bytes,
            false,
            Transfer,
            Immutable,
            CodecRule::Scalar { cell_type: CellType::Bytes }
        ),
        (
            "key_wrap_alg",
            Utf8,
            false,
            Transfer,
            Immutable,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
    ]
);

pub(super) const RULE_84: FamilyRule = table_rule!(
    "sql/object_legacy_reference_context",
    "object_legacy_reference_context",
    Transfer,
    Immutable,
    false,
    ["selector"],
    [
        (
            "selector",
            Utf8,
            true,
            Transfer,
            Immutable,
            CodecRule::RequiresOwner {
                owner: "object_legacy_reference_context",
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
            "manifest_hash",
            Utf8,
            false,
            Transfer,
            Immutable,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "metadata_json",
            Bytes,
            false,
            Transfer,
            Immutable,
            CodecRule::Scalar { cell_type: CellType::Bytes }
        ),
    ]
);

pub(super) const RULE_85: FamilyRule = table_rule!(
    "sql/object_manifest",
    "object_manifest",
    Transfer,
    Immutable,
    false,
    ["object_id"],
    [
        (
            "object_id",
            Utf8,
            true,
            Transfer,
            Immutable,
            CodecRule::RequiresOwner { owner: "object_manifest", cell_type: CellType::Utf8 }
        ),
        (
            "manifest_hash",
            Bytes,
            false,
            Transfer,
            Immutable,
            CodecRule::Scalar { cell_type: CellType::Bytes }
        ),
        (
            "encrypted_owner_ref",
            Bytes,
            false,
            Transfer,
            Immutable,
            CodecRule::Scalar { cell_type: CellType::Bytes }
        ),
        (
            "encrypted_relation_ref",
            Bytes,
            true,
            Transfer,
            Immutable,
            CodecRule::Scalar { cell_type: CellType::Bytes }
        ),
        (
            "encrypted_metadata",
            Bytes,
            false,
            Transfer,
            Immutable,
            CodecRule::Scalar { cell_type: CellType::Bytes }
        ),
        (
            "object_key_slots",
            Bytes,
            false,
            Transfer,
            Immutable,
            CodecRule::Scalar { cell_type: CellType::Bytes }
        ),
        (
            "object_created_group_key_epoch",
            I64,
            true,
            Transfer,
            Immutable,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
        (
            "chunk_manifest_hash",
            Bytes,
            false,
            Transfer,
            Immutable,
            CodecRule::Scalar { cell_type: CellType::Bytes }
        ),
        (
            "chunk_count",
            I64,
            false,
            Transfer,
            Immutable,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
        (
            "total_cipher_size",
            I64,
            false,
            Transfer,
            Immutable,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
        (
            "signature",
            Bytes,
            true,
            Transfer,
            Immutable,
            CodecRule::Scalar { cell_type: CellType::Bytes }
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

pub(super) const RULE_86: FamilyRule = table_rule!(
    "sql/object_message_reference",
    "object_message_reference",
    Transfer,
    Immutable,
    false,
    ["message_id", "reference_hash"],
    [
        (
            "message_id",
            Utf8,
            false,
            Transfer,
            Immutable,
            CodecRule::RequiresOwner {
                owner: "object_message_reference",
                cell_type: CellType::Utf8
            }
        ),
        (
            "reference_hash",
            Utf8,
            false,
            Transfer,
            Immutable,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "metadata_json",
            Bytes,
            false,
            Transfer,
            Immutable,
            CodecRule::Scalar { cell_type: CellType::Bytes }
        ),
    ]
);

pub(super) const RULE_87: FamilyRule = table_rule!(
    "sql/object_operation",
    "object_operation",
    Transfer,
    InertHistory,
    false,
    ["object_id"],
    [
        (
            "object_id",
            Utf8,
            true,
            Transfer,
            Immutable,
            CodecRule::RequiresOwner { owner: "object_operation", cell_type: CellType::Utf8 }
        ),
        (
            "operation_id",
            Utf8,
            false,
            Transfer,
            InertHistory,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
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
            "request_hash",
            Bytes,
            false,
            Transfer,
            InertHistory,
            CodecRule::Scalar { cell_type: CellType::Bytes }
        ),
        (
            "manifest_hash",
            Utf8,
            true,
            Transfer,
            InertHistory,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "plaintext_hash",
            Utf8,
            true,
            Transfer,
            InertHistory,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "terminal_result",
            Bytes,
            true,
            Transfer,
            InertHistory,
            CodecRule::Scalar { cell_type: CellType::Bytes }
        ),
        (
            "last_error",
            Utf8,
            true,
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
            "updated_at",
            I64,
            false,
            Transfer,
            InertHistory,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
    ]
);

pub(super) const RULE_88: FamilyRule = table_rule!(
    "sql/object_payload_actor",
    "object_payload_actor",
    Rebuild,
    PreferLocal,
    false,
    [],
    [
        (
            "commitment",
            Utf8,
            false,
            Rebuild,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "state_kind",
            Utf8,
            false,
            Rebuild,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
    ]
);

pub(super) const RULE_89: FamilyRule = table_rule!(
    "sql/object_payload_dependency",
    "object_payload_dependency",
    Transfer,
    Immutable,
    false,
    ["parent_commitment", "child_commitment"],
    [
        (
            "parent_commitment",
            Utf8,
            false,
            Transfer,
            Immutable,
            CodecRule::SqlBase64 { decoded_bytes: U64(32), nullable: false }
        ),
        (
            "child_commitment",
            Utf8,
            false,
            Transfer,
            Immutable,
            CodecRule::SqlBase64 { decoded_bytes: U64(32), nullable: false }
        ),
    ]
);

pub(super) const RULE_90: FamilyRule = table_rule!(
    "sql/object_projection_erasure_work",
    "object_projection_erasure_work",
    Rebuild,
    PreferLocal,
    false,
    [],
    [(
        "selector",
        Utf8,
        true,
        Rebuild,
        PreferLocal,
        CodecRule::Scalar { cell_type: CellType::Utf8 }
    ),]
);

pub(super) const RULE_91: FamilyRule = table_rule!(
    "sql/object_reference_actor",
    "object_reference_actor",
    Rebuild,
    PreferLocal,
    false,
    [],
    [
        (
            "reference_hash",
            Utf8,
            false,
            Rebuild,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "state_kind",
            Utf8,
            false,
            Rebuild,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
    ]
);

pub(super) const RULE_92: FamilyRule = table_rule!(
    "sql/object_reference_erasure_work",
    "object_reference_erasure_work",
    Rebuild,
    PreferLocal,
    false,
    [],
    [
        (
            "reference_hash",
            Utf8,
            true,
            Rebuild,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "selector",
            Utf8,
            false,
            Rebuild,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "selector_lookup",
            Utf8,
            false,
            Rebuild,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "commitment",
            Utf8,
            false,
            Rebuild,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
    ]
);

pub(super) const RULE_93: FamilyRule = table_rule!(
    "sql/object_retention_payload",
    "object_retention_payload",
    Rebuild,
    PreferLocal,
    false,
    [],
    [
        (
            "commitment",
            Utf8,
            true,
            Rebuild,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "wire_id",
            Utf8,
            false,
            Rebuild,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "manifest_hash",
            Utf8,
            false,
            Rebuild,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "wire_lookup",
            Utf8,
            false,
            Rebuild,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "retention_class",
            Utf8,
            false,
            Rebuild,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "hold_expires_at",
            I64,
            true,
            Rebuild,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
        (
            "owner_count",
            I64,
            false,
            Rebuild,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
    ]
);

pub(super) const RULE_94: FamilyRule = table_rule!(
    "sql/object_retention_reference",
    "object_retention_reference",
    Rebuild,
    PreferLocal,
    false,
    [],
    [
        (
            "reference_hash",
            Utf8,
            true,
            Rebuild,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "commitment",
            Utf8,
            false,
            Rebuild,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "selector",
            Utf8,
            false,
            Rebuild,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "selector_lookup",
            Utf8,
            false,
            Rebuild,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "reference_json",
            Bytes,
            false,
            Rebuild,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Bytes }
        ),
    ]
);

pub(super) const RULE_95: FamilyRule = table_rule!(
    "sql/object_retention_upgrade",
    "object_retention_upgrade",
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
            "format_version",
            I64,
            false,
            Rebuild,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
        ("phase", I64, false, Rebuild, PreferLocal, CodecRule::Scalar { cell_type: CellType::I64 }),
        (
            "cursor",
            I64,
            false,
            Rebuild,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
        (
            "rows_scanned",
            I64,
            false,
            Rebuild,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
        (
            "decoded_bytes",
            I64,
            false,
            Rebuild,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
        (
            "unsafe_references",
            I64,
            false,
            Rebuild,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
    ]
);

pub(super) const RULE_96: FamilyRule = table_rule!(
    "sql/object_runtime_response",
    "object_runtime_response",
    Rebuild,
    PreferLocal,
    false,
    [],
    [
        (
            "commitment",
            Utf8,
            false,
            Rebuild,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "operation_id",
            Utf8,
            false,
            Rebuild,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
    ]
);

pub(super) const RULE_97: FamilyRule = table_rule!(
    "sql/object_segment_file",
    "object_segment_file",
    Rebuild,
    PreferLocal,
    false,
    [],
    [
        (
            "transfer_id",
            Utf8,
            false,
            Rebuild,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "generation",
            I64,
            false,
            Rebuild,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
        (
            "segment_index",
            I64,
            false,
            Rebuild,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
        (
            "expected_digest",
            Bytes,
            false,
            Rebuild,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Bytes }
        ),
        (
            "expected_length",
            I64,
            false,
            Rebuild,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
        (
            "received_bitmap",
            I64,
            false,
            Rebuild,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
        (
            "chunk_digests",
            Bytes,
            false,
            Rebuild,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Bytes }
        ),
        (
            "cipher_verified",
            I64,
            false,
            Rebuild,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
    ]
);

pub(super) const RULE_98: FamilyRule = table_rule!(
    "sql/object_segment_floor",
    "object_segment_floor",
    Transfer,
    RestrictUnion,
    true,
    ["directory"],
    [
        (
            "directory",
            Utf8,
            true,
            Transfer,
            Immutable,
            CodecRule::RequiresOwner { owner: "object_segment_floor", cell_type: CellType::Utf8 }
        ),
        (
            "generation",
            I64,
            false,
            Transfer,
            RestrictUnion,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
    ]
);

pub(super) const RULE_99: FamilyRule = table_rule!(
    "sql/object_segment_reference_veto",
    "object_segment_reference_veto",
    Transfer,
    RestrictUnion,
    true,
    ["reference_id"],
    [(
        "reference_id",
        Bytes,
        true,
        Transfer,
        Immutable,
        CodecRule::SqlBytes { length: U64(32), nullable: false }
    ),]
);

pub(super) const RULE_100: FamilyRule = table_rule!(
    "sql/object_segment_resource",
    "object_segment_resource",
    Rebuild,
    PreferLocal,
    false,
    [],
    [
        (
            "directory",
            Utf8,
            false,
            Rebuild,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "generation",
            I64,
            false,
            Rebuild,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
        (
            "transfer_id",
            Utf8,
            true,
            Rebuild,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "wire",
            Utf8,
            false,
            Rebuild,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "manifest",
            Utf8,
            false,
            Rebuild,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "commitment",
            Utf8,
            false,
            Rebuild,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "selector",
            Utf8,
            true,
            Rebuild,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "reference_hash",
            Utf8,
            true,
            Rebuild,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "message_id",
            Utf8,
            true,
            Rebuild,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "retired",
            I64,
            false,
            Rebuild,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
    ]
);

pub(super) const RULE_101: FamilyRule = table_rule!(
    "sql/object_share_grant_projection",
    "object_share_grant_projection",
    Transfer,
    InertHistory,
    false,
    ["object_id", "recipient_principal_id"],
    [
        (
            "object_id",
            Utf8,
            false,
            Transfer,
            Immutable,
            CodecRule::RequiresOwner {
                owner: "object_share_grant_projection",
                cell_type: CellType::Utf8
            }
        ),
        (
            "recipient_principal_id",
            Utf8,
            false,
            Transfer,
            Immutable,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "recipient_principal_commitment",
            Utf8,
            true,
            Transfer,
            InertHistory,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "recipient_device_id",
            Utf8,
            true,
            Transfer,
            InertHistory,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
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
            "shared_at",
            I64,
            false,
            Transfer,
            InertHistory,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
        (
            "revoked_at",
            I64,
            true,
            Transfer,
            InertHistory,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
    ]
);

pub(super) const RULE_102: FamilyRule = table_rule!(
    "sql/object_tombstone",
    "object_tombstone",
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
            CodecRule::RequiresOwner { owner: "object_tombstone", cell_type: CellType::Utf8 }
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

pub(super) const RULE_103: FamilyRule = table_rule!(
    "sql/object_transfer_state",
    "object_transfer_state",
    Rebuild,
    PreferLocal,
    false,
    [],
    [
        (
            "transfer_id",
            Utf8,
            true,
            Rebuild,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "object_id",
            Utf8,
            false,
            Rebuild,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "peer_device_id",
            Utf8,
            false,
            Rebuild,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "manifest_hash",
            Bytes,
            false,
            Rebuild,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Bytes }
        ),
        (
            "resume_token",
            Utf8,
            true,
            Rebuild,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "missing_chunk_bitmap",
            Bytes,
            false,
            Rebuild,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Bytes }
        ),
        (
            "completed_chunk_bitmap",
            Bytes,
            false,
            Rebuild,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Bytes }
        ),
        (
            "state",
            Utf8,
            false,
            Rebuild,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "last_error",
            Utf8,
            true,
            Rebuild,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "updated_at",
            I64,
            false,
            Rebuild,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
        (
            "direction",
            Utf8,
            false,
            Rebuild,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "relay_endpoint",
            Utf8,
            true,
            Rebuild,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "chunk_size",
            I64,
            false,
            Rebuild,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
        (
            "total_bytes",
            I64,
            false,
            Rebuild,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
        (
            "done_bytes",
            I64,
            false,
            Rebuild,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
        (
            "total_chunks",
            I64,
            false,
            Rebuild,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
        (
            "next_chunk_index",
            I64,
            true,
            Rebuild,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::I64 }
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
            "segment_generation",
            I64,
            true,
            Rebuild,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
        (
            "segment_sequence",
            I64,
            false,
            Rebuild,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
        (
            "segment_manifest",
            Bytes,
            true,
            Rebuild,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Bytes }
        ),
    ]
);

pub(super) const RULE_104: FamilyRule = table_rule!(
    "sql/object_transport_actor",
    "object_transport_actor",
    Rebuild,
    PreferLocal,
    false,
    [],
    [
        (
            "commitment",
            Utf8,
            false,
            Rebuild,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "state_kind",
            Utf8,
            false,
            Rebuild,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
    ]
);

pub(super) const RULE_129: FamilyRule = table_rule!(
    "sql/runtime_attachment_budget",
    "runtime_attachment_budget",
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
            "grants",
            I64,
            false,
            Rebuild,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
    ]
);

pub(super) const RULE_130: FamilyRule = table_rule!(
    "sql/runtime_attachment_expiry",
    "runtime_attachment_expiry",
    Rebuild,
    PreferLocal,
    false,
    [],
    [
        (
            "grant_id",
            Bytes,
            true,
            Rebuild,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Bytes }
        ),
        (
            "expires",
            I64,
            false,
            Rebuild,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
    ]
);

pub(super) const RULE_131: FamilyRule = table_rule!(
    "sql/runtime_attachment_grant",
    "runtime_attachment_grant",
    Rebuild,
    PreferLocal,
    false,
    [],
    [
        (
            "grant_id",
            Bytes,
            true,
            Rebuild,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Bytes }
        ),
        (
            "reference_id",
            Bytes,
            false,
            Rebuild,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Bytes }
        ),
        (
            "signed_grant",
            Bytes,
            false,
            Rebuild,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Bytes }
        ),
        (
            "source",
            Utf8,
            false,
            Rebuild,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "generation",
            I64,
            false,
            Rebuild,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
    ]
);

pub(super) const RULE_132: FamilyRule = table_rule!(
    "sql/runtime_attachment_reference",
    "runtime_attachment_reference",
    Rebuild,
    PreferLocal,
    false,
    [],
    [
        (
            "reference_id",
            Bytes,
            true,
            Rebuild,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Bytes }
        ),
        (
            "message_id",
            Utf8,
            false,
            Rebuild,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "reference_hash",
            Utf8,
            false,
            Rebuild,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "sealed",
            I64,
            false,
            Rebuild,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
        (
            "grants",
            I64,
            false,
            Rebuild,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
    ]
);

pub(super) const RULE_133: FamilyRule = table_rule!(
    "sql/runtime_attachment_retirement",
    "runtime_attachment_retirement",
    Rebuild,
    PreferLocal,
    false,
    [],
    [
        (
            "operation",
            Bytes,
            true,
            Rebuild,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Bytes }
        ),
        (
            "grant_id",
            Bytes,
            false,
            Rebuild,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Bytes }
        ),
        (
            "body",
            Bytes,
            false,
            Rebuild,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Bytes }
        ),
        (
            "signature",
            Bytes,
            false,
            Rebuild,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Bytes }
        ),
        (
            "signer",
            Bytes,
            false,
            Rebuild,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Bytes }
        ),
        (
            "pending",
            I64,
            false,
            Rebuild,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
    ]
);
