// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Full-transfer SQL family declarations for identity.
use super::{
    CellRule, CellType, CodecRule, Disposition, FamilyRule, FamilySelector, FieldRule, MergeRule,
    U64,
};

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

pub(super) const RULE_52: FamilyRule = table_rule!(
    "sql/identity_lifecycle_projection",
    "identity_lifecycle_projection",
    Transfer,
    Revision,
    false,
    ["identity_commitment"],
    [
        (
            "identity_commitment",
            Utf8,
            true,
            Transfer,
            Immutable,
            CodecRule::RequiresOwner {
                owner: "identity_lifecycle_projection",
                cell_type: CellType::Utf8
            }
        ),
        (
            "lifecycle_state",
            Utf8,
            false,
            Transfer,
            Revision,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "lifecycle_epoch",
            I64,
            false,
            Transfer,
            Revision,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
        (
            "causal_event_id",
            Utf8,
            false,
            Transfer,
            Revision,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "reason_code",
            Utf8,
            true,
            Transfer,
            Revision,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "timelock_until",
            I64,
            true,
            Transfer,
            Revision,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
        (
            "grace_window_until",
            I64,
            true,
            Transfer,
            Revision,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
        (
            "finalization_time",
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

pub(super) const RULE_125: FamilyRule = table_rule!(
    "sql/root_identity_key_upgrade",
    "root_identity_key_upgrade",
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

pub(super) const RULE_126: FamilyRule = table_rule!(
    "sql/runtime_account_identity",
    "runtime_account_identity",
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
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
        (
            "principal_commitment",
            Utf8,
            false,
            Exclude,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
    ]
);

pub(super) const RULE_153: FamilyRule = table_rule!(
    "sql/self_device_control_log",
    "self_device_control_log",
    Transfer,
    InertHistory,
    false,
    ["control_event_id"],
    [
        (
            "control_event_id",
            Utf8,
            true,
            Transfer,
            Immutable,
            CodecRule::RequiresOwner {
                owner: "self_device_control_log",
                cell_type: CellType::Utf8
            }
        ),
        (
            "control_domain",
            Utf8,
            false,
            Transfer,
            InertHistory,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "action",
            Utf8,
            false,
            Transfer,
            InertHistory,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "source_device_id",
            Utf8,
            false,
            Transfer,
            InertHistory,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "target_device_id",
            Utf8,
            false,
            Transfer,
            InertHistory,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "correlation_id",
            Utf8,
            false,
            Transfer,
            InertHistory,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "encrypted_subject",
            Bytes,
            false,
            Transfer,
            InertHistory,
            CodecRule::Scalar { cell_type: CellType::Bytes }
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
