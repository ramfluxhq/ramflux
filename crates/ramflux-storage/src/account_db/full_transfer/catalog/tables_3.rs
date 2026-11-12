// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

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
pub(super) const RULE_134: FamilyRule = table_rule!(
    "sql/runtime_home_migration_job",
    "runtime_home_migration_job",
    Exclude,
    PreferLocal,
    false,
    [],
    [
        (
            "operation_id",
            Utf8,
            true,
            Exclude,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "account_anchor",
            Utf8,
            false,
            Exclude,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "intent_hash",
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
        (
            "active",
            I64,
            false,
            Exclude,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
        (
            "recovery_blocked",
            I64,
            false,
            Exclude,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
        (
            "next_attempt_at",
            I64,
            false,
            Exclude,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
        (
            "state_json",
            Bytes,
            false,
            Exclude,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Bytes }
        ),
        (
            "progress_json",
            Bytes,
            false,
            Exclude,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Bytes }
        ),
    ]
);
pub(super) const RULE_135: FamilyRule = table_rule!(
    "sql/runtime_home_migration_transition",
    "runtime_home_migration_transition",
    Exclude,
    PreferLocal,
    false,
    [],
    [
        ("id", I64, true, Exclude, PreferLocal, CodecRule::Scalar { cell_type: CellType::I64 }),
        (
            "operation_id",
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
        (
            "progress_json",
            Bytes,
            false,
            Exclude,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Bytes }
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
pub(super) const RULE_151: FamilyRule = table_rule!(
    "sql/runtime_unrouted",
    "runtime_unrouted",
    Transfer,
    InertHistory,
    false,
    ["envelope_id"],
    [
        (
            "envelope_id",
            Utf8,
            true,
            Transfer,
            Immutable,
            CodecRule::RequiresOwner { owner: "runtime_unrouted", cell_type: CellType::Utf8 }
        ),
        (
            "inbox_seq",
            I64,
            false,
            Transfer,
            InertHistory,
            CodecRule::Scalar { cell_type: CellType::I64 }
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
            "received_at",
            I64,
            false,
            Transfer,
            InertHistory,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
    ]
);
pub(super) const RULE_152: FamilyRule = table_rule!(
    "sql/schema_migration",
    "schema_migration",
    Rebuild,
    PreferLocal,
    false,
    [],
    [
        (
            "schema_version",
            I64,
            true,
            Rebuild,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
        (
            "applied_at",
            I64,
            false,
            Rebuild,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
        (
            "app_version",
            Utf8,
            false,
            Rebuild,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "checksum",
            Utf8,
            false,
            Rebuild,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "notes",
            Utf8,
            true,
            Rebuild,
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
pub(super) const RULE_154: FamilyRule = table_rule!(
    "sql/session_capability_cache",
    "session_capability_cache",
    Exclude,
    PreferLocal,
    false,
    [],
    [
        (
            "capability_id",
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
            "capability_scope",
            Utf8,
            false,
            Exclude,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
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
            "revoked_at",
            I64,
            true,
            Exclude,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
        (
            "proof_hash",
            Bytes,
            false,
            Exclude,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Bytes }
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
pub(super) const RULE_158: FamilyRule = table_rule!(
    "sql/sync_checkpoint",
    "sync_checkpoint",
    Exclude,
    PreferLocal,
    false,
    [],
    [
        (
            "checkpoint_id",
            Utf8,
            true,
            Exclude,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "sync_scope",
            Utf8,
            false,
            Exclude,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "cursor_id",
            Utf8,
            true,
            Exclude,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "checkpoint_body",
            Bytes,
            false,
            Exclude,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Bytes }
        ),
        (
            "checkpoint_hash",
            Bytes,
            false,
            Exclude,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Bytes }
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
