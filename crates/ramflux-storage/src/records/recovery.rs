// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct GuardianRecoveryShareRecord {
    pub owner_principal_id: String,
    pub guardian_principal_id: String,
    pub recovery_quorum_id: String,
    pub share_id: u8,
    pub threshold: u8,
    pub total: u8,
    pub member_kind: String,
    pub share_value: Vec<u8>,
    pub inviter_device_id: String,
    pub inviter_device_public_key_base64url: String,
    pub invite_id: String,
    pub accepted_at: i64,
    pub accepted_by_device_id: String,
    pub accept_signature: String,
    pub state: String,
    pub created_at: i64,
    pub updated_at: i64,
}

pub struct GuardianRecoveryShareWrite<'a> {
    pub owner_principal_id: &'a str,
    pub guardian_principal_id: &'a str,
    pub recovery_quorum_id: &'a str,
    pub share_id: u8,
    pub threshold: u8,
    pub total: u8,
    pub member_kind: &'a str,
    pub share_value: &'a [u8],
    pub inviter_device_id: &'a str,
    pub inviter_device_public_key_base64url: &'a str,
    pub invite_id: &'a str,
    pub accepted_at: i64,
    pub accepted_by_device_id: &'a str,
    pub accept_signature: &'a str,
    pub state: &'a str,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct PendingRecoveryRecord {
    pub recovery_id: String,
    pub owner_principal_id: String,
    pub recovery_quorum_id: String,
    pub lifecycle_epoch: u64,
    pub lineage_head: Option<String>,
    pub event_type: String,
    pub timelock_started_at: Option<i64>,
    pub timelock_until: Option<u64>,
    pub state: String,
    pub recovery_quorum: ramflux_protocol::RecoveryQuorumConfigured,
    pub context: ramflux_protocol::RecoveryApprovalContext,
    pub created_at: i64,
    pub updated_at: i64,
}

pub struct PendingRecoveryWrite<'a> {
    pub recovery_id: &'a str,
    pub owner_principal_id: &'a str,
    pub recovery_quorum: &'a ramflux_protocol::RecoveryQuorumConfigured,
    pub lifecycle_epoch: u64,
    pub lineage_head: Option<&'a str>,
    pub event_type: &'a str,
    pub timelock_until: Option<u64>,
    pub context: &'a ramflux_protocol::RecoveryApprovalContext,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct PendingRecoveryApprovalRecord {
    pub recovery_id: String,
    pub signing_key_id: String,
    pub member_kind: String,
    pub approval: ramflux_protocol::RecoveryApproval,
    pub approved_at: i64,
}

pub struct PendingRecoveryApprovalWrite<'a> {
    pub recovery_id: &'a str,
    pub approval: &'a ramflux_protocol::RecoveryApproval,
    pub approved_at: i64,
}
