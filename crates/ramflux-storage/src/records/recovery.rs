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
