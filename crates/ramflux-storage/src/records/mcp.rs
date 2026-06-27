// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use serde::Serialize;

pub struct McpGrantWrite<'a, T>
where
    T: Serialize,
{
    pub grant_id: &'a str,
    pub target_ai_device_id: &'a str,
    pub source_app_device_id: &'a str,
    pub capability: &'a str,
    pub risk_level: &'a str,
    pub registry_hash: &'a str,
    pub tool_manifest_set_hash: &'a str,
    pub expires_at: i64,
    pub signature: &'a str,
    pub created_at: i64,
    pub revoked: bool,
    pub grant: &'a T,
}

pub struct McpAuditWrite<'a, T>
where
    T: Serialize,
{
    pub audit: &'a T,
    pub audit_type: &'a str,
    pub actor_device_id: &'a str,
    pub subject_hash: Option<&'a [u8]>,
    pub redacted_summary: &'a str,
    pub created_at: i64,
}

pub struct McpToolWrite<'a, T>
where
    T: Serialize,
{
    pub tool_manifest_hash: &'a str,
    pub server_id: &'a str,
    pub tool_name: &'a str,
    pub required_capability: &'a str,
    pub risk_level: &'a str,
    pub manifest: &'a T,
    pub updated_at: i64,
}

pub struct McpStandingApprovalWrite<'a, T>
where
    T: Serialize,
{
    pub standing_approval_id: &'a str,
    pub server_id: &'a str,
    pub tool_name: &'a str,
    pub capability: &'a str,
    pub risk_level: &'a str,
    pub registry_hash: &'a str,
    pub tool_manifest_set_hash: &'a str,
    pub expires_at: i64,
    pub created_at: i64,
    pub created_by_device_id: &'a str,
    pub revoked: bool,
    pub approval: &'a T,
}
