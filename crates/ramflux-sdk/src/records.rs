// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![allow(clippy::missing_errors_doc)]
#![allow(clippy::wildcard_imports)]
use crate::prelude::*;

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct LocalCallRecord {
    pub call_id: String,
    pub target_id: String,
    pub state: String,
    pub relay: SignalingRelay,
    pub turn_allocation_id: String,
    pub node_sees_sdp: bool,
    pub relay_holds_media_key: bool,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct LocalBotRecord {
    pub bot_id: String,
    pub manifest: ramflux_protocol::BotManifest,
    pub install_grant: ramflux_protocol::BotInstallGrant,
    pub bot_manifest_hash: String,
    pub grant_hash: String,
    pub requested_scopes: Vec<String>,
    pub manifest_scopes: Vec<String>,
    pub consent_member_ids: Vec<String>,
    pub actor_type: String,
    pub operation_origin: String,
    pub trust_source: String,
    pub state: String,
    pub revocation_targets: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revocation_event_id: Option<String>,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct LocalBotTrustPinRecord {
    pub bot_identity_commitment: String,
    pub bot_public_key: String,
    pub signing_key_id: String,
    pub trust_source: String,
    pub pinned_at: i64,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct LocalMcpGrantRecord {
    pub grant_id: String,
    pub state: McpGrantState,
    pub signed_by_device_id: String,
    pub signer_public_key: String,
    pub signature: String,
    pub signing_body: LocalMcpGrantSigningBody,
    pub confirmation_mode: String,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct LocalMcpStandingApprovalRecord {
    pub standing_approval_id: String,
    pub server_id: String,
    pub tool_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_scope: Option<String>,
    pub capability: McpCapability,
    pub risk_level: RiskLevel,
    pub registry_hash: String,
    pub tool_manifest_set_hash: String,
    pub issued_at: i64,
    pub expires_at: i64,
    pub created_by_device_id: String,
    pub signer_public_key: String,
    pub signature: String,
    pub signing_body: LocalMcpStandingApprovalSigningBody,
    pub revoked: bool,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct LocalMcpApprovalRecord {
    pub approval_id: String,
    pub server_id: String,
    pub tool_name: String,
    pub capability: McpCapability,
    pub risk_level: RiskLevel,
    pub tool_scope: Option<String>,
    pub confirmation_mode: String,
    pub expires_at: i64,
    pub status: String,
    pub details: serde_json::Value,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct LocalMcpAuditRecord {
    pub event_type: String,
    pub operation_origin: String,
    pub approval_id: Option<String>,
    pub grant_id: Option<String>,
    pub server_id: String,
    pub tool_name: String,
    pub capability: String,
    pub risk_level: String,
    pub tool_scope: Option<String>,
    pub outcome: String,
    pub registry_hash: String,
    pub tool_manifest_set_hash: String,
    pub event_body: serde_json::Value,
}
