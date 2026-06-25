// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

use crate::SyncError;

pub use ramflux_protocol::{McpCapability, RiskLevel};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct McpToolManifest {
    pub server_id: String,
    pub tool_name: String,
    pub capability: McpCapability,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_scope: Option<String>,
    pub declared_risk: RiskLevel,
    #[serde(default = "default_manifest_version")]
    pub manifest_version: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct McpGrantState {
    pub server_id: String,
    pub tool_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_scope: Option<String>,
    pub registry_hash: String,
    pub tool_manifest_set_hash: String,
    pub full_delegation: bool,
    pub allowed_capabilities: BTreeSet<McpCapability>,
    pub revoked: bool,
    #[serde(default)]
    pub expires_at: i64,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct McpRegistry {
    tools: BTreeMap<String, McpToolManifest>,
    registry_hash: String,
    tool_manifest_set_hash: String,
}

impl McpRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn install_tool(&mut self, manifest: McpToolManifest) {
        let manifest = manifest.with_effective_risk();
        self.tools.insert(tool_key(&manifest.server_id, &manifest.tool_name), manifest);
        self.rehash();
    }

    pub fn remove_tool(&mut self, server_id: &str, tool_name: &str) {
        self.tools.remove(&tool_key(server_id, tool_name));
        self.rehash();
    }

    #[must_use]
    pub fn registry_hash(&self) -> &str {
        &self.registry_hash
    }

    #[must_use]
    pub fn tool_manifest_set_hash(&self) -> &str {
        &self.tool_manifest_set_hash
    }

    #[must_use]
    pub fn tools(&self) -> Vec<McpToolManifest> {
        self.tools.values().cloned().collect()
    }

    /// # Errors
    /// Returns an error when validation, serialization, storage, or state checks fail.
    pub fn invoke_tool(
        &self,
        server_id: &str,
        tool_name: &str,
        grant: &McpGrantState,
    ) -> Result<String, SyncError> {
        if grant.revoked
            || grant.registry_hash != self.registry_hash
            || grant.tool_manifest_set_hash != self.tool_manifest_set_hash
            || grant_is_expired(grant)?
        {
            return Err(SyncError::GrantInvalidated);
        }
        let manifest =
            self.tools.get(&tool_key(server_id, tool_name)).ok_or(SyncError::CapabilityDenied)?;
        if risk_requires_explicit_approval(&manifest.effective_risk()) {
            return Err(SyncError::CapabilityDenied);
        }
        if grant_matches_manifest(grant, manifest) {
            Ok(format!("{}:{}", manifest.server_id, manifest.tool_name))
        } else {
            Err(SyncError::CapabilityDenied)
        }
    }

    fn rehash(&mut self) {
        let mut registry_bytes = Vec::new();
        let mut last_server_id = None::<&str>;
        for manifest in self.tools.values() {
            if last_server_id != Some(manifest.server_id.as_str()) {
                registry_bytes.extend_from_slice(manifest.server_id.as_bytes());
                registry_bytes.push(0);
                last_server_id = Some(manifest.server_id.as_str());
            }
        }
        self.registry_hash = ramflux_crypto::blake3_256_base64url(
            ramflux_protocol::domain::MCP_GRANT,
            &registry_bytes,
        );

        let mut manifest_bytes = Vec::new();
        for (key, manifest) in &self.tools {
            manifest_bytes.extend_from_slice(key.as_bytes());
            manifest_bytes.push(0);
            manifest_bytes
                .extend_from_slice(mcp_capability_wire_name(&manifest.capability).as_bytes());
            manifest_bytes.push(0);
            if let Some(scope) = &manifest.tool_scope {
                manifest_bytes.extend_from_slice(scope.as_bytes());
            }
            manifest_bytes.push(0);
            manifest_bytes.extend_from_slice(risk_wire_name(&manifest.declared_risk).as_bytes());
            manifest_bytes.push(0);
            manifest_bytes.extend_from_slice(&manifest.manifest_version.to_be_bytes());
            manifest_bytes.push(0);
        }
        self.tool_manifest_set_hash = ramflux_crypto::blake3_256_base64url(
            ramflux_protocol::domain::MCP_GRANT,
            &manifest_bytes,
        );
    }
}

fn grant_is_expired(grant: &McpGrantState) -> Result<bool, SyncError> {
    Ok(grant.expires_at <= current_unix_timestamp()?)
}

fn current_unix_timestamp() -> Result<i64, SyncError> {
    let seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| SyncError::GrantInvalidated)?
        .as_secs();
    i64::try_from(seconds).map_err(|_| SyncError::GrantInvalidated)
}

impl McpToolManifest {
    #[must_use]
    pub fn effective_risk(&self) -> RiskLevel {
        self.declared_risk.clone().max(self.capability.default_risk())
    }

    #[must_use]
    fn with_effective_risk(mut self) -> Self {
        self.declared_risk = self.effective_risk();
        self
    }
}

/// # Errors
/// Returns an error when the input is not a canonical MCP capability or an explicit tool scope.
pub fn parse_mcp_capability(
    capability: &str,
) -> Result<(McpCapability, Option<String>), SyncError> {
    if let Some(scope) = capability.strip_prefix("external_tool_invoke.") {
        if scope.is_empty() {
            return Err(SyncError::InvalidMcpCapability(capability.to_owned()));
        }
        return Ok((McpCapability::ExternalToolInvoke, Some(scope.to_owned())));
    }
    let parsed = match capability {
        "read_conversation" => McpCapability::ReadConversation,
        "draft_message" => McpCapability::DraftMessage,
        "send_message" => McpCapability::SendMessage,
        "read_local_files" => McpCapability::ReadLocalFiles,
        "write_local_files" => McpCapability::WriteLocalFiles,
        "run_shell" => McpCapability::RunShell,
        "manage_contacts" => McpCapability::ManageContacts,
        "manage_group" => McpCapability::ManageGroup,
        "manage_media" => McpCapability::ManageMedia,
        "manage_node" => McpCapability::ManageNode,
        "external_tool_invoke" => McpCapability::ExternalToolInvoke,
        _ => return Err(SyncError::InvalidMcpCapability(capability.to_owned())),
    };
    Ok((parsed, None))
}

#[must_use]
pub const fn mcp_capability_wire_name(capability: &McpCapability) -> &'static str {
    match capability {
        McpCapability::ReadConversation => "read_conversation",
        McpCapability::DraftMessage => "draft_message",
        McpCapability::SendMessage => "send_message",
        McpCapability::ReadLocalFiles => "read_local_files",
        McpCapability::WriteLocalFiles => "write_local_files",
        McpCapability::RunShell => "run_shell",
        McpCapability::ManageContacts => "manage_contacts",
        McpCapability::ManageGroup => "manage_group",
        McpCapability::ManageMedia => "manage_media",
        McpCapability::ManageNode => "manage_node",
        McpCapability::ExternalToolInvoke => "external_tool_invoke",
    }
}

#[must_use]
pub const fn risk_wire_name(risk: &RiskLevel) -> &'static str {
    match risk {
        RiskLevel::Low => "low",
        RiskLevel::Medium => "medium",
        RiskLevel::High => "high",
        RiskLevel::Critical => "critical",
    }
}

#[must_use]
pub const fn risk_requires_explicit_approval(risk: &RiskLevel) -> bool {
    matches!(risk, RiskLevel::High | RiskLevel::Critical)
}

#[must_use]
pub fn grant_matches_manifest(grant: &McpGrantState, manifest: &McpToolManifest) -> bool {
    if grant.full_delegation {
        return wildcard_or_equal(&grant.server_id, &manifest.server_id)
            && wildcard_or_equal(&grant.tool_name, &manifest.tool_name)
            && grant_tool_scope_matches(grant.tool_scope.as_ref(), manifest.tool_scope.as_deref());
    }
    grant.allowed_capabilities.contains(&manifest.capability)
        && grant.server_id == manifest.server_id
        && grant.tool_name == manifest.tool_name
        && grant.tool_scope == manifest.tool_scope
}

fn wildcard_or_equal(grant_value: &str, manifest_value: &str) -> bool {
    grant_value == "wildcard" || grant_value == manifest_value
}

fn grant_tool_scope_matches(grant_scope: Option<&String>, manifest_scope: Option<&str>) -> bool {
    match grant_scope.map(String::as_str) {
        Some("wildcard") => true,
        Some(scope) => Some(scope) == manifest_scope,
        None => manifest_scope.is_none(),
    }
}

const fn default_manifest_version() -> u32 {
    1
}

fn tool_key(server_id: &str, tool_name: &str) -> String {
    format!("{server_id}/{tool_name}")
}

#[cfg(test)]
mod tests {
    use super::*;

    const FUTURE_EXPIRES_AT: i64 = 4_000_000_000;

    fn manifest(server_id: &str, tool_name: &str, scope: &str) -> McpToolManifest {
        McpToolManifest {
            server_id: server_id.to_owned(),
            tool_name: tool_name.to_owned(),
            capability: McpCapability::ReadConversation,
            tool_scope: Some(scope.to_owned()),
            declared_risk: RiskLevel::Low,
            manifest_version: 1,
        }
    }

    #[test]
    fn parses_canonical_and_scoped_external_tool_capabilities() -> Result<(), SyncError> {
        assert!(RiskLevel::Low < RiskLevel::Medium);
        assert!(RiskLevel::Medium < RiskLevel::High);
        assert!(RiskLevel::High < RiskLevel::Critical);

        let (capability, scope) = parse_mcp_capability("run_shell")?;
        assert_eq!(capability, McpCapability::RunShell);
        assert_eq!(scope, None);
        assert_eq!(McpCapability::RunShell.default_risk(), RiskLevel::High);

        let (capability, scope) = parse_mcp_capability("external_tool_invoke.echo")?;
        assert_eq!(capability, McpCapability::ExternalToolInvoke);
        assert_eq!(scope.as_deref(), Some("echo"));
        assert_eq!(McpCapability::ExternalToolInvoke.default_risk(), RiskLevel::High);

        assert!(parse_mcp_capability("external_tool_invoke.").is_err());
        assert!(parse_mcp_capability("external_tool_invoke.echo.freeform").is_ok());
        assert!(parse_mcp_capability("unknown_freeform").is_err());
        Ok(())
    }

    #[test]
    fn registry_and_tool_manifest_hashes_are_separated() {
        let mut registry = McpRegistry::new();
        registry.install_tool(manifest("srv", "echo", "echo"));
        let registry_hash = registry.registry_hash().to_owned();
        let manifest_hash = registry.tool_manifest_set_hash().to_owned();

        registry.install_tool(manifest("srv", "summarize", "summarize"));
        assert_eq!(registry.registry_hash(), registry_hash);
        assert_ne!(registry.tool_manifest_set_hash(), manifest_hash);

        registry.install_tool(manifest("srv2", "echo", "echo"));
        assert_ne!(registry.registry_hash(), registry_hash);
    }

    #[test]
    fn mismatched_registry_or_manifest_hash_invalidates_grant() {
        let mut registry = McpRegistry::new();
        registry.install_tool(manifest("srv", "echo", "echo"));
        let mut grant = McpGrantState {
            server_id: "srv".to_owned(),
            tool_name: "echo".to_owned(),
            tool_scope: Some("echo".to_owned()),
            registry_hash: registry.registry_hash().to_owned(),
            tool_manifest_set_hash: registry.tool_manifest_set_hash().to_owned(),
            full_delegation: false,
            allowed_capabilities: BTreeSet::from([McpCapability::ReadConversation]),
            revoked: false,
            expires_at: FUTURE_EXPIRES_AT,
        };
        assert!(registry.invoke_tool("srv", "echo", &grant).is_ok());

        grant.tool_manifest_set_hash = "wrong".to_owned();
        assert!(matches!(
            registry.invoke_tool("srv", "echo", &grant),
            Err(SyncError::GrantInvalidated)
        ));

        grant.tool_manifest_set_hash = registry.tool_manifest_set_hash().to_owned();
        grant.expires_at = 1;
        assert!(matches!(
            registry.invoke_tool("srv", "echo", &grant),
            Err(SyncError::GrantInvalidated)
        ));
    }

    #[test]
    fn install_clamps_low_declared_high_capability_to_default_risk() {
        let mut registry = McpRegistry::new();
        registry.install_tool(McpToolManifest {
            server_id: "srv".to_owned(),
            tool_name: "shell".to_owned(),
            capability: McpCapability::RunShell,
            tool_scope: None,
            declared_risk: RiskLevel::Low,
            manifest_version: 1,
        });
        let stored = registry.tools().into_iter().next();
        assert!(stored.is_some());
        let Some(stored) = stored else {
            return;
        };
        assert_eq!(stored.declared_risk, RiskLevel::High);
        assert_eq!(stored.effective_risk(), RiskLevel::High);
        let grant = McpGrantState {
            server_id: "srv".to_owned(),
            tool_name: "shell".to_owned(),
            tool_scope: None,
            registry_hash: registry.registry_hash().to_owned(),
            tool_manifest_set_hash: registry.tool_manifest_set_hash().to_owned(),
            full_delegation: false,
            allowed_capabilities: BTreeSet::from([McpCapability::RunShell]),
            revoked: false,
            expires_at: FUTURE_EXPIRES_AT,
        };
        assert!(matches!(
            registry.invoke_tool("srv", "shell", &grant),
            Err(SyncError::CapabilityDenied)
        ));
    }

    #[test]
    fn grant_scope_must_match_server_tool_and_scope() {
        let mut registry = McpRegistry::new();
        registry.install_tool(McpToolManifest {
            server_id: "srv_a".to_owned(),
            tool_name: "tool_x".to_owned(),
            capability: McpCapability::ReadConversation,
            tool_scope: Some("thread_a".to_owned()),
            declared_risk: RiskLevel::Low,
            manifest_version: 1,
        });
        registry.install_tool(McpToolManifest {
            server_id: "srv_b".to_owned(),
            tool_name: "tool_y".to_owned(),
            capability: McpCapability::ReadConversation,
            tool_scope: Some("thread_b".to_owned()),
            declared_risk: RiskLevel::Low,
            manifest_version: 1,
        });
        let grant = McpGrantState {
            server_id: "srv_a".to_owned(),
            tool_name: "tool_x".to_owned(),
            tool_scope: Some("thread_a".to_owned()),
            registry_hash: registry.registry_hash().to_owned(),
            tool_manifest_set_hash: registry.tool_manifest_set_hash().to_owned(),
            full_delegation: false,
            allowed_capabilities: BTreeSet::from([McpCapability::ReadConversation]),
            revoked: false,
            expires_at: FUTURE_EXPIRES_AT,
        };
        let result = registry.invoke_tool("srv_a", "tool_x", &grant);
        assert!(result.is_ok());
        assert_eq!(result.unwrap_or_default(), "srv_a:tool_x");
        assert!(matches!(
            registry.invoke_tool("srv_b", "tool_y", &grant),
            Err(SyncError::CapabilityDenied)
        ));
    }

    #[test]
    fn full_delegation_rejects_high_risk_tools() {
        let mut registry = McpRegistry::new();
        registry.install_tool(McpToolManifest {
            server_id: "srv".to_owned(),
            tool_name: "shell".to_owned(),
            capability: McpCapability::RunShell,
            tool_scope: None,
            declared_risk: RiskLevel::High,
            manifest_version: 1,
        });
        let grant = McpGrantState {
            server_id: "wildcard".to_owned(),
            tool_name: "wildcard".to_owned(),
            tool_scope: Some("wildcard".to_owned()),
            registry_hash: registry.registry_hash().to_owned(),
            tool_manifest_set_hash: registry.tool_manifest_set_hash().to_owned(),
            full_delegation: true,
            allowed_capabilities: BTreeSet::new(),
            revoked: false,
            expires_at: FUTURE_EXPIRES_AT,
        };
        assert!(matches!(
            registry.invoke_tool("srv", "shell", &grant),
            Err(SyncError::CapabilityDenied)
        ));
    }
}
