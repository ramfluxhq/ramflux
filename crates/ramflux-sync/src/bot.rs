// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

use crate::{McpGrantState, McpRegistry, McpToolManifest, SyncError, parse_mcp_capability};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BotManifestSigningBody {
    pub schema: String,
    pub version: u32,
    pub domain: String,
    pub bot_identity_commitment: String,
    pub actor_type: ramflux_protocol::ActorType,
    pub display_name: String,
    pub manifest_version: String,
    pub home_node: String,
    pub capabilities: Vec<String>,
    pub permissions: Vec<String>,
    pub owner_identity_commitment: String,
    pub hosting_model: ramflux_protocol::HostingModel,
    pub a2ui_profiles: Vec<String>,
    pub safety_disclosure: ramflux_protocol::SafetyDisclosure,
    pub created_at: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<i64>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BotInstallGrantSigningBody {
    pub grant_id: String,
    pub bot_identity_commitment: String,
    pub bot_manifest_hash: String,
    pub installer_identity: String,
    pub installer_device_id: String,
    pub scope: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub conversation_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group_id: Option<String>,
    pub expires_at: i64,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct BotRevocationRegistry {
    revoked_bot_identities: BTreeSet<String>,
}

impl BotRevocationRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn revoke(&mut self, bot_identity_commitment: impl Into<String>) {
        self.revoked_bot_identities.insert(bot_identity_commitment.into());
    }

    /// # Errors
    /// Returns an error when the bot identity has a local or propagated revocation tombstone.
    pub fn ensure_install_allowed(&self, bot_identity_commitment: &str) -> Result<(), SyncError> {
        if self.revoked_bot_identities.contains(bot_identity_commitment) {
            Err(SyncError::BotRevoked)
        } else {
            Ok(())
        }
    }
}

#[must_use]
pub fn bot_manifest_signing_body(
    manifest: &ramflux_protocol::BotManifest,
) -> BotManifestSigningBody {
    BotManifestSigningBody {
        schema: manifest.schema.clone(),
        version: manifest.version,
        domain: manifest.domain.clone(),
        bot_identity_commitment: manifest.bot_identity_commitment.clone(),
        actor_type: manifest.actor_type.clone(),
        display_name: manifest.display_name.clone(),
        manifest_version: manifest.manifest_version.clone(),
        home_node: manifest.home_node.clone(),
        capabilities: manifest.capabilities.clone(),
        permissions: manifest.permissions.clone(),
        owner_identity_commitment: manifest.owner_identity_commitment.clone(),
        hosting_model: manifest.hosting_model.clone(),
        a2ui_profiles: manifest.a2ui_profiles.clone(),
        safety_disclosure: manifest.safety_disclosure.clone(),
        created_at: manifest.created_at,
        expires_at: manifest.expires_at,
    }
}

#[must_use]
pub fn bot_install_grant_signing_body(
    grant: &ramflux_protocol::BotInstallGrant,
) -> BotInstallGrantSigningBody {
    BotInstallGrantSigningBody {
        grant_id: grant.grant_id.clone(),
        bot_identity_commitment: grant.bot_identity_commitment.clone(),
        bot_manifest_hash: grant.bot_manifest_hash.clone(),
        installer_identity: grant.installer_identity.clone(),
        installer_device_id: grant.installer_device_id.clone(),
        scope: grant.scope.clone(),
        conversation_id: grant.conversation_id.clone(),
        group_id: grant.group_id.clone(),
        expires_at: grant.expires_at,
    }
}

/// # Errors
/// Returns an error when the manifest signing body cannot be canonicalized.
pub fn bot_manifest_hash(manifest: &ramflux_protocol::BotManifest) -> Result<String, SyncError> {
    Ok(ramflux_protocol::hash_base64url(
        ramflux_protocol::domain::BOT_MANIFEST,
        &ramflux_protocol::canonical_json_bytes(&bot_manifest_signing_body(manifest))?,
    ))
}

/// # Errors
/// Returns an error when the manifest fields, trust pin signature, expiry or scope grammar fails.
pub fn verify_bot_manifest(
    manifest: &ramflux_protocol::BotManifest,
    trusted_bot_public_key_base64url: &str,
    now: i64,
) -> Result<String, SyncError> {
    if manifest.schema != ramflux_protocol::domain::BOT_MANIFEST
        || manifest.domain != ramflux_protocol::domain::BOT_MANIFEST
        || manifest.actor_type != ramflux_protocol::ActorType::Bot
        || manifest.safety_disclosure.hosting_model != manifest.hosting_model
        || manifest.expires_at.is_some_and(|expires_at| expires_at <= now)
    {
        return Err(SyncError::BotManifestRejected);
    }
    for permission in manifest.permissions.iter().chain(manifest.capabilities.iter()) {
        validate_bot_permission(permission)?;
    }
    ramflux_crypto::verify_device_branch_signature(
        trusted_bot_public_key_base64url,
        &bot_manifest_signing_body(manifest),
        &manifest.signature_by_bot_identity,
    )
    .map_err(|_error| SyncError::BotManifestRejected)?;
    bot_manifest_hash(manifest)
}

/// # Errors
/// Returns an error when the grant is expired, unbound from the manifest/current device, out of
/// scope, or not signed by the trusted installer device key.
pub fn verify_bot_install_grant(
    manifest: &ramflux_protocol::BotManifest,
    grant: &ramflux_protocol::BotInstallGrant,
    installer_device_public_key_base64url: &str,
    expected_installer_device_id: &str,
    now: i64,
) -> Result<(), SyncError> {
    let manifest_hash = bot_manifest_hash(manifest)?;
    if grant.schema != ramflux_protocol::domain::BOT_INSTALL_GRANT
        || grant.domain != ramflux_protocol::domain::BOT_INSTALL_GRANT
        || grant.bot_identity_commitment != manifest.bot_identity_commitment
        || grant.bot_manifest_hash != manifest_hash
        || grant.installer_device_id != expected_installer_device_id
        || grant.expires_at <= now
    {
        return Err(SyncError::BotInstallGrantRejected);
    }
    let allowed_scope = manifest
        .permissions
        .iter()
        .chain(manifest.capabilities.iter())
        .cloned()
        .collect::<BTreeSet<_>>();
    if grant.scope.iter().any(|scope| !allowed_scope.contains(scope)) {
        return Err(SyncError::BotInstallGrantRejected);
    }
    for scope in &grant.scope {
        validate_bot_permission(scope)?;
    }
    ramflux_crypto::verify_device_branch_signature(
        installer_device_public_key_base64url,
        &bot_install_grant_signing_body(grant),
        &grant.signature_by_installer_device,
    )
    .map_err(|_error| SyncError::BotInstallGrantRejected)
}

/// # Errors
/// Returns an error when the bot tool scope cannot be represented as canonical MCP capability or
/// the default risk requires explicit approval.
pub fn verify_bot_mcp_tool_capability(tool_scope: &str) -> Result<(), SyncError> {
    let (capability, parsed_scope) =
        parse_mcp_capability(&format!("external_tool_invoke.{tool_scope}"))?;
    let mut registry = McpRegistry::new();
    registry.install_tool(McpToolManifest {
        server_id: "bot".to_owned(),
        tool_name: tool_scope.to_owned(),
        capability: capability.clone(),
        tool_scope: parsed_scope.clone(),
        declared_risk: capability.default_risk(),
        manifest_version: 1,
    });
    registry.invoke_tool(
        "bot",
        tool_scope,
        &McpGrantState {
            server_id: "bot".to_owned(),
            tool_name: tool_scope.to_owned(),
            tool_scope: parsed_scope,
            registry_hash: registry.registry_hash().to_owned(),
            tool_manifest_set_hash: registry.tool_manifest_set_hash().to_owned(),
            full_delegation: false,
            allowed_capabilities: BTreeSet::from([capability]),
            revoked: false,
            expires_at: 4_000_000_000,
        },
    )?;
    Ok(())
}

fn validate_bot_permission(permission: &str) -> Result<(), SyncError> {
    let parts = permission.split(':').collect::<Vec<_>>();
    if !(2..=3).contains(&parts.len()) || parts.iter().any(|part| part.is_empty()) {
        return Err(SyncError::BotManifestRejected);
    }
    if !matches!(
        parts[0],
        "conversation"
            | "message"
            | "file"
            | "group"
            | "member"
            | "a2ui"
            | "tool"
            | "call"
            | "node"
            | "external"
    ) {
        return Err(SyncError::BotManifestRejected);
    }
    if !matches!(
        parts[1],
        "read"
            | "receive"
            | "send"
            | "request"
            | "manage"
            | "delete"
            | "mute"
            | "invite"
            | "render"
            | "submit"
            | "invoke"
            | "observe"
            | "tool"
    ) {
        return Err(SyncError::BotManifestRejected);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_760_000_000;

    fn device(principal_id: &str, device_id: &str, seed_byte: u8) -> ramflux_crypto::DeviceBranch {
        ramflux_crypto::create_device_branch(principal_id, device_id, 1, [seed_byte; 32])
    }

    fn public_key(device: &ramflux_crypto::DeviceBranch) -> String {
        ramflux_protocol::encode_base64url(device.signing_key.verifying_key().to_bytes())
    }

    fn signed_fields() -> ramflux_protocol::SignedFields {
        ramflux_protocol::SignedFields {
            signing_key_id: "unused-generic-fixture".to_owned(),
            signature_alg: ramflux_protocol::SignatureAlg::Ed25519,
            signature: "unused".to_owned(),
        }
    }

    fn safety() -> ramflux_protocol::SafetyDisclosure {
        ramflux_protocol::SafetyDisclosure {
            disclosure_version: 1,
            disclosure_text: "This bot can read messages sent to it.".to_owned(),
            hosting_model: ramflux_protocol::HostingModel::Federated,
            key_custody_class: ramflux_protocol::KeyCustodyClass::FederatedOperatorKey,
            operator_identity_commitment: Some("operator_id".to_owned()),
            operator_display_name: Some("Example operator".to_owned()),
            can_read_dm_plaintext: true,
            can_read_group_messages_when_member: true,
            tee_attestation_hash: None,
            disclosure_hash: "disclosure_hash".to_owned(),
        }
    }

    fn unsigned_manifest() -> ramflux_protocol::BotManifest {
        ramflux_protocol::BotManifest {
            schema: ramflux_protocol::domain::BOT_MANIFEST.to_owned(),
            version: 1,
            domain: ramflux_protocol::domain::BOT_MANIFEST.to_owned(),
            ext: ramflux_protocol::Ext::default(),
            signed: signed_fields(),
            bot_identity_commitment: "bot_identity_1".to_owned(),
            actor_type: ramflux_protocol::ActorType::Bot,
            display_name: "Deploy Bot".to_owned(),
            manifest_version: "1.0.0".to_owned(),
            home_node: "bots.example.test".to_owned(),
            capabilities: vec!["tool:invoke:ci.deploy".to_owned()],
            permissions: vec![
                "conversation:read:mentioned_context".to_owned(),
                "message:send".to_owned(),
            ],
            owner_identity_commitment: "owner_id".to_owned(),
            hosting_model: ramflux_protocol::HostingModel::Federated,
            a2ui_profiles: vec!["ramflux.a2ui.v1".to_owned()],
            safety_disclosure: safety(),
            created_at: NOW,
            expires_at: Some(NOW + 3_600),
            signature_by_bot_identity: String::new(),
            optional_signature_by_home_node: None,
            optional_signature_by_directory: None,
        }
    }

    fn sign_manifest(
        mut manifest: ramflux_protocol::BotManifest,
        bot_key: &ramflux_crypto::DeviceBranch,
    ) -> Result<ramflux_protocol::BotManifest, SyncError> {
        manifest.signature_by_bot_identity = ramflux_crypto::sign_with_device_branch(
            bot_key,
            &bot_manifest_signing_body(&manifest),
        )?;
        Ok(manifest)
    }

    fn signed_manifest(
        bot_key: &ramflux_crypto::DeviceBranch,
    ) -> Result<ramflux_protocol::BotManifest, SyncError> {
        sign_manifest(unsigned_manifest(), bot_key)
    }

    fn unsigned_grant(
        manifest: &ramflux_protocol::BotManifest,
    ) -> Result<ramflux_protocol::BotInstallGrant, SyncError> {
        Ok(ramflux_protocol::BotInstallGrant {
            schema: ramflux_protocol::domain::BOT_INSTALL_GRANT.to_owned(),
            version: 1,
            domain: ramflux_protocol::domain::BOT_INSTALL_GRANT.to_owned(),
            ext: ramflux_protocol::Ext::default(),
            signed: signed_fields(),
            grant_id: "grant_1".to_owned(),
            bot_identity_commitment: manifest.bot_identity_commitment.clone(),
            bot_manifest_hash: bot_manifest_hash(manifest)?,
            installer_identity: "installer_id".to_owned(),
            installer_device_id: "installer_device".to_owned(),
            scope: vec!["conversation:read:mentioned_context".to_owned()],
            conversation_id: Some("conversation_1".to_owned()),
            group_id: None,
            expires_at: NOW + 600,
            signature_by_installer_device: String::new(),
        })
    }

    fn signed_grant(
        manifest: &ramflux_protocol::BotManifest,
        installer: &ramflux_crypto::DeviceBranch,
    ) -> Result<ramflux_protocol::BotInstallGrant, SyncError> {
        let mut grant = unsigned_grant(manifest)?;
        grant.signature_by_installer_device = ramflux_crypto::sign_with_device_branch(
            installer,
            &bot_install_grant_signing_body(&grant),
        )?;
        Ok(grant)
    }

    #[test]
    fn signed_bot_manifest_and_install_grant_verify_with_trusted_keys() -> Result<(), SyncError> {
        let bot = device("bot_identity_1", "bot_device", 0xB0);
        let installer = device("installer_id", "installer_device", 0xC0);
        let manifest = signed_manifest(&bot)?;
        let manifest_hash = verify_bot_manifest(&manifest, &public_key(&bot), NOW)?;
        let grant = signed_grant(&manifest, &installer)?;
        assert_eq!(grant.bot_manifest_hash, manifest_hash);
        verify_bot_install_grant(
            &manifest,
            &grant,
            &public_key(&installer),
            "installer_device",
            NOW,
        )
    }

    #[test]
    fn bot_manifest_rejects_tampered_display_capability_or_hash() -> Result<(), SyncError> {
        let bot = device("bot_identity_1", "bot_device", 0xB1);
        let installer = device("installer_id", "installer_device", 0xC1);
        let manifest = signed_manifest(&bot)?;

        let mut tampered_display = manifest.clone();
        tampered_display.display_name = "Different Bot".to_owned();
        assert!(verify_bot_manifest(&tampered_display, &public_key(&bot), NOW).is_err());

        let mut tampered_capability = manifest.clone();
        tampered_capability.capabilities.push("node:manage".to_owned());
        assert!(verify_bot_manifest(&tampered_capability, &public_key(&bot), NOW).is_err());

        let mut grant = signed_grant(&manifest, &installer)?;
        grant.bot_manifest_hash = "wrong_hash".to_owned();
        grant.signature_by_installer_device = ramflux_crypto::sign_with_device_branch(
            &installer,
            &bot_install_grant_signing_body(&grant),
        )?;
        assert!(
            verify_bot_install_grant(
                &manifest,
                &grant,
                &public_key(&installer),
                "installer_device",
                NOW
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn bot_manifest_rejects_attacker_self_signature_when_pin_is_different() -> Result<(), SyncError>
    {
        let pinned_bot = device("bot_identity_1", "bot_device", 0xB2);
        let attacker = device("attacker", "attacker_device", 0xD2);
        let manifest = signed_manifest(&attacker)?;
        assert!(verify_bot_manifest(&manifest, &public_key(&pinned_bot), NOW).is_err());
        Ok(())
    }

    #[test]
    fn bot_install_grant_rejects_scope_or_installer_signature_mismatch() -> Result<(), SyncError> {
        let bot = device("bot_identity_1", "bot_device", 0xB3);
        let installer = device("installer_id", "installer_device", 0xC3);
        let other_installer = device("installer_id", "other_device", 0xC4);
        let manifest = signed_manifest(&bot)?;

        let mut out_of_scope = signed_grant(&manifest, &installer)?;
        out_of_scope.scope = vec!["node:manage".to_owned()];
        out_of_scope.signature_by_installer_device = ramflux_crypto::sign_with_device_branch(
            &installer,
            &bot_install_grant_signing_body(&out_of_scope),
        )?;
        assert!(
            verify_bot_install_grant(
                &manifest,
                &out_of_scope,
                &public_key(&installer),
                "installer_device",
                NOW,
            )
            .is_err()
        );

        let grant = signed_grant(&manifest, &installer)?;
        assert!(
            verify_bot_install_grant(
                &manifest,
                &grant,
                &public_key(&other_installer),
                "installer_device",
                NOW,
            )
            .is_err()
        );
        assert!(
            verify_bot_install_grant(
                &manifest,
                &grant,
                &public_key(&installer),
                "other_device",
                NOW
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn revoked_bot_identity_rejects_reinstall() {
        let mut registry = BotRevocationRegistry::new();
        registry.revoke("bot_identity_1");
        assert!(registry.ensure_install_allowed("bot_identity_1").is_err());
        assert!(registry.ensure_install_allowed("bot_identity_2").is_ok());
    }

    #[test]
    fn bot_mcp_external_tool_uses_typed_capability_and_default_high_risk_rejects() {
        let parsed = parse_mcp_capability("external_tool_invoke.ci.deploy");
        assert!(parsed.is_ok_and(|(capability, scope)| {
            capability == ramflux_protocol::McpCapability::ExternalToolInvoke
                && scope.as_deref() == Some("ci.deploy")
                && capability.default_risk() == ramflux_protocol::RiskLevel::High
        }));
        assert!(verify_bot_mcp_tool_capability("ci.deploy").is_err());
    }
}
