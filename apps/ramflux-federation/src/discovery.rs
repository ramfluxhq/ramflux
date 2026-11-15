// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Node discovery record generation and stable signing-key configuration.
use crate::helpers::non_empty_env;
use crate::{FederationDiscoverySurface, now_unix_seconds};

/// Both settings must be present and canonical; otherwise nothing is configured, so the
/// capability and the pin are not advertised.
pub(crate) fn attachment_authority_from(
    generation: Option<&str>,
    public_key: Option<&str>,
) -> Option<ramflux_node_core::FederationAttachmentAuthority> {
    let authority = ramflux_node_core::FederationAttachmentAuthority {
        generation: generation?.trim().parse().ok()?,
        signing_public_key: public_key?.trim().to_owned(),
    };
    authority.validate().ok()?;
    Some(authority)
}

pub(crate) fn federation_discovery_surface(
    config: &ramflux_node_core::NodeServiceConfig,
    node_signing_seed: [u8; 32],
) -> FederationDiscoverySurface {
    let node_ca_cert_pem = std::fs::read_to_string(&config.mesh.ca_cert).unwrap_or_default();
    let mut surface = FederationDiscoverySurface {
        node_id: ramflux_node_core::environment::var("RAMFLUX_FEDERATION_NODE_ID")
            .unwrap_or_else(|_| config.node_id.clone()),
        public_endpoint: ramflux_node_core::environment::var("RAMFLUX_FEDERATION_PUBLIC_ENDPOINT")
            .unwrap_or_else(|_| config.mesh.listen_addr.clone()),
        node_public_key: ramflux_crypto::public_key_base64url_from_seed(node_signing_seed),
        node_ca_cert_pem,
        node_signing_seed,
        protocol_versions: vec!["v1".to_owned()],
        transport_backends: vec!["quic_quinn".to_owned(), "https_json".to_owned()],
        node_capabilities: vec![
            "opaque_delivery".to_owned(),
            "federation_relay".to_owned(),
            "friend_request".to_owned(),
        ],
        attachment_authority: None,
    };
    surface.attachment_authority = attachment_authority_from(
        ramflux_node_core::environment::var("RAMFLUX_FEDERATION_ATTACHMENT_AUTHORITY_GENERATION")
            .ok()
            .as_deref(),
        ramflux_node_core::environment::var("RAMFLUX_FEDERATION_ATTACHMENT_AUTHORITY_PUBLIC_KEY")
            .ok()
            .as_deref(),
    );
    if surface.attachment_authority.is_some() {
        surface.node_capabilities.push(ramflux_node_core::ATTACHMENT_RENEWAL_CAPABILITY.into());
    }
    if ramflux_node_core::home_migration_enabled().unwrap_or(false) {
        surface.node_capabilities.push(ramflux_node_core::HOME_MIGRATION_CAPABILITY.into());
    }
    surface
}

pub(crate) fn federation_node_signing_seed(
    state: &mut ramflux_node_core::FederationTrustState,
) -> Result<[u8; 32], ramflux_node_core::NodeCoreError> {
    let key =
        ramflux_node_core::NodeSecret::required_env("RAMFLUX_FEDERATION_NODE_SIGNING_SEED_FILE")?;
    let seed = key.with_bytes(|bytes| *bytes);
    if state.node_signing_seed().is_some_and(|old| old != seed) {
        return Err(ramflux_node_core::NodeCoreError::Unauthorized("mounted federation key differs from legacy identity; export and mount the existing key".into()));
    }
    Ok(seed)
}

impl FederationDiscoverySurface {
    pub(crate) fn client_record(
        &self,
    ) -> Result<ramflux_protocol::WellKnownClientRecord, ramflux_node_core::NodeCoreError> {
        let now = now_unix_seconds()?;
        let value = |name: &str, fallback: String| non_empty_env(name).unwrap_or(fallback);
        let mut record = ramflux_protocol::WellKnownClientRecord {
            schema: ramflux_protocol::WELL_KNOWN_CLIENT_SCHEMA.to_owned(),
            node_id: self.node_id.clone(),
            node_public_key: self.node_public_key.clone(),
            node_ca_cert_pem: self.node_ca_cert_pem.clone(),
            gateway_quic_addr: value(
                "RAMFLUX_CLIENT_GATEWAY_QUIC_ADDR",
                format!("{}:443", self.node_id),
            ),
            gateway_tcp_addr: value(
                "RAMFLUX_CLIENT_GATEWAY_TCP_ADDR",
                format!("{}:443", self.node_id),
            ),
            gateway_server_name: value(
                "RAMFLUX_CLIENT_GATEWAY_SERVER_NAME",
                "ramflux-gateway".to_owned(),
            ),
            relay_quic_addr: value(
                "RAMFLUX_CLIENT_RELAY_QUIC_ADDR",
                format!("{}:17447", self.node_id),
            ),
            relay_server_name: value(
                "RAMFLUX_CLIENT_RELAY_SERVER_NAME",
                "ramflux-relay".to_owned(),
            ),
            prekey_http_url: value(
                "RAMFLUX_CLIENT_PREKEY_HTTP_URL",
                format!("https://{}", self.node_id),
            ),
            signaling_turn_addr: value(
                "RAMFLUX_CLIENT_SIGNALING_TURN_ADDR",
                format!("{}:3478", self.node_id),
            ),
            protocol_versions: ramflux_protocol::advertised_client_protocol_versions(
                &self.protocol_versions,
            ),
            client_capabilities: vec![
                "opaque_delivery".to_owned(),
                "prekey".to_owned(),
                "object_relay".to_owned(),
            ],
            updated_at: now,
            expires_at: now.saturating_add(ramflux_protocol::DISCOVERY_MAX_CACHE_TTL_SECONDS),
            signature: String::new(),
        };
        if ramflux_node_core::HOME_MIGRATION_RELEASE_GATE
            && self
                .node_capabilities
                .iter()
                .any(|cap| cap == ramflux_node_core::HOME_MIGRATION_CAPABILITY)
        {
            record.client_capabilities.push(ramflux_node_core::HOME_MIGRATION_CAPABILITY.into());
        }
        if ramflux_node_core::DEVICE_PAIRING_RELEASE_GATE
            && ramflux_node_core::device_pairing_enabled().unwrap_or(false)
        {
            record.client_capabilities.push(ramflux_node_core::DEVICE_PAIRING_CAPABILITY.into());
        }
        let bytes = ramflux_protocol::client_discovery_signing_bytes(&record)
            .map_err(|source| ramflux_node_core::NodeCoreError::ItestJson(source.to_string()))?;
        record.signature =
            ramflux_crypto::sign_canonical_bytes_with_seed(&bytes, self.node_signing_seed);
        Ok(record)
    }

    pub(crate) fn well_known_record(
        &self,
    ) -> Result<ramflux_node_core::FederationServerRecord, ramflux_node_core::NodeCoreError> {
        let now = now_unix_seconds()?;
        let mut record = ramflux_node_core::FederationServerRecord {
            schema: "ramflux.well_known_server.v1".to_owned(),
            node_id: self.node_id.clone(),
            node_public_key: self.node_public_key.clone(),
            node_ca_cert_pem: self.node_ca_cert_pem.clone(),
            node_endpoint: self.public_endpoint.clone(),
            protocol_versions: self.protocol_versions.clone(),
            transport_backends: self.transport_backends.clone(),
            node_capabilities: self
                .node_capabilities
                .iter()
                .filter(|cap| {
                    (ramflux_node_core::DEVICE_PAIRING_RELEASE_GATE
                        || !matches!(
                            cap.as_str(),
                            "device_pairing_v2" | "primary_transfer_full_v1"
                        ))
                        && (ramflux_node_core::HOME_MIGRATION_RELEASE_GATE
                            || cap.as_str() != ramflux_node_core::HOME_MIGRATION_CAPABILITY)
                        && (self.attachment_authority.is_some()
                            || cap.as_str() != ramflux_node_core::ATTACHMENT_RENEWAL_CAPABILITY)
                })
                .cloned()
                .collect(),
            node_policy_hash: ramflux_crypto::blake3_256_base64url(
                ramflux_protocol::domain::FEDERATION_HANDSHAKE,
                self.node_id.as_bytes(),
            ),
            updated_at: now,
            expires_at: now.saturating_add(86_400),
            attachment_authority: self.attachment_authority.clone(),
            signature: String::new(),
        };
        ramflux_node_core::sign_federation_server_record_with_seed(
            &mut record,
            self.node_signing_seed,
        )?;
        Ok(record)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn well_known_record_uses_current_time_window() -> Result<(), ramflux_node_core::NodeCoreError>
    {
        let now = now_unix_seconds()?;
        let seed = ramflux_crypto::blake3_256("ramflux.federation.test_seed.v1", b"well-known");
        let surface = FederationDiscoverySurface {
            node_id: "node_test.realnet".to_owned(),
            public_endpoint: "ramflux-test-federation:7443".to_owned(),
            node_public_key: ramflux_crypto::public_key_base64url_from_seed(seed),
            node_ca_cert_pem: "test-ca".to_owned(),
            node_signing_seed: seed,
            protocol_versions: vec!["v1".to_owned()],
            transport_backends: vec!["https_json".to_owned()],
            node_capabilities: vec![
                "opaque_delivery".to_owned(),
                ramflux_node_core::HOME_MIGRATION_CAPABILITY.into(),
            ],
            attachment_authority: None,
        };

        let client = surface.client_record()?;
        assert!(
            client
                .client_capabilities
                .iter()
                .any(|cap| cap == ramflux_node_core::HOME_MIGRATION_CAPABILITY)
        );
        let record = surface.well_known_record()?;
        assert!(record.node_capabilities.iter().any(|cap| cap == "opaque_delivery"));
        assert!(
            record
                .node_capabilities
                .iter()
                .any(|cap| cap == ramflux_node_core::HOME_MIGRATION_CAPABILITY)
        );

        assert!(record.updated_at >= now);
        assert_eq!(record.expires_at, record.updated_at.saturating_add(86_400));
        ramflux_node_core::verify_federation_server_record(&record, record.updated_at)?;
        Ok(())
    }
}

#[cfg(test)]
mod migration_capability_tests {
    #[test]
    fn migration_capability_advertised_only_when_enabled_after_release_gate()
    -> Result<(), Box<dyn std::error::Error>> {
        const NAME: &str = "discovery::migration_capability_tests::migration_capability_advertised_only_when_enabled_after_release_gate";
        if std::env::var_os("RAMFLUX_MIGRATION_DISCOVERY_CHILD").is_none() {
            for flag in [None, Some("0"), Some("1")] {
                let mut child = std::process::Command::new(std::env::current_exe()?);
                child
                    .args(["--exact", NAME])
                    .env("RAMFLUX_MIGRATION_DISCOVERY_CHILD", "1")
                    .env_remove("RAMFLUX_HOME_MIGRATION_ENABLED");
                if let Some(flag) = flag {
                    child.env("RAMFLUX_HOME_MIGRATION_ENABLED", flag);
                }
                let output = child.output()?;
                assert!(
                    output.status.success(),
                    "{}{}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
                assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed; 0 failed"));
            }
            return Ok(());
        }
        let config: ramflux_node_core::NodeServiceConfig = serde_json::from_value(
            serde_json::json!({
                "node_id": "A", "service_id": "ramflux-federation", "redb_path": "unused.redb",
                "mesh": {"listen_addr": "127.0.0.1:0", "ca_cert": "unused.pem", "service_cert": "unused.pem", "service_key": "unused.key", "allowed_service_ids": [], "endpoints": {}}
            }),
        )?;
        let expected = std::env::var("RAMFLUX_HOME_MIGRATION_ENABLED").as_deref() == Ok("1");
        let mut surface = super::federation_discovery_surface(&config, [8; 32]);
        surface.node_ca_cert_pem = "test-ca".into();
        let client = surface.client_record()?;
        let server = surface.well_known_record()?;
        let contains = |caps: &[String]| {
            caps.iter().any(|c| c == ramflux_node_core::HOME_MIGRATION_CAPABILITY)
        };
        assert_eq!(contains(&client.client_capabilities), expected);
        assert_eq!(contains(&server.node_capabilities), expected);
        assert!(client.client_capabilities.iter().any(|c| c == "opaque_delivery"));
        assert!(server.node_capabilities.iter().any(|c| c == "opaque_delivery"));
        ramflux_node_core::verify_federation_server_record(&server, server.updated_at)?;
        ramflux_crypto::verify_canonical_signature(
            &ramflux_protocol::client_discovery_signing_bytes(&client)?,
            &client.signature,
            &client.node_public_key,
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod attachment_capability_tests {
    use super::*;

    fn surface(
        authority: Option<ramflux_node_core::FederationAttachmentAuthority>,
    ) -> FederationDiscoverySurface {
        FederationDiscoverySurface {
            node_id: "A".into(),
            public_endpoint: "https://a.example".into(),
            node_public_key: ramflux_crypto::public_key_base64url_from_seed([8; 32]),
            node_ca_cert_pem: "test-ca".into(),
            node_signing_seed: [8; 32],
            protocol_versions: vec!["v1".into()],
            transport_backends: vec!["https_json".into()],
            node_capabilities: vec![
                "opaque_delivery".into(),
                ramflux_node_core::ATTACHMENT_RENEWAL_CAPABILITY.into(),
            ],
            attachment_authority: authority,
        }
    }
    fn key() -> String {
        ramflux_protocol::encode_base64url([6; 32])
    }

    #[test]
    fn capability_and_pin_are_advertised_only_when_the_authority_is_configured()
    -> Result<(), Box<dyn std::error::Error>> {
        let has = |r: &ramflux_node_core::FederationServerRecord| {
            r.node_capabilities
                .iter()
                .any(|c| c == ramflux_node_core::ATTACHMENT_RENEWAL_CAPABILITY)
        };
        // Not configured: neither the capability nor the field, and no `null`.
        let off = surface(None).well_known_record()?;
        assert!(!has(&off) && off.attachment_authority.is_none());
        assert!(!serde_json::to_string(&off)?.contains("attachment_authority"));
        // Configured: both, signed, and the record verifies.
        let authority = ramflux_node_core::FederationAttachmentAuthority {
            generation: 3,
            signing_public_key: key(),
        };
        let on = surface(Some(authority.clone())).well_known_record()?;
        assert!(has(&on));
        assert_eq!(on.attachment_authority, Some(authority));
        ramflux_node_core::verify_federation_server_record(&on, on.updated_at)?;
        Ok(())
    }

    #[test]
    fn configuration_requires_both_settings_in_canonical_form() {
        let k = key();
        assert!(attachment_authority_from(Some("3"), Some(&k)).is_some());
        assert!(attachment_authority_from(None, Some(&k)).is_none());
        assert!(attachment_authority_from(Some("3"), None).is_none());
        assert!(attachment_authority_from(Some("0"), Some(&k)).is_none());
        assert!(attachment_authority_from(Some("x"), Some(&k)).is_none());
        assert!(attachment_authority_from(Some("3"), Some(&k[..42])).is_none());
    }
}
