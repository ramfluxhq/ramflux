// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Node discovery record generation and stable signing-key configuration.
use crate::helpers::non_empty_env;
use crate::{FederationDiscoverySurface, now_unix_seconds};

pub(crate) fn federation_discovery_surface(
    config: &ramflux_node_core::NodeServiceConfig,
    node_signing_seed: [u8; 32],
) -> FederationDiscoverySurface {
    let node_ca_cert_pem = std::fs::read_to_string(&config.mesh.ca_cert).unwrap_or_default();
    FederationDiscoverySurface {
        node_id: std::env::var("RAMFLUX_FEDERATION_NODE_ID")
            .unwrap_or_else(|_| config.node_id.clone()),
        public_endpoint: std::env::var("RAMFLUX_FEDERATION_PUBLIC_ENDPOINT")
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
    }
}

pub(crate) fn federation_node_signing_seed(
    state: &mut ramflux_node_core::FederationTrustState,
) -> Result<[u8; 32], ramflux_node_core::NodeCoreError> {
    let configured = std::env::var("RAMFLUX_FEDERATION_NODE_SIGNING_SEED_B64URL").ok();
    federation_node_signing_seed_from_config(
        state,
        configured.as_deref(),
        ramflux_crypto::random_32,
    )
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
            protocol_versions: self.protocol_versions.clone(),
            client_capabilities: vec![
                "opaque_delivery".to_owned(),
                "prekey".to_owned(),
                "object_relay".to_owned(),
            ],
            updated_at: now,
            expires_at: now.saturating_add(ramflux_protocol::DISCOVERY_MAX_CACHE_TTL_SECONDS),
            signature: String::new(),
        };
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
            node_capabilities: self.node_capabilities.clone(),
            node_policy_hash: ramflux_crypto::blake3_256_base64url(
                ramflux_protocol::domain::FEDERATION_HANDSHAKE,
                self.node_id.as_bytes(),
            ),
            updated_at: now,
            expires_at: now.saturating_add(86_400),
            signature: String::new(),
        };
        ramflux_node_core::sign_federation_server_record_with_seed(
            &mut record,
            self.node_signing_seed,
        )?;
        Ok(record)
    }
}

fn federation_node_signing_seed_from_config(
    state: &mut ramflux_node_core::FederationTrustState,
    configured_seed: Option<&str>,
    random_seed: impl FnOnce() -> Result<[u8; 32], ramflux_crypto::CryptoError>,
) -> Result<[u8; 32], ramflux_node_core::NodeCoreError> {
    if let Some(encoded) = configured_seed.filter(|value| !value.trim().is_empty()) {
        let bytes = ramflux_protocol::decode_base64url(encoded)
            .map_err(|source| ramflux_node_core::NodeCoreError::ItestJson(source.to_string()))?;
        let seed = <[u8; 32]>::try_from(bytes).map_err(|bytes: Vec<u8>| {
            ramflux_node_core::NodeCoreError::ItestHttp(format!(
                "invalid RAMFLUX_FEDERATION_NODE_SIGNING_SEED_B64URL length: {}",
                bytes.len()
            ))
        })?;
        state.set_node_signing_seed(seed);
        return Ok(seed);
    }
    if let Some(seed) = state.node_signing_seed() {
        return Ok(seed);
    }
    let seed = random_seed()
        .map_err(|source| ramflux_node_core::NodeCoreError::ItestHttp(source.to_string()))?;
    state.set_node_signing_seed(seed);
    Ok(seed)
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
            node_capabilities: vec!["opaque_delivery".to_owned()],
        };

        let record = surface.well_known_record()?;

        assert!(record.updated_at >= now);
        assert_eq!(record.expires_at, record.updated_at.saturating_add(86_400));
        ramflux_node_core::verify_federation_server_record(&record, record.updated_at)?;
        Ok(())
    }

    #[test]
    fn node_signing_seed_uses_env_and_persists_to_state()
    -> Result<(), ramflux_node_core::NodeCoreError> {
        let env_seed = [0x42; 32];
        let encoded = ramflux_protocol::encode_base64url(env_seed);
        let mut state = ramflux_node_core::FederationTrustState::new();

        let resolved = federation_node_signing_seed_from_config(
            &mut state,
            Some(&encoded),
            || Ok([0x77; 32]),
        )?;

        assert_eq!(resolved, env_seed);
        assert_eq!(state.node_signing_seed(), Some(env_seed));
        Ok(())
    }

    #[test]
    fn node_signing_seed_rejects_invalid_env_seed() -> Result<(), ramflux_node_core::NodeCoreError>
    {
        let mut state = ramflux_node_core::FederationTrustState::new();

        let Err(error) =
            federation_node_signing_seed_from_config(&mut state, Some("bad-seed"), || {
                Ok([0x77; 32])
            })
        else {
            return Err(ramflux_node_core::NodeCoreError::ItestHttp(
                "invalid configured federation seed must fail".to_owned(),
            ));
        };

        assert!(
            error
                .to_string()
                .contains("invalid RAMFLUX_FEDERATION_NODE_SIGNING_SEED_B64URL length"),
            "{error}"
        );
        assert_eq!(state.node_signing_seed(), None);
        Ok(())
    }

    #[test]
    fn node_signing_seed_reuses_persisted_seed_before_random()
    -> Result<(), ramflux_node_core::NodeCoreError> {
        let persisted_seed = [0x33; 32];
        let mut state = ramflux_node_core::FederationTrustState::new();
        state.set_node_signing_seed(persisted_seed);

        let resolved =
            federation_node_signing_seed_from_config(&mut state, None, || Ok([0x99; 32]))?;

        assert_eq!(resolved, persisted_seed);
        Ok(())
    }

    #[test]
    fn node_signing_seed_generates_and_persists_when_missing()
    -> Result<(), ramflux_node_core::NodeCoreError> {
        let generated_seed = [0x55; 32];
        let mut state = ramflux_node_core::FederationTrustState::new();

        let resolved =
            federation_node_signing_seed_from_config(&mut state, None, || Ok(generated_seed))?;

        assert_eq!(resolved, generated_seed);
        assert_eq!(state.node_signing_seed(), Some(generated_seed));
        Ok(())
    }
}
