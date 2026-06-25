// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
use crate::{FederationDiscoverySurface, RouterMeshClient};

pub(crate) fn router_mesh_client(
    config: &ramflux_node_core::NodeServiceConfig,
) -> Result<RouterMeshClient, ramflux_node_core::NodeCoreError> {
    let endpoint = config.mesh.endpoints.get("router").cloned().unwrap_or_default();
    if endpoint.is_empty() {
        return Err(ramflux_node_core::NodeCoreError::ItestHttp(
            "missing router mesh endpoint".to_owned(),
        ));
    }
    Ok(RouterMeshClient {
        endpoint,
        server_name: "ramflux-router".to_owned(),
        tls: ramflux_transport::MeshTlsConfig {
            ca_cert: config.mesh.ca_cert.clone().into(),
            service_cert: config.mesh.service_cert.clone().into(),
            service_key: config.mesh.service_key.clone().into(),
        },
        client: ramflux_transport::MeshHttpClient::new(),
    })
}

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

pub(crate) fn now_unix_seconds() -> Result<u64, ramflux_node_core::NodeCoreError> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|source| ramflux_node_core::NodeCoreError::ItestHttp(source.to_string()))
}

pub(crate) fn mesh_tls_config(
    config: &ramflux_node_core::NodeServiceConfig,
) -> ramflux_transport::MeshTlsConfig {
    ramflux_transport::MeshTlsConfig {
        ca_cert: config.mesh.ca_cert.clone().into(),
        service_cert: config.mesh.service_cert.clone().into(),
        service_key: config.mesh.service_key.clone().into(),
    }
}

pub(crate) fn mesh_transport_error(
    error: &ramflux_transport::TransportError,
) -> ramflux_node_core::NodeCoreError {
    ramflux_node_core::NodeCoreError::ItestHttp(error.to_string())
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
