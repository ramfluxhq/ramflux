// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Retention service clients and relay TTL registration fallback.

use crate::config::{mesh_tls_config, non_empty_env};

#[cfg(feature = "itest-object-v2")]
pub(crate) const RETENTION_ASYNC_ENDPOINT_ENV: &str = "RAMFLUX_RETENTION_ASYNC_ENDPOINT";
#[cfg(feature = "itest-object-v2")]
pub(crate) const RETENTION_ASYNC_SERVER_NAME_ENV: &str = "RAMFLUX_RETENTION_ASYNC_SERVER_NAME";
#[cfg(feature = "itest-object-v2")]
pub(crate) const RETENTION_ASYNC_PEER_CA_PEM_ENV: &str = "RAMFLUX_RETENTION_ASYNC_PEER_CA_PEM";
#[cfg(feature = "itest-object-v2")]
pub(crate) const RETENTION_ASYNC_PEER_CA_PEM_FILE_ENV: &str =
    "RAMFLUX_RETENTION_ASYNC_PEER_CA_PEM_FILE";
#[cfg(feature = "itest-object-v2")]
pub(crate) const DEFAULT_RETENTION_ASYNC_ENDPOINT: &str = "ramflux-retention:17446";

#[cfg(feature = "itest-object-v2")]
pub(crate) fn register_object_relay_ttl(
    config: &ramflux_node_core::NodeServiceConfig,
    retention_client: &RetentionMeshClient,
    entry: &ramflux_node_core::RelayChunkEntry,
    now: u64,
) -> Result<(), ramflux_node_core::NodeCoreError> {
    let Some(endpoint) = config.mesh.endpoints.get("retention") else {
        return Err(ramflux_node_core::NodeCoreError::ItestHttp(
            "missing retention mesh endpoint".to_owned(),
        ));
    };
    let tls = mesh_tls_config(config);
    let record = ramflux_node_core::object_relay_retention_record(entry, now);
    let request = ramflux_node_core::RetentionRecordRequest { record };
    if let Some(async_mesh) = &retention_client.async_mesh {
        match ramflux_transport::mesh_quic_post_json_with_peer_ca_pems::<
            _,
            ramflux_node_core::RetentionMetadataRecord,
        >(
            &async_mesh.endpoint,
            "/retention/v1/object_relay_ttl",
            &async_mesh.tls,
            &async_mesh.server_name,
            &async_mesh.peer_ca_pems,
            &request,
        ) {
            Ok(_response) => return Ok(()),
            Err(error @ ramflux_transport::TransportError::Quic(_)) => {
                tracing::warn!(%error, "retention async QUIC mesh failed; falling back to blocking mesh");
            }
            Err(error) => {
                return Err(ramflux_node_core::NodeCoreError::ItestHttp(error.to_string()));
            }
        }
    }
    let _response: ramflux_node_core::RetentionMetadataRecord = retention_client
        .blocking
        .post_json(endpoint, "/retention/v1/object_relay_ttl", &tls, "ramflux-retention", &request)
        .map_err(|source| ramflux_node_core::NodeCoreError::ItestHttp(source.to_string()))?;
    Ok(())
}

#[derive(Clone)]
#[cfg(feature = "itest-object-v2")]
pub(crate) struct RetentionMeshClient {
    pub(crate) blocking: ramflux_transport::MeshHttpClient,
    pub(crate) async_mesh: Option<RetentionAsyncMeshClient>,
}

#[derive(Clone)]
#[cfg(feature = "itest-object-v2")]
pub(crate) struct RetentionAsyncMeshClient {
    pub(crate) endpoint: String,
    pub(crate) server_name: String,
    pub(crate) tls: ramflux_transport::MeshTlsConfig,
    pub(crate) peer_ca_pems: Vec<String>,
}

#[cfg(feature = "itest-object-v2")]
pub(crate) fn retention_mesh_client(
    config: &ramflux_node_core::NodeServiceConfig,
) -> anyhow::Result<RetentionMeshClient> {
    Ok(RetentionMeshClient {
        blocking: ramflux_transport::MeshHttpClient::new(),
        async_mesh: retention_async_mesh_client(config)?,
    })
}

#[cfg(feature = "itest-object-v2")]
pub(crate) fn retention_async_mesh_client(
    config: &ramflux_node_core::NodeServiceConfig,
) -> anyhow::Result<Option<RetentionAsyncMeshClient>> {
    retention_async_mesh_client_from_endpoint_value(
        config,
        std::env::var(RETENTION_ASYNC_ENDPOINT_ENV).ok().as_deref(),
    )
}

#[cfg(feature = "itest-object-v2")]
pub(crate) fn retention_async_mesh_client_from_endpoint_value(
    config: &ramflux_node_core::NodeServiceConfig,
    endpoint_value: Option<&str>,
) -> anyhow::Result<Option<RetentionAsyncMeshClient>> {
    let Some(endpoint) = endpoint_from_env_value(endpoint_value, DEFAULT_RETENTION_ASYNC_ENDPOINT)
    else {
        return Ok(None);
    };
    Ok(Some(RetentionAsyncMeshClient {
        endpoint,
        server_name: non_empty_env(RETENTION_ASYNC_SERVER_NAME_ENV)
            .unwrap_or_else(|| "ramflux-retention".to_owned()),
        tls: mesh_tls_config(config),
        peer_ca_pems: retention_async_peer_ca_pems(config)?,
    }))
}

#[cfg(feature = "itest-object-v2")]
pub(crate) fn retention_async_peer_ca_pems(
    config: &ramflux_node_core::NodeServiceConfig,
) -> anyhow::Result<Vec<String>> {
    if let Some(pem) = non_empty_env(RETENTION_ASYNC_PEER_CA_PEM_ENV) {
        return Ok(vec![pem]);
    }
    let path = non_empty_env(RETENTION_ASYNC_PEER_CA_PEM_FILE_ENV)
        .unwrap_or_else(|| config.mesh.ca_cert.clone());
    Ok(vec![std::fs::read_to_string(&path)?])
}

#[cfg(feature = "itest-object-v2")]
pub(crate) fn endpoint_from_env_value(value: Option<&str>, default: &str) -> Option<String> {
    let Some(value) = value else {
        return Some(default.to_owned());
    };
    let trimmed = value.trim();
    if trimmed.starts_with("${") {
        return Some(default.to_owned());
    }
    if trimmed.is_empty() || is_env_disabled(trimmed) {
        return None;
    }
    Some(trimmed.to_owned())
}

#[cfg(feature = "itest-object-v2")]
pub(crate) fn is_env_disabled(value: &str) -> bool {
    value == "0"
        || value.eq_ignore_ascii_case("false")
        || value.eq_ignore_ascii_case("off")
        || value.eq_ignore_ascii_case("no")
}
#[cfg(test)]
#[path = "tests/retention.rs"]
mod tests;
