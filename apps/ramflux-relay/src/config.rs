// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Relay startup configuration, TLS material, and environment resolution.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub(crate) const RELAY_CLIENT_QUIC_ADDR_ENV: &str = "RAMFLUX_RELAY_CLIENT_QUIC_ADDR";
pub(crate) const RELAY_TRUST_SNAPSHOT_CACHE_FILE_ENV: &str =
    "RAMFLUX_RELAY_TRUST_SNAPSHOT_CACHE_FILE";
pub(crate) const RELAY_TRUST_SNAPSHOT_REFRESH_INTERVAL_ENV: &str =
    "RAMFLUX_RELAY_TRUST_SNAPSHOT_REFRESH_INTERVAL_SECONDS";

#[cfg(any(feature = "itest-object-v2", feature = "itest-media-udp"))]
pub(crate) fn relay_service_key(
    config: &ramflux_node_core::NodeServiceConfig,
) -> anyhow::Result<Vec<u8>> {
    let Some(secret_ref) = std::env::var("RAMFLUX_RELAY_SERVICE_KEY_REF")
        .ok()
        .or_else(|| config.relay.as_ref().and_then(|relay| relay.service_key_ref.clone()))
    else {
        anyhow::bail!("missing relay service_key_ref")
    };
    read_relay_secret_ref(&secret_ref)
}

pub(crate) fn non_empty_env(name: &str) -> Option<String> {
    std::env::var(name).ok().and_then(|value| {
        let trimmed = value.trim();
        if trimmed.starts_with("${") {
            return None;
        }
        (!trimmed.is_empty()).then(|| trimmed.to_owned())
    })
}

// ---- T12-A: client-facing object relay QUIC — config + route skeleton ----
//
// T12-A (augmenting the client-facing QUIC address parsing above): a fail-closed server-auth TLS
// credential check and a pure request-router skeleton over the existing wire types. No QUIC listener
// is spawned and no relay token business logic is wired here — those object routes return `503` so
// the surface cannot masquerade as production-ready. The mesh mTLS surface (router peer) and the
// itest HTTP surface are unchanged.

pub(crate) fn parse_client_quic_addr(value: Option<&str>) -> anyhow::Result<std::net::SocketAddr> {
    let Some(raw) = value else {
        anyhow::bail!("{RELAY_CLIENT_QUIC_ADDR_ENV} is not set");
    };
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.starts_with("${") {
        anyhow::bail!("{RELAY_CLIENT_QUIC_ADDR_ENV} is empty or unexpanded");
    }
    trimmed.parse().map_err(|error| {
        anyhow::anyhow!("invalid {RELAY_CLIENT_QUIC_ADDR_ENV} {trimmed:?}: {error}")
    })
}

pub(crate) fn relay_client_quic_addr() -> anyhow::Result<std::net::SocketAddr> {
    parse_client_quic_addr(std::env::var(RELAY_CLIENT_QUIC_ADDR_ENV).ok().as_deref())
}

/// Builds the server-auth QUIC config for the client-facing surface, failing closed if the relay
/// lacks valid server-auth TLS credentials. Reuses the gateway server-auth QUIC config builder so
/// the credential requirements are identical; a missing/invalid cert or key surfaces a clear
/// configuration error instead of a silent insecure fallback.
pub(crate) fn validate_relay_client_quic_tls(
    config: &ramflux_node_core::NodeServiceConfig,
) -> anyhow::Result<quinn::ServerConfig> {
    ramflux_transport::quic_gateway_server_config(&mesh_tls_config(config)).map_err(|error| {
        anyhow::anyhow!("relay client QUIC requires server-auth TLS credentials: {error}")
    })
}

#[cfg(any(feature = "itest-object-v2", feature = "itest-media-udp"))]
pub(crate) fn read_relay_secret_ref(secret_ref: &str) -> anyhow::Result<Vec<u8>> {
    let value = if let Some(literal) = secret_ref.strip_prefix("literal:") {
        literal.to_owned()
    } else if let Some(name) = secret_ref.strip_prefix("env:") {
        std::env::var(name)?
    } else if let Some(path) = secret_ref.strip_prefix("file:") {
        std::fs::read_to_string(path)?
    } else {
        anyhow::bail!("unsupported relay secret ref scheme")
    };
    Ok(value.into_bytes())
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

pub(crate) fn now_unix_seconds() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |duration| duration.as_secs())
}

// ---- T13-D: relay -> federation signed trust snapshot fetch client (no object handler wired) ----

pub(crate) const RELAY_FEDERATION_TRUST_ENDPOINT_ENV: &str = "RAMFLUX_FEDERATION_TRUST_ENDPOINT";
pub(crate) const RELAY_FEDERATION_TRUST_ISSUER_NODE_ID_ENV: &str =
    "RAMFLUX_FEDERATION_TRUST_ISSUER_NODE_ID";
pub(crate) const RELAY_FEDERATION_TRUST_SERVER_NAME: &str = "ramflux-federation";
pub(crate) const RELAY_FEDERATION_TRUST_SNAPSHOT_PATH: &str = "/mvp9/federation/trust-snapshot";

pub(crate) fn trust_snapshot_refresh_interval() -> Duration {
    non_empty_env(RELAY_TRUST_SNAPSHOT_REFRESH_INTERVAL_ENV)
        .and_then(|value| value.parse::<u64>().ok())
        .map_or_else(|| Duration::from_secs(30), |seconds| Duration::from_secs(seconds.max(5)))
}
#[cfg(test)]
#[path = "tests/config.rs"]
mod tests;
