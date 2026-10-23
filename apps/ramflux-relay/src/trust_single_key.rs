// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Legacy single-provider trust retrieval, caching, and refresh.

use crate::config::{
    RELAY_FEDERATION_TRUST_ENDPOINT_ENV, RELAY_FEDERATION_TRUST_ISSUER_NODE_ID_ENV,
    RELAY_FEDERATION_TRUST_SERVER_NAME, RELAY_FEDERATION_TRUST_SNAPSHOT_PATH,
    RELAY_TRUST_SNAPSHOT_CACHE_FILE_ENV, mesh_tls_config, non_empty_env, now_unix_seconds,
};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use std::io::Write as _;

#[cfg(feature = "itest-provider-single-key")]
pub(crate) const RELAY_FEDERATION_PROVIDER_PUBLIC_KEY_ENV: &str =
    "RAMFLUX_FEDERATION_PROVIDER_PUBLIC_KEY";

/// Resolves the trust-snapshot provider config from the given endpoint and pinned provider public
/// key values. The provider is only enabled when BOTH are present and non-empty; a missing value
/// means "do not start the provider" (returns `None`), never a default.
#[cfg(feature = "itest-provider-single-key")]
pub(crate) fn relay_trust_provider_config_from_values(
    endpoint: Option<&str>,
    provider_public_key: Option<&str>,
    issuer_node_id: Option<&str>,
) -> Option<(String, String, String)> {
    let endpoint = endpoint.map(str::trim).filter(|value| !value.is_empty())?;
    let provider_public_key =
        provider_public_key.map(str::trim).filter(|value| !value.is_empty())?;
    let issuer_node_id = issuer_node_id.map(str::trim).filter(|value| !value.is_empty())?;
    Some((endpoint.to_owned(), provider_public_key.to_owned(), issuer_node_id.to_owned()))
}

/// Reads the trust-snapshot provider config from the environment (both variables required).
#[cfg(feature = "itest-provider-single-key")]
pub(crate) fn relay_trust_provider_config() -> Option<(String, String, String)> {
    relay_trust_provider_config_from_values(
        non_empty_env(RELAY_FEDERATION_TRUST_ENDPOINT_ENV).as_deref(),
        non_empty_env(RELAY_FEDERATION_PROVIDER_PUBLIC_KEY_ENV).as_deref(),
        non_empty_env(RELAY_FEDERATION_TRUST_ISSUER_NODE_ID_ENV).as_deref(),
    )
}

#[cfg(feature = "itest-provider-single-key")]
pub(crate) fn relay_trust_snapshot_cache_file() -> Option<String> {
    non_empty_env(RELAY_TRUST_SNAPSHOT_CACHE_FILE_ENV)
}

#[cfg(feature = "itest-provider-single-key")]
pub(crate) fn load_trust_snapshot_cache(
    path: &str,
) -> anyhow::Result<ramflux_node_core::SignedFederatedIssuerTrustSnapshot> {
    let bytes = std::fs::read(path)?;
    Ok(serde_json::from_slice(&bytes)?)
}

#[cfg(feature = "itest-provider-single-key")]
pub(crate) fn persist_trust_snapshot_cache(
    path: &str,
    envelope: &ramflux_node_core::SignedFederatedIssuerTrustSnapshot,
) -> anyhow::Result<()> {
    let path = std::path::Path::new(path);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let temporary = path.with_extension(format!("tmp.{}", std::process::id()));
    let bytes = serde_json::to_vec_pretty(envelope)?;
    {
        let mut file = std::fs::File::create(&temporary)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
    }
    std::fs::rename(temporary, path)?;
    Ok(())
}

#[cfg(feature = "itest-provider-single-key")]
#[allow(clippy::too_many_arguments)]
pub(crate) fn start_trust_snapshot_refresh(
    cache: Arc<Mutex<ramflux_node_core::RelayTrustSnapshotCache>>,
    config: ramflux_node_core::NodeServiceConfig,
    node_id: String,
    endpoint: String,
    provider_public_key: String,
    cache_file: Option<String>,
    interval: Duration,
) {
    let _ = thread::Builder::new()
        .name("relay-trust-refresh".to_owned())
        .spawn(move || loop {
            thread::sleep(interval);
            let tls = mesh_tls_config(&config);
            let peer_ca_pems = match std::fs::read_to_string(&config.mesh.ca_cert) {
                Ok(pem) => vec![pem],
                Err(error) => {
                    tracing::warn!(%error, "background federation trust snapshot refresh cannot read mesh CA");
                    continue;
                }
            };
            let envelope = match fetch_trust_snapshot_envelope(
                Some(&endpoint),
                &tls,
                &peer_ca_pems,
            ) {
                Ok(envelope) => envelope,
                Err(error) => {
                    tracing::warn!(%error, "background federation trust snapshot refresh failed; retaining existing cache");
                    continue;
                }
            };
            let now = now_unix_seconds();
            let installed = match cache.lock() {
                Ok(mut cache) => apply_fetched_trust_snapshot(
                    &mut cache,
                    &envelope,
                    &provider_public_key,
                    &node_id,
                    now,
                ),
                Err(error) => Err(anyhow::anyhow!("trust snapshot cache lock poisoned: {error}")),
            };
            match installed {
                Ok(()) => {
                    if let Some(path) = cache_file.as_deref()
                        && let Err(error) = persist_trust_snapshot_cache(path, &envelope)
                    {
                        tracing::warn!(%error, path, "background trust snapshot persistence failed");
                    }
                    tracing::info!(generation = envelope.snapshot.generation, "background federation trust snapshot refreshed");
                }
                Err(error) => tracing::warn!(%error, "background federation trust snapshot rejected; retaining existing cache"),
            }
        });
}

/// Fetches the signed trust snapshot envelope from federation over mesh QUIC and, only on success,
/// installs it into `cache`. A missing endpoint, a network/transport failure, or a signature/snapshot
/// rejection all leave the existing cache untouched (fail-closed; no plaintext HTTP fallback).
#[cfg(feature = "itest-provider-single-key")]
#[allow(clippy::too_many_arguments)]
pub(crate) fn fetch_signed_trust_snapshot(
    endpoint: Option<&str>,
    tls: &ramflux_transport::MeshTlsConfig,
    peer_ca_pems: &[String],
    provider_public_key: &str,
    node_id: &str,
    cache: &mut ramflux_node_core::RelayTrustSnapshotCache,
    now: u64,
) -> anyhow::Result<ramflux_node_core::SignedFederatedIssuerTrustSnapshot> {
    let envelope = fetch_trust_snapshot_envelope(endpoint, tls, peer_ca_pems)?;
    apply_fetched_trust_snapshot(cache, &envelope, provider_public_key, node_id, now)?;
    Ok(envelope)
}

#[cfg(feature = "itest-provider-single-key")]
pub(crate) fn fetch_trust_snapshot_envelope(
    endpoint: Option<&str>,
    tls: &ramflux_transport::MeshTlsConfig,
    peer_ca_pems: &[String],
) -> anyhow::Result<ramflux_node_core::SignedFederatedIssuerTrustSnapshot> {
    let Some(endpoint) = endpoint.map(str::trim).filter(|value| !value.is_empty()) else {
        anyhow::bail!("{RELAY_FEDERATION_TRUST_ENDPOINT_ENV} is not configured");
    };
    Ok(ramflux_transport::mesh_quic_get_json_with_peer_ca_pems(
        endpoint,
        RELAY_FEDERATION_TRUST_SNAPSHOT_PATH,
        tls,
        RELAY_FEDERATION_TRUST_SERVER_NAME,
        peer_ca_pems,
    )?)
}

/// Installs an already-fetched signed trust snapshot envelope, delegating source authentication and
/// the fail-closed successor rules to [`ramflux_node_core::RelayTrustSnapshotCache::update_from_signed`].
/// On any rejection the cache is left unchanged.
#[cfg(feature = "itest-provider-single-key")]
pub(crate) fn apply_fetched_trust_snapshot(
    cache: &mut ramflux_node_core::RelayTrustSnapshotCache,
    envelope: &ramflux_node_core::SignedFederatedIssuerTrustSnapshot,
    provider_public_key: &str,
    node_id: &str,
    now: u64,
) -> anyhow::Result<()> {
    cache
        .update_from_signed(envelope, provider_public_key, node_id, now)
        .map_err(|error| anyhow::anyhow!("relay trust snapshot rejected: {error}"))
}
#[cfg(test)]
#[path = "tests/trust_single_key.rs"]
mod tests;
