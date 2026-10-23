// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Provider keyring configuration, persisted high-water state, and publication.

use crate::config::{
    RELAY_FEDERATION_TRUST_ENDPOINT_ENV, RELAY_FEDERATION_TRUST_ISSUER_NODE_ID_ENV,
    RELAY_FEDERATION_TRUST_SERVER_NAME, RELAY_FEDERATION_TRUST_SNAPSHOT_PATH,
    RELAY_TRUST_SNAPSHOT_CACHE_FILE_ENV, mesh_tls_config, non_empty_env, now_unix_seconds,
};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use std::io::Write as _;

// ---- T23-A2b2a: opt-in provider keyring trust path (offline-root-signed keyring + provider_epoch) ----

#[cfg(not(feature = "itest-provider-single-key"))]
pub(crate) const RELAY_FEDERATION_PROVIDER_KEYRING_FILE_ENV: &str =
    "RAMFLUX_FEDERATION_PROVIDER_KEYRING_FILE";
#[cfg(not(feature = "itest-provider-single-key"))]
pub(crate) const RELAY_FEDERATION_PROVIDER_OFFLINE_ROOT_PUBLIC_KEY_ENV: &str =
    "RAMFLUX_FEDERATION_PROVIDER_OFFLINE_ROOT_PUBLIC_KEY";

/// Keyring-era trust config: endpoint + keyring file + pinned offline-root public key + issuer node +
/// persisted-cache file, ALL required (a missing value disables the provider; never a default). The
/// cache file is required because the strong-security keyring path relies on a persisted, fsync'd
/// anti-rollback high-water — without it there is no restart anti-rollback, so the provider stays off
/// (fail-closed) rather than authorizing without persistence.
#[cfg(not(feature = "itest-provider-single-key"))]
pub(crate) fn relay_keyring_provider_config() -> Option<(String, String, String, String, String)> {
    relay_keyring_provider_config_from_values(
        non_empty_env(RELAY_FEDERATION_TRUST_ENDPOINT_ENV).as_deref(),
        non_empty_env(RELAY_FEDERATION_PROVIDER_KEYRING_FILE_ENV).as_deref(),
        non_empty_env(RELAY_FEDERATION_PROVIDER_OFFLINE_ROOT_PUBLIC_KEY_ENV).as_deref(),
        non_empty_env(RELAY_FEDERATION_TRUST_ISSUER_NODE_ID_ENV).as_deref(),
        non_empty_env(RELAY_TRUST_SNAPSHOT_CACHE_FILE_ENV).as_deref(),
    )
}

/// Resolves the keyring-era config from raw values. The provider is enabled ONLY when ALL FIVE are
/// present and non-empty; a missing endpoint, keyring file, offline-root public key, issuer node id, or
/// cache file returns `None` (provider stays off — fail-closed), never a partial config.
#[cfg(not(feature = "itest-provider-single-key"))]
pub(crate) fn relay_keyring_provider_config_from_values(
    endpoint: Option<&str>,
    keyring_file: Option<&str>,
    offline_root_public_key: Option<&str>,
    issuer_node_id: Option<&str>,
    cache_file: Option<&str>,
) -> Option<(String, String, String, String, String)> {
    let endpoint = endpoint.map(str::trim).filter(|value| !value.is_empty())?;
    let keyring_file = keyring_file.map(str::trim).filter(|value| !value.is_empty())?;
    let offline_root = offline_root_public_key.map(str::trim).filter(|value| !value.is_empty())?;
    let issuer_node_id = issuer_node_id.map(str::trim).filter(|value| !value.is_empty())?;
    let cache_file = cache_file.map(str::trim).filter(|value| !value.is_empty())?;
    Some((
        endpoint.to_owned(),
        keyring_file.to_owned(),
        offline_root.to_owned(),
        issuer_node_id.to_owned(),
        cache_file.to_owned(),
    ))
}

/// Atomically hot-reads and validates the provider keyring file against the pinned offline root. The
/// offline-root public key is an independent trust anchor (never the provider/snapshot key), so a
/// forged keyring is rejected before any key can be selected.
#[cfg(not(feature = "itest-provider-single-key"))]
pub(crate) fn load_provider_keyring(
    keyring_file: &str,
    offline_root_public_key: &str,
    issuer_node_id: &str,
) -> anyhow::Result<ramflux_node_core::ValidatedProviderKeyring> {
    let bytes = std::fs::read(keyring_file)?;
    let keyring: ramflux_node_core::ProviderKeyring = serde_json::from_slice(&bytes)?;
    ramflux_node_core::verify_provider_keyring(&keyring, offline_root_public_key, issuer_node_id)
        .map_err(|error| anyhow::anyhow!("provider keyring rejected: {error}"))
}

/// T23-A2b2b: the fail-closed startup/readiness gate for the keyring-era object relay. Returns an
/// error (rather than silently disabling the provider) when the federation provider keyring is not
/// fully configured, or when the keyring file is missing / not valid JSON / signed by the wrong
/// offline root / for a mismatched issuer node. Callers that will serve the client object-relay QUIC
/// surface propagate this error so the relay process fails to start (the container cannot become
/// healthy) rather than accepting object requests it can never authorize.
#[cfg(not(feature = "itest-provider-single-key"))]
pub(crate) fn require_keyring_provider_ready() -> anyhow::Result<(
    String,
    String,
    String,
    String,
    String,
    ramflux_node_core::ValidatedProviderKeyring,
)> {
    require_keyring_provider_ready_from(relay_keyring_provider_config())
}

/// The fail-closed readiness decision from a resolved config. Errors (never silently disables) when the
/// config is incomplete (`None`) or the keyring file fails to load/verify.
#[cfg(not(feature = "itest-provider-single-key"))]
pub(crate) fn require_keyring_provider_ready_from(
    config: Option<(String, String, String, String, String)>,
) -> anyhow::Result<(
    String,
    String,
    String,
    String,
    String,
    ramflux_node_core::ValidatedProviderKeyring,
)> {
    let (endpoint, keyring_file, offline_root, issuer_node_id, cache_file) = config.ok_or_else(|| {
        anyhow::anyhow!(
            "the client object-relay QUIC surface is enabled but the federation provider keyring is not fully configured: {RELAY_FEDERATION_TRUST_ENDPOINT_ENV}, {RELAY_FEDERATION_PROVIDER_KEYRING_FILE_ENV}, {RELAY_FEDERATION_PROVIDER_OFFLINE_ROOT_PUBLIC_KEY_ENV}, {RELAY_FEDERATION_TRUST_ISSUER_NODE_ID_ENV} and {RELAY_TRUST_SNAPSHOT_CACHE_FILE_ENV} are all required (a missing value fails closed, it does not disable the provider)"
        )
    })?;
    let keyring =
        load_provider_keyring(&keyring_file, &offline_root, &issuer_node_id).map_err(|error| {
            anyhow::anyhow!("federation provider keyring failed to load/verify at startup: {error}")
        })?;
    Ok((endpoint, keyring_file, offline_root, issuer_node_id, cache_file, keyring))
}

/// Persisted keyring-era cache record: the accepted envelope (absent when the cache is fail-closed with
/// no authoritative snapshot) plus the anti-rollback high-waters, keyring fingerprint, and accepted
/// signer key id, so a restart restores the high-water/fingerprint and re-validates the envelope.
#[cfg(not(feature = "itest-provider-single-key"))]
#[derive(serde::Serialize, serde::Deserialize)]
pub(crate) struct PersistedKeyringTrust {
    pub(crate) envelope: Option<ramflux_node_core::ProviderSignedTrustSnapshot>,
    pub(crate) provider_epoch_high_water: u64,
    pub(crate) keyring_epoch_high_water: u64,
    pub(crate) keyring_fingerprint: Option<String>,
    pub(crate) accepted_signer_key_id: Option<String>,
}

/// Atomically persists the cache's authoritative state (tmp + fsync + rename). Callers persist a
/// candidate BEFORE publishing it live, so a persistence failure never leaves a live cache ahead of
/// the durable anti-rollback high-water.
#[cfg(not(feature = "itest-provider-single-key"))]
pub(crate) fn persist_keyring_trust(
    path: &str,
    cache: &ramflux_node_core::RelayTrustSnapshotCache,
    envelope: Option<&ramflux_node_core::ProviderSignedTrustSnapshot>,
) -> anyhow::Result<()> {
    let record = PersistedKeyringTrust {
        envelope: envelope.cloned(),
        provider_epoch_high_water: cache.provider_epoch_high_water(),
        keyring_epoch_high_water: cache.keyring_epoch_high_water(),
        keyring_fingerprint: cache.keyring_fingerprint_high_water().map(str::to_owned),
        accepted_signer_key_id: cache.accepted_signer_key_id().map(str::to_owned),
    };
    let path = std::path::Path::new(path);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let temporary = path.with_extension(format!("tmp.{}", std::process::id()));
    let bytes = serde_json::to_vec_pretty(&record)?;
    {
        let mut file = std::fs::File::create(&temporary)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
    }
    std::fs::rename(temporary, path)?;
    // Best-effort parent-directory fsync so the rename is durable on crash; not fatal where the
    // platform/filesystem does not support directory sync.
    if let Some(parent) = path.parent()
        && let Ok(dir) = std::fs::File::open(parent)
    {
        let _ = dir.sync_all();
    }
    Ok(())
}

/// Restores the persisted keyring-era high-water/fingerprint, then re-installs the persisted envelope
/// against the current validated keyring (fully re-verified) and reconciles the signer. Returns the
/// restored authoritative envelope, or `None` when the record was fail-closed or the persisted signer
/// is no longer usable under the current keyring. On a non-adoptable keyring (rollback) it errors and
/// the caller keeps the cache fail-closed.
#[cfg(not(feature = "itest-provider-single-key"))]
pub(crate) fn load_keyring_trust(
    path: &str,
    cache: &mut ramflux_node_core::RelayTrustSnapshotCache,
    keyring: &ramflux_node_core::ValidatedProviderKeyring,
    issuer_node_id: &str,
    now: u64,
) -> anyhow::Result<Option<ramflux_node_core::ProviderSignedTrustSnapshot>> {
    let bytes = std::fs::read(path)?;
    let record: PersistedKeyringTrust = serde_json::from_slice(&bytes)?;
    cache.restore_high_water(
        record.accepted_signer_key_id,
        record.provider_epoch_high_water,
        record.keyring_epoch_high_water,
        record.keyring_fingerprint,
    );
    let restored = match record.envelope {
        Some(envelope)
            if cache
                .update_from_keyring_signed(&envelope, keyring, issuer_node_id, now)
                .is_ok() =>
        {
            Some(envelope)
        }
        _ => None,
    };
    cache
        .reconcile_keyring(keyring, now)
        .map_err(|error| anyhow::anyhow!("persisted keyring not adoptable: {error}"))?;
    Ok(if cache.generation().is_some() { restored } else { None })
}

/// Fetches the versioned provider-signed envelope from federation over mesh QUIC (no cache mutation).
#[cfg(not(feature = "itest-provider-single-key"))]
pub(crate) fn fetch_keyring_envelope(
    endpoint: &str,
    tls: &ramflux_transport::MeshTlsConfig,
    peer_ca_pems: &[String],
) -> anyhow::Result<ramflux_node_core::ProviderSignedTrustSnapshot> {
    let endpoint = endpoint.trim();
    if endpoint.is_empty() {
        anyhow::bail!("{RELAY_FEDERATION_TRUST_ENDPOINT_ENV} is not configured");
    }
    Ok(ramflux_transport::mesh_quic_get_json_with_peer_ca_pems(
        endpoint,
        RELAY_FEDERATION_TRUST_SNAPSHOT_PATH,
        tls,
        RELAY_FEDERATION_TRUST_SERVER_NAME,
        peer_ca_pems,
    )?)
}

/// Pure planner: from the current live cache + the freshly-validated keyring + an optionally-fetched
/// envelope, computes the next cache candidate WITHOUT any IO. Returns `Some((candidate, envelope))`
/// when there is a change to persist+publish, or `None` when the keyring is non-adoptable (epoch
/// rollback or same-epoch content change — leave the live cache untouched) or nothing changed.
///
/// A retirement of the current signer clears the cached snapshot in the candidate (fail-closed), and
/// its authoritative envelope becomes `None`, so the persisted+published state is empty-authorization.
#[cfg(not(feature = "itest-provider-single-key"))]
pub(crate) fn plan_keyring_candidate(
    live: &ramflux_node_core::RelayTrustSnapshotCache,
    keyring: &ramflux_node_core::ValidatedProviderKeyring,
    fetched: Option<ramflux_node_core::ProviderSignedTrustSnapshot>,
    last_envelope: Option<&ramflux_node_core::ProviderSignedTrustSnapshot>,
    issuer_node_id: &str,
    now: u64,
) -> Option<(
    ramflux_node_core::RelayTrustSnapshotCache,
    Option<ramflux_node_core::ProviderSignedTrustSnapshot>,
)> {
    let mut candidate = live.clone();
    let mut candidate_envelope = last_envelope.cloned();
    match fetched {
        Some(envelope)
            if candidate
                .update_from_keyring_signed(&envelope, keyring, issuer_node_id, now)
                .is_ok() =>
        {
            candidate_envelope = Some(envelope);
        }
        // No new envelope (fetch failed / rejected): reconcile the signer against the reloaded keyring.
        // A non-adoptable keyring (rollback / same-epoch content change) leaves the live cache untouched.
        _ => {
            if candidate.reconcile_keyring(keyring, now).is_err() {
                return None;
            }
        }
    }
    if candidate.generation().is_none() {
        candidate_envelope = None;
    }
    if &candidate == live {
        return None;
    }
    Some((candidate, candidate_envelope))
}

/// Publish-after-persist: durably persist the candidate FIRST, and only on success publish it into the
/// live cache. A persistence failure leaves the live cache (and durable file) unchanged, so a crash
/// can never restore a state behind a live-but-unpersisted anti-rollback high-water.
#[cfg(not(feature = "itest-provider-single-key"))]
pub(crate) fn publish_keyring_candidate(
    live: &Mutex<ramflux_node_core::RelayTrustSnapshotCache>,
    candidate: ramflux_node_core::RelayTrustSnapshotCache,
    candidate_envelope: Option<&ramflux_node_core::ProviderSignedTrustSnapshot>,
    cache_path: &str,
) -> anyhow::Result<()> {
    persist_keyring_trust(cache_path, &candidate, candidate_envelope)?;
    let mut live = live.lock().map_err(|error| anyhow::anyhow!("cache lock poisoned: {error}"))?;
    *live = candidate;
    Ok(())
}

/// Background keyring-era refresh: each tick re-reads + re-validates the keyring file (hot-read),
/// clones the live cache, applies the fetched envelope (or reconciles the signer on a fetch failure)
/// on the CANDIDATE, then persists the candidate and only publishes it live on persist success.
#[cfg(not(feature = "itest-provider-single-key"))]
#[allow(clippy::too_many_arguments)]
pub(crate) fn start_keyring_trust_refresh(
    cache: Arc<Mutex<ramflux_node_core::RelayTrustSnapshotCache>>,
    config: ramflux_node_core::NodeServiceConfig,
    issuer_node_id: String,
    endpoint: String,
    keyring_file: String,
    offline_root_public_key: String,
    cache_file: String,
    initial_envelope: Option<ramflux_node_core::ProviderSignedTrustSnapshot>,
    interval: Duration,
) {
    let _ = thread::Builder::new()
        .name("relay-keyring-trust-refresh".to_owned())
        .spawn(move || {
            let mut last_envelope = initial_envelope;
            loop {
                thread::sleep(interval);
                let keyring = match load_provider_keyring(
                    &keyring_file,
                    &offline_root_public_key,
                    &issuer_node_id,
                ) {
                    Ok(keyring) => keyring,
                    Err(error) => {
                        tracing::warn!(%error, "background keyring reload rejected; retaining existing cache");
                        continue;
                    }
                };
                let tls = mesh_tls_config(&config);
                let peer_ca_pems = match std::fs::read_to_string(&config.mesh.ca_cert) {
                    Ok(pem) => vec![pem],
                    Err(error) => {
                        tracing::warn!(%error, "background keyring trust refresh cannot read mesh CA");
                        continue;
                    }
                };
                let now = now_unix_seconds();
                let live_clone = match cache.lock() {
                    Ok(cache) => cache.clone(),
                    Err(error) => {
                        tracing::warn!(%error, "background keyring trust cache lock poisoned");
                        continue;
                    }
                };
                let fetched = fetch_keyring_envelope(&endpoint, &tls, &peer_ca_pems).ok();
                let Some((candidate, candidate_envelope)) = plan_keyring_candidate(
                    &live_clone,
                    &keyring,
                    fetched,
                    last_envelope.as_ref(),
                    &issuer_node_id,
                    now,
                ) else {
                    continue;
                };
                let generation = candidate.generation();
                match publish_keyring_candidate(
                    &cache,
                    candidate,
                    candidate_envelope.as_ref(),
                    &cache_file,
                ) {
                    Ok(()) => {
                        last_envelope = candidate_envelope;
                        tracing::info!(generation = ?generation, "background keyring trust snapshot refreshed");
                    }
                    Err(error) => {
                        tracing::warn!(%error, "background keyring trust persistence failed; not publishing candidate");
                    }
                }
            }
        });
}

// T23-A2b2a: relay-glue pure tests for the opt-in provider-keyring trust path (file load + validate,
// persist/restore roundtrip honouring the anti-rollback high-water). The core verifier/cache logic is
// covered by node-core; these cover the relay's file IO + serde + restore wiring.
#[cfg(all(test, not(feature = "itest-provider-single-key")))]
#[path = "tests/trust_keyring.rs"]
mod keyring_loader_tests;
