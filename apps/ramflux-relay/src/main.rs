// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use crate::config::{
    RELAY_CLIENT_QUIC_ADDR_ENV, mesh_tls_config, now_unix_seconds, trust_snapshot_refresh_interval,
};
use crate::expiration::start_expire_scheduler;
#[cfg(feature = "itest-http")]
use crate::itest_http::serve_itest_http;
#[cfg(feature = "itest-object-v2")]
use crate::legacy_object::serve_relay_mesh_mtls;
#[cfg(feature = "itest-media-udp")]
use crate::media::serve_media_relay_udp;
use crate::quic_service::serve_relay_client_quic;
#[cfg(feature = "itest-object-v2")]
use crate::retention::retention_mesh_client;
#[cfg(not(feature = "itest-provider-single-key"))]
use crate::trust_keyring::{
    fetch_keyring_envelope, load_keyring_trust, persist_keyring_trust, plan_keyring_candidate,
    relay_keyring_provider_config, require_keyring_provider_ready, start_keyring_trust_refresh,
};
#[cfg(feature = "itest-provider-single-key")]
use crate::trust_single_key::{
    apply_fetched_trust_snapshot, fetch_signed_trust_snapshot, load_trust_snapshot_cache,
    persist_trust_snapshot_cache, relay_trust_provider_config, relay_trust_snapshot_cache_file,
    start_trust_snapshot_refresh,
};
#[cfg(any(feature = "itest-object-v2", feature = "itest-media-udp"))]
use config::relay_service_key;
use std::sync::{Arc, Mutex};

// CTRL-089 RELAY-MEM-02-A1 DIAGNOSTIC/profiler-only (feature `itest-alloc-prof`, default-off). Installs
// dhat as the global allocator so EVERY allocation is instrumented and attributed to a stack. Absent
// entirely from the default/production relay: without the feature there is no `#[global_allocator]`, no
// dhat dep, and no `dhat` marker string in the binary.
#[cfg(feature = "itest-alloc-prof")]
#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

fn main() {
    // DIAGNOSTIC-only: arm the dhat profiler on a dedicated owner thread that flushes the heap json on
    // SIGTERM. No-op / not compiled in the default/production build.
    #[cfg(feature = "itest-alloc-prof")]
    alloc_prof::maybe_start();
    if let Err(error) = run_service("ramflux-relay") {
        eprintln!("ramflux-relay: {error}");
        std::process::exit(2);
    }
}

#[allow(clippy::too_many_lines)]
fn run_service(service: &'static str) -> anyhow::Result<()> {
    if std::env::args().any(|arg| arg == "--health-check") {
        // T23-A2b2b: in the default keyring mode, health is NOT unconditional. When the client
        // object-relay QUIC surface is configured, the federation provider keyring must be fully
        // configured and load/verify against the pinned offline root, or the health check fails
        // (non-zero) — a relay that cannot authorize object requests must never report healthy.
        #[cfg(not(feature = "itest-provider-single-key"))]
        if service == "ramflux-relay"
            && ramflux_node_core::environment::var_os(RELAY_CLIENT_QUIC_ADDR_ENV).is_some()
        {
            require_keyring_provider_ready()?;
        }
        println!("{service}:healthy");
        return Ok(());
    }
    tracing_subscriber::fmt().with_target(false).init();
    if let Some(config) =
        ramflux_node_core::load_config_from_args(std::env::args().skip(1), service)?
    {
        voice::start(&config)?;
        let redb_path = ramflux_node_core::effective_redb_path(&config);
        let store = Arc::new(ramflux_node_core::RelayRedbStore::open(&redb_path)?);
        // Resident metadata budget (RELAY-MEM-01-A1): fail closed on a `0`/invalid override so an
        // operator misconfiguration never silently falls back to the default or an unbounded cache.
        let metadata_max_bytes = ramflux_node_core::relay_metadata_max_bytes_from_env()?;
        let state = match store.load_state(metadata_max_bytes)? {
            Some(state) => state,
            None => ramflux_node_core::RelayCacheState::with_max_bytes(metadata_max_bytes),
        };
        let state = Arc::new(Mutex::new(state));
        // The object relay HMAC service key is a legacy v2-only credential. The
        // default/production relay never loads it: v3 (Ed25519 issuer trust) is the
        // only production object data plane. It is loaded solely for the itest-only
        // v2 object surface (mesh mTLS + itest HTTP) and the itest media relay.
        #[cfg(any(feature = "itest-object-v2", feature = "itest-media-udp"))]
        let service_key = relay_service_key(&config)?;
        // Retention TTL registration is only reached by the legacy v2 object put path
        // (v3 Put returns 501 and stores nothing in the relay), so it is itest-only too.
        #[cfg(feature = "itest-object-v2")]
        let retention_client = retention_mesh_client(&config)?;
        let mut trust_snapshot_cache = ramflux_node_core::RelayTrustSnapshotCache::new();
        // T23-A2b2a: the keyring path (opt-in `provider-keyring`) and the legacy single-key path are
        // mutually exclusive at compile time — exactly one federation-trust startup wiring is compiled
        // into a given binary, so one running instance can never enable both.
        #[cfg(feature = "itest-provider-single-key")]
        if let Some((endpoint, provider_public_key, issuer_node_id)) = relay_trust_provider_config()
        {
            let tls = mesh_tls_config(&config);
            let peer_ca_pems = vec![std::fs::read_to_string(&config.mesh.ca_cert)?];
            let cache_file = relay_trust_snapshot_cache_file();
            if let Some(path) = cache_file.as_deref() {
                match load_trust_snapshot_cache(path) {
                    Ok(envelope) => {
                        if let Err(error) = apply_fetched_trust_snapshot(
                            &mut trust_snapshot_cache,
                            &envelope,
                            &provider_public_key,
                            &issuer_node_id,
                            now_unix_seconds(),
                        ) {
                            tracing::warn!(%error, path, "persisted federation trust snapshot rejected; relay remains fail-closed");
                        } else {
                            tracing::info!(path, generation = ?trust_snapshot_cache.generation(), "persisted federation trust snapshot loaded");
                        }
                    }
                    Err(error) => {
                        tracing::debug!(%error, path, "no usable persisted federation trust snapshot");
                    }
                }
            }
            match fetch_signed_trust_snapshot(
                Some(&endpoint),
                &tls,
                &peer_ca_pems,
                &provider_public_key,
                &issuer_node_id,
                &mut trust_snapshot_cache,
                now_unix_seconds(),
            ) {
                Ok(envelope) => {
                    if let Some(path) = cache_file.as_deref()
                        && let Err(error) = persist_trust_snapshot_cache(path, &envelope)
                    {
                        tracing::warn!(%error, path, "federation trust snapshot persistence failed");
                    }
                    tracing::info!(generation = ?trust_snapshot_cache.generation(), "initial federation trust snapshot loaded");
                }
                Err(error) => {
                    tracing::warn!(%error, "initial federation trust snapshot fetch rejected; relay remains fail-closed");
                }
            }
        }
        // The client-facing object-relay QUIC surface is opt-in via its bind address, and never started
        // for a one-shot `--once` init run.
        let once = std::env::args().any(|arg| arg == "--once");
        #[cfg(not(feature = "itest-provider-single-key"))]
        let client_object_quic_enabled =
            ramflux_node_core::environment::var_os(RELAY_CLIENT_QUIC_ADDR_ENV).is_some() && !once;
        #[cfg(not(feature = "itest-provider-single-key"))]
        let mut initial_keyring_envelope: Option<
            ramflux_node_core::ProviderSignedTrustSnapshot,
        > = None;
        // T23-A2b2b: when the object-relay QUIC surface will be served, the federation provider keyring
        // is MANDATORY. A missing/incomplete config or a keyring that fails to load/verify makes the
        // process fail closed (return `Err` → exit) so the relay never serves object requests it cannot
        // authorize while reporting healthy. A `--once` init run or a relay without the client QUIC
        // surface has no object surface to protect and skips the provider.
        #[cfg(not(feature = "itest-provider-single-key"))]
        if client_object_quic_enabled {
            let (endpoint, _keyring_file, _offline_root, issuer_node_id, cache_file, keyring) =
                require_keyring_provider_ready()?;
            let now = now_unix_seconds();
            let tls = mesh_tls_config(&config);
            let peer_ca_pems = vec![std::fs::read_to_string(&config.mesh.ca_cert)?];
            // Restore persisted state (best-effort) into the live-to-be cache, tracking its
            // authoritative envelope for the anti-rollback high-water.
            initial_keyring_envelope = load_keyring_trust(
                &cache_file,
                &mut trust_snapshot_cache,
                &keyring,
                &issuer_node_id,
                now,
            )
            .unwrap_or_else(|error| {
                tracing::debug!(%error, "no usable persisted keyring trust snapshot");
                None
            });
            // Fetch + plan a candidate on top of the restored state; persist BEFORE adopting, so a
            // persistence failure keeps the durable-consistent restored state. A federation outage at
            // startup leaves the cache fail-closed-at-read (empty), not fail-open.
            let fetched = fetch_keyring_envelope(&endpoint, &tls, &peer_ca_pems).ok();
            if let Some((candidate, candidate_envelope)) = plan_keyring_candidate(
                &trust_snapshot_cache,
                &keyring,
                fetched,
                initial_keyring_envelope.as_ref(),
                &issuer_node_id,
                now,
            ) {
                match persist_keyring_trust(&cache_file, &candidate, candidate_envelope.as_ref()) {
                    Ok(()) => {
                        trust_snapshot_cache = candidate;
                        initial_keyring_envelope = candidate_envelope;
                        tracing::info!(generation = ?trust_snapshot_cache.generation(), "initial keyring trust snapshot loaded");
                    }
                    Err(error) => {
                        tracing::warn!(%error, "initial keyring trust persistence failed; keeping restored state fail-closed");
                    }
                }
            }
        }
        let trust_snapshot_cache = Arc::new(Mutex::new(trust_snapshot_cache));
        #[cfg(feature = "itest-provider-single-key")]
        if !once
            && let Some((endpoint, provider_public_key, issuer_node_id)) =
                relay_trust_provider_config()
        {
            start_trust_snapshot_refresh(
                Arc::clone(&trust_snapshot_cache),
                config.clone(),
                issuer_node_id,
                endpoint,
                provider_public_key,
                relay_trust_snapshot_cache_file(),
                trust_snapshot_refresh_interval(),
            );
        }
        #[cfg(not(feature = "itest-provider-single-key"))]
        if client_object_quic_enabled
            && let Some((endpoint, keyring_file, offline_root, issuer_node_id, cache_file)) =
                relay_keyring_provider_config()
        {
            start_keyring_trust_refresh(
                Arc::clone(&trust_snapshot_cache),
                config.clone(),
                issuer_node_id,
                endpoint,
                keyring_file,
                offline_root,
                cache_file,
                initial_keyring_envelope.take(),
                trust_snapshot_refresh_interval(),
            );
        }
        if ramflux_node_core::environment::var_os(RELAY_CLIENT_QUIC_ADDR_ENV).is_some() && !once {
            serve_relay_client_quic(
                &config,
                Arc::clone(&store),
                Arc::clone(&state),
                Arc::clone(&trust_snapshot_cache),
            )?;
        }
        start_expire_scheduler(Arc::clone(&store), Arc::clone(&state));
        // RELAY-MEM-03-A0b (CTRL-093) DIAGNOSTIC/probe-only: periodically log redb page-cache metrics
        // (used_bytes/evictions/read+write hit+miss) at INFO so the control(1 GiB)-vs-candidate(32 MiB)
        // experiment can observe the cache high-water and eviction behaviour. Absent from the default
        // build (no cache_stats accessor, no thread) — no production control-surface expansion.
        #[cfg(feature = "itest-redb-cache-probe")]
        {
            let probe_redb = Arc::clone(&store);
            let _ = std::thread::Builder::new().name("relay-redb-cache-probe".to_owned()).spawn(
                move || loop {
                    std::thread::sleep(std::time::Duration::from_secs(2));
                    let cache = probe_redb.cache_stats();
                    tracing::info!(
                        used_bytes = cache.used_bytes(),
                        evictions = cache.evictions(),
                        read_hits = cache.read_hits(),
                        read_misses = cache.read_misses(),
                        write_hits = cache.write_hits(),
                        write_misses = cache.write_misses(),
                        "redb cache probe stats"
                    );
                },
            );
        }
        // Legacy v2 shared-HMAC object relay over mesh mTLS: itest-only, no production caller.
        #[cfg(feature = "itest-object-v2")]
        serve_relay_mesh_mtls(
            &config,
            Arc::clone(&store),
            Arc::clone(&state),
            service_key.clone(),
            retention_client.clone(),
        )?;
        #[cfg(feature = "itest-media-udp")]
        serve_media_relay_udp(service_key.clone())?;
        tracing::info!(service, node_id = config.node_id, "relay cache initialized");
        #[cfg(feature = "itest-http")]
        if ramflux_node_core::environment::var("RAMFLUX_ITEST_HTTP").as_deref() == Ok("1") {
            return serve_itest_http(&store, &state, &config);
        }
    }
    tracing::info!(service, "service initialized");
    if std::env::args().any(|arg| arg == "--once") {
        return Ok(());
    }
    // The dhat profiler (itest-alloc-prof) flushes on SIGTERM from its own owner thread, so the main
    // thread parks as normal here regardless of feature.
    std::thread::park();
    Ok(())
}
mod config;
mod voice;

#[cfg(feature = "itest-object-v2")]
mod retention;

mod expiration;

#[cfg(feature = "itest-http")]
mod itest_http;

#[cfg(feature = "itest-object-v2")]
mod legacy_object;

mod client_quic;

#[cfg(feature = "itest-media-udp")]
mod media;

mod quic_service;

#[cfg(not(feature = "itest-provider-single-key"))]
mod trust_keyring;

#[cfg(feature = "itest-provider-single-key")]
mod trust_single_key;

// The graceful-dump seam. dhat writes its `dhat-heap.json` on `Profiler` DROP, but compose teardown
// SIGKILLs after a short grace, so the process must drop the Profiler cleanly ON SIGTERM/SIGINT for the
// profile to flush. The serving relay's main thread blocks forever in an accept loop (the itest-http
// surface / QUIC listener), so it cannot poll a flag — instead a dedicated OWNER thread holds the
// Profiler, polls the flag, and on SIGTERM drops the Profiler (flushing the json to the host bind
// mount) and `process::exit`s. Compiled only under the diagnostic feature.
#[cfg(feature = "itest-alloc-prof")]
mod alloc_prof;

// T24-A3 post-commit QUIC fault seam. Compiled ONLY under `itest-quic-fault`; a default/release
// relay build contains neither this module, the env strings, the capture field names, nor the
// drop/hold branches. The seam fires only AFTER a client object request's business commit has
// succeeded (2xx) and BEFORE the app response is written, keyed by request route, at most once per
// process. It never changes a node-core handler return type and never fires before authorization.
#[cfg(feature = "itest-quic-fault")]
mod itest_quic_fault;

#[cfg(test)]
mod test_support;
