// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use std::io::Write as _;
#[cfg(feature = "itest-http")]
use std::net::{TcpListener, TcpStream};

#[cfg(feature = "itest-object-v2")]
const RETENTION_ASYNC_ENDPOINT_ENV: &str = "RAMFLUX_RETENTION_ASYNC_ENDPOINT";
#[cfg(feature = "itest-object-v2")]
const RETENTION_ASYNC_SERVER_NAME_ENV: &str = "RAMFLUX_RETENTION_ASYNC_SERVER_NAME";
#[cfg(feature = "itest-object-v2")]
const RETENTION_ASYNC_PEER_CA_PEM_ENV: &str = "RAMFLUX_RETENTION_ASYNC_PEER_CA_PEM";
#[cfg(feature = "itest-object-v2")]
const RETENTION_ASYNC_PEER_CA_PEM_FILE_ENV: &str = "RAMFLUX_RETENTION_ASYNC_PEER_CA_PEM_FILE";
#[cfg(feature = "itest-object-v2")]
const DEFAULT_RETENTION_ASYNC_ENDPOINT: &str = "ramflux-retention:17446";
const RELAY_CLIENT_QUIC_ADDR_ENV: &str = "RAMFLUX_RELAY_CLIENT_QUIC_ADDR";
const RELAY_TRUST_SNAPSHOT_CACHE_FILE_ENV: &str = "RAMFLUX_RELAY_TRUST_SNAPSHOT_CACHE_FILE";
const RELAY_TRUST_SNAPSHOT_REFRESH_INTERVAL_ENV: &str =
    "RAMFLUX_RELAY_TRUST_SNAPSHOT_REFRESH_INTERVAL_SECONDS";
fn main() {
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
        if service == "ramflux-relay" && std::env::var_os(RELAY_CLIENT_QUIC_ADDR_ENV).is_some() {
            require_keyring_provider_ready()?;
        }
        println!("{service}:healthy");
        return Ok(());
    }
    tracing_subscriber::fmt().with_target(false).init();
    if let Some(config) =
        ramflux_node_core::load_config_from_args(std::env::args().skip(1), service)?
    {
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
            std::env::var_os(RELAY_CLIENT_QUIC_ADDR_ENV).is_some() && !once;
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
        if std::env::var_os(RELAY_CLIENT_QUIC_ADDR_ENV).is_some() && !once {
            serve_relay_client_quic(
                &config,
                Arc::clone(&store),
                Arc::clone(&state),
                Arc::clone(&trust_snapshot_cache),
            )?;
        }
        start_expire_scheduler(Arc::clone(&store), Arc::clone(&state));
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
        if std::env::var("RAMFLUX_ITEST_HTTP").as_deref() == Ok("1") {
            return serve_itest_http(&store, &state, &config);
        }
    }
    tracing::info!(service, "service initialized");
    if std::env::args().any(|arg| arg == "--once") {
        return Ok(());
    }
    std::thread::park();
    Ok(())
}

#[cfg(feature = "itest-http")]
struct RelayItestIngressState {
    #[cfg_attr(not(feature = "itest-object-v2"), allow(dead_code))]
    store: Arc<ramflux_node_core::RelayRedbStore>,
    #[cfg_attr(not(feature = "itest-object-v2"), allow(dead_code))]
    state: Arc<Mutex<ramflux_node_core::RelayCacheState>>,
    #[cfg_attr(not(feature = "itest-object-v2"), allow(dead_code))]
    config: ramflux_node_core::NodeServiceConfig,
    // Object relay HMAC key + retention client only exist when the legacy v2 object
    // surface is compiled. itest-http alone serves only health, no key/object.
    #[cfg(feature = "itest-object-v2")]
    service_key: Vec<u8>,
    #[cfg(feature = "itest-object-v2")]
    retention_client: RetentionMeshClient,
}

#[cfg(feature = "itest-http")]
fn serve_itest_http(
    store: &Arc<ramflux_node_core::RelayRedbStore>,
    state: &Arc<Mutex<ramflux_node_core::RelayCacheState>>,
    config: &ramflux_node_core::NodeServiceConfig,
) -> anyhow::Result<()> {
    let addr = std::env::var("RAMFLUX_ITEST_RELAY_HTTP_ADDR")
        .unwrap_or_else(|_| "0.0.0.0:18084".to_owned());
    let listener = TcpListener::bind(&addr)?;
    let worker_count = relay_ingress_worker_count();
    let queue_capacity = worker_count.saturating_mul(4).max(1);
    let (sender, receiver) = std::sync::mpsc::sync_channel(queue_capacity);
    let receiver = Arc::new(Mutex::new(receiver));
    let ingress = Arc::new(RelayItestIngressState {
        store: Arc::clone(store),
        state: Arc::clone(state),
        config: config.clone(),
        #[cfg(feature = "itest-object-v2")]
        service_key: relay_service_key(config)?,
        #[cfg(feature = "itest-object-v2")]
        retention_client: retention_mesh_client(config)?,
    });
    for worker_id in 0..worker_count {
        let worker_receiver = Arc::clone(&receiver);
        let worker_ingress = Arc::clone(&ingress);
        thread::Builder::new()
            .name(format!("ramflux-relay-http-ingress-{worker_id}"))
            .spawn(move || relay_ingress_worker_loop(&worker_receiver, &worker_ingress))?;
    }
    tracing::info!(addr, worker_count, queue_capacity, "relay itest HTTP surface listening");
    for stream in listener.incoming() {
        let stream = stream?;
        if let Err(error) = stream.set_nodelay(true) {
            tracing::warn!(%error, "failed to enable TCP_NODELAY on relay ingress connection");
        }
        sender.send(stream)?;
    }
    Ok(())
}

#[cfg(feature = "itest-http")]
fn relay_ingress_worker_count() -> usize {
    std::env::var("RAMFLUX_RELAY_INGRESS_THREADS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or_else(|| {
            std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get)
        })
        .max(1)
}

#[cfg(feature = "itest-http")]
fn relay_ingress_worker_loop(
    receiver: &Arc<Mutex<std::sync::mpsc::Receiver<TcpStream>>>,
    ingress: &Arc<RelayItestIngressState>,
) {
    loop {
        let stream = {
            let Ok(receiver) = receiver.lock() else {
                tracing::error!("relay ingress receiver lock poisoned");
                return;
            };
            receiver.recv()
        };
        let Ok(mut stream) = stream else {
            return;
        };
        if let Err(error) = handle_itest_request(&mut stream, ingress) {
            let body = format!("{error}");
            if let Err(write_error) = ramflux_node_core::write_itest_text_response(
                &mut stream,
                "500 Internal Server Error",
                &body,
            ) {
                tracing::warn!(%write_error, "failed to write relay itest error response");
            }
        }
    }
}

#[cfg(feature = "itest-object-v2")]
fn serve_relay_mesh_mtls(
    config: &ramflux_node_core::NodeServiceConfig,
    store: Arc<ramflux_node_core::RelayRedbStore>,
    state: Arc<Mutex<ramflux_node_core::RelayCacheState>>,
    service_key: Vec<u8>,
    retention_client: RetentionMeshClient,
) -> anyhow::Result<()> {
    let server =
        ramflux_transport::MeshTlsServer::bind(&config.mesh.listen_addr, &mesh_tls_config(config))?;
    let config = config.clone();
    let local_service_id = config.service_id.clone();
    let allowed_service_ids = config.mesh.allowed_service_ids.clone();
    thread::spawn(move || {
        tracing::info!("relay mesh mTLS surface listening");
        loop {
            let accepted = match server.accept_authenticated() {
                Ok(accepted) => accepted,
                Err(error) => {
                    tracing::warn!(%error, "relay mesh mTLS handshake rejected");
                    continue;
                }
            };
            let peer = match ramflux_node_core::authorize_mesh_peer(
                &local_service_id,
                &allowed_service_ids,
                accepted.peer_spiffe_uri.as_deref(),
            ) {
                Ok(peer) => peer,
                Err(error) => {
                    tracing::warn!(%error, "relay mesh peer identity rejected");
                    continue;
                }
            };
            let mut stream = accepted.stream;
            let store = Arc::clone(&store);
            let state = Arc::clone(&state);
            let service_key = service_key.clone();
            let config = config.clone();
            let retention_client = retention_client.clone();
            let peer_service_id = peer.service_id;
            thread::spawn(move || {
                loop {
                    let context = RelayHandlerContext {
                        store: &store,
                        state: &state,
                        config: &config,
                        service_key: service_key.as_slice(),
                        retention_client: &retention_client,
                    };
                    match handle_mesh_request(&mut stream, &context, &peer_service_id) {
                        Ok(true) => {}
                        Ok(false) => break,
                        Err(error) => {
                            let body = format!("{error}");
                            if let Err(write_error) = ramflux_transport::write_mesh_text_response(
                                &mut stream,
                                "500 Internal Server Error",
                                &body,
                            ) {
                                tracing::warn!(%write_error, "failed to write relay mesh error response");
                            }
                            break;
                        }
                    }
                }
                if let Err(error) = ramflux_transport::close_mesh_server_stream(&mut stream) {
                    tracing::debug!(%error, "relay mesh close_notify failed");
                }
            });
        }
    });
    Ok(())
}

#[cfg(feature = "itest-http")]
fn handle_itest_request(
    stream: &mut TcpStream,
    ingress: &RelayItestIngressState,
) -> Result<(), ramflux_node_core::NodeCoreError> {
    let Some(request) = ramflux_node_core::read_itest_http_request(stream)? else {
        return Ok(());
    };
    tracing::info!(
        method = %request.method,
        path = %request.path,
        body_len = request.body.len(),
        "relay itest HTTP request received"
    );
    // Health is served directly, decoupled from the v2 object handler, so the
    // itest-http-only build (no itest-object-v2) has no object surface or key.
    if request.method == "GET" && request.path == "/healthz" {
        return ramflux_node_core::write_itest_json_response(
            stream,
            "200 OK",
            &serde_json::json!({"service": "ramflux-relay", "status": "ok"}),
        );
    }
    #[cfg(feature = "itest-object-v2")]
    {
        let context = RelayHandlerContext {
            store: &ingress.store,
            state: &ingress.state,
            config: &ingress.config,
            service_key: ingress.service_key.as_slice(),
            retention_client: &ingress.retention_client,
        };
        let response = handle_relay_request_value(
            &request.method,
            &request.path,
            &request.body,
            &context,
            RelayRequestPeer::Itest,
        )?;
        capture_itest_relay_json(&request.method, &request.path, &request.body, &response)?;
        write_relay_itest_response(stream, &response)?;
        Ok(())
    }
    #[cfg(not(feature = "itest-object-v2"))]
    {
        let _ = ingress;
        ramflux_node_core::write_itest_text_response(
            stream,
            "404 Not Found",
            "object relay surface not built (requires itest-object-v2)",
        )
    }
}

#[cfg(all(feature = "itest-http", feature = "itest-object-v2"))]
fn capture_itest_relay_json(
    method: &str,
    path: &str,
    body: &[u8],
    response: &RelayResponseValue,
) -> Result<(), ramflux_node_core::NodeCoreError> {
    let Ok(capture_path) = std::env::var("RAMFLUX_RELAY_ITEST_CAPTURE_JSON") else {
        return Ok(());
    };
    if !path.starts_with("/relay/v1/object/") {
        return Ok(());
    }
    let response_value = match response {
        RelayResponseValue::Json { status, value } => {
            serde_json::json!({ "status": status, "body": value })
        }
        RelayResponseValue::Text { status, body } => {
            serde_json::json!({ "status": status, "body": body })
        }
    };
    let record = serde_json::json!({
        "method": method,
        "path": path,
        "request_body_base64url": ramflux_protocol::encode_base64url(body),
        "response": response_value,
    });
    let capture_path = std::path::PathBuf::from(capture_path);
    if let Some(parent) = capture_path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)
            .map_err(|source| ramflux_node_core::NodeCoreError::ItestHttp(source.to_string()))?;
    }
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(capture_path)
        .map_err(|source| ramflux_node_core::NodeCoreError::ItestHttp(source.to_string()))?;
    writeln!(file, "{record}")
        .map_err(|source| ramflux_node_core::NodeCoreError::ItestHttp(source.to_string()))
}

#[cfg(feature = "itest-object-v2")]
fn handle_mesh_request(
    stream: &mut ramflux_transport::MeshTlsServerStream,
    context: &RelayHandlerContext<'_>,
    peer_service_id: &str,
) -> Result<bool, ramflux_node_core::NodeCoreError> {
    let Some(request) = ramflux_transport::read_mesh_http_request(stream)
        .map_err(|source| ramflux_node_core::NodeCoreError::ItestHttp(source.to_string()))?
    else {
        return Ok(false);
    };
    tracing::info!(
        method = %request.method,
        path = %request.path,
        body_len = request.body.len(),
        peer_service_id,
        "relay mesh request received"
    );
    let response = handle_relay_request_value(
        &request.method,
        &request.path,
        &request.body,
        context,
        RelayRequestPeer::Mesh { peer_service_id },
    )?;
    write_relay_mesh_response(stream, &response)?;
    Ok(true)
}

#[cfg(feature = "itest-object-v2")]
#[derive(Clone, Copy)]
enum RelayRequestPeer<'a> {
    #[cfg(feature = "itest-http")]
    Itest,
    Mesh {
        peer_service_id: &'a str,
    },
}

#[cfg(feature = "itest-object-v2")]
enum RelayResponseValue {
    Json { status: &'static str, value: serde_json::Value },
    Text { status: &'static str, body: String },
}

#[cfg(feature = "itest-object-v2")]
struct RelayHandlerContext<'a> {
    store: &'a ramflux_node_core::RelayRedbStore,
    state: &'a Mutex<ramflux_node_core::RelayCacheState>,
    config: &'a ramflux_node_core::NodeServiceConfig,
    service_key: &'a [u8],
    retention_client: &'a RetentionMeshClient,
}

#[cfg(feature = "itest-object-v2")]
fn handle_relay_request_value(
    method: &str,
    path: &str,
    body: &[u8],
    context: &RelayHandlerContext<'_>,
    peer: RelayRequestPeer<'_>,
) -> Result<RelayResponseValue, ramflux_node_core::NodeCoreError> {
    #[cfg(feature = "itest-http")]
    if matches!(peer, RelayRequestPeer::Itest) && method == "GET" && path == "/healthz" {
        return Ok(RelayResponseValue::Json {
            status: "200 OK",
            value: serde_json::json!({"service": "ramflux-relay", "status": "ok"}),
        });
    }
    if let RelayRequestPeer::Mesh { peer_service_id } = peer
        && peer_service_id != "ramflux-router"
    {
        return Ok(RelayResponseValue::Text {
            status: "403 Forbidden",
            body: "object relay endpoints require ramflux-router peer".to_owned(),
        });
    }
    let value = handle_object_relay_request(method, path, body, context)?;
    Ok(RelayResponseValue::Json { status: "200 OK", value })
}

#[cfg(all(feature = "itest-http", feature = "itest-object-v2"))]
fn write_relay_itest_response(
    stream: &mut TcpStream,
    response: &RelayResponseValue,
) -> Result<(), ramflux_node_core::NodeCoreError> {
    match response {
        RelayResponseValue::Json { status, value } => {
            ramflux_node_core::write_itest_json_response(stream, status, value)
        }
        RelayResponseValue::Text { status, body } => {
            ramflux_node_core::write_itest_text_response(stream, status, body)
        }
    }
}

#[cfg(feature = "itest-object-v2")]
fn write_relay_mesh_response(
    stream: &mut ramflux_transport::MeshTlsServerStream,
    response: &RelayResponseValue,
) -> Result<(), ramflux_node_core::NodeCoreError> {
    match response {
        RelayResponseValue::Json { status, value } => {
            ramflux_transport::write_mesh_json_response(stream, status, value)
        }
        RelayResponseValue::Text { status, body } => {
            ramflux_transport::write_mesh_text_response(stream, status, body)
        }
    }
    .map_err(|source| ramflux_node_core::NodeCoreError::ItestHttp(source.to_string()))
}

#[cfg(feature = "itest-object-v2")]
fn handle_object_relay_request(
    method: &str,
    path: &str,
    body: &[u8],
    context: &RelayHandlerContext<'_>,
) -> Result<serde_json::Value, ramflux_node_core::NodeCoreError> {
    match (method, path) {
        ("POST", "/relay/v1/object/put_chunk") => {
            let frame: ramflux_node_core::ObjectChunkFrame =
                serde_json::from_slice(body).map_err(|source| {
                    ramflux_node_core::NodeCoreError::ItestJson(source.to_string())
                })?;
            let now = now_unix_seconds();
            // Persist-before-publish: the ciphertext is committed to redb (post-fsync) before the
            // metadata is published to the resident index.
            let (entry, _inserted) = ramflux_node_core::relay_store_put_frame(
                context.store,
                context.state,
                frame,
                context.service_key,
                now,
            )
            .map_err(ramflux_node_core::RelayStoreOpError::into_node_core)?;
            register_object_relay_ttl(context.config, context.retention_client, &entry, now)?;
            serde_json::to_value(ramflux_node_core::ObjectRelayPutResponse::from(entry))
                .map_err(|source| ramflux_node_core::NodeCoreError::ItestJson(source.to_string()))
        }
        ("POST", "/relay/v1/object/get_chunk") => {
            let request: ramflux_node_core::ObjectRelayGetRequest = serde_json::from_slice(body)
                .map_err(|source| {
                    ramflux_node_core::NodeCoreError::ItestJson(source.to_string())
                })?;
            let now = now_unix_seconds();
            // Validate + snapshot the resident metadata under the lock, then read the ciphertext
            // through redb (lock released) with a TOCTOU recheck.
            let meta = {
                let state = lock_relay_state(context.state)?;
                state.get_object_chunk(
                    &request.chunk_id,
                    &request.relay_token,
                    &request.object_permission_envelope,
                    context.service_key,
                    now,
                )?
            };
            let chunk = ramflux_node_core::relay_store_read_through(
                context.store,
                context.state,
                &meta,
                now,
            )
            .map_err(ramflux_node_core::RelayStoreOpError::into_node_core)?;
            serde_json::to_value(ramflux_node_core::ObjectRelayGetResponse { chunk })
                .map_err(|source| ramflux_node_core::NodeCoreError::ItestJson(source.to_string()))
        }
        ("POST", "/relay/v1/object/ack") => {
            let ack: ramflux_node_core::ObjectRelayAck =
                serde_json::from_slice(body).map_err(|source| {
                    ramflux_node_core::NodeCoreError::ItestJson(source.to_string())
                })?;
            let now = now_unix_seconds();
            // Plan + reserve are atomic under one lock inside `relay_store_ack`; then persist-before-
            // publish (the updated, payload kept/cleared, row is committed first).
            let service_key = context.service_key;
            let meta = ramflux_node_core::relay_store_ack(context.store, context.state, |state| {
                state.plan_ack(&ack, service_key, now).map_err(Into::into)
            })
            .map_err(ramflux_node_core::RelayStoreOpError::into_node_core)?;
            serde_json::to_value(ramflux_node_core::ObjectRelayAckResponse {
                chunk_id: meta.chunk_id,
                status: meta.status,
                acked_by_count: meta.acked_by.len(),
            })
            .map_err(|source| ramflux_node_core::NodeCoreError::ItestJson(source.to_string()))
        }
        ("POST", "/relay/v1/object/tombstone") => {
            let tombstone: ramflux_node_core::ObjectRelayTombstone = serde_json::from_slice(body)
                .map_err(|source| {
                ramflux_node_core::NodeCoreError::ItestJson(source.to_string())
            })?;
            let now = now_unix_seconds();
            // Plan + reserve are atomic under one lock inside `relay_store_tombstone`; then persist-
            // before-publish (commit the batch, then publish the meta + tombstone).
            let service_key = context.service_key;
            let mutation = ramflux_node_core::relay_store_tombstone(
                context.store,
                context.state,
                move |state| {
                    state
                        .plan_object_tombstone_mutation(tombstone, service_key, now)
                        .map_err(Into::into)
                },
            )
            .map_err(ramflux_node_core::RelayStoreOpError::into_node_core)?;
            let retained = mutation.tombstone;
            serde_json::to_value(ramflux_node_core::ObjectRelayTombstoneResponse {
                object_id: retained.object_id,
                tombstone_hash: retained.tombstone_hash,
                expires_at: retained.expires_at,
            })
            .map_err(|source| ramflux_node_core::NodeCoreError::ItestJson(source.to_string()))
        }
        _ => Err(ramflux_node_core::NodeCoreError::ItestHttp(
            "unknown relay object endpoint".to_owned(),
        )),
    }
}

#[cfg(feature = "itest-object-v2")]
fn lock_relay_state(
    state: &Mutex<ramflux_node_core::RelayCacheState>,
) -> Result<
    std::sync::MutexGuard<'_, ramflux_node_core::RelayCacheState>,
    ramflux_node_core::NodeCoreError,
> {
    state.lock().map_err(|source| ramflux_node_core::NodeCoreError::ItestHttp(source.to_string()))
}

#[cfg(feature = "itest-object-v2")]
fn register_object_relay_ttl(
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

fn start_expire_scheduler(
    store: Arc<ramflux_node_core::RelayRedbStore>,
    state: Arc<Mutex<ramflux_node_core::RelayCacheState>>,
) {
    let interval = std::env::var("RAMFLUX_RELAY_GC_SWEEP_INTERVAL_SECONDS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(60)
        .max(60);
    thread::spawn(move || {
        loop {
            if let Err(error) = expire_relay_chunks_once(&store, &state) {
                tracing::warn!(%error, "relay background object chunk expiry failed");
            }
            thread::sleep(Duration::from_secs(interval));
        }
    });
}

fn expire_relay_chunks_once(
    store: &ramflux_node_core::RelayRedbStore,
    state: &Mutex<ramflux_node_core::RelayCacheState>,
) -> Result<(), ramflux_node_core::NodeCoreError> {
    // Persist-before-publish: redb rows are batch-deleted before the resident metadata is removed and
    // its charge released. On persist failure the resident entries stay put but reads reject them by
    // expires_at, so a restart cannot resurrect a servable payload.
    let mutation = ramflux_node_core::relay_store_expire(store, state, now_unix_seconds())
        .map_err(ramflux_node_core::RelayStoreOpError::into_node_core)?;
    tracing::info!(
        expired = mutation.expired_count(),
        "relay background object chunk expiry completed"
    );
    Ok(())
}

#[cfg(feature = "itest-media-udp")]
fn serve_media_relay_udp(service_key: Vec<u8>) -> anyhow::Result<()> {
    let addr = std::env::var("RAMFLUX_ITEST_RELAY_MEDIA_UDP_ADDR")
        .unwrap_or_else(|_| "0.0.0.0:19000".to_owned());
    let state = Arc::new(Mutex::new(ramflux_node_core::SignalingState::new()));
    thread::Builder::new().name("ramflux-relay-media-udp-itest".to_owned()).spawn(move || {
        let runtime =
            match tokio::runtime::Builder::new_current_thread().enable_io().enable_time().build() {
                Ok(runtime) => runtime,
                Err(error) => {
                    tracing::error!(%error, "failed to start media relay UDP runtime");
                    return;
                }
            };
        if let Err(error) = runtime.block_on(run_media_relay_udp(addr, state, service_key)) {
            tracing::error!(%error, "opaque media relay UDP listener stopped");
        }
    })?;
    Ok(())
}

#[cfg(feature = "itest-media-udp")]
async fn run_media_relay_udp(
    addr: String,
    state: Arc<Mutex<ramflux_node_core::SignalingState>>,
    service_key: Vec<u8>,
) -> anyhow::Result<()> {
    let socket = tokio::net::UdpSocket::bind(&addr).await?;
    let relay_address = socket.local_addr()?.to_string();
    tracing::info!(addr, "relay opaque media UDP surface listening");
    let mut buf = vec![0_u8; ramflux_node_core::TURN_MEDIA_RELAY_PACKET_MAX_BYTES];
    let mut sweep = tokio::time::interval(Duration::from_mins(1));
    loop {
        tokio::select! {
            received = socket.recv_from(&mut buf) => {
                let (len, peer) = received?;
                if let Err(error) = handle_media_relay_packet(
                    &socket,
                    &state,
                    service_key.as_slice(),
                    relay_address.as_str(),
                    peer,
                    &buf[..len],
                )
                .await
                {
                    tracing::debug!(%error, %peer, "dropping media relay packet");
                }
            }
            _ = sweep.tick() => {
                let now = now_unix_seconds();
                let expired = {
                    let mut state = state
                        .lock()
                        .map_err(|source| anyhow::anyhow!("media relay state lock failed: {source}"))?;
                    state.expire_turn_media_state(now).len()
                };
                if expired > 0 {
                    tracing::debug!(expired, "media relay expired allocations");
                }
            }
        }
    }
}

#[cfg(feature = "itest-media-udp")]
async fn handle_media_relay_packet(
    socket: &tokio::net::UdpSocket,
    state: &Arc<Mutex<ramflux_node_core::SignalingState>>,
    service_key: &[u8],
    relay_address: &str,
    peer: std::net::SocketAddr,
    packet: &[u8],
) -> anyhow::Result<()> {
    let packet = ramflux_node_core::decode_turn_media_relay_packet(packet)
        .map_err(|source| anyhow::anyhow!("{source}"))?;
    let now = now_unix_seconds();
    let source_ip_hash = format!("media-relay-source-ip:{}", peer.ip());
    let target = {
        let mut state = state
            .lock()
            .map_err(|source| anyhow::anyhow!("media relay state lock failed: {source}"))?;
        state.ensure_turn_media_relay_state(
            &packet.header.token,
            ramflux_node_core::TurnMediaRelayEnsureContext {
                service_key,
                source_ip_hash: &source_ip_hash,
                relay_address,
                now,
                policy: &ramflux_node_core::TurnQuotaPolicy::default(),
            },
        )?;
        let target_allocation_id = state.validate_turn_media_packet(
            &packet.header.token,
            peer,
            packet.payload.len(),
            service_key,
            now,
        )?;
        state.turn_allocation_source(&target_allocation_id).map(str::to_owned)
    };
    let Some(target) = target else {
        tracing::debug!(
            allocation_id = %packet.header.token.allocation_id,
            target_allocation_id = %packet.header.token.target_allocation_id,
            "media relay target allocation has no bound source address yet"
        );
        return Ok(());
    };
    let target: std::net::SocketAddr = target.parse()?;
    let allow_private_targets =
        std::env::var("RAMFLUX_RELAY_ALLOW_PRIVATE_TARGETS").as_deref() == Ok("1");
    if !allow_private_targets && !ramflux_node_core::relay_socket_target_allowed(target, &[]) {
        tracing::warn!(
            %target,
            allocation_id = %packet.header.token.allocation_id,
            "dropping media relay packet to disallowed target address"
        );
        return Ok(());
    }
    socket.send_to(&packet.payload, target).await?;
    Ok(())
}

#[cfg(any(feature = "itest-object-v2", feature = "itest-media-udp"))]
fn relay_service_key(config: &ramflux_node_core::NodeServiceConfig) -> anyhow::Result<Vec<u8>> {
    let Some(secret_ref) = std::env::var("RAMFLUX_RELAY_SERVICE_KEY_REF")
        .ok()
        .or_else(|| config.relay.as_ref().and_then(|relay| relay.service_key_ref.clone()))
    else {
        anyhow::bail!("missing relay service_key_ref")
    };
    read_relay_secret_ref(&secret_ref)
}

#[derive(Clone)]
#[cfg(feature = "itest-object-v2")]
struct RetentionMeshClient {
    blocking: ramflux_transport::MeshHttpClient,
    async_mesh: Option<RetentionAsyncMeshClient>,
}

#[derive(Clone)]
#[cfg(feature = "itest-object-v2")]
struct RetentionAsyncMeshClient {
    endpoint: String,
    server_name: String,
    tls: ramflux_transport::MeshTlsConfig,
    peer_ca_pems: Vec<String>,
}

#[cfg(feature = "itest-object-v2")]
fn retention_mesh_client(
    config: &ramflux_node_core::NodeServiceConfig,
) -> anyhow::Result<RetentionMeshClient> {
    Ok(RetentionMeshClient {
        blocking: ramflux_transport::MeshHttpClient::new(),
        async_mesh: retention_async_mesh_client(config)?,
    })
}

#[cfg(feature = "itest-object-v2")]
fn retention_async_mesh_client(
    config: &ramflux_node_core::NodeServiceConfig,
) -> anyhow::Result<Option<RetentionAsyncMeshClient>> {
    retention_async_mesh_client_from_endpoint_value(
        config,
        std::env::var(RETENTION_ASYNC_ENDPOINT_ENV).ok().as_deref(),
    )
}

#[cfg(feature = "itest-object-v2")]
fn retention_async_mesh_client_from_endpoint_value(
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
fn retention_async_peer_ca_pems(
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
fn endpoint_from_env_value(value: Option<&str>, default: &str) -> Option<String> {
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

fn non_empty_env(name: &str) -> Option<String> {
    std::env::var(name).ok().and_then(|value| {
        let trimmed = value.trim();
        if trimmed.starts_with("${") {
            return None;
        }
        (!trimmed.is_empty()).then(|| trimmed.to_owned())
    })
}

#[cfg(feature = "itest-object-v2")]
fn is_env_disabled(value: &str) -> bool {
    value == "0"
        || value.eq_ignore_ascii_case("false")
        || value.eq_ignore_ascii_case("off")
        || value.eq_ignore_ascii_case("no")
}

// ---- T12-A: client-facing object relay QUIC — config + route skeleton ----
//
// T12-A (augmenting the client-facing QUIC address parsing above): a fail-closed server-auth TLS
// credential check and a pure request-router skeleton over the existing wire types. No QUIC listener
// is spawned and no relay token business logic is wired here — those object routes return `503` so
// the surface cannot masquerade as production-ready. The mesh mTLS surface (router peer) and the
// itest HTTP surface are unchanged.

fn parse_client_quic_addr(value: Option<&str>) -> anyhow::Result<std::net::SocketAddr> {
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

fn relay_client_quic_addr() -> anyhow::Result<std::net::SocketAddr> {
    parse_client_quic_addr(std::env::var(RELAY_CLIENT_QUIC_ADDR_ENV).ok().as_deref())
}

/// Builds the server-auth QUIC config for the client-facing surface, failing closed if the relay
/// lacks valid server-auth TLS credentials. Reuses the gateway server-auth QUIC config builder so
/// the credential requirements are identical; a missing/invalid cert or key surfaces a clear
/// configuration error instead of a silent insecure fallback.
fn validate_relay_client_quic_tls(
    config: &ramflux_node_core::NodeServiceConfig,
) -> anyhow::Result<quinn::ServerConfig> {
    ramflux_transport::quic_gateway_server_config(&mesh_tls_config(config)).map_err(|error| {
        anyhow::anyhow!("relay client QUIC requires server-auth TLS credentials: {error}")
    })
}

/// The explicit v3 ingress envelope carried in an object request body. It carries the caller-supplied
/// token/certificate/authorization/`PoP` material and the request `body_hash`/`capability`, but NOT a
/// trust snapshot: the authoritative snapshot is always taken from the relay's pinned trust cache,
/// never from the request body (a body-supplied snapshot would be trivially forgeable). Unknown JSON
/// members are ignored, so a body that additionally smuggles a `snapshot` has no effect.
#[derive(serde::Deserialize)]
struct RelayClientQuicV3Envelope {
    token: ramflux_node_core::RelayTokenV3,
    certificate: ramflux_node_core::GatewayIssuerCertificate,
    #[serde(default)]
    grant: Option<ramflux_node_core::ObjectAccessGrant>,
    #[serde(default)]
    owner_proof: Option<ramflux_node_core::OwnerAuthorizationProof>,
    pop: ramflux_node_core::RequesterProofOfPossession,
    body_hash: String,
    capability: ramflux_node_core::ObjectRelayCapability,
}

/// The chunk payload carried alongside the v3 invocation on a `put_chunk` request. It is NOT trusted
/// on its own: `chunk_cipher_hash` must be the canonical hash of `encrypted_chunk` for the token's
/// manifest/index, and it must equal the invocation's `body_hash` — which both the owner proof and
/// the requester `PoP` sign — so the ciphertext cannot be substituted under a valid invocation.
#[derive(serde::Deserialize)]
struct RelayClientQuicPutPayload {
    chunk_index: u32,
    chunk_cipher_hash: String,
    encrypted_chunk: Vec<u8>,
    expires_at: u64,
    delete_after_ack: bool,
}

/// The tombstone metadata carried alongside the v3 invocation on a `tombstone` request. Its
/// `tombstone_hash` must equal the invocation's `body_hash` (which the owner proof and `PoP` sign), so
/// the tombstone the owner authorized cannot be swapped for a different one. The object and manifest
/// scope are taken from the verified token, never the payload.
#[derive(serde::Deserialize)]
struct RelayClientQuicTombstonePayload {
    tombstone_hash: String,
    source_event_id: String,
    signed_at: u64,
    expires_at: u64,
}

fn relay_client_quic_response(
    status: u16,
    body: serde_json::Value,
) -> ramflux_transport::GatewayQuicResponse {
    ramflux_transport::GatewayQuicResponse { status, body }
}

/// Verifies a client-facing object request as a fully-authenticated v3 invocation and returns the
/// parsed envelope. Fail-closed at every step and — crucially — performs NO store access, so a caller
/// that fails verification can never reach or mutate the data plane:
/// - A body that does not parse as a [`RelayClientQuicV3Envelope`] (including any v2/HMAC wire shape)
///   is rejected `401`.
/// - The route fixes `expected_capability`; a token for a different capability is rejected `403`, so
///   an Ack-scoped token cannot be replayed against the get route (or vice versa).
/// - The authoritative trust snapshot is read from the pinned `trust_cache` keyed by the token's
///   issuer node id — never from the request body. A missing/stale/mismatched pin is rejected `403`.
/// - The token trust-chain ([`ramflux_node_core::verify_relay_token_v3_with_trust_snapshot`]) and the
///   invocation binding ([`ramflux_node_core::verify_relay_invocation_v3`]) must both pass, else `403`.
fn relay_client_quic_verify_invocation(
    request: &ramflux_transport::GatewayQuicRequest,
    trust_cache: &ramflux_node_core::RelayTrustSnapshotCache,
    expected_node_id: &str,
    expected_capability: ramflux_node_core::ObjectRelayCapability,
    now: u64,
) -> Result<RelayClientQuicV3Envelope, ramflux_transport::GatewayQuicResponse> {
    let malformed =
        |reason: String| relay_client_quic_response(401, serde_json::json!({ "error": reason }));
    let unauthorized =
        |reason: String| relay_client_quic_response(403, serde_json::json!({ "error": reason }));

    let envelope: RelayClientQuicV3Envelope = serde_json::from_value(request.body.clone())
        .map_err(|error| malformed(format!("malformed v3 ingress envelope: {error}")))?;

    // The capability is fixed by the route; a mismatch means the caller is presenting a token scoped
    // to a different operation than this endpoint performs.
    if envelope.capability != expected_capability {
        return Err(unauthorized(format!(
            "capability {:?} does not match this endpoint",
            envelope.capability
        )));
    }

    // Authoritative trust snapshot: pinned cache only, keyed by the token's issuer node id. A
    // body-supplied snapshot (or any extra JSON) is ignored, so it can never anchor trust.
    let snapshot = trust_cache
        .current(&envelope.token.issuer_node_id, now)
        .map_err(|error| unauthorized(format!("no pinned trust snapshot for issuer: {error}")))?;

    ramflux_node_core::verify_relay_token_v3_with_trust_snapshot(
        &envelope.token,
        &envelope.certificate,
        snapshot,
        envelope.capability,
        expected_node_id,
        now,
    )
    .map_err(|error| unauthorized(format!("relay token rejected: {error}")))?;

    let invocation = ramflux_node_core::RelayInvocationV3 {
        token: &envelope.token,
        issuer_public_key: &envelope.certificate.attestation_public_key,
        grant: envelope.grant.as_ref(),
        owner_proof: envelope.owner_proof.as_ref(),
        pop: &envelope.pop,
        expected_audience_node_id: expected_node_id,
        expected_body_hash: &envelope.body_hash,
        capability: envelope.capability,
        now,
    };
    ramflux_node_core::verify_relay_invocation_v3(&invocation)
        .map_err(|error| unauthorized(format!("relay invocation rejected: {error}")))?;

    Ok(envelope)
}

/// Enforces the RQ-03 original-owner binding for a verified v3 Get/Ack: the stored chunk's immutable
/// original-owner identity (bound at put time) and its object/manifest must equal the token's owner
/// and object/manifest. The v3 grant proved the token's owner authorized the requester as grantee;
/// this ties that authorization to the chunk actually in the store, closing the "any self-signed
/// grant reads any chunk" gap. A legacy chunk with no owner binding fails closed.
fn relay_chunk_matches_owner_binding(
    chunk: &ramflux_node_core::RelayChunkMeta,
    token: &ramflux_node_core::RelayTokenV3,
) -> bool {
    chunk.has_owner_binding()
        && chunk.owner_signing_key_id == token.owner_signing_key_id
        && chunk.owner_public_key == token.owner_public_key
        && chunk.object_id == token.object_id
        && chunk.manifest_hash == token.manifest_hash
}

/// Verified Get data plane: after full v3 verification, returns the stored chunk that matches the
/// token's chunk id and original-owner binding. Read-only; the store is touched only after
/// verification passes. `404` when the chunk is not available, `403` on an owner/object binding
/// mismatch, `410` when the object is tombstoned.
fn relay_client_quic_object_get(
    request: &ramflux_transport::GatewayQuicRequest,
    trust_cache: &ramflux_node_core::RelayTrustSnapshotCache,
    store: &Arc<ramflux_node_core::RelayRedbStore>,
    state: &Arc<Mutex<ramflux_node_core::RelayCacheState>>,
    expected_node_id: &str,
    now: u64,
) -> ramflux_transport::GatewayQuicResponse {
    let envelope = match relay_client_quic_verify_invocation(
        request,
        trust_cache,
        expected_node_id,
        ramflux_node_core::ObjectRelayCapability::Get,
        now,
    ) {
        Ok(envelope) => envelope,
        Err(response) => return response,
    };

    // Snapshot the resident metadata under the lock (availability + owner-binding + tombstone), then
    // read the ciphertext through redb with a TOCTOU recheck (never serves a stale/tombstoned payload).
    let expected = {
        let guard = state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(meta) = guard.available_meta(&envelope.token.chunk_id, now) else {
            return relay_client_quic_response(
                404,
                serde_json::json!({ "error": "relay chunk not available" }),
            );
        };
        if !relay_chunk_matches_owner_binding(meta, &envelope.token) {
            return relay_client_quic_response(
                403,
                serde_json::json!({ "error": "relay chunk owner/object binding mismatch" }),
            );
        }
        if guard.tombstone(&meta.object_id).is_some() {
            return relay_client_quic_response(
                410,
                serde_json::json!({ "error": "relay object tombstoned" }),
            );
        }
        meta.clone()
    };
    let chunk = match ramflux_node_core::relay_store_read_through(store, state, &expected, now) {
        Ok(chunk) => chunk,
        Err(error) => {
            let status = error.status_code();
            return relay_client_quic_response(
                status,
                serde_json::json!({ "error": format!("relay get read-through failed: {error}") }),
            );
        }
    };
    let get_response = ramflux_node_core::ObjectRelayGetResponse { chunk };
    match serde_json::to_value(get_response) {
        Ok(body) => relay_client_quic_response(200, body),
        Err(error) => relay_client_quic_response(
            500,
            serde_json::json!({ "error": format!("relay get serialization failed: {error}") }),
        ),
    }
}

/// Verified Ack data plane: after full v3 verification, records the requester (grantee) device in the
/// stored chunk's `acked_by` set and applies the owner's stored delete-on-ack policy, then persists.
/// Idempotent: `acked_by` is a set, the delete policy is the owner's stored policy (never the token's),
/// and an already-consumed chunk is never resurrected. `404` when the chunk is missing, `403` on an
/// owner/object binding mismatch.
// itest-only fault seam: fail exactly the first client-facing v3 ACK per relay process when the
// RAMFLUX_RELAY_ITEST_FAIL_FIRST_V3_ACK env is set, so a test can exercise the SDK's persist-then-ACK
// retry path. It fires before any authorization or store/replay mutation, so a failed ACK never
// touches the chunk entry, and once consumed the same relay process acknowledges normally. This is
// compiled only under `itest-http`; a default/release relay build contains neither the symbol, the
// env string, nor the branch.
#[cfg(feature = "itest-http")]
static RELAY_CLIENT_ACK_FAILED_FIRST: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

#[cfg(feature = "itest-http")]
fn relay_client_quic_ack_fail_once() -> bool {
    relay_client_quic_ack_fail_once_with(
        &RELAY_CLIENT_ACK_FAILED_FIRST,
        std::env::var("RAMFLUX_RELAY_ITEST_FAIL_FIRST_V3_ACK").as_deref() == Ok("1"),
    )
}

#[cfg(feature = "itest-http")]
fn relay_client_quic_ack_fail_once_with(
    failed_first: &std::sync::atomic::AtomicBool,
    enabled: bool,
) -> bool {
    if !enabled {
        return false;
    }
    !failed_first.swap(true, std::sync::atomic::Ordering::SeqCst)
}

fn relay_client_quic_object_ack(
    request: &ramflux_transport::GatewayQuicRequest,
    trust_cache: &ramflux_node_core::RelayTrustSnapshotCache,
    store: &Arc<ramflux_node_core::RelayRedbStore>,
    state: &Arc<Mutex<ramflux_node_core::RelayCacheState>>,
    expected_node_id: &str,
    now: u64,
) -> ramflux_transport::GatewayQuicResponse {
    // Fail closed before any authorization or store/replay mutation on the injected first ACK.
    #[cfg(feature = "itest-http")]
    if relay_client_quic_ack_fail_once() {
        return relay_client_quic_response(
            503,
            serde_json::json!({ "error": "itest fail-first v3 ack seam" }),
        );
    }
    let envelope = match relay_client_quic_verify_invocation(
        request,
        trust_cache,
        expected_node_id,
        ramflux_node_core::ObjectRelayCapability::Ack,
        now,
    ) {
        Ok(envelope) => envelope,
        Err(response) => return response,
    };

    // Plan (owner-binding + acked_by + owner delete policy) + reserve are atomic under one lock inside
    // `relay_store_ack`; then persist-before-publish (payload kept unless the ack consumed the chunk).
    let token = &envelope.token;
    let updated = match ramflux_node_core::relay_store_ack(store, state, |guard| {
        let existing = guard
            .chunk_meta(&token.chunk_id)
            .ok_or(ramflux_node_core::RelayStoreOpError::NotAvailable)?;
        if !relay_chunk_matches_owner_binding(existing, token) {
            return Err(ramflux_node_core::RelayStoreOpError::Unauthorized(
                "relay chunk owner/object binding mismatch".to_owned(),
            ));
        }
        let mut updated = existing.clone();
        updated.acked_by.insert(token.requester_device_hash.clone());
        // Deletion is governed solely by the owner's stored policy, never the token, and a consumed
        // chunk is never brought back to `Available`.
        if updated.delete_after_ack {
            updated.status = ramflux_node_core::RelayChunkStatus::AckedDeleted;
        }
        Ok(updated)
    }) {
        Ok(meta) => meta,
        Err(error) => {
            let status = error.status_code();
            return relay_client_quic_response(
                status,
                serde_json::json!({ "error": format!("relay ack failed: {error}") }),
            );
        }
    };
    let ack_response = ramflux_node_core::ObjectRelayAckResponse {
        chunk_id: updated.chunk_id.clone(),
        status: updated.status,
        acked_by_count: updated.acked_by.len(),
    };
    match serde_json::to_value(ack_response) {
        Ok(body) => relay_client_quic_response(200, body),
        Err(error) => relay_client_quic_response(
            500,
            serde_json::json!({ "error": format!("relay ack serialization failed: {error}") }),
        ),
    }
}

/// Verified owner-session Put data plane: after full v3 verification (owner proof required; requester
/// must be the owner device), stores the carried chunk under the owner's immutable original-owner
/// binding. Mirrors the node-core `put_object_chunk_frame` store invariants:
/// - the carried ciphertext is bound to the signed invocation (its canonical cipher hash must match
///   `chunk_cipher_hash` AND the invocation `body_hash` that the owner proof and `PoP` both sign);
/// - a tombstone on the object blocks the put (`409`);
/// - a chunk id owned by a different original owner (or a legacy unbound record) cannot be overwritten
///   (`403`), and the same owner cannot overwrite different content or resurrect a consumed chunk;
/// - a same-owner, byte-identical replay is idempotent with zero mutation (no write, `200`).
///
/// All authorization and binding checks complete before any store write.
fn relay_client_quic_object_put(
    request: &ramflux_transport::GatewayQuicRequest,
    trust_cache: &ramflux_node_core::RelayTrustSnapshotCache,
    store: &Arc<ramflux_node_core::RelayRedbStore>,
    state: &Arc<Mutex<ramflux_node_core::RelayCacheState>>,
    expected_node_id: &str,
    now: u64,
) -> ramflux_transport::GatewayQuicResponse {
    let envelope = match relay_client_quic_verify_invocation(
        request,
        trust_cache,
        expected_node_id,
        ramflux_node_core::ObjectRelayCapability::Put,
        now,
    ) {
        Ok(envelope) => envelope,
        Err(response) => return response,
    };
    let payload: RelayClientQuicPutPayload = match serde_json::from_value(request.body.clone()) {
        Ok(payload) => payload,
        Err(error) => {
            return relay_client_quic_response(
                401,
                serde_json::json!({ "error": format!("malformed put payload: {error}") }),
            );
        }
    };
    let token = &envelope.token;

    // Bind the ciphertext to the signed invocation: the cipher hash must be the canonical hash of the
    // ciphertext for this manifest/index, and must equal the `body_hash` the owner proof and PoP both
    // sign — so a valid invocation cannot be reused to store a different payload.
    let expected_cipher_hash = ramflux_node_core::object_relay_chunk_cipher_hash(
        &token.manifest_hash,
        payload.chunk_index,
        &payload.encrypted_chunk,
    );
    if payload.chunk_cipher_hash != expected_cipher_hash {
        return relay_client_quic_response(
            403,
            serde_json::json!({ "error": "relay put chunk cipher hash mismatch" }),
        );
    }
    if envelope.body_hash != payload.chunk_cipher_hash {
        return relay_client_quic_response(
            403,
            serde_json::json!({ "error": "relay put payload not bound to the signed body hash" }),
        );
    }

    // The chunk's own expiry must be a bounded future value within the token's window.
    let capped_expires_at =
        ramflux_node_core::clamp_relay_chunk_expires_at(now, payload.expires_at);
    if payload.expires_at <= now || capped_expires_at > token.expires_at {
        return relay_client_quic_response(
            403,
            serde_json::json!({ "error": "relay put chunk ttl invalid" }),
        );
    }

    // Build the candidate entry from the verified token + payload, then apply the persist-before-
    // publish store orchestration (ciphertext committed to redb before the meta is published).
    let candidate = ramflux_node_core::RelayChunkEntry {
        chunk_id: token.chunk_id.clone(),
        object_id: token.object_id.clone(),
        manifest_hash: token.manifest_hash.clone(),
        chunk_index: payload.chunk_index,
        chunk_cipher_hash: payload.chunk_cipher_hash.clone(),
        owner_signing_key_id: token.owner_signing_key_id.clone(),
        owner_public_key: token.owner_public_key.clone(),
        encrypted_chunk: payload.encrypted_chunk.clone(),
        stored_at: now,
        expires_at: capped_expires_at,
        delete_after_ack: payload.delete_after_ack,
        acked_by: std::collections::BTreeSet::new(),
        status: ramflux_node_core::RelayChunkStatus::Available,
    };
    let (stored, _inserted) =
        match ramflux_node_core::relay_store_put_candidate(store, state, candidate, now) {
            Ok(outcome) => outcome,
            Err(error) => {
                let status = error.status_code();
                return relay_client_quic_response(
                    status,
                    serde_json::json!({ "error": format!("relay put failed: {error}") }),
                );
            }
        };
    let put_response = ramflux_node_core::ObjectRelayPutResponse {
        chunk_id: stored.chunk_id.clone(),
        object_id: stored.object_id.clone(),
        manifest_hash: stored.manifest_hash.clone(),
        expires_at: stored.expires_at,
        status: stored.status,
    };
    match serde_json::to_value(put_response) {
        Ok(body) => relay_client_quic_response(200, body),
        Err(error) => relay_client_quic_response(
            500,
            serde_json::json!({ "error": format!("relay put serialization failed: {error}") }),
        ),
    }
}

/// Verified owner-session Tombstone data plane: after full v3 verification (owner proof required;
/// requester must be the owner device), records an object/manifest tombstone via the node-core
/// owner-session core. The tombstone the owner authorized is bound to the signed invocation
/// (`tombstone_hash` must equal `body_hash`), the object/manifest scope is taken from the verified
/// token, and the node-core core preserves the fail-closed empty-scope, cross-owner, replay
/// zero-mutation, and tombstone-wins semantics. All checks complete before any store write.
fn relay_client_quic_object_tombstone(
    request: &ramflux_transport::GatewayQuicRequest,
    trust_cache: &ramflux_node_core::RelayTrustSnapshotCache,
    store: &Arc<ramflux_node_core::RelayRedbStore>,
    state: &Arc<Mutex<ramflux_node_core::RelayCacheState>>,
    expected_node_id: &str,
    now: u64,
) -> ramflux_transport::GatewayQuicResponse {
    let envelope = match relay_client_quic_verify_invocation(
        request,
        trust_cache,
        expected_node_id,
        ramflux_node_core::ObjectRelayCapability::Tombstone,
        now,
    ) {
        Ok(envelope) => envelope,
        Err(response) => return response,
    };
    let payload: RelayClientQuicTombstonePayload =
        match serde_json::from_value(request.body.clone()) {
            Ok(payload) => payload,
            Err(error) => {
                return relay_client_quic_response(
                    401,
                    serde_json::json!({ "error": format!("malformed tombstone payload: {error}") }),
                );
            }
        };
    let token = &envelope.token;

    // Bind the tombstone to the signed invocation: its `tombstone_hash` is the `body_hash` the owner
    // proof and PoP sign, so a valid invocation cannot be reused to record a different tombstone.
    if envelope.body_hash != payload.tombstone_hash {
        return relay_client_quic_response(
            403,
            serde_json::json!({ "error": "relay tombstone not bound to the signed body hash" }),
        );
    }

    // Object and manifest scope come from the verified token, never the payload.
    let tombstone_request = ramflux_node_core::OwnerSessionTombstoneRequest {
        object_id: token.object_id.clone(),
        manifest_hash: Some(token.manifest_hash.clone()),
        tombstone_hash: payload.tombstone_hash,
        source_event_id: payload.source_event_id,
        signed_at: payload.signed_at,
        expires_at: payload.expires_at,
        owner_signing_key_id: token.owner_signing_key_id.clone(),
        owner_public_key: token.owner_public_key.clone(),
    };

    // Plan + reserve are atomic under one lock inside `relay_store_tombstone` (so no concurrent PUT
    // can slip an uncovered chunk past the tombstone); then persist-before-publish.
    let mutation = match ramflux_node_core::relay_store_tombstone(store, state, move |guard| {
        guard.plan_owner_session_tombstone(tombstone_request, now).map_err(Into::into)
    }) {
        Ok(mutation) => mutation,
        Err(error) => {
            let status = error.status_code();
            return relay_client_quic_response(
                status,
                serde_json::json!({ "error": format!("relay tombstone failed: {error}") }),
            );
        }
    };
    let tombstone_response = ramflux_node_core::ObjectRelayTombstoneResponse {
        object_id: mutation.tombstone.object_id.clone(),
        tombstone_hash: mutation.tombstone.tombstone_hash.clone(),
        expires_at: mutation.tombstone.expires_at,
    };
    match serde_json::to_value(tombstone_response) {
        Ok(body) => relay_client_quic_response(200, body),
        Err(error) => relay_client_quic_response(
            500,
            serde_json::json!({ "error": format!("relay tombstone serialization failed: {error}") }),
        ),
    }
}

/// Request router for the client-facing object surface. Serves the health probe, routes every verified
/// object operation (Get/Ack/Put/Tombstone) to the store-backed data plane, and returns `404` for
/// unknown routes.
fn relay_client_quic_route(
    request: &ramflux_transport::GatewayQuicRequest,
    trust_cache: &ramflux_node_core::RelayTrustSnapshotCache,
    store: &Arc<ramflux_node_core::RelayRedbStore>,
    state: &Arc<Mutex<ramflux_node_core::RelayCacheState>>,
    expected_node_id: &str,
    now: u64,
) -> ramflux_transport::GatewayQuicResponse {
    match (request.method.as_str(), request.path.as_str()) {
        ("GET", "/healthz") => relay_client_quic_response(
            200,
            serde_json::json!({ "service": "ramflux-relay", "status": "ok" }),
        ),
        ("POST", "/relay/v1/object/get_chunk") => {
            relay_client_quic_object_get(request, trust_cache, store, state, expected_node_id, now)
        }
        ("POST", "/relay/v1/object/ack") => {
            relay_client_quic_object_ack(request, trust_cache, store, state, expected_node_id, now)
        }
        ("POST", "/relay/v1/object/put_chunk") => {
            relay_client_quic_object_put(request, trust_cache, store, state, expected_node_id, now)
        }
        ("POST", "/relay/v1/object/tombstone") => relay_client_quic_object_tombstone(
            request,
            trust_cache,
            store,
            state,
            expected_node_id,
            now,
        ),
        _ => relay_client_quic_response(
            404,
            serde_json::json!({ "error": "unknown relay client endpoint" }),
        ),
    }
}

/// Ingress metrics for the client-facing object relay QUIC surface, shared (via `Arc`) across all
/// connections handled by one listener.
#[derive(Clone, Default)]
struct RelayClientQuicMetrics {
    ingress_total: Arc<AtomicU64>,
    object_rejected_total: Arc<AtomicU64>,
}

impl RelayClientQuicMetrics {
    fn record_ingress(&self) -> u64 {
        self.ingress_total.fetch_add(1, Ordering::Relaxed) + 1
    }

    fn record_object_rejected(&self) -> u64 {
        self.object_rejected_total.fetch_add(1, Ordering::Relaxed) + 1
    }

    #[cfg(test)]
    fn ingress_total(&self) -> u64 {
        self.ingress_total.load(Ordering::Relaxed)
    }

    #[cfg(test)]
    fn object_rejected_total(&self) -> u64 {
        self.object_rejected_total.load(Ordering::Relaxed)
    }
}

/// Per-listener request context for the client-facing object relay QUIC surface. Carries the ingress
/// metrics, the pinned trust snapshot cache consulted by the v3 ingress gate, and the store/state the
/// verified Get/Ack data plane reads and mutates.
#[derive(Clone)]
struct RelayClientQuicContext {
    metrics: RelayClientQuicMetrics,
    /// Pinned federation trust snapshot loaded at startup and shared across all connections. The v3
    /// gate reads the authoritative snapshot from here (never from a request body). Held behind a
    /// mutex so a future refresh can atomically replace it while requests read it.
    trust_snapshot_cache: Arc<Mutex<ramflux_node_core::RelayTrustSnapshotCache>>,
    node_id: Arc<str>,
    store: Arc<ramflux_node_core::RelayRedbStore>,
    state: Arc<Mutex<ramflux_node_core::RelayCacheState>>,
    #[allow(dead_code)]
    config: Arc<ramflux_node_core::NodeServiceConfig>,
}

/// Routes a request while recording ingress/rejection metrics and logging the fail-closed reason for
/// rejected object requests. The v3 gate rejects a malformed/non-v3 request `401` and an
/// unauthenticated/unauthorized one `403` (both counted as object rejections); verified Get/Ack reach
/// the data plane and Put/Tombstone return `501`. Health is `200`; unknown routes are `404`.
#[allow(clippy::too_many_arguments)]
fn relay_client_quic_dispatch(
    request: &ramflux_transport::GatewayQuicRequest,
    metrics: &RelayClientQuicMetrics,
    trust_cache: &ramflux_node_core::RelayTrustSnapshotCache,
    store: &Arc<ramflux_node_core::RelayRedbStore>,
    state: &Arc<Mutex<ramflux_node_core::RelayCacheState>>,
    expected_node_id: &str,
    now: u64,
) -> ramflux_transport::GatewayQuicResponse {
    let ingress_total = metrics.record_ingress();
    let response =
        relay_client_quic_route(request, trust_cache, store, state, expected_node_id, now);
    if response.status == 401 || response.status == 403 {
        let object_rejected_total = metrics.record_object_rejected();
        tracing::info!(
            method = %request.method,
            path = %request.path,
            status = response.status,
            ingress_total,
            object_rejected_total,
            "relay client QUIC object ingress rejected: not an admissible v3 invocation"
        );
    } else {
        tracing::debug!(
            method = %request.method,
            path = %request.path,
            status = response.status,
            ingress_total,
            "relay client QUIC ingress served"
        );
    }
    response
}

/// Spawns the client-facing object relay QUIC listener on a dedicated tokio runtime thread. Fails
/// closed synchronously if the bind address or server-auth TLS credentials are missing/invalid.
fn serve_relay_client_quic(
    config: &ramflux_node_core::NodeServiceConfig,
    store: Arc<ramflux_node_core::RelayRedbStore>,
    state: Arc<Mutex<ramflux_node_core::RelayCacheState>>,
    trust_snapshot_cache: Arc<Mutex<ramflux_node_core::RelayTrustSnapshotCache>>,
) -> anyhow::Result<()> {
    let addr = relay_client_quic_addr()?;
    let server_config = validate_relay_client_quic_tls(config)?;
    let context = RelayClientQuicContext {
        metrics: RelayClientQuicMetrics::default(),
        trust_snapshot_cache,
        node_id: Arc::from(config.node_id.as_str()),
        store,
        state,
        config: Arc::new(config.clone()),
    };
    thread::Builder::new().name("ramflux-relay-client-quic".to_owned()).spawn(move || {
        let runtime = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
            Ok(runtime) => runtime,
            Err(error) => {
                tracing::error!(%error, "failed to start relay client QUIC runtime");
                return;
            }
        };
        if let Err(error) = runtime.block_on(run_relay_client_quic(addr, server_config, context)) {
            tracing::error!(%error, "relay client QUIC listener stopped");
        }
    })?;
    Ok(())
}

// T24-A3 post-commit QUIC fault seam. Compiled ONLY under `itest-quic-fault`; a default/release
// relay build contains neither this module, the env strings, the capture field names, nor the
// drop/hold branches. The seam fires only AFTER a client object request's business commit has
// succeeded (2xx) and BEFORE the app response is written, keyed by request route, at most once per
// process. It never changes a node-core handler return type and never fires before authorization.
#[cfg(feature = "itest-quic-fault")]
mod itest_quic_fault {
    use std::io::Write as _;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

    const DROP_AFTER_COMMIT_ENV: &str = "RAMFLUX_RELAY_ITEST_DROP_AFTER_COMMIT";
    const CAPTURE_FILE_ENV: &str = "RAMFLUX_RELAY_ITEST_CAPTURE_FILE";
    const HOLD_MARKER_ENV: &str = "RAMFLUX_RELAY_ITEST_HOLD_MARKER";
    const BODY_FINGERPRINT_DOMAIN: &str = "ramflux.itest.quic_fault.body.v1";

    // Fail exactly once per relay process, claimed atomically so concurrent streams cannot both
    // inject. A non-matching request never consumes the claim.
    static FAULT_CLAIMED: AtomicBool = AtomicBool::new(false);
    static REQUEST_SEQ: AtomicU64 = AtomicU64::new(0);
    // A per-process-START identity for the capture. The relay is PID 1 inside its container and
    // keeps PID 1 across a restart, so `std::process::id()` cannot distinguish a pre-restart from a
    // post-restart process — this nanosecond process-start stamp does (a between-attempt restart is
    // seconds apart). Captured once per process; used to prove a between-attempt retry lands on a
    // genuinely different relay process.
    static PROCESS_INSTANCE: std::sync::OnceLock<u64> = std::sync::OnceLock::new();

    fn process_instance() -> u64 {
        *PROCESS_INSTANCE.get_or_init(|| {
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(
                0,
                |elapsed| {
                    elapsed
                        .as_secs()
                        .wrapping_mul(1_000_000_000)
                        .wrapping_add(u64::from(elapsed.subsec_nanos()))
                },
            )
        })
    }

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Mode {
        Off,
        Put,
        Ack,
        Tombstone,
        PutRestartHold,
    }

    fn mode() -> Mode {
        match std::env::var(DROP_AFTER_COMMIT_ENV).ok().as_deref() {
            Some("put") => Mode::Put,
            Some("ack") => Mode::Ack,
            Some("tombstone") => Mode::Tombstone,
            Some("put-restart-hold") => Mode::PutRestartHold,
            _ => Mode::Off,
        }
    }

    fn path_matches(route: &str, mode: Mode) -> bool {
        match mode {
            Mode::Put | Mode::PutRestartHold => route.ends_with("/put_chunk"),
            Mode::Ack => route.ends_with("/ack"),
            Mode::Tombstone => route.ends_with("/tombstone"),
            Mode::Off => false,
        }
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(super) enum Decision {
        Write,
        Drop,
        Hold,
    }

    fn action_label(decision: Decision) -> &'static str {
        match decision {
            Decision::Write => "write",
            Decision::Drop => "drop",
            Decision::Hold => "hold",
        }
    }

    /// Pure post-commit decision: fires only on a matching route with a 2xx commit and an
    /// unclaimed once-slot; a 4xx/5xx status, a non-matching route, `Mode::Off`, or an
    /// already-claimed slot all yield `Write`.
    fn plan(mode: Mode, route: &str, response_status: u16, already_claimed: bool) -> Decision {
        let commit_succeeded = (200..300).contains(&response_status);
        let matches = commit_succeeded && path_matches(route, mode);
        if matches && !already_claimed {
            match mode {
                Mode::PutRestartHold => Decision::Hold,
                _ => Decision::Drop,
            }
        } else {
            Decision::Write
        }
    }

    /// The hold marker file also serves as the **cross-process one-shot claim** for
    /// `put-restart-hold`: the first process holds and writes it; after a between-attempt restart
    /// the new process (same mode, its in-process claim reset) finds the marker already present and
    /// returns `Write` for the retry, so it never holds twice.
    fn hold_marker_exists() -> bool {
        std::env::var_os(HOLD_MARKER_ENV).is_some_and(|path| std::path::Path::new(&path).exists())
    }

    /// Two-layer one-shot claim for `put-restart-hold`. The persistent marker guards the
    /// cross-process / post-restart claim; the in-process atomic guards concurrent connections
    /// within a single process (the relay `tokio::spawn`s one task per QUIC connection, so two
    /// matching connections could otherwise both read a not-yet-written marker and both Hold).
    /// **Short-circuit order matters**: after a restart the marker is present, so the new process
    /// returns claimed WITHOUT consuming its fresh atomic; on the first process the marker is
    /// absent, so exactly one concurrent caller wins the atomic swap (returns `false` = unclaimed
    /// → Hold) and every other caller sees `true` → Write.
    fn hold_claim_already_taken(marker_exists: bool, claimed: &AtomicBool) -> bool {
        marker_exists || claimed.swap(true, Ordering::SeqCst)
    }

    /// Computes the post-commit decision, sourcing the one-shot claim per mode: `put-restart-hold`
    /// combines the persistent hold marker (survives a relay restart) with the in-process atomic
    /// (thread-safe fail-once across concurrent connections); the drop modes use the in-process
    /// atomic alone. `plan` itself stays pure.
    fn decide(mode: Mode, route: &str, response_status: u16) -> Decision {
        let will_match = (200..300).contains(&response_status) && path_matches(route, mode);
        let already_claimed = if will_match {
            match mode {
                Mode::PutRestartHold => {
                    hold_claim_already_taken(hold_marker_exists(), &FAULT_CLAIMED)
                }
                _ => FAULT_CLAIMED.swap(true, Ordering::SeqCst),
            }
        } else {
            true
        };
        plan(mode, route, response_status, already_claimed)
    }

    /// Decides the post-commit action for a just-dispatched request and appends a non-sensitive
    /// capture record. Called for every client QUIC request (under the feature) so the capture also
    /// witnesses normal `write` actions for connection-reuse proofs. Returns `Err` (fail-closed) when
    /// a requested capture record cannot be written — the caller then fails the connection so a lost
    /// capture never masquerades as an empty log.
    pub(super) fn decide_and_capture(
        request: &ramflux_transport::GatewayQuicRequest,
        response_status: u16,
        connection_id: u64,
    ) -> Result<Decision, ()> {
        let request_seq = REQUEST_SEQ.fetch_add(1, Ordering::SeqCst) + 1;
        let decision = decide(mode(), &request.path, response_status);
        capture(request, response_status, connection_id, request_seq, action_label(decision))?;
        Ok(decision)
    }

    /// Builds the non-sensitive capture record. NEVER records raw token/grant/PoP/nonce/seed/cert or
    /// a filesystem path — only the route, method, a blake3 fingerprint of the canonical body bytes
    /// (stable across attempts regardless of JSON key ordering), the connection id, request seq, the
    /// process id (so a between-attempt retry on a restarted relay is distinguishable — connection
    /// ids and request seqs reset per process), action and business status.
    fn capture_line(
        request: &ramflux_transport::GatewayQuicRequest,
        response_status: u16,
        connection_id: u64,
        request_seq: u64,
        action: &str,
    ) -> serde_json::Value {
        let body_fingerprint = ramflux_protocol::canonical_json_bytes(&request.body).map_or_else(
            |_| "canonicalization-failed".to_owned(),
            |bytes| ramflux_protocol::hash_base64url(BODY_FINGERPRINT_DOMAIN, &bytes),
        );
        serde_json::json!({
            "request_seq": request_seq,
            "connection_id": connection_id,
            "process_instance": process_instance(),
            "method": request.method,
            "route": request.path,
            "body_fingerprint": body_fingerprint,
            "action": action,
            "status": response_status,
        })
    }

    /// Appends the capture record. `Ok(())` when no capture file is configured (capture not
    /// requested) or the record is written; `Err(())` when a configured capture file cannot be
    /// opened or written — the caller fails the connection fail-closed.
    fn capture(
        request: &ramflux_transport::GatewayQuicRequest,
        response_status: u16,
        connection_id: u64,
        request_seq: u64,
        action: &str,
    ) -> Result<(), ()> {
        let Some(path) = std::env::var_os(CAPTURE_FILE_ENV) else {
            return Ok(());
        };
        let line = capture_line(request, response_status, connection_id, request_seq, action);
        capture_to(std::path::Path::new(&path), &line)
    }

    // Serializes the process-wide capture writer. Multiple client-QUIC connections run on independent
    // tasks/threads; each `capture_to` call must land as ONE indivisible appended line. Formatting to
    // a stream (`writeln!`) could split into several `write` calls that interleave under concurrency
    // and corrupt/lose lines (observed: a whole daemon's connection dropping from the log under K-way
    // fan-out). This lock + a pre-serialized single-`write_all` guarantees atomic, race-free append.
    static CAPTURE_WRITE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn capture_to(path: &std::path::Path, line: &serde_json::Value) -> Result<(), ()> {
        // Serialize the ENTIRE line (JSON + newline) into one owned buffer BEFORE taking the lock or
        // touching the file, so the guarded critical section is a single atomic append.
        let mut buffer = serde_json::to_vec(line).map_err(|_error| ())?;
        buffer.push(b'\n');
        let _guard = CAPTURE_WRITE_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|_error| ())?;
        // One write_all of the fully-formed line; still fail-closed on any I/O error.
        file.write_all(&buffer).map_err(|_error| ())
    }

    /// Writes the between-attempt restart barrier marker (also the cross-process hold claim, see
    /// [`hold_marker_exists`]). `Err(())` when the marker env is unset or the file cannot be written,
    /// so the caller fails the connection rather than parking without a recorded barrier.
    pub(super) fn write_hold_marker() -> Result<(), ()> {
        let path = std::env::var_os(HOLD_MARKER_ENV).ok_or(())?;
        write_marker_to(std::path::Path::new(&path))
    }

    fn write_marker_to(path: &std::path::Path) -> Result<(), ()> {
        let mut file = std::fs::File::create(path).map_err(|_error| ())?;
        file.write_all(b"held-after-commit\n").map_err(|_error| ())
    }

    #[cfg(test)]
    mod tests {
        use super::{
            Decision, Mode, capture_line, capture_to, hold_claim_already_taken, path_matches, plan,
            write_marker_to,
        };
        use std::sync::atomic::{AtomicBool, Ordering};

        fn request(route: &str) -> ramflux_transport::GatewayQuicRequest {
            ramflux_transport::GatewayQuicRequest {
                method: "POST".to_owned(),
                path: route.to_owned(),
                body: serde_json::json!({
                    "token": { "nonce": "sdk-pop-1700000000-0" },
                    "chunk": "opaque",
                }),
            }
        }

        #[test]
        fn plan_injects_once_per_matching_route_only_on_2xx() {
            // Matching route + 2xx + unclaimed -> drop; claimed -> write (fail-once).
            assert_eq!(plan(Mode::Put, "/relay/v1/object/put_chunk", 200, false), Decision::Drop);
            assert_eq!(plan(Mode::Put, "/relay/v1/object/put_chunk", 200, true), Decision::Write);
            assert_eq!(plan(Mode::Ack, "/relay/v1/object/ack", 200, false), Decision::Drop);
            assert_eq!(
                plan(Mode::Tombstone, "/relay/v1/object/tombstone", 200, false),
                Decision::Drop
            );
            assert_eq!(
                plan(Mode::PutRestartHold, "/relay/v1/object/put_chunk", 200, false),
                Decision::Hold
            );
            // Cross-process one-shot: after a between-attempt restart the hold marker exists, so the
            // same put-restart-hold mode returns Write (the retry lands), never a second Hold.
            assert_eq!(
                plan(Mode::PutRestartHold, "/relay/v1/object/put_chunk", 200, true),
                Decision::Write
            );
        }

        #[test]
        fn hold_claim_is_thread_safe_one_shot_under_concurrency() {
            use std::sync::atomic::AtomicUsize;
            use std::sync::{Arc, Barrier};

            const THREADS: usize = 16;

            // Deterministic contention: every thread parks on the barrier and then races the claim.
            fn count_hold_winners(marker_exists: bool) -> (usize, bool) {
                let claimed = Arc::new(AtomicBool::new(false));
                let winners = Arc::new(AtomicUsize::new(0));
                let barrier = Arc::new(Barrier::new(THREADS));
                let handles: Vec<_> = (0..THREADS)
                    .map(|_| {
                        let claimed = Arc::clone(&claimed);
                        let winners = Arc::clone(&winners);
                        let barrier = Arc::clone(&barrier);
                        std::thread::spawn(move || {
                            barrier.wait();
                            // `already_taken == false` means this caller wins the one-shot and Holds.
                            if !hold_claim_already_taken(marker_exists, &claimed) {
                                winners.fetch_add(1, Ordering::SeqCst);
                            }
                        })
                    })
                    .collect();
                for handle in handles {
                    assert!(handle.join().is_ok(), "claim thread must not panic");
                }
                (winners.load(Ordering::SeqCst), claimed.load(Ordering::SeqCst))
            }

            // First process (marker absent): exactly one concurrent Hold winner, the atomic is set.
            let (winners, consumed) = count_hold_winners(false);
            assert_eq!(winners, 1, "marker absent -> exactly one concurrent Hold winner");
            assert!(consumed, "the winning caller must leave the in-process atomic claimed");

            // Post-restart (marker present): zero Hold winners and the fresh atomic is never
            // consumed (short-circuit), so every retry across every concurrent connection Writes.
            let (winners, consumed) = count_hold_winners(true);
            assert_eq!(winners, 0, "marker present -> zero Hold winners (all retries Write)");
            assert!(!consumed, "marker present short-circuits -> new-process atomic untouched");
        }

        #[test]
        fn plan_never_injects_on_non_matching_route_or_off_mode() {
            assert_eq!(plan(Mode::Put, "/relay/v1/object/ack", 200, false), Decision::Write);
            assert_eq!(plan(Mode::Ack, "/relay/v1/object/put_chunk", 200, false), Decision::Write);
            assert_eq!(plan(Mode::Off, "/relay/v1/object/put_chunk", 200, false), Decision::Write);
        }

        #[test]
        fn plan_never_injects_on_4xx_or_5xx_dispatch() {
            for status in [400_u16, 401, 403, 404, 409, 500, 503] {
                assert_eq!(
                    plan(Mode::Put, "/relay/v1/object/put_chunk", status, false),
                    Decision::Write,
                    "status {status} must never induce a post-commit fault"
                );
            }
        }

        #[test]
        fn path_matches_is_route_specific() {
            assert!(path_matches("/relay/v1/object/put_chunk", Mode::Put));
            assert!(path_matches("/relay/v1/object/put_chunk", Mode::PutRestartHold));
            assert!(path_matches("/relay/v1/object/ack", Mode::Ack));
            assert!(path_matches("/relay/v1/object/tombstone", Mode::Tombstone));
            assert!(!path_matches("/relay/v1/object/get_chunk", Mode::Put));
            assert!(!path_matches("/relay/v1/object/put_chunk", Mode::Ack));
        }

        #[test]
        fn capture_line_carries_no_sensitive_raw_fields() -> Result<(), String> {
            let line = capture_line(&request("/relay/v1/object/put_chunk"), 200, 7, 3, "drop");
            let Some(object) = line.as_object() else {
                return Err("capture line must be a JSON object".to_owned());
            };
            let mut keys: Vec<&str> = object.keys().map(String::as_str).collect();
            keys.sort_unstable();
            assert_eq!(
                keys,
                vec![
                    "action",
                    "body_fingerprint",
                    "connection_id",
                    "method",
                    "process_instance",
                    "request_seq",
                    "route",
                    "status",
                ],
                "capture must expose only the fixed non-sensitive fields"
            );
            // The whole record must not leak any raw secret material even though the request body
            // carried a token/nonce: only a fingerprint of the canonical body is recorded.
            let rendered = line.to_string();
            for forbidden in ["sdk-pop", "token", "nonce", "grant", "seed", "cert"] {
                assert!(
                    !rendered.contains(forbidden),
                    "capture record leaked sensitive substring {forbidden:?}: {rendered}"
                );
            }
            Ok(())
        }

        #[test]
        fn capture_write_is_fail_closed_on_unwritable_path() -> Result<(), String> {
            let line = capture_line(&request("/relay/v1/object/put_chunk"), 200, 7, 3, "write");
            // A writable path succeeds; an unwritable (missing parent dir) path is Err, so the
            // connection loop fails the connection instead of proceeding on a lost capture.
            let ok_path = std::env::temp_dir()
                .join(format!("ramflux-s62-capture-ok-{}.jsonl", std::process::id()));
            capture_to(&ok_path, &line).map_err(|()| "writable capture path must succeed")?;
            let _ = std::fs::remove_file(&ok_path);
            let bad_path =
                std::path::Path::new("/nonexistent-ramflux-itest-dir/capture.jsonl").to_path_buf();
            assert!(
                capture_to(&bad_path, &line).is_err(),
                "an unwritable capture path must fail closed"
            );
            Ok(())
        }

        #[test]
        fn capture_writes_are_atomic_under_concurrency() -> Result<(), String> {
            // CTRL-074: 16 concurrent writers x 100 lines each must produce exactly 1600 lines, every
            // one independently parseable, with unique request_seq (no interleaved/lost line). Proves
            // the pre-serialize + single-writer-lock + one write_all append is atomic under K-way
            // fan-out (the failure mode that dropped a whole daemon's connection from the log).
            use std::collections::BTreeSet;
            use std::sync::{Arc, Barrier};
            const THREADS: usize = 16;
            const LINES_PER_THREAD: usize = 100;

            let path = std::env::temp_dir()
                .join(format!("ramflux-capture-concurrency-{}.jsonl", std::process::id()));
            let _ = std::fs::remove_file(&path);
            let barrier = Arc::new(Barrier::new(THREADS));
            let handles: Vec<_> = (0..THREADS)
                .map(|thread_index| {
                    let barrier = Arc::clone(&barrier);
                    let path = path.clone();
                    std::thread::spawn(move || -> Result<(), ()> {
                        barrier.wait();
                        for i in 0..LINES_PER_THREAD {
                            let seq = (thread_index * LINES_PER_THREAD + i) as u64;
                            let line = capture_line(
                                &request("/relay/v1/object/put_chunk"),
                                200,
                                thread_index as u64,
                                seq,
                                "write",
                            );
                            capture_to(&path, &line)?;
                        }
                        Ok(())
                    })
                })
                .collect();
            for handle in handles {
                handle
                    .join()
                    .map_err(|_error| "capture writer thread panicked".to_owned())?
                    .map_err(|()| "capture_to failed under concurrency".to_owned())?;
            }
            let contents = std::fs::read_to_string(&path).map_err(|error| error.to_string())?;
            let _ = std::fs::remove_file(&path);
            let mut seqs: BTreeSet<u64> = BTreeSet::new();
            let mut line_count = 0usize;
            for raw in contents.lines() {
                line_count += 1;
                let value: serde_json::Value = serde_json::from_str(raw)
                    .map_err(|error| format!("unparseable capture line {raw:?}: {error}"))?;
                let seq = value
                    .get("request_seq")
                    .and_then(serde_json::Value::as_u64)
                    .ok_or_else(|| format!("capture line missing request_seq: {raw}"))?;
                if !seqs.insert(seq) {
                    return Err(format!(
                        "duplicate request_seq {seq} — interleaved/corrupted write"
                    ));
                }
            }
            assert_eq!(
                line_count,
                THREADS * LINES_PER_THREAD,
                "all 1600 concurrent lines must be present and independently parseable"
            );
            assert_eq!(
                seqs.len(),
                THREADS * LINES_PER_THREAD,
                "every request_seq must survive uniquely (no lost or merged line)"
            );
            Ok(())
        }

        #[test]
        fn hold_marker_write_is_fail_closed_on_unwritable_path() -> Result<(), String> {
            let ok_path = std::env::temp_dir()
                .join(format!("ramflux-s62-hold-ok-{}.marker", std::process::id()));
            write_marker_to(&ok_path).map_err(|()| "writable marker path must succeed")?;
            assert!(ok_path.exists(), "hold marker must be created");
            let _ = std::fs::remove_file(&ok_path);
            let bad_path =
                std::path::Path::new("/nonexistent-ramflux-itest-dir/hold.marker").to_path_buf();
            assert!(
                write_marker_to(&bad_path).is_err(),
                "an unwritable hold-marker path must fail closed"
            );
            Ok(())
        }
    }
}

async fn run_relay_client_quic(
    addr: std::net::SocketAddr,
    server_config: quinn::ServerConfig,
    context: RelayClientQuicContext,
) -> anyhow::Result<()> {
    let endpoint = quinn::Endpoint::server(server_config, addr)?;
    tracing::info!(addr = %endpoint.local_addr()?, "relay client-facing QUIC surface listening");
    while let Some(connecting) = endpoint.accept().await {
        let context = context.clone();
        tokio::spawn(async move {
            match connecting.await {
                Ok(connection) => handle_relay_client_quic_connection(connection, context).await,
                Err(error) => tracing::warn!(%error, "relay client QUIC handshake rejected"),
            }
        });
    }
    Ok(())
}

async fn handle_relay_client_quic_connection(
    connection: quinn::Connection,
    context: RelayClientQuicContext,
) {
    loop {
        match connection.accept_bi().await {
            Ok((mut send, mut recv)) => {
                let request: ramflux_transport::GatewayQuicRequest =
                    match ramflux_transport::read_quic_json_frame(&mut recv).await {
                        Ok(request) => request,
                        Err(error) => {
                            tracing::debug!(%error, "relay client QUIC request read failed");
                            continue;
                        }
                    };
                // Ingress gate only: metrics + fail-closed routing. Object requests run through the
                // v3 verifier gate (non-v3 -> 401, unauthorized -> 403, verified -> 501); the pinned
                // trust snapshot is the authority and no data plane is wired yet.
                let response = {
                    let trust_cache = context
                        .trust_snapshot_cache
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    relay_client_quic_dispatch(
                        &request,
                        &context.metrics,
                        &trust_cache,
                        &context.store,
                        &context.state,
                        &context.node_id,
                        now_unix_seconds(),
                    )
                };
                // T24-A3 (itest-quic-fault only): after the business commit above and before the
                // response is written, optionally drop/hold the connection to exercise the SDK's
                // ambiguous-commit retry. Absent entirely in the default/release build.
                #[cfg(feature = "itest-quic-fault")]
                match itest_quic_fault::decide_and_capture(
                    &request,
                    response.status,
                    connection.stable_id() as u64,
                ) {
                    Ok(itest_quic_fault::Decision::Write) => {}
                    Ok(itest_quic_fault::Decision::Drop) => {
                        connection.close(
                            quinn::VarInt::from_u32(0),
                            b"itest-quic-fault: drop after commit",
                        );
                        return;
                    }
                    Ok(itest_quic_fault::Decision::Hold) => {
                        if itest_quic_fault::write_hold_marker().is_err() {
                            // Fail closed: cannot record the restart barrier.
                            connection.close(
                                quinn::VarInt::from_u32(0),
                                b"itest-quic-fault: hold marker write failed",
                            );
                            return;
                        }
                        // Park until the relay process is restarted by the test; the held
                        // connection dies with the process (no partial response is ever written).
                        std::future::pending::<()>().await;
                        return;
                    }
                    Err(()) => {
                        // Fail closed: a requested capture record could not be written, so the test
                        // must not proceed on an empty log.
                        connection.close(
                            quinn::VarInt::from_u32(0),
                            b"itest-quic-fault: capture write failed",
                        );
                        return;
                    }
                }
                if let Err(error) =
                    ramflux_transport::write_quic_json_frame(&mut send, &response).await
                {
                    tracing::debug!(%error, "relay client QUIC response write failed");
                    continue;
                }
                let _ = send.finish();
            }
            Err(
                quinn::ConnectionError::ApplicationClosed(_)
                | quinn::ConnectionError::LocallyClosed,
            ) => return,
            Err(error) => {
                tracing::debug!(%error, "relay client QUIC connection closed");
                return;
            }
        }
    }
}

#[cfg(any(feature = "itest-object-v2", feature = "itest-media-udp"))]
fn read_relay_secret_ref(secret_ref: &str) -> anyhow::Result<Vec<u8>> {
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

fn mesh_tls_config(
    config: &ramflux_node_core::NodeServiceConfig,
) -> ramflux_transport::MeshTlsConfig {
    ramflux_transport::MeshTlsConfig {
        ca_cert: config.mesh.ca_cert.clone().into(),
        service_cert: config.mesh.service_cert.clone().into(),
        service_key: config.mesh.service_key.clone().into(),
    }
}

fn now_unix_seconds() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |duration| duration.as_secs())
}

// ---- T13-D: relay -> federation signed trust snapshot fetch client (no object handler wired) ----

const RELAY_FEDERATION_TRUST_ENDPOINT_ENV: &str = "RAMFLUX_FEDERATION_TRUST_ENDPOINT";
#[cfg(feature = "itest-provider-single-key")]
const RELAY_FEDERATION_PROVIDER_PUBLIC_KEY_ENV: &str = "RAMFLUX_FEDERATION_PROVIDER_PUBLIC_KEY";
const RELAY_FEDERATION_TRUST_ISSUER_NODE_ID_ENV: &str = "RAMFLUX_FEDERATION_TRUST_ISSUER_NODE_ID";
const RELAY_FEDERATION_TRUST_SERVER_NAME: &str = "ramflux-federation";
const RELAY_FEDERATION_TRUST_SNAPSHOT_PATH: &str = "/mvp9/federation/trust-snapshot";

/// Resolves the trust-snapshot provider config from the given endpoint and pinned provider public
/// key values. The provider is only enabled when BOTH are present and non-empty; a missing value
/// means "do not start the provider" (returns `None`), never a default.
#[cfg(feature = "itest-provider-single-key")]
fn relay_trust_provider_config_from_values(
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
fn relay_trust_provider_config() -> Option<(String, String, String)> {
    relay_trust_provider_config_from_values(
        non_empty_env(RELAY_FEDERATION_TRUST_ENDPOINT_ENV).as_deref(),
        non_empty_env(RELAY_FEDERATION_PROVIDER_PUBLIC_KEY_ENV).as_deref(),
        non_empty_env(RELAY_FEDERATION_TRUST_ISSUER_NODE_ID_ENV).as_deref(),
    )
}

#[cfg(feature = "itest-provider-single-key")]
fn relay_trust_snapshot_cache_file() -> Option<String> {
    non_empty_env(RELAY_TRUST_SNAPSHOT_CACHE_FILE_ENV)
}

fn trust_snapshot_refresh_interval() -> Duration {
    non_empty_env(RELAY_TRUST_SNAPSHOT_REFRESH_INTERVAL_ENV)
        .and_then(|value| value.parse::<u64>().ok())
        .map_or_else(|| Duration::from_secs(30), |seconds| Duration::from_secs(seconds.max(5)))
}

#[cfg(feature = "itest-provider-single-key")]
fn load_trust_snapshot_cache(
    path: &str,
) -> anyhow::Result<ramflux_node_core::SignedFederatedIssuerTrustSnapshot> {
    let bytes = std::fs::read(path)?;
    Ok(serde_json::from_slice(&bytes)?)
}

#[cfg(feature = "itest-provider-single-key")]
fn persist_trust_snapshot_cache(
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
fn start_trust_snapshot_refresh(
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
fn fetch_signed_trust_snapshot(
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
fn fetch_trust_snapshot_envelope(
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
fn apply_fetched_trust_snapshot(
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

// ---- T23-A2b2a: opt-in provider keyring trust path (offline-root-signed keyring + provider_epoch) ----

#[cfg(not(feature = "itest-provider-single-key"))]
const RELAY_FEDERATION_PROVIDER_KEYRING_FILE_ENV: &str = "RAMFLUX_FEDERATION_PROVIDER_KEYRING_FILE";
#[cfg(not(feature = "itest-provider-single-key"))]
const RELAY_FEDERATION_PROVIDER_OFFLINE_ROOT_PUBLIC_KEY_ENV: &str =
    "RAMFLUX_FEDERATION_PROVIDER_OFFLINE_ROOT_PUBLIC_KEY";

/// Keyring-era trust config: endpoint + keyring file + pinned offline-root public key + issuer node +
/// persisted-cache file, ALL required (a missing value disables the provider; never a default). The
/// cache file is required because the strong-security keyring path relies on a persisted, fsync'd
/// anti-rollback high-water — without it there is no restart anti-rollback, so the provider stays off
/// (fail-closed) rather than authorizing without persistence.
#[cfg(not(feature = "itest-provider-single-key"))]
fn relay_keyring_provider_config() -> Option<(String, String, String, String, String)> {
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
fn relay_keyring_provider_config_from_values(
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
fn load_provider_keyring(
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
fn require_keyring_provider_ready() -> anyhow::Result<(
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
fn require_keyring_provider_ready_from(
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
struct PersistedKeyringTrust {
    envelope: Option<ramflux_node_core::ProviderSignedTrustSnapshot>,
    provider_epoch_high_water: u64,
    keyring_epoch_high_water: u64,
    keyring_fingerprint: Option<String>,
    accepted_signer_key_id: Option<String>,
}

/// Atomically persists the cache's authoritative state (tmp + fsync + rename). Callers persist a
/// candidate BEFORE publishing it live, so a persistence failure never leaves a live cache ahead of
/// the durable anti-rollback high-water.
#[cfg(not(feature = "itest-provider-single-key"))]
fn persist_keyring_trust(
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
fn load_keyring_trust(
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
fn fetch_keyring_envelope(
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
fn plan_keyring_candidate(
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
fn publish_keyring_candidate(
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
fn start_keyring_trust_refresh(
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

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::path::{Path, PathBuf};
    use std::process::Command;
    #[cfg(feature = "itest-object-v2")]
    use std::sync::mpsc;

    #[cfg(feature = "itest-http")]
    #[test]
    fn relay_client_quic_ack_fail_once_fails_exactly_once_when_enabled() {
        use std::sync::atomic::AtomicBool;
        // Disabled (env unset): the seam never fails, so normal itest ACKs are unaffected.
        let flag = AtomicBool::new(false);
        assert!(!super::relay_client_quic_ack_fail_once_with(&flag, false));
        assert!(!super::relay_client_quic_ack_fail_once_with(&flag, false));
        // Enabled: the first ACK fails and the once-token is consumed; every subsequent ACK on the
        // same relay process succeeds, so a retry recovers.
        let flag = AtomicBool::new(false);
        assert!(super::relay_client_quic_ack_fail_once_with(&flag, true));
        assert!(!super::relay_client_quic_ack_fail_once_with(&flag, true));
        assert!(!super::relay_client_quic_ack_fail_once_with(&flag, true));
    }

    use ramflux_node_core::ObjectRelayCapability::{Ack, Get, Put, Tombstone};

    use super::*;

    #[test]
    fn relay_client_quic_addr_requires_valid_explicit_config() {
        assert!(parse_client_quic_addr(None).is_err());
    }

    #[test]
    fn relay_client_quic_addr_rejects_empty_and_invalid_values() {
        assert!(parse_client_quic_addr(Some(" ")).is_err());
        assert!(parse_client_quic_addr(Some("not-an-address")).is_err());
    }

    #[test]
    fn relay_client_quic_addr_accepts_socket_address() -> anyhow::Result<()> {
        let address = parse_client_quic_addr(Some("127.0.0.1:0"))?;
        assert_eq!(address.port(), 0);
        Ok(())
    }

    #[cfg(feature = "itest-provider-single-key")]
    #[test]
    fn trust_snapshot_cache_persistence_round_trips_atomically() -> anyhow::Result<()> {
        let root = std::env::temp_dir().join(format!(
            "ramflux-relay-trust-cache-{}-{}",
            std::process::id(),
            now_unix_seconds()
        ));
        let path = root.join("trust-snapshot.json");
        let envelope = ramflux_node_core::SignedFederatedIssuerTrustSnapshot {
            schema: ramflux_node_core::FEDERATED_ISSUER_TRUST_SNAPSHOT_ENVELOPE_SCHEMA.to_owned(),
            version: ramflux_node_core::OBJECT_RELAY_V3_PROOF_VERSION,
            snapshot: ramflux_node_core::FederatedIssuerTrustSnapshot {
                schema: ramflux_node_core::FEDERATED_ISSUER_TRUST_SNAPSHOT_SCHEMA.to_owned(),
                version: ramflux_node_core::OBJECT_RELAY_V3_PROOF_VERSION,
                node_id: "node-b".to_owned(),
                generation: 7,
                pin_epoch: 2,
                trust_status: ramflux_node_core::FederatedIssuerTrustStatus::Active,
                roots: Vec::new(),
                revoked_cert_ids: BTreeSet::new(),
                hard_stale_at: 2_000_000,
            },
            provider_signing_key_id: "provider-1".to_owned(),
            provider_public_key: "provider-public-key".to_owned(),
            issued_at: 1_000_000,
            expires_at: 1_000_300,
            signature: "signature".to_owned(),
        };
        let path_string = path.to_string_lossy();
        persist_trust_snapshot_cache(&path_string, &envelope)?;
        let loaded = load_trust_snapshot_cache(&path_string)?;
        assert_eq!(loaded, envelope);
        assert!(!path.with_extension(format!("tmp.{}", std::process::id())).exists());
        std::fs::remove_dir_all(root)?;
        Ok(())
    }

    fn client_quic_request(method: &str, path: &str) -> ramflux_transport::GatewayQuicRequest {
        ramflux_transport::GatewayQuicRequest {
            method: method.to_owned(),
            path: path.to_owned(),
            body: serde_json::Value::Null,
        }
    }

    // ---- T14-B v3 ingress gate fixtures (valid Get invocation, built via public node-core API) ----

    const V3_NOW: u64 = 1_000_000;
    const V3_OWNER_SEED: [u8; 32] = [0x11; 32];
    const V3_REQUESTER_SEED: [u8; 32] = [0x22; 32];
    const V3_ISSUER_SEED: [u8; 32] = [0x33; 32];
    const V3_ROOT_SEED: [u8; 32] = [0x44; 32];
    const V3_ISSUER_NODE: &str = "node-b";
    const V3_AUDIENCE_NODE: &str = "node-a";
    const V3_ROOT_KEY_ID: &str = "node-b#root";
    const V3_OWNER_ID: &str = "device_a_owner";
    const V3_REQUESTER_ID: &str = "device_b_requester";
    const V3_OBJECT: &str = "object_v3";
    const V3_MANIFEST: &str = "manifest_v3";
    const V3_CHUNK: &str = "chunk_v3";
    const V3_BODY_HASH: &str = "body_hash_v3";

    fn v3_pk(seed: [u8; 32]) -> String {
        ramflux_crypto::public_key_base64url_from_seed(seed)
    }

    fn v3_sign(bytes: &[u8], seed: [u8; 32]) -> String {
        ramflux_crypto::sign_canonical_bytes_with_seed(bytes, seed)
    }

    fn v3_requester_hash() -> String {
        ramflux_crypto::blake3_256_base64url(
            "ramflux.object_relay.recipient_device.v1",
            V3_REQUESTER_ID.as_bytes(),
        )
    }

    fn v3_certificate() -> Result<ramflux_node_core::GatewayIssuerCertificate, String> {
        let mut cert = ramflux_node_core::GatewayIssuerCertificate {
            schema: ramflux_node_core::GATEWAY_ISSUER_CERTIFICATE_SCHEMA.to_owned(),
            version: ramflux_node_core::OBJECT_RELAY_V3_PROOF_VERSION,
            cert_id: "cert-b-1".to_owned(),
            node_id: V3_ISSUER_NODE.to_owned(),
            gateway_instance_id: "gw-b-1".to_owned(),
            attestation_public_key: v3_pk(V3_ISSUER_SEED),
            attestation_key_id: "att-b-1".to_owned(),
            not_before: V3_NOW - 10,
            not_after: V3_NOW + 3_600,
            issued_at: V3_NOW - 10,
            node_root_signing_key_id: V3_ROOT_KEY_ID.to_owned(),
            node_root_signature: String::new(),
            revoked_at: None,
        };
        cert.node_root_signature = v3_sign(
            &ramflux_node_core::gateway_issuer_certificate_signing_bytes(&cert)
                .map_err(|error| error.to_string())?,
            V3_ROOT_SEED,
        );
        Ok(cert)
    }

    fn v3_signed_grant(
        capabilities: Vec<ramflux_node_core::ObjectRelayCapability>,
    ) -> Result<ramflux_node_core::ObjectAccessGrant, String> {
        let mut grant = ramflux_node_core::ObjectAccessGrant {
            schema: ramflux_node_core::OBJECT_ACCESS_GRANT_SCHEMA.to_owned(),
            version: ramflux_node_core::OBJECT_RELAY_V3_PROOF_VERSION,
            object_id: V3_OBJECT.to_owned(),
            manifest_hash: V3_MANIFEST.to_owned(),
            grantee_device_hash: v3_requester_hash(),
            capabilities,
            issued_at: V3_NOW,
            expires_at: V3_NOW + 300,
            owner_signing_key_id: V3_OWNER_ID.to_owned(),
            owner_public_key: v3_pk(V3_OWNER_SEED),
            owner_signature: String::new(),
        };
        grant.owner_signature = v3_sign(
            &ramflux_node_core::object_access_grant_signing_bytes(&grant)
                .map_err(|error| error.to_string())?,
            V3_OWNER_SEED,
        );
        Ok(grant)
    }

    fn v3_token(
        certificate: ramflux_node_core::GatewayIssuerCertificate,
        binding_hash: String,
        capability: ramflux_node_core::ObjectRelayCapability,
    ) -> Result<ramflux_node_core::RelayTokenV3, String> {
        let mut token = ramflux_node_core::RelayTokenV3 {
            token_version: ramflux_node_core::OBJECT_RELAY_TOKEN_V3_VERSION,
            token_id: "tok_v3_grant".to_owned(),
            requester_device_id: V3_REQUESTER_ID.to_owned(),
            requester_device_hash: v3_requester_hash(),
            requester_public_key: v3_pk(V3_REQUESTER_SEED),
            requester_device_epoch: 7,
            owner_signing_key_id: V3_OWNER_ID.to_owned(),
            owner_public_key: v3_pk(V3_OWNER_SEED),
            owner_home_node_id: V3_AUDIENCE_NODE.to_owned(),
            owner_principal_id: "principal_a".to_owned(),
            owner_device_epoch: 3,
            issuer_node_id: V3_ISSUER_NODE.to_owned(),
            gateway_instance_id: "gw-b-1".to_owned(),
            issuer_certificate_id: "cert-b-1".to_owned(),
            attestation_key_id: "att-b-1".to_owned(),
            issuer_certificate: certificate,
            audience_service: ramflux_node_core::RELAY_TOKEN_V3_AUDIENCE_RELAY.to_owned(),
            audience_node_id: V3_AUDIENCE_NODE.to_owned(),
            relay_instance_id: None,
            object_id: V3_OBJECT.to_owned(),
            manifest_hash: V3_MANIFEST.to_owned(),
            chunk_id: V3_CHUNK.to_owned(),
            capabilities: vec![capability],
            authorization_kind: ramflux_node_core::RelayAuthorizationKind::OwnerGrant,
            authorization_binding_hash: binding_hash,
            delete_after_ack: false,
            issued_at: V3_NOW,
            expires_at: V3_NOW + 120,
            nonce: "nonce_tok_v3".to_owned(),
            issuer_signature: String::new(),
        };
        token.issuer_signature = v3_sign(
            &ramflux_node_core::relay_token_v3_signing_bytes(&token)
                .map_err(|error| error.to_string())?,
            V3_ISSUER_SEED,
        );
        Ok(token)
    }

    fn v3_signed_pop(
        token: &ramflux_node_core::RelayTokenV3,
        capability: ramflux_node_core::ObjectRelayCapability,
        body_hash: &str,
        signer_seed: [u8; 32],
    ) -> Result<ramflux_node_core::RequesterProofOfPossession, String> {
        let mut pop = ramflux_node_core::RequesterProofOfPossession {
            schema: ramflux_node_core::REQUESTER_POP_SCHEMA.to_owned(),
            version: ramflux_node_core::OBJECT_RELAY_V3_PROOF_VERSION,
            token_id: token.token_id.clone(),
            capability,
            object_id: token.object_id.clone(),
            manifest_hash: token.manifest_hash.clone(),
            chunk_id: token.chunk_id.clone(),
            request_nonce: "req_nonce_v3".to_owned(),
            body_hash: body_hash.to_owned(),
            issued_at: V3_NOW,
            expires_at: V3_NOW + 60,
            signer_device_id: token.requester_device_id.clone(),
            signer_public_key: token.requester_public_key.clone(),
            signature: String::new(),
        };
        pop.signature = v3_sign(
            &ramflux_node_core::requester_pop_signing_bytes(&pop)
                .map_err(|error| error.to_string())?,
            signer_seed,
        );
        Ok(pop)
    }

    fn v3_trust_snapshot() -> ramflux_node_core::FederatedIssuerTrustSnapshot {
        ramflux_node_core::FederatedIssuerTrustSnapshot {
            schema: ramflux_node_core::FEDERATED_ISSUER_TRUST_SNAPSHOT_SCHEMA.to_owned(),
            version: ramflux_node_core::OBJECT_RELAY_V3_PROOF_VERSION,
            node_id: V3_ISSUER_NODE.to_owned(),
            generation: 5,
            pin_epoch: 3,
            trust_status: ramflux_node_core::FederatedIssuerTrustStatus::Active,
            roots: vec![ramflux_node_core::TrustedNodeRootKey {
                node_id: V3_ISSUER_NODE.to_owned(),
                key_id: V3_ROOT_KEY_ID.to_owned(),
                public_key: v3_pk(V3_ROOT_SEED),
                not_before: V3_NOW - 100,
                not_after: V3_NOW + 3_600,
                pin_epoch: 3,
                retired_at: None,
            }],
            revoked_cert_ids: BTreeSet::new(),
            hard_stale_at: V3_NOW + 300,
        }
    }

    /// A cache pinned with the valid trust snapshot for the issuer node.
    fn v3_pinned_cache() -> Result<ramflux_node_core::RelayTrustSnapshotCache, String> {
        let mut cache = ramflux_node_core::RelayTrustSnapshotCache::new();
        cache
            .update(v3_trust_snapshot(), V3_ISSUER_NODE, V3_NOW)
            .map_err(|error| error.to_string())?;
        Ok(cache)
    }

    /// A complete, correctly-signed v3 ingress envelope body for `capability` (grant covers both Get
    /// and Ack so the same fixture serves both). `mutate` can tamper the body before it is serialized
    /// (e.g. to smuggle a bogus `snapshot`).
    fn v3_envelope_body(
        capability: ramflux_node_core::ObjectRelayCapability,
        mutate: impl FnOnce(&mut serde_json::Map<String, serde_json::Value>),
    ) -> Result<serde_json::Value, String> {
        let cert = v3_certificate()?;
        let grant = v3_signed_grant(vec![
            ramflux_node_core::ObjectRelayCapability::Get,
            ramflux_node_core::ObjectRelayCapability::Ack,
        ])?;
        let binding = ramflux_node_core::object_access_grant_binding_hash(&grant)
            .map_err(|error| error.to_string())?;
        let token = v3_token(cert.clone(), binding, capability)?;
        let pop = v3_signed_pop(&token, capability, V3_BODY_HASH, V3_REQUESTER_SEED)?;
        let mut body = serde_json::Map::new();
        body.insert(
            "token".to_owned(),
            serde_json::to_value(&token).map_err(|error| error.to_string())?,
        );
        body.insert(
            "certificate".to_owned(),
            serde_json::to_value(&cert).map_err(|error| error.to_string())?,
        );
        body.insert(
            "grant".to_owned(),
            serde_json::to_value(&grant).map_err(|error| error.to_string())?,
        );
        body.insert(
            "pop".to_owned(),
            serde_json::to_value(&pop).map_err(|error| error.to_string())?,
        );
        body.insert("body_hash".to_owned(), serde_json::Value::String(V3_BODY_HASH.to_owned()));
        body.insert(
            "capability".to_owned(),
            serde_json::to_value(capability).map_err(|error| error.to_string())?,
        );
        mutate(&mut body);
        Ok(serde_json::Value::Object(body))
    }

    fn client_quic_object_request(
        body: serde_json::Value,
    ) -> ramflux_transport::GatewayQuicRequest {
        client_quic_object_request_to("/relay/v1/object/get_chunk", body)
    }

    fn client_quic_object_request_to(
        path: &str,
        body: serde_json::Value,
    ) -> ramflux_transport::GatewayQuicRequest {
        ramflux_transport::GatewayQuicRequest {
            method: "POST".to_owned(),
            path: path.to_owned(),
            body,
        }
    }

    /// A stored chunk whose immutable original-owner binding matches the token owner
    /// (`V3_OWNER_ID` / `V3_OWNER_SEED`) unless `owner_public_key` is overridden.
    fn v3_stored_chunk(
        owner_public_key: String,
        delete_after_ack: bool,
    ) -> ramflux_node_core::RelayChunkEntry {
        ramflux_node_core::RelayChunkEntry {
            chunk_id: V3_CHUNK.to_owned(),
            object_id: V3_OBJECT.to_owned(),
            manifest_hash: V3_MANIFEST.to_owned(),
            chunk_index: 0,
            // Real canonical cipher hash of the stored ciphertext so the GET read-through integrity
            // check (recompute == stored hash) passes.
            chunk_cipher_hash: ramflux_node_core::object_relay_chunk_cipher_hash(
                V3_MANIFEST,
                0,
                b"ciphertext-v3",
            ),
            owner_signing_key_id: V3_OWNER_ID.to_owned(),
            owner_public_key,
            encrypted_chunk: b"ciphertext-v3".to_vec(),
            stored_at: V3_NOW - 10,
            expires_at: V3_NOW + 300,
            delete_after_ack,
            acked_by: BTreeSet::new(),
            status: ramflux_node_core::RelayChunkStatus::Available,
        }
    }

    // Seeds a chunk into BOTH the resident meta index and the redb payload table, keeping the
    // metadata-only-in-memory invariant (ciphertext lives in redb, read through on demand).
    fn v3_state_with(
        store: &ramflux_node_core::RelayRedbStore,
        chunk: ramflux_node_core::RelayChunkEntry,
    ) -> Result<Arc<Mutex<ramflux_node_core::RelayCacheState>>, String> {
        store.record_relay_chunk_entry(&chunk).map_err(|error| error.to_string())?;
        let mut state = ramflux_node_core::RelayCacheState::new();
        state.put_chunk(chunk).map_err(|error| error.to_string())?;
        Ok(Arc::new(Mutex::new(state)))
    }

    /// A fresh on-disk relay store at a process-unique temp path (avoids redb "already open" flakes).
    fn v3_temp_store() -> Result<Arc<ramflux_node_core::RelayRedbStore>, String> {
        static NEXT_STORE_ID: AtomicU64 = AtomicU64::new(0);
        let id = NEXT_STORE_ID.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir()
            .join(format!("ramflux-relay-t14c-{}-{id}.redb", std::process::id()));
        let store =
            ramflux_node_core::RelayRedbStore::open(&path).map_err(|error| error.to_string())?;
        Ok(Arc::new(store))
    }

    fn v3_acked_by_count(state: &Arc<Mutex<ramflux_node_core::RelayCacheState>>) -> usize {
        let guard = state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        guard.chunk_entry(V3_CHUNK).map_or(0, |chunk| chunk.acked_by.len())
    }

    // ---- owner-session (Put) fixtures: the requester is the owner device itself ----

    const V3_PUT_INDEX: u32 = 0;
    // Must be within the token's own expiry window (`V3_NOW + 120`) and a bounded future value.
    const V3_PUT_EXPIRES_AT: u64 = V3_NOW + 100;

    fn v3_put_ciphertext() -> Vec<u8> {
        b"put-ciphertext-v3".to_vec()
    }

    fn v3_put_cipher_hash() -> String {
        ramflux_node_core::object_relay_chunk_cipher_hash(
            V3_MANIFEST,
            V3_PUT_INDEX,
            &v3_put_ciphertext(),
        )
    }

    fn v3_owner_proof(
        capability: ramflux_node_core::ObjectRelayCapability,
        body_hash: &str,
    ) -> Result<ramflux_node_core::OwnerAuthorizationProof, String> {
        let mut proof = ramflux_node_core::OwnerAuthorizationProof {
            schema: ramflux_node_core::OWNER_AUTHORIZATION_PROOF_SCHEMA.to_owned(),
            version: ramflux_node_core::OBJECT_RELAY_V3_PROOF_VERSION,
            capability,
            object_id: V3_OBJECT.to_owned(),
            manifest_hash: Some(V3_MANIFEST.to_owned()),
            chunk_id: Some(V3_CHUNK.to_owned()),
            owner_home_node_id: V3_AUDIENCE_NODE.to_owned(),
            owner_principal_id: "principal_a".to_owned(),
            owner_device_epoch: 3,
            request_nonce: "owner_proof_nonce_v3".to_owned(),
            body_hash: body_hash.to_owned(),
            issued_at: V3_NOW,
            expires_at: V3_NOW + 120,
            owner_signing_key_id: V3_OWNER_ID.to_owned(),
            owner_public_key: v3_pk(V3_OWNER_SEED),
            owner_signature: String::new(),
        };
        proof.owner_signature = v3_sign(
            &ramflux_node_core::owner_authorization_proof_signing_bytes(&proof)
                .map_err(|error| error.to_string())?,
            V3_OWNER_SEED,
        );
        Ok(proof)
    }

    fn v3_owner_session_token(
        certificate: ramflux_node_core::GatewayIssuerCertificate,
        binding_hash: String,
        capability: ramflux_node_core::ObjectRelayCapability,
    ) -> Result<ramflux_node_core::RelayTokenV3, String> {
        // For owner-session operations the requester IS the owner device.
        let mut token = v3_token(certificate, binding_hash, capability)?;
        token.authorization_kind = ramflux_node_core::RelayAuthorizationKind::OwnerSession;
        token.requester_device_id = V3_OWNER_ID.to_owned();
        token.requester_device_hash = ramflux_crypto::blake3_256_base64url(
            "ramflux.object_relay.recipient_device.v1",
            V3_OWNER_ID.as_bytes(),
        );
        token.requester_public_key = v3_pk(V3_OWNER_SEED);
        token.issuer_signature = v3_sign(
            &ramflux_node_core::relay_token_v3_signing_bytes(&token)
                .map_err(|error| error.to_string())?,
            V3_ISSUER_SEED,
        );
        Ok(token)
    }

    /// A complete, correctly-signed owner-session Put request body: the auth envelope (owner proof,
    /// owner-signed `PoP`) plus the chunk payload, with `body_hash` bound to the ciphertext's cipher
    /// hash. `mutate` can tamper the body before it is serialized.
    fn v3_put_request_body(
        mutate: impl FnOnce(&mut serde_json::Map<String, serde_json::Value>),
    ) -> Result<serde_json::Value, String> {
        let cipher_hash = v3_put_cipher_hash();
        let cert = v3_certificate()?;
        let proof = v3_owner_proof(Put, &cipher_hash)?;
        let binding = ramflux_node_core::owner_authorization_proof_binding_hash(&proof)
            .map_err(|error| error.to_string())?;
        let token = v3_owner_session_token(cert.clone(), binding, Put)?;
        let pop = v3_signed_pop(&token, Put, &cipher_hash, V3_OWNER_SEED)?;
        let mut body = serde_json::Map::new();
        body.insert(
            "token".to_owned(),
            serde_json::to_value(&token).map_err(|error| error.to_string())?,
        );
        body.insert(
            "certificate".to_owned(),
            serde_json::to_value(&cert).map_err(|error| error.to_string())?,
        );
        body.insert(
            "owner_proof".to_owned(),
            serde_json::to_value(&proof).map_err(|error| error.to_string())?,
        );
        body.insert(
            "pop".to_owned(),
            serde_json::to_value(&pop).map_err(|error| error.to_string())?,
        );
        body.insert("body_hash".to_owned(), serde_json::Value::String(cipher_hash.clone()));
        body.insert(
            "capability".to_owned(),
            serde_json::to_value(Put).map_err(|error| error.to_string())?,
        );
        // Chunk payload (flat, alongside the auth envelope).
        body.insert("chunk_index".to_owned(), serde_json::Value::Number(V3_PUT_INDEX.into()));
        body.insert("chunk_cipher_hash".to_owned(), serde_json::Value::String(cipher_hash));
        body.insert(
            "encrypted_chunk".to_owned(),
            serde_json::to_value(v3_put_ciphertext()).map_err(|error| error.to_string())?,
        );
        body.insert("expires_at".to_owned(), serde_json::Value::Number(V3_PUT_EXPIRES_AT.into()));
        body.insert("delete_after_ack".to_owned(), serde_json::Value::Bool(false));
        mutate(&mut body);
        Ok(serde_json::Value::Object(body))
    }

    fn v3_chunk_snapshot(
        state: &Arc<Mutex<ramflux_node_core::RelayCacheState>>,
    ) -> Option<ramflux_node_core::RelayChunkMeta> {
        let guard = state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        guard.chunk_entry(V3_CHUNK).cloned()
    }

    // ---- owner-session (Tombstone) fixtures ----

    const V3_TOMBSTONE_HASH: &str = "t14d-relay-tombstone-hash";

    /// A complete, correctly-signed owner-session Tombstone request body: the auth envelope (owner
    /// proof, owner-signed `PoP`) plus the tombstone metadata, with `body_hash` bound to the
    /// `tombstone_hash`. `mutate` can tamper the body before it is serialized.
    fn v3_tombstone_request_body(
        mutate: impl FnOnce(&mut serde_json::Map<String, serde_json::Value>),
    ) -> Result<serde_json::Value, String> {
        let cert = v3_certificate()?;
        let proof = v3_owner_proof(Tombstone, V3_TOMBSTONE_HASH)?;
        let binding = ramflux_node_core::owner_authorization_proof_binding_hash(&proof)
            .map_err(|error| error.to_string())?;
        let token = v3_owner_session_token(cert.clone(), binding, Tombstone)?;
        let pop = v3_signed_pop(&token, Tombstone, V3_TOMBSTONE_HASH, V3_OWNER_SEED)?;
        let mut body = serde_json::Map::new();
        body.insert(
            "token".to_owned(),
            serde_json::to_value(&token).map_err(|error| error.to_string())?,
        );
        body.insert(
            "certificate".to_owned(),
            serde_json::to_value(&cert).map_err(|error| error.to_string())?,
        );
        body.insert(
            "owner_proof".to_owned(),
            serde_json::to_value(&proof).map_err(|error| error.to_string())?,
        );
        body.insert(
            "pop".to_owned(),
            serde_json::to_value(&pop).map_err(|error| error.to_string())?,
        );
        body.insert(
            "body_hash".to_owned(),
            serde_json::Value::String(V3_TOMBSTONE_HASH.to_owned()),
        );
        body.insert(
            "capability".to_owned(),
            serde_json::to_value(Tombstone).map_err(|error| error.to_string())?,
        );
        body.insert(
            "tombstone_hash".to_owned(),
            serde_json::Value::String(V3_TOMBSTONE_HASH.to_owned()),
        );
        body.insert("source_event_id".to_owned(), serde_json::Value::String("t14d-evt".to_owned()));
        body.insert("signed_at".to_owned(), serde_json::Value::Number(V3_NOW.into()));
        body.insert("expires_at".to_owned(), serde_json::Value::Number((V3_NOW + 100).into()));
        mutate(&mut body);
        Ok(serde_json::Value::Object(body))
    }

    fn v3_chunk_status(
        state: &Arc<Mutex<ramflux_node_core::RelayCacheState>>,
    ) -> Option<ramflux_node_core::RelayChunkStatus> {
        v3_chunk_snapshot(state).map(|chunk| chunk.status)
    }

    #[test]
    fn relay_client_quic_get_reads_stored_chunk() -> Result<(), String> {
        let store = v3_temp_store()?;
        let cache = v3_pinned_cache()?;
        let state = v3_state_with(&store, v3_stored_chunk(v3_pk(V3_OWNER_SEED), false))?;
        let response = relay_client_quic_route(
            &client_quic_object_request(v3_envelope_body(Get, |_| {})?),
            &cache,
            &store,
            &state,
            V3_AUDIENCE_NODE,
            V3_NOW,
        );
        assert_eq!(response.status, 200, "a fully verified get returns the stored chunk");
        let parsed: ramflux_node_core::ObjectRelayGetResponse =
            serde_json::from_value(response.body).map_err(|error| error.to_string())?;
        assert_eq!(parsed.chunk.chunk_id, V3_CHUNK);
        assert_eq!(parsed.chunk.encrypted_chunk, b"ciphertext-v3");
        Ok(())
    }

    #[test]
    fn relay_client_quic_get_rejects_v2_missing_snapshot_and_wrong_owner() -> Result<(), String> {
        let store = v3_temp_store()?;
        let cache = v3_pinned_cache()?;
        let matching = v3_state_with(&store, v3_stored_chunk(v3_pk(V3_OWNER_SEED), false))?;

        // A v2/HMAC wire shape never parses as a v3 envelope: 401, and the store is never read.
        let v2 = client_quic_object_request(serde_json::json!({
            "token_version": 2, "token_id": "legacy", "mac": "deadbeef",
        }));
        assert_eq!(
            relay_client_quic_route(&v2, &cache, &store, &matching, V3_AUDIENCE_NODE, V3_NOW)
                .status,
            401,
            "a v2 wire shape must never be admitted"
        );

        // Correctly-signed envelope, but the relay has NO pinned snapshot -> 403 (fail closed).
        let empty_cache = ramflux_node_core::RelayTrustSnapshotCache::new();
        assert_eq!(
            relay_client_quic_route(
                &client_quic_object_request(v3_envelope_body(Get, |_| {})?),
                &empty_cache,
                &store,
                &matching,
                V3_AUDIENCE_NODE,
                V3_NOW,
            )
            .status,
            403,
            "no pinned snapshot must fail closed"
        );

        // A body that smuggles a forged `snapshot` is ignored; with an empty cache it is still 403.
        let forged =
            serde_json::to_value(v3_trust_snapshot()).map_err(|error| error.to_string())?;
        let smuggled = v3_envelope_body(Get, |body| {
            body.insert("snapshot".to_owned(), forged);
        })?;
        assert_eq!(
            relay_client_quic_route(
                &client_quic_object_request(smuggled),
                &empty_cache,
                &store,
                &matching,
                V3_AUDIENCE_NODE,
                V3_NOW,
            )
            .status,
            403,
            "a body-supplied snapshot must never be trusted"
        );

        // Pinned cache + valid envelope, but the stored chunk was uploaded by a DIFFERENT original
        // owner -> 403. This is the RQ-03 original-owner binding.
        let foreign = v3_state_with(&store, v3_stored_chunk(v3_pk(V3_REQUESTER_SEED), false))?;
        assert_eq!(
            relay_client_quic_route(
                &client_quic_object_request(v3_envelope_body(Get, |_| {})?),
                &cache,
                &store,
                &foreign,
                V3_AUDIENCE_NODE,
                V3_NOW,
            )
            .status,
            403,
            "a chunk owned by a different original owner must not be readable"
        );

        // A tampered (unsigned) token is well-formed but fails crypto: 403.
        let tampered = v3_envelope_body(Get, |body| {
            if let Some(token) = body.get_mut("token").and_then(serde_json::Value::as_object_mut) {
                token
                    .insert("object_id".to_owned(), serde_json::Value::String("forged".to_owned()));
            }
        })?;
        assert_eq!(
            relay_client_quic_route(
                &client_quic_object_request(tampered),
                &cache,
                &store,
                &matching,
                V3_AUDIENCE_NODE,
                V3_NOW,
            )
            .status,
            403,
            "a tampered token must fail verification"
        );
        Ok(())
    }

    #[test]
    fn relay_client_quic_invalid_ack_leaves_store_untouched() -> Result<(), String> {
        let store = v3_temp_store()?;
        let cache = v3_pinned_cache()?;
        let state = v3_state_with(&store, v3_stored_chunk(v3_pk(V3_OWNER_SEED), true))?;
        // A tampered ack token fails verification BEFORE any store access, so nothing is mutated.
        let tampered = v3_envelope_body(Ack, |body| {
            if let Some(token) = body.get_mut("token").and_then(serde_json::Value::as_object_mut) {
                token.insert("nonce".to_owned(), serde_json::Value::String("forged".to_owned()));
            }
        })?;
        let response = relay_client_quic_route(
            &client_quic_object_request_to("/relay/v1/object/ack", tampered),
            &cache,
            &store,
            &state,
            V3_AUDIENCE_NODE,
            V3_NOW,
        );
        assert_eq!(response.status, 403, "a tampered ack must fail closed");
        assert_eq!(v3_acked_by_count(&state), 0, "a rejected ack must not mutate the chunk");
        let guard = state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let chunk = guard.chunk_entry(V3_CHUNK).ok_or("chunk missing")?;
        assert_eq!(
            chunk.status,
            ramflux_node_core::RelayChunkStatus::Available,
            "a rejected ack must not consume the chunk"
        );
        Ok(())
    }

    #[test]
    fn relay_client_quic_ack_is_idempotent_and_respects_delete_policy() -> Result<(), String> {
        let cache = v3_pinned_cache()?;
        let ack_request = || -> Result<ramflux_transport::GatewayQuicRequest, String> {
            Ok(client_quic_object_request_to(
                "/relay/v1/object/ack",
                v3_envelope_body(Ack, |_| {})?,
            ))
        };

        // (1) Non-delete chunk: two acks by the same grantee keep `acked_by_count` at 1 and leave the
        // chunk Available.
        let keep_store = v3_temp_store()?;
        let keep = v3_state_with(&keep_store, v3_stored_chunk(v3_pk(V3_OWNER_SEED), false))?;
        let first = relay_client_quic_route(
            &ack_request()?,
            &cache,
            &keep_store,
            &keep,
            V3_AUDIENCE_NODE,
            V3_NOW,
        );
        assert_eq!(first.status, 200);
        let first_body: ramflux_node_core::ObjectRelayAckResponse =
            serde_json::from_value(first.body).map_err(|error| error.to_string())?;
        assert_eq!(first_body.acked_by_count, 1);
        assert_eq!(first_body.status, ramflux_node_core::RelayChunkStatus::Available);
        let second = relay_client_quic_route(
            &ack_request()?,
            &cache,
            &keep_store,
            &keep,
            V3_AUDIENCE_NODE,
            V3_NOW,
        );
        let second_body: ramflux_node_core::ObjectRelayAckResponse =
            serde_json::from_value(second.body).map_err(|error| error.to_string())?;
        assert_eq!(second_body.acked_by_count, 1, "re-ack by the same grantee is idempotent");

        // (2) Delete-on-ack chunk: the first ack consumes it; a second ack does not resurrect it.
        let del_store = v3_temp_store()?;
        let consume = v3_state_with(&del_store, v3_stored_chunk(v3_pk(V3_OWNER_SEED), true))?;
        let consumed = relay_client_quic_route(
            &ack_request()?,
            &cache,
            &del_store,
            &consume,
            V3_AUDIENCE_NODE,
            V3_NOW,
        );
        let consumed_body: ramflux_node_core::ObjectRelayAckResponse =
            serde_json::from_value(consumed.body).map_err(|error| error.to_string())?;
        assert_eq!(consumed_body.status, ramflux_node_core::RelayChunkStatus::AckedDeleted);
        assert_eq!(consumed_body.acked_by_count, 1);
        let replayed = relay_client_quic_route(
            &ack_request()?,
            &cache,
            &del_store,
            &consume,
            V3_AUDIENCE_NODE,
            V3_NOW,
        );
        let replayed_body: ramflux_node_core::ObjectRelayAckResponse =
            serde_json::from_value(replayed.body).map_err(|error| error.to_string())?;
        assert_eq!(
            replayed_body.status,
            ramflux_node_core::RelayChunkStatus::AckedDeleted,
            "a consumed chunk is never resurrected"
        );
        assert_eq!(replayed_body.acked_by_count, 1);
        Ok(())
    }

    #[test]
    fn relay_client_quic_object_routes_reject_mismatch_and_malformed() -> Result<(), String> {
        let store = v3_temp_store()?;
        let cache = v3_pinned_cache()?;
        let state = v3_state_with(&store, v3_stored_chunk(v3_pk(V3_OWNER_SEED), false))?;
        for path in ["/relay/v1/object/put_chunk", "/relay/v1/object/tombstone"] {
            // A Get-capability envelope on a put/tombstone route is a capability mismatch: 403.
            let mismatch = relay_client_quic_route(
                &client_quic_object_request_to(path, v3_envelope_body(Get, |_| {})?),
                &cache,
                &store,
                &state,
                V3_AUDIENCE_NODE,
                V3_NOW,
            );
            assert_eq!(mismatch.status, 403, "{path} must reject a mismatched capability");
            // A malformed body is rejected 401.
            let malformed = relay_client_quic_route(
                &client_quic_object_request_to(path, serde_json::Value::Null),
                &cache,
                &store,
                &state,
                V3_AUDIENCE_NODE,
                V3_NOW,
            );
            assert_eq!(malformed.status, 401, "{path} must reject a malformed body");
        }
        Ok(())
    }

    #[test]
    fn relay_client_quic_put_persists_and_is_readable() -> Result<(), String> {
        let store = v3_temp_store()?;
        let cache = v3_pinned_cache()?;
        let state = Arc::new(Mutex::new(ramflux_node_core::RelayCacheState::new()));
        let response = relay_client_quic_route(
            &client_quic_object_request_to(
                "/relay/v1/object/put_chunk",
                v3_put_request_body(|_| {})?,
            ),
            &cache,
            &store,
            &state,
            V3_AUDIENCE_NODE,
            V3_NOW,
        );
        assert_eq!(response.status, 200, "a valid owner-session put persists the chunk");
        let put_body: ramflux_node_core::ObjectRelayPutResponse =
            serde_json::from_value(response.body).map_err(|error| error.to_string())?;
        assert_eq!(put_body.chunk_id, V3_CHUNK);
        assert_eq!(put_body.status, ramflux_node_core::RelayChunkStatus::Available);

        // The stored chunk carries the owner's immutable binding and the exact ciphertext.
        let stored = v3_chunk_snapshot(&state).ok_or("chunk not stored")?;
        assert_eq!(stored.owner_signing_key_id, V3_OWNER_ID);
        assert_eq!(stored.owner_public_key, v3_pk(V3_OWNER_SEED));
        // The ciphertext is in redb (read through), not resident in the metadata index.
        let payload = store
            .relay_chunk_entry(V3_CHUNK)
            .map_err(|error| error.to_string())?
            .ok_or("payload")?;
        assert_eq!(payload.encrypted_chunk, v3_put_ciphertext());

        // End-to-end: the owner-uploaded chunk is now readable by an authorized grantee via GET.
        let get = relay_client_quic_route(
            &client_quic_object_request(v3_envelope_body(Get, |_| {})?),
            &cache,
            &store,
            &state,
            V3_AUDIENCE_NODE,
            V3_NOW,
        );
        assert_eq!(get.status, 200, "the put chunk is readable by a valid get");
        Ok(())
    }

    #[test]
    fn relay_client_quic_put_rejects_cross_owner_and_content_overwrite() -> Result<(), String> {
        let store = v3_temp_store()?;
        let cache = v3_pinned_cache()?;

        // (1) The chunk id is already owned by a DIFFERENT original owner -> 403, unchanged.
        let foreign = v3_state_with(&store, v3_stored_chunk(v3_pk(V3_REQUESTER_SEED), false))?;
        let cross = relay_client_quic_route(
            &client_quic_object_request_to(
                "/relay/v1/object/put_chunk",
                v3_put_request_body(|_| {})?,
            ),
            &cache,
            &store,
            &foreign,
            V3_AUDIENCE_NODE,
            V3_NOW,
        );
        assert_eq!(cross.status, 403, "cross-owner overwrite must be rejected");
        let after = v3_chunk_snapshot(&foreign).ok_or("foreign chunk gone")?;
        assert_eq!(after.owner_public_key, v3_pk(V3_REQUESTER_SEED));
        let after_payload = store
            .relay_chunk_entry(V3_CHUNK)
            .map_err(|error| error.to_string())?
            .ok_or("payload")?;
        assert_eq!(after_payload.encrypted_chunk, b"ciphertext-v3");

        // (2) Same owner, but the stored content differs from the request -> 403.
        let same_owner = v3_state_with(&store, v3_stored_chunk(v3_pk(V3_OWNER_SEED), false))?;
        let content = relay_client_quic_route(
            &client_quic_object_request_to(
                "/relay/v1/object/put_chunk",
                v3_put_request_body(|_| {})?,
            ),
            &cache,
            &store,
            &same_owner,
            V3_AUDIENCE_NODE,
            V3_NOW,
        );
        assert_eq!(content.status, 403, "same-owner content overwrite must be rejected");
        Ok(())
    }

    #[test]
    fn relay_client_quic_put_same_owner_same_content_replay_is_zero_mutation() -> Result<(), String>
    {
        let store = v3_temp_store()?;
        let cache = v3_pinned_cache()?;
        let state = Arc::new(Mutex::new(ramflux_node_core::RelayCacheState::new()));

        let first = relay_client_quic_route(
            &client_quic_object_request_to(
                "/relay/v1/object/put_chunk",
                v3_put_request_body(|_| {})?,
            ),
            &cache,
            &store,
            &state,
            V3_AUDIENCE_NODE,
            V3_NOW,
        );
        assert_eq!(first.status, 200);
        let after_first = v3_chunk_snapshot(&state).ok_or("chunk not stored")?;

        // A byte-identical replay is idempotent and mutates nothing (same stored_at, expiry, status).
        let second = relay_client_quic_route(
            &client_quic_object_request_to(
                "/relay/v1/object/put_chunk",
                v3_put_request_body(|_| {})?,
            ),
            &cache,
            &store,
            &state,
            V3_AUDIENCE_NODE,
            V3_NOW,
        );
        assert_eq!(second.status, 200, "an identical replay is idempotent");
        let after_second = v3_chunk_snapshot(&state).ok_or("chunk gone")?;
        assert_eq!(after_first, after_second, "an identical replay must be zero-mutation");
        Ok(())
    }

    #[test]
    fn relay_client_quic_invalid_put_leaves_store_unchanged() -> Result<(), String> {
        let store = v3_temp_store()?;
        let cache = v3_pinned_cache()?;
        let state = Arc::new(Mutex::new(ramflux_node_core::RelayCacheState::new()));

        // A tampered owner-session token fails verification before any store access: 403, nothing
        // stored.
        let tampered = v3_put_request_body(|body| {
            if let Some(token) = body.get_mut("token").and_then(serde_json::Value::as_object_mut) {
                token.insert("nonce".to_owned(), serde_json::Value::String("forged".to_owned()));
            }
        })?;
        let response = relay_client_quic_route(
            &client_quic_object_request_to("/relay/v1/object/put_chunk", tampered),
            &cache,
            &store,
            &state,
            V3_AUDIENCE_NODE,
            V3_NOW,
        );
        assert_eq!(response.status, 403, "a tampered put must fail closed");
        assert!(v3_chunk_snapshot(&state).is_none(), "a rejected put must store nothing");

        // A payload whose cipher hash is not the canonical hash of the ciphertext is rejected before
        // any store write, so the ciphertext cannot be substituted under a valid invocation.
        let bad_hash = v3_put_request_body(|body| {
            body.insert(
                "chunk_cipher_hash".to_owned(),
                serde_json::Value::String("forged_hash".to_owned()),
            );
        })?;
        let bad = relay_client_quic_route(
            &client_quic_object_request_to("/relay/v1/object/put_chunk", bad_hash),
            &cache,
            &store,
            &state,
            V3_AUDIENCE_NODE,
            V3_NOW,
        );
        assert_eq!(bad.status, 403, "a payload not bound to its cipher hash must be rejected");
        assert!(v3_chunk_snapshot(&state).is_none(), "a rejected put must store nothing");
        Ok(())
    }

    #[test]
    fn relay_client_quic_tombstone_applies_and_blocks_get() -> Result<(), String> {
        let store = v3_temp_store()?;
        let cache = v3_pinned_cache()?;
        let state = v3_state_with(&store, v3_stored_chunk(v3_pk(V3_OWNER_SEED), false))?;
        let response = relay_client_quic_route(
            &client_quic_object_request_to(
                "/relay/v1/object/tombstone",
                v3_tombstone_request_body(|_| {})?,
            ),
            &cache,
            &store,
            &state,
            V3_AUDIENCE_NODE,
            V3_NOW,
        );
        assert_eq!(response.status, 200, "a valid owner-session tombstone applies");
        let body: ramflux_node_core::ObjectRelayTombstoneResponse =
            serde_json::from_value(response.body).map_err(|error| error.to_string())?;
        assert_eq!(body.object_id, V3_OBJECT);
        assert_eq!(body.tombstone_hash, V3_TOMBSTONE_HASH);
        // The owned chunk is now tombstoned and no longer available to GET.
        assert_eq!(v3_chunk_status(&state), Some(ramflux_node_core::RelayChunkStatus::Tombstoned));
        let get = relay_client_quic_route(
            &client_quic_object_request(v3_envelope_body(Get, |_| {})?),
            &cache,
            &store,
            &state,
            V3_AUDIENCE_NODE,
            V3_NOW,
        );
        assert_eq!(get.status, 404, "a tombstoned chunk is no longer available");
        Ok(())
    }

    #[test]
    fn relay_client_quic_tombstone_rejects_empty_and_cross_owner_scope() -> Result<(), String> {
        let store = v3_temp_store()?;
        let cache = v3_pinned_cache()?;

        // Empty scope: no owned chunk proves ownership -> 403, nothing recorded.
        let empty = Arc::new(Mutex::new(ramflux_node_core::RelayCacheState::new()));
        let empty_response = relay_client_quic_route(
            &client_quic_object_request_to(
                "/relay/v1/object/tombstone",
                v3_tombstone_request_body(|_| {})?,
            ),
            &cache,
            &store,
            &empty,
            V3_AUDIENCE_NODE,
            V3_NOW,
        );
        assert_eq!(empty_response.status, 403, "an empty-scope tombstone must fail closed");

        // Cross-owner: a chunk in scope owned by a different original owner -> 403, chunk untouched.
        let foreign = v3_state_with(&store, v3_stored_chunk(v3_pk(V3_REQUESTER_SEED), false))?;
        let cross = relay_client_quic_route(
            &client_quic_object_request_to(
                "/relay/v1/object/tombstone",
                v3_tombstone_request_body(|_| {})?,
            ),
            &cache,
            &store,
            &foreign,
            V3_AUDIENCE_NODE,
            V3_NOW,
        );
        assert_eq!(cross.status, 403, "a cross-owner tombstone must be rejected");
        assert_eq!(
            v3_chunk_status(&foreign),
            Some(ramflux_node_core::RelayChunkStatus::Available),
            "a rejected tombstone must not consume the chunk"
        );
        Ok(())
    }

    #[test]
    fn relay_client_quic_invalid_tombstone_leaves_store_unchanged() -> Result<(), String> {
        let store = v3_temp_store()?;
        let cache = v3_pinned_cache()?;
        let state = v3_state_with(&store, v3_stored_chunk(v3_pk(V3_OWNER_SEED), false))?;
        // A tampered owner-session token fails verification before any store access: 403, unchanged.
        let tampered = v3_tombstone_request_body(|body| {
            if let Some(token) = body.get_mut("token").and_then(serde_json::Value::as_object_mut) {
                token.insert("nonce".to_owned(), serde_json::Value::String("forged".to_owned()));
            }
        })?;
        let response = relay_client_quic_route(
            &client_quic_object_request_to("/relay/v1/object/tombstone", tampered),
            &cache,
            &store,
            &state,
            V3_AUDIENCE_NODE,
            V3_NOW,
        );
        assert_eq!(response.status, 403, "a tampered tombstone must fail closed");
        assert_eq!(
            v3_chunk_status(&state),
            Some(ramflux_node_core::RelayChunkStatus::Available),
            "a rejected tombstone must not consume the chunk"
        );
        Ok(())
    }

    #[test]
    fn relay_client_quic_route_serves_health_and_unknown() -> Result<(), String> {
        let store = v3_temp_store()?;
        let cache = v3_pinned_cache()?;
        let state = v3_state_with(&store, v3_stored_chunk(v3_pk(V3_OWNER_SEED), false))?;
        // Health probe is served.
        assert_eq!(
            relay_client_quic_route(
                &client_quic_request("GET", "/healthz"),
                &cache,
                &store,
                &state,
                V3_AUDIENCE_NODE,
                V3_NOW,
            )
            .status,
            200
        );
        // A bodyless object request is not a v3 envelope (401).
        for path in [
            "/relay/v1/object/put_chunk",
            "/relay/v1/object/get_chunk",
            "/relay/v1/object/ack",
            "/relay/v1/object/tombstone",
        ] {
            assert_eq!(
                relay_client_quic_route(
                    &client_quic_request("POST", path),
                    &cache,
                    &store,
                    &state,
                    V3_AUDIENCE_NODE,
                    V3_NOW,
                )
                .status,
                401,
                "object route {path} must fail closed on a non-v3 request"
            );
        }
        // Unknown route and wrong method are 404.
        assert_eq!(
            relay_client_quic_route(
                &client_quic_request("POST", "/nope"),
                &cache,
                &store,
                &state,
                V3_AUDIENCE_NODE,
                V3_NOW,
            )
            .status,
            404
        );
        assert_eq!(
            relay_client_quic_route(
                &client_quic_request("GET", "/relay/v1/object/get_chunk"),
                &cache,
                &store,
                &state,
                V3_AUDIENCE_NODE,
                V3_NOW,
            )
            .status,
            404,
            "wrong method must not match an object route"
        );
        Ok(())
    }

    #[test]
    fn relay_client_quic_dispatch_records_ingress_and_object_rejections() -> Result<(), String> {
        let metrics = RelayClientQuicMetrics::default();
        let store = v3_temp_store()?;
        let cache = v3_pinned_cache()?;
        let state = v3_state_with(&store, v3_stored_chunk(v3_pk(V3_OWNER_SEED), false))?;

        // Health: served (200), counts as ingress, not an object rejection.
        assert_eq!(
            relay_client_quic_dispatch(
                &client_quic_request("GET", "/healthz"),
                &metrics,
                &cache,
                &store,
                &state,
                V3_AUDIENCE_NODE,
                V3_NOW,
            )
            .status,
            200
        );
        // Every bodyless object route is rejected by the v3 gate (401) and counted as a rejection.
        for path in [
            "/relay/v1/object/put_chunk",
            "/relay/v1/object/get_chunk",
            "/relay/v1/object/ack",
            "/relay/v1/object/tombstone",
        ] {
            assert_eq!(
                relay_client_quic_dispatch(
                    &client_quic_request("POST", path),
                    &metrics,
                    &cache,
                    &store,
                    &state,
                    V3_AUDIENCE_NODE,
                    V3_NOW,
                )
                .status,
                401,
                "object route {path} must fail closed"
            );
        }
        // A fully verified get reaches the data plane (200): ingress, not a rejection.
        assert_eq!(
            relay_client_quic_dispatch(
                &client_quic_object_request(v3_envelope_body(Get, |_| {})?),
                &metrics,
                &cache,
                &store,
                &state,
                V3_AUDIENCE_NODE,
                V3_NOW,
            )
            .status,
            200
        );
        // Unknown route: 404, ingress only.
        assert_eq!(
            relay_client_quic_dispatch(
                &client_quic_request("POST", "/nope"),
                &metrics,
                &cache,
                &store,
                &state,
                V3_AUDIENCE_NODE,
                V3_NOW,
            )
            .status,
            404
        );

        assert_eq!(metrics.ingress_total(), 7, "every request must count as ingress");
        assert_eq!(
            metrics.object_rejected_total(),
            4,
            "only the four 401 object rejections count; the served get does not"
        );
        Ok(())
    }

    #[test]
    fn validate_relay_client_quic_tls_fails_closed_on_missing_credentials()
    -> Result<(), Box<dyn std::error::Error>> {
        // Missing cert/key files: fail closed with a clear configuration error.
        let missing = ramflux_transport::MeshTlsConfig {
            ca_cert: "/nonexistent/relay-ca.pem".into(),
            service_cert: "/nonexistent/relay.pem".into(),
            service_key: "/nonexistent/relay-key.pem".into(),
        };
        let missing_config = test_config(&missing, "unused-retention:0");
        assert!(validate_relay_client_quic_tls(&missing_config).is_err());

        // Present, valid server-auth credentials: accepted.
        let root = temp_cert_root("relay_client_quic_tls")?;
        let certs = issue_test_ca_and_service_cert(&root, "node-relay-a", "ramflux-relay")?;
        let valid_config = test_config(&certs.tls, "unused-retention:0");
        validate_relay_client_quic_tls(&valid_config)?;
        Ok(())
    }

    #[test]
    fn relay_client_quic_endpoint_binds_with_valid_credentials()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = temp_cert_root("relay_client_quic_bind")?;
        let certs = issue_test_ca_and_service_cert(&root, "node-relay-a", "ramflux-relay")?;
        let config = test_config(&certs.tls, "unused-retention:0");
        let server_config = validate_relay_client_quic_tls(&config)?;
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
        runtime.block_on(async move {
            let endpoint = quinn::Endpoint::server(
                server_config,
                "127.0.0.1:0".parse::<std::net::SocketAddr>()?,
            )?;
            let addr = endpoint.local_addr()?;
            assert_ne!(addr.port(), 0, "bound client QUIC endpoint must have a concrete port");
            endpoint.close(0_u32.into(), b"test");
            Ok::<(), anyhow::Error>(())
        })?;
        Ok(())
    }

    #[test]
    fn relay_client_quic_health_round_trips_over_real_framing()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = temp_cert_root("relay_client_quic_framing")?;
        let certs = issue_test_ca_and_service_cert(&root, "node-relay-a", "ramflux-relay")?;
        let config = test_config(&certs.tls, "unused-retention:0");
        let server_config = validate_relay_client_quic_tls(&config)?;
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
        runtime.block_on(async move {
            let endpoint = quinn::Endpoint::server(
                server_config,
                "127.0.0.1:0".parse::<std::net::SocketAddr>()?,
            )?;
            let addr = endpoint.local_addr()?;
            let server = tokio::spawn(async move {
                let connecting = endpoint
                    .accept()
                    .await
                    .ok_or_else(|| anyhow::anyhow!("QUIC server did not receive a connection"))?;
                let connection = connecting.await?;
                let (mut send, mut recv) = connection.accept_bi().await?;
                let request: ramflux_transport::GatewayQuicRequest =
                    ramflux_transport::read_quic_json_frame(&mut recv).await?;
                assert_eq!(request.method, "GET");
                assert_eq!(request.path, "/healthz");
                ramflux_transport::write_quic_json_frame(
                    &mut send,
                    &ramflux_transport::GatewayQuicResponse {
                        status: 200,
                        body: serde_json::json!({ "status": "ok" }),
                    },
                )
                .await?;
                // Keep the endpoint alive long enough for the client to consume the final frame.
                tokio::time::sleep(Duration::from_millis(50)).await;
                Ok::<(), anyhow::Error>(())
            });
            let client = ramflux_transport::QuicGatewayClient::connect(
                "127.0.0.1:0".parse()?,
                addr,
                "ramflux-relay",
                Path::new(&certs.tls.ca_cert),
                Duration::from_secs(3),
            )
            .await?;
            let response = client.request(&client_quic_request("GET", "/healthz")).await;
            let server_result = server.await?;
            server_result?;
            let response = response?;
            assert_eq!(response.status, 200);
            Ok::<(), anyhow::Error>(())
        })?;
        Ok(())
    }

    #[cfg(feature = "itest-object-v2")]
    #[test]
    fn retention_async_mesh_client_defaults_on_and_explicit_close_disables_it()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = temp_cert_root("relay_retention_default")?;
        let certs = issue_test_ca_and_service_cert(&root, "node-retention-a", "ramflux-relay")?;
        let config = test_config(&certs.tls, "unused-retention:18443");

        let client = retention_async_mesh_client_from_endpoint_value(&config, None)?
            .ok_or_else(|| test_error("retention async mesh should default to QUIC"))?;
        assert_eq!(client.endpoint, DEFAULT_RETENTION_ASYNC_ENDPOINT);
        assert_eq!(client.server_name, "ramflux-retention");
        assert_eq!(client.peer_ca_pems, vec![certs.ca_pem.clone()]);

        assert!(
            retention_async_mesh_client_from_endpoint_value(&config, Some(""))
                .is_ok_and(|value| value.is_none())
        );
        assert!(
            retention_async_mesh_client_from_endpoint_value(&config, Some("0"))
                .is_ok_and(|value| value.is_none())
        );
        assert!(
            retention_async_mesh_client_from_endpoint_value(&config, Some("off"))
                .is_ok_and(|value| value.is_none())
        );
        assert_eq!(
            retention_async_mesh_client_from_endpoint_value(
                &config,
                Some("${RAMFLUX_RETENTION_ASYNC_ENDPOINT:-}")
            )?
            .ok_or_else(|| test_error("literal compose endpoint should use default"))?
            .endpoint,
            DEFAULT_RETENTION_ASYNC_ENDPOINT
        );
        Ok(())
    }

    #[cfg(feature = "itest-object-v2")]
    #[test]
    fn register_object_relay_ttl_falls_back_when_quic_transport_fails()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = temp_cert_root("relay_retention_fallback")?;
        let relay = issue_test_ca_and_service_cert(&root, "node-retention-a", "ramflux-relay")?;
        let retention =
            issue_test_ca_and_service_cert(&root, "node-retention-a", "ramflux-retention")?;
        let (endpoint, received) =
            spawn_retention_blocking_mesh_echo_server(retention.tls.clone(), relay.ca_pem.clone())?;
        let mut relay_client_tls = relay.tls.clone();
        relay_client_tls.ca_cert.clone_from(&retention.tls.ca_cert);
        let config = test_config(&relay_client_tls, &endpoint);
        let client = RetentionMeshClient {
            blocking: ramflux_transport::MeshHttpClient::new(),
            async_mesh: Some(RetentionAsyncMeshClient {
                endpoint: "127.0.0.1:1".to_owned(),
                server_name: "ramflux-retention".to_owned(),
                tls: relay_client_tls,
                peer_ca_pems: vec![retention.ca_pem],
            }),
        };
        let entry = test_relay_chunk_entry();

        register_object_relay_ttl(&config, &client, &entry, 1_000)?;

        let request = received.recv_timeout(Duration::from_secs(5))?;
        assert!(request.record.record_id.ends_with(&entry.chunk_id));
        assert_eq!(request.record.subject_hash, entry.object_id);
        Ok(())
    }

    #[cfg(feature = "itest-object-v2")]
    fn spawn_retention_blocking_mesh_echo_server(
        server_tls: ramflux_transport::MeshTlsConfig,
        trusted_relay_ca: String,
    ) -> Result<
        (String, mpsc::Receiver<ramflux_node_core::RetentionRecordRequest>),
        Box<dyn std::error::Error>,
    > {
        let server = ramflux_transport::MeshTlsServer::bind("127.0.0.1:0", &server_tls)?;
        let endpoint = server.local_addr()?.to_string();
        let (request_tx, request_rx) = mpsc::channel::<ramflux_node_core::RetentionRecordRequest>();
        std::thread::spawn(move || {
            let result: Result<(), String> = (|| {
                let mut accepted = server
                    .accept_authenticated_with_pem_roots(&server_tls, &[trusted_relay_ca])
                    .map_err(|source| source.to_string())?
                    .stream;
                let request = ramflux_transport::read_mesh_http_request(&mut accepted)
                    .map_err(|source| source.to_string())?
                    .ok_or_else(|| "missing retention blocking mesh request".to_owned())?;
                if request.method != "POST" || request.path != "/retention/v1/object_relay_ttl" {
                    return Err(format!(
                        "unexpected retention blocking mesh request {} {}",
                        request.method, request.path
                    ));
                }
                let request: ramflux_node_core::RetentionRecordRequest =
                    serde_json::from_slice(&request.body).map_err(|source| source.to_string())?;
                let response = request.record.clone();
                request_tx.send(request).map_err(|source| source.to_string())?;
                ramflux_transport::write_mesh_json_response(&mut accepted, "200 OK", &response)
                    .map_err(|source| source.to_string())?;
                ramflux_transport::close_mesh_server_stream(&mut accepted)
                    .map_err(|source| source.to_string())
            })();
            if let Err(error) = result {
                tracing::debug!(%error, "relay retention blocking mesh fallback test server stopped");
            }
        });
        Ok((endpoint, request_rx))
    }

    fn test_config(
        tls: &ramflux_transport::MeshTlsConfig,
        retention_endpoint: &str,
    ) -> ramflux_node_core::NodeServiceConfig {
        let mut endpoints = BTreeMap::new();
        endpoints.insert("retention".to_owned(), retention_endpoint.to_owned());
        ramflux_node_core::NodeServiceConfig {
            node_id: "node-retention-a".to_owned(),
            service_id: "ramflux-relay".to_owned(),
            redb_path: ":memory:".to_owned(),
            node_service_signing_seed_b64url: None,
            mesh: ramflux_node_core::MeshConfig {
                listen_addr: "127.0.0.1:0".to_owned(),
                ca_cert: tls.ca_cert.to_string_lossy().into_owned(),
                service_cert: tls.service_cert.to_string_lossy().into_owned(),
                service_key: tls.service_key.to_string_lossy().into_owned(),
                allowed_service_ids: BTreeSet::from([
                    "ramflux-relay".to_owned(),
                    "ramflux-retention".to_owned(),
                ]),
                endpoints,
            },
            gateway: None,
            signaling: None,
            relay: None,
        }
    }

    #[cfg(feature = "itest-object-v2")]
    fn test_relay_chunk_entry() -> ramflux_node_core::RelayChunkEntry {
        ramflux_node_core::RelayChunkEntry {
            chunk_id: "chunk-retention-quic-fallback".to_owned(),
            object_id: "object-retention-quic-fallback".to_owned(),
            manifest_hash: "manifest-hash".to_owned(),
            chunk_index: 0,
            chunk_cipher_hash: "chunk-cipher-hash".to_owned(),
            owner_signing_key_id: "owner-retention-quic-fallback".to_owned(),
            owner_public_key: "owner-public-retention-quic-fallback".to_owned(),
            encrypted_chunk: b"ciphertext".to_vec(),
            stored_at: 1_000,
            expires_at: 1_900,
            delete_after_ack: false,
            acked_by: BTreeSet::new(),
            status: ramflux_node_core::RelayChunkStatus::Available,
        }
    }

    struct TestPeerCerts {
        tls: ramflux_transport::MeshTlsConfig,
        #[cfg_attr(not(feature = "itest-object-v2"), allow(dead_code))]
        ca_pem: String,
    }

    fn temp_cert_root(name: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
        let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let root = std::env::temp_dir().join(format!(
            "ramflux_relay_{name}_{}_{}",
            std::process::id(),
            nanos
        ));
        if root.exists() {
            std::fs::remove_dir_all(&root)?;
        }
        std::fs::create_dir_all(&root)?;
        Ok(root)
    }

    fn issue_test_ca_and_service_cert(
        root: &Path,
        node_id: &str,
        service_id: &str,
    ) -> Result<TestPeerCerts, Box<dyn std::error::Error>> {
        let dir = root.join(service_id);
        std::fs::create_dir_all(&dir)?;
        let ca_key = dir.join("ca-key.pem");
        let ca_cert = dir.join("ca.pem");
        let service_key = dir.join(format!("{service_id}-key.pem"));
        let service_csr = dir.join(format!("{service_id}.csr"));
        let service_cert = dir.join(format!("{service_id}.pem"));
        let ext = dir.join(format!("{service_id}.ext"));
        run_openssl(&["genpkey", "-algorithm", "ED25519", "-out", path_str(&ca_key)?])?;
        run_openssl(&[
            "req",
            "-x509",
            "-new",
            "-key",
            path_str(&ca_key)?,
            "-out",
            path_str(&ca_cert)?,
            "-days",
            "30",
            "-subj",
            "/CN=Ramflux Relay Retention Mesh Test CA",
        ])?;
        run_openssl(&["genpkey", "-algorithm", "ED25519", "-out", path_str(&service_key)?])?;
        run_openssl(&[
            "req",
            "-new",
            "-key",
            path_str(&service_key)?,
            "-out",
            path_str(&service_csr)?,
            "-subj",
            &format!("/CN={service_id}"),
        ])?;
        std::fs::write(
            &ext,
            format!(
                "subjectAltName = DNS:{service_id}, DNS:localhost, URI:spiffe://{node_id}/{service_id}\nextendedKeyUsage = serverAuth, clientAuth\nkeyUsage = digitalSignature\n"
            ),
        )?;
        run_openssl(&[
            "x509",
            "-req",
            "-in",
            path_str(&service_csr)?,
            "-CA",
            path_str(&ca_cert)?,
            "-CAkey",
            path_str(&ca_key)?,
            "-CAcreateserial",
            "-out",
            path_str(&service_cert)?,
            "-days",
            "30",
            "-extfile",
            path_str(&ext)?,
        ])?;
        Ok(TestPeerCerts {
            tls: ramflux_transport::MeshTlsConfig {
                ca_cert: ca_cert.clone(),
                service_cert,
                service_key,
            },
            ca_pem: std::fs::read_to_string(ca_cert)?,
        })
    }

    fn run_openssl(args: &[&str]) -> Result<(), Box<dyn std::error::Error>> {
        let status = Command::new("openssl").args(args).status()?;
        if !status.success() {
            return Err(format!("openssl failed with status {status}: {}", args.join(" ")).into());
        }
        Ok(())
    }

    fn path_str(path: &Path) -> Result<&str, Box<dyn std::error::Error>> {
        path.to_str().ok_or_else(|| format!("non-UTF-8 path {}", path.display()).into())
    }

    #[cfg(feature = "itest-object-v2")]
    fn test_error(message: impl Into<String>) -> Box<dyn std::error::Error> {
        message.into().into()
    }
}

// T23-A2b2a: relay-glue pure tests for the opt-in provider-keyring trust path (file load + validate,
// persist/restore roundtrip honouring the anti-rollback high-water). The core verifier/cache logic is
// covered by node-core; these cover the relay's file IO + serde + restore wiring.
#[cfg(all(test, not(feature = "itest-provider-single-key")))]
mod keyring_loader_tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    const OFFLINE_ROOT_SEED: [u8; 32] = [0xa1; 32];
    const WRONG_ROOT_SEED: [u8; 32] = [0xa9; 32];
    const K1_SEED: [u8; 32] = [0xa2; 32];
    const NODE: &str = "node-b.realnet";
    const NOW: u64 = 2_000_000_000;

    fn pk(seed: [u8; 32]) -> String {
        ramflux_crypto::public_key_base64url_from_seed(seed)
    }

    fn sign(bytes: &[u8], seed: [u8; 32]) -> String {
        ramflux_crypto::sign_canonical_bytes_with_seed(bytes, seed)
    }

    fn snapshot(generation: u64) -> ramflux_node_core::FederatedIssuerTrustSnapshot {
        ramflux_node_core::FederatedIssuerTrustSnapshot {
            schema: ramflux_node_core::FEDERATED_ISSUER_TRUST_SNAPSHOT_SCHEMA.to_owned(),
            version: ramflux_node_core::OBJECT_RELAY_V3_PROOF_VERSION,
            node_id: NODE.to_owned(),
            generation,
            pin_epoch: 1,
            trust_status: ramflux_node_core::FederatedIssuerTrustStatus::Active,
            roots: Vec::new(),
            revoked_cert_ids: std::collections::BTreeSet::new(),
            hard_stale_at: NOW + 3_600,
        }
    }

    fn keyring(keyring_epoch: u64, offline_seed: [u8; 32]) -> ramflux_node_core::ProviderKeyring {
        let mut keyring = ramflux_node_core::ProviderKeyring {
            schema: ramflux_node_core::PROVIDER_KEYRING_SCHEMA.to_owned(),
            version: ramflux_node_core::PROVIDER_KEYRING_VERSION,
            issuer_node_id: NODE.to_owned(),
            keyring_epoch,
            keys: vec![ramflux_node_core::ProviderKeyEntry {
                key_id: "k1".to_owned(),
                public_key: pk(K1_SEED),
                not_before: NOW - 100,
                not_after: NOW + 3_600,
                retired_at: None,
                authorized_provider_epoch: 1,
            }],
            keyring_signature: String::new(),
        };
        keyring.keyring_signature = sign(
            &ramflux_node_core::provider_keyring_signing_bytes(&keyring).unwrap(),
            offline_seed,
        );
        keyring
    }

    fn envelope(generation: u64) -> ramflux_node_core::ProviderSignedTrustSnapshot {
        let mut envelope = ramflux_node_core::ProviderSignedTrustSnapshot {
            schema: ramflux_node_core::PROVIDER_SIGNED_TRUST_SNAPSHOT_ENVELOPE_SCHEMA.to_owned(),
            version: ramflux_node_core::PROVIDER_SIGNED_TRUST_SNAPSHOT_ENVELOPE_VERSION,
            snapshot: snapshot(generation),
            provider_signing_key_id: "k1".to_owned(),
            provider_public_key: pk(K1_SEED),
            provider_epoch: 1,
            issued_at: NOW,
            expires_at: NOW + 300,
            signature: String::new(),
        };
        envelope.signature = sign(
            &ramflux_node_core::provider_signed_trust_snapshot_signing_bytes(&envelope).unwrap(),
            K1_SEED,
        );
        envelope
    }

    const K2_SEED: [u8; 32] = [0xa3; 32];

    /// A two-key keyring at `epoch` (K1 optionally retired, K2 authorized for `provider_epoch` 2).
    fn keyring_two(epoch: u64, k1_retired: bool) -> ramflux_node_core::ProviderKeyring {
        let mut keyring = ramflux_node_core::ProviderKeyring {
            schema: ramflux_node_core::PROVIDER_KEYRING_SCHEMA.to_owned(),
            version: ramflux_node_core::PROVIDER_KEYRING_VERSION,
            issuer_node_id: NODE.to_owned(),
            keyring_epoch: epoch,
            keys: vec![
                ramflux_node_core::ProviderKeyEntry {
                    key_id: "k1".to_owned(),
                    public_key: pk(K1_SEED),
                    not_before: NOW - 100,
                    not_after: NOW + 3_600,
                    retired_at: if k1_retired { Some(NOW - 1) } else { None },
                    authorized_provider_epoch: 1,
                },
                ramflux_node_core::ProviderKeyEntry {
                    key_id: "k2".to_owned(),
                    public_key: pk(K2_SEED),
                    not_before: NOW - 100,
                    not_after: NOW + 3_600,
                    retired_at: None,
                    authorized_provider_epoch: 2,
                },
            ],
            keyring_signature: String::new(),
        };
        keyring.keyring_signature = sign(
            &ramflux_node_core::provider_keyring_signing_bytes(&keyring).unwrap(),
            OFFLINE_ROOT_SEED,
        );
        keyring
    }

    fn envelope_k2(generation: u64) -> ramflux_node_core::ProviderSignedTrustSnapshot {
        let mut envelope = ramflux_node_core::ProviderSignedTrustSnapshot {
            schema: ramflux_node_core::PROVIDER_SIGNED_TRUST_SNAPSHOT_ENVELOPE_SCHEMA.to_owned(),
            version: ramflux_node_core::PROVIDER_SIGNED_TRUST_SNAPSHOT_ENVELOPE_VERSION,
            snapshot: snapshot(generation),
            provider_signing_key_id: "k2".to_owned(),
            provider_public_key: pk(K2_SEED),
            provider_epoch: 2,
            issued_at: NOW,
            expires_at: NOW + 300,
            signature: String::new(),
        };
        envelope.signature = sign(
            &ramflux_node_core::provider_signed_trust_snapshot_signing_bytes(&envelope).unwrap(),
            K2_SEED,
        );
        envelope
    }

    fn validate(
        keyring: &ramflux_node_core::ProviderKeyring,
    ) -> ramflux_node_core::ValidatedProviderKeyring {
        ramflux_node_core::verify_provider_keyring(keyring, &pk(OFFLINE_ROOT_SEED), NODE).unwrap()
    }

    /// A live cache holding K1/e1 at snapshot generation 5.
    fn live_k1() -> ramflux_node_core::RelayTrustSnapshotCache {
        let mut cache = ramflux_node_core::RelayTrustSnapshotCache::new();
        cache
            .update_from_keyring_signed(
                &envelope(5),
                &validate(&keyring(1, OFFLINE_ROOT_SEED)),
                NODE,
                NOW,
            )
            .unwrap();
        cache
    }

    fn tmp(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("ramflux-a2b2-{name}-{}.json", std::process::id()))
    }

    #[test]
    fn keyring_provider_config_requires_all_five_fields_fail_closed() {
        let (endpoint, keyring, root, node, cache) =
            (Some("ep"), Some("kr"), Some("root"), Some("node"), Some("cache"));
        // Positive: all five present → config resolved.
        assert!(
            relay_keyring_provider_config_from_values(endpoint, keyring, root, node, cache)
                .is_some()
        );
        // Negative: each missing / empty field independently disables the provider (fail-closed).
        assert!(
            relay_keyring_provider_config_from_values(None, keyring, root, node, cache).is_none()
        );
        assert!(
            relay_keyring_provider_config_from_values(endpoint, None, root, node, cache).is_none()
        );
        assert!(
            relay_keyring_provider_config_from_values(endpoint, keyring, None, node, cache)
                .is_none()
        );
        assert!(
            relay_keyring_provider_config_from_values(endpoint, keyring, root, None, cache)
                .is_none()
        );
        assert!(
            relay_keyring_provider_config_from_values(endpoint, keyring, root, node, None)
                .is_none()
        );
        assert!(
            relay_keyring_provider_config_from_values(Some("  "), keyring, root, node, cache)
                .is_none()
        );
        assert!(
            relay_keyring_provider_config_from_values(endpoint, keyring, root, node, Some(""))
                .is_none()
        );
    }

    #[test]
    fn keyring_provider_startup_readiness_fails_closed_with_error() {
        // Incomplete config → Err (fail-closed at startup, NOT a silent disable).
        assert!(require_keyring_provider_ready_from(None).is_err());

        let good = tmp("readiness-good");
        std::fs::write(&good, serde_json::to_vec_pretty(&keyring(1, OFFLINE_ROOT_SEED)).unwrap())
            .unwrap();
        let config = |keyring_file: &str, offline_root: &str, issuer: &str| {
            Some((
                "ramflux-federation:7443".to_owned(),
                keyring_file.to_owned(),
                offline_root.to_owned(),
                issuer.to_owned(),
                "/var/lib/ramflux/relay/trust-snapshot.json".to_owned(),
            ))
        };
        // Complete config + valid keyring → Ok (proceeds to startup init).
        assert!(
            require_keyring_provider_ready_from(config(
                good.to_str().unwrap(),
                &pk(OFFLINE_ROOT_SEED),
                NODE
            ))
            .is_ok()
        );
        // Missing keyring file → Err.
        assert!(
            require_keyring_provider_ready_from(config(
                "/nonexistent/provider-keyring.json",
                &pk(OFFLINE_ROOT_SEED),
                NODE
            ))
            .is_err()
        );
        // Forged offline root (keyring signed by a non-pinned root) → Err.
        let forged = tmp("readiness-forged");
        std::fs::write(&forged, serde_json::to_vec_pretty(&keyring(1, WRONG_ROOT_SEED)).unwrap())
            .unwrap();
        assert!(
            require_keyring_provider_ready_from(config(
                forged.to_str().unwrap(),
                &pk(OFFLINE_ROOT_SEED),
                NODE
            ))
            .is_err()
        );
        // Issuer-node mismatch → Err.
        assert!(
            require_keyring_provider_ready_from(config(
                good.to_str().unwrap(),
                &pk(OFFLINE_ROOT_SEED),
                "node-wrong.realnet"
            ))
            .is_err()
        );
        let _ = std::fs::remove_file(&good);
        let _ = std::fs::remove_file(&forged);
    }

    #[test]
    fn provider_keyring_loads_from_file_and_rejects_forgery() {
        let good = tmp("keyring-good");
        std::fs::write(&good, serde_json::to_vec_pretty(&keyring(1, OFFLINE_ROOT_SEED)).unwrap())
            .unwrap();
        assert!(
            load_provider_keyring(good.to_str().unwrap(), &pk(OFFLINE_ROOT_SEED), NODE).is_ok()
        );
        // Forged keyring (signed by a non-root key) is rejected against the pinned offline root.
        let forged = tmp("keyring-forged");
        std::fs::write(&forged, serde_json::to_vec_pretty(&keyring(1, WRONG_ROOT_SEED)).unwrap())
            .unwrap();
        assert!(
            load_provider_keyring(forged.to_str().unwrap(), &pk(OFFLINE_ROOT_SEED), NODE).is_err()
        );
        let _ = std::fs::remove_file(&good);
        let _ = std::fs::remove_file(&forged);
    }

    #[test]
    fn keyring_trust_persist_restore_roundtrip_honors_high_water() {
        let validated = validate(&keyring(2, OFFLINE_ROOT_SEED));
        let mut cache = ramflux_node_core::RelayTrustSnapshotCache::new();
        cache.update_from_keyring_signed(&envelope(5), &validated, NODE, NOW).unwrap();
        assert_eq!(cache.generation(), Some(5));

        let path = tmp("keyring-cache");
        persist_keyring_trust(path.to_str().unwrap(), &cache, Some(&envelope(5))).unwrap();

        // A cold cache restores the persisted snapshot + high-water (incl. fingerprint).
        let mut restarted = ramflux_node_core::RelayTrustSnapshotCache::new();
        let restored =
            load_keyring_trust(path.to_str().unwrap(), &mut restarted, &validated, NODE, NOW)
                .unwrap();
        assert!(restored.is_some());
        assert_eq!(restarted.generation(), Some(5));
        assert_eq!(restarted.provider_epoch_high_water(), 1);
        assert_eq!(restarted.keyring_epoch_high_water(), 2);
        assert!(restarted.keyring_fingerprint_high_water().is_some());
        assert_eq!(restarted.accepted_signer_key_id(), Some("k1"));

        // The restored cache rejects a generation rollback.
        assert!(restarted.update_from_keyring_signed(&envelope(4), &validated, NODE, NOW).is_err());
        assert_eq!(restarted.generation(), Some(5));
        let _ = std::fs::remove_file(&path);
    }

    // ---- CTRL-046 closure tests ----

    // (1) A same-`keyring_epoch` content replacement (validly offline-root-signed) is not adopted, so
    // the candidate planner leaves the live cache untouched.
    #[test]
    fn closure_same_epoch_content_replacement_not_published() {
        let live = live_k1();
        let alt = validate(&keyring_two(1, false)); // same epoch 1, different content
        assert!(
            plan_keyring_candidate(&live, &alt, None, Some(&envelope(5)), NODE, NOW).is_none(),
            "same-epoch content replacement must not produce a publishable candidate"
        );
    }

    // (2) A persistence failure must NOT publish the candidate: the live cache and disk stay at K1.
    #[test]
    fn closure_persist_failure_does_not_publish() {
        let live = Mutex::new(live_k1());
        // Build a K2 candidate.
        let mut candidate = live.lock().unwrap().clone();
        candidate
            .update_from_keyring_signed(
                &envelope_k2(6),
                &validate(&keyring_two(2, false)),
                NODE,
                NOW,
            )
            .unwrap();
        // Force persist failure: a path whose parent is a regular file.
        let blocker = tmp("persist-blocker");
        std::fs::write(&blocker, b"x").unwrap();
        let bad_path = blocker.join("child.json");
        assert!(
            publish_keyring_candidate(
                &live,
                candidate,
                Some(&envelope_k2(6)),
                bad_path.to_str().unwrap()
            )
            .is_err(),
            "a persistence failure must be surfaced"
        );
        assert_eq!(
            live.lock().unwrap().generation(),
            Some(5),
            "live must remain K1 after persist failure"
        );
        let _ = std::fs::remove_file(&blocker);
    }

    // (3) Persist success THEN publish; a restart from the persisted file restores the published K2.
    #[test]
    fn closure_persist_success_publishes_and_survives_restart() {
        let live = Mutex::new(live_k1());
        let mut candidate = live.lock().unwrap().clone();
        candidate
            .update_from_keyring_signed(
                &envelope_k2(6),
                &validate(&keyring_two(2, false)),
                NODE,
                NOW,
            )
            .unwrap();
        let path = tmp("keyring-publish");
        publish_keyring_candidate(&live, candidate, Some(&envelope_k2(6)), path.to_str().unwrap())
            .unwrap();
        assert_eq!(
            live.lock().unwrap().generation(),
            Some(6),
            "K2 published after persist success"
        );

        let mut restarted = ramflux_node_core::RelayTrustSnapshotCache::new();
        load_keyring_trust(
            path.to_str().unwrap(),
            &mut restarted,
            &validate(&keyring_two(2, false)),
            NODE,
            NOW,
        )
        .unwrap();
        assert_eq!(restarted.generation(), Some(6), "restart restores published K2");
        assert_eq!(restarted.provider_epoch_high_water(), 2);
        let _ = std::fs::remove_file(&path);
    }

    // (4) Retire-current-signer + fetch failure persists the empty-authorization state, then publishes
    // fail-closed; a restart stays fail-closed while preserving the anti-rollback high-water.
    #[test]
    fn closure_retire_fetch_fail_persists_empty_and_restart_fail_closed() {
        let live = live_k1();
        let retire = validate(&keyring_two(2, true)); // epoch 2, K1 retired, K2 present
        let (candidate, candidate_envelope) =
            plan_keyring_candidate(&live, &retire, None, Some(&envelope(5)), NODE, NOW)
                .expect("retirement must produce a fail-closed candidate");
        assert!(candidate_envelope.is_none(), "retired signer leaves no authoritative envelope");
        assert!(candidate.generation().is_none(), "retired signer clears the cached snapshot");

        let path = tmp("keyring-retire");
        let mutex = Mutex::new(live);
        publish_keyring_candidate(
            &mutex,
            candidate,
            candidate_envelope.as_ref(),
            path.to_str().unwrap(),
        )
        .unwrap();
        assert!(
            mutex.lock().unwrap().current(NODE, NOW).is_err(),
            "live must be fail-closed after retire"
        );

        let mut restarted = ramflux_node_core::RelayTrustSnapshotCache::new();
        let restored =
            load_keyring_trust(path.to_str().unwrap(), &mut restarted, &retire, NODE, NOW).unwrap();
        assert!(restored.is_none());
        assert!(restarted.current(NODE, NOW).is_err(), "restart stays fail-closed");
        assert_eq!(restarted.keyring_epoch_high_water(), 2, "anti-rollback high-water preserved");
        let _ = std::fs::remove_file(&path);
    }

    // (5) An old-epoch (rolled-back) keyring is non-adoptable: it never triggers signer reconciliation
    // and never clears the existing valid cache.
    #[test]
    fn closure_old_epoch_keyring_no_reconciliation() {
        // Live cache at K2/e2, keyring epoch 2.
        let mut live = ramflux_node_core::RelayTrustSnapshotCache::new();
        live.update_from_keyring_signed(
            &envelope_k2(6),
            &validate(&keyring_two(2, false)),
            NODE,
            NOW,
        )
        .unwrap();
        // A rolled-back keyring at epoch 1 must not be adopted.
        let old = validate(&keyring(1, OFFLINE_ROOT_SEED));
        assert!(
            plan_keyring_candidate(&live, &old, None, Some(&envelope_k2(6)), NODE, NOW).is_none(),
            "an old-epoch keyring must not produce a publishable candidate"
        );
        assert_eq!(live.generation(), Some(6), "existing valid cache is retained");
    }
}
