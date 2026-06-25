// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
use std::sync::Arc;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[cfg(feature = "itest-http")]
use std::net::{TcpListener, TcpStream};

fn main() {
    if let Err(error) = run_service("ramflux-retention") {
        eprintln!("ramflux-retention: {error}");
        std::process::exit(2);
    }
}

fn run_service(service: &'static str) -> Result<(), ramflux_node_core::NodeCoreError> {
    if std::env::args().any(|arg| arg == "--health-check") {
        println!("{service}:healthy");
        return Ok(());
    }
    tracing_subscriber::fmt().with_target(false).init();
    if let Some(config) =
        ramflux_node_core::load_config_from_args(std::env::args().skip(1), service)?
    {
        let redb_path = ramflux_node_core::effective_redb_path(&config);
        let store = Arc::new(ramflux_node_core::RetentionRedbStore::open(&redb_path)?);
        let state = match store.load_state()? {
            Some(state) => state,
            None => ramflux_node_core::RetentionState::new(),
        };
        store.save_state(&state)?;
        start_gc_scheduler(Arc::clone(&store), config.clone());
        serve_retention_mesh_mtls(&config, Arc::clone(&store))?;
        tracing::info!(service, node_id = config.node_id, "retention store initialized");
        #[cfg(feature = "itest-http")]
        if std::env::var("RAMFLUX_ITEST_HTTP").as_deref() == Ok("1") {
            return serve_itest_http(&store, &config);
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
fn serve_itest_http(
    store: &ramflux_node_core::RetentionRedbStore,
    config: &ramflux_node_core::NodeServiceConfig,
) -> Result<(), ramflux_node_core::NodeCoreError> {
    let addr = std::env::var("RAMFLUX_ITEST_RETENTION_HTTP_ADDR")
        .unwrap_or_else(|_| "0.0.0.0:18087".to_owned());
    let listener = TcpListener::bind(&addr)
        .map_err(|source| ramflux_node_core::NodeCoreError::ItestHttp(source.to_string()))?;
    tracing::info!(addr, "retention itest HTTP surface listening");
    for stream in listener.incoming() {
        let mut stream = stream
            .map_err(|source| ramflux_node_core::NodeCoreError::ItestHttp(source.to_string()))?;
        if let Err(error) = handle_itest_request(&mut stream, store, config) {
            let body = format!("{error}");
            ramflux_node_core::write_itest_text_response(
                &mut stream,
                "500 Internal Server Error",
                &body,
            )?;
        }
    }
    Ok(())
}

#[cfg(feature = "itest-http")]
fn handle_itest_request(
    stream: &mut TcpStream,
    store: &ramflux_node_core::RetentionRedbStore,
    config: &ramflux_node_core::NodeServiceConfig,
) -> Result<(), ramflux_node_core::NodeCoreError> {
    let Some(request) = ramflux_node_core::read_itest_http_request(stream)? else {
        return Ok(());
    };
    match (request.method.as_str(), request.path.as_str()) {
        ("GET", "/healthz") => {
            ramflux_node_core::write_itest_json_response(
                stream,
                "200 OK",
                &serde_json::json!({
                    "service": "ramflux-retention",
                    "status": "ok"
                }),
            )?;
        }
        ("POST", "/mvp7/retention/record") => {
            let request: ramflux_node_core::ItestRetentionRecordRequest =
                serde_json::from_slice(&request.body).map_err(|source| {
                    ramflux_node_core::NodeCoreError::ItestJson(source.to_string())
                })?;
            store.record_metadata(request.record.clone())?;
            ramflux_node_core::write_itest_json_response(stream, "200 OK", &request.record)?;
        }
        ("POST", "/mvp7/retention/gc") => {
            let request: ramflux_node_core::ItestRetentionGcRequest =
                serde_json::from_slice(&request.body).map_err(|source| {
                    ramflux_node_core::NodeCoreError::ItestJson(source.to_string())
                })?;
            let response = store.gc_expired(request.now)?;
            ramflux_node_core::write_itest_json_response(stream, "200 OK", &response)?;
        }
        ("POST", "/mvp7/retention/finalize_identity_delete") => {
            let request: ramflux_node_core::ItestRetentionIdentityDeleteRequest =
                serde_json::from_slice(&request.body).map_err(|source| {
                    ramflux_node_core::NodeCoreError::ItestJson(source.to_string())
                })?;
            let signer = retention_node_signer(config);
            let context = request.into_context(now_unix_seconds());
            let response = store.finalize_identity_delete(&context, &signer)?;
            ramflux_node_core::write_itest_json_response(stream, "200 OK", &response)?;
        }
        ("GET", "/mvp7/retention/state") => {
            let state = store.load_state()?.unwrap_or_default();
            ramflux_node_core::write_itest_json_response(stream, "200 OK", &state)?;
        }
        _ => {
            ramflux_node_core::write_itest_text_response(stream, "404 Not Found", "not found")?;
        }
    }
    Ok(())
}

fn start_gc_scheduler(
    store: Arc<ramflux_node_core::RetentionRedbStore>,
    config: ramflux_node_core::NodeServiceConfig,
) {
    let interval = std::env::var("RAMFLUX_RETENTION_GC_SWEEP_INTERVAL_SECONDS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(86_400)
        .max(86_400);
    thread::spawn(move || {
        let mesh_client = ramflux_transport::MeshHttpClient::new();
        loop {
            if let Err(error) = run_gc_sweep_once(&store, &config, &mesh_client) {
                tracing::warn!(%error, "retention background GC sweep failed");
            }
            thread::sleep(Duration::from_secs(interval));
        }
    });
}

fn run_gc_sweep_once(
    store: &ramflux_node_core::RetentionRedbStore,
    config: &ramflux_node_core::NodeServiceConfig,
    mesh_client: &ramflux_transport::MeshHttpClient,
) -> Result<(), ramflux_node_core::NodeCoreError> {
    let now = now_unix_seconds();
    let local = store.gc_expired(now)?;
    tracing::info!(
        deleted = local.deleted_record_ids.len(),
        retained_legal_hold = local.retained_legal_hold_ids.len(),
        "retention background local GC sweep completed"
    );
    let tls = ramflux_transport::MeshTlsConfig {
        ca_cert: config.mesh.ca_cert.clone().into(),
        service_cert: config.mesh.service_cert.clone().into(),
        service_key: config.mesh.service_key.clone().into(),
    };
    for service_id in ["gateway", "router", "notify", "signaling", "federation"] {
        let Some(endpoint) = config.mesh.endpoints.get(service_id) else {
            continue;
        };
        let request = ramflux_node_core::RetentionGcSweepRequest {
            owner_service: service_id.to_owned(),
            sweep_id: format!("retention_gc:{service_id}:{now}"),
            now,
            dry_run: false,
        };
        let response: ramflux_node_core::RetentionGcSweepResponse = mesh_client
            .post_json(
                endpoint,
                "/internal/retention/gc_sweep",
                &tls,
                &format!("ramflux-{service_id}"),
                &request,
            )
            .map_err(|source| ramflux_node_core::NodeCoreError::ItestHttp(source.to_string()))?;
        tracing::info!(
            owner_service = %response.owner_service,
            sweep_id = %response.sweep_id,
            deleted_count = response.deleted_count,
            "retention cross-service GC sweep completed"
        );
    }
    Ok(())
}

fn serve_retention_mesh_mtls(
    config: &ramflux_node_core::NodeServiceConfig,
    store: Arc<ramflux_node_core::RetentionRedbStore>,
) -> Result<(), ramflux_node_core::NodeCoreError> {
    let server =
        ramflux_transport::MeshTlsServer::bind(&config.mesh.listen_addr, &mesh_tls_config(config))
            .map_err(|source| ramflux_node_core::NodeCoreError::ItestHttp(source.to_string()))?;
    let local_service_id = config.service_id.clone();
    let allowed_service_ids = config.mesh.allowed_service_ids.clone();
    thread::spawn(move || {
        tracing::info!("retention mesh mTLS surface listening");
        loop {
            let accepted = match server.accept_authenticated() {
                Ok(accepted) => accepted,
                Err(error) => {
                    tracing::warn!(%error, "retention mesh mTLS handshake rejected");
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
                    tracing::warn!(%error, "retention mesh peer identity rejected");
                    continue;
                }
            };
            let mut stream = accepted.stream;
            let store = Arc::clone(&store);
            thread::spawn(move || {
                loop {
                    match handle_mesh_request(&mut stream, &store, peer.service_id.as_str()) {
                        Ok(true) => {}
                        Ok(false) => break,
                        Err(error) => {
                            let body = format!("{error}");
                            if let Err(write_error) = ramflux_transport::write_mesh_text_response(
                                &mut stream,
                                "500 Internal Server Error",
                                &body,
                            ) {
                                tracing::warn!(%write_error, "failed to write retention mesh error response");
                            }
                            break;
                        }
                    }
                }
                if let Err(error) = ramflux_transport::close_mesh_server_stream(&mut stream) {
                    tracing::debug!(%error, "retention mesh close_notify failed");
                }
            });
        }
    });
    Ok(())
}

fn handle_mesh_request(
    stream: &mut ramflux_transport::MeshTlsServerStream,
    store: &ramflux_node_core::RetentionRedbStore,
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
        "retention mesh request received"
    );
    match (request.method.as_str(), request.path.as_str()) {
        ("POST", "/retention/v1/object_relay_ttl") if peer_service_id == "ramflux-relay" => {
            let request: ramflux_node_core::ItestRetentionRecordRequest =
                serde_json::from_slice(&request.body).map_err(|source| {
                    ramflux_node_core::NodeCoreError::ItestJson(source.to_string())
                })?;
            store.record_metadata(request.record.clone())?;
            ramflux_transport::write_mesh_json_response(stream, "200 OK", &request.record)
                .map_err(|source| {
                    ramflux_node_core::NodeCoreError::ItestHttp(source.to_string())
                })?;
        }
        ("POST", "/retention/v1/object_relay_ttl") => {
            ramflux_transport::write_mesh_text_response(
                stream,
                "403 Forbidden",
                "object relay TTL registration requires ramflux-relay peer",
            )
            .map_err(|source| ramflux_node_core::NodeCoreError::ItestHttp(source.to_string()))?;
        }
        _ => {
            ramflux_transport::write_mesh_text_response(stream, "404 Not Found", "not found")
                .map_err(|source| {
                    ramflux_node_core::NodeCoreError::ItestHttp(source.to_string())
                })?;
        }
    }
    Ok(true)
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

#[cfg(feature = "itest-http")]
fn retention_node_signer(
    config: &ramflux_node_core::NodeServiceConfig,
) -> ramflux_node_core::RetentionNodeSigner {
    let signing_seed = std::env::var("RAMFLUX_FEDERATION_NODE_SIGNING_SEED_B64URL")
        .ok()
        .and_then(|encoded| ramflux_protocol::decode_base64url(&encoded).ok())
        .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
        .unwrap_or_else(|| {
            ramflux_crypto::blake3_256(
                "ramflux.retention.dev_node_signing_seed.v1",
                config.node_id.as_bytes(),
            )
        });
    ramflux_node_core::RetentionNodeSigner {
        node_id: config.node_id.clone(),
        node_epoch: 1,
        signing_key_id: format!("{}#node", config.node_id),
        signing_seed,
    }
}

fn now_unix_seconds() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |duration| duration.as_secs())
}
