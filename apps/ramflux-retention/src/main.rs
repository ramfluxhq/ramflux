// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use std::sync::Arc;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[cfg(feature = "itest-http")]
use std::net::{TcpListener, TcpStream};

const RETENTION_ASYNC_INGRESS_ENV: &str = "RAMFLUX_RETENTION_ASYNC_INGRESS";
const RETENTION_ASYNC_LISTEN_ADDR_ENV: &str = "RAMFLUX_RETENTION_ASYNC_LISTEN_ADDR";
const RETENTION_ASYNC_INGRESS_RUNTIME_ENV: &str = "RAMFLUX_RETENTION_ASYNC_INGRESS_RUNTIME";
const DEFAULT_RETENTION_ASYNC_LISTEN_ADDR: &str = "0.0.0.0:17446";

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
        if retention_async_ingress_enabled()
            && let Some(listen_addr) = retention_async_listen_addr()
        {
            spawn_retention_async_mesh_quic_listener(
                listen_addr,
                mesh_tls_config(&config),
                Arc::clone(&store),
                Arc::new(config.clone()),
            )?;
        }
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

fn retention_async_ingress_enabled() -> bool {
    retention_async_ingress_enabled_from_value(
        std::env::var(RETENTION_ASYNC_INGRESS_ENV).ok().as_deref(),
    )
}

fn retention_async_ingress_enabled_from_value(value: Option<&str>) -> bool {
    let Some(value) = value else {
        return true;
    };
    let trimmed = value.trim();
    !(trimmed == "0"
        || trimmed.eq_ignore_ascii_case("false")
        || trimmed.eq_ignore_ascii_case("off")
        || trimmed.eq_ignore_ascii_case("no"))
}

fn retention_async_listen_addr() -> Option<String> {
    retention_async_listen_addr_from_value(
        std::env::var(RETENTION_ASYNC_LISTEN_ADDR_ENV).ok().as_deref(),
    )
}

fn retention_async_listen_addr_from_value(value: Option<&str>) -> Option<String> {
    let Some(value) = value else {
        return Some(DEFAULT_RETENTION_ASYNC_LISTEN_ADDR.to_owned());
    };
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }
    if trimmed.starts_with("${") {
        return Some(DEFAULT_RETENTION_ASYNC_LISTEN_ADDR.to_owned());
    }
    Some(trimmed.to_owned())
}

fn spawn_retention_async_mesh_quic_listener(
    listen_addr: String,
    tls: ramflux_transport::MeshTlsConfig,
    store: Arc<ramflux_node_core::RetentionRedbStore>,
    config: Arc<ramflux_node_core::NodeServiceConfig>,
) -> Result<(), ramflux_node_core::NodeCoreError> {
    let runtime = std::env::var(RETENTION_ASYNC_INGRESS_RUNTIME_ENV)
        .ok()
        .unwrap_or_else(|| "tokio".to_owned());
    if !runtime.trim().starts_with("${") && !matches!(runtime.trim(), "" | "tokio" | "quinn") {
        tracing::warn!(
            runtime = %runtime,
            "unsupported retention async ingress runtime; using tokio"
        );
    }
    thread::Builder::new()
        .name("ramflux-retention-async-quic-ingress".to_owned())
        .spawn(move || {
            if let Err(error) =
                run_retention_async_mesh_quic_listener(&listen_addr, &tls, store, config)
            {
                tracing::error!(%error, "retention async QUIC ingress stopped");
            }
        })
        .map_err(|source| ramflux_node_core::NodeCoreError::ItestHttp(source.to_string()))?;
    Ok(())
}

fn run_retention_async_mesh_quic_listener(
    listen_addr: &str,
    tls: &ramflux_transport::MeshTlsConfig,
    store: Arc<ramflux_node_core::RetentionRedbStore>,
    config: Arc<ramflux_node_core::NodeServiceConfig>,
) -> Result<(), ramflux_node_core::NodeCoreError> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|source| ramflux_node_core::NodeCoreError::ItestHttp(source.to_string()))?;
    runtime.block_on(async move {
        let root_pems_provider = Arc::new(|| Ok(Vec::new()));
        let server = ramflux_transport::MeshQuicServer::bind_with_pem_roots_provider(
            listen_addr,
            tls,
            root_pems_provider,
        )
        .map_err(|error| retention_transport_error(&error))?;
        let local_addr = server.local_addr().map_err(|error| retention_transport_error(&error))?;
        tracing::info!(addr = %local_addr, "retention async QUIC ingress listening");
        loop {
            let connection = match server.accept_connection().await {
                Ok(connection) => connection,
                Err(error) => {
                    tracing::warn!(%error, "retention async QUIC connection rejected");
                    continue;
                }
            };
            let store = Arc::clone(&store);
            let config = Arc::clone(&config);
            tokio::spawn(async move {
                if let Err(error) =
                    retention_async_quic_connection_loop(connection, store, config).await
                {
                    tracing::debug!(%error, "retention async QUIC connection ended");
                }
            });
        }
    })
}

async fn retention_async_quic_connection_loop(
    connection: ramflux_transport::MeshQuicConnection,
    store: Arc<ramflux_node_core::RetentionRedbStore>,
    config: Arc<ramflux_node_core::NodeServiceConfig>,
) -> Result<(), ramflux_node_core::NodeCoreError> {
    let peer = ramflux_node_core::authorize_mesh_peer(
        &config.service_id,
        &config.mesh.allowed_service_ids,
        connection.peer_spiffe_uri(),
    )?;
    let peer_service_id = Arc::new(peer.service_id);
    loop {
        let accepted = match ramflux_transport::MeshQuicServer::accept_request_on_connection(
            &connection,
        )
        .await
        {
            Ok(accepted) => accepted,
            Err(error) => {
                tracing::debug!(%error, "retention async QUIC stream loop ended");
                return Ok(());
            }
        };
        let store = Arc::clone(&store);
        let peer_service_id = Arc::clone(&peer_service_id);
        tokio::spawn(async move {
            if let Err(error) =
                handle_retention_async_quic_request(accepted, store, &peer_service_id).await
            {
                tracing::warn!(%error, "retention async QUIC request failed");
            }
        });
    }
}

async fn handle_retention_async_quic_request(
    accepted: ramflux_transport::MeshQuicAcceptedRequest,
    store: Arc<ramflux_node_core::RetentionRedbStore>,
    peer_service_id: &str,
) -> Result<(), ramflux_node_core::NodeCoreError> {
    let response = handle_retention_quic_request_value(&accepted.request, &store, peer_service_id)?;
    if (200..300).contains(&response.status) {
        accepted
            .write_json_response(response.status, &response.body)
            .await
            .map_err(|error| retention_transport_error(&error))
    } else {
        accepted
            .write_text_response(response.status, retention_quic_error_text(&response.body))
            .await
            .map_err(|error| retention_transport_error(&error))
    }
}

fn handle_retention_quic_request_value(
    request: &ramflux_transport::GatewayQuicRequest,
    store: &ramflux_node_core::RetentionRedbStore,
    peer_service_id: &str,
) -> Result<ramflux_transport::GatewayQuicResponse, ramflux_node_core::NodeCoreError> {
    tracing::info!(
        method = %request.method,
        path = %request.path,
        peer_service_id,
        "retention async QUIC request received"
    );
    match (request.method.as_str(), request.path.as_str()) {
        ("POST", "/retention/v1/object_relay_ttl") if peer_service_id == "ramflux-relay" => {
            let request: ramflux_node_core::RetentionRecordRequest =
                serde_json::from_value(request.body.clone()).map_err(|source| {
                    ramflux_node_core::NodeCoreError::ItestJson(source.to_string())
                })?;
            store.record_metadata(request.record.clone())?;
            Ok(ramflux_transport::GatewayQuicResponse {
                status: 200,
                body: serde_json::to_value(&request.record).map_err(|source| {
                    ramflux_node_core::NodeCoreError::ItestJson(source.to_string())
                })?,
            })
        }
        ("POST", "/retention/v1/object_relay_ttl") => Ok(retention_text_quic_response(
            403,
            "object relay TTL registration requires ramflux-relay peer",
        )),
        _ => Ok(retention_text_quic_response(404, "not found")),
    }
}

fn retention_text_quic_response(status: u16, body: &str) -> ramflux_transport::GatewayQuicResponse {
    ramflux_transport::GatewayQuicResponse { status, body: serde_json::json!({ "error": body }) }
}

fn retention_quic_error_text(body: &serde_json::Value) -> &str {
    body.get("error").and_then(serde_json::Value::as_str).unwrap_or("retention mesh request failed")
}

fn retention_transport_error(
    error: &ramflux_transport::TransportError,
) -> ramflux_node_core::NodeCoreError {
    ramflux_node_core::NodeCoreError::ItestHttp(error.to_string())
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
            let request: ramflux_node_core::RetentionRecordRequest =
                serde_json::from_slice(&request.body).map_err(|source| {
                    ramflux_node_core::NodeCoreError::ItestJson(source.to_string())
                })?;
            store.record_metadata(request.record.clone())?;
            ramflux_node_core::write_itest_json_response(stream, "200 OK", &request.record)?;
        }
        ("POST", "/mvp7/retention/gc") => {
            let request: ramflux_node_core::RetentionGcRequest =
                serde_json::from_slice(&request.body).map_err(|source| {
                    ramflux_node_core::NodeCoreError::ItestJson(source.to_string())
                })?;
            let response = store.gc_expired(request.now)?;
            ramflux_node_core::write_itest_json_response(stream, "200 OK", &response)?;
        }
        ("POST", "/mvp7/retention/finalize_identity_delete") => {
            let request: ramflux_node_core::RetentionIdentityDeleteRequest =
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
            let request: ramflux_node_core::RetentionRecordRequest =
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

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;

    #[test]
    fn retention_async_ingress_defaults_on_and_opt_out_disables_it() {
        assert!(retention_async_ingress_enabled_from_value(None));
        assert!(retention_async_ingress_enabled_from_value(Some("1")));
        assert!(retention_async_ingress_enabled_from_value(Some("true")));
        assert!(retention_async_ingress_enabled_from_value(Some(
            "${RAMFLUX_RETENTION_ASYNC_INGRESS:-1}"
        )));
        assert!(!retention_async_ingress_enabled_from_value(Some("0")));
        assert!(!retention_async_ingress_enabled_from_value(Some("false")));
        assert!(!retention_async_ingress_enabled_from_value(Some("off")));
        assert!(!retention_async_ingress_enabled_from_value(Some("no")));
    }

    #[test]
    fn retention_async_listen_addr_defaults_and_can_be_cleared() {
        assert_eq!(
            retention_async_listen_addr_from_value(None).as_deref(),
            Some(DEFAULT_RETENTION_ASYNC_LISTEN_ADDR)
        );
        assert_eq!(
            retention_async_listen_addr_from_value(Some(
                "${RAMFLUX_RETENTION_ASYNC_LISTEN_ADDR:-0.0.0.0:17446}"
            ))
            .as_deref(),
            Some(DEFAULT_RETENTION_ASYNC_LISTEN_ADDR)
        );
        assert_eq!(
            retention_async_listen_addr_from_value(Some(" 127.0.0.1:17446 ")).as_deref(),
            Some("127.0.0.1:17446")
        );
        assert!(retention_async_listen_addr_from_value(Some("")).is_none());
    }

    #[test]
    fn retention_quic_mesh_surface_matches_mtls_peer_gate() -> Result<(), Box<dyn std::error::Error>>
    {
        let path = temp_path("retention_quic_mesh_surface_matches_mtls_peer_gate")?;
        let store = ramflux_node_core::RetentionRedbStore::open(&path)?;
        let request = retention_quic_request("/retention/v1/object_relay_ttl")?;

        let rejected = handle_retention_quic_request_value(&request, &store, "ramflux-router")?;
        assert_eq!(rejected.status, 403);

        let accepted = handle_retention_quic_request_value(&request, &store, "ramflux-relay")?;
        assert_eq!(accepted.status, 200);
        let record: ramflux_node_core::RetentionMetadataRecord =
            serde_json::from_value(accepted.body)?;
        assert_eq!(record.record_id, "retention-quic-record");

        let finalize = handle_retention_quic_request_value(
            &retention_quic_request("/mvp7/retention/finalize_identity_delete")?,
            &store,
            "ramflux-relay",
        )?;
        assert_eq!(finalize.status, 404);

        let gc = handle_retention_quic_request_value(
            &retention_quic_request("/mvp7/retention/gc")?,
            &store,
            "ramflux-relay",
        )?;
        assert_eq!(gc.status, 404);

        let _removed = std::fs::remove_file(&path);
        let _removed = std::fs::remove_dir_all(path.with_extension("redb.wal"));
        Ok(())
    }

    fn retention_quic_request(
        path: &str,
    ) -> Result<ramflux_transport::GatewayQuicRequest, Box<dyn std::error::Error>> {
        Ok(ramflux_transport::GatewayQuicRequest {
            method: "POST".to_owned(),
            path: path.to_owned(),
            body: serde_json::to_value(ramflux_node_core::RetentionRecordRequest {
                record: retention_record(),
            })?,
        })
    }

    fn retention_record() -> ramflux_node_core::RetentionMetadataRecord {
        ramflux_node_core::RetentionMetadataRecord {
            record_id: "retention-quic-record".to_owned(),
            subject_hash: "subject-hash".to_owned(),
            metadata_class: "object_relay_ttl".to_owned(),
            source_service_id: "ramflux-relay".to_owned(),
            retention_policy_id: "relay-cache".to_owned(),
            created_at: 1,
            expires_at: 600,
            delete_after_ack: None,
            legal_hold: false,
            legal_hold_next_review_at: None,
            legal_basis: None,
            legal_hold_actor: None,
            legal_hold_created_at: None,
            metadata_hash: "metadata-hash".to_owned(),
        }
    }

    fn temp_path(test_name: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
        let elapsed = SystemTime::now().duration_since(UNIX_EPOCH)?;
        Ok(std::env::temp_dir().join(format!(
            "ramflux-retention-{test_name}-{}-{}",
            std::process::id(),
            elapsed.as_nanos()
        )))
    }
}
