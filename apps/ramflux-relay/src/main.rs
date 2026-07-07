// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[cfg(feature = "itest-http")]
use std::io::Write as _;
#[cfg(feature = "itest-http")]
use std::net::{TcpListener, TcpStream};

const RETENTION_ASYNC_ENDPOINT_ENV: &str = "RAMFLUX_RETENTION_ASYNC_ENDPOINT";
const RETENTION_ASYNC_SERVER_NAME_ENV: &str = "RAMFLUX_RETENTION_ASYNC_SERVER_NAME";
const RETENTION_ASYNC_PEER_CA_PEM_ENV: &str = "RAMFLUX_RETENTION_ASYNC_PEER_CA_PEM";
const RETENTION_ASYNC_PEER_CA_PEM_FILE_ENV: &str = "RAMFLUX_RETENTION_ASYNC_PEER_CA_PEM_FILE";
const DEFAULT_RETENTION_ASYNC_ENDPOINT: &str = "ramflux-retention:17446";

fn main() {
    if let Err(error) = run_service("ramflux-relay") {
        eprintln!("ramflux-relay: {error}");
        std::process::exit(2);
    }
}

fn run_service(service: &'static str) -> anyhow::Result<()> {
    if std::env::args().any(|arg| arg == "--health-check") {
        println!("{service}:healthy");
        return Ok(());
    }
    tracing_subscriber::fmt().with_target(false).init();
    if let Some(config) =
        ramflux_node_core::load_config_from_args(std::env::args().skip(1), service)?
    {
        let redb_path = ramflux_node_core::effective_redb_path(&config);
        let store = Arc::new(ramflux_node_core::RelayRedbStore::open(&redb_path)?);
        let state = match store.load_state()? {
            Some(state) => state,
            None => ramflux_node_core::RelayCacheState::new(),
        };
        let state = Arc::new(Mutex::new(state));
        let service_key = relay_service_key(&config)?;
        let retention_client = retention_mesh_client(&config)?;
        start_expire_scheduler(Arc::clone(&store), Arc::clone(&state));
        serve_relay_mesh_mtls(
            &config,
            Arc::clone(&store),
            Arc::clone(&state),
            service_key.clone(),
            retention_client.clone(),
        )?;
        serve_media_relay_udp(service_key.clone())?;
        tracing::info!(service, node_id = config.node_id, "relay cache initialized");
        #[cfg(feature = "itest-http")]
        if std::env::var("RAMFLUX_ITEST_HTTP").as_deref() == Ok("1") {
            return serve_itest_http(
                &store,
                &state,
                &config,
                service_key.as_slice(),
                &retention_client,
            );
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
    store: Arc<ramflux_node_core::RelayRedbStore>,
    state: Arc<Mutex<ramflux_node_core::RelayCacheState>>,
    config: ramflux_node_core::NodeServiceConfig,
    service_key: Vec<u8>,
    retention_client: RetentionMeshClient,
}

#[cfg(feature = "itest-http")]
fn serve_itest_http(
    store: &Arc<ramflux_node_core::RelayRedbStore>,
    state: &Arc<Mutex<ramflux_node_core::RelayCacheState>>,
    config: &ramflux_node_core::NodeServiceConfig,
    service_key: &[u8],
    retention_client: &RetentionMeshClient,
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
        service_key: service_key.to_vec(),
        retention_client: retention_client.clone(),
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
    if request.method == "GET" && request.path == "/healthz" {
        write_relay_itest_response(
            stream,
            &handle_relay_request_value(
                &request.method,
                &request.path,
                &request.body,
                &RelayHandlerContext {
                    store: &ingress.store,
                    state: &ingress.state,
                    config: &ingress.config,
                    service_key: ingress.service_key.as_slice(),
                    retention_client: &ingress.retention_client,
                },
                RelayRequestPeer::Itest,
            )?,
        )?;
        return Ok(());
    }
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

#[cfg(feature = "itest-http")]
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

#[derive(Clone, Copy)]
enum RelayRequestPeer<'a> {
    #[cfg(feature = "itest-http")]
    Itest,
    Mesh {
        peer_service_id: &'a str,
    },
}

enum RelayResponseValue {
    Json { status: &'static str, value: serde_json::Value },
    Text { status: &'static str, body: String },
}

struct RelayHandlerContext<'a> {
    store: &'a ramflux_node_core::RelayRedbStore,
    state: &'a Mutex<ramflux_node_core::RelayCacheState>,
    config: &'a ramflux_node_core::NodeServiceConfig,
    service_key: &'a [u8],
    retention_client: &'a RetentionMeshClient,
}

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

#[cfg(feature = "itest-http")]
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
            let entry = {
                let mut state = lock_relay_state(context.state)?;
                state.put_object_chunk_frame(frame, context.service_key, now)?
            };
            context.store.record_relay_chunk_entry(&entry)?;
            register_object_relay_ttl(context.config, context.retention_client, &entry, now)?;
            serde_json::to_value(ramflux_node_core::ObjectRelayPutResponse::from(entry))
                .map_err(|source| ramflux_node_core::NodeCoreError::ItestJson(source.to_string()))
        }
        ("POST", "/relay/v1/object/get_chunk") => {
            let request: ramflux_node_core::ObjectRelayGetRequest = serde_json::from_slice(body)
                .map_err(|source| {
                    ramflux_node_core::NodeCoreError::ItestJson(source.to_string())
                })?;
            let state = lock_relay_state(context.state)?;
            let chunk = state.get_object_chunk(
                &request.chunk_id,
                &request.relay_token,
                &request.object_permission_envelope,
                context.service_key,
                now_unix_seconds(),
            )?;
            serde_json::to_value(ramflux_node_core::ObjectRelayGetResponse { chunk })
                .map_err(|source| ramflux_node_core::NodeCoreError::ItestJson(source.to_string()))
        }
        ("POST", "/relay/v1/object/ack") => {
            let ack: ramflux_node_core::ObjectRelayAck =
                serde_json::from_slice(body).map_err(|source| {
                    ramflux_node_core::NodeCoreError::ItestJson(source.to_string())
                })?;
            let chunk = {
                let mut state = lock_relay_state(context.state)?;
                state.ack_object_chunk(ack, context.service_key, now_unix_seconds())?
            };
            context.store.record_relay_chunk_entry(&chunk)?;
            serde_json::to_value(ramflux_node_core::ObjectRelayAckResponse {
                chunk_id: chunk.chunk_id,
                status: chunk.status,
                acked_by_count: chunk.acked_by.len(),
            })
            .map_err(|source| ramflux_node_core::NodeCoreError::ItestJson(source.to_string()))
        }
        ("POST", "/relay/v1/object/tombstone") => {
            let tombstone: ramflux_node_core::ObjectRelayTombstone = serde_json::from_slice(body)
                .map_err(|source| {
                ramflux_node_core::NodeCoreError::ItestJson(source.to_string())
            })?;
            let mutation = {
                let mut state = lock_relay_state(context.state)?;
                state.apply_object_tombstone_mutation(
                    tombstone,
                    context.service_key,
                    now_unix_seconds(),
                )?
            };
            context.store.record_relay_tombstone_mutation(&mutation)?;
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

fn lock_relay_state(
    state: &Mutex<ramflux_node_core::RelayCacheState>,
) -> Result<
    std::sync::MutexGuard<'_, ramflux_node_core::RelayCacheState>,
    ramflux_node_core::NodeCoreError,
> {
    state.lock().map_err(|source| ramflux_node_core::NodeCoreError::ItestHttp(source.to_string()))
}

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
    let mutation = {
        let mut state = lock_relay_state(state)?;
        state.expire_chunks_mutation(now_unix_seconds())
    };
    let expired = mutation.expired_count();
    if !mutation.is_empty() {
        store.record_relay_expiry_mutation(&mutation)?;
    }
    tracing::info!(expired, "relay background object chunk expiry completed");
    Ok(())
}

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
struct RetentionMeshClient {
    blocking: ramflux_transport::MeshHttpClient,
    async_mesh: Option<RetentionAsyncMeshClient>,
}

#[derive(Clone)]
struct RetentionAsyncMeshClient {
    endpoint: String,
    server_name: String,
    tls: ramflux_transport::MeshTlsConfig,
    peer_ca_pems: Vec<String>,
}

fn retention_mesh_client(
    config: &ramflux_node_core::NodeServiceConfig,
) -> anyhow::Result<RetentionMeshClient> {
    Ok(RetentionMeshClient {
        blocking: ramflux_transport::MeshHttpClient::new(),
        async_mesh: retention_async_mesh_client(config)?,
    })
}

fn retention_async_mesh_client(
    config: &ramflux_node_core::NodeServiceConfig,
) -> anyhow::Result<Option<RetentionAsyncMeshClient>> {
    retention_async_mesh_client_from_endpoint_value(
        config,
        std::env::var(RETENTION_ASYNC_ENDPOINT_ENV).ok().as_deref(),
    )
}

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

fn is_env_disabled(value: &str) -> bool {
    value == "0"
        || value.eq_ignore_ascii_case("false")
        || value.eq_ignore_ascii_case("off")
        || value.eq_ignore_ascii_case("no")
}

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

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::sync::mpsc;

    use super::*;

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

    fn test_relay_chunk_entry() -> ramflux_node_core::RelayChunkEntry {
        ramflux_node_core::RelayChunkEntry {
            chunk_id: "chunk-retention-quic-fallback".to_owned(),
            object_id: "object-retention-quic-fallback".to_owned(),
            manifest_hash: "manifest-hash".to_owned(),
            chunk_index: 0,
            chunk_cipher_hash: "chunk-cipher-hash".to_owned(),
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

    fn test_error(message: impl Into<String>) -> Box<dyn std::error::Error> {
        message.into().into()
    }
}
