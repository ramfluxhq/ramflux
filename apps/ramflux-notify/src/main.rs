// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![cfg_attr(not(feature = "itest-http"), allow(dead_code))]

mod provider_issuance;
mod provider_outcome;
use provider_issuance::SendBoundary;
mod provider_payload;
mod push_registration;
mod retention;
mod send_authority;

use std::collections::{BTreeSet, HashMap};
use std::fmt::Write as FmtWrite;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::Once;
use std::time::Duration;

#[cfg(feature = "itest-http")]
use std::net::{TcpListener, TcpStream};

static RUSTLS_PROVIDER: Once = Once::new();
static JWT_PROVIDER: Once = Once::new();

const NOTIFY_RUNTIME_ENV: &str = "RAMFLUX_NOTIFY_RUNTIME";
const NOTIFY_ASYNC_ACCEPT_ENV: &str = "RAMFLUX_NOTIFY_ASYNC_ACCEPT";
const NOTIFY_ASYNC_INGRESS_ENV: &str = "RAMFLUX_NOTIFY_ASYNC_INGRESS";
const NOTIFY_WAL_RAW_ENQUEUE_ENV: &str = "RAMFLUX_NOTIFY_WAL_RAW_ENQUEUE";
const NOTIFY_BATCH_VERIFY_ENV: &str = "RAMFLUX_NOTIFY_BATCH_VERIFY";
const NOTIFY_VERIFY_BATCH_MAX_ENV: &str = "RAMFLUX_NOTIFY_VERIFY_BATCH_MAX";
const NOTIFY_VERIFY_WINDOW_US_ENV: &str = "RAMFLUX_NOTIFY_VERIFY_WINDOW_US";
const NOTIFY_MESH_INGRESS_ENV: &str = "RAMFLUX_NOTIFY_MESH_INGRESS";
const NOTIFY_MESH_LISTEN_ADDR_ENV: &str = "RAMFLUX_NOTIFY_MESH_LISTEN_ADDR";
const NOTIFY_MESH_INGRESS_RUNTIME_ENV: &str = "RAMFLUX_NOTIFY_MESH_INGRESS_RUNTIME";
const DEFAULT_NOTIFY_MESH_LISTEN_ADDR: &str = "0.0.0.0:18085";

fn main() {
    if let Err(error) = run_service("ramflux-notify") {
        eprintln!("ramflux-notify: {error}");
        std::process::exit(2);
    }
}

fn run_service(service: &'static str) -> Result<(), ramflux_node_core::NodeCoreError> {
    if std::env::args().any(|arg| arg == "--health-check") {
        println!("{service}:healthy");
        return Ok(());
    }
    let shutdown = ramflux_node_core::ServiceShutdown::install(service)?;
    tracing_subscriber::fmt().with_target(false).init();
    if let Some(config) =
        ramflux_node_core::load_config_from_args(std::env::args().skip(1), service)?
    {
        let route_key =
            ramflux_node_core::NodeSecret::required_env("RAMFLUX_NOTIFY_ROUTE_KEY_FILE")?;
        let redb_path = ramflux_node_core::effective_redb_path(&config);
        if let Some(parent) = std::path::Path::new(&redb_path).parent() {
            std::fs::create_dir_all(parent)
                .map_err(|error| ramflux_node_core::NodeCoreError::Redb(error.to_string()))?;
        }
        let secret_path = ramflux_node_core::environment::var_os("RAMFLUX_NOTIFY_ROUTE_KEY_FILE")
            .ok_or_else(|| {
            ramflux_node_core::NodeCoreError::Unauthorized("mounted notify secret required".into())
        })?;
        ramflux_node_core::NodeSecret::require_external_path(
            std::path::Path::new(&secret_path),
            std::path::Path::new(&redb_path),
        )?;
        let mut store =
            ramflux_node_core::NotifyRedbStore::open_with_route_key(redb_path, route_key)?;
        let authority = Arc::new(send_authority::Surface::new(&config, &store)?);
        authority.configure_reader(&mut store);
        push_registration::configure(&mut store, &config)?;
        let store = Arc::new(store);
        log_notify_wal_recovery(&store);
        store.drop_legacy_pending_wakes()?;
        retention::start(Arc::clone(&store))?;
        let state = match store.load_state()? {
            Some(state) => state,
            None => ramflux_node_core::NotifyQueueState::new(),
        };
        if !store.uses_notify_wal() {
            store.save_queue_state(&state)?;
        }
        tracing::info!(service, node_id = config.node_id, "notify queue initialized");
        if std::env::args().any(|arg| arg == "--once") {
            return Ok(());
        }
        let async_accept = notify_async_accept_enabled();
        if async_accept {
            start_notify_async_delivery_workers(&store)?;
        }
        let store_gate = Arc::new(Mutex::new(()));
        let runtime = Arc::new(NotifyRuntime::from_env(&store, &store_gate)?);
        let wake_auth = NotifyWakeAuth::from_config(&config)?;
        let wake_verify_batcher = NotifyWakeVerifyBatcher::from_env(&wake_auth, &store)?;
        let ingress = Arc::new(NotifyIngressState {
            authority,
            store,
            runtime,
            store_gate,
            async_accept,
            wake_auth,
            wake_verify_batcher,
        });
        if notify_mesh_ingress_enabled()
            && let Some(listen_addr) = notify_mesh_listen_addr()
        {
            serve_notify_mesh_quic(&listen_addr, &ingress, &notify_mesh_tls_config(&config))?;
        }
        #[cfg(feature = "itest-http")]
        if ramflux_node_core::environment::var("RAMFLUX_ITEST_HTTP").ok().as_deref() == Some("1") {
            let itest_ingress = Arc::clone(&ingress);
            ramflux_node_core::spawn_service_worker("ramflux-notify-itest-http", move |_| {
                if let Err(error) = serve_itest_http(&itest_ingress) {
                    tracing::error!(%error, "notify itest HTTP listener stopped");
                }
            })?;
        }
        return shutdown.wait_and_finalize(move || {
            ramflux_node_core::ensure_exclusive_service_owner(&ingress)?;
            let store = Arc::clone(&ingress.store);
            drop(ingress);
            ramflux_node_core::ensure_exclusive_service_owner(&store)?;
            drop(store);
            Ok(())
        });
    }
    tracing::info!(service, "service initialized");
    if std::env::args().any(|arg| arg == "--once") {
        return Ok(());
    }
    shutdown.wait_and_finalize(|| Ok(()))
}

struct NotifyIngressState {
    authority: Arc<send_authority::Surface>,
    store: Arc<ramflux_node_core::NotifyRedbStore>,
    runtime: Arc<NotifyRuntime>,
    store_gate: Arc<Mutex<()>>,
    async_accept: bool,
    wake_auth: NotifyWakeAuth,
    wake_verify_batcher: Option<NotifyWakeVerifyBatcher>,
}

#[derive(Clone)]
struct NotifyWakeAuth {
    key: ramflux_node_core::NodeServiceSigningKey,
}

impl NotifyWakeAuth {
    fn from_config(
        config: &ramflux_node_core::NodeServiceConfig,
    ) -> Result<Self, ramflux_node_core::NodeCoreError> {
        let key = ramflux_node_core::require_node_service_signing_key(config)?;
        Ok(Self { key })
    }

    fn verify_signed(
        &self,
        signed: &ramflux_protocol::SignedWakeV2,
    ) -> Result<(), ramflux_node_core::NodeCoreError> {
        self.key.verify_wake_v2(signed)
    }
}

#[derive(Clone)]
struct NotifyWakeVerifyBatcher {
    senders: Arc<Vec<tokio::sync::mpsc::Sender<WakeVerifyRequest>>>,
}

impl NotifyWakeVerifyBatcher {
    fn from_env(
        wake_auth: &NotifyWakeAuth,
        store: &Arc<ramflux_node_core::NotifyRedbStore>,
    ) -> Result<Option<Self>, ramflux_node_core::NodeCoreError> {
        if !notify_batch_verify_enabled() {
            return Ok(None);
        }
        let batch_max = notify_runtime_usize_env(NOTIFY_VERIFY_BATCH_MAX_ENV, || 1024).max(1);
        let window_us = notify_runtime_usize_env(NOTIFY_VERIFY_WINDOW_US_ENV, || 1_000);
        let window = Duration::from_micros(u64::try_from(window_us).unwrap_or(u64::MAX));
        let capacity = batch_max.saturating_mul(64).max(1);
        let shard_count = store.notify_ingest_shard_count();
        let mut senders = Vec::with_capacity(shard_count);
        for shard_id in 0..shard_count {
            let (sender, receiver) = tokio::sync::mpsc::channel(capacity);
            let thread_auth = wake_auth.clone();
            let thread_store = Arc::clone(store);
            ramflux_node_core::spawn_service_worker(
                format!("ramflux-notify-wake-verify-batcher-{shard_id}"),
                move |_| {
                    wake_verify_batcher_loop(
                        &thread_auth,
                        &thread_store,
                        shard_id,
                        receiver,
                        batch_max,
                        window,
                    );
                },
            )
            .map_err(|source| ramflux_node_core::NodeCoreError::ItestHttp(source.to_string()))?;
            senders.push(sender);
        }
        tracing::info!(
            batch_max,
            window_us = window.as_micros(),
            capacity,
            shard_count,
            "notify wake batch verifier started"
        );
        Ok(Some(Self { senders: Arc::new(senders) }))
    }

    async fn verify_and_enqueue(
        &self,
        shard_id: usize,
        signed: ramflux_protocol::SignedWakeV2,
        device_delivery_id: String,
        raw_body: Vec<u8>,
        queued_at: u64,
    ) -> Result<(), ramflux_node_core::NodeCoreError> {
        let (reply, response) = tokio::sync::oneshot::channel();
        let sender = self.senders.get(shard_id).ok_or_else(|| {
            ramflux_node_core::NodeCoreError::ItestHttp(format!(
                "notify wake verifier shard {shard_id} not available"
            ))
        })?;
        sender
            .send(WakeVerifyRequest { signed, device_delivery_id, raw_body, queued_at, reply })
            .await
            .map_err(|source| {
                ramflux_node_core::NodeCoreError::ItestHttp(format!(
                    "notify wake verifier stopped: {source}"
                ))
            })?;
        response.await.map_err(|source| {
            ramflux_node_core::NodeCoreError::ItestHttp(format!(
                "notify wake verifier response dropped: {source}"
            ))
        })?
    }
}

struct WakeVerifyRequest {
    signed: ramflux_protocol::SignedWakeV2,
    device_delivery_id: String,
    raw_body: Vec<u8>,
    queued_at: u64,
    reply: tokio::sync::oneshot::Sender<Result<(), ramflux_node_core::NodeCoreError>>,
}

fn wake_verify_batcher_loop(
    wake_auth: &NotifyWakeAuth,
    store: &ramflux_node_core::NotifyRedbStore,
    shard_id: usize,
    mut receiver: tokio::sync::mpsc::Receiver<WakeVerifyRequest>,
    batch_max: usize,
    window: Duration,
) {
    let shutdown = ramflux_node_core::service_shutdown_token();
    while !shutdown.is_cancelled() {
        let first = match receiver.try_recv() {
            Ok(request) => request,
            Err(tokio::sync::mpsc::error::TryRecvError::Empty) => {
                std::thread::sleep(Duration::from_millis(10));
                continue;
            }
            Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => break,
        };
        let mut batch = Vec::with_capacity(batch_max);
        batch.push(first);
        let deadline = std::time::Instant::now() + window;
        while batch.len() < batch_max {
            match receiver.try_recv() {
                Ok(request) => batch.push(request),
                Err(tokio::sync::mpsc::error::TryRecvError::Empty) => {
                    if std::time::Instant::now() >= deadline {
                        break;
                    }
                    std::thread::sleep(Duration::from_micros(50));
                }
                Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => break,
            }
        }
        verify_and_enqueue_wake_batch(wake_auth, store, shard_id, batch);
    }
}

fn verify_and_enqueue_wake_batch(
    wake_auth: &NotifyWakeAuth,
    store: &ramflux_node_core::NotifyRedbStore,
    shard_id: usize,
    batch: Vec<WakeVerifyRequest>,
) {
    let mut valid = Vec::new();
    let mut replies = Vec::new();
    for request in batch {
        let bound = request.signed.body.target_delivery_id == request.device_delivery_id;
        if wake_auth.verify_signed(&request.signed).is_err() || !bound {
            let _ = request.reply.send(Err(ramflux_node_core::NodeCoreError::Unauthorized(
                "notify wake signature rejected".to_owned(),
            )));
            continue;
        }
        if request.signed.body.action != ramflux_protocol::WakeAction::Enqueue {
            let _ = request.reply.send(Ok(()));
            continue;
        }
        if ramflux_node_core::project_wake_v2(&request.signed, request.queued_at).is_err() {
            let _ =
                request.reply.send(Err(ramflux_node_core::NodeCoreError::InvalidConfiguration(
                    "wake contract rejected".to_owned(),
                )));
            continue;
        }
        valid.push((request.raw_body, request.queued_at));
        replies.push(request.reply);
    }
    if valid.is_empty() {
        return;
    }
    let result = store
        .queue_raw_wakes_for_async_accept_shard_batch(shard_id, valid)
        .map(|_raws| ())
        .map_err(|error| ramflux_node_core::NodeCoreError::ItestHttp(error.to_string()));
    match result {
        Ok(()) => {
            for reply in replies {
                let _ = reply.send(Ok(()));
            }
        }
        Err(error) => {
            let message = error.to_string();
            for reply in replies {
                let _ =
                    reply.send(Err(ramflux_node_core::NodeCoreError::ItestHttp(message.clone())));
            }
        }
    }
}

fn notify_batch_verify_enabled() -> bool {
    notify_default_enabled_env(NOTIFY_BATCH_VERIFY_ENV)
}

#[cfg(feature = "itest-http")]
fn itest_error_status(error: &ramflux_node_core::NodeCoreError) -> &'static str {
    match error {
        ramflux_node_core::NodeCoreError::Unauthorized(_message) => "401 Unauthorized",
        _ => "500 Internal Server Error",
    }
}

fn notify_mesh_error_status(error: &ramflux_node_core::NodeCoreError) -> u16 {
    match error {
        ramflux_node_core::NodeCoreError::Unauthorized(_message) => 401,
        ramflux_node_core::NodeCoreError::PushRouteOwnerMismatch => 403,
        _ => 500,
    }
}

#[cfg(feature = "itest-http")]
fn serve_itest_http(
    ingress: &Arc<NotifyIngressState>,
) -> Result<(), ramflux_node_core::NodeCoreError> {
    if notify_async_ingress_enabled() {
        return serve_itest_http_async(ingress);
    }
    let addr = ramflux_node_core::environment::var("RAMFLUX_ITEST_NOTIFY_HTTP_ADDR")
        .unwrap_or_else(|_| "0.0.0.0:18083".to_owned());
    let listener = TcpListener::bind(&addr)
        .map_err(|source| ramflux_node_core::NodeCoreError::ItestHttp(source.to_string()))?;
    listener
        .set_nonblocking(true)
        .map_err(|source| ramflux_node_core::NodeCoreError::ItestHttp(source.to_string()))?;
    let worker_count = notify_ingress_worker_count();
    let queue_capacity = worker_count.saturating_mul(4).max(1);
    let (sender, receiver) = std::sync::mpsc::sync_channel(queue_capacity);
    let receiver = Arc::new(Mutex::new(receiver));
    for worker_id in 0..worker_count {
        let worker_receiver = Arc::clone(&receiver);
        let worker_ingress = Arc::clone(ingress);
        ramflux_node_core::spawn_service_worker(
            format!("ramflux-notify-http-ingress-{worker_id}"),
            move |_| notify_ingress_worker_loop(&worker_receiver, &worker_ingress),
        )
        .map_err(|source| ramflux_node_core::NodeCoreError::ItestHttp(source.to_string()))?;
    }
    tracing::info!(addr, worker_count, queue_capacity, "notify itest HTTP surface listening");
    let mut backoff = ramflux_node_core::ListenerAcceptBackoff::default();
    while !ramflux_node_core::service_shutdown_token().is_cancelled() {
        let stream = match listener.accept().map(|(stream, _)| stream) {
            Ok(stream) => {
                backoff.success();
                stream
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(25));
                continue;
            }
            Err(source) => {
                backoff.wait_after_failure(&source);
                continue;
            }
        };
        if let Err(error) = stream.set_nodelay(true) {
            tracing::debug!(%error, "failed to enable TCP_NODELAY on notify ingress connection");
            continue;
        }
        sender
            .send(stream)
            .map_err(|source| ramflux_node_core::NodeCoreError::ItestHttp(source.to_string()))?;
    }
    Ok(())
}

fn serve_notify_mesh_quic(
    listen_addr: &str,
    ingress: &Arc<NotifyIngressState>,
    tls: &ramflux_transport::MeshTlsConfig,
) -> Result<(), ramflux_node_core::NodeCoreError> {
    match notify_mesh_ingress_runtime() {
        NotifyMeshIngressRuntime::Tokio => {}
    }
    let listen_addr = listen_addr.to_owned();
    let ingress = Arc::clone(ingress);
    let tls = tls.clone();
    ramflux_node_core::spawn_service_worker("ramflux-notify-mesh-quic", move |shutdown| {
        if let Err(error) = run_notify_mesh_quic_listener(&listen_addr, ingress, &tls, shutdown) {
            tracing::error!(%error, "notify mesh QUIC listener stopped");
        }
    })
    .map_err(|source| ramflux_node_core::NodeCoreError::ItestHttp(source.to_string()))?;
    Ok(())
}

fn run_notify_mesh_quic_listener(
    listen_addr: &str,
    ingress: Arc<NotifyIngressState>,
    tls: &ramflux_transport::MeshTlsConfig,
    shutdown: tokio_util::sync::CancellationToken,
) -> Result<(), ramflux_node_core::NodeCoreError> {
    let mut builder = tokio::runtime::Builder::new_current_thread();
    let _threads = ramflux_node_core::track_service_runtime(&mut builder);
    let runtime = builder
        .enable_all()
        .build()
        .map_err(|source| ramflux_node_core::NodeCoreError::ItestHttp(source.to_string()))?;
    let result = runtime.block_on(async move {
        let root_pems_provider = Arc::new(|| Ok(Vec::new()));
        let server = ramflux_transport::MeshQuicServer::bind_with_pem_roots_provider(
            listen_addr,
            tls,
            root_pems_provider,
        )
        .map_err(|error| notify_mesh_transport_error(&error))?;
        let local_addr =
            server.local_addr().map_err(|error| notify_mesh_transport_error(&error))?;
        tracing::info!(addr = %local_addr, "notify mesh QUIC surface listening");
        loop {
            let connection = match tokio::select! {
                () = shutdown.cancelled() => break,
                connection = server.accept_connection() => connection,
            } {
                Ok(connection) => connection,
                Err(error) => {
                    tracing::warn!(%error, "notify mesh QUIC connection rejected");
                    continue;
                }
            };
            let connection_ingress = Arc::clone(&ingress);
            tokio::spawn(async move {
                if let Err(error) =
                    notify_mesh_quic_connection_loop(connection, connection_ingress).await
                {
                    tracing::debug!(%error, "notify mesh QUIC connection ended");
                }
            });
        }
        Ok::<(), ramflux_node_core::NodeCoreError>(())
    });
    ramflux_node_core::drain_service_runtime(runtime);
    result
}

async fn notify_mesh_quic_connection_loop(
    connection: ramflux_transport::MeshQuicConnection,
    ingress: Arc<NotifyIngressState>,
) -> Result<(), ramflux_node_core::NodeCoreError> {
    let peer_identity = connection.peer_spiffe_uri().map(str::to_owned);
    loop {
        let accepted =
            match ramflux_transport::MeshQuicServer::accept_control_request_on_connection(
                &connection,
            )
            .await
            {
                Ok(accepted) => accepted,
                Err(error) => {
                    tracing::debug!(%error, "notify mesh QUIC stream loop ended");
                    return Ok(());
                }
            };
        let request_ingress = Arc::clone(&ingress);
        let peer_identity = peer_identity.clone();
        tokio::spawn(async move {
            let Some(_in_flight) = ramflux_node_core::begin_service_request() else {
                return;
            };
            if let Err(error) =
                handle_notify_mesh_quic_accepted_request(accepted, request_ingress, peer_identity)
                    .await
            {
                tracing::warn!(%error, "notify mesh QUIC request failed");
            }
        });
    }
}

async fn handle_notify_mesh_quic_accepted_request(
    accepted: ramflux_transport::MeshQuicAcceptedRequest,
    ingress: Arc<NotifyIngressState>,
    peer_identity: Option<String>,
) -> Result<(), ramflux_node_core::NodeCoreError> {
    if accepted.request.method == "POST" && send_authority::is_path(&accepted.request.path) {
        let result =
            if let (Some(identity), Some(bytes)) = (peer_identity, accepted.raw_body.clone()) {
                match ingress.authority.admit(&identity) {
                    Ok(admission) => {
                        let path = accepted.request.path.clone();
                        tokio::task::spawn_blocking(move || {
                            ingress.authority.handle(
                                &ingress.store,
                                &identity,
                                &path,
                                &bytes,
                                admission,
                            )
                        })
                        .await
                        .map_err(|e| ramflux_node_core::NodeCoreError::ItestHttp(e.to_string()))
                        .and_then(|r| r)
                    }
                    Err(error) => Err(error),
                }
            } else {
                Err(ramflux_node_core::NodeCoreError::Unauthorized(
                    "authority RPC requires original bytes and mTLS identity".into(),
                ))
            };
        return match result {
            Ok(value) => accepted
                .write_json_response(200, &value)
                .await
                .map_err(|e| notify_mesh_transport_error(&e)),
            Err(error) => accepted
                .write_text_response(notify_mesh_error_status(&error), &error.to_string())
                .await
                .map_err(|e| notify_mesh_transport_error(&e)),
        };
    }
    let route_control = if accepted.request.method == "POST" {
        match accepted.request.path.as_str() {
            ramflux_node_core::PUSH_ROUTE_PATH => Some(true),
            ramflux_node_core::PUSH_ROUTE_DELETE_PATH => Some(false),
            _ => None,
        }
    } else {
        None
    };
    let result = if let Some(register) = route_control {
        // Route control makes blocking router or redb calls; keep it off runtime workers.
        let body = accepted.request.body.clone();
        let ingress = Arc::clone(&ingress);
        tokio::task::spawn_blocking(move || {
            if register {
                push_registration::register(&ingress, body).and_then(|answer| {
                    serde_json::to_value(answer).map_err(|source| {
                        ramflux_node_core::NodeCoreError::ItestJson(source.to_string())
                    })
                })
            } else {
                push_registration::deregister(&ingress, body)
                    .map(|removed| serde_json::json!(removed))
            }
        })
        .await
        .map_err(|error| ramflux_node_core::NodeCoreError::ItestHttp(error.to_string()))
        .and_then(|result| result)
        .map(|value| ramflux_transport::GatewayQuicResponse {
            status: 200,
            body: serde_json::json!(value),
        })
    } else {
        handle_notify_mesh_quic_request(&accepted.request, &ingress)
    };
    match result {
        Ok(response) => accepted
            .write_json_response(response.status, &response.body)
            .await
            .map_err(|error| notify_mesh_transport_error(&error)),
        Err(error) => accepted
            .write_text_response(notify_mesh_error_status(&error), &error.to_string())
            .await
            .map_err(|error| notify_mesh_transport_error(&error)),
    }
}

fn handle_notify_mesh_quic_request(
    request: &ramflux_transport::GatewayQuicRequest,
    ingress: &NotifyIngressState,
) -> Result<ramflux_transport::GatewayQuicResponse, ramflux_node_core::NodeCoreError> {
    match (request.method.as_str(), request.path.as_str()) {
        ("POST", ramflux_node_core::PUSH_ROUTE_PATH) => {
            let answer = push_registration::register(ingress, request.body.clone())?;
            Ok(ramflux_transport::GatewayQuicResponse {
                status: 200,
                body: serde_json::to_value(answer).map_err(|source| {
                    ramflux_node_core::NodeCoreError::ItestJson(source.to_string())
                })?,
            })
        }
        ("POST", "/s13/notify/wake") => {
            let mut body: S13WakeRequest =
                serde_json::from_value(request.body.clone()).map_err(|source| {
                    ramflux_node_core::NodeCoreError::ItestJson(source.to_string())
                })?;
            body.admit(&ingress.wake_auth, &ingress.store)?;
            let response = if ingress.async_accept {
                handle_s13_wake_async_accept(&ingress.store, &body)?
            } else {
                handle_s13_wake_value(&ingress.store, &ingress.store_gate, &ingress.runtime, &body)?
            };
            tracing::info!("notify mesh QUIC wake accepted");
            Ok(ramflux_transport::GatewayQuicResponse {
                status: 200,
                body: serde_json::to_value(response).map_err(|source| {
                    ramflux_node_core::NodeCoreError::ItestJson(source.to_string())
                })?,
            })
        }
        _ => Ok(ramflux_transport::GatewayQuicResponse {
            status: 404,
            body: serde_json::json!({ "error": "not found" }),
        }),
    }
}

fn notify_mesh_transport_error(
    error: &ramflux_transport::TransportError,
) -> ramflux_node_core::NodeCoreError {
    ramflux_node_core::NodeCoreError::ItestHttp(error.to_string())
}

#[cfg(feature = "itest-http")]
fn serve_itest_http_async(
    ingress: &Arc<NotifyIngressState>,
) -> Result<(), ramflux_node_core::NodeCoreError> {
    let addr = ramflux_node_core::environment::var("RAMFLUX_ITEST_NOTIFY_HTTP_ADDR")
        .unwrap_or_else(|_| "0.0.0.0:18083".to_owned());
    let worker_count = notify_async_ingress_worker_count();
    let mut builder = tokio::runtime::Builder::new_multi_thread();
    let _threads = ramflux_node_core::track_service_runtime(&mut builder);
    let runtime = builder
        .enable_all()
        .thread_name("ramflux-notify-async-ingress")
        .worker_threads(worker_count)
        .build()
        .map_err(|source| ramflux_node_core::NodeCoreError::ItestHttp(source.to_string()))?;
    let runtime_ingress = Arc::clone(ingress);
    let result = runtime.block_on(async move {
        let listener = tokio::net::TcpListener::bind(&addr)
            .await
            .map_err(|source| ramflux_node_core::NodeCoreError::ItestHttp(source.to_string()))?;
        tracing::info!(addr, worker_count, "notify async itest HTTP surface listening");
        let shutdown = ramflux_node_core::service_shutdown_token();
        let mut backoff = ramflux_node_core::ListenerAcceptBackoff::default();
        loop {
            let (stream, _peer) = tokio::select! {
                () = shutdown.cancelled() => break,
                accepted = ramflux_node_core::custody_accept(|| listener.accept(), &mut backoff) => accepted,
            };
            if let Err(error) = stream.set_nodelay(true) {
                tracing::debug!(
                    %error,
                    "failed to enable TCP_NODELAY on async notify ingress connection"
                );
                continue;
            }
            let connection_ingress = Arc::clone(&runtime_ingress);
            tokio::spawn(async move {
                if let Err(error) =
                    notify_async_ingress_connection_loop(stream, connection_ingress).await
                {
                    tracing::debug!(%error, "notify async ingress connection ended");
                }
            });
        }
        Ok::<(), ramflux_node_core::NodeCoreError>(())
    });
    ramflux_node_core::drain_service_runtime(runtime);
    result
}

#[cfg(feature = "itest-http")]
fn notify_ingress_worker_count() -> usize {
    notify_runtime_usize_env("RAMFLUX_NOTIFY_INGRESS_THREADS", || {
        std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get)
    })
    .max(1)
}

#[cfg(feature = "itest-http")]
fn notify_async_ingress_worker_count() -> usize {
    notify_runtime_usize_env("RAMFLUX_NOTIFY_ASYNC_INGRESS_WORKERS", || {
        std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get)
    })
    .max(1)
}

#[cfg(feature = "itest-http")]
fn notify_async_ingress_enabled() -> bool {
    notify_default_enabled_env(NOTIFY_ASYNC_INGRESS_ENV)
}

fn lock_notify_store(
    gate: &Arc<Mutex<()>>,
) -> Result<std::sync::MutexGuard<'_, ()>, ramflux_node_core::NodeCoreError> {
    gate.lock().map_err(|source| ramflux_node_core::NodeCoreError::ItestHttp(source.to_string()))
}

#[cfg(feature = "itest-http")]
fn notify_ingress_worker_loop(
    receiver: &Arc<Mutex<std::sync::mpsc::Receiver<TcpStream>>>,
    ingress: &Arc<NotifyIngressState>,
) {
    loop {
        let stream = {
            let Ok(receiver) = receiver.lock() else {
                tracing::error!("notify ingress receiver lock poisoned");
                return;
            };
            receiver.recv()
        };
        let Ok(mut stream) = stream else {
            return;
        };
        let Some(_in_flight) = ramflux_node_core::begin_service_request() else {
            return;
        };
        loop {
            match handle_itest_request(&mut stream, ingress) {
                Ok(true) => {}
                Ok(false) => break,
                Err(error) => {
                    let body = format!("{error}");
                    let _result = ramflux_node_core::write_itest_text_response(
                        &mut stream,
                        itest_error_status(&error),
                        &body,
                    );
                    break;
                }
            }
        }
    }
}

#[cfg(feature = "itest-http")]
fn handle_itest_request(
    stream: &mut TcpStream,
    ingress: &NotifyIngressState,
) -> Result<bool, ramflux_node_core::NodeCoreError> {
    let Some(request) = ramflux_node_core::read_itest_http_request(stream)? else {
        return Ok(false);
    };
    let keep_alive = request.keep_alive;
    match (request.method.as_str(), request.path.as_str()) {
        ("GET", "/healthz") => {
            ramflux_node_core::write_itest_json_response_with_connection(
                stream,
                "200 OK",
                &serde_json::json!({
                    "service": "ramflux-notify",
                    "status": "ok"
                }),
                keep_alive,
            )?;
        }
        ("POST", "/mvp10/notify/wake") => {
            handle_mvp10_notify_wake(stream, ingress, &request.body, keep_alive)?;
        }
        ("POST", "/s13/notify/push-route") => {
            handle_s13_push_route(
                stream,
                &ingress.store,
                &ingress.store_gate,
                &request.body,
                keep_alive,
            )?;
        }
        ("POST", "/s13/notify/provider-credential") => {
            handle_s13_provider_credential(
                stream,
                &ingress.store,
                &ingress.store_gate,
                &request.body,
                keep_alive,
            )?;
        }
        ("POST", "/s13/notify/wake") => {
            let mut body: S13WakeRequest =
                ramflux_protocol::parse_i_json(&request.body).map_err(|source| {
                    ramflux_node_core::NodeCoreError::ItestJson(source.to_string())
                })?;
            body.admit(&ingress.wake_auth, &ingress.store)?;
            let response = if ingress.async_accept {
                handle_s13_wake_async_accept(&ingress.store, &body)?
            } else {
                handle_s13_wake_value(&ingress.store, &ingress.store_gate, &ingress.runtime, &body)?
            };
            ramflux_node_core::write_itest_json_response_with_connection(
                stream, "200 OK", &response, keep_alive,
            )?;
        }
        ("GET", path) if path.starts_with("/s13/notify/provider-attempts/") => {
            let queue_id = path.trim_start_matches("/s13/notify/provider-attempts/");
            handle_s13_provider_attempts(stream, ingress, queue_id, keep_alive)?;
        }
        ("POST", "/mvp10/notify/deliver") => {
            handle_mvp10_notify_deliver(stream, ingress, &request.body, keep_alive)?;
        }
        ("GET", "/mvp10/notify/state") => {
            handle_mvp10_notify_state(stream, ingress, keep_alive)?;
        }
        _ => {
            ramflux_node_core::write_itest_text_response_with_connection(
                stream,
                "404 Not Found",
                "not found",
                keep_alive,
            )?;
        }
    }
    Ok(keep_alive)
}

#[cfg(feature = "itest-http")]
struct AsyncItestHttpRequest {
    route: AsyncItestHttpRoute,
    body: Vec<u8>,
    keep_alive: bool,
}

#[cfg(feature = "itest-http")]
enum AsyncItestHttpRoute {
    Healthz,
    Mvp10NotifyWake,
    S13NotifyPushRoute,
    S13NotifyProviderCredential,
    S13NotifyWake,
    S13NotifyProviderAttempts(String),
    Mvp10NotifyDeliver,
    Mvp10NotifyState,
    NotFound,
}

#[cfg(feature = "itest-http")]
struct AsyncItestHttpResponse {
    status: &'static str,
    content_type: &'static str,
    body: Vec<u8>,
    keep_alive: bool,
}

#[cfg(feature = "itest-http")]
async fn notify_async_ingress_connection_loop(
    mut stream: tokio::net::TcpStream,
    ingress: Arc<NotifyIngressState>,
) -> Result<(), ramflux_node_core::NodeCoreError> {
    let mut buffer = Vec::with_capacity(16 * 1024);
    loop {
        let Some(request) = read_async_itest_http_request(&mut stream, &mut buffer).await? else {
            return Ok(());
        };
        let Some(_request) = ramflux_node_core::begin_service_request() else {
            return Ok(());
        };
        let keep_alive = request.keep_alive;
        if is_raw_s13_wake_request(&request, &ingress) {
            if let Err(error) = ingest_raw_s13_wake_for_async_ingress(&ingress, request.body).await
            {
                write_async_text_response(
                    &mut stream,
                    itest_error_status(&error),
                    &error.to_string(),
                    false,
                )
                .await?;
                return Ok(());
            }
            write_async_fixed_json_ok_response(&mut stream, keep_alive).await?;
        } else {
            let response =
                match handle_itest_request_value_async(request, Arc::clone(&ingress)).await {
                    Ok(response) => response,
                    Err(error) => {
                        async_text_response(itest_error_status(&error), &error.to_string(), false)
                    }
                };
            write_async_itest_response(&mut stream, &response).await?;
        }
        if !keep_alive {
            return Ok(());
        }
    }
}

#[cfg(feature = "itest-http")]
async fn read_async_itest_http_request(
    reader: &mut tokio::net::TcpStream,
    buffer: &mut Vec<u8>,
) -> Result<Option<AsyncItestHttpRequest>, ramflux_node_core::NodeCoreError> {
    loop {
        if let Some(request) = parse_async_itest_http_request(buffer)? {
            return Ok(Some(request));
        }
        let mut chunk = [0_u8; 8192];
        let bytes = tokio::io::AsyncReadExt::read(reader, &mut chunk)
            .await
            .map_err(|source| ramflux_node_core::NodeCoreError::ItestHttp(source.to_string()))?;
        if bytes == 0 {
            if buffer.is_empty() {
                return Ok(None);
            }
            return Err(ramflux_node_core::NodeCoreError::ItestHttp(
                "incomplete async itest HTTP request".to_owned(),
            ));
        }
        buffer.extend_from_slice(&chunk[..bytes]);
        if buffer.len() > 2 * 1024 * 1024 {
            return Err(ramflux_node_core::NodeCoreError::ItestHttp(
                "async itest HTTP request too large".to_owned(),
            ));
        }
    }
}

#[cfg(feature = "itest-http")]
fn parse_async_itest_http_request(
    buffer: &mut Vec<u8>,
) -> Result<Option<AsyncItestHttpRequest>, ramflux_node_core::NodeCoreError> {
    let Some(header_end) = find_async_http_header_end(buffer) else {
        if buffer.len() > 64 * 1024 {
            return Err(ramflux_node_core::NodeCoreError::ItestHttp(
                "async request header too large".to_owned(),
            ));
        }
        return Ok(None);
    };
    let header = std::str::from_utf8(&buffer[..header_end])
        .map_err(|source| ramflux_node_core::NodeCoreError::ItestHttp(source.to_string()))?;
    let mut lines = header.lines();
    let request_line = lines.next().ok_or_else(|| {
        ramflux_node_core::NodeCoreError::ItestHttp("missing async request line".to_owned())
    })?;
    let mut parts = request_line.split_whitespace();
    let method = parts
        .next()
        .ok_or_else(|| ramflux_node_core::NodeCoreError::ItestHttp("missing method".to_owned()))?;
    let path = parts
        .next()
        .ok_or_else(|| ramflux_node_core::NodeCoreError::ItestHttp("missing path".to_owned()))?;
    let mut content_length = 0usize;
    let mut keep_alive = false;
    for line in lines {
        let Some((name, value)) = line.trim_end().split_once(':') else {
            continue;
        };
        let value = value.trim();
        if name.eq_ignore_ascii_case("Content-Length") {
            content_length = value.parse().map_err(|source| {
                ramflux_node_core::NodeCoreError::ItestHttp(format!("bad content length: {source}"))
            })?;
        } else if name.eq_ignore_ascii_case("Connection") {
            keep_alive = async_connection_header_requests_keep_alive(value);
        }
    }
    let separator_len = async_http_header_separator_len(buffer, header_end);
    let body_start = header_end + separator_len;
    let request_len = body_start + content_length;
    if buffer.len() < request_len {
        return Ok(None);
    }
    let route = async_itest_route(method, path);
    let body = buffer[body_start..request_len].to_vec();
    buffer.drain(..request_len);
    Ok(Some(AsyncItestHttpRequest { route, body, keep_alive }))
}

#[cfg(feature = "itest-http")]
async fn handle_itest_request_value_async(
    request: AsyncItestHttpRequest,
    ingress: Arc<NotifyIngressState>,
) -> Result<AsyncItestHttpResponse, ramflux_node_core::NodeCoreError> {
    let keep_alive = request.keep_alive;
    match request.route {
        AsyncItestHttpRoute::Healthz => async_json_response(
            "200 OK",
            &serde_json::json!({
                "service": "ramflux-notify",
                "status": "ok"
            }),
            keep_alive,
        ),
        AsyncItestHttpRoute::Mvp10NotifyWake => {
            handle_mvp10_notify_wake_value_async(ingress, request.body, keep_alive).await
        }
        AsyncItestHttpRoute::S13NotifyPushRoute => {
            handle_s13_push_route_value_async(ingress, request.body, keep_alive).await
        }
        AsyncItestHttpRoute::S13NotifyProviderCredential => {
            handle_s13_provider_credential_value_async(ingress, request.body, keep_alive).await
        }
        AsyncItestHttpRoute::S13NotifyWake => {
            if ingress.async_accept && notify_wal_raw_enqueue_enabled() {
                let response = handle_s13_wake_raw_async_accept_value_async(
                    &ingress.store,
                    &ingress.wake_auth,
                    request.body,
                )
                .await?;
                return async_json_response("200 OK", &response, keep_alive);
            }
            let mut body: S13WakeRequest =
                ramflux_protocol::parse_i_json(&request.body).map_err(|source| {
                    ramflux_node_core::NodeCoreError::ItestJson(source.to_string())
                })?;
            body.admit(&ingress.wake_auth, &ingress.store)?;
            let response = if ingress.async_accept {
                handle_s13_wake_async_accept_value_async(&ingress.store, &body).await?
            } else {
                let blocking_ingress = Arc::clone(&ingress);
                tokio::task::spawn_blocking(move || {
                    handle_s13_wake_value(
                        &blocking_ingress.store,
                        &blocking_ingress.store_gate,
                        &blocking_ingress.runtime,
                        &body,
                    )
                })
                .await
                .map_err(|source| {
                    ramflux_node_core::NodeCoreError::ItestHttp(source.to_string())
                })??
            };
            async_json_response("200 OK", &response, keep_alive)
        }
        AsyncItestHttpRoute::S13NotifyProviderAttempts(queue_id) => {
            let blocking_ingress = Arc::clone(&ingress);
            let attempts = tokio::task::spawn_blocking(move || {
                let _guard = lock_notify_store(&blocking_ingress.store_gate)?;
                let state = blocking_ingress.store.load_state()?.unwrap_or_default();
                Ok::<_, ramflux_node_core::NodeCoreError>(
                    state.provider_attempts(&queue_id).to_vec(),
                )
            })
            .await
            .map_err(|source| ramflux_node_core::NodeCoreError::ItestHttp(source.to_string()))??;
            async_json_response("200 OK", &attempts, keep_alive)
        }
        AsyncItestHttpRoute::Mvp10NotifyDeliver => {
            handle_mvp10_notify_deliver_value_async(ingress, request.body, keep_alive).await
        }
        AsyncItestHttpRoute::Mvp10NotifyState => {
            handle_mvp10_notify_state_value_async(ingress, keep_alive).await
        }
        AsyncItestHttpRoute::NotFound => {
            Ok(async_text_response("404 Not Found", "not found", keep_alive))
        }
    }
}

#[cfg(feature = "itest-http")]
fn is_raw_s13_wake_request(request: &AsyncItestHttpRequest, ingress: &NotifyIngressState) -> bool {
    ingress.async_accept
        && notify_wal_raw_enqueue_enabled()
        && matches!(request.route, AsyncItestHttpRoute::S13NotifyWake)
}

#[cfg(feature = "itest-http")]
fn async_itest_route(method: &str, path: &str) -> AsyncItestHttpRoute {
    match (method, path) {
        ("GET", "/healthz") => AsyncItestHttpRoute::Healthz,
        ("POST", "/mvp10/notify/wake") => AsyncItestHttpRoute::Mvp10NotifyWake,
        ("POST", "/s13/notify/push-route") => AsyncItestHttpRoute::S13NotifyPushRoute,
        ("POST", "/s13/notify/provider-credential") => {
            AsyncItestHttpRoute::S13NotifyProviderCredential
        }
        ("POST", "/s13/notify/wake") => AsyncItestHttpRoute::S13NotifyWake,
        ("POST", "/mvp10/notify/deliver") => AsyncItestHttpRoute::Mvp10NotifyDeliver,
        ("GET", "/mvp10/notify/state") => AsyncItestHttpRoute::Mvp10NotifyState,
        ("GET", value) if value.starts_with("/s13/notify/provider-attempts/") => {
            AsyncItestHttpRoute::S13NotifyProviderAttempts(
                value.trim_start_matches("/s13/notify/provider-attempts/").to_owned(),
            )
        }
        _ => AsyncItestHttpRoute::NotFound,
    }
}

#[cfg(feature = "itest-http")]
async fn handle_mvp10_notify_wake_value_async(
    ingress: Arc<NotifyIngressState>,
    body: Vec<u8>,
    keep_alive: bool,
) -> Result<AsyncItestHttpResponse, ramflux_node_core::NodeCoreError> {
    let entry = tokio::task::spawn_blocking(move || {
        let body: serde_json::Value = ramflux_protocol::parse_i_json(&body)
            .map_err(|source| ramflux_node_core::NodeCoreError::ItestJson(source.to_string()))?;
        let wake = project_mvp10_signed_wake(&ingress.wake_auth, &body)?;
        let push_alias_hash = body
            .get("push_alias_hash")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("push_alias_hash")
            .to_owned();
        let queued_at =
            body.get("queued_at").and_then(serde_json::Value::as_u64).unwrap_or(1_760_000_000);
        let _guard = lock_notify_store(&ingress.store_gate)?;
        ingress.store.queue_wake(wake, push_alias_hash, queued_at)
    })
    .await
    .map_err(|source| ramflux_node_core::NodeCoreError::ItestHttp(source.to_string()))??;
    async_json_response("200 OK", &entry, keep_alive)
}

#[cfg(feature = "itest-http")]
async fn handle_s13_push_route_value_async(
    ingress: Arc<NotifyIngressState>,
    body: Vec<u8>,
    keep_alive: bool,
) -> Result<AsyncItestHttpResponse, ramflux_node_core::NodeCoreError> {
    let route = tokio::task::spawn_blocking(move || {
        let route: ramflux_node_core::DevicePushRoute = serde_json::from_slice(&body)
            .map_err(|source| ramflux_node_core::NodeCoreError::ItestJson(source.to_string()))?;
        tracing::info!(
            device_delivery_id = route.device_delivery_id,
            provider = ?route.provider,
            credential_id = route.credential_id.as_deref().unwrap_or(""),
            "notify push route registered"
        );
        let _guard = lock_notify_store(&ingress.store_gate)?;
        ingress.store.register_push_route(route.clone())?;
        Ok::<_, ramflux_node_core::NodeCoreError>(route)
    })
    .await
    .map_err(|source| ramflux_node_core::NodeCoreError::ItestHttp(source.to_string()))??;
    async_json_response("200 OK", &route, keep_alive)
}

#[cfg(feature = "itest-http")]
async fn handle_s13_provider_credential_value_async(
    ingress: Arc<NotifyIngressState>,
    body: Vec<u8>,
    keep_alive: bool,
) -> Result<AsyncItestHttpResponse, ramflux_node_core::NodeCoreError> {
    let credential = tokio::task::spawn_blocking(move || {
        let credential: ramflux_node_core::ProviderCredential = serde_json::from_slice(&body)
            .map_err(|source| ramflux_node_core::NodeCoreError::ItestJson(source.to_string()))?;
        tracing::info!(
            credential_id = credential.credential_id(),
            provider = ?credential.provider_kind(),
            "notify provider credential registered"
        );
        let _guard = lock_notify_store(&ingress.store_gate)?;
        ingress.store.update_provider_credential(&credential)?;
        Ok::<_, ramflux_node_core::NodeCoreError>(credential)
    })
    .await
    .map_err(|source| ramflux_node_core::NodeCoreError::ItestHttp(source.to_string()))??;
    async_json_response("200 OK", &credential, keep_alive)
}

#[cfg(feature = "itest-http")]
async fn handle_s13_wake_async_accept_value_async(
    store: &ramflux_node_core::NotifyRedbStore,
    request: &S13WakeRequest,
) -> Result<S13WakeResponse, ramflux_node_core::NodeCoreError> {
    let Some(wake) = request.queued_provider_wake()? else {
        return Ok(no_push_response(request));
    };
    let entry = store
        .queue_wake_for_async_accept_async(
            &request.device_delivery_id,
            wake,
            request.queued_at.unwrap_or_else(ramflux_node_core::now_unix_seconds),
            request.dnd_active.unwrap_or(false),
        )
        .await?;
    Ok(S13WakeResponse { entry, attempts: Vec::new() })
}

#[cfg(feature = "itest-http")]
async fn handle_s13_wake_raw_async_accept_value_async(
    store: &ramflux_node_core::NotifyRedbStore,
    wake_auth: &NotifyWakeAuth,
    raw_body: Vec<u8>,
) -> Result<serde_json::Value, ramflux_node_core::NodeCoreError> {
    let mut request = parse_s13_wake_request_body(&raw_body)?;
    request.admit(wake_auth, store)?;
    if request.queued_provider_wake()?.is_none() {
        return Ok(serde_json::json!({ "queue_id": "" }));
    }
    let queued_at = ramflux_node_core::now_unix_seconds();
    let shard_id = store.notify_ingest_shard_for_key(&request.device_delivery_id);
    let raw =
        store.queue_raw_wake_for_async_accept_shard_async(shard_id, raw_body, queued_at).await?;
    Ok(serde_json::json!({
        "queue_id": raw.queue_id
    }))
}

#[cfg(feature = "itest-http")]
async fn ingest_raw_s13_wake_for_async_ingress(
    ingress: &NotifyIngressState,
    raw_body: Vec<u8>,
) -> Result<(), ramflux_node_core::NodeCoreError> {
    let queued_at = ramflux_node_core::now_unix_seconds();
    let mut request = parse_s13_wake_request_body(&raw_body)?;
    request.admit(&ingress.wake_auth, &ingress.store)?;
    if request.queued_provider_wake()?.is_none() {
        return Ok(());
    }
    let shard_id = ingress.store.notify_ingest_shard_for_key(&request.device_delivery_id);
    if let Some(batcher) = &ingress.wake_verify_batcher {
        return batcher
            .verify_and_enqueue(
                shard_id,
                request.signed_wake,
                request.device_delivery_id,
                raw_body,
                queued_at,
            )
            .await;
    }
    ingress
        .store
        .queue_raw_wake_for_async_accept_shard_async(shard_id, raw_body, queued_at)
        .await
        .map(|_raw| ())
}

#[cfg(feature = "itest-http")]
async fn handle_mvp10_notify_deliver_value_async(
    ingress: Arc<NotifyIngressState>,
    body: Vec<u8>,
    keep_alive: bool,
) -> Result<AsyncItestHttpResponse, ramflux_node_core::NodeCoreError> {
    let entry = tokio::task::spawn_blocking(move || {
        let body: serde_json::Value = serde_json::from_slice(&body)
            .map_err(|source| ramflux_node_core::NodeCoreError::ItestJson(source.to_string()))?;
        let queue_id =
            body.get("queue_id").and_then(serde_json::Value::as_str).ok_or_else(|| {
                ramflux_node_core::NodeCoreError::ItestJson("missing queue_id".to_owned())
            })?;
        let _guard = lock_notify_store(&ingress.store_gate)?;
        let mut state = ingress.store.load_state()?.unwrap_or_default();
        state.mark_delivered(queue_id)?;
        let entry = state.entry(queue_id).cloned().ok_or_else(|| {
            ramflux_node_core::NodeCoreError::EnvelopeNotFound(queue_id.to_owned())
        })?;
        ingress.store.save_queue_state(&state)?;
        Ok::<_, ramflux_node_core::NodeCoreError>(entry)
    })
    .await
    .map_err(|source| ramflux_node_core::NodeCoreError::ItestHttp(source.to_string()))??;
    async_json_response("200 OK", &entry, keep_alive)
}

#[cfg(feature = "itest-http")]
async fn handle_mvp10_notify_state_value_async(
    ingress: Arc<NotifyIngressState>,
    keep_alive: bool,
) -> Result<AsyncItestHttpResponse, ramflux_node_core::NodeCoreError> {
    let state = tokio::task::spawn_blocking(move || {
        let _guard = lock_notify_store(&ingress.store_gate)?;
        ingress.store.load_state().map(std::option::Option::unwrap_or_default)
    })
    .await
    .map_err(|source| ramflux_node_core::NodeCoreError::ItestHttp(source.to_string()))??;
    async_json_response("200 OK", &state, keep_alive)
}

#[cfg(feature = "itest-http")]
fn async_json_response<T: serde::Serialize>(
    status: &'static str,
    value: &T,
    keep_alive: bool,
) -> Result<AsyncItestHttpResponse, ramflux_node_core::NodeCoreError> {
    let body = serde_json::to_vec(value)
        .map_err(|source| ramflux_node_core::NodeCoreError::ItestJson(source.to_string()))?;
    Ok(AsyncItestHttpResponse { status, content_type: "application/json", body, keep_alive })
}

#[cfg(feature = "itest-http")]
fn async_text_response(
    status: &'static str,
    body: &str,
    keep_alive: bool,
) -> AsyncItestHttpResponse {
    AsyncItestHttpResponse {
        status,
        content_type: "text/plain; charset=utf-8",
        body: body.as_bytes().to_vec(),
        keep_alive,
    }
}

#[cfg(feature = "itest-http")]
async fn write_async_itest_response(
    writer: &mut tokio::net::TcpStream,
    response: &AsyncItestHttpResponse,
) -> Result<(), ramflux_node_core::NodeCoreError> {
    let connection = if response.keep_alive { "keep-alive" } else { "close" };
    let header = format!(
        "HTTP/1.1 {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: {connection}\r\n\r\n",
        response.status,
        response.content_type,
        response.body.len()
    );
    tokio::io::AsyncWriteExt::write_all(writer, header.as_bytes())
        .await
        .map_err(|source| ramflux_node_core::NodeCoreError::ItestHttp(source.to_string()))?;
    tokio::io::AsyncWriteExt::write_all(writer, &response.body)
        .await
        .map_err(|source| ramflux_node_core::NodeCoreError::ItestHttp(source.to_string()))?;
    tokio::io::AsyncWriteExt::flush(writer)
        .await
        .map_err(|source| ramflux_node_core::NodeCoreError::ItestHttp(source.to_string()))?;
    Ok(())
}

#[cfg(feature = "itest-http")]
async fn write_async_fixed_json_ok_response(
    writer: &mut tokio::net::TcpStream,
    keep_alive: bool,
) -> Result<(), ramflux_node_core::NodeCoreError> {
    const OK_KEEP_ALIVE: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\n{}";
    const OK_CLOSE: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}";
    let response = if keep_alive { OK_KEEP_ALIVE } else { OK_CLOSE };
    tokio::io::AsyncWriteExt::write_all(writer, response)
        .await
        .map_err(|source| ramflux_node_core::NodeCoreError::ItestHttp(source.to_string()))?;
    Ok(())
}

#[cfg(feature = "itest-http")]
async fn write_async_text_response(
    writer: &mut tokio::net::TcpStream,
    status: &'static str,
    body: &str,
    keep_alive: bool,
) -> Result<(), ramflux_node_core::NodeCoreError> {
    let response = async_text_response(status, body, keep_alive);
    write_async_itest_response(writer, &response).await
}

#[cfg(feature = "itest-http")]
fn find_async_http_header_end(buffer: &[u8]) -> Option<usize> {
    buffer.windows(4).position(|window| window == b"\r\n\r\n").or_else(|| {
        buffer.windows(2).position(|window| window == b"\n\n").map(|position| position + 1)
    })
}

#[cfg(feature = "itest-http")]
fn async_http_header_separator_len(buffer: &[u8], header_end: usize) -> usize {
    if buffer.get(header_end..header_end + 4) == Some(b"\r\n\r\n") { 4 } else { 1 }
}

#[cfg(feature = "itest-http")]
fn async_connection_header_requests_keep_alive(value: &str) -> bool {
    value.split(',').map(str::trim).any(|token| token.eq_ignore_ascii_case("keep-alive"))
}

#[cfg(feature = "itest-http")]
fn handle_mvp10_notify_wake(
    stream: &mut TcpStream,
    ingress: &NotifyIngressState,
    body: &[u8],
    keep_alive: bool,
) -> Result<(), ramflux_node_core::NodeCoreError> {
    let body: serde_json::Value = ramflux_protocol::parse_i_json(body)
        .map_err(|source| ramflux_node_core::NodeCoreError::ItestJson(source.to_string()))?;
    let wake = project_mvp10_signed_wake(&ingress.wake_auth, &body)?;
    let push_alias_hash = body
        .get("push_alias_hash")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("push_alias_hash")
        .to_owned();
    let queued_at =
        body.get("queued_at").and_then(serde_json::Value::as_u64).unwrap_or(1_760_000_000);
    let entry = {
        let _guard = lock_notify_store(&ingress.store_gate)?;
        ingress.store.queue_wake(wake, push_alias_hash, queued_at)?
    };
    ramflux_node_core::write_itest_json_response_with_connection(
        stream, "200 OK", &entry, keep_alive,
    )
}

#[cfg(feature = "itest-http")]
fn handle_s13_provider_attempts(
    stream: &mut TcpStream,
    ingress: &NotifyIngressState,
    queue_id: &str,
    keep_alive: bool,
) -> Result<(), ramflux_node_core::NodeCoreError> {
    let attempts = {
        let _guard = lock_notify_store(&ingress.store_gate)?;
        let state = ingress.store.load_state()?.unwrap_or_default();
        state.provider_attempts(queue_id).to_vec()
    };
    ramflux_node_core::write_itest_json_response_with_connection(
        stream, "200 OK", &attempts, keep_alive,
    )
}

#[cfg(feature = "itest-http")]
fn handle_mvp10_notify_deliver(
    stream: &mut TcpStream,
    ingress: &NotifyIngressState,
    body: &[u8],
    keep_alive: bool,
) -> Result<(), ramflux_node_core::NodeCoreError> {
    let body: serde_json::Value = serde_json::from_slice(body)
        .map_err(|source| ramflux_node_core::NodeCoreError::ItestJson(source.to_string()))?;
    let queue_id = body.get("queue_id").and_then(serde_json::Value::as_str).ok_or_else(|| {
        ramflux_node_core::NodeCoreError::ItestJson("missing queue_id".to_owned())
    })?;
    let entry = {
        let _guard = lock_notify_store(&ingress.store_gate)?;
        let mut state = ingress.store.load_state()?.unwrap_or_default();
        state.mark_delivered(queue_id)?;
        let entry = state.entry(queue_id).cloned().ok_or_else(|| {
            ramflux_node_core::NodeCoreError::EnvelopeNotFound(queue_id.to_owned())
        })?;
        ingress.store.save_queue_state(&state)?;
        entry
    };
    ramflux_node_core::write_itest_json_response_with_connection(
        stream, "200 OK", &entry, keep_alive,
    )
}

#[cfg(feature = "itest-http")]
fn handle_mvp10_notify_state(
    stream: &mut TcpStream,
    ingress: &NotifyIngressState,
    keep_alive: bool,
) -> Result<(), ramflux_node_core::NodeCoreError> {
    let state = {
        let _guard = lock_notify_store(&ingress.store_gate)?;
        ingress.store.load_state()?.unwrap_or_default()
    };
    ramflux_node_core::write_itest_json_response_with_connection(
        stream, "200 OK", &state, keep_alive,
    )
}

#[cfg(feature = "itest-http")]
fn handle_s13_push_route(
    stream: &mut TcpStream,
    store: &ramflux_node_core::NotifyRedbStore,
    store_gate: &Arc<Mutex<()>>,
    body: &[u8],
    keep_alive: bool,
) -> Result<(), ramflux_node_core::NodeCoreError> {
    let route: ramflux_node_core::DevicePushRoute = serde_json::from_slice(body)
        .map_err(|source| ramflux_node_core::NodeCoreError::ItestJson(source.to_string()))?;
    tracing::info!(
        device_delivery_id = route.device_delivery_id,
        provider = ?route.provider,
        credential_id = route.credential_id.as_deref().unwrap_or(""),
        "notify push route registered"
    );
    {
        let _guard = lock_notify_store(store_gate)?;
        store.register_push_route(route.clone())?;
    }
    ramflux_node_core::write_itest_json_response_with_connection(
        stream, "200 OK", &route, keep_alive,
    )
}

#[cfg(feature = "itest-http")]
fn handle_s13_provider_credential(
    stream: &mut TcpStream,
    store: &ramflux_node_core::NotifyRedbStore,
    store_gate: &Arc<Mutex<()>>,
    body: &[u8],
    keep_alive: bool,
) -> Result<(), ramflux_node_core::NodeCoreError> {
    let credential: ramflux_node_core::ProviderCredential = serde_json::from_slice(body)
        .map_err(|source| ramflux_node_core::NodeCoreError::ItestJson(source.to_string()))?;
    tracing::info!(
        credential_id = credential.credential_id(),
        provider = ?credential.provider_kind(),
        "notify provider credential registered"
    );
    {
        let _guard = lock_notify_store(store_gate)?;
        store.update_provider_credential(&credential)?;
    }
    ramflux_node_core::write_itest_json_response_with_connection(
        stream,
        "200 OK",
        &credential,
        keep_alive,
    )
}

enum NotifyRuntime {
    Current,
    TokioConcurrent(ConcurrentNotifyRuntime),
    #[cfg(all(target_os = "linux", feature = "compio-notify"))]
    Compio(CompioNotifyRuntime),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NotifyMeshIngressRuntime {
    Tokio,
}

fn notify_mesh_ingress_runtime() -> NotifyMeshIngressRuntime {
    notify_mesh_ingress_runtime_from_value(
        ramflux_node_core::environment::var(NOTIFY_MESH_INGRESS_RUNTIME_ENV).ok().as_deref(),
    )
}

fn notify_mesh_ingress_runtime_from_value(value: Option<&str>) -> NotifyMeshIngressRuntime {
    let Some(value) = value else {
        return NotifyMeshIngressRuntime::Tokio;
    };
    let trimmed = value.trim();
    if trimmed.starts_with("${") || trimmed.is_empty() {
        if !trimmed.is_empty() {
            tracing::warn!(
                runtime = %trimmed,
                "unsupported notify mesh ingress runtime; using tokio"
            );
        }
        return NotifyMeshIngressRuntime::Tokio;
    }
    if matches!(trimmed, "tokio" | "quinn") {
        return NotifyMeshIngressRuntime::Tokio;
    }
    tracing::warn!(
        runtime = %trimmed,
        "unsupported notify mesh ingress runtime; using tokio"
    );
    NotifyMeshIngressRuntime::Tokio
}

impl NotifyRuntime {
    fn from_env(
        store: &Arc<ramflux_node_core::NotifyRedbStore>,
        store_gate: &Arc<Mutex<()>>,
    ) -> Result<Self, ramflux_node_core::NodeCoreError> {
        match ramflux_node_core::environment::choice(
            NOTIFY_RUNTIME_ENV,
            ramflux_node_core::environment::var(NOTIFY_RUNTIME_ENV).ok().as_deref(),
            &["current", "tokio", "compio", "tokio-concurrent"],
            "current",
        ) {
            "compio" => notify_compio_runtime_from_store(store, store_gate),
            "tokio-concurrent" => Ok(Self::TokioConcurrent(ConcurrentNotifyRuntime::new(
                store,
                store_gate,
                "tokio-concurrent",
            )?)),
            _ => Ok(Self::Current),
        }
    }

    fn dispatch_s13_wake(
        &self,
        store: &ramflux_node_core::NotifyRedbStore,
        store_gate: &Arc<Mutex<()>>,
        request: &S13WakeRequest,
    ) -> Result<S13WakeResponse, ramflux_node_core::NodeCoreError> {
        match self {
            Self::Current => dispatch_s13_wake_current(store, store_gate, request),
            Self::TokioConcurrent(runtime) => runtime.dispatch_s13_wake(request),
            #[cfg(all(target_os = "linux", feature = "compio-notify"))]
            Self::Compio(runtime) => runtime.dispatch_s13_wake(request),
        }
    }
}

struct ConcurrentNotifyRuntime {
    workers: std::sync::Arc<ConcurrentNotifyFanoutWorkerPool>,
}

impl ConcurrentNotifyRuntime {
    fn new(
        store: &Arc<ramflux_node_core::NotifyRedbStore>,
        store_gate: &Arc<Mutex<()>>,
        env_prefix: &str,
    ) -> Result<Self, ramflux_node_core::NodeCoreError> {
        let worker_count = notify_runtime_usize_env(
            &format!("RAMFLUX_NOTIFY_{}_WORKERS", env_key(env_prefix)),
            || std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get),
        )
        .max(1);
        let queue_capacity = notify_runtime_usize_env(
            &format!("RAMFLUX_NOTIFY_{}_QUEUE_CAPACITY", env_key(env_prefix)),
            || 1024,
        )
        .max(1);
        let provider_worker_count = notify_runtime_usize_env(
            &format!("RAMFLUX_NOTIFY_{}_PROVIDER_WORKERS", env_key(env_prefix)),
            || worker_count.saturating_mul(2).max(1),
        )
        .max(1);
        let provider_workers =
            std::sync::Arc::new(ConcurrentProviderPushWorkerPool::new(provider_worker_count)?);
        let workers = std::sync::Arc::new(ConcurrentNotifyFanoutWorkerPool::new(
            worker_count,
            queue_capacity,
            store,
            store_gate,
            &provider_workers,
        )?);
        tracing::info!(
            worker_count,
            provider_worker_count,
            "notify tokio-concurrent fanout runtime initialized"
        );
        Ok(Self { workers })
    }

    fn dispatch_s13_wake(
        &self,
        request: &S13WakeRequest,
    ) -> Result<S13WakeResponse, ramflux_node_core::NodeCoreError> {
        self.workers.dispatch(request)
    }
}

struct ConcurrentNotifyFanoutCommand {
    request: S13WakeRequest,
    reply: std::sync::mpsc::SyncSender<Result<S13WakeResponse, ramflux_node_core::NodeCoreError>>,
}

struct ConcurrentNotifyFanoutWorkerPool {
    senders: Vec<std::sync::mpsc::SyncSender<ConcurrentNotifyFanoutCommand>>,
    threads: Vec<std::thread::JoinHandle<()>>,
}

impl Drop for ConcurrentNotifyFanoutWorkerPool {
    fn drop(&mut self) {
        self.senders.clear();
        for thread in self.threads.drain(..) {
            if thread.join().is_err() {
                tracing::error!("notify runtime worker panicked during shutdown");
            }
        }
    }
}

impl ConcurrentNotifyFanoutWorkerPool {
    fn new(
        worker_count: usize,
        queue_capacity: usize,
        store: &Arc<ramflux_node_core::NotifyRedbStore>,
        store_gate: &Arc<Mutex<()>>,
        provider_workers: &std::sync::Arc<ConcurrentProviderPushWorkerPool>,
    ) -> Result<Self, ramflux_node_core::NodeCoreError> {
        let mut senders = Vec::with_capacity(worker_count);
        let mut threads = Vec::with_capacity(worker_count);
        for worker_id in 0..worker_count {
            let (sender, receiver) = std::sync::mpsc::sync_channel(queue_capacity);
            let thread_store = Arc::clone(store);
            let thread_store_gate = Arc::clone(store_gate);
            let thread_provider_workers = std::sync::Arc::clone(provider_workers);
            let thread = std::thread::Builder::new()
                .name(format!("ramflux-notify-tokio-fanout-worker-{worker_id}"))
                .spawn(move || {
                    concurrent_notify_fanout_worker_loop(
                        &receiver,
                        &thread_store,
                        &thread_store_gate,
                        &thread_provider_workers,
                    );
                })
                .map_err(|source| {
                    ramflux_node_core::NodeCoreError::ItestHttp(source.to_string())
                })?;
            senders.push(sender);
            threads.push(thread);
        }
        Ok(Self { senders, threads })
    }

    fn dispatch(
        &self,
        request: &S13WakeRequest,
    ) -> Result<S13WakeResponse, ramflux_node_core::NodeCoreError> {
        let shard = notify_shard_index(&request.device_delivery_id, self.senders.len());
        let (reply, response) = std::sync::mpsc::sync_channel(1);
        let command = ConcurrentNotifyFanoutCommand { request: request.clone(), reply };
        self.senders[shard].send(command).map_err(|error| {
            ramflux_node_core::NodeCoreError::ItestHttp(format!(
                "notify tokio-concurrent worker queue closed: {error}"
            ))
        })?;
        response.recv().map_err(|error| {
            ramflux_node_core::NodeCoreError::ItestHttp(format!(
                "notify tokio-concurrent response closed: {error}"
            ))
        })?
    }
}

fn concurrent_notify_fanout_worker_loop(
    receiver: &std::sync::mpsc::Receiver<ConcurrentNotifyFanoutCommand>,
    store: &Arc<ramflux_node_core::NotifyRedbStore>,
    store_gate: &Arc<Mutex<()>>,
    provider_workers: &std::sync::Arc<ConcurrentProviderPushWorkerPool>,
) {
    while let Ok(command) = receiver.recv() {
        let result = dispatch_s13_wake_concurrent_worker(
            store,
            store_gate,
            provider_workers,
            &command.request,
        );
        let _result = command.reply.send(result);
    }
}

struct ConcurrentProviderPushWorkerPool {
    senders: Vec<std::sync::mpsc::SyncSender<ConcurrentProviderPushJob>>,
    next_worker: std::sync::atomic::AtomicUsize,
    _runtime: Arc<tokio::runtime::Runtime>,
    _h2_pool: Arc<ProviderH2ConnectionPool>,
    threads: Vec<std::thread::JoinHandle<()>>,
}

impl Drop for ConcurrentProviderPushWorkerPool {
    fn drop(&mut self) {
        self.senders.clear();
        for thread in self.threads.drain(..) {
            if thread.join().is_err() {
                tracing::error!("notify runtime worker panicked during shutdown");
            }
        }
    }
}

impl ConcurrentProviderPushWorkerPool {
    fn new(worker_count: usize) -> Result<Self, ramflux_node_core::NodeCoreError> {
        let worker_count = worker_count.clamp(1, 128);
        let runtime = Arc::new(
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .thread_name("ramflux-notify-provider-h2")
                .worker_threads(worker_count)
                .build()
                .map_err(|source| {
                    ramflux_node_core::NodeCoreError::ItestHttp(source.to_string())
                })?,
        );
        let h2_pool = Arc::new(ProviderH2ConnectionPool::from_env());
        let mut senders = Vec::with_capacity(worker_count);
        let mut threads = Vec::with_capacity(worker_count);
        for worker_id in 0..worker_count {
            let (sender, receiver) = std::sync::mpsc::sync_channel(1024);
            let thread_runtime = Arc::clone(&runtime);
            let thread_h2_pool = Arc::clone(&h2_pool);
            let thread = std::thread::Builder::new()
                .name(format!("ramflux-notify-provider-worker-{worker_id}"))
                .spawn(move || {
                    concurrent_provider_push_worker_loop(
                        &receiver,
                        &thread_runtime,
                        &thread_h2_pool,
                    );
                })
                .map_err(|source| {
                    ramflux_node_core::NodeCoreError::ItestHttp(source.to_string())
                })?;
            senders.push(sender);
            threads.push(thread);
        }
        Ok(Self {
            senders,
            next_worker: std::sync::atomic::AtomicUsize::new(0),
            _runtime: runtime,
            _h2_pool: h2_pool,
            threads,
        })
    }

    fn dispatch(
        &self,
        store: Arc<ramflux_node_core::NotifyRedbStore>,
        prepared: ramflux_node_core::PreparedProviderPush,
    ) -> Result<
        std::sync::mpsc::Receiver<
            Result<provider_outcome::ProviderSendStatus, ramflux_node_core::NodeCoreError>,
        >,
        ramflux_node_core::NodeCoreError,
    > {
        let worker = self.next_worker.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            % self.senders.len();
        let (reply, response) = std::sync::mpsc::sync_channel(1);
        self.senders[worker]
            .try_send(ConcurrentProviderPushJob { store, prepared, reply })
            .map_err(|error| {
                ramflux_node_core::NodeCoreError::ItestHttp(format!(
                    "notify provider worker queue unavailable: {error}"
                ))
            })?;
        Ok(response)
    }
}

struct ConcurrentProviderPushJob {
    store: Arc<ramflux_node_core::NotifyRedbStore>,
    prepared: ramflux_node_core::PreparedProviderPush,
    reply: std::sync::mpsc::SyncSender<
        Result<provider_outcome::ProviderSendStatus, ramflux_node_core::NodeCoreError>,
    >,
}

fn concurrent_provider_push_worker_loop(
    receiver: &std::sync::mpsc::Receiver<ConcurrentProviderPushJob>,
    runtime: &tokio::runtime::Runtime,
    h2_pool: &ProviderH2ConnectionPool,
) {
    while let Ok(job) = receiver.recv() {
        let result = send_provider_push_with_runtime(runtime, h2_pool, &job.store, &job.prepared);
        let _result = job.reply.send(result);
    }
}

fn dispatch_s13_wake_concurrent_worker(
    store: &Arc<ramflux_node_core::NotifyRedbStore>,
    _store_gate: &Arc<Mutex<()>>,
    provider_workers: &ConcurrentProviderPushWorkerPool,
    request: &S13WakeRequest,
) -> Result<S13WakeResponse, ramflux_node_core::NodeCoreError> {
    let Some(wake) = request.queued_provider_wake()? else {
        return Ok(no_push_response(request));
    };
    let (entry, pushes) = store.queue_wake_for_push(
        &request.device_delivery_id,
        wake,
        request.queued_at.unwrap_or_else(ramflux_node_core::now_unix_seconds),
        request.dnd_active.unwrap_or(false),
    )?;
    tracing::debug!(
        prepared_push_count = pushes.len(),
        "notify concurrent fanout prepared provider pushes"
    );
    let mut pending = Vec::with_capacity(pushes.len());
    for prepared in pushes {
        let response = provider_workers.dispatch(Arc::clone(store), prepared.clone())?;
        pending.push((prepared, response));
    }
    let mut attempts = Vec::with_capacity(pending.len());
    for (prepared, response) in pending {
        let received = response.recv().map_err(|error| {
            ramflux_node_core::NodeCoreError::ItestHttp(format!(
                "notify provider worker response closed: {error}"
            ))
        })?;
        let accepted = note_provider_send(store, &prepared, received);
        let attempt = ramflux_node_core::redacted_provider_attempt(
            &entry,
            &prepared,
            accepted,
            (!accepted).then(|| "provider_send_failed".to_owned()),
        );
        store.record_provider_attempt(attempt.clone())?;
        attempts.push(attempt);
    }
    Ok(S13WakeResponse { entry, attempts })
}

#[cfg(all(target_os = "linux", feature = "compio-notify"))]
fn notify_compio_runtime_from_store(
    store: &Arc<ramflux_node_core::NotifyRedbStore>,
    store_gate: &Arc<Mutex<()>>,
) -> Result<NotifyRuntime, ramflux_node_core::NodeCoreError> {
    notify_compio_runtime(store, store_gate)
}

#[cfg(not(all(target_os = "linux", feature = "compio-notify")))]
fn notify_compio_runtime_from_store(
    _store: &Arc<ramflux_node_core::NotifyRedbStore>,
    _store_gate: &Arc<Mutex<()>>,
) -> Result<NotifyRuntime, ramflux_node_core::NodeCoreError> {
    Err(notify_compio_runtime_error())
}

#[cfg(all(target_os = "linux", feature = "compio-notify"))]
fn notify_compio_runtime(
    store: &Arc<ramflux_node_core::NotifyRedbStore>,
    store_gate: &Arc<Mutex<()>>,
) -> Result<NotifyRuntime, ramflux_node_core::NodeCoreError> {
    Ok(NotifyRuntime::Compio(CompioNotifyRuntime::new(store, store_gate)?))
}

#[cfg(not(all(target_os = "linux", feature = "compio-notify")))]
fn notify_compio_runtime_error() -> ramflux_node_core::NodeCoreError {
    ramflux_node_core::NodeCoreError::ItestHttp(
        "RAMFLUX_NOTIFY_RUNTIME=compio requested but compio-notify is not compiled".to_owned(),
    )
}

#[cfg(all(target_os = "linux", feature = "compio-notify"))]
struct CompioNotifyRuntime {
    shards: Vec<tokio::sync::mpsc::Sender<NotifyFanoutCommand>>,
    _fanout_workers: std::sync::Arc<NotifyFanoutWorkerPool>,
    runtime_thread: Option<std::thread::JoinHandle<()>>,
}

#[cfg(all(target_os = "linux", feature = "compio-notify"))]
impl Drop for CompioNotifyRuntime {
    fn drop(&mut self) {
        self.shards.clear();
        if let Some(thread) = self.runtime_thread.take()
            && thread.join().is_err()
        {
            tracing::error!("notify compio runtime panicked during shutdown");
        }
    }
}

#[cfg(all(target_os = "linux", feature = "compio-notify"))]
impl CompioNotifyRuntime {
    fn new(
        store: &Arc<ramflux_node_core::NotifyRedbStore>,
        store_gate: &Arc<Mutex<()>>,
    ) -> Result<Self, ramflux_node_core::NodeCoreError> {
        let shard_count = notify_runtime_usize_env("RAMFLUX_NOTIFY_COMPIO_SHARDS", || {
            std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get)
        });
        let shard_count = shard_count.max(1);
        let command_capacity =
            notify_runtime_usize_env("RAMFLUX_NOTIFY_COMPIO_QUEUE_CAPACITY", || 1024).max(1);
        let provider_worker_count =
            notify_runtime_usize_env("RAMFLUX_NOTIFY_COMPIO_PROVIDER_WORKERS", || {
                shard_count.saturating_mul(2).max(1)
            })
            .max(1);
        let fanout_worker_count =
            notify_runtime_usize_env("RAMFLUX_NOTIFY_COMPIO_FANOUT_WORKERS", || shard_count).max(1);
        let provider_workers =
            std::sync::Arc::new(ConcurrentProviderPushWorkerPool::new(provider_worker_count)?);
        let fanout_workers = std::sync::Arc::new(NotifyFanoutWorkerPool::new(
            fanout_worker_count,
            command_capacity,
            store,
            store_gate,
            &provider_workers,
        )?);
        let mut senders = Vec::with_capacity(shard_count);
        let mut receivers = Vec::with_capacity(shard_count);
        for _index in 0..shard_count {
            let (sender, receiver) = tokio::sync::mpsc::channel(command_capacity);
            senders.push(sender);
            receivers.push(receiver);
        }
        let thread_fanout_workers = std::sync::Arc::clone(&fanout_workers);
        let runtime_thread = std::thread::Builder::new()
            .name("ramflux-notify-compio-fanout".to_owned())
            .spawn(move || {
                if let Err(error) = run_notify_compio_runtime(receivers, thread_fanout_workers) {
                    tracing::error!(%error, "notify compio runtime stopped");
                }
            })
            .map_err(|source| ramflux_node_core::NodeCoreError::ItestHttp(source.to_string()))?;
        tracing::info!(
            shard_count,
            fanout_worker_count,
            provider_worker_count,
            "notify compio per-shard fanout runtime initialized"
        );
        Ok(Self {
            shards: senders,
            _fanout_workers: fanout_workers,
            runtime_thread: Some(runtime_thread),
        })
    }

    fn dispatch_s13_wake(
        &self,
        request: &S13WakeRequest,
    ) -> Result<S13WakeResponse, ramflux_node_core::NodeCoreError> {
        let shard = notify_shard_index(&request.device_delivery_id, self.shards.len());
        let (reply, response) = std::sync::mpsc::sync_channel(1);
        let command = NotifyFanoutCommand { request: request.clone(), reply };
        self.shards[shard].blocking_send(command).map_err(|error| {
            ramflux_node_core::NodeCoreError::ItestHttp(format!(
                "notify compio shard queue closed: {error}"
            ))
        })?;
        response.recv().map_err(|error| {
            ramflux_node_core::NodeCoreError::ItestHttp(format!(
                "notify compio fanout response closed: {error}"
            ))
        })?
    }
}

#[cfg(all(target_os = "linux", feature = "compio-notify"))]
struct NotifyFanoutCommand {
    request: S13WakeRequest,
    reply: std::sync::mpsc::SyncSender<Result<S13WakeResponse, ramflux_node_core::NodeCoreError>>,
}

#[cfg(all(target_os = "linux", feature = "compio-notify"))]
struct NotifyFanoutJob {
    request: S13WakeRequest,
    reply: std::sync::mpsc::SyncSender<Result<S13WakeResponse, ramflux_node_core::NodeCoreError>>,
}

#[cfg(all(target_os = "linux", feature = "compio-notify"))]
struct NotifyFanoutWorkerPool {
    senders: Vec<std::sync::mpsc::SyncSender<NotifyFanoutJob>>,
    next_worker: std::sync::atomic::AtomicUsize,
    threads: Vec<std::thread::JoinHandle<()>>,
}

#[cfg(all(target_os = "linux", feature = "compio-notify"))]
impl Drop for NotifyFanoutWorkerPool {
    fn drop(&mut self) {
        self.senders.clear();
        for thread in self.threads.drain(..) {
            if thread.join().is_err() {
                tracing::error!("notify runtime worker panicked during shutdown");
            }
        }
    }
}

#[cfg(all(target_os = "linux", feature = "compio-notify"))]
impl NotifyFanoutWorkerPool {
    fn new(
        worker_count: usize,
        queue_capacity: usize,
        store: &Arc<ramflux_node_core::NotifyRedbStore>,
        store_gate: &Arc<Mutex<()>>,
        provider_workers: &std::sync::Arc<ConcurrentProviderPushWorkerPool>,
    ) -> Result<Self, ramflux_node_core::NodeCoreError> {
        let mut senders = Vec::with_capacity(worker_count);
        let mut threads = Vec::with_capacity(worker_count);
        for worker_id in 0..worker_count {
            let (sender, receiver) = std::sync::mpsc::sync_channel(queue_capacity);
            let thread_provider_workers = std::sync::Arc::clone(provider_workers);
            let thread_store = Arc::clone(store);
            let thread_store_gate = Arc::clone(store_gate);
            let thread = std::thread::Builder::new()
                .name(format!("ramflux-notify-fanout-worker-{worker_id}"))
                .spawn(move || {
                    notify_fanout_worker_loop(
                        &receiver,
                        &thread_store,
                        &thread_store_gate,
                        &thread_provider_workers,
                    );
                })
                .map_err(|source| {
                    ramflux_node_core::NodeCoreError::ItestHttp(source.to_string())
                })?;
            senders.push(sender);
            threads.push(thread);
        }
        Ok(Self { senders, next_worker: std::sync::atomic::AtomicUsize::new(0), threads })
    }

    fn try_dispatch(&self, job: NotifyFanoutJob) -> Result<(), Box<NotifyFanoutJob>> {
        let worker = self.next_worker.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            % self.senders.len();
        self.senders[worker].try_send(job).map_err(|error| match error {
            std::sync::mpsc::TrySendError::Full(job)
            | std::sync::mpsc::TrySendError::Disconnected(job) => Box::new(job),
        })
    }
}

#[cfg(all(target_os = "linux", feature = "compio-notify"))]
fn run_notify_compio_runtime(
    receivers: Vec<tokio::sync::mpsc::Receiver<NotifyFanoutCommand>>,
    fanout_workers: std::sync::Arc<NotifyFanoutWorkerPool>,
) -> anyhow::Result<()> {
    let runtime = compio::runtime::Runtime::new()?;
    runtime.block_on(async move {
        let mut shards = Vec::with_capacity(receivers.len());
        for receiver in receivers {
            let workers = std::sync::Arc::clone(&fanout_workers);
            shards.push(compio::runtime::spawn(async move {
                notify_compio_shard_loop(receiver, workers).await;
            }));
        }
        for shard in shards {
            let _ = shard.await;
        }
    });
    Ok(())
}

#[cfg(all(target_os = "linux", feature = "compio-notify"))]
async fn notify_compio_shard_loop(
    mut receiver: tokio::sync::mpsc::Receiver<NotifyFanoutCommand>,
    fanout_workers: std::sync::Arc<NotifyFanoutWorkerPool>,
) {
    while let Some(command) = receiver.recv().await {
        let job = NotifyFanoutJob { request: command.request, reply: command.reply };
        if let Err(job) = fanout_workers.try_dispatch(job) {
            let _result = job.reply.send(Err(ramflux_node_core::NodeCoreError::ItestHttp(
                "notify compio fanout worker queue is full".to_owned(),
            )));
        }
    }
}

#[cfg(all(target_os = "linux", feature = "compio-notify"))]
fn notify_fanout_worker_loop(
    receiver: &std::sync::mpsc::Receiver<NotifyFanoutJob>,
    store: &Arc<ramflux_node_core::NotifyRedbStore>,
    store_gate: &Arc<Mutex<()>>,
    provider_workers: &std::sync::Arc<ConcurrentProviderPushWorkerPool>,
) {
    while let Ok(job) = receiver.recv() {
        let result =
            dispatch_s13_wake_concurrent_worker(store, store_gate, provider_workers, &job.request);
        let _result = job.reply.send(result);
    }
}

fn notify_runtime_usize_env(name: &str, default: impl FnOnce() -> usize) -> usize {
    ramflux_node_core::environment::parsed::<usize>(name)
        .filter(|value| *value > 0)
        .unwrap_or_else(default)
}

fn env_key(value: &str) -> String {
    value.replace('-', "_").to_ascii_uppercase()
}

fn notify_shard_index(device_delivery_id: &str, shard_count: usize) -> usize {
    use std::hash::{Hash, Hasher};

    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    device_delivery_id.hash(&mut hasher);
    let hash = hasher.finish();
    let shard_count = u64::try_from(shard_count).unwrap_or(1).max(1);
    usize::try_from(hash % shard_count).unwrap_or(0)
}

fn handle_s13_wake_value(
    store: &ramflux_node_core::NotifyRedbStore,
    store_gate: &Arc<Mutex<()>>,
    runtime: &NotifyRuntime,
    request: &S13WakeRequest,
) -> Result<S13WakeResponse, ramflux_node_core::NodeCoreError> {
    runtime.dispatch_s13_wake(store, store_gate, request)
}

fn handle_s13_wake_async_accept(
    store: &ramflux_node_core::NotifyRedbStore,
    request: &S13WakeRequest,
) -> Result<S13WakeResponse, ramflux_node_core::NodeCoreError> {
    let Some(wake) = request.queued_provider_wake()? else {
        return Ok(no_push_response(request));
    };
    let entry = store.queue_wake_for_async_accept(
        &request.device_delivery_id,
        wake,
        request.queued_at.unwrap_or_else(ramflux_node_core::now_unix_seconds),
        request.dnd_active.unwrap_or(false),
    )?;
    Ok(S13WakeResponse { entry, attempts: Vec::new() })
}

fn dispatch_s13_wake_current(
    store: &ramflux_node_core::NotifyRedbStore,
    _store_gate: &Arc<Mutex<()>>,
    request: &S13WakeRequest,
) -> Result<S13WakeResponse, ramflux_node_core::NodeCoreError> {
    let Some(wake) = request.queued_provider_wake()? else {
        return Ok(no_push_response(request));
    };
    let (entry, pushes) = store.queue_wake_for_push(
        &request.device_delivery_id,
        wake,
        request.queued_at.unwrap_or_else(ramflux_node_core::now_unix_seconds),
        request.dnd_active.unwrap_or(false),
    )?;
    tracing::debug!(
        prepared_push_count = pushes.len(),
        "notify wake dispatch prepared provider pushes"
    );
    let mut attempts = Vec::with_capacity(pushes.len());
    for prepared in pushes {
        let accepted = note_provider_send(store, &prepared, send_provider_push(store, &prepared));
        let attempt = ramflux_node_core::redacted_provider_attempt(
            &entry,
            &prepared,
            accepted,
            (!accepted).then(|| "provider_send_failed".to_owned()),
        );
        store.record_provider_attempt(attempt.clone())?;
        attempts.push(attempt);
    }
    Ok(S13WakeResponse { entry, attempts })
}

fn notify_async_accept_enabled() -> bool {
    notify_default_enabled_env(NOTIFY_ASYNC_ACCEPT_ENV)
}

#[cfg(feature = "itest-http")]
fn notify_wal_raw_enqueue_enabled() -> bool {
    ramflux_node_core::environment::var(NOTIFY_WAL_RAW_ENQUEUE_ENV).as_deref() == Ok("1")
}

fn notify_default_enabled_env(name: &str) -> bool {
    notify_default_enabled_from_value(ramflux_node_core::environment::var(name).ok().as_deref())
}

fn notify_default_enabled_from_value(value: Option<&str>) -> bool {
    let Some(value) = value else {
        return true;
    };
    let trimmed = value.trim();
    !(trimmed == "0"
        || trimmed.eq_ignore_ascii_case("false")
        || trimmed.eq_ignore_ascii_case("off")
        || trimmed.eq_ignore_ascii_case("no"))
}

fn notify_mesh_ingress_enabled() -> bool {
    notify_mesh_ingress_enabled_from_value(
        ramflux_node_core::environment::var(NOTIFY_MESH_INGRESS_ENV).ok().as_deref(),
    )
}

fn notify_mesh_ingress_enabled_from_value(value: Option<&str>) -> bool {
    notify_default_enabled_from_value(value)
}

fn notify_mesh_listen_addr() -> Option<String> {
    notify_mesh_listen_addr_from_value(
        ramflux_node_core::environment::var(NOTIFY_MESH_LISTEN_ADDR_ENV).ok().as_deref(),
    )
}

fn notify_mesh_listen_addr_from_value(value: Option<&str>) -> Option<String> {
    let Some(value) = value else {
        return Some(DEFAULT_NOTIFY_MESH_LISTEN_ADDR.to_owned());
    };
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }
    if trimmed.parse::<std::net::SocketAddr>().is_err() {
        ramflux_node_core::environment::warn_invalid(NOTIFY_MESH_LISTEN_ADDR_ENV);
        return Some(DEFAULT_NOTIFY_MESH_LISTEN_ADDR.to_owned());
    }
    Some(trimmed.to_owned())
}

fn notify_mesh_tls_config(
    config: &ramflux_node_core::NodeServiceConfig,
) -> ramflux_transport::MeshTlsConfig {
    ramflux_transport::MeshTlsConfig {
        ca_cert: config.mesh.ca_cert.clone().into(),
        service_cert: config.mesh.service_cert.clone().into(),
        service_key: config.mesh.service_key.clone().into(),
    }
}

fn start_notify_async_delivery_workers(
    store: &Arc<ramflux_node_core::NotifyRedbStore>,
) -> Result<(), ramflux_node_core::NodeCoreError> {
    let worker_count = notify_runtime_usize_env("RAMFLUX_NOTIFY_ASYNC_DELIVERY_WORKERS", || {
        std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get)
    })
    .max(1);
    let scan_limit =
        notify_runtime_usize_env("RAMFLUX_NOTIFY_ASYNC_DELIVERY_SCAN_LIMIT", || 256).max(1);
    let idle_sleep_ms =
        notify_runtime_usize_env("RAMFLUX_NOTIFY_ASYNC_DELIVERY_IDLE_SLEEP_MS", || 10).max(1);
    let provider_worker_count =
        notify_runtime_usize_env("RAMFLUX_NOTIFY_ASYNC_PROVIDER_WORKERS", || {
            worker_count.saturating_mul(2).max(1)
        })
        .max(1);
    let provider_workers = Arc::new(ConcurrentProviderPushWorkerPool::new(provider_worker_count)?);
    let in_flight = Arc::new(Mutex::new(BTreeSet::<String>::new()));
    for worker_id in 0..worker_count {
        let thread_store = Arc::clone(store);
        let thread_provider_workers = Arc::clone(&provider_workers);
        let thread_in_flight = Arc::clone(&in_flight);
        ramflux_node_core::spawn_service_worker(
            format!("ramflux-notify-async-delivery-{worker_id}"),
            move |_| {
                notify_async_delivery_worker_loop(
                    &thread_store,
                    &thread_provider_workers,
                    &thread_in_flight,
                    scan_limit,
                    Duration::from_millis(u64::try_from(idle_sleep_ms).unwrap_or(u64::MAX)),
                );
            },
        )
        .map_err(|source| ramflux_node_core::NodeCoreError::ItestHttp(source.to_string()))?;
    }
    tracing::info!(
        worker_count,
        provider_worker_count,
        scan_limit,
        idle_sleep_ms,
        "notify async accept delivery workers initialized"
    );
    Ok(())
}

fn log_notify_wal_recovery(store: &ramflux_node_core::NotifyRedbStore) {
    for shard in store.notify_wal_recovered_counts() {
        tracing::debug!(
            shard_id = shard.shard_id,
            recovered_queue_entries = shard.counts.queue_entry_count,
            recovered_raw_wakes = shard.counts.raw_wake_count,
            recovered_provider_attempt_queues = shard.counts.provider_attempt_queue_count,
            "notify WAL shard recovered"
        );
    }
}

fn notify_async_delivery_worker_loop(
    store: &Arc<ramflux_node_core::NotifyRedbStore>,
    provider_workers: &ConcurrentProviderPushWorkerPool,
    in_flight: &Arc<Mutex<BTreeSet<String>>>,
    scan_limit: usize,
    idle_sleep: Duration,
) {
    while !ramflux_node_core::service_shutdown_token().is_cancelled() {
        match notify_async_claim_entries(store, in_flight, scan_limit) {
            Ok(entries) if entries.is_empty() => std::thread::sleep(idle_sleep),
            Ok(entries) => {
                for entry in entries {
                    let queue_id = entry.queue_id.clone();
                    if let Err(error) = notify_async_deliver_entry(store, provider_workers, &entry)
                    {
                        tracing::warn!(
                            queue_id = queue_id,
                            %error,
                            "notify async delivery failed"
                        );
                    }
                    notify_async_release_entry(in_flight, &queue_id);
                }
            }
            Err(error) => {
                tracing::warn!(%error, "notify async delivery scan failed");
                std::thread::sleep(idle_sleep);
            }
        }
    }
}

fn notify_async_claim_entries(
    store: &ramflux_node_core::NotifyRedbStore,
    in_flight: &Arc<Mutex<BTreeSet<String>>>,
    scan_limit: usize,
) -> Result<Vec<ramflux_node_core::NotifyQueueEntry>, ramflux_node_core::NodeCoreError> {
    if tracing::enabled!(tracing::Level::TRACE) {
        for shard in store.notify_wal_pending_counts(scan_limit.saturating_mul(2)) {
            tracing::trace!(
                shard_id = shard.shard_id,
                pending_queue_entries = shard.counts.queue_entry_count,
                pending_raw_wakes = shard.counts.raw_wake_count,
                "notify async delivery WAL pending scan"
            );
        }
    }
    let candidates = store.pending_entries_without_attempts(scan_limit.saturating_mul(2))?;
    let candidate_count = candidates.len();
    let mut claimed = Vec::new();
    let mut guard = in_flight.lock().map_err(|source| {
        ramflux_node_core::NodeCoreError::ItestHttp(format!(
            "notify async in-flight lock poisoned: {source}"
        ))
    })?;
    for entry in candidates {
        if claimed.len() >= scan_limit {
            break;
        }
        if guard.insert(entry.queue_id.clone()) {
            claimed.push(entry);
        }
    }
    tracing::trace!(
        candidate_count,
        claimed_count = claimed.len(),
        scan_limit,
        "notify async delivery claimed pending entries"
    );
    Ok(claimed)
}

fn notify_async_release_entry(in_flight: &Arc<Mutex<BTreeSet<String>>>, queue_id: &str) {
    match in_flight.lock() {
        Ok(mut guard) => {
            guard.remove(queue_id);
        }
        Err(error) => tracing::warn!(%error, "notify async in-flight lock poisoned on release"),
    }
}

fn notify_async_deliver_entry(
    store: &Arc<ramflux_node_core::NotifyRedbStore>,
    provider_workers: &ConcurrentProviderPushWorkerPool,
    entry: &ramflux_node_core::NotifyQueueEntry,
) -> Result<(), ramflux_node_core::NodeCoreError> {
    let pushes = store.prepare_provider_pushes_for_entry(entry)?;
    if pushes.is_empty() {
        tracing::debug!("notify async delivery found no provider pushes for pending entry");
        return Ok(());
    }
    tracing::trace!(push_count = pushes.len(), "notify async delivery prepared provider pushes");
    let mut pending = Vec::with_capacity(pushes.len());
    for prepared in pushes {
        let response = provider_workers.dispatch(Arc::clone(store), prepared.clone())?;
        pending.push((prepared, response));
    }
    let total_count = pending.len();
    let mut accepted_count = 0_usize;
    for (prepared, response) in pending {
        let received = response.recv().map_err(|error| {
            ramflux_node_core::NodeCoreError::ItestHttp(format!(
                "notify async provider worker response closed: {error}"
            ))
        })?;
        let accepted = note_provider_send(store, &prepared, received);
        if accepted {
            accepted_count = accepted_count.saturating_add(1);
        }
        let attempt = ramflux_node_core::redacted_provider_attempt(
            entry,
            &prepared,
            accepted,
            (!accepted).then(|| "provider_send_failed".to_owned()),
        );
        store.record_provider_attempt(attempt)?;
    }
    tracing::trace!(
        accepted_count,
        total_count,
        "notify async delivery recorded provider attempts"
    );
    Ok(())
}

fn send_provider_push(
    store: &ramflux_node_core::NotifyRedbStore,
    prepared: &ramflux_node_core::PreparedProviderPush,
) -> Result<provider_outcome::ProviderSendStatus, ramflux_node_core::NodeCoreError> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|source| ramflux_node_core::NodeCoreError::ItestHttp(source.to_string()))?;
    runtime.block_on(async { send_provider_push_h2_with_retry(store, prepared).await })
}

fn send_provider_push_with_runtime(
    runtime: &tokio::runtime::Runtime,
    h2_pool: &ProviderH2ConnectionPool,
    store: &ramflux_node_core::NotifyRedbStore,
    prepared: &ramflux_node_core::PreparedProviderPush,
) -> Result<provider_outcome::ProviderSendStatus, ramflux_node_core::NodeCoreError> {
    runtime
        .block_on(async { send_provider_push_h2_pooled_with_retry(store, prepared, h2_pool).await })
}

async fn send_provider_push_h2_with_retry(
    store: &ramflux_node_core::NotifyRedbStore,
    prepared: &ramflux_node_core::PreparedProviderPush,
) -> Result<provider_outcome::ProviderSendStatus, ramflux_node_core::NodeCoreError> {
    send_provider_push_with_retry(store, prepared, || send_provider_push_h2(store, prepared)).await
}

async fn send_provider_push_h2_pooled_with_retry(
    store: &ramflux_node_core::NotifyRedbStore,
    prepared: &ramflux_node_core::PreparedProviderPush,
    h2_pool: &ProviderH2ConnectionPool,
) -> Result<provider_outcome::ProviderSendStatus, ramflux_node_core::NodeCoreError> {
    send_provider_push_with_retry(store, prepared, || {
        send_provider_push_h2_pooled(store, prepared, h2_pool)
    })
    .await
}

fn note_provider_send(
    store: &ramflux_node_core::NotifyRedbStore,
    prepared: &ramflux_node_core::PreparedProviderPush,
    status: Result<provider_outcome::ProviderSendStatus, ramflux_node_core::NodeCoreError>,
) -> bool {
    let status = match status {
        Ok(status) => status,
        Err(error) => {
            tracing::warn!(%error, provider = ?prepared.route.provider, "push provider send failed");
            return false;
        }
    };
    if status == provider_outcome::ProviderSendStatus::InvalidToken
        && let Err(error) = store.delete_snapshotted_route(&prepared.route)
    {
        tracing::warn!(%error, "snapshotted route delete failed");
    }
    status.accepted()
}

async fn send_provider_push_with_retry<'a, F, Fut>(
    store: &'a ramflux_node_core::NotifyRedbStore,
    prepared: &'a ramflux_node_core::PreparedProviderPush,
    mut send: F,
) -> Result<provider_outcome::ProviderSendStatus, ramflux_node_core::NodeCoreError>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<ProviderHttpResponse, ramflux_node_core::NodeCoreError>>
        + 'a,
{
    if !store.begin_wake_send(&prepared.payload.wake_id)? {
        return Ok(provider_outcome::ProviderSendStatus::Failed);
    }
    let mut attempts_used = 0_u32;
    let mut invalidated = false;
    loop {
        let now = ramflux_node_core::now_unix_seconds();
        attempts_used = attempts_used.saturating_add(1);
        let attempt_limit = provider_outcome::attempt_timeout(now, prepared.expires_at);
        if attempt_limit.is_zero() {
            return Ok(provider_outcome::ProviderSendStatus::Failed);
        }
        let attempt_result = match tokio::time::timeout(attempt_limit, send()).await {
            Ok(result) => result,
            Err(_elapsed) => Err(ramflux_node_core::NodeCoreError::ItestHttp(
                "provider attempt timed out".to_owned(),
            )),
        };
        if let Err(ramflux_node_core::NodeCoreError::InvalidConfiguration(message)) =
            &attempt_result
            && message == "wake send dropped"
        {
            return Ok(provider_outcome::ProviderSendStatus::Failed);
        }
        let (outcome, retry_after, quota) = match attempt_result {
            Ok(response) => classify_observed_response(prepared, &response),
            Err(_error) => {
                tracing::debug!(
                    provider = ?prepared.route.provider,
                    "push provider send attempt failed"
                );
                (provider_outcome::ProviderOutcome::Transient, None, false)
            }
        };
        if provider_outcome::invalidates_token(outcome) {
            invalidated = true;
            tracing::warn!(
                provider = ?prepared.route.provider,
                "push provider rejected the snapshotted token"
            );
        }
        match provider_outcome::next_attempt(
            provider_outcome::AttemptClock { attempts_used, now, expires_at: prepared.expires_at },
            outcome,
            retry_after,
            quota,
            provider_jitter_bps(),
        ) {
            provider_outcome::AttemptStep::Stop(provider_outcome::ProviderOutcome::Accepted) => {
                return Ok(provider_outcome::ProviderSendStatus::Accepted);
            }
            provider_outcome::AttemptStep::Stop(_) if invalidated => {
                return Ok(provider_outcome::ProviderSendStatus::InvalidToken);
            }
            provider_outcome::AttemptStep::Stop(_) => {
                return Ok(provider_outcome::ProviderSendStatus::Failed);
            }
            provider_outcome::AttemptStep::Wait { delay, .. } => {
                tracing::debug!(
                    provider = ?prepared.route.provider,
                    "push provider send will retry inside the original deadline"
                );
                tokio::time::sleep(delay).await;
            }
        }
    }
}

fn classify_observed_response(
    prepared: &ramflux_node_core::PreparedProviderPush,
    response: &ProviderHttpResponse,
) -> (provider_outcome::ProviderOutcome, Option<u64>, bool) {
    provider_outcome::classify_provider_response(
        provider_family(prepared),
        response.status,
        &response.body,
        response.body_truncated,
        response.retry_after.as_deref(),
    )
}

fn provider_family(
    prepared: &ramflux_node_core::PreparedProviderPush,
) -> provider_outcome::ProviderFamily {
    match prepared.route.provider {
        ramflux_node_core::PushProviderKind::Apns
        | ramflux_node_core::PushProviderKind::ApnsVoip => provider_outcome::ProviderFamily::Apns,
        ramflux_node_core::PushProviderKind::Fcm => provider_outcome::ProviderFamily::Fcm,
        ramflux_node_core::PushProviderKind::WebPush => provider_outcome::ProviderFamily::WebPush,
    }
}

fn provider_jitter_bps() -> u16 {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.subsec_nanos());
    u16::try_from(nanos % 2_001).unwrap_or(0)
}

async fn send_provider_push_h2(
    store: &ramflux_node_core::NotifyRedbStore,
    prepared: &ramflux_node_core::PreparedProviderPush,
) -> Result<ProviderHttpResponse, ramflux_node_core::NodeCoreError> {
    let _preparation = store.send_authority().reserve_preparation()?;
    let deadline = tokio::time::Instant::from_std(store.provider_push_deadline(prepared)?);
    tokio::time::timeout_at(deadline, async {
        let request = build_provider_request(prepared).await?;
        check_call_request_budget(prepared, &request)?;
        h2_post_boundary(&request, provider_issuance::WakeBoundary { store, prepared }).await
    })
    .await
    .map_err(|_| wake_send_dropped())?
}

async fn send_provider_push_h2_pooled(
    store: &ramflux_node_core::NotifyRedbStore,
    prepared: &ramflux_node_core::PreparedProviderPush,
    h2_pool: &ProviderH2ConnectionPool,
) -> Result<ProviderHttpResponse, ramflux_node_core::NodeCoreError> {
    let _preparation = store.send_authority().reserve_preparation()?;
    let deadline = tokio::time::Instant::from_std(store.provider_push_deadline(prepared)?);
    tokio::time::timeout_at(deadline, async {
        let request = build_provider_request(prepared).await?;
        check_call_request_budget(prepared, &request)?;
        h2_pool
            .post_json_boundary(&request, provider_issuance::WakeBoundary { store, prepared })
            .await
    })
    .await
    .map_err(|_| wake_send_dropped())?
}

fn check_call_request_budget(
    prepared: &ramflux_node_core::PreparedProviderPush,
    request: &ProviderHttpRequest,
) -> Result<(), ramflux_node_core::NodeCoreError> {
    if matches!(
        prepared.payload.delivery_class,
        ramflux_protocol::NotificationDeliveryClass::CallWakeNotification
    ) {
        let bytes = request
            .headers
            .iter()
            .try_fold(request.body.len(), |size, (key, value)| {
                size.checked_add(key.len()).and_then(|size| size.checked_add(value.len()))
            })
            .ok_or(ramflux_node_core::send_authority::SendAuthorityError::Capacity)?;
        if bytes > 4096 {
            return Err(ramflux_node_core::send_authority::SendAuthorityError::Capacity.into());
        }
    }
    Ok(())
}

fn parse_https_url(url: &str) -> Result<ParsedHttpsUrl, ramflux_node_core::NodeCoreError> {
    let Some(rest) = url.strip_prefix("https://") else {
        return Err(ramflux_node_core::NodeCoreError::ItestHttp(
            "unsupported push provider url".to_owned(),
        ));
    };
    let (host_port, path) = rest
        .split_once('/')
        .map_or((rest, "/"), |(host_port, path)| (host_port, &url[url.len() - path.len() - 1..]));
    let (host, port) = split_host_port(host_port)?;
    Ok(ParsedHttpsUrl { host, port, path: path.to_owned() })
}

fn split_host_port(host_port: &str) -> Result<(String, u16), ramflux_node_core::NodeCoreError> {
    let Some((host, port)) = host_port.rsplit_once(':') else {
        return Err(ramflux_node_core::NodeCoreError::ItestHttp(
            "provider endpoint missing port".to_owned(),
        ));
    };
    let port = port
        .parse::<u16>()
        .map_err(|source| ramflux_node_core::NodeCoreError::ItestHttp(source.to_string()))?;
    Ok((host.to_owned(), port))
}

#[derive(Clone, Debug)]
struct ParsedHttpsUrl {
    host: String,
    port: u16,
    path: String,
}

#[derive(Clone, Debug)]
struct ProviderHttpRequest {
    endpoint: ParsedHttpsUrl,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    ca_pem: Option<String>,
}

#[derive(Clone, Debug)]
struct ProviderHttpResponse {
    status: u16,
    body: Vec<u8>,
    retry_after: Option<String>,
    body_truncated: bool,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct ProviderH2ConnectionKey {
    host: String,
    port: u16,
    ca_fingerprint: String,
}

struct ProviderH2ConnectionPool {
    clients: Mutex<HashMap<ProviderH2ConnectionKey, h2::client::SendRequest<bytes::Bytes>>>,
    max_connections: usize,
}

impl ProviderH2ConnectionPool {
    fn from_env() -> Self {
        let max_connections =
            notify_runtime_usize_env("RAMFLUX_NOTIFY_PROVIDER_H2_POOL_MAX_CONNECTIONS", || 128)
                .clamp(1, 128);
        Self { clients: Mutex::new(HashMap::new()), max_connections }
    }

    async fn post_json_boundary<F: SendBoundary>(
        &self,
        request: &ProviderHttpRequest,
        mut boundary: F,
    ) -> Result<ProviderHttpResponse, ramflux_node_core::NodeCoreError> {
        let key = ProviderH2ConnectionKey::from_request(request);
        match self.post_json_once(request, &key, &mut boundary).await {
            Ok(response) => Ok(response),
            Err(error) if is_wake_send_dropped(&error) => Err(error),
            Err(error) => {
                self.evict(&key)?;
                tracing::debug!(%error,"provider h2 pooled request failed; reconnecting once");
                self.post_json_once(request, &key, &mut boundary).await
            }
        }
    }

    async fn post_json_once<F: SendBoundary>(
        &self,
        request: &ProviderHttpRequest,
        key: &ProviderH2ConnectionKey,
        boundary: &mut F,
    ) -> Result<ProviderHttpResponse, ramflux_node_core::NodeCoreError> {
        let mut client = self.client_for(request, key).await?;
        post_json_with_h2_client(request, &mut client, boundary).await
    }

    async fn client_for(
        &self,
        request: &ProviderHttpRequest,
        key: &ProviderH2ConnectionKey,
    ) -> Result<h2::client::SendRequest<bytes::Bytes>, ramflux_node_core::NodeCoreError> {
        if let Some(client) = self.lock_clients()?.get(key).cloned() {
            return Ok(client);
        }
        let client = connect_provider_h2(request).await?;
        let mut clients = self.lock_clients()?;
        if clients.len() >= self.max_connections
            && let Some(oldest_key) = clients.keys().next().cloned()
        {
            clients.remove(&oldest_key);
        }
        clients.insert(key.clone(), client.clone());
        Ok(client)
    }

    fn evict(&self, key: &ProviderH2ConnectionKey) -> Result<(), ramflux_node_core::NodeCoreError> {
        self.lock_clients()?.remove(key);
        Ok(())
    }

    fn lock_clients(
        &self,
    ) -> Result<
        std::sync::MutexGuard<
            '_,
            HashMap<ProviderH2ConnectionKey, h2::client::SendRequest<bytes::Bytes>>,
        >,
        ramflux_node_core::NodeCoreError,
    > {
        self.clients.lock().map_err(|source| {
            ramflux_node_core::NodeCoreError::ItestHttp(format!(
                "provider h2 pool lock poisoned: {source}"
            ))
        })
    }
}

impl ProviderH2ConnectionKey {
    fn from_request(request: &ProviderHttpRequest) -> Self {
        Self {
            host: request.endpoint.host.clone(),
            port: request.endpoint.port,
            ca_fingerprint: provider_ca_fingerprint(request.ca_pem.as_deref()),
        }
    }
}

fn provider_ca_fingerprint(ca_pem: Option<&str>) -> String {
    use sha2::Digest;

    let mut hasher = sha2::Sha256::new();
    hasher.update(b"ramflux.notify.provider_h2_pool_ca.v1");
    hasher.update([0]);
    hasher.update(ca_pem.unwrap_or_default().as_bytes());
    let digest = hasher.finalize();
    let mut fingerprint = String::with_capacity(digest.len() * 2);
    for byte in digest {
        let _result = write!(&mut fingerprint, "{byte:02x}");
    }
    fingerprint
}

async fn build_provider_request(
    prepared: &ramflux_node_core::PreparedProviderPush,
) -> Result<ProviderHttpRequest, ramflux_node_core::NodeCoreError> {
    match &prepared.credential {
        ramflux_node_core::ProviderCredential::Apns(credential) => {
            build_apns_request(prepared, credential)
        }
        ramflux_node_core::ProviderCredential::Fcm(credential) => {
            build_fcm_request(prepared, credential).await
        }
        ramflux_node_core::ProviderCredential::WebPush(credential) => {
            build_webpush_request(prepared, credential)
        }
    }
}

fn build_apns_request(
    prepared: &ramflux_node_core::PreparedProviderPush,
    credential: &ramflux_node_core::ApnsProviderCredential,
) -> Result<ProviderHttpRequest, ramflux_node_core::NodeCoreError> {
    let mut endpoint = parse_https_url(&prepared.route.endpoint)?;
    if endpoint.path == "/" {
        endpoint.path = format!("/3/device/{}", prepared.route.token);
    }
    let jwt = apns_jwt(credential)?;
    let parts = contract_parts(prepared)?;
    let mut headers = parts.headers;
    headers.extend([
        ("authorization".to_owned(), format!("bearer {jwt}")),
        ("content-type".to_owned(), "application/json".to_owned()),
    ]);
    Ok(ProviderHttpRequest {
        endpoint,
        headers,
        body: parts.body,
        ca_pem: read_optional_secret_ref(credential.provider_ca_pem_ref.as_deref())?,
    })
}

async fn build_fcm_request(
    prepared: &ramflux_node_core::PreparedProviderPush,
    credential: &ramflux_node_core::FcmProviderCredential,
) -> Result<ProviderHttpRequest, ramflux_node_core::NodeCoreError> {
    let endpoint = parse_https_url(&prepared.route.endpoint)?;
    let ca_pem = read_optional_secret_ref(credential.provider_ca_pem_ref.as_deref())?;
    let oauth_token = fcm_oauth_access_token(credential, ca_pem.clone()).await?;
    let parts = contract_parts(prepared)?;
    let mut headers = parts.headers;
    headers.extend([
        ("authorization".to_owned(), format!("Bearer {oauth_token}")),
        ("content-type".to_owned(), "application/json".to_owned()),
    ]);
    Ok(ProviderHttpRequest { endpoint, headers, body: parts.body, ca_pem })
}

fn build_webpush_request(
    prepared: &ramflux_node_core::PreparedProviderPush,
    credential: &ramflux_node_core::WebPushProviderCredential,
) -> Result<ProviderHttpRequest, ramflux_node_core::NodeCoreError> {
    let endpoint = parse_https_url(&prepared.route.endpoint)?;
    let vapid_token = webpush_vapid_jwt(credential, &endpoint)?;
    let vapid_public_key = read_secret_ref(&credential.vapid_public_key_ref)?;
    let parts = contract_parts(prepared)?;
    let mut headers = parts.headers;
    set_provider_header(&mut headers, "content-type", "application/octet-stream".to_owned());
    headers.extend([
        ("authorization".to_owned(), format!("vapid t={vapid_token}, k={vapid_public_key}")),
        ("content-encoding".to_owned(), "aes128gcm".to_owned()),
    ]);
    let plaintext = parts.body;
    let body = encrypt_webpush_aes128gcm(
        prepared.route.webpush_p256dh.as_deref().ok_or_else(|| {
            ramflux_node_core::NodeCoreError::ItestHttp(
                "missing WebPush p256dh subscription key".to_owned(),
            )
        })?,
        prepared.route.webpush_auth.as_deref().ok_or_else(|| {
            ramflux_node_core::NodeCoreError::ItestHttp(
                "missing WebPush auth subscription secret".to_owned(),
            )
        })?,
        &plaintext,
    )?;
    provider_payload::ensure_encrypted_web_body_fits(body.len()).map_err(provider_build_error)?;
    Ok(ProviderHttpRequest {
        endpoint,
        headers,
        body,
        ca_pem: read_optional_secret_ref(credential.provider_ca_pem_ref.as_deref())?,
    })
}

fn contract_parts(
    prepared: &ramflux_node_core::PreparedProviderPush,
) -> Result<provider_payload::ProviderRequestParts, ramflux_node_core::NodeCoreError> {
    let class = provider_payload::provider_class_for_internal(&prepared.payload.delivery_class);
    let mode = wire_mode(prepared, class)?;
    let topic = match &prepared.credential {
        ramflux_node_core::ProviderCredential::Apns(credential) => credential.topic.as_str(),
        ramflux_node_core::ProviderCredential::Fcm(_)
        | ramflux_node_core::ProviderCredential::WebPush(_) => "",
    };
    provider_payload::build_provider_parts(&provider_payload::ProviderBuildInput {
        class,
        wake_id: &prepared.payload.wake_id,
        collapse_key: prepared.payload.collapse_key.as_deref(),
        token: &prepared.route.token,
        topic,
        expires_at: prepared.expires_at,
        now: ramflux_node_core::now_unix_seconds(),
        mode,
    })
    .map_err(provider_build_error)
}

fn wire_mode(
    prepared: &ramflux_node_core::PreparedProviderPush,
    class: ramflux_protocol::WakeClass,
) -> Result<provider_payload::ProviderWireMode, ramflux_node_core::NodeCoreError> {
    match &prepared.credential {
        ramflux_node_core::ProviderCredential::Apns(credential) => {
            let voip_topic = ramflux_node_core::apns_topic_is_voip(&credential.topic);
            let voip_route =
                prepared.route.provider == ramflux_node_core::PushProviderKind::ApnsVoip;
            if voip_route || voip_topic {
                if !voip_route || !voip_topic || class != ramflux_protocol::WakeClass::CallWake {
                    return Err(provider_build_error(
                        provider_payload::ProviderBuildError::VoipRequiresCall,
                    ));
                }
                Ok(provider_payload::ProviderWireMode::ApnsVoip)
            } else {
                Ok(provider_payload::select_apns_mode(class, false, false))
            }
        }
        ramflux_node_core::ProviderCredential::Fcm(_) => {
            Ok(provider_payload::ProviderWireMode::Fcm)
        }
        ramflux_node_core::ProviderCredential::WebPush(_) => {
            Ok(provider_payload::ProviderWireMode::WebPush)
        }
    }
}

fn provider_build_error(
    error: provider_payload::ProviderBuildError,
) -> ramflux_node_core::NodeCoreError {
    ramflux_node_core::NodeCoreError::ItestHttp(format!("provider payload refused: {error:?}"))
}

fn set_provider_header(headers: &mut Vec<(String, String)>, name: &str, value: String) {
    if let Some((_, existing)) = headers.iter_mut().find(|(key, _)| key.eq_ignore_ascii_case(name))
    {
        *existing = value;
    } else {
        headers.push((name.to_owned(), value));
    }
}

fn encrypt_webpush_aes128gcm(
    client_p256dh_base64url: &str,
    auth_secret_base64url: &str,
    plaintext: &[u8],
) -> Result<Vec<u8>, ramflux_node_core::NodeCoreError> {
    use p256::elliptic_curve::Generate;

    let server_secret = p256::SecretKey::try_generate().map_err(|source| {
        ramflux_node_core::NodeCoreError::ItestHttp(format!(
            "WebPush key generation failed: {source}"
        ))
    })?;
    let mut salt = [0_u8; 16];
    getrandom::fill(&mut salt).map_err(|source| {
        ramflux_node_core::NodeCoreError::ItestHttp(format!(
            "WebPush salt generation failed: {source}"
        ))
    })?;
    encrypt_webpush_aes128gcm_with(
        &server_secret,
        salt,
        client_p256dh_base64url,
        auth_secret_base64url,
        plaintext,
    )
}

fn encrypt_webpush_aes128gcm_with(
    server_secret: &p256::SecretKey,
    salt: [u8; 16],
    client_p256dh_base64url: &str,
    auth_secret_base64url: &str,
    plaintext: &[u8],
) -> Result<Vec<u8>, ramflux_node_core::NodeCoreError> {
    use aes_gcm::aead::{Aead, KeyInit};
    use p256::elliptic_curve::sec1::ToSec1Point;

    const WEBPUSH_RECORD_SIZE: u32 = 4096;
    const WEBPUSH_KEY_ID_LEN: u8 = 65;

    let client_public_bytes =
        ramflux_protocol::decode_base64url(client_p256dh_base64url).map_err(|source| {
            ramflux_node_core::NodeCoreError::ItestHttp(format!(
                "invalid WebPush p256dh subscription key: {source}"
            ))
        })?;
    let client_public_bytes: [u8; 65] =
        client_public_bytes.try_into().map_err(|bytes: Vec<u8>| {
            ramflux_node_core::NodeCoreError::ItestHttp(format!(
                "invalid WebPush p256dh length {}, expected 65",
                bytes.len()
            ))
        })?;
    let auth_secret =
        ramflux_protocol::decode_base64url(auth_secret_base64url).map_err(|source| {
            ramflux_node_core::NodeCoreError::ItestHttp(format!(
                "invalid WebPush auth subscription secret: {source}"
            ))
        })?;
    let auth_secret: [u8; 16] = auth_secret.try_into().map_err(|bytes: Vec<u8>| {
        ramflux_node_core::NodeCoreError::ItestHttp(format!(
            "invalid WebPush auth secret length {}, expected 16",
            bytes.len()
        ))
    })?;
    let client_public =
        p256::PublicKey::from_sec1_bytes(&client_public_bytes).map_err(|source| {
            ramflux_node_core::NodeCoreError::ItestHttp(format!(
                "invalid WebPush P-256 public key: {source}"
            ))
        })?;
    let server_public = server_secret.public_key();
    let server_public_bytes = server_public.to_sec1_point(false);
    let server_public_bytes = server_public_bytes.as_bytes();
    let shared_secret =
        p256::ecdh::diffie_hellman(server_secret.to_nonzero_scalar(), client_public.as_affine());

    let mut key_info = Vec::with_capacity("WebPush: info\0".len() + 65 + 65);
    key_info.extend_from_slice(b"WebPush: info\0");
    key_info.extend_from_slice(&client_public_bytes);
    key_info.extend_from_slice(server_public_bytes);
    let key_hkdf =
        hkdf::Hkdf::<sha2::Sha256>::new(Some(&auth_secret), shared_secret.raw_secret_bytes());
    let mut ikm = [0_u8; 32];
    key_hkdf.expand(&key_info, &mut ikm).map_err(|source| {
        ramflux_node_core::NodeCoreError::ItestHttp(format!(
            "WebPush key HKDF expand failed: {source:?}"
        ))
    })?;

    let content_hkdf = hkdf::Hkdf::<sha2::Sha256>::new(Some(&salt), &ikm);
    let mut cek = [0_u8; 16];
    content_hkdf.expand(b"Content-Encoding: aes128gcm\0", &mut cek).map_err(|source| {
        ramflux_node_core::NodeCoreError::ItestHttp(format!(
            "WebPush CEK HKDF expand failed: {source:?}"
        ))
    })?;
    let mut nonce = [0_u8; 12];
    content_hkdf.expand(b"Content-Encoding: nonce\0", &mut nonce).map_err(|source| {
        ramflux_node_core::NodeCoreError::ItestHttp(format!(
            "WebPush nonce HKDF expand failed: {source:?}"
        ))
    })?;

    let mut record_plaintext = Vec::with_capacity(plaintext.len() + 1);
    record_plaintext.extend_from_slice(plaintext);
    record_plaintext.push(0x02);
    let cipher = aes_gcm::Aes128Gcm::new(aes_gcm::Key::<aes_gcm::Aes128Gcm>::from_slice(&cek));
    let ciphertext = cipher
        .encrypt(aes_gcm::Nonce::from_slice(&nonce), record_plaintext.as_slice())
        .map_err(|_| {
            ramflux_node_core::NodeCoreError::ItestHttp(
                "WebPush aes128gcm encryption failed".to_owned(),
            )
        })?;

    let mut body = Vec::with_capacity(16 + 4 + 1 + 65 + ciphertext.len());
    body.extend_from_slice(&salt);
    body.extend_from_slice(&WEBPUSH_RECORD_SIZE.to_be_bytes());
    body.push(WEBPUSH_KEY_ID_LEN);
    body.extend_from_slice(server_public_bytes);
    body.extend_from_slice(&ciphertext);
    Ok(body)
}

async fn fcm_oauth_access_token(
    credential: &ramflux_node_core::FcmProviderCredential,
    ca_pem: Option<String>,
) -> Result<String, ramflux_node_core::NodeCoreError> {
    let service_account_json = read_secret_ref(&credential.service_account_json_ref)?;
    let account: FcmServiceAccount = serde_json::from_str(&service_account_json)
        .map_err(|source| ramflux_node_core::NodeCoreError::ItestJson(source.to_string()))?;
    let token_url = credential
        .oauth_token_url
        .as_deref()
        .or(account.token_uri.as_deref())
        .unwrap_or("https://oauth2.googleapis.com/token");
    let endpoint = parse_https_url(token_url)?;
    let assertion = fcm_oauth_assertion(credential, &account, token_url)?;
    let form = format!(
        "grant_type={}&assertion={}",
        percent_encode("urn:ietf:params:oauth:grant-type:jwt-bearer"),
        percent_encode(&assertion)
    );
    let response = h2_post_json(&ProviderHttpRequest {
        endpoint,
        headers: vec![("content-type".to_owned(), "application/x-www-form-urlencoded".to_owned())],
        body: form.into_bytes(),
        ca_pem,
    })
    .await?;
    if !(200..300).contains(&response.status) {
        return Err(ramflux_node_core::NodeCoreError::ItestHttp(format!(
            "fcm oauth token endpoint rejected request with status {}",
            response.status
        )));
    }
    let body: serde_json::Value = serde_json::from_slice(&response.body)
        .map_err(|source| ramflux_node_core::NodeCoreError::ItestJson(source.to_string()))?;
    body.get("access_token").and_then(serde_json::Value::as_str).map(ToOwned::to_owned).ok_or_else(
        || ramflux_node_core::NodeCoreError::ItestJson("missing access_token".to_owned()),
    )
}

fn wake_send_dropped() -> ramflux_node_core::NodeCoreError {
    ramflux_node_core::NodeCoreError::InvalidConfiguration("wake send dropped".to_owned())
}

fn is_wake_send_dropped(error: &ramflux_node_core::NodeCoreError) -> bool {
    matches!(
        error,
        ramflux_node_core::NodeCoreError::InvalidConfiguration(message)
            if message == "wake send dropped"
    )
}

async fn h2_post_json(
    request: &ProviderHttpRequest,
) -> Result<ProviderHttpResponse, ramflux_node_core::NodeCoreError> {
    h2_post_checked(request, || Ok(true)).await
}

async fn h2_post_checked<F>(
    request: &ProviderHttpRequest,
    allow: F,
) -> Result<ProviderHttpResponse, ramflux_node_core::NodeCoreError>
where
    F: FnMut() -> Result<bool, ramflux_node_core::NodeCoreError>,
{
    h2_post_boundary(request, provider_issuance::Checked(allow)).await
}

async fn h2_post_boundary<F: SendBoundary>(
    request: &ProviderHttpRequest,
    mut boundary: F,
) -> Result<ProviderHttpResponse, ramflux_node_core::NodeCoreError> {
    let mut client = connect_provider_h2(request).await?;
    post_json_with_h2_client(request, &mut client, &mut boundary).await
}

async fn connect_provider_h2(
    request: &ProviderHttpRequest,
) -> Result<h2::client::SendRequest<bytes::Bytes>, ramflux_node_core::NodeCoreError> {
    let addr = format!("{}:{}", request.endpoint.host, request.endpoint.port);
    let tcp = tokio::time::timeout(Duration::from_secs(5), tokio::net::TcpStream::connect(addr))
        .await
        .map_err(|_| {
            ramflux_node_core::NodeCoreError::ItestHttp("provider connect timed out".to_owned())
        })?
        .map_err(|source| {
            ramflux_node_core::NodeCoreError::ItestHttp(format!("provider tcp connect: {source}"))
        })?;
    tcp.set_nodelay(true).map_err(|source| {
        ramflux_node_core::NodeCoreError::ItestHttp(format!("provider tcp nodelay: {source}"))
    })?;
    let server_name = rustls_pki_types::ServerName::try_from(request.endpoint.host.clone())
        .map_err(|source| ramflux_node_core::NodeCoreError::ItestHttp(source.to_string()))?;
    let connector =
        tokio_rustls::TlsConnector::from(Arc::new(provider_tls_config(request.ca_pem.as_deref())?));
    let tls = tokio::time::timeout(Duration::from_secs(5), connector.connect(server_name, tcp))
        .await
        .map_err(|_| {
            ramflux_node_core::NodeCoreError::ItestHttp("provider tls timed out".to_owned())
        })?
        .map_err(|source| {
            ramflux_node_core::NodeCoreError::ItestHttp(format!("provider tls connect: {source}"))
        })?;
    let (client, connection) = h2::client::handshake(tls).await.map_err(|source| {
        ramflux_node_core::NodeCoreError::ItestHttp(format!("provider h2 handshake: {source}"))
    })?;
    tokio::spawn(async move {
        if let Err(error) = connection.await {
            tracing::debug!(%error, "provider h2 connection closed with error");
        }
    });
    Ok(client)
}

async fn post_json_with_h2_client<F: SendBoundary>(
    request: &ProviderHttpRequest,
    client: &mut h2::client::SendRequest<bytes::Bytes>,
    boundary: &mut F,
) -> Result<ProviderHttpResponse, ramflux_node_core::NodeCoreError> {
    std::future::poll_fn(|cx| client.poll_ready(cx)).await.map_err(|error| {
        ramflux_node_core::NodeCoreError::ItestHttp(format!("provider h2 readiness: {error}"))
    })?;
    let authority = format!("{}:{}", request.endpoint.host, request.endpoint.port);
    let uri = format!("https://{}{}", authority, request.endpoint.path);
    let mut builder = http::Request::builder()
        .method(http::Method::POST)
        .uri(uri)
        .header(http::header::CONTENT_LENGTH, request.body.len().to_string());
    for (key, value) in &request.headers {
        builder = builder.header(key.as_str(), value.as_str());
    }
    let http_request = builder
        .body(())
        .map_err(|source| ramflux_node_core::NodeCoreError::ItestHttp(source.to_string()))?;
    let owned_body = bytes::Bytes::copy_from_slice(&request.body);
    let response_future = boundary.issue(|| {
        let (response, mut stream) = client.send_request(http_request, false).map_err(|error| {
            ramflux_node_core::NodeCoreError::ItestHttp(format!(
                "provider h2 send request: {error}"
            ))
        })?;
        #[cfg(test)]
        if let Err(error) = permit_tests::issued_headers() {
            stream.send_reset(h2::Reason::CANCEL);
            return Err(error);
        }
        if let Err(error) = stream.send_data(owned_body, true) {
            stream.send_reset(h2::Reason::CANCEL);
            return Err(ramflux_node_core::NodeCoreError::ItestHttp(format!(
                "provider h2 body handoff uncertain: {error}"
            )));
        }
        #[cfg(test)]
        permit_tests::issued_body()?;
        Ok(response)
    })?;
    let response = tokio::time::timeout(Duration::from_secs(30), response_future)
        .await
        .map_err(|_| {
            ramflux_node_core::NodeCoreError::ItestHttp("provider response timed out".to_owned())
        })?
        .map_err(|source| {
            ramflux_node_core::NodeCoreError::ItestHttp(format!("provider h2 response: {source}"))
        })?;
    let status = response.status().as_u16();
    let retry_after = response.headers().get("retry-after").and_then(|value| {
        let text = value.to_str().ok()?.trim();
        let bounded = text.get(..64).unwrap_or(text);
        Some(bounded.to_owned())
    });
    let mut body = response.into_body();
    let mut bytes = Vec::new();
    let mut body_truncated = false;
    while let Some(chunk) =
        tokio::time::timeout(Duration::from_secs(30), body.data()).await.map_err(|_| {
            ramflux_node_core::NodeCoreError::ItestHttp("provider body timed out".to_owned())
        })?
    {
        let chunk = chunk.map_err(|source| {
            ramflux_node_core::NodeCoreError::ItestHttp(format!("provider h2 body: {source}"))
        })?;
        if body_truncated {
            continue;
        }
        let room = provider_outcome::MAX_PROVIDER_ERROR_BODY.saturating_sub(bytes.len());
        if chunk.len() > room {
            if let Some(prefix) = chunk.get(..room) {
                bytes.extend_from_slice(prefix);
            }
            body_truncated = true;
        } else {
            bytes.extend_from_slice(&chunk);
        }
    }
    Ok(ProviderHttpResponse { status, body: bytes, retry_after, body_truncated })
}

fn provider_tls_config(
    ca_pem: Option<&str>,
) -> Result<rustls::ClientConfig, ramflux_node_core::NodeCoreError> {
    ensure_ring_crypto_provider_installed();
    let mut root_store = rustls::RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() };
    if let Some(ca_pem) = ca_pem {
        let mut reader = std::io::Cursor::new(ca_pem.as_bytes());
        for cert in rustls_pemfile::certs(&mut reader) {
            let cert = cert.map_err(|source| {
                ramflux_node_core::NodeCoreError::ItestHttp(source.to_string())
            })?;
            root_store.add(cert).map_err(|source| {
                ramflux_node_core::NodeCoreError::ItestHttp(source.to_string())
            })?;
        }
    }
    let mut config =
        rustls::ClientConfig::builder().with_root_certificates(root_store).with_no_client_auth();
    config.alpn_protocols = vec![b"h2".to_vec()];
    Ok(config)
}

fn ensure_ring_crypto_provider_installed() {
    RUSTLS_PROVIDER.call_once(|| {
        let _result = rustls::crypto::ring::default_provider().install_default();
    });
}

fn ensure_jwt_crypto_provider_installed() {
    JWT_PROVIDER.call_once(|| {
        let _result = jsonwebtoken::crypto::aws_lc::DEFAULT_PROVIDER.install_default();
    });
}

fn apns_jwt(
    credential: &ramflux_node_core::ApnsProviderCredential,
) -> Result<String, ramflux_node_core::NodeCoreError> {
    ensure_jwt_crypto_provider_installed();
    let p8 = read_secret_ref(&credential.p8_key_ref)?;
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES256);
    header.kid = Some(credential.key_id.clone());
    let claims = serde_json::json!({
        "iss": credential.team_id,
        "iat": ramflux_node_core::now_unix_seconds()
    });
    jsonwebtoken::encode(
        &header,
        &claims,
        &jsonwebtoken::EncodingKey::from_ec_pem(p8.as_bytes())
            .map_err(|source| ramflux_node_core::NodeCoreError::ItestHttp(source.to_string()))?,
    )
    .map_err(|source| ramflux_node_core::NodeCoreError::ItestHttp(source.to_string()))
}

fn fcm_oauth_assertion(
    credential: &ramflux_node_core::FcmProviderCredential,
    account: &FcmServiceAccount,
    token_url: &str,
) -> Result<String, ramflux_node_core::NodeCoreError> {
    ensure_jwt_crypto_provider_installed();
    let iat = ramflux_node_core::now_unix_seconds();
    let private_key = account.private_key.as_deref().ok_or_else(|| {
        ramflux_node_core::NodeCoreError::ItestJson("missing fcm private_key".to_owned())
    })?;
    let client_email = account.client_email.as_deref().ok_or_else(|| {
        ramflux_node_core::NodeCoreError::ItestJson("missing fcm client_email".to_owned())
    })?;
    let claims = serde_json::json!({
        "iss": client_email,
        "scope": credential.oauth_scope,
        "aud": token_url,
        "iat": iat,
        "exp": iat.saturating_add(3_600)
    });
    jsonwebtoken::encode(
        &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256),
        &claims,
        &jsonwebtoken::EncodingKey::from_rsa_pem(private_key.as_bytes())
            .map_err(|source| ramflux_node_core::NodeCoreError::ItestHttp(source.to_string()))?,
    )
    .map_err(|source| ramflux_node_core::NodeCoreError::ItestHttp(source.to_string()))
}

fn webpush_vapid_jwt(
    credential: &ramflux_node_core::WebPushProviderCredential,
    endpoint: &ParsedHttpsUrl,
) -> Result<String, ramflux_node_core::NodeCoreError> {
    ensure_jwt_crypto_provider_installed();
    let private_key = read_secret_ref(&credential.vapid_private_key_ref)?;
    let aud = format!("https://{}:{}", endpoint.host, endpoint.port);
    let claims = serde_json::json!({
        "aud": aud,
        "exp": ramflux_node_core::now_unix_seconds().saturating_add(12 * 60 * 60),
        "sub": credential.subject
    });
    jsonwebtoken::encode(
        &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES256),
        &claims,
        &jsonwebtoken::EncodingKey::from_ec_pem(private_key.as_bytes())
            .map_err(|source| ramflux_node_core::NodeCoreError::ItestHttp(source.to_string()))?,
    )
    .map_err(|source| ramflux_node_core::NodeCoreError::ItestHttp(source.to_string()))
}

fn read_optional_secret_ref(
    secret_ref: Option<&str>,
) -> Result<Option<String>, ramflux_node_core::NodeCoreError> {
    secret_ref.map(read_secret_ref).transpose()
}

fn read_secret_ref(secret_ref: &str) -> Result<String, ramflux_node_core::NodeCoreError> {
    if let Some(literal) = secret_ref.strip_prefix("literal:") {
        return Ok(literal.to_owned());
    }
    if let Some(name) = secret_ref.strip_prefix("env:") {
        return ramflux_node_core::environment::var(name)
            .map_err(|source| ramflux_node_core::NodeCoreError::ItestHttp(source.to_string()));
    }
    if let Some(path) = secret_ref.strip_prefix("file:") {
        return std::fs::read_to_string(path)
            .map_err(|source| ramflux_node_core::NodeCoreError::ItestHttp(source.to_string()));
    }
    Err(ramflux_node_core::NodeCoreError::ItestHttp("unsupported secret ref scheme".to_owned()))
}

fn percent_encode(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                encoded.push(char::from(byte));
            }
            _ => {
                let _ = write!(&mut encoded, "%{byte:02X}");
            }
        }
    }
    encoded
}

#[derive(Clone, Default)]
enum AdmittedWake {
    #[default]
    Unverified,
    Push(Box<ramflux_protocol::NotificationWake>),
    NoPush,
}

#[derive(Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct S13WakeRequest {
    device_delivery_id: String,
    signed_wake: ramflux_protocol::SignedWakeV2,
    #[serde(default)]
    queued_at: Option<u64>,
    #[serde(default)]
    dnd_active: Option<bool>,
    #[serde(skip, default)]
    admission: AdmittedWake,
}

impl S13WakeRequest {
    fn admit(
        &mut self,
        auth: &NotifyWakeAuth,
        store: &ramflux_node_core::NotifyRedbStore,
    ) -> Result<(), ramflux_node_core::NodeCoreError> {
        if !matches!(self.admission, AdmittedWake::Unverified) {
            return Ok(());
        }
        auth.verify_signed(&self.signed_wake)?;
        if self.signed_wake.body.target_delivery_id != self.device_delivery_id {
            return Err(ramflux_node_core::NodeCoreError::Unauthorized(
                "notify wake signature rejected".to_owned(),
            ));
        }
        let now = ramflux_node_core::now_unix_seconds();
        if self.signed_wake.body.action != ramflux_protocol::WakeAction::Enqueue {
            self.signed_wake.body.validate_shape().map_err(|_source| {
                ramflux_node_core::NodeCoreError::InvalidConfiguration(
                    "wake contract rejected".to_owned(),
                )
            })?;
            self.signed_wake.body.validate_times(now).map_err(|_source| {
                ramflux_node_core::NodeCoreError::InvalidConfiguration(
                    "wake contract rejected".to_owned(),
                )
            })?;
            self.admission = AdmittedWake::NoPush;
            store.cancel_signed_wake(&self.signed_wake)?;
            return Ok(());
        }
        let mut wake =
            ramflux_node_core::project_wake_v2(&self.signed_wake, now).map_err(|_source| {
                ramflux_node_core::NodeCoreError::InvalidConfiguration(
                    "wake contract rejected".to_owned(),
                )
            })?;
        let Some(deadline) =
            store.claim_signed_wake(&self.signed_wake, wake.absolute_expires_at)?
        else {
            self.admission = AdmittedWake::NoPush;
            return Ok(());
        };
        if deadline <= now {
            self.admission = AdmittedWake::NoPush;
            return Ok(());
        }
        wake.absolute_expires_at = deadline;
        wake.ttl = u32::try_from(deadline.saturating_sub(now)).unwrap_or(u32::MAX);
        self.admission = AdmittedWake::Push(Box::new(wake));
        Ok(())
    }

    fn queued_provider_wake(
        &self,
    ) -> Result<Option<&ramflux_protocol::NotificationWake>, ramflux_node_core::NodeCoreError> {
        match &self.admission {
            AdmittedWake::Push(wake) => Ok(Some(wake.as_ref())),
            AdmittedWake::NoPush => Ok(None),
            AdmittedWake::Unverified => Err(ramflux_node_core::NodeCoreError::Unauthorized(
                "notify wake signature rejected".to_owned(),
            )),
        }
    }
}

fn project_mvp10_signed_wake(
    auth: &NotifyWakeAuth,
    body: &serde_json::Value,
) -> Result<ramflux_protocol::NotificationWake, ramflux_node_core::NodeCoreError> {
    if body.get("wake").is_some() {
        return Err(ramflux_node_core::NodeCoreError::ItestJson("legacy wake rejected".to_owned()));
    }
    let signed_value = body.get("signed_wake").cloned().ok_or_else(|| {
        ramflux_node_core::NodeCoreError::ItestJson("missing signed wake".to_owned())
    })?;
    let signed: ramflux_protocol::SignedWakeV2 = serde_json::from_value(signed_value)
        .map_err(|source| ramflux_node_core::NodeCoreError::ItestJson(source.to_string()))?;
    auth.verify_signed(&signed)?;
    ramflux_node_core::project_wake_v2(&signed, ramflux_node_core::now_unix_seconds()).map_err(
        |_source| {
            ramflux_node_core::NodeCoreError::InvalidConfiguration(
                "wake contract rejected".to_owned(),
            )
        },
    )
}

fn no_push_response(request: &S13WakeRequest) -> S13WakeResponse {
    let now = ramflux_node_core::now_unix_seconds();
    S13WakeResponse {
        entry: ramflux_node_core::NotifyQueueEntry {
            queue_id: request.signed_wake.body.wake_id.clone(),
            device_delivery_id: request.device_delivery_id.clone(),
            wake: ramflux_protocol::NotificationWake {
                schema: ramflux_protocol::domain::NOTIFICATION_WAKE_V2.to_owned(),
                version: 2,
                domain: ramflux_protocol::domain::NOTIFICATION_WAKE_V2.to_owned(),
                ext: ramflux_protocol::Ext::default(),
                signed: ramflux_protocol::SignedFields {
                    signing_key_id: request.signed_wake.body.signing_key_id.clone(),
                    signature_alg: ramflux_protocol::SignatureAlg::Ed25519,
                    signature: request.signed_wake.signature.clone(),
                },
                wake_id: request.signed_wake.body.wake_id.clone(),
                push_alias: request.device_delivery_id.clone(),
                delivery_class: ramflux_protocol::NotificationDeliveryClass::CallWakeNotification,
                priority: ramflux_protocol::PushPriority::High,
                ttl: 0,
                absolute_expires_at: 0,
                collapse_key: None,
                encrypted_hint: None,
            },
            push_alias_hash: String::new(),
            queued_at: now,
            expires_at: now,
            attempt_count: 0,
            status: ramflux_node_core::NotifyQueueStatus::DroppedExpired,
            dnd_active: request.dnd_active.unwrap_or(false),
        },
        attempts: Vec::new(),
    }
}

#[cfg(feature = "itest-http")]
fn parse_s13_wake_request_body(
    body: &[u8],
) -> Result<S13WakeRequest, ramflux_node_core::NodeCoreError> {
    ramflux_protocol::parse_i_json(body)
        .map_err(|source| ramflux_node_core::NodeCoreError::ItestJson(source.to_string()))
}

#[derive(serde::Serialize)]
struct S13WakeResponse {
    entry: ramflux_node_core::NotifyQueueEntry,
    attempts: Vec<ramflux_node_core::ProviderPushAttempt>,
}

#[derive(serde::Deserialize)]
struct FcmServiceAccount {
    #[serde(default)]
    client_email: Option<String>,
    #[serde(default)]
    private_key: Option<String>,
    #[serde(default)]
    token_uri: Option<String>,
}

#[cfg(test)]
mod acceptance;
#[cfg(test)]
mod tests;

#[cfg(test)]
mod webpush_tests;

#[cfg(test)]
mod native_provider_tests;
#[cfg(test)]
mod permit_tests;
