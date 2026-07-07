// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use std::net::SocketAddr;
use std::sync::Arc;
use std::thread;

#[cfg(feature = "itest-http")]
use crate::handlers::handle_itest_request;
use crate::handlers::handle_mesh_quic_request_value;
use crate::handlers::handle_mesh_request;
use socket2::{Domain, Protocol, Socket, Type};
#[cfg(feature = "itest-http")]
use std::net::{TcpListener, TcpStream};
#[cfg(feature = "itest-http")]
use std::sync::Mutex;

const ROUTER_ASYNC_INGRESS_ENV: &str = "RAMFLUX_ROUTER_ASYNC_INGRESS";
const ROUTER_ASYNC_INGRESS_RUNTIME_ENV: &str = "RAMFLUX_ROUTER_ASYNC_INGRESS_RUNTIME";
const ROUTER_ASYNC_LISTEN_ADDR_ENV: &str = "RAMFLUX_ROUTER_ASYNC_LISTEN_ADDR";
const ROUTER_ASYNC_INGRESS_SOCKETS_ENV: &str = "RAMFLUX_ROUTER_ASYNC_INGRESS_SOCKETS";
const ROUTER_ASYNC_WORKER_THREADS_ENV: &str = "RAMFLUX_ROUTER_ASYNC_WORKER_THREADS";
const DEFAULT_ROUTER_ASYNC_LISTEN_ADDR: &str = "0.0.0.0:17444";

#[cfg(feature = "itest-http")]
pub(crate) fn serve_itest_http(
    router: &Arc<crate::router_runtime::RouterHandle>,
) -> anyhow::Result<()> {
    let addr = std::env::var("RAMFLUX_ITEST_ROUTER_HTTP_ADDR")
        .unwrap_or_else(|_| "0.0.0.0:18080".to_owned());
    let listener = TcpListener::bind(&addr)?;
    let worker_count = router_ingress_worker_count();
    let queue_capacity = worker_count.saturating_mul(4).max(1);
    let (sender, receiver) = std::sync::mpsc::sync_channel(queue_capacity);
    let receiver = Arc::new(Mutex::new(receiver));
    for worker_id in 0..worker_count {
        let worker_receiver = Arc::clone(&receiver);
        let worker_router = Arc::clone(router);
        thread::Builder::new()
            .name(format!("ramflux-router-http-ingress-{worker_id}"))
            .spawn(move || router_ingress_worker_loop(&worker_receiver, &worker_router))?;
    }
    tracing::info!(addr, worker_count, queue_capacity, "router itest HTTP surface listening");
    for stream in listener.incoming() {
        let stream = stream?;
        if let Err(error) = stream.set_nodelay(true) {
            tracing::warn!(%error, "failed to enable TCP_NODELAY on router ingress connection");
        }
        sender.send(stream)?;
    }
    Ok(())
}

#[cfg(feature = "itest-http")]
fn router_ingress_worker_count() -> usize {
    std::env::var("RAMFLUX_ROUTER_INGRESS_THREADS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or_else(|| {
            std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get)
        })
        .max(1)
}

#[cfg(feature = "itest-http")]
fn router_ingress_worker_loop(
    receiver: &Arc<Mutex<std::sync::mpsc::Receiver<TcpStream>>>,
    router: &Arc<crate::router_runtime::RouterHandle>,
) {
    loop {
        let stream = {
            let Ok(receiver) = receiver.lock() else {
                tracing::error!("router ingress receiver lock poisoned");
                return;
            };
            receiver.recv()
        };
        let Ok(mut stream) = stream else {
            return;
        };
        if let Err(error) = handle_itest_request(&mut stream, router) {
            let body = format!("{error}");
            if let Err(write_error) = ramflux_node_core::write_itest_text_response(
                &mut stream,
                "500 Internal Server Error",
                &body,
            ) {
                tracing::warn!(%write_error, "failed to write router itest error response");
            }
        }
    }
}

pub(crate) fn serve_router_mesh_mtls(
    config: &ramflux_node_core::NodeServiceConfig,
    router: &Arc<crate::router_runtime::RouterHandle>,
) -> anyhow::Result<()> {
    let mesh_server =
        ramflux_transport::MeshTlsServer::bind(&config.mesh.listen_addr, &mesh_tls_config(config))?;
    let mesh_router = Arc::clone(router);
    let local_service_id = config.service_id.clone();
    let allowed_service_ids = config.mesh.allowed_service_ids.clone();
    thread::spawn(move || {
        if let Err(error) =
            serve_mesh_mtls(&mesh_server, &mesh_router, &local_service_id, &allowed_service_ids)
        {
            tracing::error!(%error, "router mesh mTLS listener stopped");
        }
    });
    if router_async_ingress_enabled()
        && let Some(listen_addr) = router_async_listen_addr(config)
    {
        spawn_router_async_mesh_quic_listener(
            listen_addr,
            mesh_tls_config(config),
            router,
            RouterAsyncMeshPeerAuth::from_config(config),
        )?;
    }
    Ok(())
}

fn router_async_ingress_enabled() -> bool {
    router_async_ingress_enabled_from_value(std::env::var(ROUTER_ASYNC_INGRESS_ENV).ok().as_deref())
}

fn router_async_ingress_enabled_from_value(value: Option<&str>) -> bool {
    let Some(value) = value else {
        return true;
    };
    let trimmed = value.trim();
    !(trimmed == "0"
        || trimmed.eq_ignore_ascii_case("false")
        || trimmed.eq_ignore_ascii_case("off")
        || trimmed.eq_ignore_ascii_case("no"))
}

fn router_async_listen_addr(config: &ramflux_node_core::NodeServiceConfig) -> Option<String> {
    router_async_listen_addr_from_value(
        config,
        std::env::var(ROUTER_ASYNC_LISTEN_ADDR_ENV).ok().as_deref(),
    )
}

fn router_async_listen_addr_from_value(
    config: &ramflux_node_core::NodeServiceConfig,
    env_value: Option<&str>,
) -> Option<String> {
    let Some(value) = env_value else {
        return config
            .mesh
            .endpoints
            .get("router-async-listen")
            .cloned()
            .or_else(|| Some(DEFAULT_ROUTER_ASYNC_LISTEN_ADDR.to_owned()));
    };
    let trimmed = value.trim();
    if trimmed.starts_with("${") {
        return Some(DEFAULT_ROUTER_ASYNC_LISTEN_ADDR.to_owned());
    }
    if trimmed.is_empty() {
        return config
            .mesh
            .endpoints
            .get("router-async-listen")
            .cloned()
            .or_else(|| Some(DEFAULT_ROUTER_ASYNC_LISTEN_ADDR.to_owned()));
    }
    Some(trimmed.to_owned())
}

#[derive(Clone)]
struct RouterAsyncMeshPeerAuth {
    local_service_id: String,
    allowed_service_ids: std::collections::BTreeSet<String>,
}

impl RouterAsyncMeshPeerAuth {
    fn from_config(config: &ramflux_node_core::NodeServiceConfig) -> Self {
        Self {
            local_service_id: config.service_id.clone(),
            allowed_service_ids: config.mesh.allowed_service_ids.clone(),
        }
    }

    fn authorize(&self, peer_spiffe_uri: Option<&str>) -> anyhow::Result<String> {
        Ok(ramflux_node_core::authorize_mesh_peer(
            &self.local_service_id,
            &self.allowed_service_ids,
            peer_spiffe_uri,
        )?
        .service_id)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RouterAsyncIngressRuntime {
    Tokio,
    Compio,
}

fn router_async_ingress_runtime_from_value(value: Option<&str>) -> RouterAsyncIngressRuntime {
    match value.map(str::trim) {
        Some("compio") => RouterAsyncIngressRuntime::Compio,
        Some("tokio" | "quinn") | None => RouterAsyncIngressRuntime::Tokio,
        Some(value) if value.is_empty() || value.starts_with("${") => {
            RouterAsyncIngressRuntime::Tokio
        }
        Some(other) => {
            tracing::warn!(
                runtime = %other,
                "unsupported router async ingress runtime; using tokio"
            );
            RouterAsyncIngressRuntime::Tokio
        }
    }
}

fn spawn_router_async_mesh_quic_listener(
    listen_addr: String,
    tls: ramflux_transport::MeshTlsConfig,
    router: &Arc<crate::router_runtime::RouterHandle>,
    peer_auth: RouterAsyncMeshPeerAuth,
) -> anyhow::Result<()> {
    match router_async_ingress_runtime_from_value(
        std::env::var(ROUTER_ASYNC_INGRESS_RUNTIME_ENV).ok().as_deref(),
    ) {
        RouterAsyncIngressRuntime::Compio => {
            spawn_router_async_compio_mesh_quic_thread(listen_addr, tls, router, peer_auth)
        }
        RouterAsyncIngressRuntime::Tokio => {
            spawn_router_async_tokio_mesh_quic_thread(listen_addr, tls, router, peer_auth)
        }
    }
}

fn spawn_router_async_tokio_mesh_quic_thread(
    listen_addr: String,
    tls: ramflux_transport::MeshTlsConfig,
    router: &Arc<crate::router_runtime::RouterHandle>,
    peer_auth: RouterAsyncMeshPeerAuth,
) -> anyhow::Result<()> {
    let router = Arc::clone(router);
    thread::Builder::new().name("ramflux-router-async-quic-ingress".to_owned()).spawn(
        move || {
            if let Err(error) =
                run_router_async_mesh_quic_listener(&listen_addr, &tls, router, peer_auth)
            {
                tracing::error!(%error, "router async QUIC ingress stopped");
            }
        },
    )?;
    Ok(())
}

#[cfg(all(target_os = "linux", feature = "compio-mesh"))]
fn spawn_router_async_compio_mesh_quic_thread(
    listen_addr: String,
    tls: ramflux_transport::MeshTlsConfig,
    router: &Arc<crate::router_runtime::RouterHandle>,
    peer_auth: RouterAsyncMeshPeerAuth,
) -> anyhow::Result<()> {
    let router = Arc::clone(router);
    thread::Builder::new().name("ramflux-router-async-compio-quic-ingress".to_owned()).spawn(
        move || {
            if let Err(error) =
                run_router_async_compio_mesh_quic_listener(&listen_addr, &tls, router, &peer_auth)
            {
                tracing::error!(%error, "router async compio QUIC ingress stopped");
            }
        },
    )?;
    Ok(())
}

#[cfg(not(all(target_os = "linux", feature = "compio-mesh")))]
fn spawn_router_async_compio_mesh_quic_thread(
    _listen_addr: String,
    _tls: ramflux_transport::MeshTlsConfig,
    _router: &Arc<crate::router_runtime::RouterHandle>,
    _peer_auth: RouterAsyncMeshPeerAuth,
) -> anyhow::Result<()> {
    anyhow::bail!(
        "{ROUTER_ASYNC_INGRESS_RUNTIME_ENV}=compio requested but ramflux-router compio-mesh is not compiled"
    )
}

fn run_router_async_mesh_quic_listener(
    listen_addr: &str,
    tls: &ramflux_transport::MeshTlsConfig,
    router: Arc<crate::router_runtime::RouterHandle>,
    peer_auth: RouterAsyncMeshPeerAuth,
) -> anyhow::Result<()> {
    let worker_threads = router_async_worker_threads();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(worker_threads)
        .enable_all()
        .build()?;
    runtime.block_on(async move {
        let socket_count = router_async_ingress_socket_count();
        let servers = bind_router_async_mesh_quic_servers(listen_addr, tls, socket_count)?;
        tracing::info!(
            listen_addr,
            worker_threads,
            socket_count,
            "router async QUIC ingress listening"
        );
        for (endpoint_index, server) in servers.into_iter().enumerate() {
            let endpoint_router = Arc::clone(&router);
            let endpoint_peer_auth = peer_auth.clone();
            tokio::spawn(async move {
                router_async_mesh_quic_accept_loop(
                    endpoint_index,
                    server,
                    endpoint_router,
                    endpoint_peer_auth,
                )
                .await;
            });
        }
        std::future::pending::<()>().await;
        #[allow(unreachable_code)]
        Ok::<(), anyhow::Error>(())
    })
}

#[cfg(all(target_os = "linux", feature = "compio-mesh"))]
fn run_router_async_compio_mesh_quic_listener(
    listen_addr: &str,
    tls: &ramflux_transport::MeshTlsConfig,
    router: Arc<crate::router_runtime::RouterHandle>,
    peer_auth: &RouterAsyncMeshPeerAuth,
) -> anyhow::Result<()> {
    let submit_worker_threads = router_async_worker_threads();
    let submit_runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(submit_worker_threads)
        .enable_all()
        .build()?;
    let bridge = RouterSubmitBridge { router, tokio: submit_runtime.handle().clone() };
    let socket_count = router_async_compio_ingress_socket_count();
    tracing::info!(
        listen_addr,
        submit_worker_threads,
        socket_count,
        "router async compio QUIC ingress starting"
    );

    let mut handles = Vec::with_capacity(socket_count);
    for endpoint_index in 0..socket_count {
        let listen_addr = listen_addr.to_owned();
        let tls = tls.clone();
        let endpoint_bridge = bridge.clone();
        let endpoint_peer_auth = peer_auth.clone();
        let handle = thread::Builder::new()
            .name(format!("ramflux-router-async-compio-quic-ingress-{endpoint_index}"))
            .spawn(move || {
                if let Err(error) = run_router_async_compio_mesh_quic_reactor(
                    endpoint_index,
                    &listen_addr,
                    &tls,
                    endpoint_bridge,
                    endpoint_peer_auth,
                    socket_count,
                ) {
                    tracing::error!(
                        endpoint_index,
                        %error,
                        "router async compio QUIC reactor stopped"
                    );
                }
            })?;
        handles.push(handle);
    }

    for handle in handles {
        if let Err(_panic) = handle.join() {
            tracing::error!("router async compio QUIC reactor thread panicked");
        }
    }
    Ok(())
}

#[cfg(all(target_os = "linux", feature = "compio-mesh"))]
fn run_router_async_compio_mesh_quic_reactor(
    endpoint_index: usize,
    listen_addr: &str,
    tls: &ramflux_transport::MeshTlsConfig,
    bridge: RouterSubmitBridge,
    peer_auth: RouterAsyncMeshPeerAuth,
    socket_count: usize,
) -> anyhow::Result<()> {
    let runtime = compio::runtime::Runtime::new()?;
    runtime.block_on(async move {
        let server = bind_router_async_compio_mesh_quic_server(
            endpoint_index,
            listen_addr,
            tls,
            socket_count,
        )
        .await?;
        let local_addr = server.local_addr()?;
        tracing::info!(
            endpoint_index,
            addr = %local_addr,
            "router async compio QUIC reactor listening"
        );
        router_async_compio_mesh_quic_accept_loop(endpoint_index, server, bridge, peer_auth).await;
        #[allow(unreachable_code)]
        Ok::<(), anyhow::Error>(())
    })
}

#[cfg(all(target_os = "linux", feature = "compio-mesh"))]
async fn bind_router_async_compio_mesh_quic_server(
    endpoint_index: usize,
    listen_addr: &str,
    tls: &ramflux_transport::MeshTlsConfig,
    socket_count: usize,
) -> anyhow::Result<ramflux_transport::CompioMeshQuicServer> {
    let root_pems_provider = Arc::new(|| Ok(Vec::new()));
    if socket_count <= 1 {
        let server = ramflux_transport::CompioMeshQuicServer::bind_with_pem_roots_provider(
            listen_addr,
            tls,
            root_pems_provider,
        )
        .await?;
        let local_addr = server.local_addr()?;
        tracing::info!(
            endpoint_index,
            addr = %local_addr,
            "router async compio QUIC endpoint bound"
        );
        return Ok(server);
    }

    let addr = listen_addr.parse::<SocketAddr>()?;
    if addr.port() == 0 {
        anyhow::bail!(
            "{ROUTER_ASYNC_INGRESS_SOCKETS_ENV}={socket_count} requires a fixed UDP port"
        );
    }
    let socket = bind_router_async_reuse_port_socket(addr)?;
    let server =
        ramflux_transport::CompioMeshQuicServer::bind_with_udp_socket_and_pem_roots_provider(
            socket,
            tls,
            root_pems_provider,
        )?;
    let local_addr = server.local_addr()?;
    tracing::info!(
        endpoint_index,
        addr = %local_addr,
        "router async compio QUIC SO_REUSEPORT endpoint bound"
    );
    Ok(server)
}

#[cfg(all(target_os = "linux", feature = "compio-mesh"))]
async fn router_async_compio_mesh_quic_accept_loop(
    endpoint_index: usize,
    server: ramflux_transport::CompioMeshQuicServer,
    bridge: RouterSubmitBridge,
    peer_auth: RouterAsyncMeshPeerAuth,
) {
    loop {
        let connection = match server.accept_connection().await {
            Ok(connection) => connection,
            Err(error) => {
                tracing::warn!(
                    endpoint_index,
                    %error,
                    "router async compio QUIC connection rejected"
                );
                continue;
            }
        };
        let connection_bridge = bridge.clone();
        let connection_peer_auth = peer_auth.clone();
        compio::runtime::spawn(async move {
            if let Err(error) = router_async_compio_mesh_quic_connection_loop(
                connection,
                connection_bridge,
                connection_peer_auth,
            )
            .await
            {
                tracing::debug!(
                    endpoint_index,
                    %error,
                    "router async compio QUIC connection ended"
                );
            }
        })
        .detach();
    }
}

#[cfg(all(target_os = "linux", feature = "compio-mesh"))]
#[derive(Clone)]
struct RouterSubmitBridge {
    router: Arc<crate::router_runtime::RouterHandle>,
    tokio: tokio::runtime::Handle,
}

#[cfg(any(test, all(target_os = "linux", feature = "compio-mesh")))]
struct BridgeReplyState<T> {
    result: std::sync::Mutex<Option<anyhow::Result<T>>>,
    waker: std::sync::Mutex<Option<std::task::Waker>>,
}

#[cfg(any(test, all(target_os = "linux", feature = "compio-mesh")))]
struct BridgeReplySender<T> {
    state: Option<Arc<BridgeReplyState<T>>>,
}

#[cfg(any(test, all(target_os = "linux", feature = "compio-mesh")))]
struct BridgeReply<T> {
    state: Arc<BridgeReplyState<T>>,
}

#[cfg(any(test, all(target_os = "linux", feature = "compio-mesh")))]
fn bridge_reply_channel<T>() -> (BridgeReplySender<T>, BridgeReply<T>) {
    let state = Arc::new(BridgeReplyState {
        result: std::sync::Mutex::new(None),
        waker: std::sync::Mutex::new(None),
    });
    (BridgeReplySender { state: Some(Arc::clone(&state)) }, BridgeReply { state })
}

#[cfg(any(test, all(target_os = "linux", feature = "compio-mesh")))]
impl<T> BridgeReplySender<T> {
    fn send(mut self, result: anyhow::Result<T>) {
        if let Some(state) = self.state.take() {
            complete_bridge_reply(&state, result);
        }
    }
}

#[cfg(any(test, all(target_os = "linux", feature = "compio-mesh")))]
impl<T> Drop for BridgeReplySender<T> {
    fn drop(&mut self) {
        if let Some(state) = self.state.take() {
            complete_bridge_reply(
                &state,
                Err(anyhow::anyhow!("router submit bridge sender dropped before response")),
            );
        }
    }
}

#[cfg(any(test, all(target_os = "linux", feature = "compio-mesh")))]
fn complete_bridge_reply<T>(state: &Arc<BridgeReplyState<T>>, result: anyhow::Result<T>) {
    let Ok(mut result_guard) = state.result.lock() else {
        return;
    };
    if result_guard.is_some() {
        return;
    }
    *result_guard = Some(result);
    drop(result_guard);

    let Ok(mut waker_guard) = state.waker.lock() else {
        return;
    };
    if let Some(waker) = waker_guard.take() {
        waker.wake();
    }
}

#[cfg(any(test, all(target_os = "linux", feature = "compio-mesh")))]
impl<T> std::future::Future for BridgeReply<T> {
    type Output = anyhow::Result<T>;

    fn poll(
        self: std::pin::Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        match self.state.result.lock() {
            Ok(mut result_guard) => {
                if let Some(result) = result_guard.take() {
                    return std::task::Poll::Ready(result);
                }
            }
            Err(_) => {
                return std::task::Poll::Ready(Err(anyhow::anyhow!(
                    "router submit bridge result lock poisoned"
                )));
            }
        }

        match self.state.waker.lock() {
            Ok(mut waker_guard) => {
                *waker_guard = Some(context.waker().clone());
            }
            Err(_) => {
                return std::task::Poll::Ready(Err(anyhow::anyhow!(
                    "router submit bridge waker lock poisoned"
                )));
            }
        }

        match self.state.result.lock() {
            Ok(mut result_guard) => {
                if let Some(result) = result_guard.take() {
                    std::task::Poll::Ready(result)
                } else {
                    std::task::Poll::Pending
                }
            }
            Err(_) => std::task::Poll::Ready(Err(anyhow::anyhow!(
                "router submit bridge result lock poisoned"
            ))),
        }
    }
}

#[cfg(all(target_os = "linux", feature = "compio-mesh"))]
impl RouterSubmitBridge {
    async fn handle_json_request(
        &self,
        request: ramflux_transport::GatewayQuicRequest,
        peer_service_id: String,
    ) -> anyhow::Result<ramflux_transport::GatewayQuicResponse> {
        let (sender, receiver) = bridge_reply_channel::<ramflux_transport::GatewayQuicResponse>();
        let router = Arc::clone(&self.router);
        self.tokio.spawn(async move {
            let result = handle_mesh_quic_request_value(&request, &router, &peer_service_id).await;
            sender.send(result);
        });
        receiver.await
    }

    async fn submit_raw_envelope(
        &self,
        body: Vec<u8>,
        total_started: std::time::Instant,
    ) -> anyhow::Result<ramflux_node_core::EnvelopeSubmitResponse> {
        let (sender, receiver) =
            bridge_reply_channel::<ramflux_node_core::EnvelopeSubmitResponse>();
        let router = Arc::clone(&self.router);
        self.tokio.spawn(async move {
            let result = async move {
                let envelope = serde_json::from_slice::<ramflux_protocol::Envelope>(&body)?;
                router.submit_envelope_async(envelope, total_started).await
            }
            .await;
            sender.send(result);
        });
        receiver.await
    }
}

fn router_async_worker_threads() -> usize {
    positive_usize_from_value(
        std::env::var(ROUTER_ASYNC_WORKER_THREADS_ENV).ok().as_deref(),
        std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get),
    )
}

fn router_async_ingress_socket_count() -> usize {
    positive_usize_from_value(std::env::var(ROUTER_ASYNC_INGRESS_SOCKETS_ENV).ok().as_deref(), 1)
}

#[cfg(all(target_os = "linux", feature = "compio-mesh"))]
fn router_async_compio_ingress_socket_count() -> usize {
    positive_usize_from_value(
        std::env::var(ROUTER_ASYNC_INGRESS_SOCKETS_ENV).ok().as_deref(),
        std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get),
    )
}

fn positive_usize_from_value(value: Option<&str>, default: usize) -> usize {
    value
        .and_then(|value| value.trim().parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(default)
        .max(1)
}

fn bind_router_async_mesh_quic_servers(
    listen_addr: &str,
    tls: &ramflux_transport::MeshTlsConfig,
    socket_count: usize,
) -> anyhow::Result<Vec<ramflux_transport::MeshQuicServer>> {
    if socket_count <= 1 {
        let root_pems_provider = Arc::new(|| Ok(Vec::new()));
        let server = ramflux_transport::MeshQuicServer::bind_with_pem_roots_provider(
            listen_addr,
            tls,
            root_pems_provider,
        )?;
        let local_addr = server.local_addr()?;
        tracing::info!(addr = %local_addr, "router async QUIC endpoint bound");
        return Ok(vec![server]);
    }

    let addr = listen_addr.parse::<SocketAddr>()?;
    if addr.port() == 0 {
        anyhow::bail!(
            "{ROUTER_ASYNC_INGRESS_SOCKETS_ENV}={socket_count} requires a fixed UDP port"
        );
    }

    let mut servers = Vec::with_capacity(socket_count);
    for endpoint_index in 0..socket_count {
        let socket = bind_router_async_reuse_port_socket(addr)?;
        let root_pems_provider = Arc::new(|| Ok(Vec::new()));
        let server =
            ramflux_transport::MeshQuicServer::bind_with_udp_socket_and_pem_roots_provider(
                socket,
                tls,
                root_pems_provider,
            )?;
        let local_addr = server.local_addr()?;
        tracing::info!(
            endpoint_index,
            addr = %local_addr,
            "router async QUIC SO_REUSEPORT endpoint bound"
        );
        servers.push(server);
    }
    Ok(servers)
}

fn bind_router_async_reuse_port_socket(addr: SocketAddr) -> anyhow::Result<std::net::UdpSocket> {
    let domain = if addr.is_ipv4() { Domain::IPV4 } else { Domain::IPV6 };
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_address(true)?;
    set_router_async_reuse_port(&socket)?;
    socket.set_nonblocking(true)?;
    socket.bind(&addr.into())?;
    Ok(socket.into())
}

#[cfg(not(any(
    target_os = "solaris",
    target_os = "illumos",
    target_os = "cygwin",
    target_os = "wasi"
)))]
fn set_router_async_reuse_port(socket: &Socket) -> anyhow::Result<()> {
    socket.set_reuse_port(true)?;
    Ok(())
}

#[cfg(any(target_os = "solaris", target_os = "illumos", target_os = "cygwin", target_os = "wasi"))]
fn set_router_async_reuse_port(_socket: &Socket) -> anyhow::Result<()> {
    anyhow::bail!("SO_REUSEPORT is unavailable on this target")
}

async fn router_async_mesh_quic_accept_loop(
    endpoint_index: usize,
    server: ramflux_transport::MeshQuicServer,
    router: Arc<crate::router_runtime::RouterHandle>,
    peer_auth: RouterAsyncMeshPeerAuth,
) {
    loop {
        let connection = match server.accept_connection().await {
            Ok(connection) => connection,
            Err(error) => {
                tracing::warn!(endpoint_index, %error, "router async QUIC connection rejected");
                continue;
            }
        };
        let connection_router = Arc::clone(&router);
        let connection_peer_auth = peer_auth.clone();
        tokio::spawn(async move {
            if let Err(error) = router_async_mesh_quic_connection_loop(
                connection,
                connection_router,
                connection_peer_auth,
            )
            .await
            {
                tracing::debug!(endpoint_index, %error, "router async QUIC connection ended");
            }
        });
    }
}

async fn router_async_mesh_quic_connection_loop(
    connection: ramflux_transport::MeshQuicConnection,
    router: Arc<crate::router_runtime::RouterHandle>,
    peer_auth: RouterAsyncMeshPeerAuth,
) -> anyhow::Result<()> {
    let peer_service_id = Arc::new(peer_auth.authorize(connection.peer_spiffe_uri())?);
    loop {
        let stream =
            match ramflux_transport::MeshQuicServer::accept_bi_on_connection(&connection).await {
                Ok(stream) => stream,
                Err(error) => {
                    tracing::debug!(%error, "router async QUIC stream accept loop ended");
                    return Ok(());
                }
            };
        let request_router = Arc::clone(&router);
        let peer_service_id = Arc::clone(&peer_service_id);
        tokio::spawn(async move {
            let accepted =
                match ramflux_transport::MeshQuicServer::read_wire_request_from_bi(stream).await {
                    Ok(accepted) => accepted,
                    Err(error) => {
                        tracing::warn!(%error, "router async QUIC request frame read failed");
                        return;
                    }
                };
            if let Err(error) = handle_router_async_mesh_quic_request(
                accepted,
                request_router,
                peer_service_id.as_str(),
            )
            .await
            {
                tracing::warn!(%error, "router async QUIC request failed");
            }
        });
    }
}

async fn handle_router_async_mesh_quic_request(
    accepted: ramflux_transport::MeshQuicAcceptedWireRequest,
    router: Arc<crate::router_runtime::RouterHandle>,
    peer_service_id: &str,
) -> anyhow::Result<()> {
    match accepted {
        ramflux_transport::MeshQuicAcceptedWireRequest::Json(accepted) => {
            match handle_mesh_quic_request_value(&accepted.request, &router, peer_service_id).await
            {
                Ok(response) if (200..300).contains(&response.status) => {
                    accepted.write_json_response(response.status, &response.body).await?;
                }
                Ok(response) => {
                    accepted
                        .write_text_response(response.status, &response.body.to_string())
                        .await?;
                }
                Err(error) => {
                    accepted.write_text_response(500, &error.to_string()).await?;
                }
            }
        }
        ramflux_transport::MeshQuicAcceptedWireRequest::Postcard(accepted) => {
            let response = handle_router_postcard_mesh_quic_request(accepted, &router).await;
            if let Err(error) = response {
                tracing::warn!(%error, "router async postcard request failed");
            }
        }
    }
    Ok(())
}

async fn handle_router_postcard_mesh_quic_request(
    accepted: ramflux_transport::MeshQuicPostcardAcceptedRequest,
    router: &crate::router_runtime::RouterHandle,
) -> anyhow::Result<()> {
    if (accepted.method.as_str(), accepted.path.as_str()) == ("POST", "/mvp0/envelope") {
        match crate::handlers::handle_mvp0_envelope_async(&accepted.body, router).await {
            Ok(response) => {
                accepted.write_postcard_response(200, &response).await?;
            }
            Err(error) => {
                accepted.write_text_response(500, &error.to_string()).await?;
            }
        }
        return Ok(());
    }
    accepted.write_text_response(404, "not found").await?;
    Ok(())
}

#[cfg(all(target_os = "linux", feature = "compio-mesh"))]
async fn router_async_compio_mesh_quic_connection_loop(
    connection: ramflux_transport::CompioMeshQuicConnection,
    bridge: RouterSubmitBridge,
    peer_auth: RouterAsyncMeshPeerAuth,
) -> anyhow::Result<()> {
    let peer_service_id = Arc::new(peer_auth.authorize(connection.peer_spiffe_uri())?);
    loop {
        let accepted = match ramflux_transport::CompioMeshQuicServer::accept_json_or_postcard_request_on_connection(&connection).await {
            Ok(accepted) => accepted,
            Err(error) => {
                tracing::debug!(%error, "router async compio QUIC stream loop ended");
                return Ok(());
            }
        };
        let request_bridge = bridge.clone();
        let peer_service_id = Arc::clone(&peer_service_id);
        compio::runtime::spawn(async move {
            if let Err(error) = handle_router_async_compio_mesh_quic_request(
                accepted,
                request_bridge,
                peer_service_id.as_str(),
            )
            .await
            {
                tracing::warn!(%error, "router async compio QUIC request failed");
            }
        })
        .detach();
    }
}

#[cfg(all(target_os = "linux", feature = "compio-mesh"))]
async fn handle_router_async_compio_mesh_quic_request(
    accepted: ramflux_transport::CompioMeshQuicAcceptedWireRequest,
    bridge: RouterSubmitBridge,
    peer_service_id: &str,
) -> anyhow::Result<()> {
    match accepted {
        ramflux_transport::CompioMeshQuicAcceptedWireRequest::Json(accepted) => {
            match bridge
                .handle_json_request(accepted.request.clone(), peer_service_id.to_owned())
                .await
            {
                Ok(response) if (200..300).contains(&response.status) => {
                    accepted.write_json_response(response.status, &response.body).await?;
                }
                Ok(response) => {
                    accepted
                        .write_text_response(response.status, &response.body.to_string())
                        .await?;
                }
                Err(error) => {
                    accepted.write_text_response(500, &error.to_string()).await?;
                }
            }
        }
        ramflux_transport::CompioMeshQuicAcceptedWireRequest::Postcard(accepted) => {
            handle_router_compio_postcard_mesh_quic_request(accepted, &bridge).await?;
        }
    }
    Ok(())
}

#[cfg(all(target_os = "linux", feature = "compio-mesh"))]
async fn handle_router_compio_postcard_mesh_quic_request(
    mut accepted: ramflux_transport::CompioMeshQuicPostcardAcceptedRequest,
    bridge: &RouterSubmitBridge,
) -> anyhow::Result<()> {
    if (accepted.method.as_str(), accepted.path.as_str()) == ("POST", "/mvp0/envelope") {
        let body = std::mem::take(&mut accepted.body);
        match bridge.submit_raw_envelope(body, std::time::Instant::now()).await {
            Ok(response) => {
                accepted.write_postcard_response(200, &response).await?;
            }
            Err(error) => {
                accepted.write_text_response(500, &error.to_string()).await?;
            }
        }
        return Ok(());
    }
    accepted.write_text_response(404, "not found").await?;
    Ok(())
}

fn serve_mesh_mtls(
    server: &ramflux_transport::MeshTlsServer,
    router: &Arc<crate::router_runtime::RouterHandle>,
    local_service_id: &str,
    allowed_service_ids: &std::collections::BTreeSet<String>,
) -> anyhow::Result<()> {
    tracing::info!("router mesh mTLS surface listening");
    loop {
        let accepted = match server.accept_authenticated() {
            Ok(accepted) => accepted,
            Err(error) => {
                tracing::warn!(%error, "router mesh mTLS handshake rejected");
                continue;
            }
        };
        let peer_spiffe_uri = accepted.peer_spiffe_uri.clone();
        let peer = match ramflux_node_core::authorize_mesh_peer(
            local_service_id,
            allowed_service_ids,
            peer_spiffe_uri.as_deref(),
        ) {
            Ok(peer) => peer,
            Err(error) => {
                tracing::warn!(%error, "router mesh peer identity rejected");
                continue;
            }
        };
        let mut stream = accepted.stream;
        let router = Arc::clone(router);
        let peer_service_id = peer.service_id;
        thread::spawn(move || {
            loop {
                match handle_mesh_request(&mut stream, &router, &peer_service_id) {
                    Ok(true) => {}
                    Ok(false) => break,
                    Err(error) => {
                        let body = format!("{error}");
                        if let Err(write_error) = ramflux_transport::write_mesh_text_response(
                            &mut stream,
                            "500 Internal Server Error",
                            &body,
                        ) {
                            tracing::warn!(%write_error, "failed to write router mesh error response");
                        }
                        break;
                    }
                }
            }
            if let Err(error) = ramflux_transport::close_mesh_server_stream(&mut stream) {
                tracing::debug!(%error, "router mesh close_notify failed");
            }
        });
    }
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

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use super::{
        DEFAULT_ROUTER_ASYNC_LISTEN_ADDR, RouterAsyncIngressRuntime, RouterAsyncMeshPeerAuth,
        bridge_reply_channel, positive_usize_from_value, router_async_ingress_enabled_from_value,
        router_async_ingress_runtime_from_value, router_async_listen_addr_from_value,
    };

    #[test]
    fn positive_usize_from_value_rejects_empty_zero_and_invalid() {
        assert_eq!(positive_usize_from_value(None, 7), 7);
        assert_eq!(positive_usize_from_value(Some(""), 7), 7);
        assert_eq!(positive_usize_from_value(Some("0"), 7), 7);
        assert_eq!(positive_usize_from_value(Some("not-a-number"), 7), 7);
    }

    #[test]
    fn positive_usize_from_value_accepts_trimmed_positive_values() {
        assert_eq!(positive_usize_from_value(Some(" 4 "), 1), 4);
        assert_eq!(positive_usize_from_value(Some("1"), 8), 1);
    }

    #[test]
    fn router_async_ingress_is_enabled_by_default_and_opt_out() {
        assert!(router_async_ingress_enabled_from_value(None));
        assert!(router_async_ingress_enabled_from_value(Some("")));
        assert!(router_async_ingress_enabled_from_value(Some("true")));
        assert!(router_async_ingress_enabled_from_value(Some("yes")));
        assert!(!router_async_ingress_enabled_from_value(Some("0")));
        assert!(!router_async_ingress_enabled_from_value(Some("false")));
        assert!(!router_async_ingress_enabled_from_value(Some("off")));
        assert!(!router_async_ingress_enabled_from_value(Some("no")));
    }

    #[test]
    fn router_async_listen_addr_defaults_when_env_and_config_absent() {
        let config = test_config(BTreeMap::new());

        assert_eq!(
            router_async_listen_addr_from_value(&config, None).as_deref(),
            Some(DEFAULT_ROUTER_ASYNC_LISTEN_ADDR)
        );
    }

    #[test]
    fn router_async_listen_addr_prefers_env_then_config() {
        let mut endpoints = BTreeMap::new();
        endpoints.insert("router-async-listen".to_owned(), "127.0.0.1:27444".to_owned());
        let config = test_config(endpoints);

        assert_eq!(
            router_async_listen_addr_from_value(&config, Some("127.0.0.1:37444")).as_deref(),
            Some("127.0.0.1:37444")
        );
        assert_eq!(
            router_async_listen_addr_from_value(&config, None).as_deref(),
            Some("127.0.0.1:27444")
        );
    }

    #[test]
    fn router_async_listen_addr_and_runtime_tolerate_literal_compose_defaults() {
        let mut endpoints = BTreeMap::new();
        endpoints.insert("router-async-listen".to_owned(), "127.0.0.1:27444".to_owned());
        let config = test_config(endpoints);

        assert_eq!(
            router_async_listen_addr_from_value(
                &config,
                Some("${RAMFLUX_ROUTER_ASYNC_LISTEN_ADDR:-0.0.0.0:17444}")
            )
            .as_deref(),
            Some(DEFAULT_ROUTER_ASYNC_LISTEN_ADDR)
        );
        assert_eq!(
            router_async_ingress_runtime_from_value(Some(
                "${RAMFLUX_ROUTER_ASYNC_INGRESS_RUNTIME:-tokio}"
            )),
            RouterAsyncIngressRuntime::Tokio
        );
        assert_eq!(
            router_async_ingress_runtime_from_value(Some("unsupported")),
            RouterAsyncIngressRuntime::Tokio
        );
        assert_eq!(
            router_async_ingress_runtime_from_value(Some("compio")),
            RouterAsyncIngressRuntime::Compio
        );
    }

    #[test]
    fn router_async_peer_auth_uses_certificate_peer_service_id() -> anyhow::Result<()> {
        let mut config = test_config(BTreeMap::new());
        config.mesh.allowed_service_ids.insert("ramflux-retention".to_owned());
        let peer_auth = RouterAsyncMeshPeerAuth::from_config(&config);

        let peer_service_id = peer_auth.authorize(Some("spiffe://node-a/ramflux-retention"))?;
        assert_eq!(peer_service_id, "ramflux-retention");
        assert!(peer_auth.authorize(Some("spiffe://node-a/ramflux-unknown")).is_err());
        assert!(peer_auth.authorize(None).is_err());
        Ok(())
    }

    #[test]
    fn bridge_reply_channel_wakes_cross_thread_waiter() -> anyhow::Result<()> {
        let (sender, receiver) = bridge_reply_channel::<usize>();
        let sender_thread = std::thread::spawn(move || {
            sender.send(Ok(7));
        });
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
        let value = runtime.block_on(receiver)?;
        sender_thread.join().map_err(|_| anyhow::anyhow!("bridge sender thread panicked"))?;
        assert_eq!(value, 7);
        Ok(())
    }

    #[test]
    fn bridge_reply_channel_reports_dropped_sender() -> anyhow::Result<()> {
        let (sender, receiver) = bridge_reply_channel::<usize>();
        drop(sender);
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
        let result = runtime.block_on(receiver);
        assert!(result.is_err());
        Ok(())
    }

    fn test_config(endpoints: BTreeMap<String, String>) -> ramflux_node_core::NodeServiceConfig {
        let mut allowed_service_ids = BTreeSet::new();
        allowed_service_ids.insert("ramflux-router".to_owned());
        ramflux_node_core::NodeServiceConfig {
            node_id: "test-node".to_owned(),
            service_id: "ramflux-router".to_owned(),
            redb_path: "test.redb".to_owned(),
            node_service_signing_seed_b64url: None,
            mesh: ramflux_node_core::MeshConfig {
                listen_addr: "127.0.0.1:0".to_owned(),
                ca_cert: "ca.pem".to_owned(),
                service_cert: "router.pem".to_owned(),
                service_key: "router-key.pem".to_owned(),
                allowed_service_ids,
                endpoints,
            },
            gateway: None,
            signaling: None,
            relay: None,
        }
    }
}
