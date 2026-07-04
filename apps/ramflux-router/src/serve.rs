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
const ROUTER_ASYNC_LISTEN_ADDR_ENV: &str = "RAMFLUX_ROUTER_ASYNC_LISTEN_ADDR";
const ROUTER_ASYNC_INGRESS_SOCKETS_ENV: &str = "RAMFLUX_ROUTER_ASYNC_INGRESS_SOCKETS";
const ROUTER_ASYNC_WORKER_THREADS_ENV: &str = "RAMFLUX_ROUTER_ASYNC_WORKER_THREADS";

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
        spawn_router_async_mesh_quic_thread(listen_addr, mesh_tls_config(config), router)?;
    }
    Ok(())
}

fn router_async_ingress_enabled() -> bool {
    std::env::var(ROUTER_ASYNC_INGRESS_ENV).is_ok_and(|value| {
        let trimmed = value.trim();
        trimmed == "1"
            || trimmed.eq_ignore_ascii_case("true")
            || trimmed.eq_ignore_ascii_case("on")
            || trimmed.eq_ignore_ascii_case("yes")
    })
}

fn router_async_listen_addr(config: &ramflux_node_core::NodeServiceConfig) -> Option<String> {
    std::env::var(ROUTER_ASYNC_LISTEN_ADDR_ENV)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
        .or_else(|| config.mesh.endpoints.get("router-async-listen").cloned())
}

fn spawn_router_async_mesh_quic_thread(
    listen_addr: String,
    tls: ramflux_transport::MeshTlsConfig,
    router: &Arc<crate::router_runtime::RouterHandle>,
) -> anyhow::Result<()> {
    let router = Arc::clone(router);
    thread::Builder::new().name("ramflux-router-async-quic-ingress".to_owned()).spawn(
        move || {
            if let Err(error) = run_router_async_mesh_quic_listener(&listen_addr, &tls, router) {
                tracing::error!(%error, "router async QUIC ingress stopped");
            }
        },
    )?;
    Ok(())
}

fn run_router_async_mesh_quic_listener(
    listen_addr: &str,
    tls: &ramflux_transport::MeshTlsConfig,
    router: Arc<crate::router_runtime::RouterHandle>,
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
            tokio::spawn(async move {
                router_async_mesh_quic_accept_loop(endpoint_index, server, endpoint_router).await;
            });
        }
        std::future::pending::<()>().await;
        #[allow(unreachable_code)]
        Ok::<(), anyhow::Error>(())
    })
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
        tokio::spawn(async move {
            if let Err(error) =
                router_async_mesh_quic_connection_loop(connection, connection_router).await
            {
                tracing::debug!(endpoint_index, %error, "router async QUIC connection ended");
            }
        });
    }
}

async fn router_async_mesh_quic_connection_loop(
    connection: ramflux_transport::MeshQuicConnection,
    router: Arc<crate::router_runtime::RouterHandle>,
) -> anyhow::Result<()> {
    loop {
        let accepted =
            match ramflux_transport::MeshQuicServer::accept_json_or_postcard_request_on_connection(
                &connection,
            )
            .await
            {
                Ok(accepted) => accepted,
                Err(error) => {
                    tracing::debug!(%error, "router async QUIC stream loop ended");
                    return Ok(());
                }
            };
        let request_router = Arc::clone(&router);
        tokio::spawn(async move {
            if let Err(error) =
                handle_router_async_mesh_quic_request(accepted, request_router).await
            {
                tracing::warn!(%error, "router async QUIC request failed");
            }
        });
    }
}

async fn handle_router_async_mesh_quic_request(
    accepted: ramflux_transport::MeshQuicAcceptedWireRequest,
    router: Arc<crate::router_runtime::RouterHandle>,
) -> anyhow::Result<()> {
    match accepted {
        ramflux_transport::MeshQuicAcceptedWireRequest::Json(accepted) => {
            match handle_mesh_quic_request_value(&accepted.request, &router, "ramflux-gateway")
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
    use super::positive_usize_from_value;

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
}
