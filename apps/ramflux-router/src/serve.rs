// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
use std::sync::Arc;
use std::thread;

#[cfg(feature = "itest-http")]
use crate::handlers::handle_itest_request;
use crate::handlers::handle_mesh_request;
#[cfg(feature = "itest-http")]
use std::net::{TcpListener, TcpStream};
#[cfg(feature = "itest-http")]
use std::sync::Mutex;

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
