// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use crate::session::{handle_gateway_quic_connection, handle_gateway_tcp_tls_stream};
use crate::{GatewaySessionHub, NotifyHttpClient, RouterMeshClient};

const GATEWAY_QUIC_RUNTIME_ENV: &str = "RAMFLUX_GATEWAY_QUIC_RUNTIME";

#[derive(Clone)]
pub(crate) struct GatewayListenerContext {
    pub(crate) router: RouterMeshClient,
    pub(crate) notify: NotifyHttpClient,
    pub(crate) state: Arc<Mutex<ramflux_node_core::GatewayState>>,
    pub(crate) store: Arc<ramflux_node_core::GatewayRedbStore>,
    pub(crate) hub: Arc<GatewaySessionHub>,
}

pub(crate) fn serve_gateway_quic(
    config: &ramflux_node_core::NodeServiceConfig,
    router: RouterMeshClient,
    notify: NotifyHttpClient,
    state: Arc<Mutex<ramflux_node_core::GatewayState>>,
    store: Arc<ramflux_node_core::GatewayRedbStore>,
) -> anyhow::Result<()> {
    let addr = gateway_quic_listen_addr(config)?;
    let addr: SocketAddr = addr.parse()?;
    let tls = ramflux_transport::MeshTlsConfig {
        ca_cert: config.mesh.ca_cert.clone().into(),
        service_cert: config.mesh.service_cert.clone().into(),
        service_key: config.mesh.service_key.clone().into(),
    };
    let server_config = ramflux_transport::quic_gateway_server_config(&tls)?;
    let tcp_addr = gateway_tcp_listen_addr(config)?;
    let tcp_addr: SocketAddr = tcp_addr.parse()?;
    let tcp_server_config = ramflux_transport::tcp_gateway_server_config(&tls)?;
    let context = GatewayListenerContext {
        router,
        notify,
        state,
        store,
        hub: Arc::new(GatewaySessionHub::default()),
    };
    match std::env::var(GATEWAY_QUIC_RUNTIME_ENV).as_deref() {
        Ok("compio") => {
            #[cfg(all(target_os = "linux", feature = "compio-gateway"))]
            {
                crate::compio_gateway::serve_gateway_compio_quic(
                    addr,
                    tls.clone(),
                    context.clone(),
                )?;
                spawn_gateway_tcp_tls_thread(tcp_addr, tcp_server_config, context)?;
                return Ok(());
            }
            #[cfg(not(all(target_os = "linux", feature = "compio-gateway")))]
            {
                return Err(anyhow::anyhow!(
                    "RAMFLUX_GATEWAY_QUIC_RUNTIME=compio requested but compio-gateway is not compiled"
                ));
            }
        }
        Ok("tokio" | "quinn") | Err(_) => {}
        Ok(other) => return Err(anyhow::anyhow!("unsupported gateway QUIC runtime {other}")),
    }
    spawn_gateway_quic_and_tcp_tls_thread(addr, server_config, tcp_addr, tcp_server_config, context)
}

fn spawn_gateway_quic_and_tcp_tls_thread(
    addr: SocketAddr,
    server_config: quinn::ServerConfig,
    tcp_addr: SocketAddr,
    tcp_server_config: rustls::ServerConfig,
    context: GatewayListenerContext,
) -> anyhow::Result<()> {
    std::thread::Builder::new().name("ramflux-gateway-quic".to_owned()).spawn(move || {
        let runtime = match tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
        {
            Ok(runtime) => runtime,
            Err(error) => {
                tracing::error!(%error, "gateway QUIC runtime failed");
                return;
            }
        };
        runtime.block_on(async move {
            let quic_task = tokio::spawn(run_gateway_quic(addr, server_config, context.clone()));
            let tcp_task = tokio::spawn(run_gateway_tcp_tls(tcp_addr, tcp_server_config, context));
            tokio::select! {
                result = quic_task => match result {
                    Ok(Ok(())) => {}
                    Ok(Err(error)) => tracing::error!(%error, "gateway QUIC listener stopped"),
                    Err(error) => tracing::error!(%error, "gateway QUIC task failed"),
                },
                result = tcp_task => match result {
                    Ok(Ok(())) => {}
                    Ok(Err(error)) => tracing::error!(%error, "gateway TCP-TLS listener stopped"),
                    Err(error) => tracing::error!(%error, "gateway TCP-TLS task failed"),
                },
            }
        });
    })?;
    Ok(())
}

#[cfg(all(target_os = "linux", feature = "compio-gateway"))]
fn spawn_gateway_tcp_tls_thread(
    tcp_addr: SocketAddr,
    tcp_server_config: rustls::ServerConfig,
    context: GatewayListenerContext,
) -> anyhow::Result<()> {
    std::thread::Builder::new().name("ramflux-gateway-tcp-tls".to_owned()).spawn(move || {
        let runtime = match tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
        {
            Ok(runtime) => runtime,
            Err(error) => {
                tracing::error!(%error, "gateway TCP-TLS runtime failed");
                return;
            }
        };
        runtime.block_on(async move {
            if let Err(error) = run_gateway_tcp_tls(tcp_addr, tcp_server_config, context).await {
                tracing::error!(%error, "gateway TCP-TLS listener stopped");
            }
        });
    })?;
    Ok(())
}

pub(crate) fn gateway_quic_listen_addr(
    config: &ramflux_node_core::NodeServiceConfig,
) -> anyhow::Result<String> {
    if let Ok(addr) = std::env::var("RAMFLUX_ITEST_GATEWAY_QUIC_ADDR") {
        return Ok(addr);
    }
    Ok(config
        .gateway
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("gateway.public_listen_addr is required"))?
        .public_listen_addr
        .clone())
}

pub(crate) fn gateway_tcp_listen_addr(
    config: &ramflux_node_core::NodeServiceConfig,
) -> anyhow::Result<String> {
    if let Ok(addr) = std::env::var("RAMFLUX_ITEST_GATEWAY_TCP_ADDR") {
        return Ok(addr);
    }
    Ok(config
        .gateway
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("gateway.public_listen_addr is required"))?
        .public_listen_addr
        .clone())
}

async fn run_gateway_quic(
    addr: SocketAddr,
    server_config: quinn::ServerConfig,
    context: GatewayListenerContext,
) -> anyhow::Result<()> {
    let endpoint = quinn::Endpoint::server(server_config, addr)?;
    tracing::info!(addr = %endpoint.local_addr()?, "gateway QUIC session surface listening");
    while let Some(connecting) = endpoint.accept().await {
        let context = context.clone();
        tokio::spawn(async move {
            match connecting.await {
                Ok(connection) => {
                    handle_gateway_quic_connection(
                        connection,
                        context.router,
                        context.notify,
                        context.state,
                        context.store,
                        context.hub,
                    )
                    .await;
                }
                Err(error) => tracing::warn!(%error, "gateway QUIC handshake rejected"),
            }
        });
    }
    Ok(())
}

async fn run_gateway_tcp_tls(
    addr: SocketAddr,
    server_config: rustls::ServerConfig,
    context: GatewayListenerContext,
) -> anyhow::Result<()> {
    let listener = tokio::net::TcpListener::bind(addr).await?;
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));
    tracing::info!(addr = %listener.local_addr()?, "gateway TCP-TLS session surface listening");
    loop {
        let (stream, remote_addr) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let context = context.clone();
        tokio::spawn(async move {
            let tls_stream = match acceptor.accept(stream).await {
                Ok(stream) => stream,
                Err(error) => {
                    tracing::warn!(%error, %remote_addr, "gateway TCP-TLS handshake rejected");
                    return;
                }
            };
            let context = crate::GatewayQuicContext {
                router: context.router,
                notify: context.notify,
                state: context.state,
                store: context.store,
                hub: context.hub,
                remote_addr,
            };
            let stream = ramflux_transport::GatewayTcpTlsStream::Server(tls_stream);
            if let Err(error) = handle_gateway_tcp_tls_stream(stream, context).await {
                tracing::warn!(%error, %remote_addr, "gateway TCP-TLS stream failed");
            }
        });
    }
}
