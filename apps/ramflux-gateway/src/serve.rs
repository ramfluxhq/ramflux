// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use crate::session::{handle_gateway_quic_connection, handle_gateway_tcp_tls_stream};
use crate::{
    GatewayForwardDeliverRequest, GatewayForwardDeliverResponse, GatewayPeerDirectory,
    GatewaySessionHub, NotifyHttpClient, RouterMeshClient, gateway_instance_id_from_env,
    gateway_peer_directory_from_env,
};

const GATEWAY_QUIC_RUNTIME_ENV: &str = "RAMFLUX_GATEWAY_QUIC_RUNTIME";
const GATEWAY_QUIC_WORKER_THREADS_ENV: &str = "RAMFLUX_GATEWAY_QUIC_WORKER_THREADS";

#[derive(Clone)]
pub(crate) struct GatewayListenerContext {
    pub(crate) node_id: String,
    pub(crate) gateway_id: String,
    pub(crate) peers: GatewayPeerDirectory,
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
    let gateway_id = gateway_instance_id_from_env();
    let peers = gateway_peer_directory_from_env(config, &gateway_id)?;
    let context = GatewayListenerContext {
        node_id: config.node_id.clone(),
        gateway_id,
        peers,
        router,
        notify,
        state,
        store,
        hub: Arc::new(GatewaySessionHub::default()),
    };
    if let Some(forward_listen_addr) = gateway_forward_listen_addr(config, &context.peers) {
        spawn_gateway_forward_mesh_thread(
            forward_listen_addr,
            gateway_mesh_tls_config(config),
            context.clone(),
        )?;
    }
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
        let worker_threads = gateway_quic_worker_threads();
        let runtime = match tokio::runtime::Builder::new_multi_thread()
            .worker_threads(worker_threads)
            .enable_all()
            .build()
        {
            Ok(runtime) => runtime,
            Err(error) => {
                tracing::error!(%error, "gateway QUIC runtime failed");
                return;
            }
        };
        tracing::info!(worker_threads, "gateway QUIC runtime configured");
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

fn gateway_quic_worker_threads() -> usize {
    let default = std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get);
    gateway_quic_worker_threads_from_value(
        std::env::var(GATEWAY_QUIC_WORKER_THREADS_ENV).ok().as_deref(),
        default,
    )
}

fn gateway_quic_worker_threads_from_value(value: Option<&str>, default: usize) -> usize {
    value
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(default.max(1))
        .max(1)
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
                    handle_gateway_quic_connection(connection, context).await;
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
                node_id: context.node_id,
                gateway_id: context.gateway_id,
                peers: context.peers,
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

fn gateway_forward_listen_addr(
    config: &ramflux_node_core::NodeServiceConfig,
    peers: &GatewayPeerDirectory,
) -> Option<String> {
    std::env::var("RAMFLUX_GATEWAY_FORWARD_LISTEN_ADDR")
        .ok()
        .and_then(|value| {
            let trimmed = value.trim();
            (!trimmed.is_empty()).then(|| trimmed.to_owned())
        })
        .or_else(|| (!peers.is_empty()).then(|| config.mesh.listen_addr.clone()))
}

fn gateway_mesh_tls_config(
    config: &ramflux_node_core::NodeServiceConfig,
) -> ramflux_transport::MeshTlsConfig {
    ramflux_transport::MeshTlsConfig {
        ca_cert: config.mesh.ca_cert.clone().into(),
        service_cert: config.mesh.service_cert.clone().into(),
        service_key: config.mesh.service_key.clone().into(),
    }
}

fn spawn_gateway_forward_mesh_thread(
    listen_addr: String,
    tls: ramflux_transport::MeshTlsConfig,
    context: GatewayListenerContext,
) -> anyhow::Result<()> {
    std::thread::Builder::new().name("ramflux-gateway-forward-mesh".to_owned()).spawn(
        move || {
            if let Err(error) = run_gateway_forward_mesh_listener(&listen_addr, &tls, context) {
                tracing::error!(%error, "gateway forward mesh listener stopped");
            }
        },
    )?;
    Ok(())
}

fn run_gateway_forward_mesh_listener(
    listen_addr: &str,
    tls: &ramflux_transport::MeshTlsConfig,
    context: GatewayListenerContext,
) -> anyhow::Result<()> {
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    runtime.block_on(async move {
        let root_pems_provider = Arc::new(|| Ok(Vec::new()));
        let server = ramflux_transport::MeshQuicServer::bind_with_pem_roots_provider(
            listen_addr,
            tls,
            root_pems_provider,
        )?;
        let local_addr = server.local_addr()?;
        tracing::info!(addr = %local_addr, "gateway forward mesh surface listening");
        loop {
            let connection = match server.accept_connection().await {
                Ok(connection) => connection,
                Err(error) => {
                    tracing::warn!(%error, "gateway forward mesh connection rejected");
                    continue;
                }
            };
            let connection_context = context.clone();
            tokio::spawn(async move {
                if let Err(error) =
                    gateway_forward_mesh_connection_loop(connection, connection_context).await
                {
                    tracing::debug!(%error, "gateway forward mesh connection ended");
                }
            });
        }
    })
}

async fn gateway_forward_mesh_connection_loop(
    connection: ramflux_transport::MeshQuicConnection,
    context: GatewayListenerContext,
) -> anyhow::Result<()> {
    loop {
        let accepted = match ramflux_transport::MeshQuicServer::accept_request_on_connection(
            &connection,
        )
        .await
        {
            Ok(accepted) => accepted,
            Err(error) => {
                tracing::debug!(%error, "gateway forward mesh stream loop ended");
                return Ok(());
            }
        };
        let request_context = context.clone();
        tokio::spawn(async move {
            if let Err(error) = handle_gateway_forward_mesh_request(accepted, request_context).await
            {
                tracing::warn!(%error, "gateway forward mesh request failed");
            }
        });
    }
}

async fn handle_gateway_forward_mesh_request(
    accepted: ramflux_transport::MeshQuicAcceptedRequest,
    context: GatewayListenerContext,
) -> anyhow::Result<()> {
    match handle_gateway_forward_request(&accepted.request, &context).await {
        Ok(response) => {
            accepted.write_json_response(200, &response).await?;
        }
        Err(error) => {
            accepted.write_text_response(400, &error.to_string()).await?;
        }
    }
    Ok(())
}

async fn handle_gateway_forward_request(
    request: &ramflux_transport::GatewayQuicRequest,
    context: &GatewayListenerContext,
) -> anyhow::Result<GatewayForwardDeliverResponse> {
    if request.method != "POST" || request.path != GatewayPeerDirectory::forward_path() {
        return Err(anyhow::anyhow!("not found"));
    }
    let forward: GatewayForwardDeliverRequest = serde_json::from_value(request.body.clone())?;
    if !forward.forwarded {
        return Err(anyhow::anyhow!("forward marker is required"));
    }
    handle_gateway_forward_deliver(&context.hub, forward).await
}

async fn handle_gateway_forward_deliver(
    hub: &GatewaySessionHub,
    forward: GatewayForwardDeliverRequest,
) -> anyhow::Result<GatewayForwardDeliverResponse> {
    if !forward.forwarded {
        return Err(anyhow::anyhow!("forward marker is required"));
    }
    let delivered = hub.send_to(&forward.target_delivery_id, &forward.frame).await?;
    Ok(GatewayForwardDeliverResponse { delivered })
}

#[cfg(test)]
mod tests {
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::{Arc, Mutex};

    use tokio::sync::Mutex as AsyncMutex;

    use super::{
        GatewaySessionHub, gateway_quic_worker_threads_from_value, handle_gateway_forward_deliver,
    };
    use crate::{GatewayForwardDeliverRequest, GatewaySendHandle};

    #[test]
    fn gateway_quic_worker_threads_parse_positive_env_value() {
        assert_eq!(gateway_quic_worker_threads_from_value(Some("16"), 4), 16);
        assert_eq!(gateway_quic_worker_threads_from_value(Some("0"), 4), 4);
        assert_eq!(gateway_quic_worker_threads_from_value(Some("not-a-number"), 4), 4);
        assert_eq!(gateway_quic_worker_threads_from_value(None, 4), 4);
        assert_eq!(gateway_quic_worker_threads_from_value(None, 0), 1);
    }

    #[tokio::test]
    async fn gateway_forward_deliver_hits_remote_hub_and_reports_miss()
    -> Result<(), Box<dyn std::error::Error>> {
        let source_hub = GatewaySessionHub::default();
        let receiver_hub = GatewaySessionHub::default();
        let frames = Arc::new(Mutex::new(Vec::new()));
        receiver_hub
            .register(
                "target_cross_gateway_bob".to_owned(),
                "session_bob_on_gw_b".to_owned(),
                recording_send_handle(Arc::clone(&frames)),
            )
            .await;
        let frame = deliver_frame("env_cross_gateway_forward", "target_cross_gateway_bob");

        let delivered = handle_gateway_forward_deliver(
            &receiver_hub,
            GatewayForwardDeliverRequest {
                source_gateway_id: "gw-a".to_owned(),
                target_delivery_id: "target_cross_gateway_bob".to_owned(),
                forwarded: true,
                frame: frame.clone(),
            },
        )
        .await?;

        assert!(delivered.delivered);
        let recorded_frame = {
            let recorded = frames.lock().map_err(|error| error.to_string())?;
            assert_eq!(recorded.len(), 1);
            serde_json::from_slice::<ramflux_node_core::GatewayServerFrame>(&recorded[0])?
        };
        assert_eq!(recorded_frame, frame);

        let missed = handle_gateway_forward_deliver(
            &source_hub,
            GatewayForwardDeliverRequest {
                source_gateway_id: "gw-b".to_owned(),
                target_delivery_id: "target_cross_gateway_bob".to_owned(),
                forwarded: true,
                frame,
            },
        )
        .await?;
        assert!(!missed.delivered);
        Ok(())
    }

    fn recording_send_handle(frames: Arc<Mutex<Vec<Vec<u8>>>>) -> GatewaySendHandle {
        Arc::new(AsyncMutex::new(Box::new(RecordingSink { frames })))
    }

    struct RecordingSink {
        frames: Arc<Mutex<Vec<Vec<u8>>>>,
    }

    impl ramflux_transport::GatewaySessionFrameSink for RecordingSink {
        fn send_frame<'a>(
            &'a mut self,
            frame: &'a [u8],
        ) -> Pin<Box<dyn Future<Output = Result<(), ramflux_transport::TransportError>> + Send + 'a>>
        {
            Box::pin(async move {
                let mut frames = self
                    .frames
                    .lock()
                    .map_err(|error| ramflux_transport::TransportError::Quic(error.to_string()))?;
                frames.push(frame.to_vec());
                Ok(())
            })
        }

        fn finish(&mut self) -> Result<(), ramflux_transport::TransportError> {
            Ok(())
        }
    }

    fn deliver_frame(
        envelope_id: &str,
        target_delivery_id: &str,
    ) -> ramflux_node_core::GatewayServerFrame {
        ramflux_node_core::GatewayServerFrame::Deliver {
            entry: ramflux_node_core::InboxEntry {
                inbox_seq: 1,
                target_delivery_id: target_delivery_id.to_owned(),
                envelope: test_envelope(envelope_id, target_delivery_id),
            },
        }
    }

    fn test_envelope(envelope_id: &str, target_delivery_id: &str) -> ramflux_protocol::Envelope {
        ramflux_protocol::Envelope {
            schema: ramflux_protocol::domain::ENVELOPE.to_owned(),
            version: 1,
            domain: ramflux_protocol::domain::ENVELOPE.to_owned(),
            ext: ramflux_protocol::Ext::default(),
            signed: ramflux_protocol::SignedFields {
                signing_key_id: "test-envelope-key".to_owned(),
                signature_alg: ramflux_protocol::SignatureAlg::Ed25519,
                signature: "test-envelope-signature".to_owned(),
            },
            envelope_id: envelope_id.to_owned(),
            source_principal_id: "principal_gateway_forward".to_owned(),
            source_device_id: "device_gateway_forward".to_owned(),
            target_delivery_id: target_delivery_id.to_owned(),
            routing_set_id: None,
            delivery_class: ramflux_protocol::DeliveryClass::OpaqueEvent,
            priority: ramflux_protocol::Priority::Normal,
            ttl: 86_400,
            created_at: 1_760_000_000,
            encrypted_payload: "encrypted_payload".to_owned(),
            payload_hash: "payload_hash".to_owned(),
        }
    }
}
