// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
use std::sync::Arc;
use std::thread;

use crate::{
    FederationDiscoverySurface, MeshInboundTransport, RouterMeshClient, SharedMeshObservability,
    handle_s8_receive_envelope, mesh_tls_config, mesh_transport_error,
};

const FEDERATION_MESH_RUNTIME_ENV: &str = "RAMFLUX_FEDERATION_MESH_RUNTIME";

pub(crate) fn serve_federation_mesh_mtls(
    config: &ramflux_node_core::NodeServiceConfig,
    state: &Arc<crate::SharedFederationTrustState>,
    router: &Arc<RouterMeshClient>,
    observability: &SharedMeshObservability,
    discovery: &FederationDiscoverySurface,
) -> Result<(), ramflux_node_core::NodeCoreError> {
    let mesh_server =
        ramflux_transport::MeshTlsServer::bind(&config.mesh.listen_addr, &mesh_tls_config(config))
            .map_err(|error| mesh_transport_error(&error))?;
    let mesh_state = Arc::clone(state);
    let mesh_router = Arc::clone(router);
    let mesh_observability = Arc::clone(observability);
    let mesh_discovery = discovery.clone();
    let tls = mesh_tls_config(config);
    thread::spawn(move || {
        if let Err(error) = serve_mesh_mtls(
            &mesh_server,
            &mesh_state,
            &mesh_router,
            &tls,
            &mesh_observability,
            &mesh_discovery,
        ) {
            tracing::error!(%error, "federation mesh mTLS listener stopped");
        }
    });
    #[cfg(feature = "itest-http")]
    if std::env::var("RAMFLUX_FEDERATION_DISABLE_QUIC_LISTENER").as_deref() == Ok("1") {
        observability.mark_quic_listener_disabled();
        tracing::warn!("federation mesh QUIC listener disabled by itest affordance");
        return Ok(());
    }
    let quic_state = Arc::clone(state);
    let quic_router = Arc::clone(router);
    let quic_observability = Arc::clone(observability);
    let quic_discovery = discovery.clone();
    let quic_tls = mesh_tls_config(config);
    let quic_addr = config.mesh.listen_addr.clone();
    match std::env::var(FEDERATION_MESH_RUNTIME_ENV).as_deref() {
        Ok("compio") => {
            #[cfg(all(target_os = "linux", feature = "compio-mesh"))]
            {
                thread::spawn(move || {
                    if let Err(error) = serve_mesh_compio_quic(
                        &quic_addr,
                        &quic_state,
                        &quic_router,
                        &quic_tls,
                        &quic_observability,
                        &quic_discovery,
                    ) {
                        quic_observability.mark_quic_listener_error(&error.to_string());
                        tracing::error!(%error, "federation mesh compio QUIC listener stopped");
                    }
                });
            }
            #[cfg(not(all(target_os = "linux", feature = "compio-mesh")))]
            {
                return Err(ramflux_node_core::NodeCoreError::ItestHttp(
                    "RAMFLUX_FEDERATION_MESH_RUNTIME=compio requested but compio-mesh is not compiled"
                        .to_owned(),
                ));
            }
        }
        Ok("tokio" | "quinn") | Err(_) => {
            thread::spawn(move || {
                if let Err(error) = serve_mesh_quic(
                    &quic_addr,
                    &quic_state,
                    &quic_router,
                    &quic_tls,
                    &quic_observability,
                    &quic_discovery,
                ) {
                    quic_observability.mark_quic_listener_error(&error.to_string());
                    tracing::error!(%error, "federation mesh QUIC listener stopped");
                }
            });
        }
        Ok(other) => {
            return Err(ramflux_node_core::NodeCoreError::ItestHttp(format!(
                "unsupported federation mesh runtime {other}"
            )));
        }
    }
    Ok(())
}

pub(crate) fn serve_mesh_quic(
    listen_addr: &str,
    state: &Arc<crate::SharedFederationTrustState>,
    router: &Arc<RouterMeshClient>,
    tls: &ramflux_transport::MeshTlsConfig,
    observability: &SharedMeshObservability,
    discovery: &FederationDiscoverySurface,
) -> Result<(), ramflux_node_core::NodeCoreError> {
    let roots_state = Arc::clone(state);
    let root_pems_provider = std::sync::Arc::new(move || {
        let state = roots_state
            .snapshot()
            .map_err(|error| ramflux_transport::TransportError::Http(error.to_string()))?;
        Ok(state.pinned_peer_ca_cert_pems())
    });
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|source| ramflux_node_core::NodeCoreError::ItestHttp(source.to_string()))?;
    runtime.block_on(async move {
        let server = ramflux_transport::MeshQuicServer::bind_with_pem_roots_provider(
            listen_addr,
            tls,
            root_pems_provider,
        )
        .map_err(|error| mesh_transport_error(&error))?;
        let local_addr = server.local_addr().map_err(|error| mesh_transport_error(&error))?;
        observability.mark_quic_listener_ready(local_addr.to_string());
        tracing::info!(addr = %local_addr, "federation mesh QUIC surface listening");
        loop {
            let connection = match server.accept_connection().await {
                Ok(connection) => connection,
                Err(error) => {
                    observability.mark_quic_listener_error(&error.to_string());
                    tracing::error!(%error, "federation mesh QUIC connection rejected");
                    continue;
                }
            };
            let state = Arc::clone(state);
            let router = Arc::clone(router);
            let observability = Arc::clone(observability);
            let discovery = discovery.clone();
            tokio::spawn(async move {
                if let Err(error) =
                    handle_mesh_quic_connection(connection, state, router, observability, discovery)
                        .await
                {
                    tracing::warn!(%error, "federation mesh QUIC connection failed");
                }
            });
        }
    })
}

#[cfg(all(target_os = "linux", feature = "compio-mesh"))]
pub(crate) fn serve_mesh_compio_quic(
    listen_addr: &str,
    state: &Arc<crate::SharedFederationTrustState>,
    router: &Arc<RouterMeshClient>,
    tls: &ramflux_transport::MeshTlsConfig,
    observability: &SharedMeshObservability,
    discovery: &FederationDiscoverySurface,
) -> Result<(), ramflux_node_core::NodeCoreError> {
    let roots_state = Arc::clone(state);
    let root_pems_provider = std::sync::Arc::new(move || {
        let state = roots_state
            .snapshot()
            .map_err(|error| ramflux_transport::TransportError::Http(error.to_string()))?;
        Ok(state.pinned_peer_ca_cert_pems())
    });
    let runtime = compio::runtime::Runtime::new()
        .map_err(|source| ramflux_node_core::NodeCoreError::ItestHttp(source.to_string()))?;
    runtime.block_on(async move {
        let server = ramflux_transport::CompioMeshQuicServer::bind_with_pem_roots_provider(
            listen_addr,
            tls,
            root_pems_provider,
        )
        .await
        .map_err(|error| mesh_transport_error(&error))?;
        let local_addr = server.local_addr().map_err(|error| mesh_transport_error(&error))?;
        observability.mark_quic_listener_ready(local_addr.to_string());
        tracing::info!(addr = %local_addr, "federation mesh compio QUIC surface listening");
        loop {
            let connection = match server.accept_connection().await {
                Ok(connection) => connection,
                Err(error) => {
                    observability.mark_quic_listener_error(&error.to_string());
                    tracing::error!(%error, "federation mesh compio QUIC connection rejected");
                    continue;
                }
            };
            let state = Arc::clone(state);
            let router = Arc::clone(router);
            let observability = Arc::clone(observability);
            let discovery = discovery.clone();
            compio::runtime::spawn(async move {
                if let Err(error) = handle_mesh_compio_quic_connection(
                    connection,
                    &state,
                    &router,
                    &observability,
                    &discovery,
                )
                .await
                {
                    tracing::warn!(%error, "federation mesh compio QUIC connection failed");
                }
            })
            .detach();
        }
    })
}

pub(crate) fn serve_mesh_mtls(
    server: &ramflux_transport::MeshTlsServer,
    state: &Arc<crate::SharedFederationTrustState>,
    router: &Arc<RouterMeshClient>,
    tls: &ramflux_transport::MeshTlsConfig,
    observability: &SharedMeshObservability,
    discovery: &FederationDiscoverySurface,
) -> Result<(), ramflux_node_core::NodeCoreError> {
    tracing::info!("federation mesh mTLS surface listening");
    loop {
        let accepted = match server.accept_authenticated_with_pem_roots_provider(tls, || {
            let state = state
                .snapshot()
                .map_err(|error| ramflux_transport::TransportError::Http(error.to_string()))?;
            Ok(state.pinned_peer_ca_cert_pems())
        }) {
            Ok(accepted) => accepted,
            Err(error) => {
                tracing::warn!(%error, "federation mesh mTLS handshake rejected");
                continue;
            }
        };
        let mut stream = accepted.stream;
        let peer_service_id = accepted
            .peer_spiffe_uri
            .as_deref()
            .and_then(|spiffe_uri| ramflux_node_core::parse_mesh_spiffe_uri(spiffe_uri).ok())
            .map(|peer| peer.service_id);
        let state = Arc::clone(state);
        let router = Arc::clone(router);
        let observability = Arc::clone(observability);
        let discovery = discovery.clone();
        thread::spawn(move || {
            loop {
                match handle_mesh_request(
                    &mut stream,
                    &state,
                    &router,
                    peer_service_id.as_deref(),
                    &observability,
                    &discovery,
                ) {
                    Ok(true) => {}
                    Ok(false) => break,
                    Err(error) => {
                        let body = format!("{error}");
                        if let Err(write_error) = ramflux_transport::write_mesh_text_response(
                            &mut stream,
                            "500 Internal Server Error",
                            &body,
                        ) {
                            tracing::warn!(
                                %write_error,
                                "failed to write federation mesh error response"
                            );
                        }
                        break;
                    }
                }
            }
            if let Err(error) = ramflux_transport::close_mesh_server_stream(&mut stream) {
                tracing::debug!(%error, "federation mesh close_notify failed");
            }
        });
    }
}

pub(crate) fn handle_mesh_request(
    stream: &mut ramflux_transport::MeshTlsServerStream,
    state: &Arc<crate::SharedFederationTrustState>,
    router: &RouterMeshClient,
    peer_service_id: Option<&str>,
    observability: &SharedMeshObservability,
    discovery: &FederationDiscoverySurface,
) -> Result<bool, ramflux_node_core::NodeCoreError> {
    let Some(request) = ramflux_transport::read_mesh_http_request(stream)
        .map_err(|error| mesh_transport_error(&error))?
    else {
        return Ok(false);
    };
    if peer_service_id == Some("ramflux-retention")
        && request.path != "/internal/retention/gc_sweep"
    {
        ramflux_transport::write_mesh_text_response(
            stream,
            "403 Forbidden",
            "retention peer is only authorized for gc_sweep",
        )
        .map_err(|error| mesh_transport_error(&error))?;
        return Ok(true);
    }
    match (request.method.as_str(), request.path.as_str()) {
        ("GET", "/healthz") => {
            ramflux_transport::write_mesh_json_response(
                stream,
                "200 OK",
                &serde_json::json!({
                    "service": "ramflux-federation",
                    "status": "ok"
                }),
            )
            .map_err(|error| mesh_transport_error(&error))?;
        }
        ("POST", "/s8/federation/envelope") => {
            observability.record_inbound_s8_envelope(MeshInboundTransport::Tcp);
            handle_s8_inbound_envelope_request(
                stream,
                peer_service_id,
                &request.body,
                &MeshEnvelopeContext { state, router, discovery, observability },
            )?;
        }
        ("POST", "/internal/retention/gc_sweep") => {
            if peer_service_id != Some("ramflux-retention") {
                ramflux_transport::write_mesh_text_response(
                    stream,
                    "403 Forbidden",
                    "gc_sweep requires ramflux-retention peer",
                )
                .map_err(|error| mesh_transport_error(&error))?;
                return Ok(true);
            }
            let sweep: ramflux_node_core::RetentionGcSweepRequest =
                serde_json::from_slice(&request.body).map_err(|source| {
                    ramflux_node_core::NodeCoreError::ItestJson(source.to_string())
                })?;
            ramflux_transport::write_mesh_json_response(stream, "200 OK", &sweep.response(0))
                .map_err(|error| mesh_transport_error(&error))?;
        }
        _ => {
            ramflux_transport::write_mesh_text_response(stream, "404 Not Found", "not found")
                .map_err(|error| mesh_transport_error(&error))?;
        }
    }
    Ok(true)
}

struct MeshEnvelopeContext<'a> {
    state: &'a crate::SharedFederationTrustState,
    router: &'a RouterMeshClient,
    discovery: &'a FederationDiscoverySurface,
    observability: &'a SharedMeshObservability,
}

struct MeshQuicRequestContext<'a> {
    state: &'a crate::SharedFederationTrustState,
    router: &'a RouterMeshClient,
    discovery: &'a FederationDiscoverySurface,
    observability: &'a SharedMeshObservability,
    inbound_transport: MeshInboundTransport,
}

fn handle_s8_inbound_envelope_request(
    stream: &mut ramflux_transport::MeshTlsServerStream,
    peer_service_id: Option<&str>,
    body_bytes: &[u8],
    context: &MeshEnvelopeContext<'_>,
) -> Result<(), ramflux_node_core::NodeCoreError> {
    if peer_service_id == Some("ramflux-retention") {
        ramflux_transport::write_mesh_text_response(
            stream,
            "403 Forbidden",
            "retention peer cannot submit federation envelope",
        )
        .map_err(|error| mesh_transport_error(&error))?;
        return Ok(());
    }
    let body_len = body_bytes.len();
    tracing::debug!(
        body_len,
        peer_service_id = peer_service_id.unwrap_or("<unknown>"),
        "federation inbound envelope body read; decoding request"
    );
    let request: ramflux_node_core::FederatedEnvelopeForwardRequest =
        match serde_json::from_slice(body_bytes) {
            Ok(request) => request,
            Err(source) => {
                let body = format!("inbound envelope decode failed: {source}");
                tracing::error!(
                    body_len,
                    error = %source,
                    "federation inbound envelope request decode failed"
                );
                ramflux_transport::write_mesh_text_response(
                    stream,
                    "500 Internal Server Error",
                    &body,
                )
                .map_err(|error| mesh_transport_error(&error))?;
                return Ok(());
            }
        };
    tracing::debug!(
        source_node_id = %request.source_node_id,
        target_node_id = %request.target_node_id,
        envelope_id = %request.envelope.envelope_id,
        created_at = request.envelope.created_at,
        ttl = request.envelope.ttl,
        "federation inbound envelope request decoded"
    );
    match handle_s8_receive_envelope(
        &request,
        context.state,
        context.router,
        context.discovery,
        Some(context.observability),
    ) {
        Ok(response) => {
            tracing::debug!(
                source_node_id = %request.source_node_id,
                target_node_id = %request.target_node_id,
                envelope_id = %request.envelope.envelope_id,
                outcome = %response.delivery.outcome,
                "federation inbound envelope accepted"
            );
            ramflux_transport::write_mesh_json_response(stream, "200 OK", &response)
                .map_err(|error| mesh_transport_error(&error))?;
        }
        Err(error) => {
            let body = error.to_string();
            tracing::error!(
                source_node_id = %request.source_node_id,
                target_node_id = %request.target_node_id,
                envelope_id = %request.envelope.envelope_id,
                error = %body,
                "federation inbound envelope rejected"
            );
            ramflux_transport::write_mesh_text_response(stream, "500 Internal Server Error", &body)
                .map_err(|error| mesh_transport_error(&error))?;
        }
    }
    Ok(())
}

async fn handle_mesh_quic_connection(
    connection: ramflux_transport::MeshQuicConnection,
    state: Arc<crate::SharedFederationTrustState>,
    router: Arc<RouterMeshClient>,
    observability: SharedMeshObservability,
    discovery: FederationDiscoverySurface,
) -> Result<(), ramflux_node_core::NodeCoreError> {
    let remote_address = connection.remote_address();
    tracing::debug!(%remote_address, "federation mesh QUIC connection stream loop started");
    loop {
        let accepted = match ramflux_transport::MeshQuicServer::accept_request_on_connection(
            &connection,
        )
        .await
        {
            Ok(accepted) => accepted,
            Err(error) => {
                tracing::debug!(%remote_address, %error, "federation mesh QUIC connection stream loop ended");
                return Ok(());
            }
        };
        let state = Arc::clone(&state);
        let router = Arc::clone(&router);
        let observability = Arc::clone(&observability);
        let discovery = discovery.clone();
        tokio::spawn(async move {
            if let Err(error) =
                handle_mesh_quic_request(accepted, &state, &router, &observability, &discovery)
                    .await
            {
                tracing::warn!(%remote_address, %error, "federation mesh QUIC request failed");
            }
        });
    }
}

async fn handle_mesh_quic_request(
    accepted: ramflux_transport::MeshQuicAcceptedRequest,
    state: &crate::SharedFederationTrustState,
    router: &RouterMeshClient,
    observability: &SharedMeshObservability,
    discovery: &FederationDiscoverySurface,
) -> Result<(), ramflux_node_core::NodeCoreError> {
    let response = handle_federation_mesh_quic_request(
        &accepted.request,
        None,
        &MeshQuicRequestContext {
            state,
            router,
            discovery,
            observability,
            inbound_transport: MeshInboundTransport::Quic,
        },
    )?;
    if (200..300).contains(&response.status) {
        accepted
            .write_json_response(response.status, &response.body)
            .await
            .map_err(|error| mesh_transport_error(&error))?;
    } else {
        accepted
            .write_text_response(response.status, response_error_text(&response.body))
            .await
            .map_err(|error| mesh_transport_error(&error))?;
    }
    Ok(())
}

#[cfg(all(target_os = "linux", feature = "compio-mesh"))]
async fn handle_mesh_compio_quic_connection(
    connection: ramflux_transport::CompioMeshQuicConnection,
    state: &crate::SharedFederationTrustState,
    router: &RouterMeshClient,
    observability: &SharedMeshObservability,
    discovery: &FederationDiscoverySurface,
) -> Result<(), ramflux_node_core::NodeCoreError> {
    let remote_address = connection.remote_address();
    let peer_service_id = connection
        .peer_spiffe_uri()
        .and_then(|spiffe_uri| ramflux_node_core::parse_mesh_spiffe_uri(spiffe_uri).ok())
        .map(|peer| peer.service_id);
    tracing::debug!(
        %remote_address,
        peer_service_id = peer_service_id.as_deref().unwrap_or("<unknown>"),
        "federation mesh compio QUIC connection stream loop started"
    );
    loop {
        let accepted = match ramflux_transport::CompioMeshQuicServer::accept_request_on_connection(
            &connection,
        )
        .await
        {
            Ok(accepted) => accepted,
            Err(error) => {
                tracing::debug!(%remote_address, %error, "federation mesh compio QUIC connection stream loop ended");
                return Ok(());
            }
        };
        handle_mesh_compio_quic_request(
            accepted,
            peer_service_id.as_deref(),
            state,
            router,
            observability,
            discovery,
        )
        .await?;
    }
}

#[cfg(all(target_os = "linux", feature = "compio-mesh"))]
async fn handle_mesh_compio_quic_request(
    accepted: ramflux_transport::CompioMeshQuicAcceptedRequest,
    peer_service_id: Option<&str>,
    state: &crate::SharedFederationTrustState,
    router: &RouterMeshClient,
    observability: &SharedMeshObservability,
    discovery: &FederationDiscoverySurface,
) -> Result<(), ramflux_node_core::NodeCoreError> {
    let response = handle_federation_mesh_quic_request(
        &accepted.request,
        peer_service_id,
        &MeshQuicRequestContext {
            state,
            router,
            discovery,
            observability,
            inbound_transport: MeshInboundTransport::Quic,
        },
    )?;
    if (200..300).contains(&response.status) {
        accepted
            .write_json_response(response.status, &response.body)
            .await
            .map_err(|error| mesh_transport_error(&error))?;
    } else {
        accepted
            .write_text_response(response.status, response_error_text(&response.body))
            .await
            .map_err(|error| mesh_transport_error(&error))?;
    }
    Ok(())
}

fn handle_federation_mesh_quic_request(
    request: &ramflux_transport::GatewayQuicRequest,
    peer_service_id: Option<&str>,
    context: &MeshQuicRequestContext<'_>,
) -> Result<ramflux_transport::GatewayQuicResponse, ramflux_node_core::NodeCoreError> {
    match (request.method.as_str(), request.path.as_str()) {
        ("GET", "/healthz") => Ok(ramflux_transport::GatewayQuicResponse {
            status: 200,
            body: serde_json::json!({
                "service": "ramflux-federation",
                "status": "ok"
            }),
        }),
        ("POST", "/s8/federation/envelope") => {
            if peer_service_id == Some("ramflux-retention") {
                return Ok(text_quic_response(
                    403,
                    "retention peer cannot submit federation envelope",
                ));
            }
            context.observability.record_inbound_s8_envelope(context.inbound_transport);
            let forwarded: ramflux_node_core::FederatedEnvelopeForwardRequest =
                serde_json::from_value(request.body.clone()).map_err(|source| {
                    ramflux_node_core::NodeCoreError::ItestJson(source.to_string())
                })?;
            match handle_s8_receive_envelope(
                &forwarded,
                context.state,
                context.router,
                context.discovery,
                Some(context.observability),
            ) {
                Ok(response) => Ok(ramflux_transport::GatewayQuicResponse {
                    status: 200,
                    body: serde_json::to_value(response).map_err(|source| {
                        ramflux_node_core::NodeCoreError::ItestJson(source.to_string())
                    })?,
                }),
                Err(error) => Ok(text_quic_response(500, &error.to_string())),
            }
        }
        _ => Ok(text_quic_response(404, "not found")),
    }
}

fn text_quic_response(status: u16, body: &str) -> ramflux_transport::GatewayQuicResponse {
    ramflux_transport::GatewayQuicResponse { status, body: serde_json::json!({ "error": body }) }
}

fn response_error_text(body: &serde_json::Value) -> &str {
    body.get("error").and_then(serde_json::Value::as_str).unwrap_or("mesh request failed")
}
