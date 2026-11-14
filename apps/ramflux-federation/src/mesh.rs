// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use std::sync::Arc;

use crate::{
    FederationDiscoverySurface, MeshInboundTransport, RouterMeshClient, SharedMeshObservability,
    handle_s8_receive_envelope, mesh_tls_config, mesh_transport_error,
};

const FEDERATION_MESH_RUNTIME_ENV: &str = "RAMFLUX_FEDERATION_MESH_RUNTIME";
const RETENTION_GC_SWEEP_PATH: &str = "/internal/retention/gc_sweep";
const FEDERATION_TRUST_SNAPSHOT_FILE_ENV: &str = "RAMFLUX_FEDERATION_TRUST_SNAPSHOT_FILE";
const FEDERATION_TRUST_SNAPSHOT_PATH: &str = "/mvp9/federation/trust-snapshot";

/// Loads the pre-signed federated issuer trust snapshot envelope from `path` as opaque JSON. Fails
/// (rather than synthesizing a default) when the file cannot be read or is not valid JSON.
///
/// T23-A2b2b: federation is an out-of-band file server — it holds NO signing key and never signs. It
/// round-trips whatever offline-signed envelope the operator places on disk (legacy single-key v3 or
/// the keyring-era v4 `ProviderSignedTrustSnapshot`), so it is deliberately envelope-format-agnostic:
/// the relay is the sole verifier of the envelope's schema/signature.
fn load_signed_trust_snapshot_from_file(
    path: &std::path::Path,
) -> Result<serde_json::Value, ramflux_node_core::NodeCoreError> {
    let text = std::fs::read_to_string(path).map_err(|source| {
        ramflux_node_core::NodeCoreError::ItestJson(format!(
            "failed to read trust snapshot file {}: {source}",
            path.display()
        ))
    })?;
    serde_json::from_str(&text).map_err(|source| {
        ramflux_node_core::NodeCoreError::ItestJson(format!(
            "invalid trust snapshot envelope JSON in {}: {source}",
            path.display()
        ))
    })
}

/// Reads the configured pre-signed trust snapshot envelope (opaque JSON) from the file named by
/// `RAMFLUX_FEDERATION_TRUST_SNAPSHOT_FILE`. Fails closed when the variable is unset or the file is
/// missing/invalid — it never returns a default snapshot.
fn federation_trust_snapshot_envelope()
-> Result<serde_json::Value, ramflux_node_core::NodeCoreError> {
    let path = ramflux_node_core::environment::var(FEDERATION_TRUST_SNAPSHOT_FILE_ENV).map_err(
        |_error| {
            ramflux_node_core::NodeCoreError::ItestJson(format!(
                "{FEDERATION_TRUST_SNAPSHOT_FILE_ENV} is not set"
            ))
        },
    )?;
    load_signed_trust_snapshot_from_file(std::path::Path::new(&path))
}

#[derive(Clone)]
pub(crate) struct MeshServerContext {
    state: Arc<crate::SharedFederationTrustState>,
    store: Arc<ramflux_node_core::FederationRedbStore>,
    router: Arc<RouterMeshClient>,
    observability: SharedMeshObservability,
    discovery: FederationDiscoverySurface,
}

pub(crate) fn serve_federation_mesh_mtls(
    config: &ramflux_node_core::NodeServiceConfig,
    state: &Arc<crate::SharedFederationTrustState>,
    store: &Arc<ramflux_node_core::FederationRedbStore>,
    router: &Arc<RouterMeshClient>,
    observability: &SharedMeshObservability,
    discovery: &FederationDiscoverySurface,
) -> Result<(), ramflux_node_core::NodeCoreError> {
    let mesh_server =
        ramflux_transport::MeshTlsServer::bind(&config.mesh.listen_addr, &mesh_tls_config(config))
            .map_err(|error| mesh_transport_error(&error))?;
    mesh_server.set_nonblocking(true).map_err(|error| mesh_transport_error(&error))?;
    let context = MeshServerContext {
        state: Arc::clone(state),
        store: Arc::clone(store),
        router: Arc::clone(router),
        observability: Arc::clone(observability),
        discovery: discovery.clone(),
    };
    let mesh_context = context.clone();
    let tls = mesh_tls_config(config);
    ramflux_node_core::spawn_service_worker("ramflux-federation-mesh-tls", move |_| {
        serve_mesh_mtls(&mesh_server, &mesh_context, &tls);
    })?;
    #[cfg(feature = "itest-http")]
    if ramflux_node_core::environment::var("RAMFLUX_FEDERATION_DISABLE_QUIC_LISTENER").as_deref()
        == Ok("1")
    {
        observability.mark_quic_listener_disabled();
        tracing::warn!("federation mesh QUIC listener disabled by itest affordance");
        return Ok(());
    }
    let quic_context = context;
    let quic_tls = mesh_tls_config(config);
    let quic_addr = config.mesh.listen_addr.clone();
    match ramflux_node_core::environment::choice(
        FEDERATION_MESH_RUNTIME_ENV,
        ramflux_node_core::environment::var(FEDERATION_MESH_RUNTIME_ENV).ok().as_deref(),
        &["compio", "tokio", "quinn"],
        "tokio",
    ) {
        "compio" => {
            #[cfg(all(target_os = "linux", feature = "compio-mesh"))]
            {
                std::thread::spawn(move || {
                    if let Err(error) = serve_mesh_compio_quic(&quic_addr, &quic_context, &quic_tls)
                    {
                        quic_context.observability.mark_quic_listener_error(&error.to_string());
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
        _ => {
            ramflux_node_core::spawn_service_worker(
                "ramflux-federation-mesh-quic",
                move |shutdown| {
                    if let Err(error) =
                        serve_mesh_quic(&quic_addr, &quic_context, &quic_tls, shutdown)
                    {
                        quic_context.observability.mark_quic_listener_error(&error.to_string());
                        tracing::error!(%error, "federation mesh QUIC listener stopped");
                    }
                },
            )?;
        }
    }
    Ok(())
}

pub(crate) fn serve_mesh_quic(
    listen_addr: &str,
    context: &MeshServerContext,
    tls: &ramflux_transport::MeshTlsConfig,
    shutdown: tokio_util::sync::CancellationToken,
) -> Result<(), ramflux_node_core::NodeCoreError> {
    let roots_state = Arc::clone(&context.state);
    let root_pems_provider = std::sync::Arc::new(move || {
        let state = roots_state
            .snapshot()
            .map_err(|error| ramflux_transport::TransportError::Http(error.to_string()))?;
        Ok(state.pinned_peer_ca_cert_pems())
    });
    let mut builder = tokio::runtime::Builder::new_current_thread();
    let _threads = ramflux_node_core::track_service_runtime(&mut builder);
    let runtime = builder
        .enable_all()
        .build()
        .map_err(|source| ramflux_node_core::NodeCoreError::ItestHttp(source.to_string()))?;
    let result = runtime.block_on(async move {
        let server = ramflux_transport::MeshQuicServer::bind_with_pem_roots_provider(
            listen_addr,
            tls,
            root_pems_provider,
        )
        .map_err(|error| mesh_transport_error(&error))?;
        let local_addr = server.local_addr().map_err(|error| mesh_transport_error(&error))?;
        context.observability.mark_quic_listener_ready(local_addr.to_string());
        tracing::info!(addr = %local_addr, "federation mesh QUIC surface listening");
        loop {
            let connection = match tokio::select! {
                () = shutdown.cancelled() => break,
                connection = server.accept_connection() => connection,
            } {
                Ok(connection) => connection,
                Err(error) => {
                    context.observability.mark_quic_listener_error(&error.to_string());
                    tracing::error!(%error, "federation mesh QUIC connection rejected");
                    continue;
                }
            };
            let context = context.clone();
            tokio::spawn(async move {
                if let Err(error) = handle_mesh_quic_connection(connection, context).await {
                    tracing::warn!(%error, "federation mesh QUIC connection failed");
                }
            });
        }
        Ok::<(), ramflux_node_core::NodeCoreError>(())
    });
    ramflux_node_core::drain_service_runtime(runtime);
    result
}

#[cfg(all(target_os = "linux", feature = "compio-mesh"))]
pub(crate) fn serve_mesh_compio_quic(
    listen_addr: &str,
    context: &MeshServerContext,
    tls: &ramflux_transport::MeshTlsConfig,
) -> Result<(), ramflux_node_core::NodeCoreError> {
    let roots_state = Arc::clone(&context.state);
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
        context.observability.mark_quic_listener_ready(local_addr.to_string());
        tracing::info!(addr = %local_addr, "federation mesh compio QUIC surface listening");
        loop {
            let connection = match server.accept_connection().await {
                Ok(connection) => connection,
                Err(error) => {
                    context.observability.mark_quic_listener_error(&error.to_string());
                    tracing::error!(%error, "federation mesh compio QUIC connection rejected");
                    continue;
                }
            };
            let context = context.clone();
            compio::runtime::spawn(async move {
                if let Err(error) = handle_mesh_compio_quic_connection(connection, &context).await {
                    tracing::warn!(%error, "federation mesh compio QUIC connection failed");
                }
            })
            .detach();
        }
    })
}

pub(crate) fn serve_mesh_mtls(
    server: &ramflux_transport::MeshTlsServer,
    context: &MeshServerContext,
    tls: &ramflux_transport::MeshTlsConfig,
) {
    let connections =
        ramflux_node_core::ConnectionSet::new(ramflux_node_core::DEFAULT_CONNECTION_LIMIT);
    let mut backoff = ramflux_node_core::ListenerAcceptBackoff::default();
    tracing::info!("federation mesh mTLS surface listening");
    while !ramflux_node_core::service_shutdown_token().is_cancelled() {
        let socket = match server.accept_tcp_stream() {
            Ok(socket) => socket,
            Err(ramflux_transport::TransportError::Io(error))
                if error.kind() == std::io::ErrorKind::WouldBlock =>
            {
                std::thread::sleep(std::time::Duration::from_millis(25));
                continue;
            }
            Err(error) => {
                let error = match error {
                    ramflux_transport::TransportError::Io(error) => error,
                    other => std::io::Error::other(other.to_string()),
                };
                backoff.wait_after_failure(&error);
                continue;
            }
        };
        match connections.spawn(
            socket,
            (context.clone(), tls.clone()),
            |socket, context, connection| {
                let (context, tls) = context;
                let accepted = (|| {
                    let roots = context
                        .state
                        .snapshot()
                        .map_err(|error| {
                            ramflux_transport::TransportError::Http(error.to_string())
                        })?
                        .pinned_peer_ca_cert_pems();
                    ramflux_transport::authenticate_tcp_stream_with_pem_roots(socket, tls, &roots)
                })();
                let accepted = match accepted {
                    Ok(accepted) => accepted,
                    Err(error) => {
                        tracing::debug!(%error, "federation mesh TLS handshake ended");
                        return;
                    }
                };
                let peer_service_id = accepted
                    .peer_spiffe_uri
                    .as_deref()
                    .and_then(|uri| ramflux_node_core::parse_mesh_spiffe_uri(uri).ok())
                    .map(|peer| peer.service_id);
                let mut stream = accepted.stream;
                while !ramflux_node_core::service_shutdown_token().is_cancelled() {
                    match handle_mesh_request(
                        &mut stream,
                        context,
                        peer_service_id.as_deref(),
                        accepted.peer_spiffe_uri.as_deref(),
                        connection,
                    ) {
                        Ok(true) => {}
                        Ok(false) => break,
                        Err(error) => {
                            if !ramflux_node_core::service_shutdown_token().is_cancelled() {
                                let _ = ramflux_transport::write_mesh_text_response(
                                    &mut stream,
                                    "500 Internal Server Error",
                                    &error.to_string(),
                                );
                            }
                            tracing::debug!(%error, "federation mesh connection ended");
                            break;
                        }
                    }
                }
                let _ = ramflux_transport::close_mesh_server_stream(&mut stream);
            },
        ) {
            Ok(_) => backoff.success(),
            Err(error) => std::thread::sleep(backoff.resource_failure(&error)),
        }
    }
}

/// The body cap for a request, decided from its path before any body byte is read. The
/// attachment renewal route is bounded at 16 KiB; everything else keeps the migration frame cap.
pub(crate) fn mesh_body_cap(_method: &str, path: &str) -> usize {
    if path == crate::attachment_renewal::PEER_PATH {
        crate::attachment_renewal::MAX_BODY
    } else {
        ramflux_protocol::home_migration::MAX_FRAME_BYTES
    }
}

pub(crate) fn handle_mesh_request(
    stream: &mut ramflux_transport::MeshTlsServerStream,
    context: &MeshServerContext,
    peer_service_id: Option<&str>,
    peer_spiffe_uri: Option<&str>,
    connection: &ramflux_node_core::ConnectionGuard,
) -> Result<bool, ramflux_node_core::NodeCoreError> {
    let received = std::time::Instant::now();
    let _deadline = migration_request_deadline(stream, context, received)?;
    let Some(request) =
        ramflux_transport::read_bounded_mesh_http_request_by_path(stream, &mesh_body_cap)
            .map_err(|error| mesh_transport_error(&error))?
    else {
        return Ok(false);
    };
    let Some(_request) = connection.begin_request() else {
        let _ = ramflux_transport::write_mesh_text_response(
            stream,
            "503 Service Unavailable",
            "shutting down",
        );
        return Ok(false);
    };
    #[cfg(feature = "itest-http")]
    ramflux_node_core::shutdown_request_test_delay();
    if refuse_retention_peer(stream, peer_service_id, &request.path)? {
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
        ("GET", FEDERATION_TRUST_SNAPSHOT_PATH) => {
            let envelope = federation_trust_snapshot_envelope()?;
            ramflux_transport::write_mesh_json_response(stream, "200 OK", &envelope)
                .map_err(|error| mesh_transport_error(&error))?;
        }
        ("POST", ramflux_node_core::MIGRATION_PEER_PATH) => {
            handle_migration_peer_request(
                stream,
                context,
                peer_service_id,
                &request.body,
                received,
            )?;
        }
        ("POST", crate::attachment_renewal::PEER_PATH) => {
            serve_attachment_peer(stream, context, peer_spiffe_uri, &request.body, received)?;
        }
        ("POST", "/s8/federation/envelope") => {
            context.observability.record_inbound_s8_envelope(MeshInboundTransport::Tcp);
            handle_s8_inbound_envelope_request(stream, peer_service_id, &request.body, context)?;
        }
        ("POST", RETENTION_GC_SWEEP_PATH) => {
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
            if sweep.owner_service != "federation" {
                return Err(ramflux_node_core::NodeCoreError::Unauthorized(
                    "retention owner mismatch".into(),
                ));
            }
            ramflux_transport::write_mesh_json_response(
                stream,
                "200 OK",
                &sweep.response(
                    u64::try_from(
                        context
                            .store
                            .sweep_delivery_retention(sweep.effective_now(), sweep.dry_run)?,
                    )
                    .unwrap_or(u64::MAX),
                ),
            )
            .map_err(|error| mesh_transport_error(&error))?;
        }
        _ => {
            ramflux_transport::write_mesh_text_response(stream, "404 Not Found", "not found")
                .map_err(|error| mesh_transport_error(&error))?;
        }
    }
    Ok(true)
}

struct MeshQuicRequestContext<'a> {
    state: &'a crate::SharedFederationTrustState,
    store: &'a ramflux_node_core::FederationRedbStore,
    router: &'a RouterMeshClient,
    discovery: &'a FederationDiscoverySurface,
    observability: &'a SharedMeshObservability,
    inbound_transport: MeshInboundTransport,
}

fn handle_s8_inbound_envelope_request(
    stream: &mut ramflux_transport::MeshTlsServerStream,
    peer_service_id: Option<&str>,
    body_bytes: &[u8],
    context: &MeshServerContext,
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
        match ramflux_protocol::parse_i_json(body_bytes) {
            Ok(request) => request,
            Err(source) => {
                tracing::error!(
                    body_len,
                    error = %source,
                    "federation inbound envelope request decode failed"
                );
                ramflux_transport::write_mesh_json_response(
                    stream,
                    "400 Bad Request",
                    &ramflux_protocol::i_json_rejection_body(),
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
        context.state.as_ref(),
        context.store.as_ref(),
        context.router.as_ref(),
        &context.discovery,
        Some(context.observability.as_ref()),
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
            if matches!(error, ramflux_node_core::NodeCoreError::Capacity { .. }) {
                ramflux_transport::write_mesh_json_response(
                    stream,
                    "429 Too Many Requests",
                    &inbound_failure_response(&error).body,
                )
                .map_err(|error| mesh_transport_error(&error))?;
            } else {
                ramflux_transport::write_mesh_text_response(
                    stream,
                    "500 Internal Server Error",
                    &body,
                )
                .map_err(|error| mesh_transport_error(&error))?;
            }
        }
    }
    Ok(())
}

async fn handle_mesh_quic_connection(
    connection: ramflux_transport::MeshQuicConnection,
    context: MeshServerContext,
) -> Result<(), ramflux_node_core::NodeCoreError> {
    let remote_address = connection.remote_address();
    let peer_service_id = mesh_peer_service_id(connection.peer_spiffe_uri());
    tracing::debug!(
        %remote_address,
        peer_service_id = peer_service_id.as_deref().unwrap_or("<unknown>"),
        "federation mesh QUIC connection stream loop started"
    );
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
        let context = context.clone();
        let request_peer_service_id = peer_service_id.clone();
        tokio::spawn(async move {
            if let Err(error) =
                handle_mesh_quic_request(accepted, request_peer_service_id.as_deref(), &context)
                    .await
            {
                tracing::warn!(%remote_address, %error, "federation mesh QUIC request failed");
            }
        });
    }
}

async fn handle_mesh_quic_request(
    accepted: ramflux_transport::MeshQuicAcceptedRequest,
    peer_service_id: Option<&str>,
    context: &MeshServerContext,
) -> Result<(), ramflux_node_core::NodeCoreError> {
    let Some(_request) = ramflux_node_core::begin_service_request() else {
        return Ok(());
    };
    let response = handle_federation_mesh_quic_request(
        &accepted.request,
        peer_service_id,
        &MeshQuicRequestContext {
            state: context.state.as_ref(),
            store: context.store.as_ref(),
            router: context.router.as_ref(),
            discovery: &context.discovery,
            observability: &context.observability,
            inbound_transport: MeshInboundTransport::Quic,
        },
    )?;
    if (200..300).contains(&response.status)
        || response.body["reason_code"] == "capacity"
        || response.body["reason_code"] == "i_json_rejected"
    {
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
    context: &MeshServerContext,
) -> Result<(), ramflux_node_core::NodeCoreError> {
    let remote_address = connection.remote_address();
    let peer_service_id = mesh_peer_service_id(connection.peer_spiffe_uri());
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
        handle_mesh_compio_quic_request(accepted, peer_service_id.as_deref(), context).await?;
    }
}

#[cfg(all(target_os = "linux", feature = "compio-mesh"))]
async fn handle_mesh_compio_quic_request(
    accepted: ramflux_transport::CompioMeshQuicAcceptedRequest,
    peer_service_id: Option<&str>,
    context: &MeshServerContext,
) -> Result<(), ramflux_node_core::NodeCoreError> {
    let response = handle_federation_mesh_quic_request(
        &accepted.request,
        peer_service_id,
        &MeshQuicRequestContext {
            state: context.state.as_ref(),
            store: context.store.as_ref(),
            router: context.router.as_ref(),
            discovery: &context.discovery,
            observability: &context.observability,
            inbound_transport: MeshInboundTransport::Quic,
        },
    )?;
    if (200..300).contains(&response.status)
        || response.body["reason_code"] == "capacity"
        || response.body["reason_code"] == "i_json_rejected"
    {
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
    if peer_service_id == Some("ramflux-retention") && request.path != RETENTION_GC_SWEEP_PATH {
        return Ok(text_quic_response(403, "retention peer is only authorized for gc_sweep"));
    }
    match (request.method.as_str(), request.path.as_str()) {
        ("GET", "/healthz") => Ok(ramflux_transport::GatewayQuicResponse {
            status: 200,
            body: serde_json::json!({
                "service": "ramflux-federation",
                "status": "ok"
            }),
        }),
        ("GET", FEDERATION_TRUST_SNAPSHOT_PATH) => Ok(ramflux_transport::GatewayQuicResponse {
            status: 200,
            body: serde_json::to_value(federation_trust_snapshot_envelope()?).map_err(
                |source| ramflux_node_core::NodeCoreError::ItestJson(source.to_string()),
            )?,
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
                context.store,
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
                Err(error) => Ok(inbound_failure_response(&error)),
            }
        }
        ("POST", RETENTION_GC_SWEEP_PATH) => {
            if peer_service_id != Some("ramflux-retention") {
                return Ok(text_quic_response(403, "gc_sweep requires ramflux-retention peer"));
            }
            let sweep: ramflux_node_core::RetentionGcSweepRequest =
                serde_json::from_value(request.body.clone()).map_err(|source| {
                    ramflux_node_core::NodeCoreError::ItestJson(source.to_string())
                })?;
            if sweep.owner_service != "federation" {
                return Ok(text_quic_response(400, "retention owner mismatch"));
            }
            Ok(ramflux_transport::GatewayQuicResponse {
                status: 200,
                body: serde_json::to_value(
                    sweep.response(
                        u64::try_from(
                            context
                                .store
                                .sweep_delivery_retention(sweep.effective_now(), sweep.dry_run)?,
                        )
                        .unwrap_or(u64::MAX),
                    ),
                )
                .map_err(|source| {
                    ramflux_node_core::NodeCoreError::ItestJson(source.to_string())
                })?,
            })
        }
        _ => Ok(text_quic_response(404, "not found")),
    }
}

fn mesh_peer_service_id(peer_spiffe_uri: Option<&str>) -> Option<String> {
    peer_spiffe_uri
        .and_then(|spiffe_uri| ramflux_node_core::parse_mesh_spiffe_uri(spiffe_uri).ok())
        .map(|peer| peer.service_id)
}

fn inbound_failure_response(
    error: &ramflux_node_core::NodeCoreError,
) -> ramflux_transport::GatewayQuicResponse {
    match error {
        ramflux_node_core::NodeCoreError::Capacity { resource } => {
            ramflux_transport::GatewayQuicResponse {
                status: 429,
                body: serde_json::json!({"error":"capacity","reason_code":"capacity","resource":resource}),
            }
        }
        other => text_quic_response(500, &other.to_string()),
    }
}
fn text_quic_response(status: u16, body: &str) -> ramflux_transport::GatewayQuicResponse {
    ramflux_transport::GatewayQuicResponse { status, body: serde_json::json!({ "error": body }) }
}

fn response_error_text(body: &serde_json::Value) -> &str {
    body.get("error").and_then(serde_json::Value::as_str).unwrap_or("mesh request failed")
}

/// The retention peer may only call `gc_sweep`; anything else is refused here.
fn refuse_retention_peer(
    stream: &mut ramflux_transport::MeshTlsServerStream,
    peer_service_id: Option<&str>,
    path: &str,
) -> Result<bool, ramflux_node_core::NodeCoreError> {
    if peer_service_id != Some("ramflux-retention") || path == RETENTION_GC_SWEEP_PATH {
        return Ok(false);
    }
    ramflux_transport::write_mesh_text_response(
        stream,
        "403 Forbidden",
        "retention peer is only authorized for gc_sweep",
    )
    .map_err(|error| mesh_transport_error(&error))?;
    Ok(true)
}

fn serve_attachment_peer(
    stream: &mut ramflux_transport::MeshTlsServerStream,
    context: &MeshServerContext,
    peer_spiffe_uri: Option<&str>,
    body: &[u8],
    received: std::time::Instant,
) -> Result<(), ramflux_node_core::NodeCoreError> {
    // The listener's socket deadline is tightened to the originating budget once the
    // envelope names it, so a late read, forward or write is cut off at that deadline.
    let guard = std::cell::RefCell::new(None);
    let tighten = |deadline: std::time::Instant| {
        ramflux_transport::mesh_request_deadline(stream, deadline)
            .map(|g| *guard.borrow_mut() = Some(g))
            .map_err(|_| ramflux_node_core::attachment::RenewalRefusal::Busy)
    };
    let server = crate::attachment_renewal::PeerServer {
        state: &context.state,
        router: &context.router,
        discovery: &context.discovery,
    };
    let reply =
        crate::attachment_renewal::serve_peer(&server, peer_spiffe_uri, body, received, &tighten);
    if reply.status == "200 OK" {
        let value: serde_json::Value =
            serde_json::from_slice(&reply.body).unwrap_or(serde_json::Value::Null);
        ramflux_transport::write_mesh_json_response(stream, reply.status, &value)
    } else {
        ramflux_transport::write_mesh_text_response(
            stream,
            reply.status,
            &String::from_utf8_lossy(&reply.body),
        )
    }
    .map_err(|error| mesh_transport_error(&error))
}

fn handle_migration_peer_request(
    stream: &mut ramflux_transport::MeshTlsServerStream,
    context: &MeshServerContext,
    peer_service_id: Option<&str>,
    body: &[u8],
    received: std::time::Instant,
) -> Result<(), ramflux_node_core::NodeCoreError> {
    if peer_service_id != Some("ramflux-federation") {
        ramflux_transport::write_mesh_text_response(
            stream,
            "403 Forbidden",
            "migration peer requires federation identity",
        )
        .map_err(|error| mesh_transport_error(&error))?;
        return Ok(());
    }
    let envelope = ramflux_protocol::home_migration::decode(
        body,
        ramflux_protocol::home_migration::MAX_FRAME_BYTES,
    )
    .map_err(|_| {
        ramflux_node_core::NodeCoreError::ItestHttp("invalid migration peer frame".into())
    })?;
    let reply = crate::home_migration::inbound(
        envelope,
        &context.state,
        &context.router,
        &context.discovery,
        received,
    )?;
    ramflux_transport::write_mesh_json_response(stream, "200 OK", &reply)
        .map_err(|error| mesh_transport_error(&error))?;
    Ok(())
}

fn migration_request_deadline(
    stream: &ramflux_transport::MeshTlsServerStream,
    context: &MeshServerContext,
    received: std::time::Instant,
) -> Result<Option<ramflux_transport::MeshRequestDeadline>, ramflux_node_core::NodeCoreError> {
    Ok(
        if context
            .discovery
            .node_capabilities
            .iter()
            .any(|cap| cap == ramflux_node_core::HOME_MIGRATION_CAPABILITY)
            || context.discovery.attachment_authority.is_some()
        {
            Some(
                ramflux_transport::mesh_request_deadline(
                    stream,
                    received + std::time::Duration::from_secs(10),
                )
                .map_err(|error| mesh_transport_error(&error))?,
            )
        } else {
            None
        },
    )
}

#[cfg(test)]
pub(crate) mod tests {
    use crate::test_certificates::{issue_test_ca, issue_test_service_cert, temp_cert_root};
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
    use std::sync::mpsc;

    use super::*;

    struct QuicServerDone {
        stop: Option<tokio::sync::oneshot::Sender<()>>,
        done: mpsc::Receiver<Result<(), String>>,
        worker: Option<std::thread::JoinHandle<()>>,
        store_path: ramflux_test_support::TestPath,
    }

    impl QuicServerDone {
        fn finish(&mut self) -> Result<(), Box<dyn std::error::Error>> {
            let Some(worker) = self.worker.as_ref() else { return Ok(()) };
            if let Some(stop) = self.stop.take() {
                let _sent = stop.send(());
            }
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
            let result = self.done.recv_timeout(std::time::Duration::from_secs(10))?;
            while !worker.is_finished() {
                if std::time::Instant::now() >= deadline {
                    return Err(test_error("QUIC fixture worker did not stop within its deadline"));
                }
                std::thread::yield_now();
            }
            if let Some(worker) = self.worker.take() {
                worker.join().map_err(|_| test_error("QUIC fixture worker panicked"))?;
            }
            result.map_err(test_error)
        }
    }

    impl Drop for QuicServerDone {
        fn drop(&mut self) {
            let _stopped = self.finish();
        }
    }

    #[test]
    fn federation_quic_dispatcher_authorizes_retention_gc_sweep()
    -> Result<(), Box<dyn std::error::Error>> {
        let context = TestMeshContext::new("federation_quic_dispatcher_authorizes_retention")?;
        let request = gc_sweep_quic_request("federation");

        let accepted = context.handle_quic_request(&request, Some("ramflux-retention"))?;
        assert_eq!(accepted.status, 200);
        let response: ramflux_node_core::RetentionGcSweepResponse =
            serde_json::from_value(accepted.body)?;
        assert_eq!(response.owner_service, "federation");
        assert!(response.accepted);

        let rejected = context.handle_quic_request(&request, Some("ramflux-gateway"))?;
        assert_eq!(rejected.status, 403);
        assert_eq!(rejected.body["error"], "gc_sweep requires ramflux-retention peer");

        let envelope = ramflux_transport::GatewayQuicRequest {
            method: "POST".to_owned(),
            path: "/s8/federation/envelope".to_owned(),
            body: serde_json::json!({}),
        };
        let retention_blocked =
            context.handle_quic_request(&envelope, Some("ramflux-retention"))?;
        assert_eq!(retention_blocked.status, 403);
        assert_eq!(
            retention_blocked.body["error"],
            "retention peer is only authorized for gc_sweep"
        );
        Ok(())
    }

    #[test]
    fn federation_ijson_ingress_refuses_unsafe_integer() -> Result<(), Box<dyn std::error::Error>> {
        const EXPECTED_BODY: &[u8] =
            br#"{"error":"i_json_rejected","reason_code":"i_json_rejected"}"#;
        let root = temp_cert_root("federation-ijson-mesh-http")?;
        let (server_tls, client_tls, ca_pem) = issue_rsa_mesh_certificates(&root)?;

        for (created_at, duplicate, rejected) in [
            (9_007_199_254_740_991, true, true),
            (9_007_199_254_740_992, false, true),
            (9_007_199_254_740_991, false, false),
        ] {
            let server = ramflux_transport::MeshTlsServer::bind("127.0.0.1:0", &server_tls)?;
            let endpoint = server.local_addr()?.to_string();
            let (store_path, mut context) = test_mesh_server_context("federation-ijson-mesh-http")?;
            let router_listener = std::net::TcpListener::bind("127.0.0.1:0")?;
            router_listener.set_nonblocking(true)?;
            Arc::make_mut(&mut context.router).endpoint = router_listener.local_addr()?.to_string();
            let store = Arc::clone(&context.store);
            let pending_before = store.list_pending_outbound(100)?;
            let roots = vec![ca_pem.clone()];
            let accepted_server_tls = server_tls.clone();
            let worker = std::thread::spawn(move || -> Result<(), String> {
                let mut stream = server
                    .accept_authenticated_with_pem_roots(&accepted_server_tls, &roots)
                    .map_err(|error| error.to_string())?
                    .stream;
                let request = ramflux_transport::read_mesh_http_request(&mut stream)
                    .map_err(|error| error.to_string())?
                    .ok_or_else(|| "missing mesh request".to_owned())?;
                if request.path != "/s8/federation/envelope" {
                    return Err(format!("unexpected mesh path {}", request.path));
                }
                handle_s8_inbound_envelope_request(&mut stream, None, &request.body, &context)
                    .map_err(|error| error.to_string())
            });

            let (status, body) = ramflux_transport::mesh_http_post_status_body(
                &endpoint,
                "/s8/federation/envelope",
                &client_tls,
                "ramflux-federation",
                &RawForward { created_at, duplicate_ext: duplicate },
            )?;
            worker.join().map_err(|_| "mesh HTTP worker panicked")??;
            if rejected {
                assert_eq!(status, 400);
                assert_eq!(body, EXPECTED_BODY);
            } else {
                assert_eq!(status, 500);
                assert_ne!(body, EXPECTED_BODY);
            }
            assert_eq!(store.list_pending_outbound(100)?, pending_before);
            assert!(matches!(
                router_listener.accept(),
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock
            ));
            drop(store);
            cleanup_store(&store_path);
        }

        Ok(())
    }

    const SIGNED_FORWARD_ADMISSION_NOW: i64 = 1_760_000_020;

    pub(crate) fn admitted_forward_source(
        source_seed: [u8; 32],
    ) -> Result<ramflux_node_core::FederationTrustState, Box<dyn std::error::Error>> {
        use ramflux_node_core::test_support::federation_fixtures::{
            federation_route_with_key, signed_federation_handshake, test_federation_ca_pem,
        };
        let source_public_key = ramflux_crypto::public_key_base64url_from_seed(source_seed);
        let mut route = federation_route_with_key(
            "node-b",
            &source_public_key,
            "node-b-federation:7443",
            ramflux_node_core::FederationTrustStatus::Invited,
        );
        route.expires_at = 4_000_000_000;
        let handshake = signed_federation_handshake("node-b", "node-a", source_seed)?;
        let mut invitation = ramflux_node_core::FederationNodeInvitation {
            invitation_id: "inv_node_b_to_a".to_owned(),
            inviter_node_id: "node-a".to_owned(),
            candidate_node_id: "node-b".to_owned(),
            candidate_node_public_key_hash: route.node_public_key_hash.clone(),
            candidate_node_public_key: source_public_key,
            candidate_node_ca_cert_pem: test_federation_ca_pem(),
            allowed_capabilities: vec!["opaque_delivery".to_owned(), "federation_relay".to_owned()],
            expires_at: 4_000_000_000,
            signature: String::new(),
        };
        invitation.signature =
            ramflux_crypto::sign_protocol_object_with_seed(&invitation, source_seed)?;
        let mut state = ramflux_node_core::FederationTrustState::new();
        state.admit_handshake(ramflux_node_core::FederationHandshakeAdmissionRequest {
            route,
            handshake,
            invitation: Some(invitation),
            local_capabilities: vec!["opaque_delivery".to_owned(), "federation_relay".to_owned()],
            local_protocol_versions: vec!["v1".to_owned()],
            local_transport_backends: vec!["quic_quinn".to_owned()],
            now: SIGNED_FORWARD_ADMISSION_NOW,
        })?;
        Ok(state)
    }

    /// Builds a fully root-bound, genuinely signed forward from node-b to node-a whose envelope
    /// ext carries `x_probe`. The signature covers the canonical object, so a raw duplicate of
    /// that member is authenticated identically under lenient decoding.
    pub(crate) fn signed_forward_for_mesh(
        source_seed: [u8; 32],
    ) -> Result<ramflux_node_core::FederatedEnvelopeForwardRequest, Box<dyn std::error::Error>>
    {
        signed_forward_for_mesh_at(source_seed, unix_now_seconds()?)
    }

    pub(crate) fn signed_forward_for_mesh_at(
        source_seed: [u8; 32],
        created_at: i64,
    ) -> Result<ramflux_node_core::FederatedEnvelopeForwardRequest, Box<dyn std::error::Error>>
    {
        use ramflux_node_core::test_support::federation_fixtures::root_bound_forward;
        let root = ramflux_crypto::create_identity_root("alice", [0x91; 32]);
        let mut forward = root_bound_forward(&root, "device", None, "ijson-signed-forward")?;
        forward.source_node_id = "node-b".to_owned();
        forward.target_node_id = "node-a".to_owned();
        forward.envelope.created_at = created_at;
        forward.envelope.ext.ext.insert("x_probe".to_owned(), serde_json::json!("v"));
        forward.envelope.signed.signature = ramflux_crypto::sign_canonical_bytes(
            &ramflux_protocol::envelope_sender_signed_bytes(&forward.envelope)?,
        );
        ramflux_node_core::sign_federated_envelope_forward(&mut forward, source_seed)?;
        Ok(forward)
    }

    pub(crate) fn unix_now_seconds() -> Result<i64, Box<dyn std::error::Error>> {
        Ok(i64::try_from(
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs(),
        )?)
    }

    /// Duplicates the single `x_probe` member at the raw byte level; the object stays identical.
    pub(crate) fn duplicate_x_probe_member(
        body: &str,
    ) -> Result<String, Box<dyn std::error::Error>> {
        const NEEDLE: &str = "\"x_probe\":\"v\"";
        if body.matches(NEEDLE).count() != 1 {
            return Err(test_error("expected exactly one x_probe member in signed forward"));
        }
        Ok(body.replacen(NEEDLE, "\"x_probe\":\"v\",\"x_probe\":\"v\"", 1))
    }

    struct CountingRouter {
        endpoint: String,
        calls: Arc<std::sync::atomic::AtomicUsize>,
        stop: Arc<std::sync::atomic::AtomicBool>,
        worker: std::thread::JoinHandle<()>,
    }

    impl CountingRouter {
        /// Serves `/mvp0/envelope` over mesh TLS with an `online` outcome and counts each request
        /// that completes the TLS handshake and HTTP read.
        fn spawn(
            router_tls: &ramflux_transport::MeshTlsConfig,
            federation_ca_pem: &str,
        ) -> Result<Self, Box<dyn std::error::Error>> {
            let server = ramflux_transport::MeshTlsServer::bind("127.0.0.1:0", router_tls)?;
            let endpoint = server.local_addr()?.to_string();
            let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let roots = vec![federation_ca_pem.to_owned()];
            let tls = router_tls.clone();
            let worker_calls = Arc::clone(&calls);
            let worker_stop = Arc::clone(&stop);
            let worker = std::thread::spawn(move || {
                while !worker_stop.load(std::sync::atomic::Ordering::SeqCst) {
                    let Ok(accepted) = server.accept_authenticated_with_pem_roots(&tls, &roots)
                    else {
                        continue;
                    };
                    let mut stream = accepted.stream;
                    if let Ok(Some(_request)) =
                        ramflux_transport::read_mesh_http_request(&mut stream)
                    {
                        worker_calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        let _ = ramflux_transport::write_mesh_json_response(
                            &mut stream,
                            "200 OK",
                            &serde_json::json!({
                                "migration_refusal": null,
                                "outcome": "online",
                                "target_delivery_id": "peer",
                                "inbox_seq": null,
                                "cursor": null,
                                "nack": null
                            }),
                        );
                    }
                }
            });
            Ok(Self { endpoint, calls, stop, worker })
        }

        fn finish(self) -> Result<usize, Box<dyn std::error::Error>> {
            self.stop.store(true, std::sync::atomic::Ordering::SeqCst);
            // Wake the blocking accept so the worker observes the stop flag.
            let _wake = std::net::TcpStream::connect(&self.endpoint);
            self.worker.join().map_err(|_| test_error("counting router worker panicked"))?;
            Ok(self.calls.load(std::sync::atomic::Ordering::SeqCst))
        }
    }

    #[test]
    fn federation_ijson_ingress_refuses_unsafe_integer_signed_forward()
    -> Result<(), Box<dyn std::error::Error>> {
        const EXPECTED_BODY: &[u8] =
            br#"{"error":"i_json_rejected","reason_code":"i_json_rejected"}"#;
        let root = temp_cert_root("federation-ijson-signed-forward")?;
        let (server_tls, router_tls, ca_pem) = issue_rsa_mesh_certificates(&root)?;
        let source_seed = [0x5b; 32];
        let valid_text = serde_json::to_string(&signed_forward_for_mesh(source_seed)?)?;
        let mutated_text = duplicate_x_probe_member(&valid_text)?;

        for (text, accepted) in [(mutated_text, false), (valid_text, true)] {
            let (store_path, mut context) =
                test_mesh_server_context("federation-ijson-signed-forward")?;
            context.state = Arc::new(crate::SharedFederationTrustState::new(
                admitted_forward_source(source_seed)?,
            ));
            let router = CountingRouter::spawn(&router_tls, &ca_pem)?;
            context.router = Arc::new(RouterMeshClient {
                endpoint: router.endpoint.clone(),
                server_name: "ramflux-router".to_owned(),
                tls: server_tls.clone(),
                client: ramflux_transport::MeshHttpClient::new(),
                async_mesh: None,
            });
            let store = Arc::clone(&context.store);
            let pending_before = store.list_pending_outbound(100)?;
            let seen_before = store.inbound_forward_seen_count()?;

            let server = ramflux_transport::MeshTlsServer::bind("127.0.0.1:0", &server_tls)?;
            let endpoint = server.local_addr()?.to_string();
            let roots = vec![ca_pem.clone()];
            let accepted_server_tls = server_tls.clone();
            let worker = std::thread::spawn(move || -> Result<(), String> {
                let mut stream = server
                    .accept_authenticated_with_pem_roots(&accepted_server_tls, &roots)
                    .map_err(|error| error.to_string())?
                    .stream;
                let request = ramflux_transport::read_mesh_http_request(&mut stream)
                    .map_err(|error| error.to_string())?
                    .ok_or_else(|| "missing mesh request".to_owned())?;
                handle_s8_inbound_envelope_request(&mut stream, None, &request.body, &context)
                    .map_err(|error| error.to_string())
            });
            let raw = serde_json::value::RawValue::from_string(text)?;
            let (status, body) = ramflux_transport::mesh_http_post_status_body(
                &endpoint,
                "/s8/federation/envelope",
                &router_tls,
                "ramflux-federation",
                &raw,
            )?;
            worker.join().map_err(|_| "mesh HTTP worker panicked")??;
            let router_calls = router.finish()?;
            let seen_after = store.inbound_forward_seen_count()?;

            if accepted {
                assert_eq!(status, 200, "control body: {}", String::from_utf8_lossy(&body));
                let response: ramflux_node_core::FederatedEnvelopeForwardResponse =
                    serde_json::from_slice(&body)?;
                assert!(response.accepted);
                assert_eq!(router_calls, 1);
                assert_eq!(seen_after, seen_before + 1);
            } else {
                assert_eq!(status, 400);
                assert_eq!(body, EXPECTED_BODY);
                assert_eq!(router_calls, 0);
                assert_eq!(seen_after, seen_before);
            }
            assert_eq!(store.list_pending_outbound(100)?, pending_before);
            drop(store);
            cleanup_store(&store_path);
        }

        Ok(())
    }

    #[cfg(all(target_os = "linux", feature = "compio-mesh"))]
    fn spawn_compio_federation_listener(
        context: MeshServerContext,
        tls: ramflux_transport::MeshTlsConfig,
        ca_pem: String,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let (addr_tx, addr_rx) = mpsc::channel::<Result<String, String>>();
        std::thread::Builder::new().name("federation-compio-ijson-test".into()).spawn(
            move || {
                let error_tx = addr_tx.clone();
                let outcome = (|| -> Result<(), String> {
                    let reactor = compio::runtime::Runtime::new().map_err(|e| e.to_string())?;
                    reactor.block_on(async move {
                        let roots = Arc::new(move || Ok(vec![ca_pem.clone()]));
                        let server =
                            ramflux_transport::CompioMeshQuicServer::bind_with_pem_roots_provider(
                                "127.0.0.1:0",
                                &tls,
                                roots,
                            )
                            .await
                            .map_err(|error| error.to_string())?;
                        let local = server.local_addr().map_err(|error| error.to_string())?;
                        let _sent = addr_tx.send(Ok(local.to_string()));
                        loop {
                            let connection = server
                                .accept_connection()
                                .await
                                .map_err(|error| error.to_string())?;
                            let context = context.clone();
                            compio::runtime::spawn(async move {
                                let _ =
                                    handle_mesh_compio_quic_connection(connection, &context).await;
                            })
                            .detach();
                        }
                    })
                })();
                if let Err(error) = outcome {
                    let _sent = error_tx.send(Err(error));
                }
            },
        )?;
        addr_rx
            .recv_timeout(std::time::Duration::from_secs(10))
            .map_err(|_| test_error("compio federation listener did not bind"))?
            .map_err(test_error)
    }

    #[cfg(all(target_os = "linux", feature = "compio-mesh"))]
    fn compio_quic_frame(path: &str, body: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let path = serde_json::to_string(path)?;
        Ok(format!(r#"{{"method":"POST","path":{path},"body":{body}}}"#).into_bytes())
    }

    #[cfg(all(target_os = "linux", feature = "compio-mesh"))]
    #[test]
    fn federation_ijson_ingress_refuses_unsafe_integer_compio_quic()
    -> Result<(), Box<dyn std::error::Error>> {
        const REFUSAL_FRAME: &[u8] =
            br#"{"status":400,"body":{"error":"i_json_rejected","reason_code":"i_json_rejected"}}"#;
        let root = temp_cert_root("federation-ijson-compio-quic")?;
        let (server_tls, router_tls, ca_pem) = issue_rsa_mesh_certificates(&root)?;
        let source_seed = [0x5c; 32];
        let valid_text = serde_json::to_string(&signed_forward_for_mesh(source_seed)?)?;
        let duplicate_text = duplicate_x_probe_member(&valid_text)?;
        let created_at_marker = "\"created_at\":";
        if valid_text.matches(created_at_marker).count() != 1 {
            return Err(test_error("expected exactly one created_at member"));
        }
        let value_start = valid_text
            .find(created_at_marker)
            .ok_or_else(|| test_error("missing created_at member"))?
            + created_at_marker.len();
        let value_len = valid_text[value_start..]
            .find([',', '}'])
            .ok_or_else(|| test_error("unterminated created_at value"))?;
        let unsafe_created_at = format!(
            "{}9007199254740992{}",
            &valid_text[..value_start],
            &valid_text[value_start + value_len..]
        );
        let upper_bound_text = serde_json::to_string(&signed_forward_for_mesh_at(
            source_seed,
            9_007_199_254_740_991,
        )?)?;
        let rows = [
            ("duplicate", duplicate_text.as_str(), Expected::IJsonRefusal),
            ("unsafe_integer", unsafe_created_at.as_str(), Expected::IJsonRefusal),
            ("upper_bound", upper_bound_text.as_str(), Expected::ReachedHandler),
            ("control", valid_text.as_str(), Expected::Accepted),
        ];
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;

        for (label, text, expected) in rows {
            let (store_path, mut context) =
                test_mesh_server_context("federation-ijson-compio-quic")?;
            context.state = Arc::new(crate::SharedFederationTrustState::new(
                admitted_forward_source(source_seed)?,
            ));
            let router = CountingRouter::spawn(&router_tls, &ca_pem)?;
            context.router = Arc::new(RouterMeshClient {
                endpoint: router.endpoint.clone(),
                server_name: "ramflux-router".to_owned(),
                tls: server_tls.clone(),
                client: ramflux_transport::MeshHttpClient::new(),
                async_mesh: None,
            });
            let store = Arc::clone(&context.store);
            let pending_before = store.list_pending_outbound(100)?;
            let seen_before = store.inbound_forward_seen_count()?;
            let endpoint =
                spawn_compio_federation_listener(context, server_tls.clone(), ca_pem.clone())?;
            let frame = compio_quic_frame("/s8/federation/envelope", text)?;
            let response =
                runtime.block_on(ramflux_transport::mesh_quic_exchange_raw_response_frame(
                    &endpoint,
                    &router_tls,
                    "ramflux-federation",
                    std::slice::from_ref(&ca_pem),
                    &frame,
                    std::time::Instant::now() + std::time::Duration::from_secs(10),
                ))?;
            let router_calls = router.finish()?;
            let seen_after = store.inbound_forward_seen_count()?;

            match expected {
                Expected::Accepted => {
                    let parsed: ramflux_transport::GatewayQuicResponse =
                        serde_json::from_slice(&response)?;
                    assert_eq!(parsed.status, 200, "{label} control: {parsed:?}");
                    assert!(parsed.body["accepted"].as_bool().unwrap_or(false), "{label} control");
                    assert_eq!(router_calls, 1, "{label} router calls");
                    assert_eq!(seen_after, seen_before + 1, "{label} seen rows");
                    assert_eq!(store.list_pending_outbound(100)?, pending_before, "{label} spool");
                }
                Expected::IJsonRefusal => {
                    assert_eq!(response, REFUSAL_FRAME, "{label} exact D3 refusal frame");
                    assert_eq!(router_calls, 0, "{label} router calls");
                    assert_eq!(seen_after, seen_before, "{label} seen rows");
                    assert_eq!(store.list_pending_outbound(100)?, pending_before, "{label} spool");
                }
                Expected::ReachedHandler => {
                    let parsed: ramflux_transport::GatewayQuicResponse =
                        serde_json::from_slice(&response)?;
                    assert_ne!(
                        parsed.body["reason_code"], "i_json_rejected",
                        "{label} must pass the strict decoder"
                    );
                }
            }
            drop(store);
            cleanup_store(&store_path);
        }

        std::fs::remove_dir_all(root)?;
        Ok(())
    }

    #[cfg(all(target_os = "linux", feature = "compio-mesh"))]
    #[derive(Clone, Copy)]
    enum Expected {
        IJsonRefusal,
        ReachedHandler,
        Accepted,
    }

    fn issue_rsa_mesh_certificates(
        root: &Path,
    ) -> Result<
        (ramflux_transport::MeshTlsConfig, ramflux_transport::MeshTlsConfig, String),
        Box<dyn std::error::Error>,
    > {
        use std::process::Command;

        let ca_key = root.join("mesh-ca-key.pem");
        let ca_cert = root.join("mesh-ca.pem");
        let ca_config = root.join("mesh-ca.cnf");
        std::fs::write(
            &ca_config,
            "[req]\nprompt=no\ndistinguished_name=dn\nx509_extensions=v3_ca\n[dn]\nCN=Ramflux I-JSON Test CA\n[v3_ca]\nbasicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n",
        )?;
        let ca_status = Command::new("openssl")
            .args([
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-keyout",
                ca_key.to_str().ok_or("invalid CA key path")?,
                "-out",
                ca_cert.to_str().ok_or("invalid CA cert path")?,
                "-days",
                "2",
                "-config",
                ca_config.to_str().ok_or("invalid CA config path")?,
            ])
            .status()?;
        if !ca_status.success() {
            return Err(format!("OpenSSL CA generation failed: {ca_status}").into());
        }

        let issue_service = |name: &str,
                             service: &str|
         -> Result<
            ramflux_transport::MeshTlsConfig,
            Box<dyn std::error::Error>,
        > {
            let service_dir = root.join(name);
            std::fs::create_dir_all(&service_dir)?;
            let key = service_dir.join("service-key.pem");
            let csr = service_dir.join("service.csr");
            let cert = service_dir.join("service.pem");
            let extensions = service_dir.join("service.ext");
            let key_path = key.to_str().ok_or("invalid service key path")?;
            let csr_path = csr.to_str().ok_or("invalid service CSR path")?;
            let cert_path = cert.to_str().ok_or("invalid service cert path")?;
            let subject = format!("/CN={service}");
            let status = Command::new("openssl")
                .args([
                    "req", "-new", "-newkey", "rsa:2048", "-nodes", "-keyout", key_path, "-out",
                    csr_path, "-subj", &subject,
                ])
                .status()?;
            if !status.success() {
                return Err(format!("OpenSSL service key generation failed: {status}").into());
            }
            std::fs::write(
                &extensions,
                format!(
                    "subjectAltName = DNS:localhost, DNS:{service}, URI:spiffe://{name}/{service}\nextendedKeyUsage = serverAuth, clientAuth\nkeyUsage = digitalSignature, keyEncipherment\n"
                ),
            )?;
            let status = Command::new("openssl")
                .args([
                    "x509",
                    "-req",
                    "-in",
                    csr_path,
                    "-CA",
                    ca_cert.to_str().ok_or("invalid CA cert path")?,
                    "-CAkey",
                    ca_key.to_str().ok_or("invalid CA key path")?,
                    "-CAcreateserial",
                    "-out",
                    cert_path,
                    "-days",
                    "2",
                    "-extfile",
                    extensions.to_str().ok_or("invalid extension path")?,
                ])
                .status()?;
            if !status.success() {
                return Err(format!("OpenSSL service certificate signing failed: {status}").into());
            }
            Ok(ramflux_transport::MeshTlsConfig {
                ca_cert: ca_cert.clone(),
                service_cert: cert,
                service_key: key,
            })
        };

        Ok((
            issue_service("node-a", "ramflux-federation")?,
            issue_service("node-b", "ramflux-router")?,
            std::fs::read_to_string(ca_cert)?,
        ))
    }

    #[test]
    fn federation_quic_peer_service_id_comes_from_spiffe_uri() {
        assert_eq!(
            mesh_peer_service_id(Some("spiffe://node-a/ramflux-retention")).as_deref(),
            Some("ramflux-retention")
        );
        assert_eq!(
            mesh_peer_service_id(Some("spiffe://node-a/ramflux-gateway")).as_deref(),
            Some("ramflux-gateway")
        );
        assert_eq!(
            mesh_peer_service_id(Some("spiffe://node-a/ramflux-gateway/gw-a")).as_deref(),
            Some("ramflux-gateway")
        );
        assert!(mesh_peer_service_id(None).is_none());
        assert!(mesh_peer_service_id(Some("not-spiffe")).is_none());
    }

    #[test]
    fn federation_tokio_quic_connection_uses_real_peer_identity()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = temp_cert_root("federation_tokio_quic_connection_uses_real_peer_identity")?;
        let ca = issue_test_ca(&root)?;
        let retention = issue_test_service_cert(&ca, "node-a", "ramflux-retention")?;
        let federation = issue_test_service_cert(&ca, "node-a", "ramflux-federation")?;
        let (endpoint, mut server_done) =
            spawn_federation_gc_quic_server(federation.tls.clone(), retention.ca_pem.clone())?;
        let request = ramflux_node_core::RetentionGcSweepRequest {
            owner_service: "federation".to_owned(),
            sweep_id: "retention_gc:federation:1".to_owned(),
            now: 1,
            dry_run: false,
        };

        let response: ramflux_node_core::RetentionGcSweepResponse =
            ramflux_transport::mesh_quic_post_json_with_peer_ca_pems(
                &endpoint,
                RETENTION_GC_SWEEP_PATH,
                &retention.tls,
                "ramflux-federation",
                &[federation.ca_pem],
                &request,
            )?;

        assert_eq!(response.owner_service, "federation");
        let directory =
            server_done.store_path.parent().ok_or("test: no store directory")?.to_path_buf();
        server_done.finish()?;
        drop(server_done);
        assert!(!directory.exists(), "joined QUIC fixture must release its store directory");
        Ok(())
    }

    #[test]
    fn federation_quic_fixture_drop_stops_idle_listener_and_cleans_store()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = temp_cert_root("quic-fixture-drop")?;
        let ca = issue_test_ca(&root)?;
        let retention = issue_test_service_cert(&ca, "node-a", "ramflux-retention")?;
        let federation = issue_test_service_cert(&ca, "node-a", "ramflux-federation")?;
        let (_, server_done) = spawn_federation_gc_quic_server(federation.tls, retention.ca_pem)?;
        let directory =
            server_done.store_path.parent().ok_or("test: no store directory")?.to_path_buf();
        drop(server_done);
        assert!(
            !directory.exists(),
            "Drop must cancel an idle QUIC listener before removing its store"
        );
        Ok(())
    }

    fn gc_sweep_quic_request(owner_service: &str) -> ramflux_transport::GatewayQuicRequest {
        ramflux_transport::GatewayQuicRequest {
            method: "POST".to_owned(),
            path: RETENTION_GC_SWEEP_PATH.to_owned(),
            body: serde_json::to_value(ramflux_node_core::RetentionGcSweepRequest {
                owner_service: owner_service.to_owned(),
                sweep_id: format!("retention_gc:{owner_service}:1"),
                now: 1,
                dry_run: false,
            })
            .unwrap_or_else(|error| serde_json::json!({ "error": error.to_string() })),
        }
    }

    struct RawForward {
        created_at: i64,
        duplicate_ext: bool,
    }

    impl serde::Serialize for RawForward {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            use serde::ser::SerializeMap;
            let mut map = serializer.serialize_map(Some(8))?;
            map.serialize_entry("source_node_id", "node-b")?;
            map.serialize_entry("target_node_id", "node-a")?;
            map.serialize_entry("delivery_class", "opaque_event")?;
            map.serialize_entry("required_capability", "opaque_delivery")?;
            map.serialize_entry("signing_key_id", "node-b")?;
            map.serialize_entry("signature_alg", "ed25519")?;
            map.serialize_entry("signature", "sig")?;
            map.serialize_entry(
                "envelope",
                &RawEnvelope { created_at: self.created_at, duplicate_ext: self.duplicate_ext },
            )?;
            map.end()
        }
    }

    struct RawEnvelope {
        created_at: i64,
        duplicate_ext: bool,
    }

    impl serde::Serialize for RawEnvelope {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            use serde::ser::SerializeMap;
            let mut map = serializer.serialize_map(Some(19))?;
            map.serialize_entry("schema", "ramflux.envelope.v1")?;
            map.serialize_entry("version", &1)?;
            map.serialize_entry("domain", "ramflux.envelope.v1")?;
            map.serialize_entry("ext", &RawExt { duplicate: self.duplicate_ext })?;
            map.serialize_entry("signing_key_id", "device")?;
            map.serialize_entry("signature_alg", "ed25519")?;
            map.serialize_entry("signature", "sig")?;
            map.serialize_entry("envelope_id", "federated-forward")?;
            map.serialize_entry("source_principal_id", "alice")?;
            map.serialize_entry("source_device_id", "phone")?;
            map.serialize_entry("target_delivery_id", "peer")?;
            map.serialize_entry("routing_set_id", &Option::<String>::None)?;
            map.serialize_entry("delivery_class", "opaque_event")?;
            map.serialize_entry("priority", "normal")?;
            map.serialize_entry("ttl", &3600)?;
            map.serialize_entry("created_at", &self.created_at)?;
            map.serialize_entry("encrypted_payload", "opaque")?;
            map.serialize_entry("payload_hash", "hash")?;
            map.end()
        }
    }

    struct RawExt {
        duplicate: bool,
    }

    impl serde::Serialize for RawExt {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            use serde::ser::SerializeMap;
            let mut map = serializer.serialize_map(Some(if self.duplicate { 2 } else { 1 }))?;
            map.serialize_entry("x_probe", "v")?;
            if self.duplicate {
                map.serialize_entry("x_probe", "v")?;
            }
            map.end()
        }
    }

    struct TestMeshContext {
        state: crate::SharedFederationTrustState,
        store: ramflux_node_core::FederationRedbStore,
        router: RouterMeshClient,
        discovery: FederationDiscoverySurface,
        observability: SharedMeshObservability,
        _store_path: ramflux_test_support::TestPath,
    }

    impl TestMeshContext {
        fn new(test_name: &str) -> Result<Self, Box<dyn std::error::Error>> {
            let store_path = temp_path(test_name)?;
            let store = ramflux_node_core::FederationRedbStore::open(&store_path)?;
            let state = crate::SharedFederationTrustState::new(
                ramflux_node_core::FederationTrustState::new(),
            );
            let tls = ramflux_transport::MeshTlsConfig {
                ca_cert: PathBuf::from("ca.pem"),
                service_cert: PathBuf::from("federation.pem"),
                service_key: PathBuf::from("federation-key.pem"),
            };
            Ok(Self {
                state,
                store,
                router: RouterMeshClient {
                    endpoint: "127.0.0.1:1".to_owned(),
                    server_name: "ramflux-router".to_owned(),
                    tls,
                    client: ramflux_transport::MeshHttpClient::new(),
                    async_mesh: None,
                },
                discovery: FederationDiscoverySurface {
                    node_id: "node-a".to_owned(),
                    public_endpoint: "ramflux-federation:7443".to_owned(),
                    node_public_key: "node-public-key".to_owned(),
                    node_ca_cert_pem: "node-ca".to_owned(),
                    node_signing_seed: [7; 32],
                    protocol_versions: vec!["s8".to_owned()],
                    transport_backends: vec!["quic".to_owned()],
                    node_capabilities: vec!["mesh".to_owned()],
                    attachment_authority: None,
                },
                observability: Arc::new(crate::FederationMeshObservability::default()),
                _store_path: store_path,
            })
        }

        fn handle_quic_request(
            &self,
            request: &ramflux_transport::GatewayQuicRequest,
            peer_service_id: Option<&str>,
        ) -> Result<ramflux_transport::GatewayQuicResponse, ramflux_node_core::NodeCoreError>
        {
            let context = MeshQuicRequestContext {
                state: &self.state,
                store: &self.store,
                router: &self.router,
                discovery: &self.discovery,
                observability: &self.observability,
                inbound_transport: MeshInboundTransport::Quic,
            };
            handle_federation_mesh_quic_request(request, peer_service_id, &context)
        }
    }

    fn spawn_federation_gc_quic_server(
        server_tls: ramflux_transport::MeshTlsConfig,
        trusted_retention_ca: String,
    ) -> Result<(String, QuicServerDone), Box<dyn std::error::Error>> {
        let (endpoint_tx, endpoint_rx) = mpsc::sync_channel::<Result<String, String>>(1);
        let (done_tx, done_rx) = mpsc::sync_channel::<Result<(), String>>(1);
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let (store_path, context) = test_mesh_server_context("federation_tokio_quic_server")?;
        let worker_root = store_path.clone();
        let worker = std::thread::Builder::new().name("federation-test-quic".into()).spawn(move || {
            let result: Result<(), String> = (|| {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|source| source.to_string())?;
                runtime.block_on(async move {
                    let roots = Arc::new(move || Ok(vec![trusted_retention_ca.clone()]));
                    let server = ramflux_transport::MeshQuicServer::bind_with_pem_roots_provider(
                        "127.0.0.1:0", &server_tls, roots,
                    ).map_err(|source| source.to_string())?;
                    endpoint_tx.send(server.local_addr().map(|addr| addr.to_string()).map_err(|source| source.to_string()))
                        .map_err(|source| source.to_string())?;
                    tokio::select! {
                        result = async {
                            let connection = server.accept_connection().await.map_err(|source| source.to_string())?;
                            handle_mesh_quic_connection(connection, context).await.map_err(|source| source.to_string())
                        } => result,
                        _ = stopped => Ok(()),
                    }
                })
            })();
            // The runtime and all request tasks have stopped before the last worker owner drops.
            drop(worker_root);
            let _sent = done_tx.send(result);
        })?;
        let server_done =
            QuicServerDone { stop: Some(stop), done: done_rx, worker: Some(worker), store_path };
        let endpoint =
            endpoint_rx.recv_timeout(std::time::Duration::from_secs(10))?.map_err(test_error)?;
        Ok((endpoint, server_done))
    }

    fn test_mesh_server_context(
        test_name: &str,
    ) -> Result<(ramflux_test_support::TestPath, MeshServerContext), Box<dyn std::error::Error>>
    {
        let store_path = temp_path(test_name)?;
        let store = Arc::new(ramflux_node_core::FederationRedbStore::open(&store_path)?);
        let tls = ramflux_transport::MeshTlsConfig {
            ca_cert: PathBuf::from("ca.pem"),
            service_cert: PathBuf::from("federation.pem"),
            service_key: PathBuf::from("federation-key.pem"),
        };
        let context = MeshServerContext {
            state: Arc::new(crate::SharedFederationTrustState::new(
                ramflux_node_core::FederationTrustState::new(),
            )),
            store,
            router: Arc::new(RouterMeshClient {
                endpoint: "127.0.0.1:1".to_owned(),
                server_name: "ramflux-router".to_owned(),
                tls,
                client: ramflux_transport::MeshHttpClient::new(),
                async_mesh: None,
            }),
            observability: Arc::new(crate::FederationMeshObservability::default()),
            discovery: FederationDiscoverySurface {
                node_id: "node-a".to_owned(),
                public_endpoint: "ramflux-federation:7443".to_owned(),
                node_public_key: "node-public-key".to_owned(),
                node_ca_cert_pem: "node-ca".to_owned(),
                node_signing_seed: [7; 32],
                protocol_versions: vec!["s8".to_owned()],
                transport_backends: vec!["quic".to_owned()],
                node_capabilities: vec!["mesh".to_owned()],
                attachment_authority: None,
            },
        };
        Ok((store_path, context))
    }

    fn temp_path(
        test_name: &str,
    ) -> Result<ramflux_test_support::TestPath, Box<dyn std::error::Error>> {
        Ok(crate::test_directories::temp_store_path(test_name)?)
    }

    fn cleanup_store(path: &Path) {
        let _removed = crate::test_directories::remove_store_path(path);
    }

    fn test_error(message: impl Into<String>) -> Box<dyn std::error::Error> {
        message.into().into()
    }
}
