// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use std::sync::Arc;
use std::thread;

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
    let path = std::env::var(FEDERATION_TRUST_SNAPSHOT_FILE_ENV).map_err(|_error| {
        ramflux_node_core::NodeCoreError::ItestJson(format!(
            "{FEDERATION_TRUST_SNAPSHOT_FILE_ENV} is not set"
        ))
    })?;
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
    let context = MeshServerContext {
        state: Arc::clone(state),
        store: Arc::clone(store),
        router: Arc::clone(router),
        observability: Arc::clone(observability),
        discovery: discovery.clone(),
    };
    let mesh_context = context.clone();
    let tls = mesh_tls_config(config);
    thread::spawn(move || {
        if let Err(error) = serve_mesh_mtls(&mesh_server, &mesh_context, &tls) {
            tracing::error!(%error, "federation mesh mTLS listener stopped");
        }
    });
    #[cfg(feature = "itest-http")]
    if std::env::var("RAMFLUX_FEDERATION_DISABLE_QUIC_LISTENER").as_deref() == Ok("1") {
        observability.mark_quic_listener_disabled();
        tracing::warn!("federation mesh QUIC listener disabled by itest affordance");
        return Ok(());
    }
    let quic_context = context;
    let quic_tls = mesh_tls_config(config);
    let quic_addr = config.mesh.listen_addr.clone();
    match std::env::var(FEDERATION_MESH_RUNTIME_ENV).as_deref() {
        Ok("compio") => {
            #[cfg(all(target_os = "linux", feature = "compio-mesh"))]
            {
                thread::spawn(move || {
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
        Ok("tokio" | "quinn") | Err(_) => {
            thread::spawn(move || {
                if let Err(error) = serve_mesh_quic(&quic_addr, &quic_context, &quic_tls) {
                    quic_context.observability.mark_quic_listener_error(&error.to_string());
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
        context.observability.mark_quic_listener_ready(local_addr.to_string());
        tracing::info!(addr = %local_addr, "federation mesh QUIC surface listening");
        loop {
            let connection = match server.accept_connection().await {
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
    })
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
) -> Result<(), ramflux_node_core::NodeCoreError> {
    tracing::info!("federation mesh mTLS surface listening");
    loop {
        let accepted = match server.accept_authenticated_with_pem_roots_provider(tls, || {
            let state = context
                .state
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
        let context = context.clone();
        thread::spawn(move || {
            loop {
                match handle_mesh_request(&mut stream, &context, peer_service_id.as_deref()) {
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
    context: &MeshServerContext,
    peer_service_id: Option<&str>,
) -> Result<bool, ramflux_node_core::NodeCoreError> {
    let Some(request) = ramflux_transport::read_mesh_http_request(stream)
        .map_err(|error| mesh_transport_error(&error))?
    else {
        return Ok(false);
    };
    if peer_service_id == Some("ramflux-retention") && request.path != RETENTION_GC_SWEEP_PATH {
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
        ("GET", FEDERATION_TRUST_SNAPSHOT_PATH) => {
            let envelope = federation_trust_snapshot_envelope()?;
            ramflux_transport::write_mesh_json_response(stream, "200 OK", &envelope)
                .map_err(|error| mesh_transport_error(&error))?;
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
            ramflux_transport::write_mesh_text_response(stream, "500 Internal Server Error", &body)
                .map_err(|error| mesh_transport_error(&error))?;
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
                Err(error) => Ok(text_quic_response(500, &error.to_string())),
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
            Ok(ramflux_transport::GatewayQuicResponse {
                status: 200,
                body: serde_json::to_value(sweep.response(0)).map_err(|source| {
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

fn text_quic_response(status: u16, body: &str) -> ramflux_transport::GatewayQuicResponse {
    ramflux_transport::GatewayQuicResponse { status, body: serde_json::json!({ "error": body }) }
}

fn response_error_text(body: &serde_json::Value) -> &str {
    body.get("error").and_then(serde_json::Value::as_str).unwrap_or("mesh request failed")
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::sync::Arc;
    use std::sync::mpsc;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;

    type QuicServerDone = mpsc::Receiver<Result<(), String>>;

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
    fn federation_quic_peer_service_id_comes_from_spiffe_uri() {
        assert_eq!(
            mesh_peer_service_id(Some("spiffe://node-a/ramflux-retention")).as_deref(),
            Some("ramflux-retention")
        );
        assert_eq!(
            mesh_peer_service_id(Some("spiffe://node-a/ramflux-gateway")).as_deref(),
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
        let (endpoint, _server_done) =
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
        std::fs::remove_dir_all(root)?;
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

    struct TestMeshContext {
        store_path: PathBuf,
        state: crate::SharedFederationTrustState,
        store: ramflux_node_core::FederationRedbStore,
        router: RouterMeshClient,
        discovery: FederationDiscoverySurface,
        observability: SharedMeshObservability,
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
                store_path,
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
                },
                observability: Arc::new(crate::FederationMeshObservability::default()),
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

    impl Drop for TestMeshContext {
        fn drop(&mut self) {
            let _removed = std::fs::remove_file(&self.store_path);
            let _removed = std::fs::remove_dir_all(self.store_path.with_extension("redb.wal"));
        }
    }

    fn spawn_federation_gc_quic_server(
        server_tls: ramflux_transport::MeshTlsConfig,
        trusted_retention_ca: String,
    ) -> Result<(String, QuicServerDone), Box<dyn std::error::Error>> {
        let (endpoint_tx, endpoint_rx) = mpsc::channel::<Result<String, String>>();
        let (done_tx, done_rx) = mpsc::channel::<Result<(), String>>();
        std::thread::spawn(move || {
            let result: Result<(), String> = (|| {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|source| source.to_string())?;
                let (context, store_path) =
                    test_mesh_server_context("federation_tokio_quic_server")
                        .map_err(|source| source.to_string())?;
                let result = runtime.block_on(async move {
                    let roots = Arc::new(move || Ok(vec![trusted_retention_ca.clone()]));
                    let server = ramflux_transport::MeshQuicServer::bind_with_pem_roots_provider(
                        "127.0.0.1:0",
                        &server_tls,
                        roots,
                    )
                    .map_err(|source| source.to_string())?;
                    endpoint_tx
                        .send(
                            server
                                .local_addr()
                                .map(|addr| addr.to_string())
                                .map_err(|source| source.to_string()),
                        )
                        .map_err(|source| source.to_string())?;
                    let connection =
                        server.accept_connection().await.map_err(|source| source.to_string())?;
                    handle_mesh_quic_connection(connection, context)
                        .await
                        .map_err(|source| source.to_string())
                });
                cleanup_store(&store_path);
                result
            })();
            let _sent = done_tx.send(result);
        });
        let endpoint = endpoint_rx
            .recv()
            .map_err(|source| test_error(source.to_string()))?
            .map_err(test_error)?;
        Ok((endpoint, done_rx))
    }

    fn test_mesh_server_context(
        test_name: &str,
    ) -> Result<(MeshServerContext, PathBuf), Box<dyn std::error::Error>> {
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
            },
        };
        Ok((context, store_path))
    }

    fn temp_path(test_name: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
        let elapsed = SystemTime::now().duration_since(UNIX_EPOCH)?;
        Ok(std::env::temp_dir().join(format!(
            "ramflux-federation-{test_name}-{}-{}",
            std::process::id(),
            elapsed.as_nanos()
        )))
    }

    fn cleanup_store(path: &Path) {
        let _removed = std::fs::remove_file(path);
        let _removed = std::fs::remove_dir_all(path.with_extension("redb.wal"));
    }

    struct TestCa {
        cert: PathBuf,
        key: PathBuf,
    }

    struct TestPeerCerts {
        tls: ramflux_transport::MeshTlsConfig,
        ca_pem: String,
    }

    fn temp_cert_root(name: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
        let elapsed = SystemTime::now().duration_since(UNIX_EPOCH)?;
        let root = std::env::temp_dir().join(format!(
            "ramflux-federation-certs-{name}-{}-{}",
            std::process::id(),
            elapsed.as_nanos()
        ));
        if root.exists() {
            std::fs::remove_dir_all(&root)?;
        }
        std::fs::create_dir_all(&root)?;
        Ok(root)
    }

    fn issue_test_ca(root: &Path) -> Result<TestCa, Box<dyn std::error::Error>> {
        let ca_key = root.join("ca-key.pem");
        let ca_cert = root.join("ca.pem");
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
            "/CN=Ramflux Federation QUIC Test CA",
        ])?;
        Ok(TestCa { cert: ca_cert, key: ca_key })
    }

    fn issue_test_service_cert(
        ca: &TestCa,
        node_id: &str,
        service_id: &str,
    ) -> Result<TestPeerCerts, Box<dyn std::error::Error>> {
        let service_dir =
            ca.cert.parent().ok_or_else(|| test_error("CA cert has no parent"))?.join(service_id);
        std::fs::create_dir_all(&service_dir)?;
        let service_key = service_dir.join(format!("{service_id}-key.pem"));
        let service_csr = service_dir.join(format!("{service_id}.csr"));
        let service_cert = service_dir.join(format!("{service_id}.pem"));
        let ext = service_dir.join(format!("{service_id}.ext"));
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
            path_str(&ca.cert)?,
            "-CAkey",
            path_str(&ca.key)?,
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
                ca_cert: ca.cert.clone(),
                service_cert,
                service_key,
            },
            ca_pem: std::fs::read_to_string(&ca.cert)?,
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
