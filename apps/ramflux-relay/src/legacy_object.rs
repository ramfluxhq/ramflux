// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Feature-gated v2 object handlers and mesh mTLS service.

use crate::config::{mesh_tls_config, now_unix_seconds};
#[cfg(feature = "itest-object-v2")]
use crate::retention::{RetentionMeshClient, register_object_relay_ttl};
use std::sync::{Arc, Mutex};
use std::thread;

#[cfg(feature = "itest-object-v2")]
pub(crate) fn serve_relay_mesh_mtls(
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

#[cfg(feature = "itest-object-v2")]
pub(crate) fn handle_mesh_request(
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

#[cfg(feature = "itest-object-v2")]
#[derive(Clone, Copy)]
pub(crate) enum RelayRequestPeer<'a> {
    #[cfg(feature = "itest-http")]
    Itest,
    Mesh {
        peer_service_id: &'a str,
    },
}

#[cfg(feature = "itest-object-v2")]
pub(crate) enum RelayResponseValue {
    Json { status: &'static str, value: serde_json::Value },
    Text { status: &'static str, body: String },
}

#[cfg(feature = "itest-object-v2")]
pub(crate) struct RelayHandlerContext<'a> {
    pub(crate) store: &'a ramflux_node_core::RelayRedbStore,
    pub(crate) state: &'a Mutex<ramflux_node_core::RelayCacheState>,
    pub(crate) config: &'a ramflux_node_core::NodeServiceConfig,
    pub(crate) service_key: &'a [u8],
    pub(crate) retention_client: &'a RetentionMeshClient,
}

#[cfg(feature = "itest-object-v2")]
pub(crate) fn handle_relay_request_value(
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

#[cfg(feature = "itest-object-v2")]
pub(crate) fn write_relay_mesh_response(
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

#[cfg(feature = "itest-object-v2")]
pub(crate) fn handle_object_relay_request(
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
            // Persist-before-publish: the ciphertext is committed to redb (post-fsync) before the
            // metadata is published to the resident index.
            let (entry, _inserted) = ramflux_node_core::relay_store_put_frame(
                context.store,
                context.state,
                frame,
                context.service_key,
                now,
            )
            .map_err(ramflux_node_core::RelayStoreOpError::into_node_core)?;
            register_object_relay_ttl(context.config, context.retention_client, &entry, now)?;
            serde_json::to_value(ramflux_node_core::ObjectRelayPutResponse::from(entry))
                .map_err(|source| ramflux_node_core::NodeCoreError::ItestJson(source.to_string()))
        }
        ("POST", "/relay/v1/object/get_chunk") => {
            let request: ramflux_node_core::ObjectRelayGetRequest = serde_json::from_slice(body)
                .map_err(|source| {
                    ramflux_node_core::NodeCoreError::ItestJson(source.to_string())
                })?;
            let now = now_unix_seconds();
            // Validate + snapshot the resident metadata under the lock, then read the ciphertext
            // through redb (lock released) with a TOCTOU recheck.
            let meta = {
                let state = lock_relay_state(context.state)?;
                state.get_object_chunk(
                    &request.chunk_id,
                    &request.relay_token,
                    &request.object_permission_envelope,
                    context.service_key,
                    now,
                )?
            };
            let chunk = ramflux_node_core::relay_store_read_through(
                context.store,
                context.state,
                &meta,
                now,
            )
            .map_err(ramflux_node_core::RelayStoreOpError::into_node_core)?;
            serde_json::to_value(ramflux_node_core::ObjectRelayGetResponse { chunk })
                .map_err(|source| ramflux_node_core::NodeCoreError::ItestJson(source.to_string()))
        }
        ("POST", "/relay/v1/object/ack") => {
            let ack: ramflux_node_core::ObjectRelayAck =
                serde_json::from_slice(body).map_err(|source| {
                    ramflux_node_core::NodeCoreError::ItestJson(source.to_string())
                })?;
            let now = now_unix_seconds();
            // Plan + reserve are atomic under one lock inside `relay_store_ack`; then persist-before-
            // publish (the updated, payload kept/cleared, row is committed first).
            let service_key = context.service_key;
            let meta = ramflux_node_core::relay_store_ack(context.store, context.state, |state| {
                state.plan_ack(&ack, service_key, now).map_err(Into::into)
            })
            .map_err(ramflux_node_core::RelayStoreOpError::into_node_core)?;
            serde_json::to_value(ramflux_node_core::ObjectRelayAckResponse {
                chunk_id: meta.chunk_id,
                status: meta.status,
                acked_by_count: meta.acked_by.len(),
            })
            .map_err(|source| ramflux_node_core::NodeCoreError::ItestJson(source.to_string()))
        }
        ("POST", "/relay/v1/object/tombstone") => {
            let tombstone: ramflux_node_core::ObjectRelayTombstone = serde_json::from_slice(body)
                .map_err(|source| {
                ramflux_node_core::NodeCoreError::ItestJson(source.to_string())
            })?;
            let now = now_unix_seconds();
            // Plan + reserve are atomic under one lock inside `relay_store_tombstone`; then persist-
            // before-publish (commit the batch, then publish the meta + tombstone).
            let service_key = context.service_key;
            let mutation = ramflux_node_core::relay_store_tombstone(
                context.store,
                context.state,
                move |state| {
                    state
                        .plan_object_tombstone_mutation(tombstone, service_key, now)
                        .map_err(Into::into)
                },
            )
            .map_err(ramflux_node_core::RelayStoreOpError::into_node_core)?;
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

#[cfg(feature = "itest-object-v2")]
pub(crate) fn lock_relay_state(
    state: &Mutex<ramflux_node_core::RelayCacheState>,
) -> Result<
    std::sync::MutexGuard<'_, ramflux_node_core::RelayCacheState>,
    ramflux_node_core::NodeCoreError,
> {
    state.lock().map_err(|source| ramflux_node_core::NodeCoreError::ItestHttp(source.to_string()))
}
