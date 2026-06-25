// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
use std::sync::Arc;

use crate::flow::ensure_receive_target_node;
use crate::{
    FederationDiscoverySurface, RouterMeshClient, S12DiscoveryResolveRequest,
    SharedFederationTrustState, now_unix_seconds,
};
#[cfg(feature = "itest-http")]
use crate::{ItestMvp4CanDeliverResponse, ItestMvp4TrustStatusRequest, SharedMeshObservability};

#[cfg(feature = "itest-http")]
use std::net::{Shutdown, TcpListener, TcpStream};
#[cfg(feature = "itest-http")]
use std::thread;

#[cfg(feature = "itest-http")]
pub(crate) fn serve_itest_http(
    store: &Arc<ramflux_node_core::FederationRedbStore>,
    state: &Arc<SharedFederationTrustState>,
    router: &Arc<RouterMeshClient>,
    discovery: &FederationDiscoverySurface,
    mesh_observability: &SharedMeshObservability,
) -> Result<(), ramflux_node_core::NodeCoreError> {
    let addr = std::env::var("RAMFLUX_ITEST_FEDERATION_HTTP_ADDR")
        .unwrap_or_else(|_| "0.0.0.0:18082".to_owned());
    let listener = TcpListener::bind(&addr)
        .map_err(|source| ramflux_node_core::NodeCoreError::ItestHttp(source.to_string()))?;
    tracing::info!(addr, "federation itest HTTP surface listening");
    for stream in listener.incoming() {
        let stream = match stream {
            Ok(stream) => stream,
            Err(error) => {
                tracing::warn!(%error, "federation itest accept failed");
                continue;
            }
        };
        let state = Arc::clone(state);
        let store = Arc::clone(store);
        let router = Arc::clone(router);
        let discovery = discovery.clone();
        let mesh_observability = Arc::clone(mesh_observability);
        thread::spawn(move || {
            handle_itest_connection(
                stream,
                &state,
                &store,
                &router,
                &discovery,
                &mesh_observability,
            );
        });
    }
    Ok(())
}

#[cfg(feature = "itest-http")]
fn handle_itest_connection(
    mut stream: TcpStream,
    state: &Arc<SharedFederationTrustState>,
    store: &ramflux_node_core::FederationRedbStore,
    router: &RouterMeshClient,
    discovery: &FederationDiscoverySurface,
    mesh_observability: &SharedMeshObservability,
) {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        handle_itest_request(&mut stream, state, store, router, discovery, mesh_observability)
    }));
    match result {
        Ok(Ok(())) => shutdown_itest_stream(&mut stream),
        Ok(Err(error)) => {
            tracing::error!(%error, "federation itest request failed");
            write_itest_500_and_close(&mut stream, &error.to_string());
        }
        Err(payload) => {
            let message = panic_payload_to_string(payload.as_ref());
            tracing::error!(panic = %message, "federation itest request panicked");
            write_itest_500_and_close(&mut stream, &format!("federation itest panic: {message}"));
        }
    }
}

#[cfg(feature = "itest-http")]
fn shutdown_itest_stream(stream: &mut TcpStream) {
    if let Err(error) = stream.shutdown(Shutdown::Both) {
        tracing::debug!(%error, "failed to close federation itest stream");
    }
}

#[cfg(feature = "itest-http")]
fn write_itest_500_and_close(stream: &mut TcpStream, body: &str) {
    if let Err(error) =
        ramflux_node_core::write_itest_text_response(stream, "500 Internal Server Error", body)
    {
        tracing::warn!(%error, "failed to write federation itest error");
    }
    shutdown_itest_stream(stream);
}

#[cfg(feature = "itest-http")]
fn panic_payload_to_string(payload: &(dyn std::any::Any + Send)) -> String {
    if let Some(message) = payload.downcast_ref::<&str>() {
        (*message).to_owned()
    } else if let Some(message) = payload.downcast_ref::<String>() {
        message.clone()
    } else {
        "non-string panic payload".to_owned()
    }
}

#[cfg(feature = "itest-http")]
#[allow(clippy::too_many_lines)]
pub(crate) fn handle_itest_request(
    stream: &mut TcpStream,
    state: &Arc<SharedFederationTrustState>,
    store: &ramflux_node_core::FederationRedbStore,
    router: &RouterMeshClient,
    discovery: &FederationDiscoverySurface,
    mesh_observability: &SharedMeshObservability,
) -> Result<(), ramflux_node_core::NodeCoreError> {
    let Some(request) = ramflux_node_core::read_itest_http_request(stream)? else {
        return Ok(());
    };
    tracing::info!(
        method = %request.method,
        path = %request.path,
        local_node_id = %discovery.node_id,
        "federation itest HTTP request received"
    );
    match (request.method.as_str(), request.path.as_str()) {
        ("GET", "/healthz") => {
            ramflux_node_core::write_itest_json_response(
                stream,
                "200 OK",
                &serde_json::json!({
                    "service": "ramflux-federation",
                    "status": "ok"
                }),
            )?;
        }
        ("GET", "/s8/federation/mesh-observability") => {
            let snapshot = mesh_observability.snapshot();
            tracing::info!(
                quic_listener_ready = snapshot.quic_listener_ready,
                quic_listener_local_addr =
                    snapshot.quic_listener_local_addr.as_deref().unwrap_or("<none>"),
                quic_listener_last_error =
                    snapshot.quic_listener_last_error.as_deref().unwrap_or("<none>"),
                tcp_inbound_s8_envelopes = snapshot.tcp_inbound_s8_envelopes,
                quic_inbound_s8_envelopes = snapshot.quic_inbound_s8_envelopes,
                "federation mesh observability returned"
            );
            ramflux_node_core::write_itest_json_response(stream, "200 OK", &snapshot)?;
        }
        ("GET", "/.well-known/ramflux/server") => {
            let record = discovery.well_known_record()?;
            tracing::info!(
                node_id = %record.node_id,
                endpoint_len = record.node_endpoint.len(),
                node_public_key_len = record.node_public_key.len(),
                ca_len = record.node_ca_cert_pem.len(),
                "federation well-known record returned"
            );
            ramflux_node_core::write_itest_json_response(stream, "200 OK", &record)?;
        }
        ("POST", "/s12/federation/discovery/resolve") => {
            let request: S12DiscoveryResolveRequest = serde_json::from_slice(&request.body)
                .map_err(|source| {
                    ramflux_node_core::NodeCoreError::ItestJson(source.to_string())
                })?;
            tracing::info!(
                requested_node_id = %request.request.node_id,
                has_well_known_url = request.request.well_known_url.is_some(),
                well_known_url_len = request.request.well_known_url.as_ref().map_or(0, String::len),
                has_inline_record = request.well_known_record.is_some(),
                "federation discovery resolve request decoded"
            );
            let response = handle_s12_discovery_resolve(request, state, store)?;
            tracing::info!(
                node_id = %response.node_id,
                endpoint_len = response.node_endpoint.len(),
                pin_state = ?response.pin_state,
                source = ?response.source,
                "federation discovery resolve returned"
            );
            ramflux_node_core::write_itest_json_response(stream, "200 OK", &response)?;
        }
        ("GET", path) if path.starts_with("/s12/federation/discovery/pin/") => {
            let node_id = path.trim_start_matches("/s12/federation/discovery/pin/");
            let pin = {
                let state = state.snapshot()?;
                state.discovery_pin(node_id).cloned()
            };
            tracing::info!(
                node_id,
                present = pin.is_some(),
                pin_state = ?pin.as_ref().map(|pin| pin.state),
                "federation discovery pin returned"
            );
            ramflux_node_core::write_itest_json_response(stream, "200 OK", &pin)?;
        }
        ("POST", "/mvp4/federation/route") => {
            let route: ramflux_node_core::FederationPeerRoute =
                serde_json::from_slice(&request.body).map_err(|source| {
                    ramflux_node_core::NodeCoreError::ItestJson(source.to_string())
                })?;
            tracing::info!(
                peer_node_id = %route.node_id,
                endpoint_len = route.endpoint.len(),
                trust_status = ?route.trust_status,
                "federation route upsert request decoded"
            );
            let response = handle_route_upsert(route, state, store)?;
            tracing::info!(
                peer_node_id = %response.node_id,
                can_deliver = response.can_deliver,
                "federation route upsert returned"
            );
            ramflux_node_core::write_itest_json_response(stream, "200 OK", &response)?;
        }
        ("POST", "/mvp4/federation/trust-status") => {
            let request: ItestMvp4TrustStatusRequest = serde_json::from_slice(&request.body)
                .map_err(|source| {
                    ramflux_node_core::NodeCoreError::ItestJson(source.to_string())
                })?;
            let response = handle_trust_status(request, state, store)?;
            ramflux_node_core::write_itest_json_response(stream, "200 OK", &response)?;
        }
        ("GET", path) if path.starts_with("/mvp4/federation/can-deliver/") => {
            let node_id = path.trim_start_matches("/mvp4/federation/can-deliver/");
            let response = handle_can_deliver(node_id, state)?;
            ramflux_node_core::write_itest_json_response(stream, "200 OK", &response)?;
        }
        ("POST", "/mvp8/federation/handshake") => {
            let request: ramflux_node_core::FederationHandshakeAdmissionRequest =
                serde_json::from_slice(&request.body).map_err(|source| {
                    ramflux_node_core::NodeCoreError::ItestJson(source.to_string())
                })?;
            tracing::info!(
                source_node_id = %request.handshake.source_node_id,
                target_node_id = %request.handshake.target_node_id,
                route_node_id = %request.route.node_id,
                route_endpoint_len = request.route.endpoint.len(),
                has_invitation = request.invitation.is_some(),
                "federation handshake admission request decoded"
            );
            let response = handle_mvp8_handshake(request, state, store)?;
            tracing::info!(
                node_id = %response.node_id,
                accepted = response.accepted,
                trust_status = ?response.trust_status,
                "federation handshake admission returned"
            );
            ramflux_node_core::write_itest_json_response(stream, "200 OK", &response)?;
        }
        ("GET", path) if path.starts_with("/mvp8/federation/capabilities/") => {
            let node_id = path.trim_start_matches("/mvp8/federation/capabilities/");
            let response = handle_mvp8_capabilities(node_id, state)?;
            ramflux_node_core::write_itest_json_response(stream, "200 OK", &response)?;
        }
        ("POST", "/mvp8/federation/friend-request") => {
            let request: ramflux_node_core::FederatedFriendRequestEnvelope =
                serde_json::from_slice(&request.body).map_err(|source| {
                    ramflux_node_core::NodeCoreError::ItestJson(source.to_string())
                })?;
            let response = handle_mvp8_friend_request(&request, state, router)?;
            ramflux_node_core::write_itest_json_response(stream, "200 OK", &response)?;
        }
        ("POST", "/s8/federation/forward") => {
            let body_len = request.body.len();
            tracing::info!(
                body_len,
                local_node_id = %discovery.node_id,
                "federation forward body read; decoding request"
            );
            let request: ramflux_node_core::FederatedEnvelopeForwardRequest =
                match serde_json::from_slice(&request.body) {
                    Ok(request) => request,
                    Err(source) => {
                        tracing::error!(
                            body_len,
                            error = %source,
                            "federation forward request decode failed"
                        );
                        let body = format!("forward decode failed: {source}");
                        tracing::info!(
                            status = "500 Internal Server Error",
                            body_len = body.len(),
                            "federation forward responding"
                        );
                        ramflux_node_core::write_itest_text_response(
                            stream,
                            "500 Internal Server Error",
                            &body,
                        )?;
                        return Ok(());
                    }
                };
            tracing::info!(body_len, "federation forward request decoded ok");
            match handle_s8_forward_envelope(&request, state, store, router, discovery) {
                Ok(response) => {
                    tracing::info!(
                        source_node_id = %request.source_node_id,
                        target_node_id = %request.target_node_id,
                        outcome = %response.delivery.outcome,
                        target_delivery_id = %response.delivery.target_delivery_id,
                        status = "200 OK",
                        "federation forward responding"
                    );
                    ramflux_node_core::write_itest_json_response(stream, "200 OK", &response)?;
                }
                Err(error) => {
                    let body = error.to_string();
                    tracing::info!(
                        source_node_id = %request.source_node_id,
                        target_node_id = %request.target_node_id,
                        error = %body,
                        status = "500 Internal Server Error",
                        body_len = body.len(),
                        "federation forward responding"
                    );
                    ramflux_node_core::write_itest_text_response(
                        stream,
                        "500 Internal Server Error",
                        &body,
                    )?;
                }
            }
        }
        ("POST", "/mvp7/federation/tombstone") => {
            let request: ramflux_node_core::FederatedLifecycleTombstoneRequest =
                serde_json::from_slice(&request.body).map_err(|source| {
                    ramflux_node_core::NodeCoreError::ItestJson(source.to_string())
                })?;
            let response = handle_federated_tombstone(&request, state, store, router)?;
            ramflux_node_core::write_itest_json_response(stream, "200 OK", &response)?;
        }
        ("GET", path) if path.starts_with("/mvp7/federation/tombstone/") => {
            let target_delivery_id = path.trim_start_matches("/mvp7/federation/tombstone/");
            let tombstone = {
                let state = state.snapshot()?;
                state.lifecycle_tombstone(target_delivery_id).cloned()
            };
            ramflux_node_core::write_itest_json_response(stream, "200 OK", &tombstone)?;
        }
        _ => {
            ramflux_node_core::write_itest_text_response(stream, "404 Not Found", "not found")?;
        }
    }
    Ok(())
}

#[cfg(feature = "itest-http")]
pub(crate) fn handle_route_upsert(
    route: ramflux_node_core::FederationPeerRoute,
    state: &SharedFederationTrustState,
    store: &ramflux_node_core::FederationRedbStore,
) -> Result<ItestMvp4CanDeliverResponse, ramflux_node_core::NodeCoreError> {
    let node_id = route.node_id.clone();
    let now = now_unix_seconds()?;
    let can_deliver = state.update_and_save(store, |state| {
        state.upsert_route(route);
        Ok(state.can_deliver_to(&node_id, now))
    })?;
    Ok(ItestMvp4CanDeliverResponse { node_id, can_deliver })
}

#[cfg(feature = "itest-http")]
pub(crate) fn handle_trust_status(
    request: ItestMvp4TrustStatusRequest,
    state: &SharedFederationTrustState,
    store: &ramflux_node_core::FederationRedbStore,
) -> Result<ItestMvp4CanDeliverResponse, ramflux_node_core::NodeCoreError> {
    let now = now_unix_seconds()?;
    let can_deliver = state.update_and_save(store, |state| {
        state.update_trust_status(&request.node_id, request.trust_status, request.updated_at)?;
        Ok(state.can_deliver_to(&request.node_id, now))
    })?;
    Ok(ItestMvp4CanDeliverResponse { node_id: request.node_id, can_deliver })
}

#[cfg(feature = "itest-http")]
pub(crate) fn handle_can_deliver(
    node_id: &str,
    state: &SharedFederationTrustState,
) -> Result<ItestMvp4CanDeliverResponse, ramflux_node_core::NodeCoreError> {
    let now = now_unix_seconds()?;
    let state = state.snapshot()?;
    Ok(ItestMvp4CanDeliverResponse {
        node_id: node_id.to_owned(),
        can_deliver: state.can_deliver_to(node_id, now),
    })
}

#[cfg(feature = "itest-http")]
pub(crate) fn handle_mvp8_handshake(
    request: ramflux_node_core::FederationHandshakeAdmissionRequest,
    state: &SharedFederationTrustState,
    store: &ramflux_node_core::FederationRedbStore,
) -> Result<ramflux_node_core::FederationHandshakeAdmissionResponse, ramflux_node_core::NodeCoreError>
{
    let response = state.update_and_save(store, |state| state.admit_handshake(request))?;
    Ok(response)
}

#[cfg(feature = "itest-http")]
pub(crate) fn handle_mvp8_capabilities(
    node_id: &str,
    state: &SharedFederationTrustState,
) -> Result<Vec<String>, ramflux_node_core::NodeCoreError> {
    let state = state.snapshot()?;
    let mut capabilities: Vec<String> = state
        .negotiated_capabilities(node_id)
        .map(|capabilities| capabilities.iter().cloned().collect())
        .unwrap_or_default();
    capabilities.sort();
    Ok(capabilities)
}

pub(crate) fn handle_s12_discovery_resolve(
    request: S12DiscoveryResolveRequest,
    state: &SharedFederationTrustState,
    store: &ramflux_node_core::FederationRedbStore,
) -> Result<ramflux_node_core::FederationDiscoveryResult, ramflux_node_core::NodeCoreError> {
    let now = now_unix_seconds()?;
    let mut discovery_request = request.request.clone();
    discovery_request.now = now;
    let record = match request.well_known_record {
        Some(record) => Some(record),
        None => match discovery_request.well_known_url.as_deref() {
            Some(url) => {
                tracing::info!(
                    requested_node_id = %discovery_request.node_id,
                    well_known_url_len = url.len(),
                    "federation discovery fetching remote well-known"
                );
                let record = ramflux_node_core::itest_http_get_json(url)?;
                tracing::info!(
                    requested_node_id = %discovery_request.node_id,
                    well_known_url_len = url.len(),
                    "federation discovery fetched remote well-known"
                );
                Some(record)
            }
            None => None,
        },
    };
    let result = state.update_and_save(store, |state| {
        state.resolve_discovery_result(
            &discovery_request,
            record.as_ref(),
            request.rotation.as_ref(),
        )
    })?;
    tracing::info!(
        requested_node_id = %discovery_request.node_id,
        result_node_id = %result.node_id,
        endpoint_len = result.node_endpoint.len(),
        pin_state = ?result.pin_state,
        source = ?result.source,
        "federation discovery resolved and pinned"
    );
    Ok(result)
}
#[cfg(feature = "itest-http")]
pub(crate) fn handle_mvp8_friend_request(
    request: &ramflux_node_core::FederatedFriendRequestEnvelope,
    state: &SharedFederationTrustState,
    router: &RouterMeshClient,
) -> Result<ramflux_node_core::FederatedFriendRequestResponse, ramflux_node_core::NodeCoreError> {
    tracing::info!(
        source_node_id = %request.source_node_id,
        target_node_id = %request.target_node_id,
        envelope_id = %request.envelope.envelope_id,
        target_delivery_id = %request.envelope.target_delivery_id,
        required_capability = %request.required_capability,
        "federated friend request validating trust"
    );
    {
        let now = now_unix_seconds()?;
        let state = state.snapshot()?;
        state.ensure_cross_node_friend_request_allowed(request, now)?;
    }
    tracing::info!(
        source_node_id = %request.source_node_id,
        target_node_id = %request.target_node_id,
        envelope_id = %request.envelope.envelope_id,
        "federated friend request trust accepted; delivering to local router"
    );
    let delivery: ramflux_node_core::ItestMvp0SubmitResponse = router
        .client
        .post_json(
            &router.endpoint,
            "/mvp0/envelope",
            &router.tls,
            &router.server_name,
            &request.envelope,
        )
        .map_err(|source| ramflux_node_core::NodeCoreError::ItestHttp(source.to_string()))?;
    tracing::info!(
        source_node_id = %request.source_node_id,
        target_node_id = %request.target_node_id,
        envelope_id = %request.envelope.envelope_id,
        outcome = %delivery.outcome,
        target_delivery_id = %delivery.target_delivery_id,
        "federated friend request delivered to local router"
    );
    Ok(ramflux_node_core::FederatedFriendRequestResponse {
        accepted: true,
        source_node_id: request.source_node_id.clone(),
        target_node_id: request.target_node_id.clone(),
        delivery,
    })
}

pub(crate) fn handle_s8_forward_envelope(
    request: &ramflux_node_core::FederatedEnvelopeForwardRequest,
    state: &SharedFederationTrustState,
    store: &ramflux_node_core::FederationRedbStore,
    router: &RouterMeshClient,
    discovery: &FederationDiscoverySurface,
) -> Result<ramflux_node_core::FederatedEnvelopeForwardResponse, ramflux_node_core::NodeCoreError> {
    let route_decision = if request.target_node_id == discovery.node_id {
        "local_target_rejected"
    } else {
        "remote_federation_forward"
    };
    tracing::info!(
        local_node_id = %discovery.node_id,
        source_node_id = %request.source_node_id,
        target_node_id = %request.target_node_id,
        envelope_id = %request.envelope.envelope_id,
        target_delivery_id = %request.envelope.target_delivery_id,
        route_decision,
        "evaluating federated envelope route"
    );
    if request.target_node_id == discovery.node_id {
        return Err(ramflux_node_core::NodeCoreError::ItestHttp(format!(
            "federation forward target {} is local node {}",
            request.target_node_id, discovery.node_id
        )));
    }
    let peer = resolve_forward_peer(request, state)?;
    tracing::info!(
        target_node_id = %request.target_node_id,
        peer_federation_endpoint_len = peer.endpoint.len(),
        peer_ca_len = peer.peer_ca_cert_pem.len(),
        "federation forward route and peer CA resolved"
    );
    let mut signed_request = request.clone();
    signed_request.source_node_id.clone_from(&discovery.node_id);
    tracing::info!(
        source_node_id = %signed_request.source_node_id,
        target_node_id = %signed_request.target_node_id,
        "federation forward signing request with local node key"
    );
    ramflux_node_core::sign_federated_envelope_forward(
        &mut signed_request,
        discovery.node_signing_seed,
    )?;
    tracing::info!(
        source_node_id = %signed_request.source_node_id,
        target_node_id = %signed_request.target_node_id,
        signing_key_id = %signed_request.signed.signing_key_id,
        signature_len = signed_request.signed.signature.len(),
        "federation forward request signed"
    );
    match send_signed_forward_to_peer(router, &peer, &signed_request) {
        Ok(response) => Ok(response),
        Err(error) => spool_failed_forward(store, &signed_request, &error),
    }
}

struct ForwardPeer {
    endpoint: String,
    peer_ca_cert_pem: String,
}

fn resolve_forward_peer(
    request: &ramflux_node_core::FederatedEnvelopeForwardRequest,
    state: &SharedFederationTrustState,
) -> Result<ForwardPeer, ramflux_node_core::NodeCoreError> {
    tracing::info!(
        source_node_id = %request.source_node_id,
        target_node_id = %request.target_node_id,
        "federation forward checking route and pinned peer CA"
    );
    tracing::info!(
        source_node_id = %request.source_node_id,
        target_node_id = %request.target_node_id,
        "federation forward taking state snapshot"
    );
    let state = state.snapshot()?;
    tracing::info!(
        source_node_id = %request.source_node_id,
        target_node_id = %request.target_node_id,
        "federation forward validating trust and capability"
    );
    let now = now_unix_seconds()?;
    state.ensure_federated_envelope_allowed(request, &request.target_node_id, now)?;
    tracing::info!(
        source_node_id = %request.source_node_id,
        target_node_id = %request.target_node_id,
        "federation forward trust and capability accepted"
    );
    let route = state.route(&request.target_node_id).ok_or_else(|| {
        ramflux_node_core::NodeCoreError::ItestHttp(format!(
            "missing federation route for {}",
            request.target_node_id
        ))
    })?;
    tracing::info!(
        target_node_id = %request.target_node_id,
        peer_federation_endpoint_len = route.endpoint.len(),
        "federation forward route found"
    );
    let peer_ca_cert_pem =
        state.pinned_peer_ca_cert_pem(&request.target_node_id).ok_or_else(|| {
            ramflux_node_core::NodeCoreError::ItestHttp(format!(
                "missing federation CA pin for {}",
                request.target_node_id
            ))
        })?;
    tracing::info!(
        target_node_id = %request.target_node_id,
        peer_ca_len = peer_ca_cert_pem.len(),
        "federation forward pinned peer CA found"
    );
    Ok(ForwardPeer { endpoint: route.endpoint.clone(), peer_ca_cert_pem })
}

fn send_signed_forward_to_peer(
    router: &RouterMeshClient,
    peer: &ForwardPeer,
    signed_request: &ramflux_node_core::FederatedEnvelopeForwardRequest,
) -> Result<ramflux_node_core::FederatedEnvelopeForwardResponse, ramflux_node_core::NodeCoreError> {
    tracing::info!(
        source_node_id = %signed_request.source_node_id,
        target_node_id = %signed_request.target_node_id,
        peer_endpoint = %peer.endpoint,
        peer_federation_endpoint_len = peer.endpoint.len(),
        path = "/s8/federation/envelope",
        envelope_id = %signed_request.envelope.envelope_id,
        target_delivery_id = %signed_request.envelope.target_delivery_id,
        "forwarding federated envelope to peer federation endpoint"
    );
    let peer_ca_pems = std::slice::from_ref(&peer.peer_ca_cert_pem);
    let force_tcp = std::env::var("RAMFLUX_FEDERATION_FORCE_TCP_MESH").as_deref() == Ok("1");
    let response: ramflux_node_core::FederatedEnvelopeForwardResponse = if force_tcp {
        send_signed_forward_to_peer_over_tcp(router, peer, peer_ca_pems, signed_request)?
    } else {
        match ramflux_transport::mesh_quic_post_json_with_peer_ca_pems(
            &peer.endpoint,
            "/s8/federation/envelope",
            &router.tls,
            "ramflux-federation",
            peer_ca_pems,
            &signed_request,
        ) {
            Ok(response) => response,
            Err(quic_error) => {
                if std::env::var("RAMFLUX_FEDERATION_DISABLE_TCP_FALLBACK").as_deref() == Ok("1") {
                    return Err(ramflux_node_core::NodeCoreError::ItestHttp(
                        quic_error.to_string(),
                    ));
                }
                tracing::warn!(
                    source_node_id = %signed_request.source_node_id,
                    target_node_id = %signed_request.target_node_id,
                    peer_endpoint = %peer.endpoint,
                    error = %quic_error,
                    "federation forward QUIC request failed; falling back to TCP-TLS mesh"
                );
                send_signed_forward_to_peer_over_tcp(router, peer, peer_ca_pems, signed_request)?
            }
        }
    };
    tracing::info!(
        source_node_id = %response.source_node_id,
        target_node_id = %response.target_node_id,
        outcome = %response.delivery.outcome,
        target_delivery_id = %response.delivery.target_delivery_id,
        "federation forward peer response received"
    );
    Ok(response)
}

fn spool_failed_forward(
    store: &ramflux_node_core::FederationRedbStore,
    signed_request: &ramflux_node_core::FederatedEnvelopeForwardRequest,
    send_error: &ramflux_node_core::NodeCoreError,
) -> Result<ramflux_node_core::FederatedEnvelopeForwardResponse, ramflux_node_core::NodeCoreError> {
    let entry = store.spool_outbound_forward(
        &signed_request.target_node_id,
        signed_request,
        now_unix_seconds()?,
        outbound_spool_ttl_seconds(),
    )?;
    tracing::warn!(
        source_node_id = %signed_request.source_node_id,
        target_node_id = %signed_request.target_node_id,
        envelope_id = %signed_request.envelope.envelope_id,
        target_delivery_id = %signed_request.envelope.target_delivery_id,
        spool_seq = entry.seq,
        error = %send_error,
        "federation peer unavailable; persisted outbound forward to spool"
    );
    Ok(ramflux_node_core::FederatedEnvelopeForwardResponse {
        accepted: true,
        source_node_id: signed_request.source_node_id.clone(),
        target_node_id: signed_request.target_node_id.clone(),
        delivery: ramflux_node_core::ItestMvp0SubmitResponse {
            outcome: "federation_spooled_offline_peer".to_owned(),
            target_delivery_id: signed_request.envelope.target_delivery_id.clone(),
            inbox_seq: None,
            cursor: None,
        },
    })
}

fn outbound_spool_ttl_seconds() -> u64 {
    std::env::var("RAMFLUX_FEDERATION_SPOOL_TTL_SECONDS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(7 * 24 * 60 * 60)
}

fn send_signed_forward_to_peer_over_tcp(
    router: &RouterMeshClient,
    peer: &ForwardPeer,
    peer_ca_pems: &[String],
    signed_request: &ramflux_node_core::FederatedEnvelopeForwardRequest,
) -> Result<ramflux_node_core::FederatedEnvelopeForwardResponse, ramflux_node_core::NodeCoreError> {
    router
        .client
        .post_json_with_peer_ca_pems(
            &peer.endpoint,
            "/s8/federation/envelope",
            &router.tls,
            "ramflux-federation",
            peer_ca_pems,
            signed_request,
        )
        .map_err(|source| {
            tracing::error!(
                source_node_id = %signed_request.source_node_id,
                target_node_id = %signed_request.target_node_id,
                peer_endpoint = %peer.endpoint,
                peer_ca_len = peer.peer_ca_cert_pem.len(),
                error = %source,
                "federation forward peer mesh request failed"
            );
            ramflux_node_core::NodeCoreError::ItestHttp(source.to_string())
        })
}

#[allow(dead_code)]
pub(crate) fn handle_s8_receive_envelope(
    request: &ramflux_node_core::FederatedEnvelopeForwardRequest,
    state: &SharedFederationTrustState,
    router: &RouterMeshClient,
    discovery: &FederationDiscoverySurface,
) -> Result<ramflux_node_core::FederatedEnvelopeForwardResponse, ramflux_node_core::NodeCoreError> {
    ensure_receive_target_node(request, &discovery.node_id)?;
    {
        let now = now_unix_seconds()?;
        let state = state.snapshot()?;
        state.ensure_federated_envelope_allowed(request, &request.source_node_id, now)?;
        let pinned_public_key =
            state.pinned_node_public_key(&request.source_node_id).ok_or_else(|| {
                ramflux_node_core::NodeCoreError::ItestHttp(format!(
                    "missing federation pin for {}",
                    request.source_node_id
                ))
            })?;
        ramflux_node_core::verify_federated_envelope_forward(request, &pinned_public_key)?;
        tracing::info!(
            source_node_id = %request.source_node_id,
            target_node_id = %request.target_node_id,
            envelope_id = %request.envelope.envelope_id,
            target_delivery_id = %request.envelope.target_delivery_id,
            "verified federated envelope against pinned source node key"
        );
    }
    tracing::info!(
        source_node_id = request.source_node_id,
        target_node_id = request.target_node_id,
        local_router_endpoint_len = router.endpoint.len(),
        path = "/mvp0/envelope",
        envelope_id = request.envelope.envelope_id,
        target_delivery_id = request.envelope.target_delivery_id,
        "accepted federated envelope proof and delivering to local router"
    );
    let delivery: ramflux_node_core::ItestMvp0SubmitResponse = router
        .client
        .post_json(
            &router.endpoint,
            "/mvp0/envelope",
            &router.tls,
            &router.server_name,
            &request.envelope,
        )
        .map_err(|source| ramflux_node_core::NodeCoreError::ItestHttp(source.to_string()))?;
    tracing::info!(
        source_node_id = %request.source_node_id,
        target_node_id = %request.target_node_id,
        envelope_id = %request.envelope.envelope_id,
        target_delivery_id = %request.envelope.target_delivery_id,
        outcome = %delivery.outcome,
        "delivered inbound federated envelope to local router"
    );
    Ok(ramflux_node_core::FederatedEnvelopeForwardResponse {
        accepted: true,
        source_node_id: request.source_node_id.clone(),
        target_node_id: request.target_node_id.clone(),
        delivery,
    })
}

#[cfg(feature = "itest-http")]
pub(crate) fn handle_federated_tombstone(
    request: &ramflux_node_core::FederatedLifecycleTombstoneRequest,
    state: &SharedFederationTrustState,
    store: &ramflux_node_core::FederationRedbStore,
    router: &RouterMeshClient,
) -> Result<ramflux_node_core::FederatedLifecycleTombstoneResponse, ramflux_node_core::NodeCoreError>
{
    if let Some(tombstone) = request.tombstone.as_ref() {
        ramflux_node_core::verify_lifecycle_tombstone(tombstone)?;
    }
    let response: ramflux_node_core::FederatedLifecycleTombstoneResponse = router
        .client
        .post_json(
            &router.endpoint,
            "/mvp7/federation/tombstone/apply",
            &router.tls,
            &router.server_name,
            &request,
        )
        .map_err(|source| ramflux_node_core::NodeCoreError::ItestHttp(source.to_string()))?;
    state.update_and_save(store, |state| {
        state.record_lifecycle_tombstone(response.clone());
        Ok(())
    })?;
    Ok(response)
}
