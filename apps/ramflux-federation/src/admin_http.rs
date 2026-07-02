// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;

use crate::SharedMeshObservability;
use crate::{
    FederationAdminDiscoverRequest, FederationAdminPeerRequest, FederationAdminPeerResponse,
    FederationDiscoverySurface, RouterMeshClient, S12DiscoveryResolveRequest,
    handle_s8_forward_envelope, handle_s12_discovery_resolve, now_unix_seconds,
};

#[derive(serde::Deserialize)]
struct FederationAdminMeshObservabilityRequest {
    admin_token: String,
}

#[derive(Clone)]
pub(crate) struct FederationAdminHttpContext {
    pub(crate) store: Arc<ramflux_node_core::FederationRedbStore>,
    pub(crate) state: Arc<crate::SharedFederationTrustState>,
    pub(crate) router: Arc<RouterMeshClient>,
    pub(crate) discovery: FederationDiscoverySurface,
    pub(crate) mesh_observability: SharedMeshObservability,
    pub(crate) admin_token: Option<String>,
}

pub(crate) fn serve_admin_http(
    addr: &str,
    context: FederationAdminHttpContext,
) -> Result<(), ramflux_node_core::NodeCoreError> {
    let listener = TcpListener::bind(addr)
        .map_err(|source| ramflux_node_core::NodeCoreError::ItestHttp(source.to_string()))?;
    tracing::info!(addr, "federation production admin HTTP surface listening");
    thread::spawn(move || {
        for stream in listener.incoming() {
            let mut stream = match stream {
                Ok(stream) => stream,
                Err(error) => {
                    tracing::warn!(%error, "federation admin accept failed");
                    continue;
                }
            };
            let context = context.clone();
            thread::spawn(move || {
                if let Err(error) = handle_admin_request(&mut stream, &context) {
                    let body = format!("{error}");
                    if let Err(write_error) = ramflux_node_core::write_itest_text_response(
                        &mut stream,
                        "500 Internal Server Error",
                        &body,
                    ) {
                        tracing::warn!(%write_error, "failed to write federation admin error");
                    }
                }
            });
        }
    });
    Ok(())
}

pub(crate) fn handle_admin_request(
    stream: &mut TcpStream,
    context: &FederationAdminHttpContext,
) -> Result<(), ramflux_node_core::NodeCoreError> {
    let Some(request) = ramflux_node_core::read_itest_http_request(stream)? else {
        return Ok(());
    };
    let state = &context.state;
    let store = context.store.as_ref();
    let router = context.router.as_ref();
    let discovery = &context.discovery;
    let admin_token = context.admin_token.as_deref();
    log_admin_request(&request, discovery);
    match (request.method.as_str(), request.path.as_str()) {
        ("GET", "/healthz") => {
            ramflux_node_core::write_itest_json_response(
                stream,
                "200 OK",
                &serde_json::json!({
                    "service": "ramflux-federation-admin",
                    "status": "ok"
                }),
            )?;
        }
        ("GET", "/.well-known/ramflux/server") => {
            let record = discovery.well_known_record()?;
            log_admin_well_known(&record);
            ramflux_node_core::write_itest_json_response(stream, "200 OK", &record)?;
        }
        ("GET", path) if path.starts_with("/mvp1/prekey/") => {
            let response = proxy_router_get_json(router, path)?;
            ramflux_node_core::write_itest_json_response(stream, "200 OK", &response)?;
        }
        ("GET", path) if path.starts_with("/mvp1/device-manifest/") => {
            let response = proxy_router_get_json(router, path)?;
            ramflux_node_core::write_itest_json_response(stream, "200 OK", &response)?;
        }
        ("POST", "/mvp1/prekey/fetch") => {
            let value: serde_json::Value =
                serde_json::from_slice(&request.body).map_err(|source| {
                    ramflux_node_core::NodeCoreError::ItestJson(source.to_string())
                })?;
            let response: serde_json::Value = router
                .client
                .post_json(
                    &router.endpoint,
                    "/mvp1/prekey/fetch",
                    &router.tls,
                    &router.server_name,
                    &value,
                )
                .map_err(|source| {
                    ramflux_node_core::NodeCoreError::ItestHttp(source.to_string())
                })?;
            ramflux_node_core::write_itest_json_response(stream, "200 OK", &response)?;
        }
        ("POST", "/s8/federation/forward") => {
            let request: ramflux_node_core::FederatedEnvelopeForwardRequest =
                serde_json::from_slice(&request.body).map_err(|source| {
                    ramflux_node_core::NodeCoreError::ItestJson(source.to_string())
                })?;
            require_admin_token(admin_token, &request.admin_token)?;
            log_admin_forward_request(&request);
            let response = handle_s8_forward_envelope(&request, state, store, router, discovery)?;
            log_admin_forward_response(&response);
            ramflux_node_core::write_itest_json_response(stream, "200 OK", &response)?;
        }
        ("POST", "/s8/federation/mesh-observability") => {
            handle_admin_mesh_observability_request(stream, &request, context, admin_token)?;
        }
        ("POST", "/admin/federation/peer") => {
            let request: FederationAdminPeerRequest = serde_json::from_slice(&request.body)
                .map_err(|source| {
                    ramflux_node_core::NodeCoreError::ItestJson(source.to_string())
                })?;
            require_admin_token(admin_token, &request.admin_token)?;
            log_admin_peer_request(&request);
            let response = handle_admin_peer(request, state, store, discovery)?;
            log_admin_peer_response(&response);
            ramflux_node_core::write_itest_json_response(stream, "200 OK", &response)?;
        }
        ("POST", "/admin/federation/discover") => {
            let request: FederationAdminDiscoverRequest = serde_json::from_slice(&request.body)
                .map_err(|source| {
                    ramflux_node_core::NodeCoreError::ItestJson(source.to_string())
                })?;
            require_admin_token(admin_token, &request.admin_token)?;
            log_admin_discover_request(&request);
            let response = handle_admin_discover(request, state, store)?;
            log_admin_discover_response(&response);
            ramflux_node_core::write_itest_json_response(stream, "200 OK", &response)?;
        }
        _ => {
            ramflux_node_core::write_itest_text_response(stream, "404 Not Found", "not found")?;
        }
    }
    Ok(())
}

fn proxy_router_get_json(
    router: &RouterMeshClient,
    path: &str,
) -> Result<serde_json::Value, ramflux_node_core::NodeCoreError> {
    router
        .client
        .get_json(&router.endpoint, path, &router.tls, &router.server_name)
        .map_err(|source| ramflux_node_core::NodeCoreError::ItestHttp(source.to_string()))
}

fn handle_admin_mesh_observability_request(
    stream: &mut TcpStream,
    request: &ramflux_node_core::NodeHttpRequest,
    context: &FederationAdminHttpContext,
    admin_token: Option<&str>,
) -> Result<(), ramflux_node_core::NodeCoreError> {
    let request: FederationAdminMeshObservabilityRequest = serde_json::from_slice(&request.body)
        .map_err(|source| ramflux_node_core::NodeCoreError::ItestJson(source.to_string()))?;
    require_admin_token(admin_token, &request.admin_token)?;
    let snapshot = context.mesh_observability.snapshot();
    tracing::info!(
        quic_listener_ready = snapshot.quic_listener_ready,
        quic_listener_local_addr = snapshot.quic_listener_local_addr.as_deref().unwrap_or("<none>"),
        quic_listener_last_error = snapshot.quic_listener_last_error.as_deref().unwrap_or("<none>"),
        tcp_inbound_s8_envelopes = snapshot.tcp_inbound_s8_envelopes,
        quic_inbound_s8_envelopes = snapshot.quic_inbound_s8_envelopes,
        "federation admin mesh observability returned"
    );
    ramflux_node_core::write_itest_json_response(stream, "200 OK", &snapshot)
}

fn log_admin_request(
    request: &ramflux_node_core::NodeHttpRequest,
    discovery: &FederationDiscoverySurface,
) {
    tracing::info!(
        method = %request.method,
        path = %request.path,
        local_node_id = %discovery.node_id,
        "federation admin HTTP request received"
    );
}

fn log_admin_well_known(record: &ramflux_node_core::FederationServerRecord) {
    tracing::info!(
        node_id = %record.node_id,
        endpoint_len = record.node_endpoint.len(),
        node_public_key_len = record.node_public_key.len(),
        ca_len = record.node_ca_cert_pem.len(),
        "federation admin well-known record returned"
    );
}

fn log_admin_forward_request(request: &ramflux_node_core::FederatedEnvelopeForwardRequest) {
    tracing::info!(
        source_node_id = %request.source_node_id,
        target_node_id = %request.target_node_id,
        envelope_id = %request.envelope.envelope_id,
        target_delivery_id = %request.envelope.target_delivery_id,
        "federation admin forward request decoded"
    );
}

fn log_admin_forward_response(response: &ramflux_node_core::FederatedEnvelopeForwardResponse) {
    tracing::info!(
        source_node_id = %response.source_node_id,
        target_node_id = %response.target_node_id,
        outcome = %response.delivery.outcome,
        "federation admin forward returned"
    );
}

fn log_admin_peer_request(request: &FederationAdminPeerRequest) {
    tracing::info!(
        peer_node_id = %request.peer_node_id,
        has_peer_well_known_url = request.peer_well_known_url.is_some(),
        peer_well_known_url_len = request.peer_well_known_url.as_ref().map_or(0, String::len),
        "federation admin peer request decoded"
    );
}

fn log_admin_peer_response(response: &FederationAdminPeerResponse) {
    tracing::info!(
        peer_node_id = %response.discovered.node_id,
        endpoint_len = response.discovered.node_endpoint.len(),
        can_deliver = response.can_deliver,
        accepted = response.admitted.accepted,
        "federation admin peer returned"
    );
}

fn log_admin_discover_request(request: &FederationAdminDiscoverRequest) {
    tracing::info!(
        requested_node_id = %request.discovery.request.node_id,
        has_well_known_url = request.discovery.request.well_known_url.is_some(),
        well_known_url_len = request.discovery.request.well_known_url.as_ref().map_or(0, String::len),
        "federation admin discovery request decoded"
    );
}

fn log_admin_discover_response(response: &ramflux_node_core::FederationDiscoveryResult) {
    tracing::info!(
        node_id = %response.node_id,
        endpoint_len = response.node_endpoint.len(),
        pin_state = ?response.pin_state,
        "federation admin discovery returned"
    );
}

pub(crate) fn handle_admin_discover(
    request: FederationAdminDiscoverRequest,
    state: &crate::SharedFederationTrustState,
    store: &ramflux_node_core::FederationRedbStore,
) -> Result<ramflux_node_core::FederationDiscoveryResult, ramflux_node_core::NodeCoreError> {
    handle_s12_discovery_resolve(request.discovery, state, store)
}

#[allow(clippy::too_many_lines)]
pub(crate) fn handle_admin_peer(
    request: FederationAdminPeerRequest,
    state: &crate::SharedFederationTrustState,
    store: &ramflux_node_core::FederationRedbStore,
    discovery: &FederationDiscoverySurface,
) -> Result<FederationAdminPeerResponse, ramflux_node_core::NodeCoreError> {
    let now = match request.now {
        Some(now) => now,
        None => now_unix_seconds()?,
    };
    let capabilities = if request.capabilities.is_empty() {
        discovery.node_capabilities.clone()
    } else {
        request.capabilities
    };
    let discovery_request = S12DiscoveryResolveRequest {
        request: ramflux_node_core::FederationDiscoveryRequest {
            node_id: request.peer_node_id.clone(),
            now,
            invite_endpoint: request.invite_endpoint.clone(),
            well_known_url: request.peer_well_known_url.clone(),
            dns_srv_records: request.dns_srv_records,
            address_records: request.address_records,
            directory_endpoint: request.directory_endpoint.clone(),
        },
        well_known_record: None,
        rotation: None,
    };
    let discovered = handle_s12_discovery_resolve(discovery_request, state, store)?;
    let node_public_key_hash = ramflux_crypto::blake3_256_base64url(
        ramflux_protocol::domain::FEDERATION_HANDSHAKE,
        discovered.node_public_key.as_bytes(),
    );
    let route = ramflux_node_core::FederationPeerRoute {
        node_id: discovered.node_id.clone(),
        endpoint: discovered.node_endpoint.clone(),
        node_public_key_hash,
        node_capabilities: discovered.node_capabilities.clone(),
        trust_status: ramflux_node_core::FederationTrustStatus::Invited,
        updated_at: now,
        expires_at: discovered.expires_at,
        route_update_proof_hash: ramflux_crypto::blake3_256_base64url(
            ramflux_protocol::domain::FEDERATION_HANDSHAKE,
            format!("{}:{}:{}", discovery.node_id, discovered.node_id, now).as_bytes(),
        ),
    };
    let mut peer_capabilities: Vec<String> = discovered
        .node_capabilities
        .iter()
        .filter(|capability| capabilities.iter().any(|allowed| allowed == *capability))
        .cloned()
        .collect();
    peer_capabilities.sort();
    if peer_capabilities.is_empty() {
        peer_capabilities.push("opaque_delivery".to_owned());
    }
    let admitted = state.update_and_save(store, |state| {
        state.admit_verified_discovered_peer(
            route,
            &peer_capabilities,
            &discovery.node_capabilities,
        )
    })?;
    let can_deliver = {
        let state = state.snapshot()?;
        state.can_deliver_to(&discovered.node_id, now)
    };
    Ok(FederationAdminPeerResponse { discovered, admitted, can_deliver })
}

pub(crate) fn require_admin_token(
    configured: Option<&str>,
    supplied: &str,
) -> Result<(), ramflux_node_core::NodeCoreError> {
    let Some(configured) = configured else {
        return Err(ramflux_node_core::NodeCoreError::ItestHttp(
            "federation admin token is not configured".to_owned(),
        ));
    };
    if configured.is_empty() || !constant_time_eq(supplied.as_bytes(), configured.as_bytes()) {
        return Err(ramflux_node_core::NodeCoreError::ItestHttp(
            "federation admin authentication failed".to_owned(),
        ));
    }
    Ok(())
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter().zip(right.iter()).fold(0_u8, |acc, (left, right)| acc | (left ^ right)) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admin_token_check_requires_configured_constant_time_match() {
        assert!(require_admin_token(Some("admin-secret"), "admin-secret").is_ok());
        assert!(require_admin_token(Some("admin-secret"), "wrong-secret").is_err());
        assert!(require_admin_token(Some("admin-secret"), "").is_err());
        assert!(require_admin_token(Some(""), "admin-secret").is_err());
        assert!(require_admin_token(None, "admin-secret").is_err());
    }
}
