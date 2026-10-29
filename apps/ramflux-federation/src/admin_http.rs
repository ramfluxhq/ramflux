// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use crate::http_response::HttpResponse;
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;

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

#[derive(serde::Deserialize)]
struct HomeNodeMigrationForwardLocalRequest {
    #[serde(default)]
    admin_token: String,
    forward: ramflux_node_core::FederatedEnvelopeForwardRequest,
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
    let limits = crate::http_limits::configured(false)?;
    let limit = crate::http_connections::connection_limit(
        false,
        ramflux_node_core::environment::var("RAMFLUX_FEDERATION_ADMIN_MAX_CONNECTIONS")
            .ok()
            .as_deref(),
    )?;
    let active = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let listener = TcpListener::bind(addr).map_err(|source| {
        ramflux_node_core::NodeCoreError::ItestHttp(format!(
            "federation admin HTTP bind failed at {addr}: {source}"
        ))
    })?;
    tracing::info!(addr, limit, "federation production admin HTTP surface listening");
    std::thread::Builder::new()
        .spawn(move || {
            for stream in listener.incoming() {
                let stream = match stream {
                    Ok(stream) => stream,
                    Err(error) => {
                        tracing::warn!(%error, "federation admin accept failed");
                        continue;
                    }
                };
                let _worker =
                    spawn_admin_connection(stream, context.clone(), active.clone(), limit, limits);
            }
        })
        .map_err(|error| {
            ramflux_node_core::NodeCoreError::ItestHttp(format!(
                "federation admin listener thread unavailable: {error}"
            ))
        })?;
    Ok(())
}

pub(crate) fn spawn_admin_connection(
    stream: TcpStream,
    context: FederationAdminHttpContext,
    active: Arc<std::sync::atomic::AtomicUsize>,
    limit: usize,
    limits: ramflux_node_core::HttpRequestLimits,
) -> Option<std::thread::JoinHandle<()>> {
    crate::http_connections::spawn_connection(
        stream,
        active,
        limit,
        std::time::Instant::now(),
        move |stream, accepted_at| {
            handle_admin_connection_with_limits(stream, &context, limits, accepted_at);
        },
    )
}
pub(crate) fn handle_admin_connection_with_limits(
    stream: &mut TcpStream,
    context: &FederationAdminHttpContext,
    limits: ramflux_node_core::HttpRequestLimits,
    accepted_at: std::time::Instant,
) {
    let response = match admin_response(stream, context, limits, accepted_at) {
        Ok(response) => response,
        Err(error) => {
            tracing::warn!(%error, "federation admin request failed");
            Some(HttpResponse::text(
                crate::http_limits::rejection(&error).unwrap_or("500 Internal Server Error"),
                &error.to_string(),
            ))
        }
    };
    if let Some(response) = response
        && let Err(error) = response.write_admin(stream, limits, accepted_at)
    {
        tracing::warn!(%error, "federation admin response failed");
    }
}

#[cfg(test)]
pub(crate) fn handle_admin_request(
    stream: &mut TcpStream,
    context: &FederationAdminHttpContext,
) -> Result<(), ramflux_node_core::NodeCoreError> {
    let limits = crate::http_limits::defaults(false);
    let accepted_at = std::time::Instant::now();
    if let Some(response) = admin_response(stream, context, limits, accepted_at)? {
        response.write(stream, limits, accepted_at)?;
    }
    Ok(())
}

fn admin_response(
    stream: &mut TcpStream,
    context: &FederationAdminHttpContext,
    limits: ramflux_node_core::HttpRequestLimits,
    accepted_at: std::time::Instant,
) -> Result<Option<HttpResponse>, ramflux_node_core::NodeCoreError> {
    let Some(request) =
        ramflux_node_core::read_http_request_with_limits(stream, limits, accepted_at)?
    else {
        return Ok(None);
    };
    let state = &context.state;
    let store = context.store.as_ref();
    let discovery = &context.discovery;
    let admin_token = context.admin_token.as_deref();
    log_admin_request(&request, discovery);
    let response = match (request.method.as_str(), request.path.as_str()) {
        ("GET", "/healthz") => HttpResponse::json(&serde_json::json!({
            "service": "ramflux-federation-admin", "status": "ok"
        }))?,
        ("POST", "/s8/federation/forward") => {
            handle_admin_forward_request(&request, context, admin_token)?
        }
        ("POST", "/internal/home-node-migration/forward") => {
            handle_home_node_forward_request(&request, context, admin_token)?
        }
        ("POST", "/s8/federation/mesh-observability") => {
            handle_admin_mesh_observability_request(&request, context, admin_token)?
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
            HttpResponse::json(&response)?
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
            HttpResponse::json(&response)?
        }
        _ => HttpResponse::text("404 Not Found", "not found"),
    };
    Ok(Some(response))
}

fn handle_admin_mesh_observability_request(
    request: &ramflux_node_core::NodeHttpRequest,
    context: &FederationAdminHttpContext,
    admin_token: Option<&str>,
) -> Result<HttpResponse, ramflux_node_core::NodeCoreError> {
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
    HttpResponse::json(&snapshot)
}

fn handle_admin_forward_request(
    request: &ramflux_node_core::NodeHttpRequest,
    context: &FederationAdminHttpContext,
    admin_token: Option<&str>,
) -> Result<HttpResponse, ramflux_node_core::NodeCoreError> {
    let request: ramflux_node_core::FederatedEnvelopeForwardRequest =
        serde_json::from_slice(&request.body)
            .map_err(|source| ramflux_node_core::NodeCoreError::ItestJson(source.to_string()))?;
    require_admin_token(admin_token, &request.admin_token)?;
    log_admin_forward_request(&request);
    let response = handle_s8_forward_envelope(
        &request,
        context.state.as_ref(),
        context.store.as_ref(),
        context.router.as_ref(),
        &context.discovery,
    )?;
    log_admin_forward_response(&response);
    HttpResponse::json(&response)
}

fn handle_home_node_forward_request(
    request: &ramflux_node_core::NodeHttpRequest,
    context: &FederationAdminHttpContext,
    admin_token: Option<&str>,
) -> Result<HttpResponse, ramflux_node_core::NodeCoreError> {
    let request: HomeNodeMigrationForwardLocalRequest = serde_json::from_slice(&request.body)
        .map_err(|source| ramflux_node_core::NodeCoreError::ItestJson(source.to_string()))?;
    require_admin_token(admin_token, &request.admin_token)?;
    log_home_node_forward_request(&request.forward);
    let response = handle_s8_forward_envelope(
        &request.forward,
        context.state.as_ref(),
        context.store.as_ref(),
        context.router.as_ref(),
        &context.discovery,
    )?;
    log_home_node_forward_response(&response);
    HttpResponse::json(&response)
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

fn log_admin_forward_request(request: &ramflux_node_core::FederatedEnvelopeForwardRequest) {
    tracing::info!(
        source_node_id = %request.source_node_id,
        target_node_id = %request.target_node_id,
        envelope_id = %request.envelope.envelope_id,
        target_delivery_id = %request.envelope.target_delivery_id,
        "federation admin forward request decoded"
    );
}

fn log_home_node_forward_request(request: &ramflux_node_core::FederatedEnvelopeForwardRequest) {
    tracing::info!(
        source_node_id = %request.source_node_id,
        target_node_id = %request.target_node_id,
        envelope_id = %request.envelope.envelope_id,
        target_delivery_id = %request.envelope.target_delivery_id,
        "federation local home-node migration forward requested"
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

fn log_home_node_forward_response(response: &ramflux_node_core::FederatedEnvelopeForwardResponse) {
    tracing::info!(
        source_node_id = %response.source_node_id,
        target_node_id = %response.target_node_id,
        outcome = %response.delivery.outcome,
        target_delivery_id = %response.delivery.target_delivery_id,
        "federation local home-node migration forward response"
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
