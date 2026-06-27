// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use crate::{
    FederationDiscoverySurface, FederationMeshObservability, RouterMeshClient,
    S12DiscoveryResolveRequest, now_unix_seconds,
};
use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

const DEFAULT_OUTBOUND_SPOOL_TTL_SECONDS: u64 = 7 * 24 * 60 * 60;
const DEFAULT_OUTBOUND_SPOOL_RETRY_INTERVAL_SECONDS: u64 = 30;
const DEFAULT_OUTBOUND_SPOOL_RETRY_BATCH: usize = 256;

pub(crate) fn handle_s12_discovery_resolve(
    request: S12DiscoveryResolveRequest,
    state: &crate::SharedFederationTrustState,
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

pub(crate) fn handle_s8_forward_envelope(
    request: &ramflux_node_core::FederatedEnvelopeForwardRequest,
    state: &crate::SharedFederationTrustState,
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
    state: &crate::SharedFederationTrustState,
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

pub(crate) fn start_outbound_spool_retry_loop(
    store: Arc<ramflux_node_core::FederationRedbStore>,
    state: Arc<crate::SharedFederationTrustState>,
    router: Arc<RouterMeshClient>,
) {
    let interval = Duration::from_secs(outbound_spool_retry_interval_seconds().max(1));
    std::thread::spawn(move || {
        loop {
            std::thread::sleep(interval);
            if let Err(error) = retry_outbound_spool_once(&store, &state, &router) {
                tracing::warn!(%error, "federation outbound spool retry pass failed");
            }
        }
    });
}

pub(crate) fn retry_outbound_spool_once(
    store: &ramflux_node_core::FederationRedbStore,
    state: &crate::SharedFederationTrustState,
    router: &RouterMeshClient,
) -> Result<(), ramflux_node_core::NodeCoreError> {
    let now = now_unix_seconds()?;
    let expired = store.expire_outbound_spool(now)?;
    if expired > 0 {
        tracing::info!(expired, "expired federation outbound spool entries");
    }
    let pending = store.list_pending_outbound(outbound_spool_retry_batch())?;
    let mut blocked_peers = BTreeSet::new();
    for entry in pending {
        if blocked_peers.contains(&entry.peer_node_id) {
            continue;
        }
        let peer = match resolve_forward_peer(&entry.forward, state) {
            Ok(peer) => peer,
            Err(error) => {
                tracing::warn!(
                    peer_node_id = %entry.peer_node_id,
                    seq = entry.seq,
                    error = %error,
                    "federation outbound spool route unavailable"
                );
                store.record_outbound_attempt(&entry.peer_node_id, entry.seq)?;
                blocked_peers.insert(entry.peer_node_id);
                continue;
            }
        };
        match send_signed_forward_to_peer(router, &peer, &entry.forward) {
            Ok(response) => {
                store.mark_outbound_delivered(&entry.peer_node_id, entry.seq)?;
                tracing::info!(
                    peer_node_id = %entry.peer_node_id,
                    seq = entry.seq,
                    outcome = %response.delivery.outcome,
                    "delivered federation outbound spool entry"
                );
            }
            Err(error) => {
                store.record_outbound_attempt(&entry.peer_node_id, entry.seq)?;
                tracing::warn!(
                    peer_node_id = %entry.peer_node_id,
                    seq = entry.seq,
                    error = %error,
                    "federation outbound spool retry failed"
                );
                blocked_peers.insert(entry.peer_node_id);
            }
        }
    }
    Ok(())
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
    Ok(spooled_forward_response(signed_request))
}

fn spooled_forward_response(
    signed_request: &ramflux_node_core::FederatedEnvelopeForwardRequest,
) -> ramflux_node_core::FederatedEnvelopeForwardResponse {
    ramflux_node_core::FederatedEnvelopeForwardResponse {
        accepted: true,
        source_node_id: signed_request.source_node_id.clone(),
        target_node_id: signed_request.target_node_id.clone(),
        delivery: ramflux_node_core::ItestMvp0SubmitResponse {
            outcome: "federation_spooled_offline_peer".to_owned(),
            target_delivery_id: signed_request.envelope.target_delivery_id.clone(),
            inbox_seq: None,
            cursor: None,
        },
    }
}

fn outbound_spool_ttl_seconds() -> u64 {
    env_u64("RAMFLUX_FEDERATION_SPOOL_TTL_SECONDS", DEFAULT_OUTBOUND_SPOOL_TTL_SECONDS)
}

fn outbound_spool_retry_interval_seconds() -> u64 {
    env_u64(
        "RAMFLUX_FEDERATION_SPOOL_RETRY_INTERVAL_SECS",
        DEFAULT_OUTBOUND_SPOOL_RETRY_INTERVAL_SECONDS,
    )
}

fn outbound_spool_retry_batch() -> usize {
    usize::try_from(env_u64(
        "RAMFLUX_FEDERATION_SPOOL_RETRY_BATCH",
        DEFAULT_OUTBOUND_SPOOL_RETRY_BATCH as u64,
    ))
    .unwrap_or(DEFAULT_OUTBOUND_SPOOL_RETRY_BATCH)
    .max(1)
}

fn env_u64(name: &str, default_value: u64) -> u64 {
    std::env::var(name).ok().and_then(|value| value.parse::<u64>().ok()).unwrap_or(default_value)
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

pub(crate) fn handle_s8_receive_envelope(
    request: &ramflux_node_core::FederatedEnvelopeForwardRequest,
    state: &crate::SharedFederationTrustState,
    router: &RouterMeshClient,
    discovery: &FederationDiscoverySurface,
    observability: Option<&FederationMeshObservability>,
) -> Result<ramflux_node_core::FederatedEnvelopeForwardResponse, ramflux_node_core::NodeCoreError> {
    let total_started = std::time::Instant::now();
    let step_started = std::time::Instant::now();
    ensure_receive_target_node(request, &discovery.node_id)?;
    if let Some(observability) = observability {
        observability.record_receive_target_check(step_started.elapsed());
    }
    {
        let now = now_unix_seconds()?;
        let step_started = std::time::Instant::now();
        let state = state.snapshot()?;
        if let Some(observability) = observability {
            observability.record_receive_trust_snapshot(step_started.elapsed());
        }
        let step_started = std::time::Instant::now();
        state.ensure_federated_envelope_allowed(request, &request.source_node_id, now)?;
        if let Some(observability) = observability {
            observability.record_receive_policy_check(step_started.elapsed());
        }
        let step_started = std::time::Instant::now();
        let pinned_public_key =
            state.pinned_node_public_key(&request.source_node_id).ok_or_else(|| {
                ramflux_node_core::NodeCoreError::ItestHttp(format!(
                    "missing federation pin for {}",
                    request.source_node_id
                ))
            })?;
        if let Some(observability) = observability {
            observability.record_receive_pin_lookup(step_started.elapsed());
        }
        let step_started = std::time::Instant::now();
        let verify_timings = ramflux_node_core::verify_federated_envelope_forward_with_timings(
            request,
            &pinned_public_key,
        )?;
        if let Some(observability) = observability {
            observability.record_receive_signature_verify(step_started.elapsed());
            observability.record_receive_signature_segments(verify_timings);
        }
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
    let step_started = std::time::Instant::now();
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
    if let Some(observability) = observability {
        observability.record_receive_router_post(step_started.elapsed());
    }
    tracing::info!(
        source_node_id = %request.source_node_id,
        target_node_id = %request.target_node_id,
        envelope_id = %request.envelope.envelope_id,
        target_delivery_id = %request.envelope.target_delivery_id,
        outcome = %delivery.outcome,
        "delivered inbound federated envelope to local router"
    );
    let response = ramflux_node_core::FederatedEnvelopeForwardResponse {
        accepted: true,
        source_node_id: request.source_node_id.clone(),
        target_node_id: request.target_node_id.clone(),
        delivery,
    };
    if let Some(observability) = observability {
        observability.record_receive_total(total_started.elapsed());
    }
    Ok(response)
}

pub(crate) fn ensure_receive_target_node(
    request: &ramflux_node_core::FederatedEnvelopeForwardRequest,
    local_node_id: &str,
) -> Result<(), ramflux_node_core::NodeCoreError> {
    if request.target_node_id != local_node_id {
        return Err(ramflux_node_core::NodeCoreError::ItestHttp(format!(
            "federation inbound target {} is not local node {}",
            request.target_node_id, local_node_id
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn receive_target_node_must_match_local_node() {
        let request = ramflux_node_core::FederatedEnvelopeForwardRequest {
            signed: ramflux_node_core::default_federation_forward_signed_fields(),
            admin_token: String::new(),
            source_node_id: "node_a.example".to_owned(),
            target_node_id: "node_c.example".to_owned(),
            delivery_class: "opaque_event".to_owned(),
            required_capability: "opaque_delivery".to_owned(),
            envelope: ramflux_protocol::Envelope {
                schema: "ramflux.envelope.v1".to_owned(),
                version: 1,
                domain: "ramflux.envelope.v1".to_owned(),
                ext: ramflux_protocol::Ext::default(),
                signed: ramflux_protocol::SignedFields {
                    signature_alg: ramflux_protocol::SignatureAlg::Ed25519,
                    signing_key_id: "signing_key".to_owned(),
                    signature: "signature".to_owned(),
                },
                envelope_id: "env_wrong_target".to_owned(),
                source_principal_id: "alice".to_owned(),
                source_device_id: "alice_device".to_owned(),
                target_delivery_id: "target_b".to_owned(),
                routing_set_id: None,
                delivery_class: ramflux_protocol::DeliveryClass::OpaqueEvent,
                priority: ramflux_protocol::Priority::Normal,
                ttl: 3_600,
                created_at: 1_760_000_000,
                encrypted_payload: "ciphertext".to_owned(),
                payload_hash: "payload_hash".to_owned(),
            },
        };

        let rejected = ensure_receive_target_node(&request, "node_b.example");

        assert!(matches!(rejected, Err(ramflux_node_core::NodeCoreError::ItestHttp(_))));
    }
}
