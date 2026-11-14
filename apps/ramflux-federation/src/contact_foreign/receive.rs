// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Authenticate the first peer hop before relaying the unchanged signed forward to this router.
use super::{Context, Response, budget, failure, remaining};
use ramflux_node_core::{MeshPeerIdentity, NodeCoreError, contact_reach::ReachForward};
use ramflux_protocol::contact_reach::{self as wire, OperationResult, Reason};
use ramflux_transport::{BoundedHttpPost, BoundedHttpTls};
use std::time::{Duration, Instant};

pub(super) const PATH: &str = "/s8/federation/envelope";
const ROUTER_PATH: &str = "/internal/contact/forward/v1";

pub(super) fn route(
    method: &str,
    bytes: &[u8],
    context: Context<'_>,
) -> Result<Option<Response>, NodeCoreError> {
    if bytes.len() > wire::MAX_FRAME_BYTES {
        return Ok(Some(failure(413, "foreign_payload_too_large")));
    }
    if method != "POST" {
        return Ok(Some(failure(400, "foreign_invalid_frame")));
    }
    let Ok(forward) = ReachForward::decode(bytes) else {
        return Ok(Some(failure(400, "foreign_invalid_frame")));
    };
    let Ok(peer) = authorized(&forward, context.node.node_id.as_str(), context.peer.uri) else {
        return Ok(Some(failure(403, "foreign_policy_denied")));
    };
    let mut permit = None;
    let result = if wire::enabled() {
        budget::reserve(&peer.node_id, true).and_then(|reserved| {
            permit = Some(reserved);
            dispatch(&forward, bytes, &peer, context)
        })
    } else {
        Err(Reason::FeatureDisabled)
    };
    let response = wire::ForwardResult {
        kind: wire::ForwardResultKind::ForwardResult,
        source_node_id: forward.source_node_id,
        target_node_id: forward.target_node_id,
        envelope_id: forward.submission.envelope.envelope_id,
        result: result.unwrap_or_else(|reason| OperationResult::Error {
            reason,
            retry_after_ms: None,
            current_revision: None,
        }),
    };
    response.validate().map_err(|error| NodeCoreError::ItestJson(error.to_string()))?;
    Ok(Some(Response {
        frame: ramflux_transport::GatewayQuicResponse {
            status: 200,
            body: serde_json::to_value(response)
                .map_err(|error| NodeCoreError::ItestJson(error.to_string()))?,
        },
        _reservation: permit,
    }))
}
fn authorized(
    forward: &ReachForward,
    own_node: &str,
    uri: Option<&str>,
) -> Result<MeshPeerIdentity, Reason> {
    let peer = uri
        .and_then(|uri| ramflux_node_core::parse_mesh_spiffe_uri(uri).ok())
        .ok_or(Reason::ForeignPolicyDenied)?;
    if peer.service_id != "ramflux-federation"
        || peer.node_id != forward.source_node_id
        || forward.target_node_id != own_node
        || peer.node_id == own_node
    {
        return Err(Reason::ForeignPolicyDenied);
    }
    Ok(peer)
}
fn dispatch(
    forward: &ReachForward,
    original: &[u8],
    peer: &MeshPeerIdentity,
    context: Context<'_>,
) -> Result<OperationResult, Reason> {
    let deadline =
        context.received.checked_add(Duration::from_secs(10)).ok_or(Reason::ForeignUnavailable)?;
    remaining(deadline)?;
    if forward.submission.envelope.delivery_class != ramflux_protocol::DeliveryClass::Message {
        return Err(Reason::ForeignCapabilityMissing);
    }
    let nonce = ramflux_protocol::encode_base64url(
        ramflux_crypto::random_32().map_err(|_| Reason::ForeignUnavailable)?,
    );
    let request = wire::PeerQueryRequest {
        kind: wire::PeerQueryKind::Query,
        request_id: nonce.clone(),
        remaining_ms: remaining(deadline)?,
        query: wire::Query {
            version: 1,
            source_node: context.node.node_id.clone(),
            target_node: peer.node_id.clone(),
            account_anchor: forward.submission.route.body.source.account_anchor.clone(),
            card_hash: None,
            nonce,
            base: None,
            device_ref: None,
        },
    };
    let now = context
        .store
        .contact_clock_floor(crate::now_unix_seconds().map_err(|_| Reason::ForeignUnavailable)?)
        .map_err(|_| Reason::ForeignUnavailable)?;
    let response = super::outgoing(&request, context.router, deadline, now)
        .map_err(|_| Reason::ForeignUnavailable)?;
    let wire::PeerQueryResult::Query { reply } = response.result else {
        return Err(Reason::ForeignPolicyDenied);
    };
    let now = context
        .store
        .contact_clock_floor(crate::now_unix_seconds().map_err(|_| Reason::ForeignUnavailable)?)
        .map_err(|_| Reason::ForeignUnavailable)?;
    let source = ramflux_crypto::contact_reach::verify_peer_reply(
        &reply,
        &request.query,
        &reply.payload.discovery.client.node_public_key,
        None,
        now,
    )
    .map_err(|_| Reason::ForeignPolicyDenied)?;
    forward
        .verify(peer, &source, &context.node.node_id, now)
        .map_err(|_| Reason::ReachRouteInvalid)?;
    remaining(deadline)?;
    // Own-service TLS authenticates this relay's first-hop check to the router. The body
    // is unchanged; the router independently checks source evidence and recipient policy.
    Ok(proxy(forward, original, context, deadline))
}
fn proxy(
    forward: &ReachForward,
    original: &[u8],
    context: Context<'_>,
    deadline: Instant,
) -> OperationResult {
    let attempt = || {
        let tls = BoundedHttpTls::new(&context.router.tls, &context.router.server_name, None)
            .and_then(|tls| tls.with_mesh_peer(&context.node.node_id, "ramflux-router"))
            .ok()?;
        let bytes = ramflux_transport::bounded_http_post(BoundedHttpPost {
            endpoint: &context.router.endpoint,
            path: ROUTER_PATH,
            body: original,
            tls: Some(&tls),
            deadline,
            max_bytes: wire::MAX_SUBMIT_RESPONSE_BYTES,
        })
        .ok()?;
        remaining(deadline).ok()?;
        checked_reply(forward, &bytes)
    };
    attempt().unwrap_or_else(|| unknown(forward))
}
fn unknown(forward: &ReachForward) -> OperationResult {
    OperationResult::Submit {
        envelope_id: forward.submission.envelope.envelope_id.clone(),
        outcome: wire::SubmitOutcome::Unknown,
        reason: None,
    }
}
fn checked_reply(forward: &ReachForward, bytes: &[u8]) -> Option<OperationResult> {
    let result = wire::decode(bytes, wire::MAX_SUBMIT_RESPONSE_BYTES).ok()?;
    wire::validate_receiving_result(&result).ok()?;
    if matches!(&result, OperationResult::Submit { envelope_id, .. }
        if envelope_id != &forward.submission.envelope.envelope_id)
    {
        return None;
    }
    Some(result)
}

#[cfg(test)]
mod tests;
