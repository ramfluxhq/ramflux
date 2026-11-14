// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Cost requests cross only the own-service and public issuer hops, without owner credentials.
use super::{Context, Response, budget, remaining};
use ramflux_node_core::{NodeCoreError, contact_reach::ReachError};
use ramflux_protocol::contact_reach::{self as wire, OperationResult, Reason};
use ramflux_transport::{
    BoundedHttpPost, BoundedHttpTls, GatewayQuicResponse, contact_egress::PublicMeshPost,
};
use std::time::{Duration, Instant};

fn error(reason: Reason) -> OperationResult {
    OperationResult::Error {
        reason,
        current_revision: None,
        retry_after_ms: (reason == Reason::ForeignRateLimited).then_some(1000),
    }
}
fn frame(
    value: impl serde::Serialize,
    permit: Option<budget::Permit>,
) -> Result<Response, NodeCoreError> {
    Ok(Response {
        frame: GatewayQuicResponse {
            status: 200,
            body: serde_json::to_value(value)
                .map_err(|error| NodeCoreError::ItestJson(error.to_string()))?,
        },
        _reservation: permit,
    })
}
fn deadline(context: Context<'_>, remaining_ms: u64) -> Result<Instant, Reason> {
    context
        .received
        .checked_add(Duration::from_millis(remaining_ms))
        .ok_or(Reason::ForeignUnavailable)
}
pub(super) fn source(
    request: &wire::SourceCostRequest,
    context: Context<'_>,
) -> Result<Response, NodeCoreError> {
    let mut permit = None;
    let result = if !wire::enabled() {
        Err(Reason::FeatureDisabled)
    } else if request.target_node_id == context.own_node {
        // Same-node R.Op issuance belongs to the authenticated router owner.
        Err(Reason::ForeignPolicyDenied)
    } else {
        budget::reserve(&request.target_node_id, false).and_then(|reserved| {
            permit = Some(reserved);
            let deadline = deadline(context, request.remaining_ms)?;
            remaining(deadline)?;
            let now = context
                .store
                .contact_clock_floor(
                    crate::now_unix_seconds().map_err(|_| Reason::ForeignUnavailable)?,
                )
                .map_err(|_| Reason::ForeignStorageUnavailable)?;
            outgoing(request, context, deadline, now)
        })
    };
    let response = wire::SourceCostResponse {
        kind: wire::SourceCostResultKind::CostResult,
        request_id: request.request_id.clone(),
        result: result.unwrap_or_else(error),
    };
    request
        .validate_response(&response)
        .map_err(|error| NodeCoreError::ItestJson(error.to_string()))?;
    frame(response, permit)
}
pub(super) fn peer(
    request: &wire::CostRequest,
    context: Context<'_>,
) -> Result<Response, NodeCoreError> {
    let mut permit = None;
    let result = if wire::enabled() {
        receiving(request, context, &mut permit)
    } else {
        Err(Reason::FeatureDisabled)
    };
    frame(
        wire::CostResponse {
            request_id: request.request_id.clone(),
            result: result.unwrap_or_else(error),
        },
        permit,
    )
}
fn receiving(
    request: &wire::CostRequest,
    context: Context<'_>,
    permit: &mut Option<budget::Permit>,
) -> Result<OperationResult, Reason> {
    let peer = context
        .peer
        .uri
        .and_then(|uri| ramflux_node_core::parse_mesh_spiffe_uri(uri).ok())
        .ok_or(Reason::ForeignPolicyDenied)?;
    let ip = context.peer.ip.ok_or(Reason::ForeignUnavailable)?;
    *permit = Some(budget::reserve(&peer.node_id, true)?);
    let deadline = deadline(context, request.remaining_ms)?;
    remaining(deadline)?;
    let now = crate::now_unix_seconds().map_err(|_| Reason::ForeignUnavailable)?;
    context.store.admit_contact_cost(&peer, ip, now).map_err(|error| match error {
        ReachError::Refused(reason) if wire::cost_error_reason(reason) => reason,
        ReachError::Storage(_) => Reason::ForeignStorageUnavailable,
        _ => Reason::ForeignPolicyDenied,
    })?;
    let mut next = request.clone();
    next.remaining_ms = remaining(deadline)?;
    let body =
        ramflux_protocol::canonical_json_bytes(&next).map_err(|_| Reason::ForeignInvalidFrame)?;
    let tls = BoundedHttpTls::new(&context.router.tls, &context.router.server_name, None)
        .and_then(|tls| tls.with_mesh_peer(context.own_node, "ramflux-router"))
        .map_err(|_| Reason::ForeignUnavailable)?;
    let bytes = ramflux_transport::bounded_http_post(BoundedHttpPost {
        endpoint: &context.router.endpoint,
        path: wire::ISSUER_COST_PATH,
        body: &body,
        tls: Some(&tls),
        deadline,
        max_bytes: wire::MAX_COST_RESPONSE_BYTES,
    })
    .map_err(|_| Reason::ForeignUnavailable)?;
    let response = checked_reply(request, &bytes, context.own_node)?;
    remaining(deadline)?;
    Ok(response.result)
}
fn checked_reply(
    request: &wire::CostRequest,
    bytes: &[u8],
    issuer: &str,
) -> Result<wire::CostResponse, Reason> {
    let response: wire::CostResponse =
        wire::decode(bytes, wire::MAX_COST_RESPONSE_BYTES).map_err(|_| {
            tracing::warn!("cost peer protocol violation: invalid response carrier");
            Reason::ForeignUnavailable
        })?;
    request.validate_response(&response, issuer).map_err(|_| {
        tracing::warn!("cost peer protocol violation: invalid correlation, result or reason");
        Reason::ForeignUnavailable
    })?;
    Ok(response)
}
fn outgoing(
    request: &wire::SourceCostRequest,
    context: Context<'_>,
    deadline: Instant,
    now: u64,
) -> Result<OperationResult, Reason> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| Reason::ForeignUnavailable)?;
    let (target, discovery) = runtime
        .block_on(super::discover(&request.target_node_id, deadline, now))
        .map_err(|_| Reason::ForeignUnavailable)?;
    let mut public = request.public_request();
    public.remaining_ms = remaining(deadline)?;
    let body =
        ramflux_protocol::canonical_json_bytes(&public).map_err(|_| Reason::ForeignInvalidFrame)?;
    let roots = vec![discovery.client.node_ca_cert_pem.clone()];
    let bytes = target
        .post_mesh(PublicMeshPost {
            path: wire::PEER_COST_PATH,
            body: &body,
            tls: &context.router.tls,
            peer_ca_pems: &roots,
            deadline,
            max_bytes: wire::MAX_COST_RESPONSE_BYTES,
        })
        .map_err(|_| Reason::ForeignUnavailable)?;
    let response = checked_reply(&public, &bytes, &request.target_node_id)?;
    if let OperationResult::Challenge { challenge } = &response.result {
        wire::check_submission_time(challenge.body.issued_at, challenge.body.expires_at, now)
            .map_err(|_| Reason::ForeignUnavailable)?;
        ramflux_crypto::verify_canonical_signature(
            &ramflux_protocol::custody::signing_bytes(wire::COST_DOMAIN, &challenge.body)
                .map_err(|_| Reason::ForeignUnavailable)?,
            &challenge.signature,
            &discovery.client.node_public_key,
        )
        .map_err(|_| Reason::ForeignUnavailable)?;
    }
    remaining(deadline)?;
    Ok(response.result)
}

#[cfg(test)]
mod tests;
