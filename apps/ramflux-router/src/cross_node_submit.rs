// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Home-node forward of a gateway submit whose recipient lives on another node.

use ramflux_node_core::{
    EnvelopeSubmitResponse, HomeSubmitForward, NodeCoreError, SessionPushSubmitResponse,
};
use ramflux_protocol::DeliveryClass;

pub(crate) fn respond(
    body: &[u8],
    router: &crate::router_runtime::RouterHandle,
    peer_service_id: &str,
) -> anyhow::Result<crate::handlers::MeshResponse> {
    if !crate::router_engine::gateway_may_forward_submit(peer_service_id) {
        return Ok(crate::handlers::MeshResponse::text(
            "403 Forbidden",
            "cross-node submit requires gateway peer",
        ));
    }
    let Ok(request) = serde_json::from_slice::<HomeSubmitForward>(body) else {
        return refused_response("", "rejected_malformed");
    };
    let response = decide(router, &request);
    json_response(&response)
}

fn decide(
    router: &crate::router_runtime::RouterHandle,
    request: &HomeSubmitForward,
) -> SessionPushSubmitResponse {
    if !node_id(&request.target_node) {
        return refused(&request.envelope, "rejected_target_node");
    }
    if !forwardable(&request.envelope.delivery_class) {
        return refused(&request.envelope, "rejected_malformed");
    }
    match router.forward_cross_node(request) {
        Ok(response) => accepted(&request.envelope, response.delivery),
        Err(error) => refused(&request.envelope, refusal_outcome(&error)),
    }
}

/// The sender gateway treats `online` as a local inbox write. A home forward is `forwarded`.
fn sender_outcome(outcome: &str) -> &str {
    match outcome {
        "online"
        | "offline_queued"
        | "duplicate_federated_forward"
        | "federation_spooled_offline_peer" => "forwarded",
        "forward_retryable" => "aborted_retry_safe",
        other if other.starts_with("rejected_") => other,
        _ => "rejected_federation",
    }
}

fn accepted(
    envelope: &ramflux_protocol::Envelope,
    mut delivery: EnvelopeSubmitResponse,
) -> SessionPushSubmitResponse {
    delivery.outcome = sender_outcome(&delivery.outcome).to_owned();
    if delivery.outcome == "forwarded" && delivery.target_delivery_id != envelope.target_delivery_id
    {
        return refused(envelope, "rejected_federation");
    }
    SessionPushSubmitResponse { delivery, incarnation_id: None, retain_until: None }
}

fn forwardable(class: &DeliveryClass) -> bool {
    matches!(class, DeliveryClass::Message | DeliveryClass::CallWake)
}

fn node_id(value: &str) -> bool {
    let bytes = value.as_bytes();
    (1..=63).contains(&bytes.len())
        && !value.starts_with(['.', '-'])
        && !value.ends_with(['.', '-'])
        && bytes.iter().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'-')
        })
}

fn refusal_outcome(error: &NodeCoreError) -> &'static str {
    let text = error.to_string();
    if text.contains("missing federation route") || text.contains("missing federation CA") {
        "rejected_peer_unknown"
    } else if text.contains("is local node") {
        "rejected_target_node"
    } else {
        "rejected_federation"
    }
}

fn refused(envelope: &ramflux_protocol::Envelope, outcome: &str) -> SessionPushSubmitResponse {
    SessionPushSubmitResponse {
        delivery: EnvelopeSubmitResponse {
            migration_refusal: None,
            outcome: outcome.to_owned(),
            target_delivery_id: envelope.target_delivery_id.clone(),
            inbox_seq: None,
            cursor: None,
            nack: None,
        },
        incarnation_id: None,
        retain_until: None,
    }
}

fn refused_response(
    target_delivery_id: &str,
    outcome: &str,
) -> anyhow::Result<crate::handlers::MeshResponse> {
    let response = SessionPushSubmitResponse {
        delivery: EnvelopeSubmitResponse {
            migration_refusal: None,
            outcome: outcome.to_owned(),
            target_delivery_id: target_delivery_id.to_owned(),
            inbox_seq: None,
            cursor: None,
            nack: None,
        },
        incarnation_id: None,
        retain_until: None,
    };
    json_response(&response)
}

fn json_response(
    response: &SessionPushSubmitResponse,
) -> anyhow::Result<crate::handlers::MeshResponse> {
    Ok(crate::handlers::MeshResponse::json("200 OK", serde_json::to_vec(response)?))
}
