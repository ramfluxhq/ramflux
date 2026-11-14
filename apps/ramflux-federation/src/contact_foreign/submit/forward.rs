// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Sign the complete immutable submission and correlate the exact receiving-home result.
use super::{Context, Instant, OperationResult, Reason, SourceSubmitRequest, remaining};
use ramflux_node_core::contact_reach::{ReachCapability, ReachDeliveryClass, ReachForward};
use ramflux_protocol::contact_reach as wire;
use ramflux_transport::contact_egress::{PublicMeshPost, PublicTarget};

pub(super) fn signed(
    request: &SourceSubmitRequest,
    node: &crate::FederationDiscoverySurface,
) -> Result<ReachForward, Reason> {
    if ramflux_crypto::public_key_base64url_from_seed(node.node_signing_seed)
        != node.node_public_key
    {
        return Err(Reason::ForeignUnavailable);
    }
    let mut forward = ReachForward {
        signing_key_id: String::new(),
        signature_alg: ramflux_protocol::SignatureAlg::Ed25519,
        signature: String::new(),
        source_node_id: node.node_id.clone(),
        target_node_id: request.target_node_id.clone(),
        delivery_class: ReachDeliveryClass::Message,
        required_capability: ReachCapability::V1,
        submission: request.submission.clone(),
        migration_evidence: None,
    };
    forward.sign(&node.node_id, node.node_signing_seed).map_err(|_| Reason::ReachRouteInvalid)?;
    if ramflux_protocol::canonical_json_bytes(&forward)
        .map_err(|_| Reason::ForeignInvalidFrame)?
        .len()
        > wire::MAX_FRAME_BYTES
    {
        return Err(Reason::ForeignPayloadTooLarge);
    }
    Ok(forward)
}

pub(super) fn send(
    request: &SourceSubmitRequest,
    forward: &ReachForward,
    target: &PublicTarget,
    discovery: &wire::Discovery,
    context: Context<'_>,
    deadline: Instant,
) -> OperationResult {
    let attempt = || {
        let body = ramflux_protocol::canonical_json_bytes(forward).ok()?;
        let roots = vec![discovery.client.node_ca_cert_pem.clone()];
        let bytes = target
            .post_mesh(PublicMeshPost {
                path: "/s8/federation/envelope",
                body: &body,
                tls: &context.router.tls,
                peer_ca_pems: &roots,
                deadline,
                max_bytes: wire::MAX_SUBMIT_RESPONSE_BYTES,
            })
            .ok()?;
        remaining(deadline).ok()?;
        wire::decode::<wire::ForwardResult>(&bytes, wire::MAX_SUBMIT_RESPONSE_BYTES).ok()
    };
    wire::ForwardResult::source_result(
        attempt().as_ref(),
        200,
        &context.node.node_id,
        &request.target_node_id,
        &request.submission.envelope.envelope_id,
    )
}

#[cfg(test)]
mod tests;
