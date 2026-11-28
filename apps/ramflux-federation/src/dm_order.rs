// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! The one node-to-node call of the MLS DM track (MLS-SPEC 3.2): a `dm_order` operation moves
//! from the home of the submitting device to the home of the orderer and the reply comes back in
//! the same call. The call is signed with the sending node's federation key and travels over the
//! mTLS mesh between federation services, like the migration hop. The orderer accepts it from any
//! pinned peer (no origin-is-home check, M2) and keeps no replay window: a replayed `submit`
//! fails the exact-epoch compare-and-swap or the fresh group id check, `since` and `status` only
//! read.
use crate::{
    FederationDiscoverySurface, RouterMeshClient, SharedFederationTrustState,
    peer_pin::{self, LocalNode},
};
use ramflux_node_core::{
    DM_ORDER_BODY_MAX_BYTES, DM_ORDER_INBOUND_PATH, DM_ORDER_PEER_PATH, DmOrderForward,
    DmOrderInbound, DmOrderReply, FEDERATED_DM_ORDER_VERSION, FederatedDmOrderRequest,
    FederatedDmOrderResponse, FederationRedbStore, NodeCoreError,
};
use std::time::{Duration, Instant};

/// A `since` answer: up to 4 MiB of commits in base64url plus framing.
const REPLY_MAX_BYTES: usize = 8 * 1024 * 1024;
const HOP_BUDGET: Duration = Duration::from_secs(10);
const ID_MAX_BYTES: usize = 128;

fn refused(message: &str) -> NodeCoreError {
    NodeCoreError::Unauthorized(message.to_owned())
}

fn transport(error: impl std::fmt::Display) -> NodeCoreError {
    NodeCoreError::ItestHttp(error.to_string())
}

/// Sign `forward` with the node key and send it to the orderer node.
///
/// # Errors
/// The orderer is this node, unknown, unpinned or unreachable, or the reply is malformed.
pub(crate) fn forward(
    forward: DmOrderForward,
    state: &SharedFederationTrustState,
    store: &FederationRedbStore,
    discovery: &FederationDiscoverySurface,
    router: &RouterMeshClient,
) -> Result<FederatedDmOrderResponse, NodeCoreError> {
    let target = forward.target_node;
    if !peer_pin::node_id_ok(&target) || target == discovery.node_id {
        return Err(refused("dm_order orderer rejected"));
    }
    let local = LocalNode {
        node_id: discovery.node_id.clone(),
        capabilities: discovery.node_capabilities.clone(),
    };
    peer_pin::ensure_forward_pin(&target, state, store, &local)?;
    let snapshot = state.snapshot()?;
    let now = crate::now_unix_seconds()?;
    if !snapshot.can_deliver_to(&target, now) {
        return Err(refused("dm_order orderer not admitted"));
    }
    let key = snapshot
        .pinned_node_public_key(&target)
        .ok_or_else(|| refused("dm_order orderer not pinned"))?;
    crate::node_directory::sanction::check_peer(&target, Some(&key), "outbound")?;
    let ca = snapshot
        .pinned_peer_ca_cert_pem(&target)
        .ok_or_else(|| refused("dm_order orderer has no pinned CA"))?;
    let route = snapshot.route(&target).ok_or_else(|| refused("dm_order orderer has no route"))?;
    let deadline = Instant::now() + HOP_BUDGET;
    let endpoint = peer_pin::checked_forward_endpoint_until(&target, &route.endpoint, deadline)?;
    let request_id =
        ramflux_protocol::encode_base64url(ramflux_crypto::random_32().map_err(transport)?);
    let mut request = FederatedDmOrderRequest {
        version: FEDERATED_DM_ORDER_VERSION,
        signed: ramflux_node_core::default_federation_forward_signed_fields(),
        source_node_id: discovery.node_id.clone(),
        target_node_id: target,
        request_id,
        issued_at: now,
        anchor: forward.anchor,
        op: forward.op,
    };
    ramflux_node_core::sign_federated_dm_order(&mut request, discovery.node_signing_seed)?;
    let body = serde_json::to_vec(&request).map_err(transport)?;
    let tls =
        ramflux_transport::BoundedHttpTls::new(&router.tls, "ramflux-federation", Some(&[ca]))
            .map_err(transport)?;
    let bytes = ramflux_transport::bounded_http_post(ramflux_transport::BoundedHttpPost {
        endpoint: &endpoint,
        path: DM_ORDER_PEER_PATH,
        body: &body,
        tls: Some(&tls),
        deadline,
        max_bytes: REPLY_MAX_BYTES,
    })
    .map_err(transport)?;
    ramflux_protocol::parse_i_json(&bytes).map_err(transport)
}

/// Verify a `dm_order` call of the pinned peer `peer_node` (the mTLS identity of the connection)
/// and let the local router order it.
///
/// # Errors
/// The call is malformed, not for this node, from an unpinned or blocked peer, or badly signed.
pub(crate) fn inbound(
    request: &FederatedDmOrderRequest,
    peer_node: &str,
    state: &SharedFederationTrustState,
    discovery: &FederationDiscoverySurface,
    router: &RouterMeshClient,
) -> Result<FederatedDmOrderResponse, NodeCoreError> {
    if request.target_node_id != discovery.node_id
        || request.source_node_id != peer_node
        || request.source_node_id == discovery.node_id
        || !peer_pin::node_id_ok(&request.source_node_id)
        || request.request_id.is_empty()
        || request.request_id.len() > ID_MAX_BYTES
        || request.anchor.is_empty()
        || request.anchor.len() > ID_MAX_BYTES
    {
        return Err(refused("dm_order call rejected"));
    }
    let snapshot = state.snapshot()?;
    let now = crate::now_unix_seconds()?;
    if snapshot.peer_pin_blocked(&request.source_node_id, now) {
        return Err(refused("dm_order peer blocked"));
    }
    let key = snapshot
        .pinned_node_public_key(&request.source_node_id)
        .ok_or_else(|| refused("dm_order peer not pinned"))?;
    crate::node_directory::sanction::check_peer(&request.source_node_id, Some(&key), "inbound")?;
    ramflux_node_core::verify_federated_dm_order(request, &key)?;
    let call = DmOrderInbound {
        anchor: request.anchor.clone(),
        origin_node: request.source_node_id.clone(),
        op: request.op.clone(),
    };
    let reply: DmOrderReply = crate::router_post_json(router, DM_ORDER_INBOUND_PATH, &call)?;
    Ok(FederatedDmOrderResponse { reply })
}

/// Largest accepted body of both `dm_order` routes.
pub(crate) const BODY_MAX_BYTES: usize = DM_ORDER_BODY_MAX_BYTES;
