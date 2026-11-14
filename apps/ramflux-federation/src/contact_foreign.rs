// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Contact queries use public DNS-pinned bootstrap and exact service carriers, without admin RPCs.
use crate::RouterMeshClient;
use ramflux_node_core::{FederationRedbStore, NodeCoreError};
use ramflux_protocol::contact_reach::{
    self as wire, Discovery, PeerQueryRequest, PeerQueryResponse, PeerQueryResult,
    PeerQueryResultKind, Reason,
};
use ramflux_transport::{
    BoundedHttpPost, BoundedHttpTls, GatewayQuicResponse,
    contact_egress::{PublicMeshPost, PublicTarget},
};
use std::time::{Duration, Instant};

mod budget;
mod cost;
pub(crate) mod quic;
mod receive;
mod request;
mod submit;
pub(crate) struct Response {
    pub frame: GatewayQuicResponse,
    _reservation: Option<budget::Permit>,
}
#[derive(Clone, Copy)]
pub(crate) struct PeerContext<'a> {
    pub uri: Option<&'a str>,
    pub ip: Option<std::net::IpAddr>,
}
#[derive(Clone, Copy)]
pub(crate) struct Context<'a> {
    pub node: &'a crate::FederationDiscoverySurface,
    pub router: &'a RouterMeshClient,
    pub store: &'a FederationRedbStore,
    pub peer: PeerContext<'a>,
    pub received: Instant,
}
pub(crate) fn recognizes(path: &str) -> bool {
    matches!(
        path,
        wire::FOREIGN_PATH | wire::PEER_QUERY_PATH | wire::PEER_COST_PATH | receive::PATH
    )
}
fn failure(status: u16, reason: &str) -> Response {
    Response {
        frame: GatewayQuicResponse {
            status,
            body: serde_json::json!({"frame_type":"contact_foreign_error","reason":reason}),
        },
        _reservation: None,
    }
}
fn correlated(request: &PeerQueryRequest, reason: Reason) -> PeerQueryResponse {
    PeerQueryResponse {
        kind: PeerQueryResultKind::QueryResult,
        request_id: request.request_id.clone(),
        result: PeerQueryResult::Error {
            reason,
            retry_after_ms: matches!(
                reason,
                Reason::ForeignRateLimited | Reason::ForeignSpamLimited
            )
            .then_some(1000),
            current_revision: None,
        },
    }
}
fn remaining(deadline: Instant) -> Result<u64, Reason> {
    deadline
        .checked_duration_since(Instant::now())
        .and_then(|left| u64::try_from(left.as_millis()).ok())
        .filter(|ms| (1..=10_000).contains(ms))
        .ok_or(Reason::ForeignUnavailable)
}
/// Must run on a bounded blocking service worker; public bootstrap owns its temporary runtime.
pub(crate) fn route(
    method: &str,
    path: &str,
    bytes: &[u8],
    context: Context<'_>,
) -> Result<Option<Response>, NodeCoreError> {
    if wire::ephemeral_frame(bytes) {
        return Ok(Some(Response {
            frame: GatewayQuicResponse {
                status: 200,
                body: serde_json::to_value(wire::unavailable())
                    .map_err(|error| NodeCoreError::ItestJson(error.to_string()))?,
            },
            _reservation: None,
        }));
    }
    if !recognizes(path) {
        return Ok(None);
    }
    if path == receive::PATH {
        return receive::route(method, bytes, context);
    }
    let request =
        match request::decode(method, path, bytes, context.node.node_id.as_str(), context.peer.uri)
        {
            Ok(request::Request::Query(request)) => request,
            Ok(request::Request::Submit(request)) => {
                return submit::route(&request, context).map(Some);
            }
            Ok(request::Request::Cost(request)) => {
                return cost::source(&request, context).map(Some);
            }
            Ok(request::Request::PeerCost(request)) => {
                return cost::peer(&request, context).map(Some);
            }
            Err(response) => return Ok(Some(response)),
        };
    let own = path == wire::FOREIGN_PATH;
    let peer_key =
        if own { request.query.target_node.as_str() } else { request.query.source_node.as_str() };
    let reservation =
        if wire::enabled() { budget::reserve(peer_key, !own).map(Some) } else { Ok(None) };
    let (reservation, refusal) = match reservation {
        Ok(permit) => (permit, None),
        Err(reason) => (None, Some(reason)),
    };
    let result = if let Some(reason) = refusal {
        Err(reason)
    } else if !wire::enabled() {
        Err(Reason::FeatureDisabled)
    } else {
        let deadline = context.received + Duration::from_millis(request.remaining_ms);
        if !own || request.query.target_node == context.node.node_id.as_str() {
            source_proxy(&request, context.router, deadline)
        } else {
            let now = context.store.contact_clock_floor(crate::now_unix_seconds()?)?;
            outgoing(&request, context.router, deadline, now)
        }
    };
    let response = result.unwrap_or_else(|reason| correlated(&request, reason));
    Ok(Some(Response {
        frame: GatewayQuicResponse {
            status: 200,
            body: serde_json::to_value(response)
                .map_err(|error| NodeCoreError::ItestJson(error.to_string()))?,
        },
        _reservation: reservation,
    }))
}
fn source_proxy(
    request: &PeerQueryRequest,
    router: &RouterMeshClient,
    deadline: Instant,
) -> Result<PeerQueryResponse, Reason> {
    let mut next = request.clone();
    next.remaining_ms = remaining(deadline)?;
    let bytes =
        ramflux_protocol::canonical_json_bytes(&next).map_err(|_| Reason::ForeignInvalidFrame)?;
    let tls = BoundedHttpTls::new(&router.tls, &router.server_name, None)
        .and_then(|tls| tls.with_mesh_peer(&request.query.target_node, "ramflux-router"))
        .map_err(|_| Reason::ForeignUnavailable)?;
    let bytes = ramflux_transport::bounded_http_post(BoundedHttpPost {
        endpoint: &router.endpoint,
        path: wire::SNAPSHOT_PATH,
        body: &bytes,
        tls: Some(&tls),
        deadline,
        max_bytes: wire::MAX_FRAME_BYTES,
    })
    .map_err(|_| Reason::ForeignUnavailable)?;
    let response =
        wire::decode(&bytes, wire::MAX_FRAME_BYTES).map_err(|_| Reason::ForeignSnapshotInvalid)?;
    request.validate_response(&response).map_err(|_| Reason::ForeignSnapshotInvalid)?;
    Ok(response)
}
fn outgoing(
    request: &PeerQueryRequest,
    router: &RouterMeshClient,
    deadline: Instant,
    now: u64,
) -> Result<PeerQueryResponse, Reason> {
    // TCP workers and QUIC blocking workers may own a temporary discovery runtime.
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| Reason::ForeignUnavailable)?;
    let (target, discovery) =
        runtime.block_on(discover(&request.query.target_node, deadline, now))?;
    let mut next = request.clone();
    next.remaining_ms = remaining(deadline)?;
    let bytes =
        ramflux_protocol::canonical_json_bytes(&next).map_err(|_| Reason::ForeignInvalidFrame)?;
    let roots = vec![discovery.client.node_ca_cert_pem.clone()];
    let response = target
        .post_mesh(PublicMeshPost {
            path: wire::PEER_QUERY_PATH,
            body: &bytes,
            tls: &router.tls,
            peer_ca_pems: &roots,
            deadline,
            max_bytes: wire::MAX_FRAME_BYTES,
        })
        .map_err(|_| Reason::ForeignBootstrapFailed)?;
    let response: PeerQueryResponse = wire::decode(&response, wire::MAX_FRAME_BYTES)
        .map_err(|_| Reason::ForeignSnapshotInvalid)?;
    request.validate_response(&response).map_err(|_| Reason::ForeignSnapshotInvalid)?;
    if let PeerQueryResult::Query { reply } = &response.result {
        ramflux_crypto::contact_reach::verify_transport_snapshot(
            reply,
            &request.query,
            &discovery.client.node_public_key,
            now,
        )
        .map_err(|_| Reason::ForeignSnapshotInvalid)?;
    }
    Ok(response)
}
async fn discover(
    node: &str,
    deadline: Instant,
    now: u64,
) -> Result<(PublicTarget, Discovery), Reason> {
    let origin = format!("https://{node}");
    let target = PublicTarget::resolve(&origin, node, deadline)
        .await
        .map_err(|_| Reason::ForeignEndpointRefused)?;
    let client = target
        .get("/.well-known/ramflux/client", deadline, 1024 * 1024)
        .await
        .map_err(|_| Reason::ForeignBootstrapFailed)?;
    let server = target
        .get("/.well-known/ramflux/server", deadline, 1024 * 1024)
        .await
        .map_err(|_| Reason::ForeignBootstrapFailed)?;
    let client = ramflux_protocol::custody::decode(&client, 1024 * 1024)
        .map_err(|_| Reason::ForeignSnapshotInvalid)?;
    let server =
        ramflux_protocol::parse_i_json(&server).map_err(|_| Reason::ForeignSnapshotInvalid)?;
    let discovery = Discovery { client, server };
    ramflux_crypto::contact_reach::verify_node_discovery(
        &discovery,
        node,
        &discovery.client.node_public_key,
        now,
    )
    .map_err(|_| Reason::ForeignSnapshotInvalid)?;
    let server: ramflux_node_core::FederationServerRecord =
        serde_json::from_value(discovery.server.clone())
            .map_err(|_| Reason::ForeignSnapshotInvalid)?;
    let target = PublicTarget::resolve(&server.node_endpoint, node, deadline)
        .await
        .map_err(|_| Reason::ForeignEndpointRefused)?;
    Ok((target, discovery))
}

#[cfg(test)]
mod test_support;
