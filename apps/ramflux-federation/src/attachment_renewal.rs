// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
//! Dormant federation hops of the attachment renewal route (P25 N6a):
//! B router -> B federation (`/internal/attachment-renewal/peer`, admin token) and
//! A federation -> A router (`/s9/attachments/renew/peer`, TLS node identity).
//! Admission is [`ramflux_node_core::admit_peer_renewal`]; nothing here mounts a
//! listener, and every refusal is typed and final: no hop falls back to another path.
use ramflux_node_core::{
    NodeCoreError, PeerRenewalFacts, admit_peer_renewal, attachment::RenewalRefusal,
    parse_mesh_spiffe_uri,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::time::Instant;

pub(crate) const PEER_PATH: &str = "/s9/attachments/renew/peer";
pub(crate) const LOCAL_PATH: &str = "/internal/attachment-renewal/peer";
pub(crate) const ROUTER_SOURCE_PATH: &str = "/s9/attachments/renew/source";
/// Design section 1: bodies are at most 16 KiB.
pub(crate) const MAX_BODY: usize = 16 * 1024;
const FEDERATION_SERVICE: &str = "ramflux-federation";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Kind {
    Challenge,
    Forward,
}

/// B federation -> A federation. `home_node` is B's claim; A checks it against TLS.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PeerEnvelope {
    pub(crate) kind: Kind,
    pub(crate) home_node: String,
    pub(crate) request: Value,
}

/// A federation -> A router.
#[derive(Debug, Serialize)]
struct SourceEnvelope<'a> {
    kind: Kind,
    peer_node: &'a str,
    request: &'a Value,
}

/// This node's view of one peer, read from its own trust state.
pub(crate) struct PeerView {
    pub(crate) advertised: bool,
    pub(crate) admitted: bool,
    pub(crate) negotiated: bool,
}

/// Reaches the local router (inbound) or the admitted peer (outbound).
pub(crate) trait Forwarder {
    /// # Errors
    /// The typed refusal when the next hop cannot be reached within `deadline`.
    fn post(
        &self,
        node: &str,
        path: &str,
        body: Vec<u8>,
        deadline: Instant,
    ) -> Result<Vec<u8>, RenewalRefusal>;
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Reply {
    pub(crate) status: &'static str,
    pub(crate) body: Vec<u8>,
}
#[derive(Serialize)]
enum Refused {
    Refused { code: RenewalRefusal },
}
fn refused(code: RenewalRefusal) -> Reply {
    Reply {
        status: "200 OK",
        body: serde_json::to_vec(&Refused::Refused { code }).unwrap_or_default(),
    }
}
fn text(status: &'static str, body: &str) -> Reply {
    Reply { status, body: body.as_bytes().to_vec() }
}
fn budget(deadline: Instant) -> Result<(), RenewalRefusal> {
    if deadline.checked_duration_since(Instant::now()).is_some_and(|d| !d.is_zero()) {
        Ok(())
    } else {
        Err(RenewalRefusal::Busy)
    }
}

/// A federation, inbound from B federation. The peer is authenticated from the TLS
/// SPIFFE identity before the body is looked at; `peer_node` is stamped from it.
pub(crate) fn inbound_peer(
    peer_spiffe_uri: Option<&str>,
    body: &[u8],
    view: &PeerView,
    router: &dyn Forwarder,
    deadline: Instant,
) -> Reply {
    let identity = match peer_spiffe_uri.map(parse_mesh_spiffe_uri) {
        Some(Ok(identity)) if identity.service_id == FEDERATION_SERVICE => identity,
        _ => return text("403 Forbidden", "attachment renewal requires federation identity"),
    };
    if body.len() > MAX_BODY {
        return text("413 Payload Too Large", "body");
    }
    let Ok(envelope) = serde_json::from_slice::<PeerEnvelope>(body) else {
        return refused(RenewalRefusal::Invalid);
    };
    let facts = PeerRenewalFacts {
        tls_node: &identity.node_id,
        home_node: &envelope.home_node,
        admitted: view.admitted,
        advertised: view.advertised,
        negotiated: view.negotiated,
    };
    if let Err(code) = admit_peer_renewal(&facts) {
        return refused(code);
    }
    let forward = serde_json::to_vec(&SourceEnvelope {
        kind: envelope.kind,
        peer_node: &identity.node_id,
        request: &envelope.request,
    });
    let result = forward
        .map_err(|_| RenewalRefusal::Invalid)
        .and_then(|bytes| budget(deadline).map(|()| bytes))
        .and_then(|bytes| router.post("", ROUTER_SOURCE_PATH, bytes, deadline));
    match result {
        Ok(bytes) => Reply { status: "200 OK", body: bytes },
        Err(code) => refused(code),
    }
}

/// B federation, from the local router. The router has already chosen the peer from a
/// pin-verified receipt; this hop re-checks that the peer is admitted and negotiated.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LocalRequest {
    pub(crate) admin_token: String,
    pub(crate) source_node: String,
    pub(crate) kind: Kind,
    pub(crate) request: Value,
}

pub(crate) fn local_peer(
    configured_admin_token: Option<&str>,
    body: &[u8],
    own_node: &str,
    view: &dyn Fn(&str) -> PeerView,
    peer: &dyn Forwarder,
    deadline: Instant,
) -> Result<Reply, NodeCoreError> {
    if body.len() > MAX_BODY {
        return Ok(text("413 Payload Too Large", "body"));
    }
    let request: LocalRequest = serde_json::from_slice(body)
        .map_err(|_| NodeCoreError::ItestHttp("invalid attachment renewal request".into()))?;
    crate::admin_http::require_admin_token(configured_admin_token, &request.admin_token)?;
    let view = view(&request.source_node);
    // The outbound claim is this node's own id, and the TLS check happens at the peer.
    let facts = PeerRenewalFacts {
        tls_node: own_node,
        home_node: own_node,
        admitted: view.admitted,
        advertised: view.advertised,
        negotiated: view.negotiated,
    };
    if let Err(code) = admit_peer_renewal(&facts) {
        return Ok(refused(code));
    }
    let source_node = request.source_node;
    let envelope = PeerEnvelope {
        kind: request.kind,
        home_node: own_node.to_owned(),
        request: request.request,
    };
    let result = serde_json::to_vec(&envelope)
        .map_err(|_| RenewalRefusal::Invalid)
        .and_then(|bytes| budget(deadline).map(|()| bytes))
        .and_then(|bytes| peer.post(&source_node, PEER_PATH, bytes, deadline));
    Ok(match result {
        Ok(bytes) => Reply { status: "200 OK", body: bytes },
        Err(code) => refused(code),
    })
}

fn transport(_: impl std::fmt::Display) -> RenewalRefusal {
    RenewalRefusal::Busy
}

/// Inbound hop to the local router over the mesh client TLS.
struct LocalRouter<'a>(&'a crate::RouterMeshClient);
impl Forwarder for LocalRouter<'_> {
    fn post(
        &self,
        _node: &str,
        path: &str,
        body: Vec<u8>,
        deadline: Instant,
    ) -> Result<Vec<u8>, RenewalRefusal> {
        let tls = ramflux_transport::BoundedHttpTls::new(&self.0.tls, &self.0.server_name, None)
            .map_err(transport)?;
        ramflux_transport::bounded_http_post(ramflux_transport::BoundedHttpPost {
            endpoint: &self.0.endpoint,
            path,
            body: &body,
            tls: Some(&tls),
            deadline,
            max_bytes: MAX_BODY,
        })
        .map_err(transport)
    }
}

/// Outbound hop to an admitted peer on its pinned CA.
struct AdmittedPeer<'a> {
    state: &'a crate::SharedFederationTrustState,
    tls: &'a ramflux_transport::MeshTlsConfig,
}
impl Forwarder for AdmittedPeer<'_> {
    fn post(
        &self,
        node: &str,
        path: &str,
        body: Vec<u8>,
        deadline: Instant,
    ) -> Result<Vec<u8>, RenewalRefusal> {
        let state = self.state.snapshot().map_err(transport)?;
        let endpoint = state.route(node).ok_or(RenewalRefusal::SourceUnknown)?.endpoint.clone();
        let ca = state.pinned_peer_ca_cert_pem(node).ok_or(RenewalRefusal::SourceUnknown)?;
        let tls = ramflux_transport::BoundedHttpTls::new(self.tls, FEDERATION_SERVICE, Some(&[ca]))
            .map_err(transport)?;
        ramflux_transport::bounded_http_post(ramflux_transport::BoundedHttpPost {
            endpoint: &endpoint,
            path,
            body: &body,
            tls: Some(&tls),
            deadline,
            max_bytes: MAX_BODY,
        })
        .map_err(transport)
    }
}

fn view_of(
    state: &crate::SharedFederationTrustState,
    discovery: &crate::FederationDiscoverySurface,
    node: &str,
) -> PeerView {
    let advertised = discovery.attachment_authority.is_some();
    let Ok(snapshot) = state.snapshot() else {
        return PeerView { advertised, admitted: false, negotiated: false };
    };
    let admitted = crate::now_unix_seconds().is_ok_and(|now| snapshot.can_deliver_to(node, now));
    let negotiated = snapshot
        .negotiated_capabilities(node)
        .is_some_and(|caps| caps.contains(ramflux_node_core::ATTACHMENT_RENEWAL_CAPABILITY));
    PeerView { advertised, admitted, negotiated }
}

/// The pin answer for the local router. It is empty unless this node advertises the
/// capability, and the book rechecks admission and negotiation on every lookup.
pub(crate) fn pin_answer(
    context: &crate::FederationAdminHttpContext,
    node_id: &str,
) -> Result<ramflux_node_core::PinAnswer, NodeCoreError> {
    pin_answer_for(
        &context.state,
        &context.store,
        context.discovery.attachment_authority.is_some(),
        node_id,
    )
}

fn pin_answer_for(
    state: &crate::SharedFederationTrustState,
    store: &ramflux_node_core::FederationRedbStore,
    advertised: bool,
    node_id: &str,
) -> Result<ramflux_node_core::PinAnswer, NodeCoreError> {
    if !advertised {
        return Ok(ramflux_node_core::PinAnswer::Unavailable);
    }
    let snapshot = state.snapshot()?;
    Ok(state.attachment_authority().answer(store, &snapshot, node_id, crate::now_unix_seconds()?))
}

/// `/s9/attachments/renew/peer` on the mesh listener.
pub(crate) fn serve_peer(
    peer_spiffe_uri: Option<&str>,
    body: &[u8],
    state: &crate::SharedFederationTrustState,
    router: &crate::RouterMeshClient,
    discovery: &crate::FederationDiscoverySurface,
    received: Instant,
) -> Reply {
    let tls_node = peer_spiffe_uri
        .and_then(|uri| parse_mesh_spiffe_uri(uri).ok())
        .map(|identity| identity.node_id)
        .unwrap_or_default();
    let view = view_of(state, discovery, &tls_node);
    inbound_peer(peer_spiffe_uri, body, &view, &LocalRouter(router), received + BUDGET)
}

/// `/internal/attachment-renewal/peer` on the admin listener.
pub(crate) fn serve_local(
    body: &[u8],
    context: &crate::FederationAdminHttpContext,
    received: Instant,
) -> Result<Reply, NodeCoreError> {
    local_peer(
        context.admin_token.as_deref(),
        body,
        &context.discovery.node_id,
        &|node| view_of(&context.state, &context.discovery, node),
        &AdmittedPeer { state: &context.state, tls: &context.router.tls },
        received + BUDGET,
    )
}

/// One budget for the whole route (design section 1).
const BUDGET: std::time::Duration = std::time::Duration::from_secs(10);

#[cfg(test)]
mod tests;
