// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! The router reads its own node's original signed public discoveries over mutual TLS.
use crate::FederationDiscoverySurface;
use ramflux_node_core::NodeCoreError;
use ramflux_transport::GatewayQuicResponse;
fn authorized(own_node: &str, peer_uri: Option<&str>) -> bool {
    peer_uri
        .and_then(|uri| ramflux_node_core::parse_mesh_spiffe_uri(uri).ok())
        .is_some_and(|peer| peer.node_id == own_node && peer.service_id == "ramflux-router")
}
pub(crate) fn route(
    method: &str,
    path: &str,
    body: &[u8],
    peer_uri: Option<&str>,
    discovery: &FederationDiscoverySurface,
) -> Result<Option<GatewayQuicResponse>, NodeCoreError> {
    if !matches!(path, "/.well-known/ramflux/client" | "/.well-known/ramflux/server") {
        return Ok(None);
    }
    if method != "GET" || !body.is_empty() || !authorized(&discovery.node_id, peer_uri) {
        return Ok(Some(GatewayQuicResponse {
            status: 403,
            body: serde_json::json!({"reason":"own_router_required"}),
        }));
    }
    let body = if path == "/.well-known/ramflux/client" {
        serde_json::to_value(discovery.client_record()?)
    } else {
        serde_json::to_value(discovery.well_known_record()?)
    }
    .map_err(|error| NodeCoreError::ItestJson(error.to_string()))?;
    ramflux_protocol::contact_reach::original_document(&body, 1024 * 1024)
        .map_err(|error| NodeCoreError::ItestJson(error.to_string()))?;
    Ok(Some(GatewayQuicResponse { status: 200, body }))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cr_source_discovery_requires_own_node_and_router_role() {
        assert!(
            authorized("own.example", Some("spiffe://own.example/ramflux-router")),
            "the configured own router must retain its signed document read"
        );
        assert!(
            !authorized("own.example", Some("spiffe://foreign.example/ramflux-router")),
            "a foreign CA's router role is not this node's internal source proxy"
        );
        assert!(
            !authorized("own.example", Some("spiffe://own.example/ramflux-gateway/one")),
            "same-node certificates do not substitute an unauthorized service role"
        );
        assert!(
            !authorized("own.example", None),
            "missing TLS identity cannot enter the source read"
        );
    }
}
