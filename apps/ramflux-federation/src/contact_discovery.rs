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
    if !matches!(
        path,
        "/.well-known/ramflux/client"
            | "/.well-known/ramflux/server"
            | "/.well-known/ramflux/continuity"
    ) {
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
    } else if path == "/.well-known/ramflux/server" {
        serde_json::to_value(discovery.well_known_record()?)
    } else {
        serde_json::to_value(continuity(discovery)?)
    }
    .map_err(|error| NodeCoreError::ItestJson(error.to_string()))?;
    ramflux_protocol::contact_reach::original_document(&body, 1024 * 1024)
        .map_err(|error| NodeCoreError::ItestJson(error.to_string()))?;
    Ok(Some(GatewayQuicResponse { status: 200, body }))
}
/// Publish only original operator-mounted rotation proofs; never synthesize a new authority link.
pub(crate) fn continuity(
    discovery: &FederationDiscoverySurface,
) -> Result<ramflux_protocol::contact_reach::NodeContinuityDocument, NodeCoreError> {
    use ramflux_protocol::contact_reach as wire;
    use std::io::Read as _;
    let error = |error: &dyn std::fmt::Display| NodeCoreError::ItestJson(error.to_string());
    let document = match ramflux_node_core::environment::var("RAMFLUX_CONTACT_NODE_CONTINUITY_FILE")
    {
        Ok(path) if !path.is_empty() => {
            let mut bytes = Vec::new();
            std::fs::File::open(path)
                .map_err(|e| error(&e))?
                .take(1024 * 1024 + 1)
                .read_to_end(&mut bytes)
                .map_err(|e| error(&e))?;
            wire::decode::<wire::NodeContinuityDocument>(&bytes, 1024 * 1024)
                .map_err(|e| error(&e))?
        }
        Ok(_) | Err(std::env::VarError::NotPresent) => wire::NodeContinuityDocument {
            kind: wire::NodeContinuityKind::NodeContinuity,
            node_id: discovery.node_id.clone(),
            rotations: Vec::new(),
        },
        Err(e) => return Err(error(&e)),
    };
    document.validate().map_err(|e| error(&e))?;
    if document.node_id != discovery.node_id {
        return Err(NodeCoreError::Unauthorized("configured continuity node mismatch".into()));
    }
    let proofs = document
        .rotations
        .iter()
        .map(serde_json::to_value)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| error(&e))?;
    let old_key = document
        .rotations
        .first()
        .map_or(discovery.node_public_key.as_str(), |r| r.old_node_public_key.as_str());
    ramflux_crypto::contact_reach::verify_node_continuity(
        &proofs,
        ramflux_crypto::contact_reach::NodeContinuityContext {
            node: &discovery.node_id,
            old_key,
            current_key: &discovery.node_public_key,
            minimum_rotated_at: 0,
            now: crate::now_unix_seconds()?,
        },
    )
    .map_err(|e| error(&e))?;
    Ok(document)
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
