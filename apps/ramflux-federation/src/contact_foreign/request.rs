// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Strict kind dispatch preserves the independent Query and durable Submit limits.
use super::{Response, failure};
use ramflux_protocol::contact_reach::{self as wire, PeerQueryRequest, SourceSubmitRequest};

#[derive(serde::Deserialize)]
struct Kind<'a> {
    #[serde(borrow)]
    kind: std::borrow::Cow<'a, str>,
}

pub(super) enum Request {
    Query(Box<PeerQueryRequest>),
    Submit(Box<SourceSubmitRequest>),
}

pub(super) fn decode(
    method: &str,
    path: &str,
    bytes: &[u8],
    own_node: &str,
    peer_uri: Option<&str>,
) -> Result<Request, Response> {
    if method != "POST" {
        return Err(failure(400, "foreign_invalid_frame"));
    }
    if bytes.len() > wire::MAX_FRAME_BYTES {
        return Err(failure(413, "foreign_payload_too_large"));
    }
    // This borrowed selector skips other values without materializing their strings/arrays.
    // The selected owning codec below then checks original I-JSON, depth and every field.
    let selector: Kind<'_> =
        serde_json::from_slice(bytes).map_err(|_| failure(400, "foreign_invalid_frame"))?;
    let peer = peer_uri.and_then(|uri| ramflux_node_core::parse_mesh_spiffe_uri(uri).ok());
    let own = path == wire::FOREIGN_PATH;
    match selector.kind.as_ref() {
        "query" => {
            let request: PeerQueryRequest =
                wire::decode(bytes, 8192).map_err(|_| failure(400, "foreign_invalid_frame"))?;
            request.validate().map_err(|_| failure(400, "foreign_invalid_frame"))?;
            let authorized = peer.as_ref().is_some_and(|peer| {
                if own {
                    peer.node_id == own_node
                        && matches!(peer.service_id.as_str(), "ramflux-router" | "ramflux-gateway")
                        && request.query.source_node == own_node
                } else {
                    peer.service_id == "ramflux-federation"
                        && request.query.source_node == peer.node_id
                        && request.query.target_node == own_node
                }
            });
            if !authorized {
                return Err(failure(403, "foreign_policy_denied"));
            }
            Ok(Request::Query(Box::new(request)))
        }
        "submit" => {
            if !own {
                return Err(failure(400, "foreign_invalid_frame"));
            }
            let request: SourceSubmitRequest = wire::decode(bytes, wire::MAX_FRAME_BYTES)
                .map_err(|_| failure(400, "foreign_invalid_frame"))?;
            request.validate().map_err(|_| failure(400, "foreign_invalid_frame"))?;
            if !peer.as_ref().is_some_and(|peer| {
                peer.node_id == own_node
                    && matches!(peer.service_id.as_str(), "ramflux-router" | "ramflux-gateway")
            }) {
                return Err(failure(403, "foreign_policy_denied"));
            }
            Ok(Request::Submit(Box::new(request)))
        }
        _ => Err(failure(400, "foreign_invalid_frame")),
    }
}

#[cfg(test)]
mod tests;
