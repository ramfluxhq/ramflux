// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Own-account/public-snapshot proxy hops are trusted only within this node's service identity.
use super::MeshResponse;
use ramflux_node_core::MeshPeerIdentity;
use ramflux_protocol::contact_reach::{
    FOREIGN_PATH, ISSUER_COST_PATH, RECIPIENT_PATH, SNAPSHOT_PATH,
};
fn allowed(method: &str, path: &str, own_node: &str, peer: &MeshPeerIdentity) -> Option<bool> {
    let role = match path {
        RECIPIENT_PATH => peer.service_id == "ramflux-gateway",
        SNAPSHOT_PATH | ISSUER_COST_PATH | "/internal/contact/forward/v1" => {
            peer.service_id == "ramflux-federation"
        }
        FOREIGN_PATH => matches!(peer.service_id.as_str(), "ramflux-gateway" | "ramflux-router"),
        _ => return None,
    };
    Some(method == "POST" && peer.node_id == own_node && role)
}
pub(super) fn guard(
    method: &str,
    path: &str,
    own_node: &str,
    peer: &MeshPeerIdentity,
) -> Option<MeshResponse> {
    (allowed(method, path, own_node, peer) == Some(false)).then(|| {
        MeshResponse::text(
            "403 Forbidden",
            "contact hop requires the node's own authorized service identity",
        )
    })
}
pub(super) fn route(
    method: &str,
    path: &str,
    body: &[u8],
    router: &crate::router_runtime::RouterHandle,
    received: std::time::Instant,
) -> anyhow::Result<Option<MeshResponse>> {
    if method == "POST" && path == "/internal/contact/forward/v1" {
        let Ok(forward) = ramflux_node_core::contact_reach::ReachForward::decode(body) else {
            return Ok(Some(MeshResponse::json(
                "400 Bad Request",
                br#"{"frame_type":"contact_foreign_error","reason":"foreign_invalid_frame"}"#
                    .to_vec(),
            )));
        };
        let result = router.contact_forward(&forward, received);
        ramflux_protocol::contact_reach::validate_receiving_result(&result)?;
        return Ok(Some(MeshResponse::json(
            "200 OK",
            ramflux_protocol::canonical_json_bytes(&result)?,
        )));
    }
    if method == "POST" && path == ISSUER_COST_PATH {
        use ramflux_protocol::contact_reach::{self as wire, OperationResult, Reason};
        let mut request: wire::CostRequest =
            match wire::decode(body, wire::MAX_COST_REQUEST_BYTES) {
                Ok(request) => request,
                Err(_) => return Ok(Some(MeshResponse::json(
                    "400 Bad Request",
                    br#"{"frame_type":"contact_foreign_error","reason":"foreign_invalid_frame"}"#
                        .to_vec(),
                ))),
            };
        if request.validate().is_err() {
            return Ok(Some(MeshResponse::json(
                "400 Bad Request",
                br#"{"frame_type":"contact_foreign_error","reason":"foreign_invalid_frame"}"#
                    .to_vec(),
            )));
        }
        let elapsed = u64::try_from(received.elapsed().as_millis()).unwrap_or(u64::MAX);
        request.remaining_ms = request.remaining_ms.saturating_sub(elapsed);
        let response = if request.remaining_ms == 0 {
            wire::CostResponse {
                request_id: request.request_id,
                result: OperationResult::Error {
                    reason: Reason::ForeignUnavailable,
                    retry_after_ms: None,
                    current_revision: None,
                },
            }
        } else {
            router.contact_cost(&request)?
        };
        return Ok(Some(MeshResponse::json(
            "200 OK",
            ramflux_protocol::canonical_json_bytes(&response)?,
        )));
    }
    if method == "POST" && path == ramflux_protocol::contact_reach::SNAPSHOT_PATH {
        let mut request: ramflux_protocol::contact_reach::PeerQueryRequest =
            match ramflux_protocol::contact_reach::decode(body, 8192) {
                Ok(value) => value,
                Err(_) => return Ok(Some(MeshResponse::json(
                    "400 Bad Request",
                    br#"{"frame_type":"contact_foreign_error","reason":"foreign_invalid_frame"}"#
                        .to_vec(),
                ))),
            };
        if request.validate().is_err() {
            return Ok(Some(MeshResponse::json(
                "400 Bad Request",
                br#"{"frame_type":"contact_foreign_error","reason":"foreign_invalid_frame"}"#
                    .to_vec(),
            )));
        }
        let elapsed = u64::try_from(received.elapsed().as_millis()).unwrap_or(u64::MAX);
        request.remaining_ms = request.remaining_ms.saturating_sub(elapsed);
        if request.remaining_ms == 0 {
            return Ok(Some(MeshResponse::text(
                "504 Gateway Timeout",
                "contact query deadline exceeded",
            )));
        }
        return Ok(Some(MeshResponse::json(
            "200 OK",
            serde_json::to_vec(&router.contact_snapshot(&request)?)?,
        )));
    }

    if method == "POST" && path == ramflux_protocol::contact_reach::RECIPIENT_PATH {
        let request = ramflux_protocol::contact_reach::decode(
            body,
            ramflux_protocol::contact_reach::MAX_FRAME_BYTES,
        )?;
        return Ok(Some(MeshResponse::json(
            "200 OK",
            serde_json::to_vec(&router.contact_owner(&request))?,
        )));
    }

    Ok(None)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cr_foreign_service_name_cannot_enter_own_contact_hops() -> anyhow::Result<()> {
        for (path, role) in [
            (RECIPIENT_PATH, "ramflux-gateway"),
            (SNAPSHOT_PATH, "ramflux-federation"),
            (ISSUER_COST_PATH, "ramflux-federation"),
            ("/internal/contact/forward/v1", "ramflux-federation"),
            (FOREIGN_PATH, "ramflux-router"),
        ] {
            let own =
                ramflux_node_core::parse_mesh_spiffe_uri(&format!("spiffe://own.example/{role}"))?;
            let foreign = ramflux_node_core::parse_mesh_spiffe_uri(&format!(
                "spiffe://foreign.example/{role}"
            ))?;
            assert_eq!(
                allowed("POST", path, "own.example", &own),
                Some(true),
                "the configured local service must retain its own hop"
            );
            assert_eq!(
                allowed("POST", path, "own.example", &foreign),
                Some(false),
                "an otherwise valid foreign certificate with the same service name has no owner-hop authority"
            );
            assert_eq!(
                allowed("GET", path, "own.example", &own),
                Some(false),
                "these closed carriers have no alternate GET operation"
            );
        }
        let wrong =
            ramflux_node_core::parse_mesh_spiffe_uri("spiffe://own.example/ramflux-retention")?;
        assert_eq!(
            allowed("POST", RECIPIENT_PATH, "own.example", &wrong),
            Some(false),
            "being local is insufficient without the authorized service role"
        );
        Ok(())
    }
}
