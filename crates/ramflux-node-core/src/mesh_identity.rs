use std::collections::BTreeSet;

use crate::NodeCoreError;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MeshPeerIdentity {
    pub node_id: String,
    pub service_id: String,
    pub spiffe_uri: String,
}

/// # Errors
/// Returns an error when the URI is not a Ramflux SPIFFE service identity.
pub fn parse_mesh_spiffe_uri(spiffe_uri: &str) -> Result<MeshPeerIdentity, NodeCoreError> {
    let Some(rest) = spiffe_uri.strip_prefix("spiffe://") else {
        return Err(NodeCoreError::ItestHttp("peer certificate SAN is not SPIFFE".to_owned()));
    };
    let Some((node_id, service_id)) = rest.split_once('/') else {
        return Err(NodeCoreError::ItestHttp("peer SPIFFE SAN missing service path".to_owned()));
    };
    if node_id.is_empty() || service_id.is_empty() || !service_id.starts_with("ramflux-") {
        return Err(NodeCoreError::ItestHttp(
            "peer SPIFFE SAN is not a Ramflux service".to_owned(),
        ));
    }
    Ok(MeshPeerIdentity {
        node_id: node_id.to_owned(),
        service_id: service_id.to_owned(),
        spiffe_uri: spiffe_uri.to_owned(),
    })
}

/// # Errors
/// Returns an error when the peer SAN is missing, not whitelisted, or not authorized by the
/// service-to-service matrix.
pub fn authorize_mesh_peer(
    local_service_id: &str,
    allowed_service_ids: &BTreeSet<String>,
    peer_spiffe_uri: Option<&str>,
) -> Result<MeshPeerIdentity, NodeCoreError> {
    let spiffe_uri = peer_spiffe_uri.ok_or_else(|| {
        NodeCoreError::ItestHttp("peer certificate missing SPIFFE SAN".to_owned())
    })?;
    let peer = parse_mesh_spiffe_uri(spiffe_uri)?;
    if !allowed_service_ids.contains(&peer.service_id) {
        return Err(NodeCoreError::MeshPeerUnauthorized {
            local_service_id: local_service_id.to_owned(),
            peer_spiffe_uri: peer.spiffe_uri,
        });
    }
    if !service_matrix_allows(local_service_id, &peer.service_id) {
        return Err(NodeCoreError::MeshPeerUnauthorized {
            local_service_id: local_service_id.to_owned(),
            peer_spiffe_uri: peer.spiffe_uri,
        });
    }
    Ok(peer)
}

#[must_use]
pub fn service_matrix_allows(local_service_id: &str, peer_service_id: &str) -> bool {
    match local_service_id {
        "ramflux-gateway" => {
            matches!(peer_service_id, "ramflux-router" | "ramflux-notify" | "ramflux-retention")
        }
        "ramflux-router" => matches!(
            peer_service_id,
            "ramflux-gateway"
                | "ramflux-notify"
                | "ramflux-federation"
                | "ramflux-relay"
                | "ramflux-retention"
        ),
        "ramflux-notify" => {
            matches!(peer_service_id, "ramflux-gateway" | "ramflux-router" | "ramflux-retention")
        }
        "ramflux-federation" => matches!(peer_service_id, "ramflux-router" | "ramflux-retention"),
        "ramflux-relay" => matches!(peer_service_id, "ramflux-router" | "ramflux-retention"),
        "ramflux-signaling" => {
            matches!(peer_service_id, "ramflux-gateway" | "ramflux-router" | "ramflux-retention")
        }
        "ramflux-retention" => matches!(
            peer_service_id,
            "ramflux-gateway"
                | "ramflux-router"
                | "ramflux-notify"
                | "ramflux-relay"
                | "ramflux-signaling"
                | "ramflux-federation"
        ),
        _ => false,
    }
}
