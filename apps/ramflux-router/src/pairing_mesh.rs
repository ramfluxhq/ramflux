// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Federation→router pairing mesh. Tokens relay SAS bytes; the node owns the store.
use ramflux_node_core::pairing_relay::{
    PairingMeshForward, PairingMeshReply, encode_pairing_mesh_body, handle_pairing_mesh,
    is_pairing_path,
};

use crate::handlers::MeshResponse;
use crate::router_runtime::RouterHandle;

const FEDERATION_SERVICE_ID: &str = "ramflux-federation";

/// Dispatch a pairing mesh POST. Other paths return `None`.
/// # Errors
/// Returns JSON encoding failures from the mesh reply.
pub(crate) fn route(
    peer_service_id: &str,
    method: &str,
    path: &str,
    body: &[u8],
    router: &RouterHandle,
) -> anyhow::Result<Option<MeshResponse>> {
    if !is_pairing_path(path) {
        return Ok(None);
    }
    if peer_service_id != FEDERATION_SERVICE_ID {
        return Ok(Some(MeshResponse {
            status: "403 Forbidden",
            content_type: "text/plain; charset=utf-8",
            body: b"pairing mesh requires federation peer".to_vec(),
            keep_alive: true,
        }));
    }
    if method != "POST" {
        return Ok(Some(mesh_reply("405 Method Not Allowed", b"method not allowed")?));
    }
    if !ramflux_node_core::device_pairing_enabled()? {
        return Ok(Some(mesh_reply("404 Not Found", b"not found")?));
    }
    let Some(store) = router.pairing_relay() else {
        return Ok(Some(mesh_reply("503 Service Unavailable", b"service unavailable")?));
    };
    let Ok(forward) = serde_json::from_slice::<PairingMeshForward>(body) else {
        return Ok(Some(mesh_reply("400 Bad Request", b"request rejected")?));
    };
    let reply = handle_pairing_mesh(&store, path, &forward);
    Ok(Some(MeshResponse {
        status: "200 OK",
        content_type: "application/json",
        body: serde_json::to_vec(&reply)?,
        keep_alive: true,
    }))
}

fn mesh_reply(status: &str, body: &[u8]) -> anyhow::Result<MeshResponse> {
    Ok(MeshResponse {
        status: "200 OK",
        content_type: "application/json",
        body: serde_json::to_vec(&PairingMeshReply {
            status: status.to_owned(),
            body: encode_pairing_mesh_body(body),
        })?,
        keep_alive: true,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ramflux_node_core::pairing_relay::PAIRING_CLAIM_PATH;

    #[test]
    fn pairing_mesh_requires_federation_peer() -> anyhow::Result<()> {
        let (state, store, path) = crate::router_runtime::tests::test_router("pairing-mesh-peer")?;
        let handle = RouterHandle::tokio(state, store, None);
        let response = route("ramflux-gateway", "POST", PAIRING_CLAIM_PATH, b"{}", &handle)?
            .ok_or_else(|| anyhow::anyhow!("pairing mesh route"))?;
        assert_eq!(response.status, "403 Forbidden");
        let _ = std::fs::remove_file(path);
        Ok(())
    }
}
