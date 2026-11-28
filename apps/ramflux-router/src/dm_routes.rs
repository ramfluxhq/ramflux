// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Mesh routes of the MLS DM track (MLS-SPEC 3.1, 3.5): `dm_order` calls and the key package
//! store. The gateway authenticated the device before it calls; a pinned peer reaches
//! `dm_order` only through its own federation service, which verified the peer signature.
use ramflux_node_core::{
    DM_ORDER_FORWARD_PATH, DM_ORDER_INBOUND_PATH, DM_ORDER_ROUTER_PATH, DmCaller, DmOrderCall,
    DmOrderForward, DmOrderInbound, KEY_PACKAGE_FETCH_PATH, KEY_PACKAGE_PUBLISH_PATH,
    KEY_PACKAGE_STATUS_PATH, KeyPackageFetchCall, KeyPackagePublishCall, KeyPackageStatusCall,
};

use crate::handlers::MeshResponse;
use crate::router_runtime::RouterHandle;

const GATEWAY: &str = "ramflux-gateway";
const FEDERATION: &str = "ramflux-federation";

fn reply(value: &impl serde::Serialize) -> anyhow::Result<MeshResponse> {
    Ok(MeshResponse::json("200 OK", serde_json::to_vec(value)?))
}

fn refusal(status: &'static str, text: &str) -> MeshResponse {
    MeshResponse::text(status, text)
}

/// Dispatch a DM-track mesh POST. Other paths return `None`.
///
/// # Errors
/// Database and encoding failures.
pub(crate) fn route(
    peer_service_id: &str,
    method: &str,
    path: &str,
    body: &[u8],
    router: &RouterHandle,
) -> anyhow::Result<Option<MeshResponse>> {
    let allowed: &[&str] = match path {
        DM_ORDER_ROUTER_PATH | KEY_PACKAGE_PUBLISH_PATH | KEY_PACKAGE_STATUS_PATH => &[GATEWAY],
        DM_ORDER_INBOUND_PATH => &[FEDERATION],
        KEY_PACKAGE_FETCH_PATH => &[GATEWAY, FEDERATION],
        _ => return Ok(None),
    };
    if method != "POST" {
        return Ok(Some(refusal("405 Method Not Allowed", "method not allowed")));
    }
    if !allowed.contains(&peer_service_id) {
        return Ok(Some(refusal("403 Forbidden", "route requires an admitted caller")));
    }
    let now = ramflux_node_core::now_unix_seconds();
    let response = match path {
        DM_ORDER_ROUTER_PATH => dm_order(body, router, now),
        DM_ORDER_INBOUND_PATH => dm_order_inbound(body, router, now),
        KEY_PACKAGE_PUBLISH_PATH => key_package_publish(body, router, now),
        KEY_PACKAGE_STATUS_PATH => key_package_status(body, router, now),
        _ => key_package_fetch(body, router, peer_service_id, now),
    };
    response.map(Some)
}

fn dm_order(body: &[u8], router: &RouterHandle, now: u64) -> anyhow::Result<MeshResponse> {
    let Ok(call) = ramflux_protocol::parse_i_json::<DmOrderCall>(body) else {
        return Ok(refusal("400 Bad Request", "request rejected"));
    };
    let Some(target) = call.orderer_node.filter(|node| node != router.node_id()) else {
        let caller = DmCaller { anchor: &call.anchor, origin_node: router.node_id() };
        let reply_value = router.dm_order().handle(router.store(), &caller, &call.op, now)?;
        return reply(&reply_value);
    };
    // The submitter's home (this node) already authenticated the device; the orderer node is
    // another node, reached through the same-node federation service (`DM_ORDER_FORWARD_PATH`).
    let forward = DmOrderForward { target_node: target, anchor: call.anchor, op: call.op };
    match router.forward_dm_order(&forward) {
        Ok(response) => reply(&response.reply),
        Err(error) => {
            tracing::warn!(%error, path = DM_ORDER_FORWARD_PATH, "dm_order orderer unreachable");
            Ok(refusal("502 Bad Gateway", "orderer unreachable"))
        }
    }
}

fn dm_order_inbound(body: &[u8], router: &RouterHandle, now: u64) -> anyhow::Result<MeshResponse> {
    let Ok(call) = ramflux_protocol::parse_i_json::<DmOrderInbound>(body) else {
        return Ok(refusal("400 Bad Request", "request rejected"));
    };
    let caller = DmCaller { anchor: &call.anchor, origin_node: &call.origin_node };
    reply(&router.dm_order().handle(router.store(), &caller, &call.op, now)?)
}

fn key_package_publish(
    body: &[u8],
    router: &RouterHandle,
    now: u64,
) -> anyhow::Result<MeshResponse> {
    let Ok(call) = ramflux_protocol::parse_i_json::<KeyPackagePublishCall>(body) else {
        return Ok(refusal("400 Bad Request", "request rejected"));
    };
    reply(&router.store().key_package_publish(&call.anchor, &call.device_id, &call.request, now)?)
}

fn key_package_status(
    body: &[u8],
    router: &RouterHandle,
    now: u64,
) -> anyhow::Result<MeshResponse> {
    let Ok(call) = ramflux_protocol::parse_i_json::<KeyPackageStatusCall>(body) else {
        return Ok(refusal("400 Bad Request", "request rejected"));
    };
    reply(&router.store().key_package_status(&call.anchor, &call.device_id, now)?)
}

fn key_package_fetch(
    body: &[u8],
    router: &RouterHandle,
    peer_service_id: &str,
    now: u64,
) -> anyhow::Result<MeshResponse> {
    let Ok(call) = ramflux_protocol::parse_i_json::<KeyPackageFetchCall>(body) else {
        return Ok(refusal("400 Bad Request", "request rejected"));
    };
    // Only the gateway authenticates a requester; the public endpoint limits its own addresses.
    let requester = (peer_service_id == GATEWAY).then_some(call.requester.as_deref()).flatten();
    if let Err(retry_after) = router.key_package_limits().admit(None, requester, now) {
        return Ok(MeshResponse::json(
            "429 Too Many Requests",
            serde_json::to_vec(&serde_json::json!({ "retry_after": retry_after }))?,
        ));
    }
    reply(&router.store().key_package_fetch(&call.anchor, now)?)
}
