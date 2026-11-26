// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Device policy, activity and in-band clear from authenticated device sessions (CENTRAL
//! K9-K12). The gateway only authenticates the control, derives the opaque account group and
//! forwards to notify over the mesh; policy state never leaves the node.

use crate::{GatewayQuicContext, GatewaySessionRuntime};
use sha2::{Digest, Sha256};

/// Opaque per-account group: first 32 hex chars of
/// `SHA-256("ramflux.notify.account_group.v1" || 0x00 || principal_id)`.
pub(crate) fn account_group(principal_id: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"ramflux.notify.account_group.v1");
    hasher.update([0_u8]);
    hasher.update(principal_id.as_bytes());
    hasher.finalize().iter().take(16).fold(String::with_capacity(32), |mut hex, byte| {
        // Writing to a String cannot fail.
        let _ = std::fmt::Write::write_fmt(&mut hex, format_args!("{byte:02x}"));
        hex
    })
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX))
}

async fn post_notify<T: serde::Serialize, R: serde::de::DeserializeOwned>(
    context: &GatewayQuicContext,
    path: &str,
    body: &T,
) -> anyhow::Result<R> {
    if let Some(mesh) = &context.notify.mesh {
        Ok(ramflux_transport::mesh_quic_post_json_with_peer_ca_pems_async(
            &mesh.endpoint,
            path,
            &mesh.tls,
            &mesh.server_name,
            &mesh.peer_ca_pems,
            body,
        )
        .await?)
    } else {
        Ok(ramflux_node_core::itest_http_post_json(
            &format!("{}{path}", context.notify.endpoint),
            body,
        )?)
    }
}

#[derive(serde::Serialize)]
struct DevicePolicyBody {
    device_delivery_id: String,
    account_group: String,
    device_class: ramflux_node_core::DeviceClass,
    muted: bool,
    at_ms: u64,
}

#[derive(serde::Serialize)]
struct ActivityBody {
    device_delivery_id: String,
    at_ms: u64,
}

#[derive(serde::Serialize)]
struct ClearPlanBody {
    device_delivery_id: String,
}

#[derive(serde::Deserialize)]
struct ClearPlanReply {
    account_group: String,
    peers: Vec<ClearPeer>,
}

#[derive(serde::Deserialize)]
struct ClearPeer {
    device_delivery_id: String,
    muted: bool,
}

#[derive(serde::Serialize)]
struct ClearBody {
    device_delivery_id: String,
    account_group: String,
    at_ms: u64,
    live_cleared: Vec<String>,
}

/// `device.push_policy.set`: record this device's class and mute at the home node.
pub(crate) async fn handle_device_policy(
    context: &GatewayQuicContext,
    runtime: &GatewaySessionRuntime,
    device_class: ramflux_node_core::DeviceClass,
    muted: bool,
) -> anyhow::Result<()> {
    let body = DevicePolicyBody {
        device_delivery_id: runtime.target_delivery_id.clone(),
        account_group: account_group(&runtime.principal_id),
        device_class,
        muted,
        at_ms: now_ms(),
    };
    let _ack: serde_json::Value = post_notify(context, "/s13/notify/device-policy", &body).await?;
    Ok(())
}

/// `device.activity.report`: this device is active now (K10).
pub(crate) async fn handle_activity(
    context: &GatewayQuicContext,
    runtime: &GatewaySessionRuntime,
) -> anyhow::Result<()> {
    let body =
        ActivityBody { device_delivery_id: runtime.target_delivery_id.clone(), at_ms: now_ms() };
    let _ack: serde_json::Value = post_notify(context, "/s13/notify/activity", &body).await?;
    Ok(())
}

/// `device.notifications.cleared`: the read fan-out (K12). Live unmuted peers get the in-band
/// frame and count as `clears_conn`; the node writes `x` rows only for the others.
pub(crate) async fn handle_notifications_cleared(
    context: &GatewayQuicContext,
    runtime: &GatewaySessionRuntime,
) -> anyhow::Result<()> {
    let device = runtime.target_delivery_id.clone();
    let plan: Option<ClearPlanReply> = post_notify(
        context,
        "/s13/notify/clear-plan",
        &ClearPlanBody { device_delivery_id: device.clone() },
    )
    .await?;
    let Some(plan) = plan else {
        return Ok(());
    };
    let mut live_cleared = Vec::new();
    for peer in plan.peers.iter().filter(|peer| !peer.muted) {
        let frame = ramflux_node_core::GatewayServerFrame::NotificationsCleared {};
        if context.hub.send_delivery(&peer.device_delivery_id, &frame, None).await {
            live_cleared.push(peer.device_delivery_id.clone());
        }
    }
    let _outcome: serde_json::Value = post_notify(
        context,
        "/s13/notify/clear",
        &ClearBody {
            device_delivery_id: device,
            account_group: plan.account_group,
            at_ms: now_ms(),
            live_cleared,
        },
    )
    .await?;
    Ok(())
}
