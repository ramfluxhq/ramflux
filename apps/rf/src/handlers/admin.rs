// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![allow(unused_imports)]
#![allow(clippy::wildcard_imports)]
use super::*;

pub(crate) fn handle_admin(command: AdminCommand) -> Result<(), RfError> {
    match command.action {
        AdminAction::Federation(command) => handle_admin_federation(command),
    }
}

pub(crate) fn handle_admin_federation(command: AdminFederationCommand) -> Result<(), RfError> {
    match command.action {
        AdminFederationAction::Peer(peer) => {
            let now = peer.now.unwrap_or_else(rf_now_unix_timestamp_u64);
            let a_to_b = rf_admin_federation_peer(
                &peer.node_a_admin_url,
                &peer.node_a_token,
                &peer.node_b_id,
                &peer.node_b_well_known_url,
                &peer.capabilities,
                now,
            )?;
            let b_to_a = rf_admin_federation_peer(
                &peer.node_b_admin_url,
                &peer.node_b_token,
                &peer.node_a_id,
                &peer.node_a_well_known_url,
                &peer.capabilities,
                now,
            )?;
            print_json(&serde_json::json!({
                "node_a": peer.node_a_id,
                "node_b": peer.node_b_id,
                "a_to_b": a_to_b,
                "b_to_a": b_to_a,
            }))
        }
    }
}

pub(crate) fn rf_admin_federation_peer(
    admin_url: &str,
    token: &str,
    peer_node_id: &str,
    peer_well_known_url: &str,
    capabilities: &[String],
    now: u64,
) -> Result<serde_json::Value, RfError> {
    rf_http_post_json(
        admin_url,
        "/admin/federation/peer",
        &serde_json::json!({
            "admin_token": token,
            "peer_node_id": peer_node_id,
            "peer_well_known_url": peer_well_known_url,
            "capabilities": capabilities,
            "now": now,
        }),
    )
}
