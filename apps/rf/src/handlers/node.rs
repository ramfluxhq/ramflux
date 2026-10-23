// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use crate::RfError;
use crate::cli::{NodeAction, NodeCommand};
use crate::utils::print_json;
use ramflux_sdk::LocalBusClient;
use std::path::PathBuf;

pub(crate) async fn handle_node(socket: PathBuf, command: NodeCommand) -> Result<(), RfError> {
    let (method, body) = match command.action {
        NodeAction::Add(add) => {
            ("node.add", serde_json::json!({"url": add.url, "refresh": add.refresh}))
        }
        NodeAction::Confirm(confirm) => (
            "node.confirm",
            serde_json::json!({"node_id": confirm.node_id, "pin_source": confirm.pin_source, "expected_public_key": confirm.expected_public_key}),
        ),
        NodeAction::List => ("node.list", serde_json::json!({})),
        NodeAction::Probe(node) => ("node.probe", serde_json::json!({"node_id": node.node_id})),
        NodeAction::Remove(node) => ("node.remove", serde_json::json!({"node_id": node.node_id})),
        NodeAction::SetDefault(node) => {
            ("node.set_default", serde_json::json!({"node_id": node.node_id}))
        }
        NodeAction::Enable(node) => {
            ("node.set_enabled", serde_json::json!({"node_id": node.node_id, "enabled": true}))
        }
        NodeAction::Disable(node) => {
            ("node.set_enabled", serde_json::json!({"node_id": node.node_id, "enabled": false}))
        }
    };
    let mut bus = LocalBusClient::connect(socket).await?;
    print_json(&bus.request(None, "node", method, &body).await?)
}
