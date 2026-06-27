// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![allow(unused_imports)]
#![allow(clippy::wildcard_imports)]
use super::*;

pub(crate) async fn handle_mcp(socket: PathBuf, command: McpCommand) -> Result<(), RfError> {
    let mut bus = LocalBusClient::connect(socket).await?;
    match command.action {
        McpAction::Server(server) => match server.action {
            McpServerAction::Add(add) => {
                let (capability, tool_scope) = parse_mcp_capability(&add.capability)?;
                let request = LocalBusMcpServerAddRequest {
                    server_id: add.server,
                    command: add.command,
                    tool_name: add.tool,
                    capability,
                    tool_scope,
                    risk_level: Some(parse_mcp_risk(&add.risk)?),
                    manifest_version: 1,
                };
                print_json(
                    &bus.request(Some(add.account), "mcp", "mcp.server.add", &request).await?,
                )
            }
            McpServerAction::List(selector) => print_json(
                &bus.request(
                    Some(selector.account),
                    "mcp",
                    "mcp.server.list",
                    &serde_json::json!({}),
                )
                .await?,
            ),
            McpServerAction::Refresh(selector) => print_json(
                &bus.request(
                    Some(selector.account),
                    "mcp",
                    "mcp.server.refresh",
                    &serde_json::json!({}),
                )
                .await?,
            ),
        },
        McpAction::Tool(tool) => match tool.action {
            McpToolAction::List(selector) => print_json(
                &bus.request(
                    Some(selector.account),
                    "mcp",
                    "mcp.tool.list",
                    &serde_json::json!({}),
                )
                .await?,
            ),
            McpToolAction::Call(call) => {
                let request = LocalBusMcpToolCallRequest {
                    server_id: call.server,
                    tool_name: call.tool,
                    arguments: serde_json::from_str(&call.args_json)?,
                    operation_origin: Some("ai_mcp".to_owned()),
                };
                print_json(
                    &bus.request(Some(call.account), "mcp", "mcp.tool.started", &request).await?,
                )
            }
        },
        McpAction::Approval(approval) => handle_mcp_approval(&mut bus, approval).await,
    }
}

async fn handle_mcp_approval(
    bus: &mut LocalBusClient,
    approval: McpApprovalCommand,
) -> Result<(), RfError> {
    match approval.action {
        McpApprovalAction::List(selector) => print_json(
            &bus.request(
                Some(selector.account),
                "mcp",
                "mcp.approval.list",
                &serde_json::json!({}),
            )
            .await?,
        ),
        McpApprovalAction::Show(selector) => {
            let value = bus
                .request(Some(selector.account), "mcp", "mcp.approval.list", &serde_json::json!({}))
                .await?;
            print_json(&crate::handlers::grant::rf_select_record(
                &value,
                "approvals",
                "approval_id",
                &selector.approval,
                "approval",
            )?)
        }
        McpApprovalAction::Approve(selector) => {
            let request = LocalBusMcpApprovalDecisionRequest { approval_id: selector.approval };
            print_json(
                &bus.request(Some(selector.account), "grant", "grant.approve", &request).await?,
            )
        }
        McpApprovalAction::Deny(selector) => {
            let request = LocalBusMcpApprovalDecisionRequest { approval_id: selector.approval };
            print_json(&bus.request(Some(selector.account), "grant", "grant.deny", &request).await?)
        }
    }
}
