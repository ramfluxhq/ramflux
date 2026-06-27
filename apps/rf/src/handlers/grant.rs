// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![allow(unused_imports)]
#![allow(clippy::wildcard_imports)]
use super::*;

pub(crate) async fn handle_grant(socket: PathBuf, command: GrantCommand) -> Result<(), RfError> {
    let mut bus = LocalBusClient::connect(socket).await?;
    match command.action {
        GrantAction::List(selector) => print_json(
            &bus.request(Some(selector.account), "grant", "grant.list", &serde_json::json!({}))
                .await?,
        ),
        GrantAction::Show(selector) => {
            let value = bus
                .request(Some(selector.account), "grant", "grant.list", &serde_json::json!({}))
                .await?;
            print_json(&rf_select_record(&value, "grants", "grant_id", &selector.grant, "grant")?)
        }
        GrantAction::Audit(selector) => print_json(
            &bus.request(Some(selector.account), "mcp", "mcp.audit.list", &serde_json::json!({}))
                .await?,
        ),
        GrantAction::Approve(selector) => {
            rf_guard_local_approval(&mut bus, &selector.account, &selector.approval).await?;
            let request = LocalBusMcpApprovalDecisionRequest { approval_id: selector.approval };
            print_json(
                &bus.request(Some(selector.account), "grant", "grant.approve", &request).await?,
            )
        }
        GrantAction::Deny(selector) => {
            let request = LocalBusMcpApprovalDecisionRequest { approval_id: selector.approval };
            print_json(&bus.request(Some(selector.account), "grant", "grant.deny", &request).await?)
        }
        GrantAction::Request(request) => {
            let (capability, tool_scope) = match request.capability.as_deref() {
                Some(value) => {
                    let (capability, scope) = parse_mcp_capability(value)?;
                    (Some(capability), scope)
                }
                None => (None, None),
            };
            let body = LocalBusGrantRequest {
                grant_id: request.grant,
                server_id: request.server,
                tool_name: request.tool,
                capability,
                tool_scope,
                full_delegation: request.full_delegation,
            };
            print_json(&bus.request(Some(request.account), "grant", "grant.request", &body).await?)
        }
        GrantAction::Revoke(revoke) => {
            let body = LocalBusGrantRevokeRequest { grant_id: revoke.grant };
            print_json(&bus.request(Some(revoke.account), "grant", "grant.revoke", &body).await?)
        }
    }
}

/// Refuses to finalize an approval that requires App-side signing.
///
/// Mirrors the TUI gate (cli-pro `app.rs` `decide_selected_approval`): a `remote_app`
/// approval must be signed on the App, so a LOCAL `rf` approve must not fail open.
/// The approval is fetched first to read its `confirmation_mode`; a missing field is
/// treated as `remote_app` to stay fail-closed (matching the TUI parser default).
///
/// # Errors
/// Returns an error when the approval cannot be fetched, is not found, or when its
/// `confirmation_mode` is `remote_app`.
pub(crate) async fn rf_guard_local_approval(
    bus: &mut LocalBusClient,
    account: &str,
    approval_id: &str,
) -> Result<(), RfError> {
    let value = bus
        .request(Some(account.to_owned()), "mcp", "mcp.approval.list", &serde_json::json!({}))
        .await?;
    let approval = rf_select_record(&value, "approvals", "approval_id", approval_id, "approval")?;
    let confirmation_mode = approval
        .get("confirmation_mode")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("remote_app");
    if confirmation_mode == "remote_app" {
        return Err(RfError::Message(format!(
            "approval {approval_id} requires app-side signing (remote_app)"
        )));
    }
    Ok(())
}

pub(crate) fn rf_select_record(
    value: &serde_json::Value,
    array_key: &str,
    id_key: &str,
    id_value: &str,
    label: &str,
) -> Result<serde_json::Value, RfError> {
    let records = value
        .get(array_key)
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| RfError::Message(format!("{label} list response missing {array_key}")))?;
    records
        .iter()
        .find(|record| record.get(id_key).and_then(serde_json::Value::as_str) == Some(id_value))
        .cloned()
        .ok_or_else(|| RfError::Message(format!("{label} not found: {id_value}")))
}
