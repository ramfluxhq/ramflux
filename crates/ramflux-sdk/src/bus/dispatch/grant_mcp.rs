// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![allow(clippy::missing_errors_doc)]
#![allow(clippy::wildcard_imports)]
use crate::prelude::*;

pub(crate) const MCP_GRANT_TTL_SECONDS: i64 = 86_400;
const MCP_STANDING_APPROVAL_TTL_SECONDS: i64 = 30 * 24 * 60 * 60;

pub(crate) fn dispatch_mcp_bus_request(
    request: &LocalBusFrame,
    state: &mut LocalBusDaemonState,
    connection: &mut LocalBusConnectionState,
) -> Result<LocalBusDispatchResult, SdkError> {
    let account_id = request_account_id(request)?;
    match request.method.as_str() {
        "mcp.server.add" => {
            let body: LocalBusMcpServerAddRequest = serde_json::from_value(request.body.clone())?;
            let account = local_bus_account_mut(state, account_id)?;
            let default_risk = body.capability.default_risk();
            let declared_risk =
                body.risk_level.clone().unwrap_or(default_risk.clone()).max(default_risk);
            let manifest = McpToolManifest {
                server_id: body.server_id.clone(),
                tool_name: body.tool_name,
                capability: body.capability.clone(),
                tool_scope: body.tool_scope,
                declared_risk,
                manifest_version: body.manifest_version,
            };
            account.mcp_registry.install_tool(manifest.clone());
            persist_mcp_tool(account, &manifest)?;
            Ok(local_bus_ok(serde_json::json!({
                "server_id": body.server_id,
                "command": body.command,
                "registry_hash": account.mcp_registry.registry_hash(),
                "tool_manifest_set_hash": account.mcp_registry.tool_manifest_set_hash(),
            })))
        }
        "mcp.server.list" => {
            let account = local_bus_account(state, account_id)?;
            let servers = account
                .mcp_registry
                .tools()
                .into_iter()
                .map(|tool| tool.server_id)
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect::<Vec<_>>();
            Ok(local_bus_ok(serde_json::json!({ "servers": servers })))
        }
        "mcp.server.refresh" => {
            let account = local_bus_account(state, account_id)?;
            Ok(local_bus_ok(serde_json::json!({
                "registry_hash": account.mcp_registry.registry_hash(),
                "tool_manifest_set_hash": account.mcp_registry.tool_manifest_set_hash(),
            })))
        }
        "mcp.tool.list" => {
            let account = local_bus_account(state, account_id)?;
            Ok(local_bus_ok(serde_json::json!({
                "registry_hash": account.mcp_registry.registry_hash(),
                "tool_manifest_set_hash": account.mcp_registry.tool_manifest_set_hash(),
                "tools": account.mcp_registry.tools(),
            })))
        }
        "mcp.tool.started" => {
            let body: LocalBusMcpToolCallRequest = serde_json::from_value(request.body.clone())?;
            dispatch_mcp_tool_call(request, state, connection, account_id, &body)
        }
        "mcp.approval.list" => {
            let account = local_bus_account(state, account_id)?;
            Ok(local_bus_ok(serde_json::json!({
                "approvals": super::task_approval::list(account)?,
            })))
        }
        "mcp.approval.granted" => {
            dispatch_mcp_approval_granted(request, state, connection, account_id)
        }
        "mcp.approval.denied" => {
            dispatch_mcp_approval_denied(request, state, connection, account_id)
        }
        "mcp.audit.list" => {
            let account = local_bus_account(state, account_id)?;
            Ok(local_bus_ok(
                serde_json::json!({ "audit": account.client.account_db()?.load_mcp_audit::<LocalMcpAuditRecord>()? }),
            ))
        }
        other => Err(SdkError::LocalBus(format!("unsupported local bus method: {other}"))),
    }
}

fn dispatch_mcp_approval_granted(
    request: &LocalBusFrame,
    state: &mut LocalBusDaemonState,
    connection: &mut LocalBusConnectionState,
    account_id: &str,
) -> Result<LocalBusDispatchResult, SdkError> {
    if let Some(result) = super::task_approval::decide(request, state, account_id, true)? {
        return Ok(local_bus_ok(result));
    }
    let account = local_bus_account_mut(state, account_id)?;
    if request.body.get("signature").is_some() {
        let body: LocalBusMcpApprovalGrantRequest = serde_json::from_value(request.body.clone())?;
        let approval =
            account.mcp_pending_approvals.get(&body.approval_id).cloned().ok_or_else(|| {
                SdkError::LocalBus(format!("approval not found: {}", body.approval_id))
            })?;
        let grant = mcp_remote_grant_from_approval(account, approval.clone(), body, None)?;
        let event_body = mcp_approval_granted_event_body(&approval, &grant);
        mcp_emit_lifecycle_event(
            request,
            connection,
            account_id,
            account,
            "mcp.approval.granted",
            event_body,
        )?;
        account.mcp_pending_approvals.remove(&approval.approval_id);
        Ok(local_bus_ok(serde_json::to_value(grant)?))
    } else {
        let body: LocalBusMcpApprovalDecisionRequest =
            serde_json::from_value(request.body.clone())?;
        let approval =
            account.mcp_pending_approvals.remove(&body.approval_id).ok_or_else(|| {
                SdkError::LocalBus(format!("approval not found: {}", body.approval_id))
            })?;
        let grant = mcp_local_grant_from_approval(account, approval.clone())?;
        let event_body = mcp_approval_granted_event_body(&approval, &grant);
        mcp_emit_lifecycle_event(
            request,
            connection,
            account_id,
            account,
            "mcp.approval.granted",
            event_body,
        )?;
        Ok(local_bus_ok(serde_json::to_value(grant)?))
    }
}

fn dispatch_mcp_approval_denied(
    request: &LocalBusFrame,
    state: &mut LocalBusDaemonState,
    connection: &mut LocalBusConnectionState,
    account_id: &str,
) -> Result<LocalBusDispatchResult, SdkError> {
    if let Some(result) = super::task_approval::decide(request, state, account_id, false)? {
        return Ok(local_bus_ok(result));
    }
    let body: LocalBusMcpApprovalDecisionRequest = serde_json::from_value(request.body.clone())?;
    let account = local_bus_account_mut(state, account_id)?;
    let mut approval = account
        .mcp_pending_approvals
        .remove(&body.approval_id)
        .ok_or_else(|| SdkError::LocalBus(format!("approval not found: {}", body.approval_id)))?;
    "denied".clone_into(&mut approval.status);
    account
        .client
        .account_db()?
        .persist_actor_state(&format!("mcp/denied/{}", approval.approval_id), &approval)?;
    let event_body = mcp_approval_denied_event_body(&approval);
    mcp_emit_lifecycle_event(
        request,
        connection,
        account_id,
        account,
        "mcp.approval.denied",
        event_body,
    )?;
    Ok(local_bus_ok(serde_json::to_value(approval)?))
}

pub(crate) fn dispatch_grant_bus_request(
    request: &LocalBusFrame,
    state: &mut LocalBusDaemonState,
    connection: &mut LocalBusConnectionState,
) -> Result<LocalBusDispatchResult, SdkError> {
    let account_id = request_account_id(request)?;
    match request.method.as_str() {
        "grant.list" => {
            let account = local_bus_account(state, account_id)?;
            Ok(local_bus_ok(serde_json::json!({
                "grants": account.mcp_grants.values().collect::<Vec<_>>(),
                "approvals": super::task_approval::list(account)?,
            })))
        }
        "grant.request" => {
            let body: LocalBusGrantRequest = serde_json::from_value(request.body.clone())?;
            dispatch_grant_request(request, state, connection, account_id, &body)
        }
        "grant.revoke" => {
            let body: LocalBusGrantRevokeRequest = serde_json::from_value(request.body.clone())?;
            dispatch_grant_revoke(state, account_id, &body)
        }
        "grant.create_standing_approval" => {
            let body: LocalBusGrantStandingApprovalCreateRequest =
                serde_json::from_value(request.body.clone())?;
            dispatch_standing_approval_create(request, state, connection, account_id, &body)
        }
        "grant.revoke_standing_approval" => {
            let body: LocalBusGrantStandingApprovalRevokeRequest =
                serde_json::from_value(request.body.clone())?;
            dispatch_standing_approval_revoke(request, state, connection, account_id, &body)
        }
        "grant.list_standing_approvals" => dispatch_standing_approval_list(state, account_id),
        "grant.approve" => {
            let body: LocalBusMcpApprovalDecisionRequest =
                serde_json::from_value(request.body.clone())?;
            dispatch_grant_approve(request, state, connection, account_id, &body)
        }
        "grant.deny" => {
            let body: LocalBusMcpApprovalDecisionRequest =
                serde_json::from_value(request.body.clone())?;
            dispatch_grant_deny(request, state, connection, account_id, &body)
        }
        other => Err(SdkError::LocalBus(format!("unsupported local bus method: {other}"))),
    }
}

fn dispatch_grant_request(
    request: &LocalBusFrame,
    state: &mut LocalBusDaemonState,
    connection: &mut LocalBusConnectionState,
    account_id: &str,
    body: &LocalBusGrantRequest,
) -> Result<LocalBusDispatchResult, SdkError> {
    let account = local_bus_account_mut(state, account_id)?;
    let manifest = mcp_manifest_for_grant_request(account, body)?;
    let approval = mcp_create_approval(
        account,
        &manifest,
        false,
        Some(body.grant_id.as_str()),
        body.full_delegation,
        &serde_json::json!({
            "requested_grant": true,
        }),
    )?;
    let event_body = mcp_approval_request_event_body(&approval);
    mcp_emit_lifecycle_event(
        request,
        connection,
        account_id,
        account,
        "mcp.approval.request",
        event_body,
    )?;
    Ok(local_bus_ok(serde_json::json!({
        "status": "approval_required",
        "approval": approval,
    })))
}

fn dispatch_grant_revoke(
    state: &mut LocalBusDaemonState,
    account_id: &str,
    body: &LocalBusGrantRevokeRequest,
) -> Result<LocalBusDispatchResult, SdkError> {
    let account = local_bus_account_mut(state, account_id)?;
    let record = account
        .mcp_grants
        .get_mut(&body.grant_id)
        .ok_or_else(|| SdkError::LocalBus(format!("grant not found: {}", body.grant_id)))?;
    record.state.revoked = true;
    account.client.account_db()?.set_mcp_grant_revoked(&body.grant_id)?;
    Ok(local_bus_ok(serde_json::to_value(record.clone())?))
}

fn dispatch_standing_approval_create(
    request: &LocalBusFrame,
    state: &mut LocalBusDaemonState,
    connection: &mut LocalBusConnectionState,
    account_id: &str,
    body: &LocalBusGrantStandingApprovalCreateRequest,
) -> Result<LocalBusDispatchResult, SdkError> {
    let account = local_bus_account_mut(state, account_id)?;
    let record = mcp_create_standing_approval(account, body)?;
    mcp_emit_lifecycle_event(
        request,
        connection,
        account_id,
        account,
        "mcp.standing_auto_approval.created",
        mcp_standing_approval_created_event_body(&record),
    )?;
    Ok(local_bus_ok(serde_json::to_value(record)?))
}

fn dispatch_standing_approval_revoke(
    request: &LocalBusFrame,
    state: &mut LocalBusDaemonState,
    connection: &mut LocalBusConnectionState,
    account_id: &str,
    body: &LocalBusGrantStandingApprovalRevokeRequest,
) -> Result<LocalBusDispatchResult, SdkError> {
    let account = local_bus_account_mut(state, account_id)?;
    let mut record =
        account.mcp_standing_approvals.get(&body.standing_approval_id).cloned().ok_or_else(
            || {
                SdkError::LocalBus(format!(
                    "standing approval not found: {}",
                    body.standing_approval_id
                ))
            },
        )?;
    record.revoked = true;
    account.client.account_db()?.set_mcp_standing_approval_revoked(&body.standing_approval_id)?;
    account.mcp_standing_approvals.insert(body.standing_approval_id.clone(), record.clone());
    mcp_emit_lifecycle_event(
        request,
        connection,
        account_id,
        account,
        "mcp.standing_auto_approval.revoked",
        mcp_standing_approval_revoked_event_body(&record),
    )?;
    Ok(local_bus_ok(serde_json::to_value(record)?))
}

fn dispatch_standing_approval_list(
    state: &LocalBusDaemonState,
    account_id: &str,
) -> Result<LocalBusDispatchResult, SdkError> {
    let account = local_bus_account(state, account_id)?;
    Ok(local_bus_ok(serde_json::json!({
        "standing_approvals": account.mcp_standing_approvals.values().collect::<Vec<_>>(),
    })))
}

fn dispatch_grant_approve(
    request: &LocalBusFrame,
    state: &mut LocalBusDaemonState,
    connection: &mut LocalBusConnectionState,
    account_id: &str,
    body: &LocalBusMcpApprovalDecisionRequest,
) -> Result<LocalBusDispatchResult, SdkError> {
    if let Some(result) = super::task_approval::decide(request, state, account_id, true)? {
        return Ok(local_bus_ok(result));
    }
    let account = local_bus_account_mut(state, account_id)?;
    let approval = account
        .mcp_pending_approvals
        .remove(&body.approval_id)
        .ok_or_else(|| SdkError::LocalBus(format!("approval not found: {}", body.approval_id)))?;
    let grant = mcp_local_grant_from_approval(account, approval.clone())?;
    let event_body = mcp_approval_granted_event_body(&approval, &grant);
    mcp_emit_lifecycle_event(
        request,
        connection,
        account_id,
        account,
        "mcp.approval.granted",
        event_body,
    )?;
    Ok(local_bus_ok(serde_json::to_value(grant)?))
}

fn dispatch_grant_deny(
    request: &LocalBusFrame,
    state: &mut LocalBusDaemonState,
    connection: &mut LocalBusConnectionState,
    account_id: &str,
    body: &LocalBusMcpApprovalDecisionRequest,
) -> Result<LocalBusDispatchResult, SdkError> {
    if let Some(result) = super::task_approval::decide(request, state, account_id, false)? {
        return Ok(local_bus_ok(result));
    }
    let account = local_bus_account_mut(state, account_id)?;
    let mut approval = account
        .mcp_pending_approvals
        .remove(&body.approval_id)
        .ok_or_else(|| SdkError::LocalBus(format!("approval not found: {}", body.approval_id)))?;
    "denied".clone_into(&mut approval.status);
    let event_body = mcp_approval_denied_event_body(&approval);
    mcp_emit_lifecycle_event(
        request,
        connection,
        account_id,
        account,
        "mcp.approval.denied",
        event_body,
    )?;
    Ok(local_bus_ok(serde_json::to_value(approval)?))
}

pub(crate) fn dispatch_mcp_tool_call(
    request: &LocalBusFrame,
    state: &mut LocalBusDaemonState,
    connection: &mut LocalBusConnectionState,
    account_id: &str,
    body: &LocalBusMcpToolCallRequest,
) -> Result<LocalBusDispatchResult, SdkError> {
    let attended = state.attended_accounts.contains(account_id);
    let account = local_bus_account_mut(state, account_id)?;
    let manifest = mcp_manifest(&account.mcp_registry, &body.server_id, &body.tool_name)
        .ok_or_else(|| {
            SdkError::LocalBus(format!("tool not found: {}/{}", body.server_id, body.tool_name))
        })?;
    let operation_origin = body.operation_origin.clone().unwrap_or_else(|| "ai_mcp".to_owned());
    mcp_emit_lifecycle_event(
        request,
        connection,
        account_id,
        account,
        "mcp.tool.started",
        mcp_tool_started_event_body(account, &manifest, &operation_origin, &body.arguments),
    )?;
    if mcp_full_delegation_blocked_by_risk(account, &manifest) {
        mcp_emit_lifecycle_event(
            request,
            connection,
            account_id,
            account,
            "mcp.tool.failed",
            mcp_tool_failed_event_body(
                account,
                &manifest,
                &operation_origin,
                "CapabilityDenied",
                "high risk tool requires explicit approval",
            ),
        )?;
        return Err(SdkError::CapabilityDenied(
            "high risk tool requires explicit approval".to_owned(),
        ));
    }
    if let Some(grant) = mcp_valid_grant(account, &manifest, &body.arguments) {
        let grant = grant.clone();
        let mut ctx = McpInvokeContext {
            request,
            connection,
            account_id,
            account,
            manifest: &manifest,
            operation_origin: &operation_origin,
            body,
        };
        return dispatch_mcp_tool_call_with_grant(&mut ctx, &grant);
    }
    if mcp_invalidated_grant_exists(account, &manifest) {
        mcp_emit_lifecycle_event(
            request,
            connection,
            account_id,
            account,
            "mcp.tool.failed",
            mcp_tool_failed_event_body(
                account,
                &manifest,
                &operation_origin,
                "GrantInvalidated",
                "mcp grant is invalidated",
            ),
        )?;
        return Err(SdkError::GrantInvalidated);
    }
    if let Some(standing) = mcp_find_standing_auto_approval(account, &manifest) {
        let mut ctx = McpInvokeContext {
            request,
            connection,
            account_id,
            account,
            manifest: &manifest,
            operation_origin: &operation_origin,
            body,
        };
        return dispatch_mcp_tool_call_with_standing(&mut ctx, &standing);
    }
    let approval = mcp_create_approval(account, &manifest, attended, None, false, &body.arguments)?;
    let event_body = mcp_approval_request_event_body(&approval);
    mcp_emit_lifecycle_event(
        request,
        connection,
        account_id,
        account,
        "mcp.approval.request",
        event_body,
    )?;
    Ok(local_bus_ok(serde_json::json!({
        "status": "approval_required",
        "approval": approval,
    })))
}

struct McpInvokeContext<'a> {
    request: &'a LocalBusFrame,
    connection: &'a mut LocalBusConnectionState,
    account_id: &'a str,
    account: &'a mut LocalBusAccountState,
    manifest: &'a McpToolManifest,
    operation_origin: &'a str,
    body: &'a LocalBusMcpToolCallRequest,
}

fn dispatch_mcp_tool_call_with_grant(
    ctx: &mut McpInvokeContext<'_>,
    grant: &LocalMcpGrantRecord,
) -> Result<LocalBusDispatchResult, SdkError> {
    mcp_trace_tool("BUS-MCP-VALID-GRANT", ctx.request, ctx.body, Some(&grant.grant_id));
    mcp_trace_tool("BUS-MCP-INVOKE-IN", ctx.request, ctx.body, None);
    if mcp_grant_requires_single_use(grant) {
        mcp_consume_single_use_grant(ctx.account, &grant.grant_id)?;
    }
    let result = if risk_requires_explicit_approval(&ctx.manifest.effective_risk()) {
        if grant_matches_manifest(&grant.state, ctx.manifest) {
            Ok(format!("{}:{}", ctx.manifest.server_id, ctx.manifest.tool_name))
        } else {
            Err(SyncError::CapabilityDenied)
        }
    } else {
        ctx.account.mcp_registry.invoke_tool(&ctx.body.server_id, &ctx.body.tool_name, &grant.state)
    }
    .map_err(mcp_sync_error)?;
    mcp_trace_tool("BUS-MCP-INVOKE-OUT", ctx.request, ctx.body, None);
    let output = mcp_echo_tool_output(&ctx.body.arguments);
    mcp_trace_tool("BUS-MCP-COMPLETED-EVENT-IN", ctx.request, ctx.body, None);
    mcp_emit_lifecycle_event(
        ctx.request,
        ctx.connection,
        ctx.account_id,
        ctx.account,
        "mcp.tool.completed",
        mcp_tool_completed_event_body(
            ctx.manifest,
            ctx.operation_origin,
            &grant.state.registry_hash,
            &grant.state.tool_manifest_set_hash,
            &result,
            &output,
        ),
    )?;
    mcp_trace_tool("BUS-MCP-COMPLETED-EVENT-OUT", ctx.request, ctx.body, None);
    Ok(local_bus_ok(serde_json::json!({
        "status": "ok",
        "result": result,
        "output": output,
    })))
}

fn dispatch_mcp_tool_call_with_standing(
    ctx: &mut McpInvokeContext<'_>,
    standing: &LocalMcpStandingApprovalRecord,
) -> Result<LocalBusDispatchResult, SdkError> {
    let grant_state = mcp_grant_state_from_standing(standing);
    let result = ctx
        .account
        .mcp_registry
        .invoke_tool(&ctx.body.server_id, &ctx.body.tool_name, &grant_state)
        .map_err(mcp_sync_error)?;
    let output = mcp_echo_tool_output(&ctx.body.arguments);
    mcp_emit_lifecycle_event(
        ctx.request,
        ctx.connection,
        ctx.account_id,
        ctx.account,
        "mcp.standing_auto_approval.invoked",
        mcp_standing_auto_approval_invoked_event_body(
            ctx.manifest,
            standing,
            ctx.operation_origin,
            &result,
            &output,
        ),
    )?;
    mcp_emit_lifecycle_event(
        ctx.request,
        ctx.connection,
        ctx.account_id,
        ctx.account,
        "mcp.tool.completed",
        mcp_tool_completed_event_body(
            ctx.manifest,
            ctx.operation_origin,
            &standing.registry_hash,
            &standing.tool_manifest_set_hash,
            &result,
            &output,
        ),
    )?;
    Ok(local_bus_ok(serde_json::json!({
        "status": "ok",
        "result": result,
        "output": output,
        "standing_approval_id": standing.standing_approval_id,
    })))
}

fn mcp_trace_tool(
    message: &str,
    request: &LocalBusFrame,
    body: &LocalBusMcpToolCallRequest,
    grant_id: Option<&str>,
) {
    local_bus_trace(
        message,
        format!(
            "method={} server_id={} tool_name={} grant_id={}",
            request.method,
            body.server_id,
            body.tool_name,
            grant_id.unwrap_or("-")
        ),
    );
}

fn mcp_emit_lifecycle_event(
    request: &LocalBusFrame,
    connection: &mut LocalBusConnectionState,
    account_id: &str,
    account: &mut LocalBusAccountState,
    event_type: &str,
    mut body: serde_json::Value,
) -> Result<(), SdkError> {
    super::super::read_model::capture_mcp_event(account, request, event_type, &mut body)?;
    let audit = mcp_audit_record(event_type, &body);
    account.client.account_db()?.append_mcp_audit(&McpAuditWrite {
        audit: &audit,
        audit_type: &audit.event_type,
        actor_device_id: account
            .client
            .device_branch
            .as_ref()
            .map_or("unknown", |device| device.device_id.as_str()),
        subject_hash: None,
        redacted_summary: &audit.event_type,
        created_at: now_unix_timestamp(),
    })?;
    account.mcp_audit_log.push(audit);
    if account.mcp_audit_log.len() > 256 {
        account.mcp_audit_log.remove(0);
    }
    connection.push_event(local_bus_event(request, account_id, "mcp", event_type, body));
    Ok(())
}

fn mcp_approval_request_event_body(approval: &LocalMcpApprovalRecord) -> serde_json::Value {
    serde_json::json!({
        "event_type": "mcp.approval.request",
        "approval_id": approval.approval_id,
        "server_id": approval.server_id,
        "tool_name": approval.tool_name,
        "capability": approval.capability,
        "risk_level": approval.risk_level,
        "tool_scope": approval.tool_scope,
        "confirmation_mode": approval.confirmation_mode,
        "expires_at": approval.expires_at,
        "status": approval.status,
        "registry_hash": approval.details.get("registry_hash").cloned().unwrap_or(serde_json::Value::Null),
        "tool_manifest_set_hash": approval.details.get("tool_manifest_set_hash").cloned().unwrap_or(serde_json::Value::Null),
        "details": approval.details,
    })
}

fn mcp_approval_granted_event_body(
    approval: &LocalMcpApprovalRecord,
    grant: &LocalMcpGrantRecord,
) -> serde_json::Value {
    serde_json::json!({
        "event_type": "mcp.approval.granted",
        "approval_id": approval.approval_id,
        "grant_id": grant.grant_id,
        "server_id": approval.server_id,
        "tool_name": approval.tool_name,
        "capability": approval.capability,
        "risk_level": approval.risk_level,
        "tool_scope": approval.tool_scope,
        "confirmation_mode": approval.confirmation_mode,
        "expires_at": grant.signing_body.expires_at,
        "status": "approved",
        "registry_hash": grant.state.registry_hash,
        "tool_manifest_set_hash": grant.state.tool_manifest_set_hash,
        "signed_by_device_id": grant.signed_by_device_id,
    })
}

fn mcp_approval_denied_event_body(approval: &LocalMcpApprovalRecord) -> serde_json::Value {
    serde_json::json!({
        "event_type": "mcp.approval.denied",
        "approval_id": approval.approval_id,
        "server_id": approval.server_id,
        "tool_name": approval.tool_name,
        "capability": approval.capability,
        "risk_level": approval.risk_level,
        "tool_scope": approval.tool_scope,
        "confirmation_mode": approval.confirmation_mode,
        "expires_at": approval.expires_at,
        "status": approval.status,
        "registry_hash": approval.details.get("registry_hash").cloned().unwrap_or(serde_json::Value::Null),
        "tool_manifest_set_hash": approval.details.get("tool_manifest_set_hash").cloned().unwrap_or(serde_json::Value::Null),
    })
}

fn mcp_standing_approval_created_event_body(
    record: &LocalMcpStandingApprovalRecord,
) -> serde_json::Value {
    serde_json::json!({
        "event_type": "mcp.standing_auto_approval.created",
        "standing_approval_id": record.standing_approval_id,
        "server_id": record.server_id,
        "tool_name": record.tool_name,
        "capability": record.capability,
        "risk_level": record.risk_level,
        "tool_scope": record.tool_scope,
        "expires_at": record.expires_at,
        "status": "active",
        "registry_hash": record.registry_hash,
        "tool_manifest_set_hash": record.tool_manifest_set_hash,
        "signed_by_device_id": record.created_by_device_id,
    })
}

fn mcp_standing_approval_revoked_event_body(
    record: &LocalMcpStandingApprovalRecord,
) -> serde_json::Value {
    serde_json::json!({
        "event_type": "mcp.standing_auto_approval.revoked",
        "standing_approval_id": record.standing_approval_id,
        "server_id": record.server_id,
        "tool_name": record.tool_name,
        "capability": record.capability,
        "risk_level": record.risk_level,
        "tool_scope": record.tool_scope,
        "expires_at": record.expires_at,
        "status": "revoked",
        "registry_hash": record.registry_hash,
        "tool_manifest_set_hash": record.tool_manifest_set_hash,
    })
}

fn mcp_standing_auto_approval_invoked_event_body(
    manifest: &McpToolManifest,
    record: &LocalMcpStandingApprovalRecord,
    operation_origin: &str,
    result: &str,
    output: &serde_json::Value,
) -> serde_json::Value {
    serde_json::json!({
        "event_type": "mcp.standing_auto_approval.invoked",
        "operation_origin": operation_origin,
        "standing_approval_id": record.standing_approval_id,
        "server_id": manifest.server_id,
        "tool_name": manifest.tool_name,
        "capability": manifest.capability,
        "risk_level": manifest.effective_risk(),
        "tool_scope": manifest.tool_scope,
        "outcome": "allowed",
        "registry_hash": record.registry_hash,
        "tool_manifest_set_hash": record.tool_manifest_set_hash,
        "result": result,
        "output": output,
    })
}

fn mcp_tool_started_event_body(
    account: &LocalBusAccountState,
    manifest: &McpToolManifest,
    operation_origin: &str,
    arguments: &serde_json::Value,
) -> serde_json::Value {
    serde_json::json!({
        "event_type": "mcp.tool.started",
        "operation_origin": operation_origin,
        "server_id": manifest.server_id,
        "tool_name": manifest.tool_name,
        "capability": manifest.capability,
        "risk_level": manifest.declared_risk,
        "tool_scope": manifest.tool_scope,
        "registry_hash": account.mcp_registry.registry_hash(),
        "tool_manifest_set_hash": account.mcp_registry.tool_manifest_set_hash(),
        "arguments": arguments,
    })
}

fn mcp_tool_completed_event_body(
    manifest: &McpToolManifest,
    operation_origin: &str,
    registry_hash: &str,
    tool_manifest_set_hash: &str,
    result: &str,
    output: &serde_json::Value,
) -> serde_json::Value {
    serde_json::json!({
        "event_type": "mcp.tool.completed",
        "operation_origin": operation_origin,
        "server_id": manifest.server_id,
        "tool_name": manifest.tool_name,
        "capability": manifest.capability,
        "risk_level": manifest.declared_risk,
        "tool_scope": manifest.tool_scope,
        "outcome": "allowed",
        "registry_hash": registry_hash,
        "tool_manifest_set_hash": tool_manifest_set_hash,
        "result": result,
        "output": output,
    })
}

fn mcp_tool_failed_event_body(
    account: &LocalBusAccountState,
    manifest: &McpToolManifest,
    operation_origin: &str,
    error_code: &str,
    error_message: &str,
) -> serde_json::Value {
    serde_json::json!({
        "event_type": "mcp.tool.failed",
        "operation_origin": operation_origin,
        "server_id": manifest.server_id,
        "tool_name": manifest.tool_name,
        "capability": manifest.capability,
        "risk_level": manifest.declared_risk,
        "tool_scope": manifest.tool_scope,
        "outcome": "failed",
        "registry_hash": account.mcp_registry.registry_hash(),
        "tool_manifest_set_hash": account.mcp_registry.tool_manifest_set_hash(),
        "error": {
            "code": error_code,
            "message": error_message,
        },
    })
}

fn mcp_audit_record(event_type: &str, event_body: &serde_json::Value) -> LocalMcpAuditRecord {
    LocalMcpAuditRecord {
        event_type: event_type.to_owned(),
        operation_origin: event_body
            .get("operation_origin")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("ai_mcp")
            .to_owned(),
        approval_id: event_body
            .get("approval_id")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned),
        grant_id: event_body.get("grant_id").and_then(serde_json::Value::as_str).map(str::to_owned),
        server_id: event_body
            .get("server_id")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("")
            .to_owned(),
        tool_name: event_body
            .get("tool_name")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("")
            .to_owned(),
        capability: event_body
            .get("capability")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("")
            .to_owned(),
        risk_level: event_body
            .get("risk_level")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("")
            .to_owned(),
        tool_scope: event_body
            .get("tool_scope")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned),
        outcome: event_body
            .get("outcome")
            .and_then(serde_json::Value::as_str)
            .or_else(|| event_body.get("status").and_then(serde_json::Value::as_str))
            .unwrap_or(event_type)
            .to_owned(),
        registry_hash: event_body
            .get("registry_hash")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("")
            .to_owned(),
        tool_manifest_set_hash: event_body
            .get("tool_manifest_set_hash")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("")
            .to_owned(),
        event_body: event_body.clone(),
    }
}

fn mcp_manifest(
    registry: &McpRegistry,
    server_id: &str,
    tool_name: &str,
) -> Option<McpToolManifest> {
    registry
        .tools()
        .into_iter()
        .find(|tool| tool.server_id == server_id && tool.tool_name == tool_name)
}

fn mcp_manifest_for_grant_request(
    account: &LocalBusAccountState,
    body: &LocalBusGrantRequest,
) -> Result<McpToolManifest, SdkError> {
    if let (Some(server_id), Some(tool_name)) = (&body.server_id, &body.tool_name)
        && let Some(tool) = mcp_manifest(&account.mcp_registry, server_id, tool_name)
    {
        return Ok(tool);
    }
    if !body.full_delegation {
        return Err(SdkError::LocalBus(
            "non-delegation grant request requires server_id and tool_name".to_owned(),
        ));
    }
    let capability = body.capability.clone().ok_or_else(|| {
        SdkError::LocalBus("grant request requires server/tool or capability".to_owned())
    })?;
    Ok(McpToolManifest {
        server_id: body.server_id.clone().unwrap_or_else(|| "wildcard".to_owned()),
        tool_name: body.tool_name.clone().unwrap_or_else(|| "wildcard".to_owned()),
        capability: capability.clone(),
        tool_scope: Some("wildcard".to_owned()),
        declared_risk: capability.default_risk(),
        manifest_version: 1,
    })
}

fn mcp_invalidated_grant_exists(
    account: &LocalBusAccountState,
    manifest: &McpToolManifest,
) -> bool {
    let now = now_unix_timestamp();
    account.mcp_grants.values().any(|grant| {
        (!mcp_grant_requires_single_use(grant)
            && (grant.state.revoked
                || mcp_grant_expired(grant, now)
                || grant.state.registry_hash != account.mcp_registry.registry_hash()
                || grant.state.tool_manifest_set_hash
                    != account.mcp_registry.tool_manifest_set_hash()))
            && grant_matches_manifest(&grant.state, manifest)
    })
}

fn mcp_full_delegation_blocked_by_risk(
    account: &LocalBusAccountState,
    manifest: &McpToolManifest,
) -> bool {
    let now = now_unix_timestamp();
    risk_requires_explicit_approval(&manifest.effective_risk())
        && account.mcp_grants.values().any(|grant| {
            !grant.state.revoked
                && !mcp_grant_expired(grant, now)
                && grant.state.registry_hash == account.mcp_registry.registry_hash()
                && grant.state.tool_manifest_set_hash
                    == account.mcp_registry.tool_manifest_set_hash()
                && grant.state.full_delegation
                && grant_matches_manifest(&grant.state, manifest)
        })
}

fn mcp_valid_grant<'a>(
    account: &'a LocalBusAccountState,
    manifest: &McpToolManifest,
    arguments: &serde_json::Value,
) -> Option<&'a LocalMcpGrantRecord> {
    let now = now_unix_timestamp();
    account.mcp_grants.values().find(|grant| {
        !grant.state.revoked
            && !mcp_grant_expired(grant, now)
            && grant.state.registry_hash == account.mcp_registry.registry_hash()
            && grant.state.tool_manifest_set_hash == account.mcp_registry.tool_manifest_set_hash()
            && ((grant.state.full_delegation
                && !risk_requires_explicit_approval(&manifest.effective_risk()))
                || grant.state.allowed_capabilities.contains(&manifest.capability))
            && grant_matches_manifest(&grant.state, manifest)
            && mcp_grant_single_use_matches(grant, manifest, arguments)
            && mcp_verify_grant_signature(grant).is_ok()
    })
}

fn mcp_grant_single_use_matches(
    grant: &LocalMcpGrantRecord,
    manifest: &McpToolManifest,
    arguments: &serde_json::Value,
) -> bool {
    if !risk_requires_explicit_approval(&manifest.effective_risk()) {
        return true;
    }
    grant.confirmation_mode == "remote_app"
        && grant.signing_body.single_use
        && grant
            .signing_body
            .arguments_hash
            .as_deref()
            .is_some_and(|hash| mcp_arguments_hash(arguments).is_ok_and(|current| current == hash))
}

fn mcp_grant_requires_single_use(grant: &LocalMcpGrantRecord) -> bool {
    grant.signing_body.single_use
}

fn mcp_consume_single_use_grant(
    account: &mut LocalBusAccountState,
    grant_id: &str,
) -> Result<(), SdkError> {
    if let Some(record) = account.mcp_grants.get_mut(grant_id) {
        record.state.revoked = true;
    }
    account.client.account_db()?.set_mcp_grant_revoked(grant_id)?;
    Ok(())
}

fn mcp_find_standing_auto_approval(
    account: &LocalBusAccountState,
    manifest: &McpToolManifest,
) -> Option<LocalMcpStandingApprovalRecord> {
    if risk_requires_explicit_approval(&manifest.effective_risk()) {
        return None;
    }
    let now = now_unix_timestamp();
    account.mcp_standing_approvals.values().find_map(|record| {
        (!record.revoked
            && record.expires_at > now
            && record.registry_hash == account.mcp_registry.registry_hash()
            && record.tool_manifest_set_hash == account.mcp_registry.tool_manifest_set_hash()
            && standing_matches_manifest(record, manifest)
            && mcp_verify_standing_approval_signature(record).is_ok())
        .then(|| record.clone())
    })
}

fn standing_matches_manifest(
    record: &LocalMcpStandingApprovalRecord,
    manifest: &McpToolManifest,
) -> bool {
    record.server_id == manifest.server_id
        && record.tool_name == manifest.tool_name
        && record.tool_scope == manifest.tool_scope
        && record.capability == manifest.capability
}

fn mcp_grant_state_from_standing(record: &LocalMcpStandingApprovalRecord) -> McpGrantState {
    McpGrantState {
        server_id: record.server_id.clone(),
        tool_name: record.tool_name.clone(),
        tool_scope: record.tool_scope.clone(),
        registry_hash: record.registry_hash.clone(),
        tool_manifest_set_hash: record.tool_manifest_set_hash.clone(),
        full_delegation: false,
        allowed_capabilities: BTreeSet::from([record.capability.clone()]),
        revoked: record.revoked,
        expires_at: record.expires_at,
    }
}

fn mcp_grant_expired(grant: &LocalMcpGrantRecord, now: i64) -> bool {
    grant.signing_body.expires_at <= now || grant.state.expires_at <= now
}

fn mcp_create_standing_approval(
    account: &mut LocalBusAccountState,
    body: &LocalBusGrantStandingApprovalCreateRequest,
) -> Result<LocalMcpStandingApprovalRecord, SdkError> {
    let manifest = mcp_manifest(&account.mcp_registry, &body.server_id, &body.tool_name)
        .ok_or_else(|| {
            SdkError::LocalBus(format!("tool not found: {}/{}", body.server_id, body.tool_name))
        })?;
    if manifest.tool_scope != body.tool_scope {
        return Err(SdkError::LocalBus("standing approval tool_scope mismatch".to_owned()));
    }
    if risk_requires_explicit_approval(&manifest.effective_risk()) {
        return Err(SdkError::CapabilityDenied(
            "standing approval cannot cover high or critical risk tools".to_owned(),
        ));
    }
    let now = now_unix_timestamp();
    let ttl = body
        .ttl_seconds
        .unwrap_or(MCP_STANDING_APPROVAL_TTL_SECONDS)
        .clamp(1, MCP_STANDING_APPROVAL_TTL_SECONDS);
    let expires_at = now.saturating_add(ttl);
    let standing_approval_id = format!(
        "standing_{}_{}_{}",
        manifest.server_id,
        manifest.tool_name,
        account.mcp_standing_approvals.len().saturating_add(1)
    );
    let signing_body = LocalMcpStandingApprovalSigningBody {
        standing_approval_id: standing_approval_id.clone(),
        server_id: manifest.server_id.clone(),
        tool_name: manifest.tool_name.clone(),
        tool_scope: manifest.tool_scope.clone(),
        capability: manifest.capability.clone(),
        risk_level: manifest.effective_risk(),
        registry_hash: account.mcp_registry.registry_hash().to_owned(),
        tool_manifest_set_hash: account.mcp_registry.tool_manifest_set_hash().to_owned(),
        issued_at: now,
        expires_at,
    };
    let device =
        account.client.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?.clone();
    let signature = ramflux_crypto::sign_with_device_branch(&device, &signing_body)?;
    let signer_public_key =
        ramflux_protocol::encode_base64url(device.signing_key.verifying_key().to_bytes());
    let record = LocalMcpStandingApprovalRecord {
        standing_approval_id: standing_approval_id.clone(),
        server_id: signing_body.server_id.clone(),
        tool_name: signing_body.tool_name.clone(),
        tool_scope: signing_body.tool_scope.clone(),
        capability: signing_body.capability.clone(),
        risk_level: signing_body.risk_level.clone(),
        registry_hash: signing_body.registry_hash.clone(),
        tool_manifest_set_hash: signing_body.tool_manifest_set_hash.clone(),
        issued_at: signing_body.issued_at,
        expires_at: signing_body.expires_at,
        created_by_device_id: device.device_id.clone(),
        signer_public_key,
        signature,
        signing_body,
        revoked: false,
    };
    persist_mcp_standing_approval(account, &record)?;
    account.mcp_standing_approvals.insert(standing_approval_id, record.clone());
    Ok(record)
}

fn mcp_create_approval(
    account: &mut LocalBusAccountState,
    manifest: &McpToolManifest,
    attended: bool,
    requested_grant_id: Option<&str>,
    full_delegation: bool,
    arguments: &serde_json::Value,
) -> Result<LocalMcpApprovalRecord, SdkError> {
    let confirmation_mode =
        if attended && !risk_requires_explicit_approval(&manifest.effective_risk()) {
            "attended_local"
        } else {
            "remote_app"
        };
    let approval_id = format!(
        "approval_{}_{}_{}",
        manifest.server_id,
        manifest.tool_name,
        crate::new_surface_message_id()?
    );
    let expires_at = now_unix_timestamp().saturating_add(MCP_GRANT_TTL_SECONDS);
    let single_use = risk_requires_explicit_approval(&manifest.effective_risk());
    let arguments_hash = mcp_arguments_hash(arguments)?;
    let approval = LocalMcpApprovalRecord {
        approval_id: approval_id.clone(),
        server_id: manifest.server_id.clone(),
        tool_name: manifest.tool_name.clone(),
        capability: manifest.capability.clone(),
        risk_level: manifest.effective_risk(),
        tool_scope: manifest.tool_scope.clone(),
        confirmation_mode: confirmation_mode.to_owned(),
        expires_at,
        status: "pending".to_owned(),
        details: serde_json::json!({
            "operation_origin": "ai_mcp",
            "registry_hash": account.mcp_registry.registry_hash(),
            "tool_manifest_set_hash": account.mcp_registry.tool_manifest_set_hash(),
            "tool_scope": manifest.tool_scope.clone(),
            "requested_grant_id": requested_grant_id,
            "full_delegation": full_delegation,
            "single_use": single_use,
            "arguments_hash": arguments_hash,
            "expires_at": expires_at,
            "arguments": arguments,
        }),
    };
    account.mcp_pending_approvals.insert(approval_id, approval.clone());
    Ok(approval)
}

fn mcp_local_grant_from_approval(
    account: &mut LocalBusAccountState,
    approval: LocalMcpApprovalRecord,
) -> Result<LocalMcpGrantRecord, SdkError> {
    if approval.confirmation_mode != "attended_local" {
        account.mcp_pending_approvals.insert(approval.approval_id.clone(), approval);
        return Err(SdkError::RemoteAppApprovalRequired);
    }
    let device =
        account.client.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?.clone();
    let body = mcp_grant_signing_body(account, &approval)?;
    let signature = ramflux_crypto::sign_with_device_branch(&device, &body)?;
    let public_key =
        ramflux_protocol::encode_base64url(device.signing_key.verifying_key().to_bytes());
    let signed = LocalBusMcpApprovalGrantRequest {
        approval_id: approval.approval_id.clone(),
        signed_by_device_id: device.device_id.clone(),
        signer_public_key: public_key,
        signature,
    };
    mcp_store_grant(account, approval, body, signed, None)
}

pub(super) fn mcp_remote_grant_from_approval(
    account: &mut LocalBusAccountState,
    approval: LocalMcpApprovalRecord,
    signed: LocalBusMcpApprovalGrantRequest,
    expires_cap: Option<i64>,
) -> Result<LocalMcpGrantRecord, SdkError> {
    let body = mcp_grant_signing_body(account, &approval)?;
    ramflux_crypto::verify_device_branch_signature(
        &signed.signer_public_key,
        &body,
        &signed.signature,
    )
    .map_err(|source| SdkError::SignatureVerificationFailed(source.to_string()))?;
    mcp_store_grant(account, approval, body, signed, expires_cap)
}

pub(super) fn mcp_grant_signing_body(
    account: &LocalBusAccountState,
    approval: &LocalMcpApprovalRecord,
) -> Result<LocalMcpGrantSigningBody, SdkError> {
    let requested_grant_id = approval
        .details
        .get("requested_grant_id")
        .and_then(serde_json::Value::as_str)
        .map_or_else(|| format!("grant_{}", approval.approval_id), str::to_owned);
    let full_delegation = approval
        .details
        .get("full_delegation")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    let single_use =
        approval.details.get("single_use").and_then(serde_json::Value::as_bool).unwrap_or(false);
    let arguments_hash = if single_use {
        Some(
            approval
                .details
                .get("arguments_hash")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| {
                    SdkError::LocalBus("single-use mcp grant missing arguments_hash".to_owned())
                })?
                .to_owned(),
        )
    } else {
        None
    };
    Ok(LocalMcpGrantSigningBody {
        task_binding: approval
            .details
            .get("task_binding")
            .cloned()
            .map(serde_json::from_value)
            .transpose()?,
        approval_id: approval.approval_id.clone(),
        grant_id: requested_grant_id,
        server_id: approval.server_id.clone(),
        tool_name: approval.tool_name.clone(),
        tool_scope: approval.tool_scope.clone(),
        capability: approval.capability.clone(),
        registry_hash: account.mcp_registry.registry_hash().to_owned(),
        tool_manifest_set_hash: account.mcp_registry.tool_manifest_set_hash().to_owned(),
        full_delegation,
        single_use,
        arguments_hash,
        expires_at: approval.expires_at,
    })
}

fn mcp_store_grant(
    account: &mut LocalBusAccountState,
    mut approval: LocalMcpApprovalRecord,
    body: LocalMcpGrantSigningBody,
    signed: LocalBusMcpApprovalGrantRequest,
    expires_cap: Option<i64>,
) -> Result<LocalMcpGrantRecord, SdkError> {
    "approved".clone_into(&mut approval.status);
    let record = LocalMcpGrantRecord {
        grant_id: body.grant_id.clone(),
        state: McpGrantState {
            server_id: body.server_id.clone(),
            tool_name: body.tool_name.clone(),
            tool_scope: body.tool_scope.clone(),
            registry_hash: body.registry_hash.clone(),
            tool_manifest_set_hash: body.tool_manifest_set_hash.clone(),
            full_delegation: body.full_delegation,
            allowed_capabilities: BTreeSet::from([approval.capability]),
            revoked: false,
            expires_at: body.expires_at.min(expires_cap.unwrap_or(body.expires_at)),
        },
        signed_by_device_id: signed.signed_by_device_id,
        signer_public_key: signed.signer_public_key,
        signature: signed.signature,
        signing_body: body,
        confirmation_mode: approval.confirmation_mode,
    };
    persist_mcp_grant(account, &record)?;
    account.mcp_grants.insert(record.grant_id.clone(), record.clone());
    Ok(record)
}

pub(super) fn persist_mcp_grant(
    account: &LocalBusAccountState,
    record: &LocalMcpGrantRecord,
) -> Result<(), SdkError> {
    account.client.account_db()?.upsert_mcp_grant(&McpGrantWrite {
        grant_id: &record.grant_id,
        target_ai_device_id: &record.state.server_id,
        source_app_device_id: &record.signed_by_device_id,
        capability: mcp_capability_wire_name(&record.signing_body.capability),
        risk_level: ramflux_sync::risk_wire_name(&record.signing_body.capability.default_risk()),
        registry_hash: &record.state.registry_hash,
        tool_manifest_set_hash: &record.state.tool_manifest_set_hash,
        expires_at: record.signing_body.expires_at.min(record.state.expires_at),
        signature: &record.signature,
        created_at: now_unix_timestamp(),
        revoked: record.state.revoked,
        grant: record,
    })?;
    Ok(())
}

fn persist_mcp_standing_approval(
    account: &LocalBusAccountState,
    record: &LocalMcpStandingApprovalRecord,
) -> Result<(), SdkError> {
    account.client.account_db()?.upsert_mcp_standing_approval(&McpStandingApprovalWrite {
        standing_approval_id: &record.standing_approval_id,
        server_id: &record.server_id,
        tool_name: &record.tool_name,
        capability: mcp_capability_wire_name(&record.capability),
        risk_level: ramflux_sync::risk_wire_name(&record.risk_level),
        registry_hash: &record.registry_hash,
        tool_manifest_set_hash: &record.tool_manifest_set_hash,
        expires_at: record.expires_at,
        created_at: record.issued_at,
        created_by_device_id: &record.created_by_device_id,
        revoked: record.revoked,
        approval: record,
    })?;
    Ok(())
}

fn persist_mcp_tool(
    account: &LocalBusAccountState,
    manifest: &McpToolManifest,
) -> Result<(), SdkError> {
    let manifest_body = ramflux_protocol::canonical_json_bytes(manifest)?;
    let tool_manifest_hash =
        ramflux_protocol::hash_base64url(ramflux_protocol::domain::MCP_GRANT, &manifest_body);
    account.client.account_db()?.upsert_mcp_tool(&McpToolWrite {
        tool_manifest_hash: &tool_manifest_hash,
        server_id: &manifest.server_id,
        tool_name: &manifest.tool_name,
        required_capability: mcp_capability_wire_name(&manifest.capability),
        risk_level: ramflux_sync::risk_wire_name(&manifest.declared_risk),
        manifest,
        updated_at: now_unix_timestamp(),
    })?;
    Ok(())
}

fn mcp_verify_grant_signature(grant: &LocalMcpGrantRecord) -> Result<(), SdkError> {
    Ok(ramflux_crypto::verify_device_branch_signature(
        &grant.signer_public_key,
        &grant.signing_body,
        &grant.signature,
    )?)
}

fn mcp_verify_standing_approval_signature(
    record: &LocalMcpStandingApprovalRecord,
) -> Result<(), SdkError> {
    Ok(ramflux_crypto::verify_device_branch_signature(
        &record.signer_public_key,
        &record.signing_body,
        &record.signature,
    )?)
}

pub(crate) fn hydrate_local_mcp_state(account: &mut LocalBusAccountState) -> Result<(), SdkError> {
    account.mcp_registry = McpRegistry::new();
    account.mcp_pending_approvals.clear();
    let terminal_task_approvals = account
        .client
        .task_approval_decision_rows()?
        .into_iter()
        .filter_map(|row| row["decision_id"].as_str().map(str::to_owned))
        .collect::<BTreeSet<_>>();
    for manifest in account.client.account_db()?.load_mcp_tools::<McpToolManifest>()? {
        account.mcp_registry.install_tool(manifest);
    }
    for value in account
        .client
        .account_db()?
        .list_actor_states::<serde_json::Value>("directory/approval/")?
    {
        if value.get("status").and_then(serde_json::Value::as_str) == Some("pending")
            && value
                .get("approval_id")
                .and_then(serde_json::Value::as_str)
                .is_none_or(|id| !terminal_task_approvals.contains(id))
        {
            let approval: LocalMcpApprovalRecord = serde_json::from_value(value)?;
            account.mcp_pending_approvals.insert(approval.approval_id.clone(), approval);
        }
    }
    account.mcp_grants = account.client.account_db()?.load_mcp_grants::<LocalMcpGrantRecord>()?;
    account.mcp_standing_approvals = account
        .client
        .account_db()?
        .load_mcp_standing_approvals::<LocalMcpStandingApprovalRecord>()?;
    account.mcp_audit_log =
        account.client.account_db()?.load_recent_mcp_audit::<LocalMcpAuditRecord>(256)?;
    Ok(())
}

fn mcp_echo_tool_output(arguments: &serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "echo": arguments,
    })
}

fn mcp_arguments_hash(arguments: &serde_json::Value) -> Result<String, SdkError> {
    let body = ramflux_protocol::canonical_json_bytes(arguments)?;
    Ok(ramflux_protocol::hash_base64url(ramflux_protocol::domain::MCP_GRANT, &body))
}

fn mcp_sync_error(error: SyncError) -> SdkError {
    match error {
        SyncError::CapabilityDenied => {
            SdkError::CapabilityDenied("mcp tool capability denied".to_owned())
        }
        SyncError::GrantInvalidated => SdkError::GrantInvalidated,
        other => SdkError::from(other),
    }
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::manual_let_else,
    clippy::needless_pass_by_value,
    clippy::panic,
    clippy::too_many_lines
)]
#[path = "tests/mcp_grants.rs"]
mod tests;

#[cfg(test)]
#[path = "tests/mcp_approval_ids.rs"]
mod approval_ids;
