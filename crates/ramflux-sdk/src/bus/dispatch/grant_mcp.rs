#![allow(clippy::missing_errors_doc)]
#![allow(clippy::wildcard_imports)]
use crate::prelude::*;

const MCP_GRANT_TTL_SECONDS: i64 = 86_400;
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
                "approvals": account.mcp_pending_approvals.values().collect::<Vec<_>>(),
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
            Ok(local_bus_ok(serde_json::json!({ "audit": account.mcp_audit_log })))
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
    let account = local_bus_account_mut(state, account_id)?;
    if request.body.get("signature").is_some() {
        let body: LocalBusMcpApprovalGrantRequest = serde_json::from_value(request.body.clone())?;
        let approval =
            account.mcp_pending_approvals.get(&body.approval_id).cloned().ok_or_else(|| {
                SdkError::LocalBus(format!("approval not found: {}", body.approval_id))
            })?;
        let grant = mcp_remote_grant_from_approval(account, approval.clone(), body)?;
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
    let body: LocalBusMcpApprovalDecisionRequest = serde_json::from_value(request.body.clone())?;
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
    );
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
    if let Some(grant) = mcp_valid_grant(account, &manifest) {
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
    let approval = mcp_create_approval(account, &manifest, attended, None, false, &body.arguments);
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
    let result = ctx
        .account
        .mcp_registry
        .invoke_tool(&ctx.body.server_id, &ctx.body.tool_name, &grant.state)
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
    body: serde_json::Value,
) -> Result<(), SdkError> {
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
        (grant.state.revoked
            || mcp_grant_expired(grant, now)
            || grant.state.registry_hash != account.mcp_registry.registry_hash()
            || grant.state.tool_manifest_set_hash != account.mcp_registry.tool_manifest_set_hash())
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
            && mcp_verify_grant_signature(grant).is_ok()
    })
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
) -> LocalMcpApprovalRecord {
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
        account.mcp_pending_approvals.len().saturating_add(1)
    );
    let expires_at = now_unix_timestamp().saturating_add(MCP_GRANT_TTL_SECONDS);
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
            "expires_at": expires_at,
            "arguments": arguments,
        }),
    };
    account.mcp_pending_approvals.insert(approval_id, approval.clone());
    approval
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
    let body = mcp_grant_signing_body(account, &approval);
    let signature = ramflux_crypto::sign_with_device_branch(&device, &body)?;
    let public_key =
        ramflux_protocol::encode_base64url(device.signing_key.verifying_key().to_bytes());
    mcp_store_grant(account, approval, body, device.device_id.clone(), public_key, signature)
}

fn mcp_remote_grant_from_approval(
    account: &mut LocalBusAccountState,
    approval: LocalMcpApprovalRecord,
    signed: LocalBusMcpApprovalGrantRequest,
) -> Result<LocalMcpGrantRecord, SdkError> {
    let body = mcp_grant_signing_body(account, &approval);
    ramflux_crypto::verify_device_branch_signature(
        &signed.signer_public_key,
        &body,
        &signed.signature,
    )
    .map_err(|source| SdkError::SignatureVerificationFailed(source.to_string()))?;
    mcp_store_grant(
        account,
        approval,
        body,
        signed.signed_by_device_id,
        signed.signer_public_key,
        signed.signature,
    )
}

fn mcp_grant_signing_body(
    account: &LocalBusAccountState,
    approval: &LocalMcpApprovalRecord,
) -> LocalMcpGrantSigningBody {
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
    LocalMcpGrantSigningBody {
        approval_id: approval.approval_id.clone(),
        grant_id: requested_grant_id,
        server_id: approval.server_id.clone(),
        tool_name: approval.tool_name.clone(),
        tool_scope: approval.tool_scope.clone(),
        capability: approval.capability.clone(),
        registry_hash: account.mcp_registry.registry_hash().to_owned(),
        tool_manifest_set_hash: account.mcp_registry.tool_manifest_set_hash().to_owned(),
        full_delegation,
        expires_at: approval.expires_at,
    }
}

fn mcp_store_grant(
    account: &mut LocalBusAccountState,
    mut approval: LocalMcpApprovalRecord,
    body: LocalMcpGrantSigningBody,
    signed_by_device_id: String,
    signer_public_key: String,
    signature: String,
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
            expires_at: body.expires_at,
        },
        signed_by_device_id,
        signer_public_key,
        signature,
        signing_body: body,
        confirmation_mode: approval.confirmation_mode,
    };
    persist_mcp_grant(account, &record)?;
    account.mcp_grants.insert(record.grant_id.clone(), record.clone());
    Ok(record)
}

fn persist_mcp_grant(
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
        expires_at: record.signing_body.expires_at,
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
    for manifest in account.client.account_db()?.load_mcp_tools::<McpToolManifest>()? {
        account.mcp_registry.install_tool(manifest);
    }
    account.mcp_grants = account.client.account_db()?.load_mcp_grants::<LocalMcpGrantRecord>()?;
    account.mcp_standing_approvals = account
        .client
        .account_db()?
        .load_mcp_standing_approvals::<LocalMcpStandingApprovalRecord>()?;
    account.mcp_audit_log = account.client.account_db()?.load_mcp_audit::<LocalMcpAuditRecord>()?;
    Ok(())
}

fn mcp_echo_tool_output(arguments: &serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "echo": arguments,
    })
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
mod tests {
    use super::*;

    const ACCOUNT_ID: &str = "acct_mcp";
    const PRINCIPAL_ID: &str = "principal_mcp_test";
    const DEVICE_ID: &str = "device_mcp_test";
    const FUTURE_EXPIRES_AT: i64 = 4_000_000_000;

    fn temp_root(test_name: &str) -> PathBuf {
        let nanos = SystemTime::now().duration_since(UNIX_EPOCH).expect("clock").as_nanos();
        std::env::temp_dir()
            .join(format!("ramflux-sdk-mcp-{test_name}-{}-{nanos}", std::process::id()))
    }

    fn gateway_config() -> GatewaySessionConfig {
        GatewaySessionConfig::quic(GatewayQuicEndpointConfig {
            bind_addr: "127.0.0.1:0".parse().expect("valid bind addr"),
            gateway_addr: "127.0.0.1:1".parse().expect("valid gateway addr"),
            server_name: "ramflux-gateway".to_owned(),
            ca_cert: PathBuf::from("ca.pem"),
            principal_id: PRINCIPAL_ID.to_owned(),
            device_id: DEVICE_ID.to_owned(),
            target_delivery_id: "target_mcp_test".to_owned(),
            prekey_http_url: None,
        })
    }

    fn unlocked_client(root: &Path) -> RamfluxClient {
        let mut client = RamfluxClient::new();
        client.create_identity_root(PRINCIPAL_ID, [0x11; 32]);
        client.create_device_branch(PRINCIPAL_ID, DEVICE_ID, 1, [0x12; 32]);
        client.open_account_index(root).expect("open account index");
        client.set_active_account(ACCOUNT_ID).expect("set active account");
        client.unlock_account(ACCOUNT_ID, b"mcp-test-secret").expect("unlock account");
        client
    }

    fn test_state_named(test_name: &str) -> (LocalBusDaemonState, PathBuf) {
        let root = temp_root(test_name);
        let mut client = RamfluxClient::new();
        client.create_identity_root(PRINCIPAL_ID, [0x11; 32]);
        client.create_device_branch(PRINCIPAL_ID, DEVICE_ID, 1, [0x12; 32]);
        client.open_account_index(&root).expect("open account index");
        client.create_account(ACCOUNT_ID, "principal_mcp_test").expect("create account");
        client.set_active_account(ACCOUNT_ID).expect("set active account");
        client.unlock_account(ACCOUNT_ID, b"mcp-test-secret").expect("unlock account");
        let gateway = gateway_config();
        let account = LocalBusAccountState::disconnected(client, gateway);
        (
            LocalBusDaemonState {
                config: LocalBusConfig::new(root.join("bus.sock"), root.clone()),
                accounts: BTreeMap::from([(ACCOUNT_ID.to_owned(), account)]),
                active_account_id: Some(ACCOUNT_ID.to_owned()),
                attended_accounts: BTreeSet::from([ACCOUNT_ID.to_owned()]),
                subscribers: BTreeMap::new(),
            },
            root,
        )
    }

    fn test_state() -> LocalBusDaemonState {
        test_state_named("grant-mcp").0
    }

    fn test_connection(connection_id: u64) -> LocalBusConnectionState {
        let (outbound, _inbound) = mpsc::channel(8);
        LocalBusConnectionState::new(connection_id, outbound)
    }

    fn request(method: &str, body: serde_json::Value) -> LocalBusFrame {
        LocalBusFrame::request("req_test", Some(ACCOUNT_ID.to_owned()), "mcp", method, body)
    }

    fn install_tool(
        state: &mut LocalBusDaemonState,
        server_id: &str,
        tool_name: &str,
        capability: McpCapability,
        tool_scope: Option<&str>,
        risk_level: RiskLevel,
    ) {
        let mut connection = test_connection(1);
        let frame = request(
            "mcp.server.add",
            serde_json::json!({
                "server_id": server_id,
                "command": "stdio",
                "tool_name": tool_name,
                "capability": capability,
                "tool_scope": tool_scope,
                "risk_level": risk_level,
            }),
        );
        dispatch_mcp_bus_request(&frame, state, &mut connection).expect("install tool");
    }

    fn account(state: &LocalBusDaemonState) -> &LocalBusAccountState {
        state.accounts.get(ACCOUNT_ID).expect("test account exists")
    }

    fn account_mut(state: &mut LocalBusDaemonState) -> &mut LocalBusAccountState {
        state.accounts.get_mut(ACCOUNT_ID).expect("test account exists")
    }

    #[test]
    fn mcp_approval_request_event_and_audit_are_canonical() {
        let mut state = test_state();
        install_tool(
            &mut state,
            "srv",
            "echo",
            McpCapability::ReadConversation,
            Some("echo"),
            RiskLevel::Low,
        );
        let mut connection = test_connection(1);
        connection.topics.insert("mcp.approval.request".to_owned());
        let frame = request(
            "mcp.tool.started",
            serde_json::json!({
                "server_id": "srv",
                "tool_name": "echo",
                "arguments": {"text": "hello"},
                "operation_origin": "ai_mcp",
            }),
        );
        let result =
            dispatch_mcp_bus_request(&frame, &mut state, &mut connection).expect("tool call");
        assert_eq!(result.response_body["status"], "approval_required");
        let events = connection.drain_events();
        let approval_event = events
            .iter()
            .find(|event| event.method == "mcp.approval.request")
            .expect("approval request event");
        assert_eq!(approval_event.body["event_type"], "mcp.approval.request");
        assert_eq!(
            approval_event.body["registry_hash"],
            account(&state).mcp_registry.registry_hash()
        );
        assert_eq!(
            approval_event.body["tool_manifest_set_hash"],
            account(&state).mcp_registry.tool_manifest_set_hash()
        );
        assert!(
            account(&state)
                .mcp_audit_log
                .iter()
                .any(|record| record.event_type == "mcp.approval.request"
                    && record.event_body == approval_event.body)
        );
    }

    #[test]
    fn mcp_approval_granted_and_denied_events_are_canonical() {
        let mut state = test_state();
        install_tool(
            &mut state,
            "srv",
            "echo",
            McpCapability::ReadConversation,
            Some("echo"),
            RiskLevel::Low,
        );
        let create = request(
            "mcp.tool.started",
            serde_json::json!({
                "server_id": "srv",
                "tool_name": "echo",
                "arguments": {},
                "operation_origin": "ai_mcp",
            }),
        );
        let mut create_connection = test_connection(1);
        let approval = dispatch_mcp_bus_request(&create, &mut state, &mut create_connection)
            .expect("create approval")
            .response_body["approval"]
            .clone();
        let approval_id = approval["approval_id"].as_str().expect("approval id");

        let mut grant_connection = test_connection(2);
        grant_connection.topics.insert("mcp.approval.granted".to_owned());
        let grant = request("grant.approve", serde_json::json!({ "approval_id": approval_id }));
        dispatch_grant_bus_request(&grant, &mut state, &mut grant_connection)
            .expect("approve grant");
        let granted = grant_connection.drain_events();
        assert_eq!(granted.len(), 1);
        assert_eq!(granted[0].method, "mcp.approval.granted");
        assert_eq!(granted[0].body["event_type"], "mcp.approval.granted");
        assert!(
            granted[0].body["tool_manifest_set_hash"].as_str().is_some_and(|hash| {
                hash == account(&state).mcp_registry.tool_manifest_set_hash()
            })
        );

        let create_second = request(
            "grant.request",
            serde_json::json!({
                "grant_id": "grant_deny",
                "server_id": "srv",
                "tool_name": "echo",
                "capability": serde_json::Value::Null,
                "full_delegation": false,
            }),
        );
        let mut request_connection = test_connection(3);
        let denial_approval =
            dispatch_grant_bus_request(&create_second, &mut state, &mut request_connection)
                .expect("create denial approval")
                .response_body["approval"]
                .clone();
        let denial_id = denial_approval["approval_id"].as_str().expect("denial id");
        let mut deny_connection = test_connection(4);
        deny_connection.topics.insert("mcp.approval.denied".to_owned());
        let deny = request("grant.deny", serde_json::json!({ "approval_id": denial_id }));
        dispatch_grant_bus_request(&deny, &mut state, &mut deny_connection).expect("deny grant");
        let denied = deny_connection.drain_events();
        assert_eq!(denied.len(), 1);
        assert_eq!(denied[0].method, "mcp.approval.denied");
        assert_eq!(denied[0].body["event_type"], "mcp.approval.denied");
        assert_eq!(denied[0].body["status"], "denied");
    }

    #[test]
    fn mcp_registry_grant_and_audit_survive_account_reload() {
        let (mut state, root) = test_state_named("mcp-reload");
        install_tool(
            &mut state,
            "srv",
            "notes",
            McpCapability::ReadConversation,
            Some("thread:1"),
            RiskLevel::Low,
        );
        let registry_hash = account(&state).mcp_registry.registry_hash().to_owned();
        let tool_manifest_set_hash =
            account(&state).mcp_registry.tool_manifest_set_hash().to_owned();
        let started = request(
            "mcp.tool.started",
            serde_json::json!({
                "server_id": "srv",
                "tool_name": "notes",
                "arguments": {"text": "hello"},
                "operation_origin": "ai_mcp",
            }),
        );
        let pending = dispatch_mcp_bus_request(&started, &mut state, &mut test_connection(1))
            .expect("first tool call creates approval");
        assert_eq!(pending.response_body["status"], "approval_required");
        let approval_id = pending.response_body["approval"]["approval_id"]
            .as_str()
            .expect("approval id")
            .to_owned();
        let approved = dispatch_grant_bus_request(
            &request("grant.approve", serde_json::json!({ "approval_id": approval_id })),
            &mut state,
            &mut test_connection(2),
        )
        .expect("approve grant");
        assert_eq!(approved.response_body["state"]["revoked"], false);
        assert!(
            account(&state)
                .mcp_audit_log
                .iter()
                .any(|record| record.event_type == "mcp.approval.granted")
        );

        let restored_client = unlocked_client(&root);
        let mut restored_account =
            LocalBusAccountState::disconnected(restored_client, gateway_config());
        hydrate_local_mcp_state(&mut restored_account).expect("hydrate mcp state");
        assert_eq!(restored_account.mcp_registry.registry_hash(), registry_hash);
        assert_eq!(restored_account.mcp_registry.tool_manifest_set_hash(), tool_manifest_set_hash);
        assert_eq!(restored_account.mcp_grants.len(), 1);
        assert!(
            restored_account
                .mcp_audit_log
                .iter()
                .any(|record| record.event_type == "mcp.approval.request")
        );

        let mut restored_state = LocalBusDaemonState {
            config: LocalBusConfig::new(root.join("bus-restored.sock"), root),
            accounts: BTreeMap::from([(ACCOUNT_ID.to_owned(), restored_account)]),
            active_account_id: Some(ACCOUNT_ID.to_owned()),
            attended_accounts: BTreeSet::from([ACCOUNT_ID.to_owned()]),
            subscribers: BTreeMap::new(),
        };
        let invoked =
            dispatch_mcp_bus_request(&started, &mut restored_state, &mut test_connection(3))
                .expect("authorized invoke after reload");
        assert_eq!(invoked.response_body["status"], "ok");
        assert_eq!(invoked.response_body["result"], "srv:notes");
    }

    #[test]
    fn mcp_standing_auto_approval_allows_low_risk_and_survives_reload() {
        let (mut state, root) = test_state_named("mcp-standing");
        install_tool(
            &mut state,
            "srv",
            "notes",
            McpCapability::ReadConversation,
            Some("thread:standing"),
            RiskLevel::Low,
        );
        let create = request(
            "grant.create_standing_approval",
            serde_json::json!({
                "server_id": "srv",
                "tool_name": "notes",
                "tool_scope": "thread:standing",
                "ttl_seconds": 3600,
            }),
        );
        let standing = dispatch_grant_bus_request(&create, &mut state, &mut test_connection(1))
            .expect("create standing approval")
            .response_body;
        assert_eq!(standing["server_id"], "srv");
        assert_eq!(standing["tool_name"], "notes");
        assert_eq!(standing["revoked"], false);

        let started = request(
            "mcp.tool.started",
            serde_json::json!({
                "server_id": "srv",
                "tool_name": "notes",
                "arguments": {"text": "auto"},
                "operation_origin": "ai_mcp",
            }),
        );
        let mut invoke_connection = test_connection(2);
        invoke_connection.topics.insert("mcp.standing_auto_approval.invoked".to_owned());
        let invoked = dispatch_mcp_bus_request(&started, &mut state, &mut invoke_connection)
            .expect("standing invoke");
        assert_eq!(invoked.response_body["status"], "ok");
        assert_eq!(invoked.response_body["standing_approval_id"], standing["standing_approval_id"]);
        assert!(account(&state).mcp_pending_approvals.is_empty());
        assert!(
            account(&state)
                .mcp_audit_log
                .iter()
                .any(|record| record.event_type == "mcp.standing_auto_approval.invoked"
                    && record.outcome == "allowed")
        );

        let restored_client = unlocked_client(&root);
        let mut restored_account =
            LocalBusAccountState::disconnected(restored_client, gateway_config());
        hydrate_local_mcp_state(&mut restored_account).expect("hydrate mcp state");
        assert_eq!(restored_account.mcp_standing_approvals.len(), 1);
        let mut restored_state = LocalBusDaemonState {
            config: LocalBusConfig::new(root.join("bus-restored.sock"), root),
            accounts: BTreeMap::from([(ACCOUNT_ID.to_owned(), restored_account)]),
            active_account_id: Some(ACCOUNT_ID.to_owned()),
            attended_accounts: BTreeSet::from([ACCOUNT_ID.to_owned()]),
            subscribers: BTreeMap::new(),
        };
        let restored_invoked =
            dispatch_mcp_bus_request(&started, &mut restored_state, &mut test_connection(3))
                .expect("standing invoke after reload");
        assert_eq!(restored_invoked.response_body["status"], "ok");
        assert!(account(&restored_state).mcp_pending_approvals.is_empty());
    }

    #[test]
    fn mcp_standing_auto_approval_respects_risk_floor_revoke_and_expiry() {
        let mut state = test_state();
        install_tool(
            &mut state,
            "srv",
            "notes",
            McpCapability::ReadConversation,
            Some("thread:standing"),
            RiskLevel::Low,
        );
        install_tool(
            &mut state,
            "srv",
            "shell",
            McpCapability::ExternalToolInvoke,
            Some("shell"),
            RiskLevel::High,
        );
        let create = request(
            "grant.create_standing_approval",
            serde_json::json!({
                "server_id": "srv",
                "tool_name": "notes",
                "tool_scope": "thread:standing",
            }),
        );
        let standing = dispatch_grant_bus_request(&create, &mut state, &mut test_connection(1))
            .expect("create standing")
            .response_body;
        let standing_id =
            standing["standing_approval_id"].as_str().expect("standing id").to_owned();

        let revoke = request(
            "grant.revoke_standing_approval",
            serde_json::json!({ "standing_approval_id": standing_id }),
        );
        dispatch_grant_bus_request(&revoke, &mut state, &mut test_connection(2))
            .expect("revoke standing");
        let started = request(
            "mcp.tool.started",
            serde_json::json!({
                "server_id": "srv",
                "tool_name": "notes",
                "arguments": {},
                "operation_origin": "ai_mcp",
            }),
        );
        let revoked_result =
            dispatch_mcp_bus_request(&started, &mut state, &mut test_connection(3))
                .expect("revoked standing falls back to approval");
        assert_eq!(revoked_result.response_body["status"], "approval_required");

        let create_expiring = request(
            "grant.create_standing_approval",
            serde_json::json!({
                "server_id": "srv",
                "tool_name": "notes",
                "tool_scope": "thread:standing",
                "ttl_seconds": 1,
            }),
        );
        let expiring =
            dispatch_grant_bus_request(&create_expiring, &mut state, &mut test_connection(4))
                .expect("create expiring standing")
                .response_body["standing_approval_id"]
                .as_str()
                .expect("expiring standing id")
                .to_owned();
        account_mut(&mut state)
            .mcp_standing_approvals
            .get_mut(&expiring)
            .expect("expiring standing")
            .expires_at = 1;
        let expired_result =
            dispatch_mcp_bus_request(&started, &mut state, &mut test_connection(5))
                .expect("expired standing falls back to approval");
        assert_eq!(expired_result.response_body["status"], "approval_required");

        let high_create = request(
            "grant.create_standing_approval",
            serde_json::json!({
                "server_id": "srv",
                "tool_name": "shell",
                "tool_scope": "shell",
            }),
        );
        let high_rejected =
            dispatch_grant_bus_request(&high_create, &mut state, &mut test_connection(6));
        assert!(matches!(high_rejected, Err(SdkError::CapabilityDenied(_))));
        let high_call = request(
            "mcp.tool.started",
            serde_json::json!({
                "server_id": "srv",
                "tool_name": "shell",
                "arguments": {"cmd": "echo nope"},
                "operation_origin": "ai_mcp",
            }),
        );
        let high_result = dispatch_mcp_bus_request(&high_call, &mut state, &mut test_connection(7))
            .expect("high risk still requires approval");
        assert_eq!(high_result.response_body["status"], "approval_required");
        assert_eq!(high_result.response_body["approval"]["confirmation_mode"], "remote_app");
    }

    #[test]
    fn mcp_grant_signature_uses_stored_approval_expiry() {
        let mut state = test_state();
        install_tool(
            &mut state,
            "srv",
            "notes",
            McpCapability::ReadConversation,
            Some("thread:expiry"),
            RiskLevel::Low,
        );
        let approval = dispatch_mcp_bus_request(
            &request(
                "mcp.tool.started",
                serde_json::json!({
                    "server_id": "srv",
                    "tool_name": "notes",
                    "arguments": {},
                    "operation_origin": "ai_mcp",
                }),
            ),
            &mut state,
            &mut test_connection(1),
        )
        .expect("create approval")
        .response_body["approval"]
            .clone();
        let approval_id = approval["approval_id"].as_str().expect("approval id");
        let approval_expires_at = approval["expires_at"].as_i64().expect("approval expires_at");
        assert!(approval_expires_at > now_unix_timestamp());

        let grant: LocalMcpGrantRecord = serde_json::from_value(
            dispatch_grant_bus_request(
                &request("grant.approve", serde_json::json!({ "approval_id": approval_id })),
                &mut state,
                &mut test_connection(2),
            )
            .expect("approve grant")
            .response_body,
        )
        .expect("grant record");

        assert_eq!(grant.signing_body.expires_at, approval_expires_at);
        assert_eq!(grant.state.expires_at, approval_expires_at);
        assert!(mcp_verify_grant_signature(&grant).is_ok());
    }

    #[test]
    fn expired_mcp_grant_is_rejected_even_with_valid_signature() {
        let mut state = test_state();
        install_tool(
            &mut state,
            "srv",
            "notes",
            McpCapability::ReadConversation,
            Some("thread:expired"),
            RiskLevel::Low,
        );
        let approval = dispatch_mcp_bus_request(
            &request(
                "mcp.tool.started",
                serde_json::json!({
                    "server_id": "srv",
                    "tool_name": "notes",
                    "arguments": {},
                    "operation_origin": "ai_mcp",
                }),
            ),
            &mut state,
            &mut test_connection(1),
        )
        .expect("create approval")
        .response_body["approval"]
            .clone();
        let approval_id = approval["approval_id"].as_str().expect("approval id").to_owned();
        let expired_at = now_unix_timestamp().saturating_sub(1);
        let pending = account_mut(&mut state)
            .mcp_pending_approvals
            .get_mut(&approval_id)
            .expect("pending approval");
        pending.expires_at = expired_at;
        pending.details["expires_at"] = serde_json::json!(expired_at);

        let grant: LocalMcpGrantRecord = serde_json::from_value(
            dispatch_grant_bus_request(
                &request("grant.approve", serde_json::json!({ "approval_id": approval_id })),
                &mut state,
                &mut test_connection(2),
            )
            .expect("approve expired grant")
            .response_body,
        )
        .expect("expired grant record");
        assert_eq!(grant.signing_body.expires_at, expired_at);
        assert!(mcp_verify_grant_signature(&grant).is_ok());

        let error = match dispatch_mcp_bus_request(
            &request(
                "mcp.tool.started",
                serde_json::json!({
                    "server_id": "srv",
                    "tool_name": "notes",
                    "arguments": {},
                    "operation_origin": "ai_mcp",
                }),
            ),
            &mut state,
            &mut test_connection(3),
        ) {
            Ok(_) => panic!("expired grant must not authorize invoke"),
            Err(error) => error,
        };
        assert!(matches!(error, SdkError::GrantInvalidated));
    }

    #[test]
    fn mcp_tool_started_completed_and_failed_events_are_canonical() {
        let mut state = test_state();
        install_tool(
            &mut state,
            "srv",
            "echo",
            McpCapability::ReadConversation,
            Some("echo"),
            RiskLevel::Low,
        );
        let mut create_connection = test_connection(1);
        let approval = dispatch_mcp_bus_request(
            &request(
                "mcp.tool.started",
                serde_json::json!({
                    "server_id": "srv",
                    "tool_name": "echo",
                    "arguments": {},
                    "operation_origin": "ai_mcp",
                }),
            ),
            &mut state,
            &mut create_connection,
        )
        .expect("create approval")
        .response_body["approval"]
            .clone();
        let approval_id = approval["approval_id"].as_str().expect("approval id");
        let mut approve_connection = test_connection(2);
        dispatch_grant_bus_request(
            &request("grant.approve", serde_json::json!({ "approval_id": approval_id })),
            &mut state,
            &mut approve_connection,
        )
        .expect("approve grant");

        let mut connection = test_connection(3);
        connection.topics.extend([
            "mcp.tool.started".to_owned(),
            "mcp.tool.completed".to_owned(),
            "mcp.tool.failed".to_owned(),
        ]);
        let granted_result = dispatch_mcp_bus_request(
            &request(
                "mcp.tool.started",
                serde_json::json!({
                    "server_id": "srv",
                    "tool_name": "echo",
                    "arguments": {"text": "ok"},
                    "operation_origin": "ai_mcp",
                }),
            ),
            &mut state,
            &mut connection,
        )
        .expect("invoke granted tool");
        assert_eq!(granted_result.response_body["status"], "ok");
        assert_eq!(granted_result.response_body["result"], "srv:echo");
        assert_eq!(granted_result.response_body["output"]["echo"]["text"], "ok");
        let events = connection.drain_events();
        assert_eq!(
            events.iter().map(|event| event.method.as_str()).collect::<Vec<_>>(),
            ["mcp.tool.started", "mcp.tool.completed",]
        );
        assert!(events.iter().all(|event| event.body["tool_manifest_set_hash"]
            == account(&state).mcp_registry.tool_manifest_set_hash()));

        install_tool(&mut state, "srv", "shell", McpCapability::RunShell, None, RiskLevel::High);
        let registry_hash = account(&state).mcp_registry.registry_hash().to_owned();
        let tool_manifest_set_hash =
            account(&state).mcp_registry.tool_manifest_set_hash().to_owned();
        account_mut(&mut state).mcp_grants.insert(
            "grant_full".to_owned(),
            LocalMcpGrantRecord {
                grant_id: "grant_full".to_owned(),
                state: McpGrantState {
                    server_id: "wildcard".to_owned(),
                    tool_name: "wildcard".to_owned(),
                    tool_scope: Some("wildcard".to_owned()),
                    registry_hash: registry_hash.clone(),
                    tool_manifest_set_hash: tool_manifest_set_hash.clone(),
                    full_delegation: true,
                    allowed_capabilities: BTreeSet::new(),
                    revoked: false,
                    expires_at: FUTURE_EXPIRES_AT,
                },
                signed_by_device_id: "device_mcp_test".to_owned(),
                signer_public_key: String::new(),
                signature: String::new(),
                signing_body: LocalMcpGrantSigningBody {
                    approval_id: "approval_full".to_owned(),
                    grant_id: "grant_full".to_owned(),
                    server_id: "wildcard".to_owned(),
                    tool_name: "wildcard".to_owned(),
                    tool_scope: Some("wildcard".to_owned()),
                    capability: McpCapability::ExternalToolInvoke,
                    registry_hash,
                    tool_manifest_set_hash,
                    full_delegation: true,
                    expires_at: FUTURE_EXPIRES_AT,
                },
                confirmation_mode: "remote_app".to_owned(),
            },
        );
        let mut failed_connection = test_connection(4);
        failed_connection
            .topics
            .extend(["mcp.tool.started".to_owned(), "mcp.tool.failed".to_owned()]);
        let error = match dispatch_mcp_bus_request(
            &request(
                "mcp.tool.started",
                serde_json::json!({
                    "server_id": "srv",
                    "tool_name": "shell",
                    "arguments": {"cmd": "id"},
                    "operation_origin": "ai_mcp",
                }),
            ),
            &mut state,
            &mut failed_connection,
        ) {
            Ok(_) => panic!("high-risk full delegation unexpectedly succeeded"),
            Err(error) => error,
        };
        assert!(matches!(error, SdkError::CapabilityDenied(_)));
        let failed = failed_connection.drain_events();
        assert_eq!(
            failed.iter().map(|event| event.method.as_str()).collect::<Vec<_>>(),
            ["mcp.tool.started", "mcp.tool.failed",]
        );
        assert_eq!(failed[1].body["error"]["code"], "CapabilityDenied");
    }

    #[test]
    fn mcp_valid_grant_wins_over_stale_grant_for_same_capability() {
        let mut state = test_state();
        install_tool(
            &mut state,
            "srv",
            "echo",
            McpCapability::ReadConversation,
            Some("echo"),
            RiskLevel::Low,
        );
        let approval = dispatch_mcp_bus_request(
            &request(
                "mcp.tool.started",
                serde_json::json!({
                    "server_id": "srv",
                    "tool_name": "echo",
                    "arguments": {"text": "needs approval"},
                    "operation_origin": "ai_mcp",
                }),
            ),
            &mut state,
            &mut test_connection(1),
        )
        .expect("create approval")
        .response_body["approval"]
            .clone();
        let approval_id = approval["approval_id"].as_str().expect("approval id");
        let approved = dispatch_grant_bus_request(
            &request("grant.approve", serde_json::json!({ "approval_id": approval_id })),
            &mut state,
            &mut test_connection(2),
        )
        .expect("approve grant")
        .response_body;
        let valid_grant: LocalMcpGrantRecord =
            serde_json::from_value(approved).expect("valid grant json");
        let mut stale_grant = valid_grant;
        stale_grant.grant_id = "aaa_stale_grant".to_owned();
        stale_grant.state.tool_manifest_set_hash = "stale_manifest_hash".to_owned();
        stale_grant.signing_body.tool_manifest_set_hash = "stale_manifest_hash".to_owned();
        account_mut(&mut state).mcp_grants.insert(stale_grant.grant_id.clone(), stale_grant);

        let result = dispatch_mcp_bus_request(
            &request(
                "mcp.tool.started",
                serde_json::json!({
                    "server_id": "srv",
                    "tool_name": "echo",
                    "arguments": {"text": "ok"},
                    "operation_origin": "ai_mcp",
                }),
            ),
            &mut state,
            &mut test_connection(3),
        )
        .expect("valid grant should not be shadowed by stale grant");
        assert_eq!(result.response_body["status"], "ok");
        assert_eq!(result.response_body["result"], "srv:echo");
    }

    #[test]
    fn mcp_server_add_clamps_low_risk_override_for_high_default_capability() {
        let mut state = test_state();
        install_tool(&mut state, "srv", "shell", McpCapability::RunShell, None, RiskLevel::Low);
        let manifest = account(&state)
            .mcp_registry
            .tools()
            .into_iter()
            .find(|tool| tool.server_id == "srv" && tool.tool_name == "shell")
            .expect("stored shell manifest");
        assert_eq!(manifest.declared_risk, RiskLevel::High);
        assert_eq!(manifest.effective_risk(), RiskLevel::High);
    }

    #[test]
    fn mcp_grant_scope_does_not_cover_other_tool_with_same_capability() {
        let mut state = test_state();
        install_tool(
            &mut state,
            "srv_a",
            "tool_x",
            McpCapability::ReadConversation,
            Some("thread_a"),
            RiskLevel::Low,
        );
        install_tool(
            &mut state,
            "srv_b",
            "tool_y",
            McpCapability::ReadConversation,
            Some("thread_b"),
            RiskLevel::Low,
        );
        let approval = dispatch_mcp_bus_request(
            &request(
                "mcp.tool.started",
                serde_json::json!({
                    "server_id": "srv_a",
                    "tool_name": "tool_x",
                    "arguments": {},
                    "operation_origin": "ai_mcp",
                }),
            ),
            &mut state,
            &mut test_connection(1),
        )
        .expect("create scoped approval")
        .response_body["approval"]
            .clone();
        let approval_id = approval["approval_id"].as_str().expect("approval id");
        dispatch_grant_bus_request(
            &request("grant.approve", serde_json::json!({ "approval_id": approval_id })),
            &mut state,
            &mut test_connection(2),
        )
        .expect("approve scoped grant");

        let result = dispatch_mcp_bus_request(
            &request(
                "mcp.tool.started",
                serde_json::json!({
                    "server_id": "srv_b",
                    "tool_name": "tool_y",
                    "arguments": {},
                    "operation_origin": "ai_mcp",
                }),
            ),
            &mut state,
            &mut test_connection(3),
        )
        .expect("other tool should require its own approval");
        assert_eq!(result.response_body["status"], "approval_required");
    }

    #[test]
    fn mcp_grant_scope_is_covered_by_device_signature() {
        let mut state = test_state();
        install_tool(
            &mut state,
            "srv",
            "echo",
            McpCapability::ReadConversation,
            Some("thread_a"),
            RiskLevel::Low,
        );
        let approval = dispatch_mcp_bus_request(
            &request(
                "mcp.tool.started",
                serde_json::json!({
                    "server_id": "srv",
                    "tool_name": "echo",
                    "arguments": {},
                    "operation_origin": "ai_mcp",
                }),
            ),
            &mut state,
            &mut test_connection(1),
        )
        .expect("create approval")
        .response_body["approval"]
            .clone();
        let approval_id = approval["approval_id"].as_str().expect("approval id");
        let mut grant: LocalMcpGrantRecord = serde_json::from_value(
            dispatch_grant_bus_request(
                &request("grant.approve", serde_json::json!({ "approval_id": approval_id })),
                &mut state,
                &mut test_connection(2),
            )
            .expect("approve grant")
            .response_body,
        )
        .expect("grant record");
        assert!(mcp_verify_grant_signature(&grant).is_ok());

        grant.signing_body.tool_scope = Some("thread_b".to_owned());
        assert!(mcp_verify_grant_signature(&grant).is_err());
    }
}
