// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Bounded approval courier between task endpoints; MCP remains the capability authority.
use crate::client::task::{
    approval::{Job, Packet, Payload, Request},
    invalid, key,
};
use crate::prelude::*;
use serde_json::{Value, json};

pub(super) fn list(account: &LocalBusAccountState) -> Result<Vec<Value>, SdkError> {
    let mut rows = account
        .mcp_pending_approvals
        .values()
        .map(serde_json::to_value)
        .collect::<Result<Vec<_>, _>>()?;
    rows.extend(account.client.task_remote_approvals()?);
    Ok(rows)
}
pub(super) fn decide(
    request: &LocalBusFrame,
    state: &LocalBusDaemonState,
    account_id: &str,
    approved: bool,
) -> Result<Option<Value>, SdkError> {
    let Some(id) =
        request.body["approval_id"].as_str().filter(|id| id.starts_with("task_approval_"))
    else {
        return Ok(None);
    };
    let manifest = read_local_bus_account_manifest(&local_bus_account_manifest_path(
        &state.config.data_root,
        account_id,
    ))?;
    let kind = manifest.kind.as_deref().unwrap_or(
        if manifest.client_mode == LocalBusClientMode::HeadlessAi {
            "headless_ai"
        } else {
            "human"
        },
    );
    crate::client::task::require_local_human(&manifest.client_mode, Some(kind))?;
    Ok(Some(local_bus_account(state, account_id)?.client.decide_task_approval(id, approved)?))
}
pub(crate) async fn drive(account: &mut LocalBusAccountState) -> Result<usize, SdkError> {
    apply_decisions(account)?;
    queue_requests(account)?;
    let now = now_unix_timestamp();
    let rows = account.client.account_db()?.task_record_page::<Job>(
        "task/approval_out/",
        "task/approval_out/",
        129,
    )?;
    let mut sent = 0;
    for (storage, mut job) in rows
        .into_iter()
        .filter(|(_, j)| {
            j.next_at <= now && j.attempts < 8 && j.packet.request().approval.expires_at > now
        })
        .take(2)
    {
        let request = job.packet.request();
        if request.approval.expires_at <= now || job.attempts >= 8 {
            continue;
        }
        let bytes = job.packet.bytes()?;
        let result = super::task_approval_transport::send(
            account,
            &request.binding.conversation_id,
            job.packet.recipient(),
            &bytes,
        )
        .await;
        // Keep the durable packet as an idempotency fence; bounded expiry cleanup removes it later.
        job.attempts += 1;
        job.next_at = if result.is_ok() {
            request.approval.expires_at
        } else {
            now.saturating_add(2_i64.pow(job.attempts.min(6)))
        };
        account.client.account_db()?.persist_actor_state(&storage, &job)?;
        if result.is_ok() {
            sent += 1;
        }
    }
    Ok(sent)
}
fn queue_requests(account: &mut LocalBusAccountState) -> Result<(), SdkError> {
    cleanup(account)?;
    let local = account.client.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?.clone();
    let pending = account.mcp_pending_approvals.values().cloned().collect::<Vec<_>>();
    if pending.is_empty() {
        return Ok(());
    }
    let mut cursor = "task/view/".to_owned();
    let mut made = 0;
    for _ in 0..10 {
        let rows =
            account.client.account_db()?.task_record_page::<Value>("task/view/", &cursor, 101)?;
        let done = rows.len() < 101;
        for (row_key, row) in rows {
            cursor = row_key;
            if row["assignee"] != local.principal_id {
                continue;
            }
            let Some(conv) = row["conversation_id"].as_str() else { continue };
            let Some(id) = row["task_id"].as_str() else { continue };
            let history = account.client.task_history(conv, id)?;
            let state = history.state()?;
            let Some(task) = state.task() else { continue };
            for step in &task.steps {
                let Some(ramflux_protocol::NeedsMe::Approval { grant_id }) = &step.needs_me else {
                    continue;
                };
                let binding = account.client.task_approval_binding(
                    conv,
                    id,
                    &step.id,
                    step.needs_me.as_ref().ok_or_else(|| invalid("approval target missing"))?,
                )?;
                if binding.executor_device_id != local.device_id {
                    continue;
                }
                let Some(mut approval) = pending
                    .iter()
                    .find(|a| {
                        a.details["requested_grant_id"].as_str() == Some(grant_id.as_str())
                            || format!("grant_{}", a.approval_id) == *grant_id
                    })
                    .cloned()
                else {
                    continue;
                };
                if approval.expires_at <= now_unix_timestamp() {
                    continue;
                }
                approval.details["task_binding"] = serde_json::to_value(&binding)?;
                approval.details["single_use"] = json!(true);
                approval.details["full_delegation"] = json!(false);
                let body = super::grant_mcp::mcp_grant_signing_body(account, &approval)?;
                let packet = account.client.sign_task_approval(Payload::Request {
                    request: Box::new(Request {
                        binding,
                        approval: approval.clone(),
                        grant_body: body,
                    }),
                })?;
                let source_key = key("approval_source", &packet.id()?);
                if account.client.account_db()?.actor_state_exists(&source_key)? {
                    continue;
                }
                account.client.account_db()?.write_transaction(|| {
                    account.client.queue_task_approval(&packet)?;
                    account.client.account_db()?.persist_actor_state(&source_key, &packet)?;
                    Ok::<_, SdkError>(())
                })?;
                account.mcp_pending_approvals.insert(approval.approval_id.clone(), approval);
                made += 1;
                if made >= 2 {
                    return Ok(());
                }
            }
        }
        if done {
            break;
        }
    }
    Ok(())
}
fn apply_decisions(account: &mut LocalBusAccountState) -> Result<(), SdkError> {
    let rows = account.client.account_db()?.task_record_page::<Packet>(
        "task/approval_decision_in/",
        "task/approval_decision_in/",
        129,
    )?;
    let local = account.client.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?.clone();
    let mut accepted = 0;
    for (_, packet) in
        rows.into_iter().filter(|(_, p)| p.request().binding.executor_device_id == local.device_id)
    {
        let id = packet.id()?;
        let applied = key("approval_applied", &id);
        if account.client.account_db()?.actor_state_exists(&applied)? {
            continue;
        }
        let Some(original) = account
            .client
            .account_db()?
            .load_actor_state::<Packet>(&key("approval_source", &id))?
        else {
            continue;
        };
        let Payload::Decision { request, approved, .. } = &packet.payload else {
            continue;
        };
        if serde_json::to_vec(request.as_ref())? != serde_json::to_vec(original.request())? {
            return Err(invalid("task decision differs from original MCP approval"));
        }
        if accepted >= 2 {
            break;
        }
        let approval = request.approval.clone();
        // Recompute against the current installed registry; a stale registry requires a new approval.
        if serde_json::to_vec(&super::grant_mcp::mcp_grant_signing_body(account, &approval)?)?
            != serde_json::to_vec(&request.grant_body)?
        {
            continue;
        }
        if *approved {
            if let Err(error) = accept_grant(account, &packet) {
                tracing::warn!(%error,"task approval rejected by MCP validation");
                account.client.account_db()?.persist_actor_state(
                    &applied,
                    &json!({"expires_at":approval.expires_at,"rejected":true}),
                )?;
                continue;
            }
        } else {
            let mut denial = approval.clone();
            denial.status = "denied".into();
            account
                .client
                .account_db()?
                .persist_actor_state(&format!("mcp/denied/{}", approval.approval_id), &denial)?;
        }
        accepted += 1;
        account.mcp_pending_approvals.remove(&approval.approval_id);
        account
            .client
            .account_db()?
            .persist_actor_state(&applied, &json!({"expires_at":approval.expires_at}))?;
        account.client.account_db()?.append_journal(
            &format!("task-approval-applied:{id}"),
            if *approved { "mcp.approval.granted" } else { "mcp.approval.denied" },
            &json!({"grant_id":request.grant_body.grant_id,"task_id":request.binding.task_id}),
            now_unix_timestamp(),
            None,
        )?;
    }
    Ok(())
}
fn cleanup(account: &LocalBusAccountState) -> Result<(), SdkError> {
    let db = account.client.account_db()?;
    let now = now_unix_timestamp();
    for (key, row) in db.task_record_page::<Value>("task/approval_", "task/approval_", 513)? {
        let packet = row.get("packet").unwrap_or(&row);
        let expires = packet["payload"]["request"]["approval"]["expires_at"]
            .as_i64()
            .or_else(|| row["expires_at"].as_i64());
        if expires.is_some_and(|t| t <= now) {
            db.delete_task_state(&key)?;
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "tests/task_approval.rs"]
mod tests;

fn accept_grant(account: &mut LocalBusAccountState, packet: &Packet) -> Result<(), SdkError> {
    let Payload::Decision { request, grant_signature, .. } = &packet.payload else {
        return Err(invalid("approval decision expected"));
    };
    let body = &request.grant_body;
    let signature =
        grant_signature.as_deref().ok_or_else(|| invalid("task grant signature missing"))?;
    if let Some(stored) =
        account.client.account_db()?.load_mcp_grant::<LocalMcpGrantRecord>(&body.grant_id)?
    {
        if stored.signature != signature
            || serde_json::to_vec(&stored.signing_body)? != serde_json::to_vec(body)?
        {
            return Err(invalid("task approval conflicts with an existing grant"));
        }
        // Recovery after grant persistence must never undo consumption or revocation.
        account.mcp_grants.insert(stored.grant_id.clone(), stored);
        return Ok(());
    }
    let binding = account.client.task_approval_binding(
        &request.binding.conversation_id,
        &request.binding.task_id,
        &request.binding.step_id,
        &ramflux_protocol::NeedsMe::Approval { grant_id: body.grant_id.clone() },
    )?;
    if binding != request.binding {
        return Err(invalid("task approval intervention changed before MCP acceptance"));
    }
    let public = account.client.task_signer_key(&packet.principal, &packet.device)?;
    super::grant_mcp::mcp_remote_grant_from_approval(
        account,
        request.approval.clone(),
        LocalBusMcpApprovalGrantRequest {
            approval_id: request.approval.approval_id.clone(),
            signed_by_device_id: packet.device.clone(),
            signer_public_key: public,
            signature: signature.into(),
        },
    )?;
    Ok(())
}
