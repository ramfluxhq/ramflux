// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Isolated decision application uses the executor's own immutable approval source.
use super::{Packet, Payload, invalid, key};
use crate::client::task::approval_retention::{DeliveryReason, DeliveryState};
use crate::prelude::*;
use serde_json::{Value, json};

pub(super) fn apply_decisions(account: &mut LocalBusAccountState) -> Result<(), SdkError> {
    apply_using(account, apply_one)
}
pub(super) fn apply_using(
    account: &mut LocalBusAccountState,
    mut apply: impl FnMut(&mut LocalBusAccountState, &Packet) -> Result<bool, SdkError>,
) -> Result<(), SdkError> {
    let rows = account.client.account_db()?.task_record_page::<Value>(
        "task/approval_decision_in/",
        "task/approval_decision_in/",
        101,
    )?;
    let local = account
        .client
        .device_branch
        .as_ref()
        .ok_or(SdkError::IdentityRootMissing)?
        .device_id
        .clone();
    let mut accepted = 0;
    for (storage, row) in rows {
        let result = match serde_json::from_value::<Packet>(row) {
            Ok(packet) if packet.request().binding.executor_device_id == local => {
                apply(account, &packet)
            }
            Ok(_) => continue,
            Err(error) => Err(SdkError::Json(error)),
        };
        match result {
            Ok(applied) => accepted += usize::from(applied),
            Err(error) if crate::error_policy::approval_retryable(&error) => {
                crate::task_warnings::warn(&storage, &error, "task approval deferred for retry");
            }
            Err(error) => {
                crate::task_warnings::warn(
                    &storage,
                    &error,
                    "task approval row rejected; other decisions continue",
                );
                if let Err(error) = reject_row(account, &storage) {
                    crate::task_warnings::warn(
                        &storage,
                        &error,
                        "task approval rejection persistence deferred",
                    );
                }
            }
        }
        if accepted >= 2 {
            break;
        }
    }
    Ok(())
}
fn reject_row(account: &LocalBusAccountState, storage: &str) -> Result<(), SdkError> {
    let db = account.client.account_db()?;
    let suffix = storage
        .strip_prefix("task/approval_decision_in/")
        .filter(|suffix| !suffix.is_empty())
        .ok_or_else(|| invalid("decision row id missing"))?;
    let rejected = format!("task/approval_rejected/{suffix}");
    db.write_transaction(|| {
        db.persist_actor_state(&rejected,&json!({"expires_at":now_unix_timestamp().saturating_add(crate::client::task::approval_retention::TTL),"reason_code":DeliveryReason::InvalidDecision}))?;
        db.prune_task_diagnostics("task/approval_rejected/",128)?;
        db.delete_task_state(storage)?;
        Ok(())
    })
}
pub(super) fn apply_one(
    account: &mut LocalBusAccountState,
    packet: &Packet,
) -> Result<bool, SdkError> {
    let id = packet.id()?;
    if let Some(receipt) = account.client.task_approval_receipt(&id)? {
        finish_directory_approval(
            account,
            &packet.request().approval.approval_id,
            receipt.approved,
        )?;
        return Ok(false);
    }
    let original = account
        .client
        .account_db()?
        .load_actor_state::<Packet>(&key("approval_source", &id))?
        .ok_or_else(|| invalid("task decision has no executor approval source"))?;
    if ramflux_protocol::canonical_json_bytes(packet.request())?
        != ramflux_protocol::canonical_json_bytes(original.request())?
    {
        return Err(invalid("task decision differs from original MCP approval"));
    }
    let Payload::Decision { approved, grant_signature, .. } = &packet.payload else {
        return Err(invalid("approval decision expected"));
    };
    let trusted = Packet {
        local_expires_at: Some(packet.deadline().min(original.deadline())),
        payload: Payload::Decision {
            request: Box::new(original.request().clone()),
            approved: *approved,
            grant_signature: grant_signature.clone(),
        },
        ..packet.clone()
    };
    if trusted.deadline() <= now_unix_timestamp() {
        return Err(invalid("task decision expired"));
    }
    let approval = original.request().approval.clone();
    let validation = (|| {
        if ramflux_protocol::canonical_json_bytes(
            &super::super::grant_mcp::mcp_grant_signing_body(account, &approval)?,
        )? != ramflux_protocol::canonical_json_bytes(&original.request().grant_body)?
        {
            return Err(invalid("task decision no longer matches installed MCP registry"));
        }
        if *approved {
            accept_grant(account, &trusted)?;
        } else {
            let mut denial = approval.clone();
            denial.status = "denied".into();
            account
                .client
                .account_db()?
                .persist_actor_state(&format!("mcp/denied/{}", approval.approval_id), &denial)?;
        }
        Ok::<_, SdkError>(())
    })();
    if let Err(error) = validation {
        if crate::error_policy::approval_retryable(&error) {
            return Err(error);
        }
        crate::task_warnings::warn(
            &key("approval_decision_in", &id),
            &error,
            "task approval rejected by MCP validation",
        );
        account.client.retire_task_approval(
            &trusted,
            DeliveryState::Rejected,
            Some(DeliveryReason::InvalidDecision),
        )?;
        return Ok(false);
    }
    account.mcp_pending_approvals.remove(&approval.approval_id);
    account.client.retire_task_approval(&trusted, DeliveryState::Applied, None)?;
    finish_directory_approval(account, &approval.approval_id, *approved)?;
    account.client.account_db()?.delete_task_state(&key("approval_applied", &id))?;
    account.client.account_db()?.append_journal(&format!("task-approval-applied:{id}"),if *approved {"mcp.approval.granted"}else{"mcp.approval.denied"},&json!({"grant_id":original.request().grant_body.grant_id,"task_id":original.request().binding.task_id}),now_unix_timestamp(),None)?;
    Ok(true)
}

fn finish_directory_approval(
    account: &mut LocalBusAccountState,
    approval_id: &str,
    approved: bool,
) -> Result<(), SdkError> {
    let db = account.client.account_db()?;
    if let Some(mut row) = db.client_record("approval", approval_id)? {
        let status = if approved { "approved" } else { "denied" };
        if row["status"].as_str() == Some(status) {
            account.mcp_pending_approvals.remove(approval_id);
            return Ok(());
        }
        row["status"] = json!(status);
        row["event_type"] =
            json!(if approved { "mcp.approval.granted" } else { "mcp.approval.denied" });
        db.persist_client_record("approval", approval_id, &row)?;
    }
    account.mcp_pending_approvals.remove(approval_id);
    Ok(())
}
fn accept_grant(account: &mut LocalBusAccountState, packet: &Packet) -> Result<(), SdkError> {
    let Payload::Decision { request, grant_signature, .. } = &packet.payload else {
        return Err(invalid("approval decision expected"));
    };
    let body = &request.grant_body;
    let signature =
        grant_signature.as_deref().ok_or_else(|| invalid("task grant signature missing"))?;
    if let Some(mut stored) =
        account.client.account_db()?.load_mcp_grant::<LocalMcpGrantRecord>(&body.grant_id)?
    {
        if stored.signature != signature
            || ramflux_protocol::canonical_json_bytes(&stored.signing_body)?
                != ramflux_protocol::canonical_json_bytes(body)?
        {
            return Err(invalid("task approval conflicts with an existing grant"));
        }
        if stored.state.expires_at > packet.deadline() {
            stored.state.expires_at = packet.deadline();
            super::super::grant_mcp::persist_mcp_grant(account, &stored)?;
        }
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
    super::super::grant_mcp::mcp_remote_grant_from_approval(
        account,
        request.approval.clone(),
        LocalBusMcpApprovalGrantRequest {
            approval_id: request.approval.approval_id.clone(),
            signed_by_device_id: packet.device.clone(),
            signer_public_key: public,
            signature: signature.into(),
        },
        Some(packet.deadline()),
    )?;
    Ok(())
}
