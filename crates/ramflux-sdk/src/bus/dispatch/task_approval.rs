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
    rows.extend(account.client.task_approval_decision_rows()?);
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
    if let Err(error) = apply_decisions(account) {
        tracing::warn!(%error,"task approval decision scan deferred");
    }
    if let Err(error) = cleanup(account) {
        tracing::warn!(%error,"task approval cleanup deferred");
    }
    if let Err(error) = queue_requests(account) {
        tracing::warn!(%error,"task approval request admission deferred; decision courier continues");
    }
    let now = now_unix_timestamp();
    let mut rows = account.client.account_db()?.task_record_page::<Value>(
        "task/approval_decision_out/",
        "task/approval_decision_out/",
        65,
    )?;
    rows.extend(account.client.account_db()?.task_record_page::<Value>(
        "task/approval_out/",
        "task/approval_out/",
        65,
    )?);
    let mut sent = 0;
    let mut attempted = 0;
    for (storage, row) in rows {
        let Some(mut job) = crate::error_policy::task_scan(
            &storage,
            serde_json::from_value::<Job>(row).map_err(SdkError::from),
        )?
        else {
            continue;
        };
        if job.next_at > now || job.packet.deadline() <= now || job.attempts >= 8 {
            continue;
        }
        let Some(bytes) = crate::error_policy::task_scan(&storage, job.packet.bytes())? else {
            continue;
        };
        let request = job.packet.request();
        attempted += 1;
        let result = super::task_approval_transport::send(
            account,
            &request.binding.conversation_id,
            job.packet.recipient(),
            &bytes,
        )
        .await;
        if let Err(error) = &result {
            tracing::debug!(%error, job = %storage, "task approval transport attempt deferred");
        }
        crate::error_policy::task_scan(
            &storage,
            record_delivery(account, &storage, &mut job, result.is_ok(), now),
        )?;
        if result.is_ok() {
            sent += 1;
        }
        if attempted >= 2 {
            break;
        }
    }
    Ok(sent)
}
fn queue_requests(account: &mut LocalBusAccountState) -> Result<(), SdkError> {
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
            let result = (|| {
                if row["assignee"] != local.principal_id {
                    return Ok(());
                }
                let Some(conv) = row["conversation_id"].as_str() else { return Ok(()) };
                let Some(id) = row["task_id"].as_str() else { return Ok(()) };
                let history = account.client.task_history(conv, id)?;
                let state = history.state()?;
                let Some(task) = state.task() else { return Ok(()) };
                for step in &task.steps {
                    let Some(ramflux_protocol::NeedsMe::Approval { grant_id }) = &step.needs_me
                    else {
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
                    if account.client.account_db()?.actor_state_exists(&source_key)?
                        || account.client.task_approval_receipt(&packet.id()?)?.is_some()
                    {
                        continue;
                    }
                    let queued = account.client.account_db()?.write_transaction(|| {
                        account.client.queue_task_approval(&packet)?;
                        account.client.remember_task_approval_source(&packet)?;
                        Ok::<_, SdkError>(())
                    });
                    match queued {
                        Ok(()) => {}
                        Err(SdkError::TaskRefused {
                            reason: crate::TaskRefusalCode::PeerQuotaExhausted,
                            ..
                        }) => continue,
                        Err(error) => return Err(error),
                    }
                    account.mcp_pending_approvals.insert(approval.approval_id.clone(), approval);
                    made += 1;
                    if made >= 2 {
                        return Ok(());
                    }
                }
                Ok::<_, SdkError>(())
            })();
            crate::error_policy::task_scan(&cursor, result)?;
            if made >= 2 {
                return Ok(());
            }
        }
        if done {
            break;
        }
    }
    Ok(())
}
#[path = "task_approval_apply.rs"]
mod apply;
use apply::apply_decisions;
#[path = "task_approval_cleanup.rs"]
mod cleanup;
use cleanup::cleanup;
#[cfg(test)]
#[path = "tests/task_approval.rs"]
mod tests;

fn record_delivery(
    account: &LocalBusAccountState,
    storage: &str,
    job: &mut Job,
    success: bool,
    now: i64,
) -> Result<(), SdkError> {
    use crate::client::task::approval_retention::{DeliveryReason, DeliveryState};
    job.attempts = job.attempts.saturating_add(1);
    let db = account.client.account_db()?;
    db.write_transaction(|| {
        let decision = matches!(job.packet.payload, Payload::Decision { .. });
        if success {
            if decision {
                account.client.retire_task_approval(&job.packet, DeliveryState::Submitted, None)?;
            }
            db.delete_task_state(storage)?;
        } else {
            job.next_at = now.saturating_add(2_i64.pow(job.attempts.min(6)));
            db.persist_actor_state(storage, job)?;
            if decision {
                account.client.record_task_approval_delivery(
                    &job.packet,
                    if job.attempts >= 8 { DeliveryState::Failed } else { DeliveryState::Pending },
                    Some(if job.attempts >= 8 {
                        DeliveryReason::RetryExhausted
                    } else {
                        DeliveryReason::TransportUnavailable
                    }),
                )?;
            }
        }
        Ok(())
    })
}
