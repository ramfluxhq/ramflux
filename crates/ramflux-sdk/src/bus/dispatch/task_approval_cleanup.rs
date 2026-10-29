// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Courier rows have receiver-owned expiry and retire when their intervention closes.
use super::Packet;
use crate::client::task::approval_retention::{DeliveryReason, DeliveryState, TTL};
use crate::prelude::*;
use serde_json::{Value, json};
pub(super) fn cleanup(account: &LocalBusAccountState) -> Result<(), SdkError> {
    let db = account.client.account_db()?;
    let now = now_unix_timestamp();
    for namespace in [
        "approval_source",
        "approval_in",
        "approval_decision_in",
        "approval_out",
        "approval_decision_out",
    ] {
        let prefix = format!("task/{namespace}/");
        validate_outbound_jobs(account, namespace, &prefix)?;
        for (storage, mut row) in db.task_record_page::<Value>(&prefix, &prefix, 101)? {
            let result = (|| {
                let nested = row.get("packet").is_some();
                let value = if nested { row["packet"].clone() } else { row.clone() };
                let mut packet = match serde_json::from_value::<Packet>(value) {
                    Ok(packet) => packet,
                    Err(error) => {
                        if matches!(namespace, "approval_out" | "approval_decision_out") {
                            crate::bus::task_courier_queue::quarantine(
                                account,
                                &storage,
                                crate::bus::task_courier::Failure::UndecodableRow,
                            )?;
                        } else {
                            crate::task_warnings::warn(
                                &storage,
                                &SdkError::from(error),
                                "malformed approval row retired",
                            );
                            db.delete_task_state(&storage)?;
                        }
                        return Ok(());
                    }
                };
                if packet.local_expires_at.is_none() {
                    packet = packet.received();
                    if nested {
                        row["packet"] = serde_json::to_value(&packet)?;
                    } else {
                        row = serde_json::to_value(&packet)?;
                    }
                    db.persist_actor_state(&storage, &row)?;
                }
                let request = packet.request();
                let closed = match account.client.task_approval_binding(
                    &request.binding.conversation_id,
                    &request.binding.task_id,
                    &request.binding.step_id,
                    &ramflux_protocol::NeedsMe::Approval {
                        grant_id: request.grant_body.grant_id.clone(),
                    },
                ) {
                    Ok(binding) => binding != request.binding,
                    Err(
                        SdkError::TaskRefused { .. }
                        | SdkError::InboundRejected(_)
                        | SdkError::LocalBus(_),
                    ) => true,
                    Err(error) => return Err(error),
                };
                if packet.deadline() <= now || closed {
                    if closed
                        && packet.deadline() > now
                        && matches!(
                            packet.payload,
                            crate::client::task::approval::Payload::Decision { .. }
                        )
                    {
                        account.client.retire_task_approval(
                            &packet,
                            DeliveryState::Rejected,
                            Some(DeliveryReason::InterventionClosed),
                        )?;
                    }
                    db.delete_task_state(&storage)?;
                }
                Ok::<_, SdkError>(())
            })();
            crate::error_policy::task_scan(&storage, result)?;
        }
    }
    for namespace in ["approval_applied", "approval_rejected"] {
        let prefix = format!("task/{namespace}/");
        for (storage, mut row) in db.task_record_page::<Value>(&prefix, &prefix, 101)? {
            let expiry = row["expires_at"].as_i64().unwrap_or(now).min(now.saturating_add(TTL));
            if expiry <= now {
                db.delete_task_state(&storage)?;
            } else {
                row["expires_at"] = json!(expiry);
                db.persist_actor_state(&storage, &row)?;
            }
        }
        db.prune_task_diagnostics(&prefix, 128)?;
    }
    account.client.prune_task_approval_receipts()?;
    Ok(())
}

fn validate_outbound_jobs(
    account: &LocalBusAccountState,
    namespace: &str,
    prefix: &str,
) -> Result<(), SdkError> {
    if matches!(namespace, "approval_out" | "approval_decision_out") {
        // Validate complete jobs before legacy packet cleanup can delete them.
        // Reading keys first also isolates syntactically invalid JSON rows.
        for key in account.client.account_db()?.actor_state_key_page(prefix, 101)? {
            let _ = crate::bus::task_courier_queue::load(account, &key)?;
        }
    }
    Ok(())
}
