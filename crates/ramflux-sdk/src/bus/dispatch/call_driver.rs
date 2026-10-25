// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Bounded account-owned signaling retries, ring timers and authenticated relay lease maintenance.
use super::{invalid, recover};
use crate::client::call::{self, state::LiveCall};
use crate::prelude::*;
use ramflux_protocol::{VoiceAllocationRequest, VoiceLeaseRequest, VoiceLeaseResponse};
fn scope(c: &LiveCall) -> VoiceAllocationRequest {
    VoiceAllocationRequest {
        call_id: c.row.call_id.clone(),
        caller: c.caller.clone(),
        callee: c.callee.clone(),
    }
}
pub(crate) async fn drive(account: &mut LocalBusAccountState) -> Result<usize, SdkError> {
    recover(account)?;
    let ids = account.client.voice_calls.keys().cloned().collect::<Vec<_>>();
    let mut count = 0;
    for id in ids {
        let mut next =
            account.client.voice_calls.get(&id).cloned().ok_or_else(|| invalid("call vanished"))?;
        let now = now_unix_timestamp();
        next.expire(now)?;
        next.expire_media(now)?;
        maintain_lease(account, &mut next, now).await?;
        let old = &account.client.voice_calls[&id].row;
        if next.row != *old {
            account
                .client
                .account_db()?
                .write_transaction(|| account.client.persist_call_row(&next.row))?;
        }
        account.client.voice_calls.insert(id.clone(), next);
        release_lease(account, &id, now).await?;
        count += deliver_pending(account, &id, now).await?;
    }
    // Public rows are persisted; finished runtime keys and bearer credentials can be destroyed.
    account.client.voice_calls.retain(|_, c| {
        c.row.state != "ended"
            || !c.pending.is_empty()
            || c.release_until > now_unix_timestamp().unsigned_abs()
    });
    Ok(count)
}
async fn flush(account: &mut LocalBusAccountState, id: &str) -> Result<usize, SdkError> {
    let pending = account.client.voice_calls[id].pending.clone();
    if pending.is_empty() {
        return Ok(0);
    }
    let c = &account.client.voice_calls[id];
    let conversation = c.row.conversation_id.clone();
    let thread = account
        .client
        .account_db()?
        .client_record("conversation", &conversation)?
        .ok_or_else(|| invalid("call conversation absent"))?;
    let targets = crate::bus::dispatch::task_transport::direct_targets(
        account,
        &account.gateway_config,
        &thread,
    )
    .await?;
    let mut engine = account.take_live_engine().await?;
    let result = async {
        let mut deliveries = Vec::new();
        for mut control in pending {
            let target_device = if control.sender == control.caller {
                &control.callee.device_id
            } else {
                &control.caller.device_id
            };
            let target = targets
                .iter()
                .find(|t| &t.device == target_device)
                .ok_or_else(|| invalid("call target no longer active"))?;
            let local =
                account.client.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
            control.signature = ramflux_crypto::sign_canonical_bytes_with_device_branch(
                &call::signing_bytes(&control)?,
                local,
            );
            let bytes = call::bytes(&control)?;
            deliveries.push(
                crate::bus::dispatch::task_transport::seal(
                    account,
                    &mut engine,
                    target,
                    &conversation,
                    &bytes,
                    crate::client::routed::Route::control(),
                )
                .await?,
            );
        }
        Ok::<_, SdkError>(deliveries)
    }
    .await;
    account.put_engine(engine);
    let deliveries = result?;
    let n = crate::bus::task_delivery::submit_all(account, deliveries).await?;
    account.client.voice_calls.get_mut(id).ok_or_else(|| invalid("call vanished"))?.pending.clear();
    Ok(n)
}

pub(crate) fn expire_due(account: &mut LocalBusAccountState) -> Result<(), SdkError> {
    recover(account)?;
    let now = now_unix_timestamp();
    let mut changed = Vec::new();
    for (id, call) in &account.client.voice_calls {
        let mut next = call.clone();
        if next.expire(now)? || next.expire_media(now)? {
            changed.push((id.clone(), next));
        }
    }
    for (id, next) in changed {
        account
            .client
            .account_db()?
            .write_transaction(|| account.client.persist_call_row(&next.row))?;
        account.client.voice_calls.insert(id, next);
    }
    Ok(())
}

async fn maintain_lease(
    account: &mut LocalBusAccountState,
    next: &mut LiveCall,
    now: i64,
) -> Result<(), SdkError> {
    if next.next_lease_refresh > now {
        return Ok(());
    }
    if next.local == next.caller
        && matches!(next.row.state.as_str(), "connecting" | "active")
        && (next.row.state == "connecting" || next.next_lease_refresh <= now)
    {
        let thread = account
            .client
            .account_db()?
            .client_record("conversation", &next.row.conversation_id)?
            .ok_or_else(|| invalid("call conversation absent"))?;
        let targets = match crate::bus::dispatch::task_transport::direct_targets(
            account,
            &account.gateway_config,
            &thread,
        )
        .await
        {
            Ok(targets) => targets,
            Err(error @ (SdkError::Storage(_) | SdkError::Io(_))) => return Err(error),
            Err(error)
                if crate::error_policy::approval_retryable(&error)
                    && crate::error_policy::security_code(&error).is_none() =>
            {
                next.next_lease_refresh = now.saturating_add(5);
                return Ok(());
            }
            Err(_) => {
                next.fail(now)?;
                return Ok(());
            }
        };
        let record = account.client.trusted_device(&next.callee.device_id)?;
        if !targets.iter().any(|t| t.device == next.callee.device_id)
            || !record["signing_public_key"]
                .as_str()
                .is_some_and(|key| next.peer_key_matches(&next.callee, key))
        {
            next.fail(now)?;
            return Ok(());
        }
    }
    if next.local == next.caller && next.row.state == "connecting" && next.receive_key.is_some() {
        let mut engine = account.take_live_engine().await?;
        let result = engine.voice_lease(VoiceLeaseRequest::Allocate { scope: scope(next) }).await;
        account.put_engine(engine);
        match result {
            Ok(VoiceLeaseResponse::Allocation { allocation }) => {
                next.activate(allocation, now)?;
            }
            Ok(_) | Err(_) => next.fail(now)?,
        }
    } else if next.local == next.caller
        && next.row.state == "active"
        && next.next_lease_refresh <= now
    {
        let mut engine = account.take_live_engine().await?;
        let result = engine.voice_lease(VoiceLeaseRequest::Renew { scope: scope(next) }).await;
        account.put_engine(engine);
        if let Ok(VoiceLeaseResponse::Status { status }) = result {
            if let Some(allocation) = next.allocation.as_mut() {
                allocation.expires_at = status.expires_at;
            }
            let allocation =
                next.allocation.clone().ok_or_else(|| invalid("renewed lease missing"))?;
            let ack = next.control(
                ramflux_protocol::CallAction::Ack { allocation: Box::new(allocation.for_callee()) },
                now,
            )?;
            next.pending.push(ack);
            next.next_lease_refresh = now.saturating_add(20);
        } else {
            // Existing authorization remains bounded by its lease; retry without extending it.
            next.next_lease_refresh = now.saturating_add(5);
        }
    }
    Ok(())
}
async fn release_lease(
    account: &mut LocalBusAccountState,
    id: &str,
    now: i64,
) -> Result<(), SdkError> {
    if account.client.voice_calls[id].release_until > now.unsigned_abs()
        && account.client.voice_calls[id].next_lease_refresh <= now
    {
        let mut engine = account.take_live_engine().await?;
        let result = engine
            .voice_lease(VoiceLeaseRequest::Release {
                scope: scope(&account.client.voice_calls[id]),
            })
            .await;
        account.put_engine(engine);
        let call =
            account.client.voice_calls.get_mut(id).ok_or_else(|| invalid("call vanished"))?;
        if result.is_ok() {
            call.release_until = 0;
        } else {
            call.next_lease_refresh = now.saturating_add(5);
        }
    }
    Ok(())
}
async fn deliver_pending(
    account: &mut LocalBusAccountState,
    id: &str,
    now: i64,
) -> Result<usize, SdkError> {
    let mut count = 0;
    if account.client.voice_calls[id].retry_at <= now {
        if let Ok(n) = flush(account, id).await {
            count += n;
            let call =
                account.client.voice_calls.get_mut(id).ok_or_else(|| invalid("call vanished"))?;
            call.retry_attempts = 0;
            call.retry_at = 0;
        } else {
            let call =
                account.client.voice_calls.get_mut(id).ok_or_else(|| invalid("call vanished"))?;
            call.retry_attempts = call.retry_attempts.saturating_add(1);
            call.retry_at =
                now.saturating_add(1_i64 << call.retry_attempts.saturating_sub(1).min(4));
            if call.row.state == "ended"
                && now.saturating_sub(call.row.ended_at.unwrap_or(now)) >= 60
            {
                call.pending.clear();
            }
            tracing::warn!("call control delivery deferred");
        }
    }
    Ok(count)
}
