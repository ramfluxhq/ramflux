// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Bounded account-owned signaling retries, ring timers and authenticated relay lease maintenance.
use super::{invalid, recover};
use crate::client::call::{self, state::LiveCall};
use crate::client::identity_authority::NativeOperation;
use crate::prelude::*;
use ramflux_protocol::{VoiceAllocationRequest, VoiceLeaseRequest};
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
        count += drive_controls(account, &id, now).await?;
    }
    // Public rows are persisted; finished runtime keys and bearer credentials can be destroyed.
    account.client.voice_calls.retain(|_, c| {
        c.row.state != "ended"
            || !c.pending.is_empty()
            || c.release_until > now_unix_timestamp().unsigned_abs()
    });
    Ok(count)
}

trait ControlDriver {
    async fn deliver(&mut self, id: &str, now: i64) -> Result<usize, SdkError>;
    async fn release(&mut self, id: &str, now: i64) -> Result<(), SdkError>;
}
impl ControlDriver for LocalBusAccountState {
    async fn deliver(&mut self, id: &str, now: i64) -> Result<usize, SdkError> {
        deliver_pending(self, id, now).await
    }
    async fn release(&mut self, id: &str, now: i64) -> Result<(), SdkError> {
        release_lease(self, id, now).await
    }
}
async fn drive_controls(
    driver: &mut impl ControlDriver,
    id: &str,
    now: i64,
) -> Result<usize, SdkError> {
    // Even an offline peer must get a completed delivery attempt before lease release.
    let delivered = driver.deliver(id, now).await;
    driver.release(id, now).await?;
    delivered
}

#[cfg(all(feature = "itest-local-mint", ramflux_itest, not(ramflux_production)))]
#[path = "call_refresh_barrier.rs"]
mod refresh_barrier;

#[cfg(test)]
#[path = "call_driver_tests.rs"]
mod tests;
async fn flush(account: &mut LocalBusAccountState, id: &str) -> Result<usize, SdkError> {
    account.client.require_native_operation(
        &account.client.owned_device_identity()?,
        NativeOperation::Call,
    )?;
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

#[path = "call_lease.rs"]
mod leases;
use leases::maintain_lease;
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
