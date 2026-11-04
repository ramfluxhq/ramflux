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
#[path = "call_item_deadline.rs"]
mod item_deadline;
use crate::bus::task_delivery::SubmitError;
use tokio::time::Instant;
const NESTED_SLACK: Duration = Duration::from_secs(1);

enum ItemOutcome {
    Completed(usize),
    Deferred,
    ItemTimeout,
}
#[cfg(test)]
impl ItemOutcome {
    fn name(&self) -> &'static str {
        match self {
            Self::Completed(_) => "Completed",
            Self::Deferred => "Deferred",
            Self::ItemTimeout => "ItemTimeout",
        }
    }
}

pub(crate) async fn drive(account: &mut LocalBusAccountState) -> Result<usize, SdkError> {
    drive_until(account, Instant::now() + crate::bus::courier_cycle::LIMIT, Duration::ZERO).await
}

/// Runs local call timers before admitting complete network items.
///
/// # Errors
/// Returns unrecoverable account, storage or lease preparation errors.
pub(crate) async fn drive_until(
    account: &mut LocalBusAccountState,
    deadline: Instant,
    reserve: Duration,
) -> Result<usize, SdkError> {
    // Local expiry and persistence cover every call, including calls deferred below.
    expire_due(account)?;
    let ids = account.client.voice_calls.keys().cloned().collect::<Vec<_>>();
    let mut count = 0;
    let mut deferred = false;
    for id in ids {
        let now = Instant::now();
        let call = &account.client.voice_calls[&id];
        let outcome = if deferred
            || call.network_backoff_until.is_some_and(|until| now < until)
            || deadline.saturating_duration_since(now).saturating_sub(reserve)
                < crate::bus::courier_cycle::CALL_ALLOWANCE
        {
            ItemOutcome::Deferred
        } else {
            let item_deadline =
                (now + crate::bus::courier_cycle::CALL_ALLOWANCE).min(deadline - reserve);
            run_item(account, &id, item_deadline).await?
        };
        #[cfg(test)]
        account.call_outcomes.push((id.clone(), outcome.name()));
        match outcome {
            ItemOutcome::Completed(sent) => count += sent,
            ItemOutcome::Deferred => {
                deferred = true;
                tracing::debug!(call_id = %id, outcome = "Deferred", "call network work deferred");
            }
            ItemOutcome::ItemTimeout => deferred = true,
        }
    }
    account.client.voice_calls.retain(|_, c| {
        c.row.state != "ended"
            || !c.pending.is_empty()
            || c.release_until > now_unix_timestamp().unsigned_abs()
    });
    Ok(count)
}

async fn run_item(
    account: &mut LocalBusAccountState,
    id: &str,
    deadline: Instant,
) -> Result<ItemOutcome, SdkError> {
    let mut resume = Some(crate::bus::gateway_resume::Snapshot::capture(account));
    #[cfg(test)]
    let polls = account.call_probe.polls.clone();
    let inner = network_item(account, id, deadline);
    #[cfg(test)]
    let inner = {
        let mut inner = Box::pin(inner);
        std::future::poll_fn(move |cx| {
            polls.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            inner.as_mut().poll(cx)
        })
    };
    let result = item_deadline::ItemDeadline::new(inner, deadline).await;
    match result {
        Ok(Ok(n)) => {
            let call =
                account.client.voice_calls.get_mut(id).ok_or_else(|| invalid("call vanished"))?;
            call.network_backoff_until = None;
            call.network_timeouts = 0;
            Ok(ItemOutcome::Completed(n))
        }
        Ok(Err(SubmitError::Failure(error))) => Err(error),
        // Typed nested expiry is defensive: it never takes the ordinary flush retry path.
        Err(()) | Ok(Err(SubmitError::DeadlineExceeded)) => {
            let saved = resume.take().map(|snapshot| snapshot.retire(account));
            let call =
                account.client.voice_calls.get_mut(id).ok_or_else(|| invalid("call vanished"))?;
            call.network_timeouts = call.network_timeouts.saturating_add(1);
            call.network_backoff_until = Some(
                Instant::now()
                    + Duration::from_secs(1_u64 << call.network_timeouts.saturating_sub(1).min(4)),
            );
            let checkpoint_error = saved.and_then(Result::err).map(|error| error.to_string());
            tracing::warn!(call_id = %id, outcome = "ItemTimeout", ?checkpoint_error,
                "call item deadline exceeded; pending work retained");
            Ok(ItemOutcome::ItemTimeout)
        }
    }
}

async fn network_item(
    account: &mut LocalBusAccountState,
    id: &str,
    deadline: Instant,
) -> Result<usize, SubmitError> {
    let mut next = account.client.voice_calls[id].clone();
    let now = now_unix_timestamp();
    maintain_lease(account, &mut next, now).await?;
    if next.row != account.client.voice_calls[id].row {
        account
            .client
            .account_db()?
            .write_transaction(|| account.client.persist_call_row(&next.row))?;
    }
    account.client.voice_calls.insert(id.into(), next);
    let mut driver = ItemControls { account, deadline: deadline + NESTED_SLACK };
    drive_controls(&mut driver, id, now).await
}

trait ControlDriver {
    async fn deliver(&mut self, id: &str, now: i64) -> Result<usize, SubmitError>;
    async fn release(&mut self, id: &str, now: i64) -> Result<(), SdkError>;
}
struct ItemControls<'a> {
    account: &'a mut LocalBusAccountState,
    deadline: Instant,
}
impl ControlDriver for ItemControls<'_> {
    async fn deliver(&mut self, id: &str, now: i64) -> Result<usize, SubmitError> {
        deliver_pending(self.account, id, now, self.deadline).await
    }
    async fn release(&mut self, id: &str, now: i64) -> Result<(), SdkError> {
        release_lease(self.account, id, now).await
    }
}

async fn drive_controls(
    driver: &mut impl ControlDriver,
    id: &str,
    now: i64,
) -> Result<usize, SubmitError> {
    // Even an offline peer must get a completed delivery attempt before lease release.
    let delivered = driver.deliver(id, now).await;
    if matches!(delivered, Err(SubmitError::DeadlineExceeded)) {
        return delivered;
    }
    driver.release(id, now).await?;
    delivered
}

#[cfg(all(feature = "itest-local-mint", ramflux_itest, not(ramflux_production)))]
#[path = "call_refresh_barrier.rs"]
mod refresh_barrier;

#[cfg(test)]
#[path = "call_driver_tests.rs"]
mod tests;
async fn flush(
    account: &mut LocalBusAccountState,
    id: &str,
    deadline: Instant,
) -> Result<usize, SubmitError> {
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
        .client_record("conversation", &conversation)
        .map_err(SdkError::from)?
        .ok_or_else(|| invalid("call conversation absent"))?;
    #[cfg(test)]
    account.call_test_phase("lookup").await;
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
            #[cfg(test)]
            account.call_test_phase("seal").await;
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
    let n = crate::bus::task_delivery::submit_until_typed(account, deliveries, deadline).await?;
    account.client.voice_calls.get_mut(id).ok_or_else(|| invalid("call vanished"))?.pending.clear();
    Ok(n)
}

pub(crate) fn expire_due(account: &mut LocalBusAccountState) -> Result<(), SdkError> {
    recover(account)?;
    let now = now_unix_timestamp();
    let mut changed = Vec::new();
    for (id, call) in &account.client.voice_calls {
        let mut next = call.clone();
        let expired = next.expire(now)?;
        let media_expired = next.expire_media(now)?;
        if expired || media_expired {
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
pub(crate) async fn deliver_pending(
    account: &mut LocalBusAccountState,
    id: &str,
    now: i64,
    deadline: Instant,
) -> Result<usize, SubmitError> {
    let mut count = 0;
    if account.client.voice_calls[id].retry_at <= now {
        let result = flush(account, id, deadline).await;
        if matches!(result, Err(SubmitError::DeadlineExceeded)) {
            return result;
        }
        if let Ok(n) = result {
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
