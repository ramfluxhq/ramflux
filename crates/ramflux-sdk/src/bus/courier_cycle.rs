// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Actor-owned cycle accounting and priority service before task submissions.

use crate::prelude::*;

pub(super) const LIMIT: Duration = Duration::from_secs(20);
// Reserve five seconds for actor-side authority/sealing, one for submit, and one
// for local bookkeeping. Courier-worker manifest preparation is outside this budget.
const TASK_MINIMUM: Duration = Duration::from_secs(7);

// Admission floor for the post-receive pass, independent of the call submit budget.
pub(super) const PRIORITY_ALLOWANCE: Duration = Duration::from_secs(8);
const RECEIPT_ALLOWANCE: Duration = Duration::from_secs(4);
pub(super) const RECEIVE_RESERVE: Duration = Duration::from_secs(4);
pub(super) const CALL_ALLOWANCE: Duration = super::task_delivery::SUBMIT_ALLOWANCE;

pub(super) trait Couriers {
    async fn priority(&mut self);
    async fn submit(&mut self) -> Result<bool, SdkError>;
}

#[derive(Default)]
pub(super) struct Cycle {
    spent: Duration,
    priority_served: bool,
}

impl Cycle {
    #[cfg(test)]
    pub(super) fn exhausted() -> Self {
        Self { spent: LIMIT, priority_served: false }
    }

    pub(super) async fn apply(&mut self, couriers: &mut impl Couriers) -> Result<bool, SdkError> {
        if !self.priority_served {
            let started = tokio::time::Instant::now();
            couriers.priority().await;
            self.spent = self.spent.saturating_add(started.elapsed());
            self.priority_served = true;
        }
        if LIMIT.saturating_sub(self.spent) < TASK_MINIMUM {
            return Ok(false);
        }
        let started = tokio::time::Instant::now();
        let result = couriers.submit().await;
        // Charge the entire actor application, including every awaited submit and failures.
        self.spent = self.spent.saturating_add(started.elapsed());
        result
    }
}

pub(super) async fn priority(account: &mut LocalBusAccountState) -> usize {
    priority_until(account, tokio::time::Instant::now() + LIMIT, Duration::ZERO).await
}

pub(super) async fn priority_until(
    account: &mut LocalBusAccountState,
    deadline: tokio::time::Instant,
    reserve: Duration,
) -> usize {
    if !super::task_courier_queue::networking_ready(account) {
        // Admission can block networking without blocking local call timers.
        if let Err(error) = super::dispatch::call::expire_due(account) {
            tracing::warn!(%error, "local call expiry deferred");
        }
        return 0;
    }
    let receipts = priority_step(account, "receipt", Priority::Receipt, deadline).await;
    receipts + priority_step(account, "call", Priority::Call { reserve }, deadline - reserve).await
}

trait PriorityOperation {
    fn allowance(&self) -> Duration {
        Duration::from_secs(4)
    }
    async fn run(
        &self,
        account: &mut LocalBusAccountState,
        deadline: tokio::time::Instant,
    ) -> Result<usize, SdkError>;
}

enum Priority {
    Receipt,
    Call { reserve: Duration },
}
impl PriorityOperation for Priority {
    fn allowance(&self) -> Duration {
        match self {
            Self::Receipt => RECEIPT_ALLOWANCE,
            Self::Call { .. } => LIMIT,
        }
    }
    async fn run(
        &self,
        account: &mut LocalBusAccountState,
        deadline: tokio::time::Instant,
    ) -> Result<usize, SdkError> {
        match self {
            Self::Receipt => super::delivery_receipts::flush(account).await,
            Self::Call { reserve } => {
                super::dispatch::call::drive_until(account, deadline + *reserve, *reserve).await
            }
        }
    }
}

async fn priority_step(
    account: &mut LocalBusAccountState,
    courier: &'static str,
    operation: impl PriorityOperation,
    deadline: tokio::time::Instant,
) -> usize {
    let now = tokio::time::Instant::now();
    if deadline <= now {
        return 0;
    }
    let resume = super::gateway_resume::Snapshot::capture(account);
    let deadline = deadline.min(now + operation.allowance());
    let result = tokio::time::timeout_at(deadline, operation.run(account, deadline)).await;
    match result {
        Ok(Ok(n)) => n,
        Ok(Err(error)) => {
            tracing::warn!(%error, courier, "priority courier deferred");
            0
        }
        Err(_) => {
            let saved = resume.retire(account);
            if let Err(error) = saved {
                tracing::warn!(%error, courier, "priority timeout resume checkpoint failed");
            }
            tracing::warn!(courier, "priority courier deadline exceeded; pending work retained");
            0
        }
    }
}

pub(super) struct Task<'a> {
    pub account: &'a mut LocalBusAccountState,
    pub item: Option<(super::task_courier::Item, super::task_courier::Preparation)>,
}

impl Couriers for Task<'_> {
    async fn priority(&mut self) {
        priority(self.account).await;
    }
    async fn submit(&mut self) -> Result<bool, SdkError> {
        match self.item.take() {
            Some((item, preparation)) => {
                super::task_courier_apply::apply(self.account, item, preparation).await
            }
            None => Ok(false),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct SlowCouriers {
        submitted: usize,
        receipts: usize,
        calls: usize,
        fail: bool,
    }
    impl Couriers for SlowCouriers {
        async fn priority(&mut self) {
            self.receipts += 1;
            self.calls += 1;
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        async fn submit(&mut self) -> Result<bool, SdkError> {
            self.submitted += 1;
            tokio::time::sleep(Duration::from_secs(14)).await;
            if self.fail {
                Err(SdkError::InboundPending("fixture failure".into()))
            } else {
                Ok(true)
            }
        }
    }

    #[tokio::test(start_paused = true)]
    async fn slow_submissions_are_charged_and_cannot_starve_receipts_or_calls_for_two_cycles()
    -> Result<(), SdkError> {
        let mut couriers = SlowCouriers { submitted: 0, receipts: 0, calls: 0, fail: false };
        for expected in 1..=2 {
            let started = tokio::time::Instant::now();
            let mut cycle = Cycle::default();
            assert!(cycle.apply(&mut couriers).await?);
            assert!(
                !cycle.apply(&mut couriers).await?,
                "lower-priority submit started below its minimum"
            );
            assert_eq!(couriers.submitted, expected);
            assert_eq!(couriers.receipts, expected);
            assert_eq!(couriers.calls, expected);
            assert!(started.elapsed() <= LIMIT);
        }
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn failed_submissions_consume_the_same_cycle_budget() -> Result<(), SdkError> {
        let mut couriers = SlowCouriers { submitted: 0, receipts: 0, calls: 0, fail: true };
        let mut cycle = Cycle::default();
        assert!(matches!(cycle.apply(&mut couriers).await, Err(SdkError::InboundPending(_))));
        assert!(!cycle.apply(&mut couriers).await?);
        assert_eq!(couriers.submitted, 1);
        Ok(())
    }
    struct StalledPriority {
        takes_engine: bool,
        rotate_scope: bool,
    }
    impl PriorityOperation for StalledPriority {
        async fn run(
            &self,
            account: &mut LocalBusAccountState,
            _deadline: tokio::time::Instant,
        ) -> Result<usize, SdkError> {
            let engine = if self.takes_engine { account.engine.take() } else { None };
            if self.rotate_scope {
                account.gateway_config.device_epoch += 1;
                account.gateway_config.previous_session_id = Some("current-session".into());
                account.gateway_config.resume_token = Some("current-token".into());
                account.gateway_config.last_seen_inbox_seq = 73;
            }
            let result = std::future::pending().await;
            drop(engine);
            result
        }
    }

    #[tokio::test(start_paused = true)]
    async fn priority_timeout_retires_both_pooled_and_borrowed_engines_with_resume_evidence()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::sync::{Arc, atomic::AtomicBool};
        for (takes_engine, rotate_scope) in
            [(false, false), (true, false), (false, true), (true, true)]
        {
            let root = crate::bus::runtime_tests::root("priority-resume-timeout");
            let mut account = crate::bus::runtime_tests::account(
                &root,
                "sender",
                None,
                Arc::new(AtomicBool::new(false)),
            )?;
            let before_epoch = account.gateway_config.device_epoch;
            let engine = account.engine.as_mut().ok_or("engine")?;
            engine.config.previous_session_id = Some("retained-session".into());
            engine.config.resume_token = Some("retained-token".into());
            engine.config.last_seen_inbox_seq = 41;
            let started = tokio::time::Instant::now();
            assert_eq!(
                priority_step(
                    &mut account,
                    "fixture",
                    StalledPriority { takes_engine, rotate_scope },
                    started + LIMIT,
                )
                .await,
                0
            );
            assert_eq!(started.elapsed(), Duration::from_secs(4));
            assert!(account.engine.is_none());
            let saved = account
                .client
                .projection_checkpoint(LocalBusAccountState::GATEWAY_RESUME_CHECKPOINT)?
                .ok_or("checkpoint")?;
            let saved: serde_json::Value = serde_json::from_str(&saved)?;
            if rotate_scope {
                assert_eq!(account.gateway_config.device_epoch, before_epoch + 1);
                assert_eq!(saved["previous_session_id"], "current-session");
                assert_eq!(saved["resume_token"], "current-token");
                assert_eq!(saved["last_seen_inbox_seq"], 73);
                assert_eq!(
                    account.gateway_config.previous_session_id.as_deref(),
                    Some("current-session")
                );
            } else {
                assert_eq!(saved["previous_session_id"], "retained-session");
                assert_eq!(saved["resume_token"], "retained-token");
                assert_eq!(saved["last_seen_inbox_seq"], 41);
            }
        }
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn priority_step_cannot_extend_the_remaining_sync_window()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::sync::{Arc, atomic::AtomicBool};
        let root = crate::bus::runtime_tests::root("priority-remaining-time");
        let mut account = crate::bus::runtime_tests::account(
            &root,
            "sender",
            None,
            Arc::new(AtomicBool::new(false)),
        )?;
        let started = tokio::time::Instant::now();
        assert_eq!(
            priority_step(
                &mut account,
                "fixture",
                StalledPriority { takes_engine: false, rotate_scope: false },
                started + Duration::from_secs(2),
            )
            .await,
            0
        );
        assert_eq!(started.elapsed(), Duration::from_secs(2));
        assert!(account.engine.is_none());
        Ok(())
    }
}
