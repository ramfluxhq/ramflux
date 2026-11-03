// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Bounded Busy retries and an account-local lease shared by independent processes.
use crate::SdkError;
use ramflux_protocol::custody::{CapacityHint, CustodyRefusal, RetryHint};
use std::{fs::File, future::Future, path::Path, time::Duration};
use tokio::time::Instant;

const RETRY_BUDGET: Duration = Duration::from_secs(90);
const MAX_BACKOFF: Duration = Duration::from_secs(16);

pub(super) fn busy() -> SdkError {
    CustodyRefusal::Busy.into()
}
pub(super) fn is_busy(error: &SdkError) -> bool {
    error.custody_refusal() == Some(CustodyRefusal::Busy)
}
fn timeout() -> SdkError {
    SdkError::NodeTimeout { retry_after_ms: crate::node::NODE_RETRY_AFTER_MS }
}
pub(crate) struct Budget {
    deadline: Instant,
    backoff: Duration,
    busy_observed: bool,
    last_busy_hint: Option<RetryHint>,
}
impl Budget {
    pub(crate) fn new() -> Self {
        Self {
            deadline: Instant::now() + RETRY_BUDGET,
            backoff: Duration::from_secs(1),
            busy_observed: false,
            last_busy_hint: None,
        }
    }
    pub(crate) async fn attempt<T>(
        &mut self,
        operation: impl Future<Output = Result<T, SdkError>>,
    ) -> Result<T, SdkError> {
        if Instant::now() >= self.deadline {
            return Err(if self.busy_observed { self.busy_error() } else { timeout() });
        }
        let result = match tokio::time::timeout_at(self.deadline, operation).await {
            Ok(result) => result,
            Err(_) if self.busy_observed => return Err(self.busy_error()),
            Err(_) => return Err(timeout()),
        };
        self.busy_observed = result.as_ref().is_err_and(is_busy);
        self.last_busy_hint =
            result.as_ref().err().filter(|error| is_busy(error)).and_then(SdkError::retry_hint);
        result
    }
    fn busy_error(&self) -> SdkError {
        self.last_busy_hint.map_or_else(busy, |retry| SdkError::CustodyAdmission {
            code: CustodyRefusal::Busy,
            retry,
        })
    }
    pub(crate) async fn pause(&mut self) -> Result<(), SdkError> {
        let mut bytes = [0; 8];
        getrandom::fill(&mut bytes).map_err(|_| SdkError::CustodyRandomUnavailable)?;
        let delay = self.last_busy_hint.map_or_else(
            || jitter(self.backoff, u64::from_ne_bytes(bytes)),
            |hint| hint_delay(hint, u64::from_ne_bytes(bytes)),
        );
        self.backoff = (self.backoff * 2).min(MAX_BACKOFF);
        if Instant::now() + delay >= self.deadline {
            if self.last_busy_hint.is_none() {
                tokio::time::sleep_until(self.deadline).await;
            }
            return Err(self.busy_error());
        }
        tokio::time::sleep(delay).await;
        Ok(())
    }
    pub(super) async fn until_ready<T, F, Fut>(&mut self, mut operation: F) -> Result<T, SdkError>
    where
        F: FnMut() -> Fut,
        Fut: Future<Output = Result<T, SdkError>>,
    {
        loop {
            match self.attempt(operation()).await {
                Err(error) if is_busy(&error) => self.pause().await?,
                result => return result,
            }
        }
    }
}
fn hint_delay(hint: RetryHint, random: u64) -> Duration {
    let millis = u64::from(hint.clamped().retry_after_ms);
    Duration::from_millis(millis + random % (millis / 10 + 1))
}

/// Last retry category shared with the account's connection manager.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RetryReason {
    Busy { hint: Option<RetryHint> },
    Capacity { hint: Option<RetryHint>, capacity: Option<CapacityHint> },
    Timeout,
}
/// Account-owned monotonic retry state; constructing a new attempt never erases its deadline.
#[derive(Default)]
pub(crate) struct AdmissionRetry {
    not_before: Option<Instant>,
    reason: Option<RetryReason>,
}
impl AdmissionRetry {
    pub(crate) fn record(&mut self, error: &SdkError, now: Instant) {
        let hint = error.retry_hint();
        let capacity = error.capacity_hint();
        let mut bytes = [0; 8];
        // Jitter is advisory. If entropy is unavailable, zero extra delay still preserves
        // the complete server minimum; authentication entropy failures remain fatal elsewhere.
        if getrandom::fill(&mut bytes).is_err() {
            bytes = [0; 8];
        }
        let random = u64::from_ne_bytes(bytes);
        let (reason, delay) = match error.custody_refusal() {
            Some(CustodyRefusal::Busy) => (
                RetryReason::Busy { hint },
                hint.map_or_else(|| jitter(MAX_BACKOFF, random), |hint| hint_delay(hint, random)),
            ),
            Some(CustodyRefusal::Capacity) => {
                let delay = if let Some(capacity) = capacity {
                    Duration::from_millis(super::capacity_hint::retry_after_ms(
                        capacity,
                        super::capacity_hint::unix_now(),
                    ))
                } else {
                    hint.map_or(
                        Duration::from_millis(super::capacity_backoff::RETRY_AFTER_MS),
                        |hint| hint_delay(hint, random),
                    )
                };
                (RetryReason::Capacity { hint, capacity }, delay)
            }
            _ if matches!(
                error,
                SdkError::NodeTimeout { .. } | SdkError::NodeUnreachable { .. }
            ) =>
            {
                (RetryReason::Timeout, Duration::from_millis(crate::node::NODE_RETRY_AFTER_MS))
            }
            _ => return,
        };
        let next = now + delay;
        if self.not_before.is_none_or(|old| next >= old) {
            self.not_before = Some(next);
            self.reason = Some(reason);
        }
    }
    pub(crate) fn not_before(&self) -> Option<Instant> {
        self.not_before
    }
    pub(crate) async fn begin_attempt(&mut self) -> Budget {
        if let (Some(deadline), Some(_)) = (self.not_before(), self.reason) {
            tokio::time::sleep_until(deadline).await;
        }
        Budget::new()
    }
}

fn jitter(backoff: Duration, random: u64) -> Duration {
    // Nominal 1, 2, 4, 8, 16 seconds; the upper quarter is jittered, with a
    // one-second floor and a sixteen-second ceiling, including at saturation.
    let upper = u64::try_from(backoff.as_millis()).unwrap_or(16_000).min(16_000);
    let lower = (upper * 3 / 4).max(1_000);
    Duration::from_millis(lower + random % (upper - lower + 1))
}
pub(crate) struct AccountLease(File);
impl Drop for AccountLease {
    fn drop(&mut self) {
        let _ = fs2::FileExt::unlock(&self.0);
    }
}
pub(crate) async fn single_flight(
    root: &Path,
    id: &str,
    budget: &mut Budget,
) -> Result<AccountLease, SdkError> {
    super::valid_id(id)?;
    let path = root.join("custody_accounts").join(id).join(".network.lock");
    let file = budget
        .attempt(async move {
            tokio::task::spawn_blocking(move || {
                let mut options = std::fs::OpenOptions::new();
                options.read(true).write(true).create(true).truncate(false);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::OpenOptionsExt;
                    options.mode(0o600).custom_flags(
                        i32::try_from(rustix::fs::OFlags::NOFOLLOW.bits())
                            .map_err(std::io::Error::other)?,
                    );
                }
                options.open(path)
            })
            .await
            .map_err(|_| SdkError::CustodySetupInvalid)?
            .map_err(SdkError::from)
        })
        .await?;
    budget
        .until_ready(|| async {
            match fs2::FileExt::try_lock_exclusive(&file) {
                Ok(()) => Ok(()),
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => Err(busy()),
                Err(error) => Err(error.into()),
            }
        })
        .await?;
    Ok(AccountLease(file))
}

#[cfg(test)]
#[path = "retry_tests.rs"]
mod tests;
