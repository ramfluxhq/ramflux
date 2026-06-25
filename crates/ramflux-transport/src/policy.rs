use ramflux_core::{BackpressureBudget, CancellationToken, CoreError, RetryPolicy};
use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;
use tokio::sync::Notify;

use crate::TransportError;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransportRetryPolicy {
    core: RetryPolicy,
    jitter_per_mille: u16,
}

impl TransportRetryPolicy {
    #[must_use]
    pub const fn new(core: RetryPolicy, jitter_per_mille: u16) -> Self {
        Self { core, jitter_per_mille }
    }

    #[must_use]
    pub const fn core(self) -> RetryPolicy {
        self.core
    }

    #[must_use]
    pub fn delay_for_attempt(self, attempt: u32) -> Option<Duration> {
        let base = self.core.delay_for_attempt(attempt)?;
        let jitter = deterministic_jitter(base, attempt, self.jitter_per_mille);
        Some(base.saturating_add(jitter).min(self.core.max_delay))
    }
}

/// # Errors
/// Returns the last retryable transport error as `RetryExhausted`, maps
/// cancellation to `ShutdownDraining`, or returns the operation's successful
/// value before the retry budget is exhausted.
pub async fn retry_with_policy<T, F, Fut>(
    policy: TransportRetryPolicy,
    cancellation: &CancellationToken,
    mut operation: F,
) -> Result<T, TransportError>
where
    F: FnMut(u32) -> Fut,
    Fut: Future<Output = Result<T, TransportError>>,
{
    let mut attempt = 0;
    loop {
        cancellation.check().map_err(|error| map_core_error(&error))?;
        match operation(attempt).await {
            Ok(value) => return Ok(value),
            Err(error) if attempt + 1 >= policy.core().max_attempts => {
                tracing::debug!(attempts = attempt + 1, %error, "transport retry exhausted");
                return Err(TransportError::RetryExhausted { attempts: attempt + 1 });
            }
            Err(error) => {
                tracing::debug!(attempt, %error, "transport retryable operation failed");
                let delay = policy
                    .delay_for_attempt(attempt)
                    .ok_or(TransportError::RetryExhausted { attempts: attempt + 1 })?;
                tokio::time::sleep(delay).await;
                attempt = attempt.saturating_add(1);
            }
        }
    }
}

#[derive(Clone, Debug)]
pub struct TransportBackpressure {
    budget: BackpressureBudget,
}

impl TransportBackpressure {
    #[must_use]
    pub fn new(capacity: u64) -> Self {
        Self { budget: BackpressureBudget::new(capacity) }
    }

    /// # Errors
    /// Returns `BackpressureRejected` when the configured in-flight capacity is exhausted.
    pub fn try_acquire(&self) -> Result<TransportBackpressurePermit, TransportError> {
        self.budget
            .try_acquire()
            .map(|permit| TransportBackpressurePermit { _permit: permit })
            .map_err(|error| map_core_error(&error))
    }

    #[must_use]
    pub fn in_flight(&self) -> u64 {
        self.budget.in_flight()
    }

    #[must_use]
    pub fn capacity(&self) -> u64 {
        self.budget.capacity()
    }
}

#[derive(Debug)]
pub struct TransportBackpressurePermit {
    _permit: ramflux_core::BackpressurePermit,
}

#[derive(Clone, Debug, Default)]
pub struct ShutdownDrain {
    accepting: Arc<AtomicBool>,
    in_flight: Arc<AtomicU64>,
    notify: Arc<Notify>,
}

impl ShutdownDrain {
    #[must_use]
    pub fn new() -> Self {
        Self {
            accepting: Arc::new(AtomicBool::new(true)),
            in_flight: Arc::new(AtomicU64::new(0)),
            notify: Arc::new(Notify::new()),
        }
    }

    pub fn begin_shutdown(&self) {
        self.accepting.store(false, Ordering::Release);
        if self.in_flight() == 0 {
            self.notify.notify_waiters();
        }
    }

    #[must_use]
    pub fn is_accepting(&self) -> bool {
        self.accepting.load(Ordering::Acquire)
    }

    /// # Errors
    /// Returns `ShutdownDraining` after shutdown has started.
    pub fn try_start_operation(&self) -> Result<ShutdownDrainPermit, TransportError> {
        if !self.is_accepting() {
            return Err(TransportError::ShutdownDraining);
        }
        self.in_flight.fetch_add(1, Ordering::AcqRel);
        if !self.is_accepting() {
            self.finish_operation();
            return Err(TransportError::ShutdownDraining);
        }
        Ok(ShutdownDrainPermit { drain: self.clone() })
    }

    /// # Errors
    /// Returns `ShutdownTimeout` if in-flight work does not drain before `deadline`.
    pub async fn drain(&self, deadline: Duration) -> Result<(), TransportError> {
        let wait = async {
            while self.in_flight() != 0 {
                self.notify.notified().await;
            }
        };
        tokio::time::timeout(deadline, wait)
            .await
            .map_err(|_elapsed| TransportError::ShutdownTimeout { in_flight: self.in_flight() })
    }

    #[must_use]
    pub fn in_flight(&self) -> u64 {
        self.in_flight.load(Ordering::Acquire)
    }

    fn finish_operation(&self) {
        let previous = self.in_flight.fetch_sub(1, Ordering::AcqRel);
        if previous <= 1 {
            self.notify.notify_waiters();
        }
    }
}

#[derive(Debug)]
pub struct ShutdownDrainPermit {
    drain: ShutdownDrain,
}

impl Drop for ShutdownDrainPermit {
    fn drop(&mut self) {
        self.drain.finish_operation();
    }
}

fn deterministic_jitter(base: Duration, attempt: u32, jitter_per_mille: u16) -> Duration {
    if jitter_per_mille == 0 {
        return Duration::ZERO;
    }
    let spread = base.as_millis().saturating_mul(u128::from(jitter_per_mille)).saturating_div(1000);
    if spread == 0 {
        return Duration::ZERO;
    }
    let bucket = u128::from(attempt.wrapping_mul(1_103_515_245).wrapping_add(12_345) % 1000);
    let jitter_millis = spread.saturating_mul(bucket).saturating_div(1000);
    Duration::from_millis(u64::try_from(jitter_millis).unwrap_or(u64::MAX))
}

fn map_core_error(error: &CoreError) -> TransportError {
    match error {
        CoreError::BackpressureExhausted { capacity, in_flight } => {
            TransportError::BackpressureRejected { capacity: *capacity, in_flight: *in_flight }
        }
        CoreError::Cancelled => TransportError::ShutdownDraining,
        CoreError::RetryExhausted { attempts } => {
            TransportError::RetryExhausted { attempts: *attempts }
        }
        CoreError::InvalidId { .. }
        | CoreError::ClockBeforeUnixEpoch
        | CoreError::FeatureDisabled(_) => TransportError::Http(error.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use ramflux_core::{CancellationToken, RetryPolicy};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::time::Duration;

    use super::{ShutdownDrain, TransportBackpressure, TransportRetryPolicy, retry_with_policy};
    use crate::TransportError;

    #[test]
    fn retry_policy_retries_with_backoff_and_jitter() -> Result<(), Box<dyn std::error::Error>> {
        let runtime = tokio::runtime::Builder::new_current_thread().enable_time().build()?;
        runtime.block_on(async {
            let attempts = Arc::new(AtomicU32::new(0));
            let policy = TransportRetryPolicy::new(
                RetryPolicy::new(3, Duration::from_millis(1), Duration::from_millis(5)),
                250,
            );
            let delay = policy
                .delay_for_attempt(1)
                .ok_or(TransportError::RetryExhausted { attempts: 1 })?;
            assert!(delay.as_millis() >= 2);
            let result = retry_with_policy(policy, &CancellationToken::new(), {
                let attempts = Arc::clone(&attempts);
                move |_attempt| {
                    let attempts = Arc::clone(&attempts);
                    async move {
                        let current = attempts.fetch_add(1, Ordering::SeqCst);
                        if current < 2 {
                            Err(TransportError::Http("temporary".to_owned()))
                        } else {
                            Ok("sent")
                        }
                    }
                }
            })
            .await?;
            assert_eq!(result, "sent");
            assert_eq!(attempts.load(Ordering::SeqCst), 3);
            Ok::<(), Box<dyn std::error::Error>>(())
        })
    }

    #[test]
    fn backpressure_rejects_when_budget_is_exhausted() -> Result<(), Box<dyn std::error::Error>> {
        let budget = TransportBackpressure::new(1);
        let first = budget.try_acquire()?;
        assert_eq!(budget.in_flight(), 1);
        assert!(matches!(
            budget.try_acquire(),
            Err(TransportError::BackpressureRejected { capacity: 1, in_flight: 1 })
        ));
        drop(first);
        assert_eq!(budget.in_flight(), 0);
        Ok(())
    }

    #[test]
    fn shutdown_drain_rejects_new_work_and_waits_for_in_flight()
    -> Result<(), Box<dyn std::error::Error>> {
        let runtime = tokio::runtime::Builder::new_current_thread().enable_time().build()?;
        runtime.block_on(async {
            let drain = ShutdownDrain::new();
            let permit = drain.try_start_operation()?;
            drain.begin_shutdown();
            assert!(!drain.is_accepting());
            assert!(matches!(drain.try_start_operation(), Err(TransportError::ShutdownDraining)));
            drop(permit);
            drain.drain(Duration::from_millis(10)).await?;
            Ok::<(), Box<dyn std::error::Error>>(())
        })
    }
}
