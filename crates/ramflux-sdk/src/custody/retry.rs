// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Bounded Busy retries and an account-local lease shared by independent processes.
use crate::SdkError;
use ramflux_protocol::custody::CustodyRefusal;
use std::{fs::File, future::Future, path::Path, time::Duration};
use tokio::time::Instant;

const RETRY_BUDGET: Duration = Duration::from_secs(90);
const MAX_BACKOFF: Duration = Duration::from_secs(16);

pub(super) fn busy() -> SdkError {
    CustodyRefusal::Busy.into()
}
pub(super) fn is_busy(error: &SdkError) -> bool {
    matches!(error, SdkError::CustodyNetwork(CustodyRefusal::Busy))
}
pub(crate) struct Budget {
    deadline: Instant,
    backoff: Duration,
}
impl Budget {
    pub(crate) fn new() -> Self {
        Self { deadline: Instant::now() + RETRY_BUDGET, backoff: Duration::from_secs(1) }
    }
    pub(crate) async fn attempt<T>(
        &self,
        operation: impl Future<Output = Result<T, SdkError>>,
    ) -> Result<T, SdkError> {
        if Instant::now() >= self.deadline {
            return Err(busy());
        }
        tokio::time::timeout_at(self.deadline, operation).await.map_err(|_| busy())?
    }
    pub(super) async fn pause(&mut self) -> Result<(), SdkError> {
        let mut bytes = [0; 8];
        getrandom::fill(&mut bytes).map_err(|_| SdkError::CustodyRandomUnavailable)?;
        let delay = jitter(self.backoff, u64::from_ne_bytes(bytes));
        self.backoff = (self.backoff * 2).min(MAX_BACKOFF);
        if Instant::now() + delay >= self.deadline {
            tokio::time::sleep_until(self.deadline).await;
            return Err(busy());
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
fn jitter(backoff: Duration, random: u64) -> Duration {
    // Nominal 1, 2, 4, 8, 16 seconds; the upper quarter is jittered, with a
    // one-second floor and a sixteen-second ceiling, including at saturation.
    let upper = u64::try_from(backoff.as_millis()).unwrap_or(16_000).min(16_000);
    let lower = (upper * 3 / 4).max(1_000);
    Duration::from_millis(lower + random % (upper - lower + 1))
}
pub(super) struct AccountLease(File);
impl Drop for AccountLease {
    fn drop(&mut self) {
        let _ = fs2::FileExt::unlock(&self.0);
    }
}
pub(super) async fn single_flight(
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
