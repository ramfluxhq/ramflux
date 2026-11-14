// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! A finite catch-up may outlive one sync budget while durable coverage advances.

use std::{future::Future, time::Duration};
use tokio::{
    sync::watch,
    time::{Instant, error::Elapsed, timeout_at},
};

pub(super) struct Progress(watch::Sender<Instant>);

impl Progress {
    pub(super) fn start() -> (Self, watch::Receiver<Instant>) {
        let (sent, observed) = watch::channel(Instant::now());
        (Self(sent), observed)
    }

    /// Only committed forward coverage renews the budget; reads and repeated rows do not.
    pub(super) fn advanced(&self, before: u64, after: u64) {
        if after > before {
            self.0.send_replace(Instant::now());
        }
    }
}

pub(super) async fn until_stalled<F: Future>(
    budget: Duration,
    mut observed: watch::Receiver<Instant>,
    pass: F,
) -> Result<F::Output, Elapsed> {
    tokio::pin!(pass);
    loop {
        let deadline =
            observed.borrow_and_update().checked_add(budget).unwrap_or_else(Instant::now);
        tokio::select! {
            biased;
            // Prefer a committed advance racing the old deadline. Keep the same pass future.
            Ok(()) = observed.changed() => {}
            result = timeout_at(deadline, &mut pass) => return result,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BUDGET: Duration = Duration::from_secs(10);
    const STEP: Duration = Duration::from_secs(6);
    const TEST_LIMIT: Duration = Duration::from_secs(60);

    #[tokio::test(start_paused = true)]
    async fn progressing_catchup_drains_in_one_pass_beyond_the_sync_budget()
    -> Result<(), Box<dyn std::error::Error>> {
        tokio::time::timeout(TEST_LIMIT, async {
            let (progress, observed) = Progress::start();
            let started = Instant::now();
            let result = until_stalled(BUDGET, observed, async {
                for cursor in 1..=3 {
                    tokio::time::sleep(STEP).await;
                    progress.advanced(cursor - 1, cursor);
                }
                tokio::time::sleep(STEP).await;
                3
            })
            .await?;
            assert_eq!(result, 3, "the original pass must drain the complete finite backlog");
            assert_eq!(
                started.elapsed(),
                STEP * 4,
                "forward coverage must renew the idle deadline"
            );
            Ok::<_, Box<dyn std::error::Error>>(())
        })
        .await?
    }

    #[tokio::test(start_paused = true)]
    async fn repeated_cursor_does_not_keep_a_stalled_catchup_alive()
    -> Result<(), Box<dyn std::error::Error>> {
        tokio::time::timeout(TEST_LIMIT, async {
            let (progress, observed) = Progress::start();
            let started = Instant::now();
            let result = until_stalled(BUDGET, observed, async {
                tokio::time::sleep(STEP).await;
                progress.advanced(3, 3);
                std::future::pending::<()>().await;
            })
            .await;
            assert!(result.is_err(), "re-reading covered work must still time out");
            assert_eq!(started.elapsed(), BUDGET, "no progress retains the original deadline");
            Ok::<_, Box<dyn std::error::Error>>(())
        })
        .await?
    }

    #[tokio::test(start_paused = true)]
    async fn catchup_still_times_out_after_forward_progress_stops()
    -> Result<(), Box<dyn std::error::Error>> {
        tokio::time::timeout(TEST_LIMIT, async {
            let (progress, observed) = Progress::start();
            let started = Instant::now();
            let result = until_stalled(BUDGET, observed, async {
                tokio::time::sleep(STEP).await;
                progress.advanced(0, 1);
                std::future::pending::<()>().await;
            })
            .await;
            assert!(result.is_err(), "one commit must not disable the stalled-pass watchdog");
            assert_eq!(started.elapsed(), STEP + BUDGET, "the last commit anchors the deadline");
            Ok::<_, Box<dyn std::error::Error>>(())
        })
        .await?
    }
}
