// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Ordinary standalone SDK drivers wait without borrowing a database or polling sleeps.
use super::PairingActor;
use std::sync::Arc;
impl PairingActor {
    /// Wakeups for queued full-data local I/O, async completion and root shutdown.
    /// Keep the signal while driving this actor; notifications grant no data or authority.
    #[must_use]
    pub fn local_work_signal(&self) -> Arc<tokio::sync::Notify> {
        self.full_runtime.activity_signal()
    }
    /// Whether the DATA worker has replaced this actor's short SAS relay pump.
    /// Standalone two-endpoint drivers keep pumping both actors until both return true
    /// before waiting solely on their worker signals. This is a scheduling hint only.
    #[must_use]
    pub fn full_data_worker_owns_relay(&self) -> bool {
        self.ceremony
            .as_ref()
            .and_then(|ceremony| ceremony.full.as_ref())
            .and_then(|full| full.bootstrap.as_ref())
            .is_some_and(|state| {
                state.epoch_job.is_some() || state.epoch_ready.is_some() || state.stream.is_some()
            })
            || !self.tail_jobs.is_empty()
    }
    #[cfg(test)]
    pub(crate) fn full_tail_epoch_in_flight_for_test(&self) -> bool {
        self.tail_jobs.values().any(|job| job.epoch.as_ref().is_some_and(|epoch| !epoch.finished()))
    }
    /// Whether a full-data async worker still needs local service or completion.
    /// A driver services its ordinary writer, pumps both peers, then waits on their
    /// signals only while this predicate is true AND both peers report
    /// `full_data_worker_owns_relay`. Short SAS relay messages still need pumping.
    /// Service local data again after `sync_relay`: it can publish a newly ready
    /// epoch which requires foreground service before a worker can emit a wakeup.
    #[must_use]
    pub fn has_pending_full_local_work(&self) -> bool {
        let pending = self
            .ceremony
            .as_ref()
            .and_then(|ceremony| ceremony.full.as_ref())
            .and_then(|full| full.bootstrap.as_ref())
            .is_some_and(|state| {
                state.epoch_job.as_ref().is_some_and(|job| !job.finished())
                    || state
                        .stream
                        .as_ref()
                        .and_then(|stream| stream.job.as_ref())
                        .is_some_and(|job| !job.finished())
            });
        pending
            || self
                .tail_jobs
                .values()
                .any(|job| job.epoch.as_ref().is_some_and(|epoch| !epoch.finished()))
    }
}
