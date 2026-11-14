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
    /// Whether a full-data async worker still needs local service or completion.
    /// A driver services its ordinary writer, pumps both peers, then waits on their
    /// signals only while this predicate is true. Relay messages still need pumping.
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
