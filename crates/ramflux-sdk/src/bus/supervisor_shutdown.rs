// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Daemon stop: one bounded, logged shutdown run. Every phase has a time limit; an overrun
//! is named in the log and in the stop reply, never silent. The limits are a safety net.

use super::{AccountActor, Supervisor};
use crate::prelude::*;
use std::collections::BTreeSet;
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, Instant};

const LIFECYCLE_TASKS_MS: u64 = 1000;
const BACKUP_JOBS_MS: u64 = 500;
const BACKUP_EXPIRY_MS: u64 = 250;
const ACTORS_MS: u64 = 1500;
/// Cleanup of the aborted lifecycle tasks after their budget ran out.
const ABORT_JOIN_MS: u64 = 250;
const WATCHDOG: Duration = Duration::from_millis(4500);
const PHASE_IDLE: &str = "idle";
const PHASE_FINISHED: &str = "finished";

/// The stored outcome of the single shutdown run.
#[derive(Clone)]
pub(super) struct ShutdownReport {
    pub(super) forced: bool,
    pub(super) overran: Vec<&'static str>,
    result: Result<(), String>,
}

/// A std thread that only logs which phase is still running when the stop takes too long.
pub(super) struct StopWatch {
    phase: Arc<Mutex<&'static str>>,
    cancel: Mutex<Option<mpsc::Sender<()>>>,
}

impl StopWatch {
    pub(super) fn new() -> Self {
        Self { phase: Arc::new(Mutex::new(PHASE_IDLE)), cancel: Mutex::new(None) }
    }

    fn set_phase(&self, name: &'static str) {
        if let Ok(mut phase) = self.phase.lock() {
            *phase = name;
        }
    }

    /// Starts the watchdog once. Dropping the supervisor drops the sender and ends the thread.
    fn start(&self, started: Instant) {
        let Ok(mut cancel) = self.cancel.lock() else { return };
        if cancel.is_some() {
            return;
        }
        let (sender, receiver) = mpsc::channel::<()>();
        let phase = Arc::clone(&self.phase);
        let spawned =
            std::thread::Builder::new().name("ramflux-stop-watchdog".to_owned()).spawn(move || {
                if receiver.recv_timeout(WATCHDOG) != Err(mpsc::RecvTimeoutError::Timeout) {
                    return;
                }
                let name = phase.lock().map_or("unknown", |name| *name);
                if name != PHASE_IDLE && name != PHASE_FINISHED {
                    tracing::warn!(
                        phase = name,
                        elapsed_ms = elapsed_ms(started),
                        "daemon stop watchdog: phase still running"
                    );
                }
            });
        match spawned {
            Ok(_) => *cancel = Some(sender),
            Err(error) => tracing::warn!(%error, "daemon stop watchdog could not start"),
        }
    }
}

fn elapsed_ms(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}

fn note_overrun(overran: &mut Vec<&'static str>, phase: &'static str, budget_ms: u64) {
    overran.push(phase);
    tracing::warn!(phase, budget_ms, "daemon stop phase overran");
}

impl Supervisor {
    /// Runs the shutdown once; a later call returns the stored result without waiting again.
    pub(in crate::bus) async fn shutdown(&self) -> Result<(), SdkError> {
        self.shutdown_report().await.result.map_err(SdkError::LocalBus)
    }

    /// Runs the shutdown and builds the `daemon.stop` reply body.
    pub(super) async fn stop_reply_body(&self) -> Result<serde_json::Value, SdkError> {
        let report = self.shutdown_report().await;
        report.result.map_err(SdkError::LocalBus)?;
        Ok(serde_json::json!({
            "stopping": true,
            "forced": report.forced,
            "overran": report.overran,
            "pid": std::process::id(),
        }))
    }

    /// The first caller starts the run as its own local task; every caller then waits for it.
    /// The run never lives inside a caller's future, so closing the caller's connection (the
    /// stop request's own, or any other) cannot cancel it and cannot make it start a second time.
    async fn shutdown_report(&self) -> ShutdownReport {
        if !self.shutdown_started.replace(true) {
            let owner = self.owner.borrow().upgrade();
            if let Some(supervisor) = owner {
                tokio::task::spawn_local(async move {
                    let report = supervisor.run_shutdown().await;
                    let _ = supervisor.shutdown_report.set(report);
                    supervisor.shutdown_done.send_replace(true);
                });
            } else {
                let report = self.run_shutdown().await;
                let _ = self.shutdown_report.set(report);
                self.shutdown_done.send_replace(true);
            }
        }
        let mut done = self.shutdown_done.subscribe();
        while !*done.borrow_and_update() {
            if done.changed().await.is_err() {
                break;
            }
        }
        self.shutdown_report.get().cloned().unwrap_or_else(|| ShutdownReport {
            forced: true,
            overran: Vec::new(),
            result: Err("daemon stop did not finish".to_owned()),
        })
    }

    /// Marks the phase the watchdog reports; the teardown after the stop reply uses it too.
    pub(in crate::bus) fn set_stop_phase(&self, name: &'static str) {
        self.stop_watch.set_phase(name);
    }

    /// Runs one teardown phase with a time limit. `None` means the limit ran out.
    pub(in crate::bus) async fn bounded_phase<T>(
        &self,
        phase: &'static str,
        budget_ms: u64,
        work: impl std::future::Future<Output = T>,
    ) -> Option<T> {
        self.set_stop_phase(phase);
        let done = tokio::time::timeout(Duration::from_millis(budget_ms), work).await.ok();
        if done.is_none() {
            tracing::warn!(phase, budget_ms, "daemon stop phase overran");
        }
        done
    }

    async fn run_shutdown(&self) -> ShutdownReport {
        let started = Instant::now();
        self.stop_watch.start(started);
        tracing::info!(accounts = self.accounts.borrow().len(), "daemon stop started");
        let mut overran = Vec::new();
        if let Some(timer) = self.app_timer.borrow_mut().take() {
            timer.abort();
        }
        self.close_lifecycle_admission();
        self.drain_lifecycle_tasks(&mut overran).await;
        self.set_stop_phase("backup_jobs");
        if self.backup_jobs.stop_within(Duration::from_millis(BACKUP_JOBS_MS)).await {
            note_overrun(&mut overran, "backup_jobs", BACKUP_JOBS_MS);
        }
        self.start_event_router();
        self.stop_backup_expiry(&mut overran).await;
        let result = self.stop_actors(&mut overran).await;
        self.set_stop_phase(PHASE_FINISHED);
        let forced = !overran.is_empty();
        tracing::info!(
            elapsed_ms = elapsed_ms(started),
            forced,
            overran = ?overran,
            "daemon stop finished"
        );
        ShutdownReport { forced, overran, result: result.map_err(|error| error.to_string()) }
    }

    async fn drain_lifecycle_tasks(&self, overran: &mut Vec<&'static str>) {
        self.set_stop_phase("lifecycle_tasks");
        // Admission is closed before moving the set; no new task can escape this drain.
        let mut tasks = std::mem::take(&mut *self.lifecycle_tasks.borrow_mut());
        #[cfg(test)]
        if let Some(gate) = &self.config.lifecycle_gate {
            gate.draining.notify_one();
        }
        let drained = tokio::time::timeout(Duration::from_millis(LIFECYCLE_TASKS_MS), async {
            while tasks.join_next().await.is_some() {}
        })
        .await;
        if drained.is_err() {
            note_overrun(overran, "lifecycle_tasks", LIFECYCLE_TASKS_MS);
            tasks.abort_all();
            let _ = tokio::time::timeout(Duration::from_millis(ABORT_JOIN_MS), async {
                while tasks.join_next().await.is_some() {}
            })
            .await;
        }
    }

    async fn stop_backup_expiry(&self, overran: &mut Vec<&'static str>) {
        self.set_stop_phase("backup_expiry");
        // A retained stopped handle must not reclaim a replacement daemon's staging.
        let expiry = self.backup_expiry.borrow_mut().take();
        if let Some(task) = expiry {
            task.abort();
            if tokio::time::timeout(Duration::from_millis(BACKUP_EXPIRY_MS), task).await.is_err() {
                note_overrun(overran, "backup_expiry", BACKUP_EXPIRY_MS);
            }
        }
    }

    /// Signals every actor first, then waits for all of them together under one limit.
    async fn stop_actors(&self, overran: &mut Vec<&'static str>) -> Result<(), SdkError> {
        self.set_stop_phase("actors");
        let mut actors: Vec<(String, AccountActor)> =
            self.accounts.borrow().iter().map(|(id, actor)| (id.clone(), actor.clone())).collect();
        actors.push(("node".to_owned(), self.node_actor.clone()));
        for (_, actor) in &actors {
            actor.signal_stop();
        }
        let mut pending = actors.iter().map(|(id, _)| id.clone()).collect::<BTreeSet<_>>();
        let mut waits = tokio::task::JoinSet::new();
        for (id, actor) in actors {
            waits.spawn_local(async move { (id, actor.stop().await) });
        }
        let mut result = Ok(());
        let waited = tokio::time::timeout(Duration::from_millis(ACTORS_MS), async {
            while let Some(joined) = waits.join_next().await {
                let Ok((id, stopped)) = joined else { continue };
                pending.remove(&id);
                if let Err(error) = stopped {
                    result = Err(error);
                }
            }
        })
        .await;
        if waited.is_err() {
            overran.push("actors");
            for account_id in &pending {
                tracing::warn!(
                    phase = "actors",
                    budget_ms = ACTORS_MS,
                    account_id = %account_id,
                    "daemon stop phase overran"
                );
            }
            waits.abort_all();
        }
        result
    }
}
