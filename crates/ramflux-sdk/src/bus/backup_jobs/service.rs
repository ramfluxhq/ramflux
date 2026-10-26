// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Short synchronous job-state guards; workers own all filesystem and crypto work.
use crate::{
    SdkError,
    backup::{
        BackupCategory, BackupFailure, BackupFailureCode, BackupJob, BackupJobKind,
        BackupJobRegistry, BackupJobState, BackupProgress,
    },
};

use std::{
    collections::VecDeque,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::task::JoinHandle;

struct ProgressMark {
    category: BackupCategory,
    items: bool,
    done: u64,
    total: Option<u64>,
    at: std::time::Instant,
}
pub(super) struct State {
    pub registry: BackupJobRegistry,
    pub events: VecDeque<(u64, BackupJob)>,
    pub head: u64,
    pub cancelling: std::collections::BTreeSet<String>,
    progress: std::collections::BTreeMap<String, ProgressMark>,
}
#[derive(Clone)]
pub(crate) struct BackupJobs {
    pub(super) state: Arc<Mutex<State>>,
    pub(super) root: PathBuf,
    pub(super) data_root: PathBuf,
    pub(super) index: ramflux_storage::AccountIndex,
    pub(super) generations: super::generation_lock::GenerationLocks,
    tasks: Arc<Mutex<Vec<JoinHandle<()>>>>,
    next_cleanup: Arc<Mutex<std::time::Instant>>,
    pub(super) diagnostics: super::attachments::Diagnostics,
    #[cfg(test)]
    pub(super) install_hook: super::test_install::InstallHook,
}
pub(super) fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |time| time.as_secs())
}
pub(crate) fn refused(reason: &str) -> SdkError {
    SdkError::LocalBusRefused {
        code: "BackupRefused".into(),
        message: reason.into(),
        body: Box::new(serde_json::json!({"reason_code":reason})),
    }
}
impl BackupJobs {
    pub(crate) fn new(
        data_root: &Path,
        index: ramflux_storage::AccountIndex,
    ) -> Result<Self, SdkError> {
        let root = data_root.join("backup_jobs");
        std::fs::create_dir_all(&root)?;
        crate::bus::daemon::set_owner_only_dir_permissions(&root)?;
        let generations = super::generation_lock::GenerationLocks::default();
        if super::recovery::recover_with_locks(&root, data_root, &index, &generations).is_err() {
            tracing::warn!("backup cleanup deferred; daemon startup continues");
        }
        Ok(Self {
            state: Arc::new(Mutex::new(State {
                registry: BackupJobRegistry::default(),
                events: VecDeque::new(),
                head: 0,
                cancelling: std::collections::BTreeSet::default(),
                progress: std::collections::BTreeMap::default(),
            })),
            root,
            data_root: data_root.to_owned(),
            index,
            generations,
            tasks: Arc::default(),
            next_cleanup: Arc::new(Mutex::new(std::time::Instant::now())),
            diagnostics: Arc::default(),
            #[cfg(test)]
            install_hook: Arc::default(),
        })
    }
    pub(super) fn change(
        &self,
        update: impl FnOnce(&mut BackupJobRegistry) -> Result<BackupJob, SdkError>,
    ) -> Result<BackupJob, SdkError> {
        let mut state = self.state.lock().map_err(|_| refused("interrupted"))?;
        if !state.cancelling.is_empty() {
            return Err(refused("interrupted"));
        }
        let row = update(&mut state.registry)?;
        state.head = state.head.checked_add(1).ok_or_else(|| refused("interrupted"))?;
        let seq = state.head;
        state.events.push_back((seq, row.clone()));
        while state.events.len() > 1024 {
            state.events.pop_front();
        }
        Ok(row)
    }
    pub(super) fn fail_install(&self, id: &str, error: &SdkError) {
        let failure = match error {
            SdkError::LocalBusRefused { body, .. } => body
                .get("failure")
                .and_then(|value| serde_json::from_value(value.clone()).ok())
                .or_else(|| {
                    body.get("reason_code")
                        .and_then(|value| {
                            serde_json::from_value::<BackupFailureCode>(value.clone()).ok()
                        })
                        .map(BackupFailure::new)
                })
                .unwrap_or_else(|| BackupFailure::new(BackupFailureCode::Interrupted)),
            SdkError::Storage(error) if error.is_insufficient_space() => {
                BackupFailure::new(BackupFailureCode::InsufficientSpace)
            }
            SdkError::Io(error) if error.kind() == std::io::ErrorKind::StorageFull => {
                BackupFailure::new(BackupFailureCode::InsufficientSpace)
            }
            _ => BackupFailure::new(BackupFailureCode::Interrupted),
        };
        self.fail(id, failure);
    }
    pub(crate) fn jobs(&self) -> Result<serde_json::Value, SdkError> {
        let state = self.state.lock().map_err(|_| refused("interrupted"))?;
        Ok(serde_json::json!({"jobs":state.registry.jobs()}))
    }
    pub(super) fn start(&self, kind: BackupJobKind, path: String) -> Result<BackupJob, SdkError> {
        if path.len() > 4096 {
            return Err(refused("unreadable"));
        }
        self.change(|registry| registry.start(kind, path, now()))
    }
    pub(super) fn directory(&self, id: &str) -> Result<PathBuf, SdkError> {
        let path = self.root.join(format!("job_{id}"));
        std::fs::create_dir(&path)?;
        crate::bus::daemon::set_owner_only_dir_permissions(&path)?;
        Ok(path)
    }
    pub(super) fn task(&self, task: JoinHandle<()>) -> Result<(), SdkError> {
        let mut tasks = self.tasks.lock().map_err(|_| refused("interrupted"))?;
        tasks.retain(|task| !task.is_finished());
        tasks.push(task);
        Ok(())
    }
    pub(crate) fn create(
        &self,
        path: String,
        secret: zeroize::Zeroizing<String>,
        actor: crate::bus::actor::AccountActor,
        allow_missing_attachments: bool,
    ) -> Result<BackupJob, SdkError> {
        let row = self.start(BackupJobKind::Backup, path)?;
        let job = row.clone();
        let service = self.clone();
        self.task(tokio::task::spawn_local(async move {
            let id = job.job_id.clone();
            match service.fetch_before_capture(&actor, &job).await {
                Ok(captured) => {
                    let worker = service.clone();
                    match tokio::task::spawn_blocking(move || {
                        worker.write_archive(&job, secret, captured, allow_missing_attachments)
                    })
                    .await
                    {
                        Ok(Ok(())) => {}
                        Ok(Err(failure)) => service.fail(&id, failure),
                        Err(_) => {
                            service.fail(&id, BackupFailure::new(BackupFailureCode::Interrupted));
                        }
                    }
                }
                Err(_) => service.fail(
                    &id,
                    BackupFailure::new(
                        if service
                            .cancellation(&id)
                            .is_ok_and(|c| c.load(std::sync::atomic::Ordering::Acquire))
                        {
                            BackupFailureCode::Interrupted
                        } else {
                            BackupFailureCode::Unreadable
                        },
                    ),
                ),
            }
        }))?;
        Ok(row)
    }
    pub(crate) fn verify(
        &self,
        path: String,
        secret: zeroize::Zeroizing<String>,
    ) -> Result<BackupJob, SdkError> {
        let row = self.start(BackupJobKind::Restore, path)?;
        let job = row.clone();
        let service = self.clone();
        self.task(tokio::task::spawn_local(async move {
            let worker = service.clone();
            let id = job.job_id.clone();
            match tokio::task::spawn_blocking(move || worker.verify_archive(&job, secret)).await {
                Ok(Ok(())) => {}
                Ok(Err(failure)) => service.fail(&id, failure),
                Err(_) => service.fail(&id, BackupFailure::new(BackupFailureCode::Interrupted)),
            }
        }))?;
        Ok(row)
    }
    pub(super) fn fail(&self, id: &str, mut failure: BackupFailure) {
        if failure.code == BackupFailureCode::InsufficientSpace
            && failure.needed_bytes.is_none()
            && let Ok(available) = fs2::available_space(&self.root)
        {
            failure.available_bytes = Some(available);
            failure.needed_bytes = Some(available.saturating_add(2 * 1024 * 1024));
        }
        let discard = {
            let Ok(mut state) = self.state.lock() else { return };
            if state.cancelling.contains(id) {
                return;
            }
            let Ok((row, staging)) = state.registry.fail(id, failure, now()) else { return };
            state.head += 1;
            let seq = state.head;
            state.events.push_back((seq, row));
            while state.events.len() > 1024 {
                state.events.pop_front();
            }
            staging
        };
        drop(discard);
    }
    pub(crate) async fn cancel(&self, id: &str) -> Result<BackupJob, SdkError> {
        {
            let mut state = self.state.lock().map_err(|_| refused("interrupted"))?;
            let row = state.registry.job(id)?;
            if row.state.terminal() || row.state == BackupJobState::Installing {
                return Err(refused("invalid_job_phase"));
            }
            state.registry.cancellation(id)?.store(true, std::sync::atomic::Ordering::Release);
            state.cancelling.insert(id.into());
        }
        let tasks = self
            .tasks
            .lock()
            .map(|mut tasks| std::mem::take(&mut *tasks))
            .map_err(|_| refused("interrupted"))?;
        for task in tasks {
            let _ = task.await;
        }
        let (row, staging) = {
            let mut state = self.state.lock().map_err(|_| refused("interrupted"))?;
            state.cancelling.remove(id);
            state.registry.cancel(id, now())?
        };
        drop(staging);
        let mut state = self.state.lock().map_err(|_| refused("interrupted"))?;
        state.head += 1;
        let seq = state.head;
        state.events.push_back((seq, row.clone()));
        Ok(row)
    }
    #[cfg(test)]
    pub(super) fn force_periodic_cleanup(&self) {
        if let Ok(mut next) = self.next_cleanup.lock() {
            *next = std::time::Instant::now();
        }
        self.expire();
    }
    pub(crate) fn expire(&self) {
        if let Ok(mut diagnostics) = self.diagnostics.lock() {
            let retained = self
                .state
                .lock()
                .map(|s| {
                    s.registry
                        .jobs()
                        .into_iter()
                        .map(|r| r.job_id)
                        .collect::<std::collections::BTreeSet<_>>()
                })
                .unwrap_or_default();
            diagnostics.retain(|id, stage| retained.contains(id) && !stage.expired(now()));
        }
        if let Ok(mut next) = self.next_cleanup.try_lock()
            && std::time::Instant::now() >= *next
        {
            *next = std::time::Instant::now() + std::time::Duration::from_secs(30);
            let mut protected = self.state.lock().map(|s| {
                s.registry
                    .jobs()
                    .into_iter()
                    .filter(|r| !r.state.terminal())
                    .map(|r| format!("job_{}", r.job_id))
                    .collect::<std::collections::BTreeSet<_>>()
            });
            if let Ok(diagnostics) = self.diagnostics.lock()
                && let Ok(protected) = &mut protected
            {
                protected.extend(diagnostics.keys().map(|id| format!("job_{id}")));
            }
            if let Ok(protected) = protected
                && super::recovery::recover_jobs_excluding(&self.root, &protected).is_err()
            {
                tracing::warn!("backup cleanup remains deferred; retry scheduled");
            }
        }
        let expired = {
            let Ok(mut state) = self.state.lock() else { return };
            let expired = state.registry.expire(now());
            for (row, _) in &expired {
                state.head += 1;
                let seq = state.head;
                state.events.push_back((seq, row.clone()));
            }
            while state.events.len() > 1024 {
                state.events.pop_front();
            }
            expired
        };
        drop(expired);
    }
    pub(super) fn progress(
        &self,
        id: &str,
        category: BackupCategory,
        items: u64,
        bytes: u64,
        totals: Option<u64>,
    ) {
        self.progress_value(
            id,
            BackupProgress {
                category,
                items_done: items,
                items_total: None,
                bytes_done: bytes,
                bytes_total: totals,
            },
        );
    }
    pub(super) fn progress_fetch(&self, id: &str, done: u64, total: u64) {
        self.progress_value(
            id,
            BackupProgress {
                category: BackupCategory::Attachments,
                items_done: done,
                items_total: Some(total),
                bytes_done: 0,
                bytes_total: None,
            },
        );
    }
    fn progress_value(&self, id: &str, progress: BackupProgress) {
        let Ok(mut state) = self.state.lock() else { return };
        if !state.cancelling.is_empty() {
            return;
        }
        let at = std::time::Instant::now();
        let items = progress.items_total.is_some() && progress.bytes_total.is_none();
        let done = if items { progress.items_done } else { progress.bytes_done };
        let total = if items { progress.items_total } else { progress.bytes_total };
        if let Some(previous) = state.progress.get(id) {
            let percent = total.filter(|n| *n > 0).is_some_and(|n| {
                u128::from(done.saturating_sub(previous.done)) * 100 >= u128::from(n)
                    || (done >= n && previous.done < n)
            });
            if previous.category == progress.category
                && previous.items == items
                && previous.total == total
                && done >= previous.done
                && !percent
                && at.duration_since(previous.at) < std::time::Duration::from_millis(250)
            {
                return;
            }
        }
        let category = progress.category;
        let Ok(row) = state.registry.progress(id, progress) else { return };
        state.progress.retain(|key, _| key == id);
        state.progress.insert(id.into(), ProgressMark { category, items, done, total, at });
        state.head += 1;
        let seq = state.head;
        state.events.push_back((seq, row));
        while state.events.len() > 1024 {
            state.events.pop_front();
        }
    }
    pub(crate) async fn stop(&self) {
        if let Ok(state) = self.state.lock() {
            state.registry.shutdown();
        }
        let tasks =
            self.tasks.lock().map(|mut tasks| std::mem::take(&mut *tasks)).unwrap_or_default();
        for task in tasks {
            let _ = task.await;
        }
    }
    pub(super) fn cancellation(
        &self,
        id: &str,
    ) -> Result<Arc<std::sync::atomic::AtomicBool>, SdkError> {
        self.state.lock().map_err(|_| refused("interrupted"))?.registry.cancellation(id)
    }
}

#[cfg(test)]
mod review_tests {
    use super::*;
    #[test]
    fn r2_fast_chunk_progress_cannot_overflow_the_replay_ring()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = crate::bus::runtime_tests::root("backup-progress");
        let jobs = BackupJobs::new(&root, ramflux_storage::AccountIndex::open(&root)?)?;
        let row = jobs.start(BackupJobKind::Backup, "archive".into())?;
        let total = 1024 * 1024 * 1024;
        for bytes in (0..=total).step_by(64 * 1024) {
            jobs.progress(&row.job_id, BackupCategory::Attachments, 0, bytes, Some(total));
        }
        let state = jobs.state.lock().map_err(|_| "lock")?;
        assert!(state.head <= 105, "one GiB must coalesce chunk events into percentage updates");
        assert_eq!(state.registry.job(&row.job_id)?.progress.bytes_done, total);
        drop(state);
        std::fs::remove_dir_all(root)?;
        Ok(())
    }
    #[test]
    fn r2_cleanup_failure_does_not_block_startup_and_a_later_retry_removes_the_marker()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = crate::bus::runtime_tests::root("backup-cleanup-retry");
        let index = ramflux_storage::AccountIndex::open(&root)?;
        let stage = root.join("backup_jobs/job_retry");
        std::fs::create_dir_all(&stage)?;
        let partial = root.join(".ramflux-backup-retry.partial");
        std::fs::create_dir(&partial)?;
        super::super::recovery::remember_partial_output(&stage, &partial)?;
        let jobs = BackupJobs::new(&root, index)?;
        assert!(stage.exists(), "failed cleanup retains its durable retry marker");
        std::fs::remove_dir(&partial)?;
        jobs.expire();
        assert!(!stage.exists(), "the periodic cleanup must retry without a daemon restart");
        std::fs::remove_dir_all(root)?;
        Ok(())
    }
}
