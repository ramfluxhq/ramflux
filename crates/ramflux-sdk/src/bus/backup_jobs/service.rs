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

pub(super) struct State {
    pub registry: BackupJobRegistry,
    pub events: VecDeque<(u64, BackupJob)>,
    pub head: u64,
    pub cancelling: std::collections::BTreeSet<String>,
}
#[derive(Clone)]
pub(crate) struct BackupJobs {
    pub(super) state: Arc<Mutex<State>>,
    pub(super) root: PathBuf,
    pub(super) data_root: PathBuf,
    pub(super) index: ramflux_storage::AccountIndex,
    tasks: Arc<Mutex<Vec<JoinHandle<()>>>>,
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
        super::recovery::recover(&root, data_root, &index)?;
        Ok(Self {
            state: Arc::new(Mutex::new(State {
                registry: BackupJobRegistry::default(),
                events: VecDeque::new(),
                head: 0,
                cancelling: std::collections::BTreeSet::default(),
            })),
            root,
            data_root: data_root.to_owned(),
            index,
            tasks: Arc::default(),
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
    ) -> Result<BackupJob, SdkError> {
        let row = self.start(BackupJobKind::Backup, path)?;
        let job = row.clone();
        let service = self.clone();
        self.task(tokio::task::spawn_local(async move {
            let id = job.job_id.clone();
            match actor.capture_backup().await {
                Ok(captured) => {
                    let worker = service.clone();
                    match tokio::task::spawn_blocking(move || {
                        worker.write_archive(&job, secret, captured)
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
                Err(_) => service.fail(&id, BackupFailure::new(BackupFailureCode::Unreadable)),
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
    pub(crate) fn expire(&self) {
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
        let _ = self.change(|registry| {
            registry.progress(
                id,
                BackupProgress {
                    category,
                    items_done: items,
                    items_total: None,
                    bytes_done: bytes,
                    bytes_total: totals,
                },
            )
        });
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
