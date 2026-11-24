// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Account-scoped cancellation and completion drain for app lock.
use super::service::BackupJobs;
use crate::SdkError;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use tokio::sync::watch;

pub(super) struct Export {
    pub account: String,
    pub job: String,
    pub cancel: Arc<AtomicBool>,
    pub done: watch::Receiver<bool>,
}
pub(super) struct ExportDone(pub watch::Sender<bool>);
impl Drop for ExportDone {
    fn drop(&mut self) {
        self.0.send_replace(true);
    }
}
impl BackupJobs {
    pub(super) fn bind_app_account(&self, job: &str, account: &str) -> Result<(), SdkError> {
        let mut state = self.state.lock().map_err(|_| crate::bus::app_lock_fence::locked())?;
        let current = state
            .registry
            .jobs()
            .into_iter()
            .map(|row| row.job_id)
            .collect::<std::collections::BTreeSet<_>>();
        state.accounts.retain(|id, _| current.contains(id));
        state.accounts.insert(job.into(), account.into());
        Ok(())
    }

    pub(super) fn app_job_visible(
        &self,
        id: &str,
        fences: &crate::bus::app_lock_fence::Fences,
    ) -> Result<bool, SdkError> {
        let state = self.state.lock().map_err(|_| crate::bus::app_lock_fence::locked())?;
        let row = state.registry.job(id)?;
        let account = state
            .accounts
            .get(id)
            .map(String::as_str)
            .or_else(|| row.archive.as_ref().map(|preview| preview.local_account_id.as_str()))
            .or_else(|| {
                row.installed_account.as_ref().map(|account| account.local_account_id.as_str())
            });
        match account {
            Some(account) => Ok(!fences.epoch(account)?.blocks_access()),
            None => Ok(!fences.any_locked()?),
        }
    }

    pub(super) fn app_visible_jobs(
        &self,
        fences: &crate::bus::app_lock_fence::Fences,
    ) -> Result<serde_json::Value, SdkError> {
        let jobs =
            self.state.lock().map_err(|_| crate::bus::app_lock_fence::locked())?.registry.jobs();
        let mut visible = Vec::new();
        for row in jobs {
            if self.app_job_visible(&row.job_id, fences)? {
                visible.push(row);
            }
        }
        Ok(serde_json::json!({"jobs":visible}))
    }

    pub(crate) async fn app_lock_account(&self, account: &str) -> Result<(), SdkError> {
        let mut waiting = {
            let mut exports =
                self.exports.lock().map_err(|_| crate::bus::app_lock_fence::locked())?;
            exports.retain(|export| !*export.done.borrow());
            exports
                .iter()
                .filter(|export| export.account == account)
                .map(|export| {
                    export.cancel.store(true, Ordering::Release);
                    export.done.clone()
                })
                .collect::<Vec<_>>()
        };
        let jobs = self
            .exports
            .lock()
            .map_err(|_| crate::bus::app_lock_fence::locked())?
            .iter()
            .filter(|export| export.account == account && !*export.done.borrow())
            .map(|export| export.job.clone())
            .collect::<Vec<_>>();
        for job in jobs {
            self.fail(
                &job,
                crate::backup::BackupFailure::new(crate::backup::BackupFailureCode::AppLocked),
            );
        }
        for done in &mut waiting {
            while !*done.borrow_and_update() {
                done.changed().await.map_err(|_| crate::bus::app_lock_fence::locked())?;
            }
        }
        Ok(())
    }
}
