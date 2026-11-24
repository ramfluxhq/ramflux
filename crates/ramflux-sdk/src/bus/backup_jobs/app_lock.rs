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
