// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Fetch-before-snapshot, explicit omissions, and bounded unavailable-file diagnostics.
use super::{
    CapturedAccount,
    service::{BackupJobs, now, refused},
};
use crate::{
    SdkError,
    backup::{BackupFailure, BackupFailureCode, BackupJob, VerifiedBackupStaging},
    bus::{
        actor::{AccountActor, AccountCommand},
        protocol::LocalBusFrame,
    },
};
use ramflux_storage::{AccountDbKey, BackupDatabase};
use std::{
    collections::BTreeMap,
    path::PathBuf,
    sync::{Arc, Mutex, atomic::Ordering},
};
pub(super) type Diagnostics = Arc<Mutex<BTreeMap<String, Arc<VerifiedBackupStaging>>>>;
impl BackupJobs {
    pub(super) async fn fetch_before_capture(
        &self,
        actor: &AccountActor,
        job: &BackupJob,
    ) -> Result<CapturedAccount, SdkError> {
        let missing = actor.backup_missing_references().await?;
        let account = missing.account_id;
        let total = missing.total;
        let mut done = 0_u64;
        self.progress_fetch(&job.job_id, done, total);
        for selector in missing.selectors {
            if self.cancellation(&job.job_id)?.load(Ordering::Acquire) {
                return Err(refused("interrupted"));
            }
            let operation = format!(
                "backup-fetch:{}:{}",
                job.job_id,
                ramflux_protocol::hash_base64url("ramflux.backup.fetch.v1", selector.as_bytes())
            );
            let mut request = LocalBusFrame::request(
                &operation,
                Some(account.clone()),
                "object",
                "object.fetch",
                serde_json::json!({"object_id":selector,"operation_id":operation}),
            );
            request.operation_id = Some(operation.clone());
            let (outbound, _events) = tokio::sync::mpsc::channel(1);
            // Each object has its normal bounded fetch deadline; a failure never skips the
            // next reference. The final snapshot independently enumerates what is missing.
            let _ = actor
                .request(AccountCommand {
                    private: None,
                    request,
                    connection_id: 0,
                    topics: std::collections::BTreeSet::default(),
                    attended: true,
                    nodes: None,
                    outbound,
                    reply: None,
                })
                .await;
            done = done.saturating_add(1);
            self.progress_fetch(&job.job_id, done, total);
        }
        self.progress_fetch(&job.job_id, done, done);
        actor.capture_backup().await
    }
    pub(super) fn unavailable_failure(
        &self,
        job: &BackupJob,
        directory: PathBuf,
        key: &AccountDbKey,
        db: &BackupDatabase,
    ) -> Result<BackupFailure, SdkError> {
        let page = db.missing_attachment_page("")?;
        let count = db.missing_attachment_count()?;
        let next = if page.len() == 64 { page.last().cloned() } else { None };
        let stage = VerifiedBackupStaging::new(directory, *key.bytes(), now())?;
        self.diagnostics
            .lock()
            .map_err(|_| refused("interrupted"))?
            .insert(job.job_id.clone(), Arc::new(stage));
        Ok(BackupFailure {
            unavailable_attachments: page,
            unavailable_count: Some(count),
            unavailable_next_cursor: next,
            ..BackupFailure::new(BackupFailureCode::AttachmentsUnavailable)
        })
    }
    pub(super) async fn missing_page(
        &self,
        id: &str,
        after: &str,
    ) -> Result<serde_json::Value, SdkError> {
        let row = self.state.lock().map_err(|_| refused("interrupted"))?.registry.job(id)?;
        let stage = self
            .diagnostics
            .lock()
            .map_err(|_| refused("interrupted"))?
            .get(id)
            .cloned()
            .ok_or_else(|| refused("staging_expired"))?;
        if stage.expired(now()) {
            return Err(refused("staging_expired"));
        }
        let after = after.to_owned();
        tokio::task::spawn_blocking(move||->Result<serde_json::Value,SdkError>{
        let db = BackupDatabase::open(
            &stage.directory().join("account.db"),
            &AccountDbKey::from_bytes(*stage.key()),
        )?;
        let page = db.missing_attachment_page(&after)?;
        let next = if page.len() == 64 { page.last().cloned() } else { None };
        Ok(
            serde_json::json!({"job":row,"unavailable_attachments":page,"unavailable_count":db.missing_attachment_count()?,"unavailable_next_cursor":next}),
        )
        }).await.map_err(|_|refused("interrupted"))?
    }
}
