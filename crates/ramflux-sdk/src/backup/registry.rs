// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! One active job, monotonic whole-row updates and short-lived encrypted staging ownership.

use super::{
    BackupArchivePreview, BackupAttachmentChecks, BackupFailure, BackupFailureCode, BackupJob,
    BackupJobKind, BackupJobState, BackupProgress,
};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use zeroize::Zeroizing;

const VERIFIED_LIFETIME_SECONDS: u64 = 30 * 60;
const RECENT_JOBS: usize = 32;

/// Private staging is removed and its only retained key is erased when ownership ends.
/// It is never serializable or printable. The directory must contain encrypted files only.
pub struct VerifiedBackupStaging {
    directory: PathBuf,
    key: Zeroizing<[u8; 32]>,
    expires_at: u64,
    deadline: std::time::Instant,
}
impl VerifiedBackupStaging {
    /// Takes ownership of an already verified encrypted staging directory.
    /// # Errors
    /// Rejects a missing/non-directory path or an overflowing lifetime.
    pub fn new(directory: PathBuf, key: [u8; 32], now: u64) -> Result<Self, crate::SdkError> {
        if !directory.is_dir() {
            return Err(refused("unreadable"));
        }
        let expires_at =
            now.checked_add(VERIFIED_LIFETIME_SECONDS).ok_or_else(|| refused("interrupted"))?;
        Ok(Self {
            directory,
            key: Zeroizing::new(key),
            expires_at,
            deadline: std::time::Instant::now()
                + std::time::Duration::from_secs(VERIFIED_LIFETIME_SECONDS),
        })
    }
    #[must_use]
    pub fn directory(&self) -> &Path {
        &self.directory
    }
    #[must_use]
    pub fn key(&self) -> &[u8; 32] {
        &self.key
    }
    fn expired(&self, now: u64) -> bool {
        now >= self.expires_at || std::time::Instant::now() >= self.deadline
    }
    #[must_use]
    pub const fn expires_at(&self) -> u64 {
        self.expires_at
    }
}
impl Drop for VerifiedBackupStaging {
    fn drop(&mut self) {
        // Even if unlink fails, the random key disappears; no passphrase is retained.
        if let Err(error) = std::fs::remove_dir_all(&self.directory) {
            tracing::warn!(kind=?error.kind(), "encrypted backup staging cleanup deferred");
        }
    }
}

/// Authenticated preview and strictly verified attachment counts with private staging ownership.
pub struct VerifiedBackup {
    pub preview: BackupArchivePreview,
    pub counts: ramflux_storage::BackupCounts,
    pub archive_bytes: u64,
    pub checks: BackupAttachmentChecks,
    pub staging: VerifiedBackupStaging,
}

struct Entry {
    row: BackupJob,
    order: u64,
    cancellation: Arc<AtomicBool>,
    staging: Option<VerifiedBackupStaging>,
}

/// Synchronous state only. Callers never hold its guard across I/O or awaits.
#[derive(Default)]
pub struct BackupJobRegistry {
    entries: BTreeMap<String, Entry>,
    order: u64,
}

impl BackupJobRegistry {
    /// Reserves one job; terminal rows are retained independently from account data.
    /// # Errors
    /// Refuses a second active job, empty path, or CSPRNG failure.
    pub fn start(
        &mut self,
        kind: BackupJobKind,
        path: String,
        now: u64,
    ) -> Result<BackupJob, crate::SdkError> {
        if self.entries.values().any(|entry| !entry.row.state.terminal()) {
            return Err(refused("busy"));
        }
        if path.is_empty() {
            return Err(refused("unreadable"));
        }
        let order = self.order.checked_add(1).ok_or_else(|| refused("interrupted"))?;
        self.prune();
        self.order = order;
        let id = ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?);
        let row = BackupJob {
            job_id: id.clone(),
            kind,
            state: match kind {
                BackupJobKind::Backup => BackupJobState::Preparing,
                BackupJobKind::Restore => BackupJobState::Verifying,
            },
            seq: 1,
            path,
            created_at: now,
            finished_at: None,
            progress: BackupProgress::default(),
            counts: None,
            archive_bytes: None,
            archive: None,
            restored: None,
            kept_newer: None,
            attachments: None,
            error: None,
        };
        self.entries.insert(
            id,
            Entry {
                row: row.clone(),
                order,
                cancellation: Arc::new(AtomicBool::new(false)),
                staging: None,
            },
        );
        Ok(row)
    }
    #[must_use]
    pub fn jobs(&self) -> Vec<BackupJob> {
        let mut rows = self.entries.values().collect::<Vec<_>>();
        rows.sort_by_key(|entry| std::cmp::Reverse(entry.order));
        rows.into_iter().map(|entry| entry.row.clone()).collect()
    }
    /// Returns only public job projection.
    /// # Errors
    /// Refuses unknown job IDs.
    pub fn job(&self, id: &str) -> Result<BackupJob, crate::SdkError> {
        Ok(self.entry(id)?.row.clone())
    }
    /// Shares a cancellation flag with the bounded worker, never a request secret.
    /// # Errors
    /// Refuses unknown job IDs.
    pub fn cancellation(&self, id: &str) -> Result<Arc<AtomicBool>, crate::SdkError> {
        Ok(Arc::clone(&self.entry(id)?.cancellation))
    }
    /// Advances only legal state transitions, incrementing seq once per visible update.
    /// # Errors
    /// Refuses unknown jobs, illegal transitions and sequence overflow.
    fn transition(
        &mut self,
        id: &str,
        state: BackupJobState,
        now: u64,
    ) -> Result<BackupJob, crate::SdkError> {
        let entry = self.entry_mut(id)?;
        if !entry.row.state.allows(state) {
            return Err(refused("invalid_job_phase"));
        }
        entry.row.seq = entry.row.seq.checked_add(1).ok_or_else(|| refused("interrupted"))?;
        entry.row.state = state;
        if state.terminal() {
            entry.row.finished_at = Some(now);
        }
        if state == BackupJobState::Cancelled || state == BackupJobState::Failed {
            entry.cancellation.store(true, Ordering::Release);
        }
        Ok(entry.row.clone())
    }
    /// Starts writing only after the worker has counted its consistent snapshot.
    /// # Errors
    /// Refuses an unknown job or a phase other than backup preparation.
    pub fn writing(
        &mut self,
        id: &str,
        counts: ramflux_storage::BackupCounts,
        now: u64,
    ) -> Result<BackupJob, crate::SdkError> {
        if self.entry(id)?.row.state != BackupJobState::Preparing {
            return Err(refused("invalid_job_phase"));
        }
        let mut row = self.transition(id, BackupJobState::Writing, now)?;
        row.counts = Some(counts);
        self.entry_mut(id)?.row = row.clone();
        Ok(row)
    }
    /// Completes a published, fsynced backup without losing its upfront counts.
    /// # Errors
    /// Refuses a non-writing job or one missing its content counts.
    pub fn written(
        &mut self,
        id: &str,
        archive_bytes: u64,
        now: u64,
    ) -> Result<BackupJob, crate::SdkError> {
        let entry = self.entry(id)?;
        if entry.row.state != BackupJobState::Writing || entry.row.counts.is_none() {
            return Err(refused("invalid_job_phase"));
        }
        let mut row = self.transition(id, BackupJobState::Done, now)?;
        row.archive_bytes = Some(archive_bytes);
        self.entry_mut(id)?.row = row.clone();
        Ok(row)
    }
    /// Publishes an already committed restore result with per-category merge counts.
    /// # Errors
    /// Refuses a non-installing job or incomplete attachment verification.
    pub fn installed(
        &mut self,
        id: &str,
        restored: ramflux_storage::BackupCounts,
        kept_newer: ramflux_storage::BackupCounts,
        now: u64,
    ) -> Result<BackupJob, crate::SdkError> {
        let entry = self.entry(id)?;
        if entry.row.state != BackupJobState::Installing
            || entry
                .row
                .attachments
                .as_ref()
                .is_none_or(|checks| checks.missing != 0 || checks.mismatched != 0)
        {
            return Err(refused("invalid_job_phase"));
        }
        let mut row = self.transition(id, BackupJobState::Done, now)?;
        row.restored = Some(restored);
        row.kept_newer = Some(kept_newer);
        self.entry_mut(id)?.row = row.clone();
        Ok(row)
    }
    /// Updates progress while preserving job identity and state.
    /// # Errors
    /// Refuses terminal jobs, unknown IDs and sequence overflow.
    pub fn progress(
        &mut self,
        id: &str,
        progress: BackupProgress,
    ) -> Result<BackupJob, crate::SdkError> {
        let entry = self.entry_mut(id)?;
        if entry.row.state.terminal() {
            return Err(refused("invalid_job_phase"));
        }
        entry.row.seq = entry.row.seq.checked_add(1).ok_or_else(|| refused("interrupted"))?;
        entry.row.progress = progress;
        Ok(entry.row.clone())
    }
    /// Records authenticated preview and transfers exclusive ownership of verified staging.
    /// # Errors
    /// Refuses a non-verifying restore or attachment mismatch/missing payload.
    pub fn verified(
        &mut self,
        id: &str,
        verified: VerifiedBackup,
        now: u64,
    ) -> Result<BackupJob, crate::SdkError> {
        let VerifiedBackup { preview, counts, archive_bytes, checks, staging } = verified;
        if checks.mismatched != 0 || checks.missing != 0 || checks.verified != counts.attachments {
            return Err(refused("attachment_mismatch"));
        }
        if staging.expired(now) {
            return Err(refused("staging_expired"));
        }
        let entry = self.entry_mut(id)?;
        if entry.row.kind != BackupJobKind::Restore || entry.row.state != BackupJobState::Verifying
        {
            return Err(refused("invalid_job_phase"));
        }
        entry.row.archive = Some(preview);
        entry.row.counts = Some(counts);
        entry.row.archive_bytes = Some(archive_bytes);
        entry.row.attachments = Some(checks);
        entry.staging = Some(staging);
        self.transition(id, BackupJobState::Verified, now)
    }
    /// Cancels only cancellable phases; installing cannot be interrupted by the UI.
    /// # Errors
    /// Refuses unknown or non-cancellable jobs.
    pub fn cancel(
        &mut self,
        id: &str,
        now: u64,
    ) -> Result<(BackupJob, Option<VerifiedBackupStaging>), crate::SdkError> {
        let row = self.transition(id, BackupJobState::Cancelled, now)?;
        let staging = self.entry_mut(id)?.staging.take();
        Ok((row, staging))
    }
    /// Takes verified staging for installation, rechecking expiry at the commit boundary.
    /// # Errors
    /// Refuses an expired or unverified restore; `expire` transfers expired staging for disposal.
    pub fn install(
        &mut self,
        id: &str,
        now: u64,
    ) -> Result<(BackupJob, VerifiedBackupStaging), crate::SdkError> {
        let entry = self.entry(id)?;
        if entry.row.state != BackupJobState::Verified {
            return Err(refused("invalid_job_phase"));
        }
        if entry.staging.as_ref().is_none_or(|stage| stage.expired(now)) {
            return Err(refused("staging_expired"));
        }
        let row = self.transition(id, BackupJobState::Installing, now)?;
        let staging =
            self.entry_mut(id)?.staging.take().ok_or_else(|| refused("staging_expired"))?;
        Ok((row, staging))
    }
    /// Marks expired verified jobs failed and returns staging for disposal outside any guard.
    pub fn expire(&mut self, now: u64) -> Vec<(BackupJob, VerifiedBackupStaging)> {
        let ids = self
            .entries
            .iter()
            .filter(|(_, entry)| {
                entry.row.state == BackupJobState::Verified
                    && entry.staging.as_ref().is_some_and(|stage| stage.expired(now))
            })
            .map(|(id, _)| id.clone())
            .collect::<Vec<_>>();
        let mut expired = Vec::new();
        for id in ids {
            if let Ok((row, Some(stage))) =
                self.fail(&id, BackupFailure::new(BackupFailureCode::StagingExpired), now)
            {
                expired.push((row, stage));
            }
        }
        expired
    }
    /// Records typed worker failure without retaining diagnostics or input secrets.
    /// # Errors
    /// Refuses terminal/unknown jobs or sequence overflow.
    pub fn fail(
        &mut self,
        id: &str,
        error: BackupFailure,
        now: u64,
    ) -> Result<(BackupJob, Option<VerifiedBackupStaging>), crate::SdkError> {
        if !self.entry(id)?.row.state.allows(BackupJobState::Failed) {
            return Err(refused("invalid_job_phase"));
        }
        let mut row = self.transition(id, BackupJobState::Failed, now)?;
        row.error = Some(error);
        let entry = self.entry_mut(id)?;
        entry.row = row.clone();
        Ok((row, entry.staging.take()))
    }
    /// Requests worker cancellation on daemon shutdown; no I/O is performed here.
    pub fn shutdown(&self) {
        for entry in self.entries.values() {
            entry.cancellation.store(true, Ordering::Release);
        }
    }
    fn entry(&self, id: &str) -> Result<&Entry, crate::SdkError> {
        self.entries.get(id).ok_or_else(|| refused("unknown_job"))
    }
    fn entry_mut(&mut self, id: &str) -> Result<&mut Entry, crate::SdkError> {
        self.entries.get_mut(id).ok_or_else(|| refused("unknown_job"))
    }
    fn prune(&mut self) {
        while self.entries.len() >= RECENT_JOBS {
            let oldest = self
                .entries
                .iter()
                .filter(|(_, entry)| entry.row.state.terminal() && entry.staging.is_none())
                .min_by_key(|(_, entry)| entry.order)
                .map(|(id, _)| id.clone());
            let Some(id) = oldest else { break };
            self.entries.remove(&id);
        }
    }
}

fn refused(reason: &str) -> crate::SdkError {
    crate::SdkError::LocalBusRefused {
        code: "BackupRefused".into(),
        message: reason.into(),
        body: Box::new(serde_json::json!({"reason_code":reason})),
    }
}

#[cfg(test)]
mod tests;
