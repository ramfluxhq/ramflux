// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Secret-free whole-row job projection shared by bus replies, events and polling.

use ramflux_storage::BackupCounts;
use serde::{Deserialize, Serialize};

pub const BACKUP_JOB_TOPIC: &str = "account.backup.job.changed";
pub const BACKUP_JOB_METHODS: [&str; 5] = [
    "account.backup.create",
    "account.restore.verify",
    "account.restore.install",
    "account.backup.cancel",
    "account.backup.jobs",
];

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackupJobKind {
    Backup,
    Restore,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackupJobState {
    Preparing,
    Writing,
    Verifying,
    Verified,
    Installing,
    Done,
    Failed,
    Cancelled,
}
impl BackupJobState {
    #[must_use]
    pub const fn terminal(self) -> bool {
        matches!(self, Self::Done | Self::Failed | Self::Cancelled)
    }
    pub(super) const fn allows(self, next: Self) -> bool {
        use BackupJobState::{
            Cancelled, Done, Failed, Installing, Preparing, Verified, Verifying, Writing,
        };
        matches!(
            (self, next),
            (Preparing, Writing | Failed | Cancelled)
                | (Writing, Done | Failed | Cancelled)
                | (Verifying, Verified | Failed | Cancelled)
                | (Verified, Installing | Failed | Cancelled)
                | (Installing, Done | Failed)
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackupCategory {
    Identity,
    Contacts,
    Conversations,
    Messages,
    Groups,
    Surfaces,
    Tasks,
    Settings,
    Attachments,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BackupProgress {
    pub category: BackupCategory,
    pub items_done: u64,
    pub items_total: Option<u64>,
    pub bytes_done: u64,
    pub bytes_total: Option<u64>,
}
impl Default for BackupProgress {
    fn default() -> Self {
        Self {
            category: BackupCategory::Identity,
            items_done: 0,
            items_total: None,
            bytes_done: 0,
            bytes_total: None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BackupArchivePreview {
    pub local_account_id: String,
    pub account_label: Option<String>,
    pub created_at: u64,
    pub merge: bool,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct BackupAttachmentChecks {
    pub verified: u64,
    pub mismatched: u64,
    pub missing: u64,
    #[serde(default)]
    pub unavailable_at_source: u64,
    #[serde(default)]
    pub local_missing_kept: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackupFailureCode {
    WrongPassphrase,
    NetworkingPending,
    Tampered,
    Truncated,
    UnsupportedVersion,
    InsufficientSpace,
    Unreadable,
    NotWritable,
    StagingExpired,
    Interrupted,
    AttachmentMismatch,
    AttachmentsUnavailable,
    IdentityRollback,
    RootConflict,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BackupFailure {
    pub code: BackupFailureCode,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub needed_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub available_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unavailable_attachments: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unavailable_count: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unavailable_next_cursor: Option<String>,
}
impl BackupFailure {
    #[must_use]
    pub const fn new(code: BackupFailureCode) -> Self {
        Self {
            code,
            needed_bytes: None,
            available_bytes: None,
            unavailable_attachments: Vec::new(),
            unavailable_count: None,
            unavailable_next_cursor: None,
        }
    }
}

/// No request body, passphrase, private root material or staging key belongs in this row.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BackupJob {
    pub job_id: String,
    pub kind: BackupJobKind,
    pub state: BackupJobState,
    pub seq: u64,
    pub path: String,
    pub created_at: u64,
    pub finished_at: Option<u64>,
    pub progress: BackupProgress,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub counts: Option<BackupCounts>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub archive_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub archive: Option<BackupArchivePreview>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub restored: Option<BackupCounts>,
    /// Newer local values retained, per category rather than a scalar total.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kept_newer: Option<BackupCounts>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attachments: Option<BackupAttachmentChecks>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<BackupFailure>,
}
