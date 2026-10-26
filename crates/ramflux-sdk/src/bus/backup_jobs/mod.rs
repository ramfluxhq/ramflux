// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Daemon-owned background backup jobs with account-ordered snapshot capture.
mod attachments;
mod format;
mod generation_lock;
mod install;
mod output_ownership;
mod publication;
mod reclamation;
mod recovery;
mod routing;
mod stream;
pub(super) use service::refused as refusal;
mod io;
mod service;
mod workers;

pub(super) use service::BackupJobs;
pub(super) struct CapturedAccount {
    pub reader: ramflux_storage::AccountDb,
    pub manifest: super::protocol::LocalBusPersistedAccount,
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod test_install;

pub(super) struct MissingAttachments {
    pub account_id: String,
    pub total: u64,
    pub selectors: Vec<String>,
}
