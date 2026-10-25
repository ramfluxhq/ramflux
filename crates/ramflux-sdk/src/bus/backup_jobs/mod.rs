// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Daemon-owned background backup jobs with account-ordered snapshot capture.
mod attachments;
mod format;
mod install;
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
