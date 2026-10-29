// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Daemon-owned background backup jobs with account-ordered snapshot capture.
mod attachments;
mod format;
mod generation_lock;
mod install;
mod native;
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

pub(super) use native::capture_identity;
pub(super) use service::BackupJobs;
pub(super) struct CapturedAccount {
    pub reader: ramflux_storage::AccountDb,
    pub identity: format::Identity,
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

#[cfg(test)]
mod native_tests;

pub(crate) struct NativeInstallKey {
    pub account_id: String,
    pub key: ramflux_storage::AccountDbKey,
}
pub(crate) struct NativeRestoreSetup {
    pub vault: std::sync::Arc<dyn crate::custody::PrimaryVault>,
    pub passphrase: zeroize::Zeroizing<String>,
}
