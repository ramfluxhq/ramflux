// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Verify again after quiescing, prepare an encrypted generation, then commit its index pointer.
use super::{
    format,
    service::{BackupJobs, now, refused},
};
use crate::{
    SdkError,
    backup::{BackupJob, VerifiedBackupStaging},
};
use ramflux_storage::{
    AccountDbKey, AccountIndex, BackupCounts, BackupDatabase, FileVaultSecretSource,
    VaultSecretSource, unwrap_with_vault_secret,
};
use std::path::Path;
use zeroize::Zeroizing;

/// Unit tests model plain clients on a device with a vault (native data is device-bound).
#[cfg(test)]
pub(super) fn existing_key(
    index: &AccountIndex,
    root: &Path,
    id: &str,
    secret: &[u8],
) -> Result<AccountDbKey, SdkError> {
    if !FileVaultSecretSource::new(root).vault_secret_path(id).exists() {
        return Err(SdkError::AccountDbNotUnlocked);
    }
    let secret_key = Zeroizing::new(
        crate::client::device_unlock::test_device::PlainSource::new(root).vault_secret(id)?,
    );
    unwrap_local_key(index, id, &secret_key, secret)
}

/// Native accounts: the local code wrap is bound to the platform-held device secret.
pub(super) fn existing_device_key(
    index: &AccountIndex,
    root: &Path,
    id: &str,
    vault: &dyn crate::custody::PrimaryVault,
    secret: &[u8],
) -> Result<AccountDbKey, SdkError> {
    use crate::client::device_unlock::{DeviceBoundVaultSecret, DeviceSecret};
    if !FileVaultSecretSource::new(root).vault_secret_path(id).exists() {
        return Err(SdkError::AccountDbNotUnlocked);
    }
    let source = DeviceBoundVaultSecret::bind(root, vault, id, DeviceSecret::Load)?;
    let secret_key = Zeroizing::new(source.vault_secret(id)?);
    unwrap_local_key(index, id, &secret_key, secret)
}

fn unwrap_local_key(
    index: &AccountIndex,
    id: &str,
    secret_key: &[u8; 32],
    secret: &[u8],
) -> Result<AccountDbKey, SdkError> {
    let wrapping =
        Zeroizing::new(crate::client::account::account_db_key_encryption_key(secret_key, secret)?);
    unwrap_with_vault_secret(
        &wrapping,
        &index.load_wrapped_db_key(id)?.ok_or(SdkError::AccountDbNotUnlocked)?,
    )
    .map_err(|error| match error {
        // This authenticates the local key, not the backup archive.
        ramflux_storage::StorageError::Integrity(_) => refused("unreadable"),
        error => error.into(),
    })
}
impl BackupJobs {
    pub(crate) fn install_account(&self, id: &str) -> Result<String, SdkError> {
        let state = self.state.lock().map_err(|_| refused("interrupted"))?;
        state
            .registry
            .job(id)?
            .archive
            .as_ref()
            .map(|archive| archive.local_account_id.clone())
            .ok_or_else(|| refused("invalid_job_phase"))
    }
    pub(crate) fn begin_install(
        &self,
        id: &str,
    ) -> Result<(BackupJob, VerifiedBackupStaging), SdkError> {
        let mut state = self.state.lock().map_err(|_| refused("interrupted"))?;
        if state.cancelling.contains(id) {
            return Err(refused("interrupted"));
        }
        let (row, staging) = state.registry.install(id, now())?;
        state.head += 1;
        let seq = state.head;
        state.events.push_back((seq, row.clone()));
        Ok((row, staging))
    }
    pub(crate) fn install_generation(
        &self,
        job: &BackupJob,
        staging: VerifiedBackupStaging,
        native_key: Option<super::NativeInstallKey>,
        native_setup: Option<super::NativeRestoreSetup>,
    ) -> Result<(crate::backup::BackupInstalledAccount, BackupCounts, BackupCounts), SdkError> {
        let metadata =
            format::load_metadata(&staging.directory().join("identity.sealed"), staging.key())?;
        validate_staged_observation(&staging, &metadata)?;
        // The staging is owned here: it is discarded when this call ends, success or refusal.
        let installed = self.install_native(job, &staging, &metadata, (native_key, native_setup));
        drop(staging);
        installed
    }
}

impl BackupJobs {
    pub(super) fn cleanup_committed_generations(&self) {
        if super::recovery::recover_generations(&self.data_root, &self.index, &self.generations)
            .is_err()
        {
            tracing::warn!(
                "committed generation cleanup deferred until restart or the next install"
            );
        }
    }
    pub(super) fn verify_install_contribution(
        &self,
        job: &BackupJob,
        db: &BackupDatabase,
        incoming: &Path,
        key: &AccountDbKey,
        merge: bool,
    ) -> Result<(), SdkError> {
        let files = if merge {
            db.verify_archive_contribution(incoming, key, |_, _| Ok(()))?
        } else {
            db.verify_attachments(|_, _| Ok(()))?
        };
        if files.missing != files.unavailable_at_source || files.mismatched != 0 {
            return Err(refused("attachment_mismatch"));
        }
        self.change(|registry| {
            registry.attachment_checks(
                &job.job_id,
                crate::backup::BackupAttachmentChecks {
                    verified: files.verified,
                    placeholders_checked: files.placeholders_checked,
                    mismatched: files.mismatched,
                    missing: files.missing,
                    unavailable_at_source: files.unavailable_at_source,
                    local_missing_kept: files.local_missing_kept,
                },
            )
        })?;
        Ok(())
    }
}

fn validate_staged_observation(
    staging: &VerifiedBackupStaging,
    metadata: &format::Metadata,
) -> Result<(), SdkError> {
    let original =
        staging.input_observation().ok_or(ramflux_storage::StorageError::AuthorizationRejected)?;
    let db = open_stage(
        &staging.directory().join("account.db"),
        &AccountDbKey::from_bytes(metadata.database_key),
        None,
    )?;
    if db.original_input() != original {
        return Err(ramflux_storage::StorageError::AuthorizationRejected.into());
    }
    Ok(())
}

pub(super) fn relative(root: &Path, path: &Path) -> Result<String, SdkError> {
    path.strip_prefix(root)
        .map_err(|_| refused("root_conflict"))?
        .to_str()
        .map(str::to_owned)
        .ok_or_else(|| refused("unreadable"))
}

fn open_stage(
    path: &Path,
    key: &AccountDbKey,
    original: Option<&ramflux_storage::BackupInputObservation>,
) -> Result<BackupDatabase, ramflux_storage::StorageError> {
    #[cfg(test)]
    super::tests::selector_normalization_tests::record_open("stage");
    let db = BackupDatabase::open_restore_input(
        path,
        key,
        ramflux_storage::BackupOpenMode::PreNormalization,
    )?;
    Ok(if let Some(original) = original { db.retain_original_input(original) } else { db })
}

pub(super) fn open_live_stage(
    path: &Path,
    key: &AccountDbKey,
) -> Result<BackupDatabase, ramflux_storage::StorageError> {
    #[cfg(test)]
    super::tests::selector_normalization_tests::record_open("stage");
    BackupDatabase::open_live_restore_input(path, key)
}
