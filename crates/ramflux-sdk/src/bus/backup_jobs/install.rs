// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Verify again after quiescing, prepare an encrypted generation, then commit its index pointer.
use super::{
    format,
    io::{PrivateDirectory, check_space},
    service::{BackupJobs, now, refused},
};
use crate::{
    SdkError,
    backup::{BackupJob, VerifiedBackupStaging},
};
use ramflux_storage::{
    AccountDbKey, AccountIndex, BackupCounts, BackupDatabase, BackupIndexInstall,
    FileVaultSecretSource, VaultSecretSource, WrappedAccountDbKey, unwrap_with_vault_secret,
    wrap_with_vault_secret,
};
use std::path::Path;
use zeroize::Zeroizing;

pub(super) fn existing_key(
    index: &AccountIndex,
    root: &Path,
    id: &str,
    secret: &[u8],
) -> Result<AccountDbKey, SdkError> {
    let vault = FileVaultSecretSource::new(root);
    if !vault.vault_secret_path(id).exists() {
        return Err(SdkError::AccountDbNotUnlocked);
    }
    let secret_key = Zeroizing::new(vault.vault_secret(id)?);
    let wrapping =
        Zeroizing::new(crate::client::account::account_db_key_encryption_key(&secret_key, secret));
    Ok(unwrap_with_vault_secret(
        &wrapping,
        &index.load_wrapped_db_key(id)?.ok_or(SdkError::AccountDbNotUnlocked)?,
    )?)
}
impl BackupJobs {
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
    ) -> Result<(String, BackupCounts, BackupCounts), SdkError> {
        let mut metadata =
            format::load_metadata(&staging.directory().join("identity.sealed"), staging.key())?;
        let id = metadata.manifest.local_account_id.clone();
        let incoming = staging.directory().join("account.db");
        let incoming_key = AccountDbKey::from_bytes(metadata.database_key);
        self.check_existing_identity(&metadata, &incoming, &incoming_key).map_err(|failure| {
            SdkError::LocalBusRefused {
                code: "BackupRefused".into(),
                message: "restore identity check failed".into(),
                body: Box::new(serde_json::json!({"reason_code":failure.code,"failure":failure})),
            }
        })?;
        let previous = match self.index.account(&id) {
            Ok(record) => Some(record),
            Err(ramflux_storage::StorageError::AccountNotFound(_)) => None,
            Err(error) => return Err(error.into()),
        };
        let parent = self.data_root.join("accounts").join(&id);
        std::fs::create_dir_all(&parent)?;
        crate::bus::daemon::set_owner_only_dir_permissions(&parent)?;
        check_space(
            &parent,
            staging
                .directory()
                .join("account.db")
                .metadata()?
                .len()
                .saturating_mul(2)
                .saturating_add(20 * 1024 * 1024),
        )
        .map_err(|failure| SdkError::LocalBusRefused {
            code: "BackupRefused".into(),
            message: "restore requires more space".into(),
            body: Box::new(
                serde_json::json!({"reason_code":"insufficient_space","failure":failure}),
            ),
        })?;
        let generation = parent.join(format!("generation_{}", job.job_id));
        std::fs::create_dir(&generation)?;
        crate::bus::daemon::set_owner_only_dir_permissions(&generation)?;
        let mut guard = PrivateDirectory { path: generation.clone(), transferred: false };
        let target = generation.join("account.db");
        let installed_key = AccountDbKey::generate()?;
        let (restored, kept_newer) = if let Some(record) = previous.as_ref() {
            let local = crate::bus::daemon::read_local_bus_account_manifest(
                &crate::bus::daemon::local_bus_account_manifest_path(&self.data_root, &id),
            )?;
            let key =
                existing_key(&self.index, &self.data_root, &id, local.account_secret.as_bytes())?;
            BackupDatabase::open(&self.data_root.join(&record.db_relative_path), &key)?
                .copy_to(&target, &installed_key)?;
            let mut merged = BackupDatabase::open(&target, &installed_key)?;
            let report = merged.merge_backup(&incoming, &incoming_key, || Ok(()))?;
            metadata.manifest = local;
            (report.restored, report.kept_newer)
        } else {
            prepare_fresh_restore(&incoming, &incoming_key, &target, &installed_key, &mut metadata)?
        };
        let db = BackupDatabase::open(&target, &installed_key)?;
        db.check_integrity()?;
        db.enqueue_restore_events(&id, &job.job_id)?;
        let files = db.verify_attachments(|_, _| Ok(()))?;
        if files.missing != 0 || files.mismatched != 0 {
            return Err(refused("attachment_mismatch"));
        }
        drop(db);
        let ca = generation.join("ca.pem");
        std::fs::write(&ca, &metadata.ca_pem)?;
        std::fs::File::open(&ca)?.sync_all()?;
        metadata.manifest.gateway.ca_cert = ca;
        let vault = FileVaultSecretSource::new(&self.data_root);
        let secret = Zeroizing::new(vault.vault_secret(&id)?);
        let kek = Zeroizing::new(crate::client::account::account_db_key_encryption_key(
            &secret,
            metadata.manifest.account_secret.as_bytes(),
        ));
        let (nonce, wrapped_key) = wrap_with_vault_secret(&kek, installed_key.bytes())?;
        let wrapped = WrappedAccountDbKey {
            key_wrapping_provider: "platform-local-vault".into(),
            key_wrapping_ref: format!("platform-local-vault:{id}"),
            nonce,
            wrapped_key,
        };
        let manifest = Zeroizing::new(serde_json::to_vec(&metadata.manifest)?);
        std::fs::File::open(&target)?.sync_all()?;
        std::fs::File::open(&generation)?.sync_all()?;
        std::fs::File::open(&parent)?.sync_all()?;
        self.index.install_backup_generation(&BackupIndexInstall {
            account_id: &id,
            principal_commitment: &metadata.manifest.principal_commitment,
            db_relative_path: &relative(&self.data_root, &target)?,
            object_relative_path: &relative(&self.data_root, &generation)?,
            manifest_json: &manifest,
            wrapped_key: &wrapped,
        })?;
        guard.transferred = true;
        drop(staging);
        Ok((id, restored, kept_newer))
    }
}

fn prepare_fresh_restore(
    incoming: &Path,
    incoming_key: &AccountDbKey,
    target: &Path,
    installed_key: &AccountDbKey,
    metadata: &mut format::Metadata,
) -> Result<(BackupCounts, BackupCounts), SdkError> {
    let source = BackupDatabase::open(incoming, incoming_key)?;
    source.copy_to(target, installed_key)?;
    let db = BackupDatabase::open(target, installed_key)?;
    db.archive_outbound()?;
    db.put_state("backup/reestablishing", &true)?;
    db.put_state("backup/fresh-outbound", &true)?;
    metadata.manifest.activation_pending = true;
    let previous = metadata
        .manifest
        .devices
        .iter()
        .find(|device| device.device_id == metadata.manifest.device_id)
        .map_or(1, |device| device.device_epoch);
    db.put_state("backup/previous-device-epoch", &previous)?;
    let next = previous.checked_add(1).ok_or_else(|| refused("identity_rollback"))?;
    if let Some(device) = metadata
        .manifest
        .devices
        .iter_mut()
        .find(|device| device.device_id == metadata.manifest.device_id)
    {
        device.device_epoch = next;
    } else {
        metadata.manifest.devices.push(crate::LocalBusDeviceRecord {
            device_id: metadata.manifest.device_id.clone(),
            device_epoch: next,
            target_delivery_id: metadata.manifest.target_delivery_id.clone(),
            capability_scope: Vec::new(),
            is_local: true,
        });
    }
    Ok((db.counts()?, BackupCounts::default()))
}

fn relative(root: &Path, path: &Path) -> Result<String, SdkError> {
    path.strip_prefix(root)
        .map_err(|_| refused("root_conflict"))?
        .to_str()
        .map(str::to_owned)
        .ok_or_else(|| refused("unreadable"))
}
