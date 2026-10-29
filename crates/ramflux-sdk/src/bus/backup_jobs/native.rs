// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Data-only native archives: public identity is evidence, never installation authority.
use super::{
    format::{Identity, Metadata},
    install::relative,
    io::{PrivateDirectory, check_space},
    service::{BackupJobs, refused},
};
use crate::{
    RamfluxClient, SdkError,
    backup::{BackupJob, VerifiedBackupStaging},
};
use ramflux_storage::{AccountDbKey, BackupCounts, BackupDatabase, BackupIndexInstall};
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::bus) struct DataIdentity {
    pub schema: String,
    pub local_account_id: String,
    pub authority: ramflux_protocol::custody::CustodyAuthority,
}
impl DataIdentity {
    pub(super) fn anchor(&self) -> &str {
        &self.authority.publication.record.body.account_anchor
    }
    pub(super) fn validate(&self, account: &str) -> Result<(), SdkError> {
        let id = Path::new(&self.local_account_id);
        if self.schema != "ramflux.backup.native_data.v1"
            || self.local_account_id != account
            || id.components().count() != 1
            || id.components().any(|part| !matches!(part, std::path::Component::Normal(_)))
        {
            return Err(refused("root_conflict"));
        }
        ramflux_crypto::custody::verify_publication(
            &self.authority,
            crate::custody::network_now()?,
        )?;
        Ok(())
    }
}

pub(in crate::bus) fn capture_identity(
    client: &RamfluxClient,
    root: &Path,
    id: &str,
) -> Result<Identity, SdkError> {
    if let Some(native) = &client.born_v3_account {
        let native = DataIdentity {
            schema: "ramflux.backup.native_data.v1".into(),
            local_account_id: id.into(),
            authority: ramflux_protocol::custody::CustodyAuthority {
                publication: native.publication(),
                custodian_publication: native
                    .custodian_publication(root, crate::custody::network_now()?)?,
            },
        };
        native.validate(id)?;
        return Ok(Identity::Native { native: Box::new(native) });
    }
    Ok(Identity::Legacy {
        manifest: Box::new(crate::bus::daemon::read_local_bus_account_manifest(
            &crate::bus::daemon::local_bus_account_manifest_path(root, id),
        )?),
    })
}

impl BackupJobs {
    pub(super) fn native_restore_target(
        &self,
        native: &DataIdentity,
    ) -> Result<Option<String>, SdkError> {
        native.validate(&native.local_account_id)?;
        let mut target = None;
        for id in self.index.known_account_ids()? {
            if self.index.account(&id)?.principal_commitment != native.anchor() {
                continue;
            }
            let own = crate::custody::load_data_account(
                &self.data_root,
                &id,
                crate::custody::network_now()?,
            )?;
            if own.record().body.account_anchor != native.anchor() || target.is_some() {
                return Err(refused("root_conflict"));
            }
            target = Some(id);
        }
        Ok(target)
    }

    fn install_target(
        &self,
        job: &BackupJob,
        native: &DataIdentity,
        local_key: Option<super::NativeInstallKey>,
        setup: Option<super::NativeRestoreSetup>,
    ) -> Result<(String, Option<super::NativeInstallKey>), SdkError> {
        // Resolve only independently installed authority, never the archive's local selector.
        let result = if let Some(id) = self.native_restore_target(native)? {
            if setup.is_some() {
                return Err(SdkError::CustodySetupInvalid);
            }
            (id, local_key)
        } else {
            let setup = setup.ok_or(SdkError::NetworkingPending)?;
            let id = job
                .archive
                .as_ref()
                .ok_or_else(|| refused("invalid_job_phase"))?
                .local_account_id
                .clone();
            crate::custody::pending_restore(
                &self.data_root,
                &id,
                &native.authority,
                setup.vault.as_ref(),
                setup.passphrase.as_bytes(),
                crate::custody::network_now()?,
            )?;
            let key = super::install::existing_key(
                &self.index,
                &self.data_root,
                &id,
                setup.passphrase.as_bytes(),
            )?;
            (id.clone(), Some(super::NativeInstallKey { account_id: id, key }))
        };
        Ok(result)
    }
    pub(super) fn install_native(
        &self,
        job: &BackupJob,
        staging: &VerifiedBackupStaging,
        metadata: &Metadata,
        local_key: Option<super::NativeInstallKey>,
        setup: Option<super::NativeRestoreSetup>,
    ) -> Result<(String, BackupCounts, BackupCounts), SdkError> {
        let Identity::Native { native } = &metadata.identity else {
            return Err(refused("root_conflict"));
        };
        let (id, local_key) = self.install_target(job, native, local_key, setup)?;
        let id = &id;
        let lease =
            self.generations.try_acquire(id)?.ok_or_else(|| refused("install_in_progress"))?;
        let prepared = local_key.ok_or(SdkError::AccountDbNotUnlocked)?;
        if prepared.account_id != *id {
            return Err(refused("root_conflict"));
        }
        let local_key = prepared.key;
        let previous = self.index.account(id)?;
        let incoming = staging.directory().join("account.db");
        let incoming_key = AccountDbKey::from_bytes(metadata.database_key);
        let source =
            BackupDatabase::open(&self.data_root.join(&previous.db_relative_path), &local_key)?;
        source.check_backup_pins(&incoming, &incoming_key)?;
        let parent = self.data_root.join("accounts").join(id);
        check_space(
            &parent,
            incoming.metadata()?.len().saturating_mul(2).saturating_add(20 * 1024 * 1024),
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
        super::recovery::mark_install(&generation)?;
        let target = generation.join("account.db");
        // Retain the independently wrapped live data key; no archive passphrase is used.
        source.copy_to(&target, &local_key)?;
        drop(source);
        let mut merged = BackupDatabase::open(&target, &local_key)?;
        let report = merged.merge_native_backup(&incoming, &incoming_key, || Ok(()))?;
        merged.check_integrity()?;
        merged.enqueue_restore_events(id, &job.job_id)?;
        self.verify_install_contribution(job, &merged, &incoming, &incoming_key, true)?;
        drop(merged);
        let wrapped = self.index.load_wrapped_db_key(id)?.ok_or(SdkError::AccountDbNotUnlocked)?;
        let marker = serde_json::to_vec(
            &serde_json::json!({"schema":"ramflux.local.native_data_generation.v1","local_account_id":id,"account_anchor":native.anchor()}),
        )?;
        std::fs::File::open(&target)?.sync_all()?;
        std::fs::File::open(&generation)?.sync_all()?;
        std::fs::File::open(&parent)?.sync_all()?;
        super::reclamation::remember(&generation, Some(&previous))?;
        self.index.install_backup_generation(&BackupIndexInstall {
            account_id: id,
            principal_commitment: native.anchor(),
            db_relative_path: &relative(&self.data_root, &target)?,
            object_relative_path: &relative(&self.data_root, &generation)?,
            manifest_json: &marker,
            wrapped_key: &wrapped,
        })?;
        guard.transferred = true;
        super::recovery::selected(&generation);
        drop(lease);
        self.cleanup_committed_generations();
        Ok((id.clone(), report.restored, report.kept_newer))
    }
}
