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
use ramflux_storage::{AccountDbKey, BackupCounts, BackupIndexInstall};
use serde::{Deserialize, Serialize};
use std::path::Path;

struct InstallTarget {
    id: String,
    local_key: Option<super::NativeInstallKey>,
    _writer: ramflux_storage::AccountWriterLease,
}

// Never format an underlying error: SQLite input errors can contain key-bearing SQL.
fn install_step<T, E: Into<SdkError>>(
    stage: &'static str,
    result: Result<T, E>,
) -> Result<T, SdkError> {
    result.map_err(Into::into).inspect_err(|error| {
        use ramflux_storage::StorageError;
        let (category, sqlite_code) = match error {
            SdkError::Storage(StorageError::Sqlite(error)) => {
                ("sqlite", error.sqlite_error().map_or(0, |code| code.extended_code))
            }
            SdkError::Storage(StorageError::Crypto(_)) => ("crypto", 0),
            SdkError::Storage(StorageError::Protocol(_)) => ("protocol", 0),
            SdkError::Storage(StorageError::Serde(_)) => ("serialization", 0),
            SdkError::Storage(StorageError::AuthorizationRejected) => ("authorization", 0),
            SdkError::Storage(_) => ("storage", 0),
            SdkError::Io(_) => ("io", 0),
            SdkError::LocalBusRefused { .. } => ("refused", 0),
            _ => ("sdk", 0),
        };
        tracing::warn!(stage, category, sqlite_code, "native backup installation failed");
    })
}

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
    ) -> Result<InstallTarget, SdkError> {
        // Resolve only independently installed authority, never the archive's local selector.
        let result = if let Some(id) = self.native_restore_target(native)? {
            if setup.is_some() {
                return Err(SdkError::CustodySetupInvalid);
            }
            let writer = self.index.acquire_account_writer(&id)?;
            InstallTarget { id, local_key, _writer: writer }
        } else {
            let setup = setup.ok_or(SdkError::RestoreSetupRequired)?;
            let id = job
                .archive
                .as_ref()
                .ok_or_else(|| refused("invalid_job_phase"))?
                .local_account_id
                .clone();
            let writer = self.index.acquire_account_writer(&id)?;
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
            InstallTarget {
                id: id.clone(),
                local_key: Some(super::NativeInstallKey { account_id: id, key }),
                _writer: writer,
            }
        };
        Ok(result)
    }
    fn native_generation_parent(
        &self,
        id: &str,
        incoming: &Path,
    ) -> Result<std::path::PathBuf, SdkError> {
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
        Ok(parent)
    }
    pub(super) fn install_native(
        &self,
        job: &BackupJob,
        staging: &VerifiedBackupStaging,
        metadata: &Metadata,
        options: (Option<super::NativeInstallKey>, Option<super::NativeRestoreSetup>),
    ) -> Result<(crate::backup::BackupInstalledAccount, BackupCounts, BackupCounts), SdkError> {
        let (local_key, setup) = options;
        let Identity::Native { native } = &metadata.identity else {
            return Err(refused("root_conflict"));
        };
        let InstallTarget { id, local_key, _writer } =
            install_step("target", self.install_target(job, native, local_key, setup))?;
        let id = &id;
        let networking =
            crate::custody::load_data_account(&self.data_root, id, crate::custody::network_now()?)?
                .state();
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
        let source = super::install::open_live_stage(
            &self.data_root.join(&previous.db_relative_path),
            &local_key,
        )?;
        install_step("pins", source.check_backup_pins(&incoming, &incoming_key))?;
        let parent = self.native_generation_parent(id, &incoming)?;
        let generation = parent.join(format!("generation_{}", job.job_id));
        std::fs::create_dir(&generation)?;
        crate::bus::daemon::set_owner_only_dir_permissions(&generation)?;
        let mut guard = PrivateDirectory { path: generation.clone(), transferred: false };
        super::recovery::mark_install(&generation)?;
        #[cfg(test)]
        self.install_checkpoint(super::test_install::InstallPoint::Prepared, &generation)?;
        let target = generation.join("account.db");
        // Retain the independently wrapped live data key; no archive passphrase is used.
        install_step("copy", source.copy_to(&target, &local_key))?;
        #[cfg(test)]
        super::tests::selector_normalization_tests::record_open("stage");
        let mut merged = source.reopen_restore_input(
            &target,
            &local_key,
            ramflux_storage::BackupOpenMode::PreNormalization,
        )?;
        let report = install_step(
            "merge",
            merged.merge_native_backup_candidate(&incoming, &incoming_key, || Ok(())),
        )?;
        merged = strict_candidate(&merged, &target, &local_key)?;
        install_step("integrity", merged.check_integrity())?;
        install_step("events", merged.enqueue_restore_events(id, &job.job_id))?;
        install_step(
            "contribution",
            self.verify_install_contribution(job, &merged, &incoming, &incoming_key, true),
        )?;
        drop(merged);
        drop(source);
        let wrapped = self.index.load_wrapped_db_key(id)?.ok_or(SdkError::AccountDbNotUnlocked)?;
        let marker = serde_json::to_vec(
            &serde_json::json!({"schema":"ramflux.local.native_data_generation.v1","local_account_id":id,"account_anchor":native.anchor()}),
        )?;
        std::fs::File::open(&target)?.sync_all()?;
        std::fs::File::open(&generation)?.sync_all()?;
        std::fs::File::open(&parent)?.sync_all()?;
        super::reclamation::remember(&generation, Some(&previous))?;
        #[cfg(test)]
        self.install_checkpoint(super::test_install::InstallPoint::BeforeCommit, &generation)?;
        self.index.install_backup_generation(&BackupIndexInstall {
            account_id: id,
            principal_commitment: native.anchor(),
            db_relative_path: &relative(&self.data_root, &target)?,
            object_relative_path: &relative(&self.data_root, &generation)?,
            manifest_json: &marker,
            wrapped_key: &wrapped,
        })?;
        guard.transferred = true;
        #[cfg(test)]
        self.install_checkpoint(super::test_install::InstallPoint::Committed, &generation)?;
        super::recovery::selected(&generation);
        drop(lease);
        self.cleanup_committed_generations();
        Ok((
            crate::backup::BackupInstalledAccount {
                local_account_id: id.clone(),
                networking: Some(networking),
            },
            report.restored,
            report.kept_newer,
        ))
    }
}

#[cfg(test)]
#[path = "native_writer_tests.rs"]
mod writer_tests;

fn strict_candidate(
    db: &ramflux_storage::BackupDatabase,
    path: &Path,
    key: &AccountDbKey,
) -> Result<ramflux_storage::BackupDatabase, SdkError> {
    #[cfg(test)]
    {
        super::tests::selector_normalization_tests::record_open("normalized");
        super::tests::selector_normalization_tests::record_open("strict");
    }
    Ok(db.reopen_restore_input(path, key, ramflux_storage::BackupOpenMode::Normalized)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_restore_setup_is_typed_and_does_not_persist_an_account()
    -> Result<(), Box<dyn std::error::Error>> {
        let source = crate::custody::tests::Root::new()?;
        let target = crate::custody::tests::Root::new()?;
        let vault = crate::custody::tests::TestVault::default();
        let account = crate::custody::tests::create(
            &source.0,
            "source",
            &vault,
            crate::custody::network_now()?,
        )?;
        let identity = DataIdentity {
            schema: "ramflux.backup.native_data.v1".into(),
            local_account_id: "source".into(),
            authority: ramflux_protocol::custody::CustodyAuthority {
                publication: account.publication(),
                custodian_publication: None,
            },
        };
        let index = ramflux_storage::AccountIndex::open(&target.0)?;
        let jobs = BackupJobs::new(&target.0, index.clone())?;
        let job = crate::backup::BackupJobRegistry::default().start(
            crate::backup::BackupJobKind::Restore,
            "archive.rfb".into(),
            1,
        )?;
        let error =
            jobs.install_target(&job, &identity, None, None).err().ok_or("missing refusal")?;
        assert!(matches!(error, SdkError::RestoreSetupRequired));
        assert_eq!(crate::bus::io::local_bus_error_code(&error), "restore_setup_required");
        assert!(error.to_string().contains("--new-passphrase-env"));
        assert_eq!(index.known_account_ids()?, Vec::<String>::new());
        assert!(!target.0.join("custody_accounts").exists());
        Ok(())
    }
}
