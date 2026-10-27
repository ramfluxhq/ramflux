// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Crash cleanup uses only secret-free ownership markers and the committed generation pointer.
use crate::SdkError;
use ramflux_storage::AccountIndex;
use std::{io::Write, os::unix::fs::OpenOptionsExt, path::Path};
pub(super) const INSTALL_MARKER: &str = ".backup-installing";
const OUTPUT_MARKER: &str = "output-partial.json";
pub(super) fn remember_partial_output(stage: &Path, path: &Path) -> Result<(), SdkError> {
    let mut file = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(stage.join(OUTPUT_MARKER))?;
    file.write_all(&serde_json::to_vec(path)?)?;
    file.sync_all()?;
    std::fs::File::open(stage)?.sync_all()?;
    Ok(())
}
pub(super) fn mark_install(generation: &Path) -> Result<(), SdkError> {
    let file = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(generation.join(INSTALL_MARKER))?;
    file.sync_all()?;
    std::fs::File::open(generation)?.sync_all()?;
    Ok(())
}
pub(super) fn selected(generation: &Path) {
    // Selection is already committed. A failed unlink is retried on restart, never a failed restore.
    if let Err(error) = std::fs::remove_file(generation.join(INSTALL_MARKER)) {
        tracing::debug!(%error,"selected backup generation marker cleanup deferred");
    }
}
#[cfg(test)]
pub(super) fn recover(root: &Path, data_root: &Path, index: &AccountIndex) -> Result<(), SdkError> {
    recover_with_locks(root, data_root, index, &super::generation_lock::GenerationLocks::default())
}
pub(super) fn recover_with_locks(
    root: &Path,
    data_root: &Path,
    index: &AccountIndex,
    locks: &super::generation_lock::GenerationLocks,
) -> Result<(), SdkError> {
    recover_jobs_excluding(root, &std::collections::BTreeSet::new())?;
    recover_generations(data_root, index, locks)
}
pub(super) fn recover_jobs_excluding(
    root: &Path,
    protected: &std::collections::BTreeSet<String>,
) -> Result<(), SdkError> {
    for entry in std::fs::read_dir(root)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if protected.contains(name.as_ref()) {
            continue;
        }
        let Some(id) = name.strip_prefix("job_") else { continue };
        let path = entry.path();
        if entry.file_type()?.is_symlink() {
            std::fs::remove_file(path)?;
            continue;
        }
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let marker = path.join(OUTPUT_MARKER);
        if let Ok(metadata) = std::fs::symlink_metadata(&marker)
            && metadata.file_type().is_file()
            && metadata.len() <= 32 * 1024
            && let Ok(partial) =
                serde_json::from_slice::<std::path::PathBuf>(&std::fs::read(&marker)?)
            && partial
                .file_name()
                .is_some_and(|name| name == format!(".ramflux-backup-{id}.partial").as_str())
        {
            match std::fs::remove_file(partial) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
        }
        super::output_ownership::recover(&path)?;
        std::fs::remove_dir_all(path)?;
    }
    Ok(())
}
pub(super) fn recover_generations(
    data_root: &Path,
    index: &AccountIndex,
    locks: &super::generation_lock::GenerationLocks,
) -> Result<(), SdkError> {
    let accounts = data_root.join("accounts");
    if !accounts.exists() {
        return Ok(());
    }
    for account in std::fs::read_dir(accounts)? {
        let account = account?;
        if !account.file_type()?.is_dir() {
            continue;
        }
        let name = account.file_name();
        let Some(id) = name.to_str() else { continue };
        let Some(_lease) = locks.try_acquire(id)? else { continue };
        let _writer = match index.acquire_account_writer(id) {
            Ok(writer) => writer,
            Err(ramflux_storage::StorageError::AccountWriterBusy(_)) => continue,
            Err(error) => return Err(error.into()),
        };
        let selected = match index.account(id) {
            Ok(row) => Some(data_root.join(row.db_relative_path)),
            Err(ramflux_storage::StorageError::AccountNotFound(_)) => None,
            Err(error) => return Err(error.into()),
        };
        for generation in std::fs::read_dir(account.path())? {
            let generation = generation?;
            if !generation.file_type()?.is_dir()
                || !generation.file_name().to_string_lossy().starts_with("generation_")
            {
                continue;
            }
            let path = generation.path();
            if selected.as_deref().and_then(Path::parent) == Some(path.as_path()) {
                super::reclamation::complete(&path, data_root, index, id)?;
            }
            let marker = path.join(INSTALL_MARKER);
            if !std::fs::symlink_metadata(&marker).is_ok_and(|m| m.file_type().is_file()) {
                continue;
            }
            if selected.as_deref().and_then(Path::parent) == Some(path.as_path()) {
                std::fs::remove_file(marker)?;
            } else {
                std::fs::remove_dir_all(path)?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn restart_discards_abandoned_encrypted_work_and_partial_output_but_preserves_selected_and_unmarked_data()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = std::env::temp_dir().join(format!(
            "rf-backup-recovery-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_nanos()
        ));
        let index = AccountIndex::open(&root)?;
        index.create_account("alice", "root")?;
        let jobs = root.join("backup_jobs");
        let stage = jobs.join("job_crash");
        std::fs::create_dir_all(&stage)?;
        let partial = root.join(".ramflux-backup-crash.partial");
        std::fs::write(&partial, b"encrypted prefix")?;
        remember_partial_output(&stage, &partial)?;
        let complete = root.join("keep.rfb");
        std::fs::write(&complete, b"complete archive")?;
        let wrong = jobs.join("job_wrong");
        std::fs::create_dir_all(&wrong)?;
        remember_partial_output(&wrong, &complete)?;
        let parent = root.join("accounts/alice");
        let chosen = parent.join("generation_chosen");
        let orphan = parent.join("generation_orphan");
        let older = parent.join("generation_older");
        for path in [&chosen, &orphan, &older] {
            std::fs::create_dir_all(path)?;
            std::fs::write(path.join("account.db"), b"encrypted database")?;
        }
        mark_install(&chosen)?;
        mark_install(&orphan)?;
        let wrapped = ramflux_storage::WrappedAccountDbKey {
            key_wrapping_provider: "test".into(),
            key_wrapping_ref: "test".into(),
            nonce: [1; 12],
            wrapped_key: vec![2; 48],
        };
        index.install_backup_generation(&ramflux_storage::BackupIndexInstall {
            account_id: "alice",
            principal_commitment: "root",
            db_relative_path: "accounts/alice/generation_chosen/account.db",
            object_relative_path: "accounts/alice/generation_chosen",
            manifest_json: b"{}",
            wrapped_key: &wrapped,
        })?;
        recover(&jobs, &root, &index)?;
        assert!(!partial.exists());
        assert!(!stage.exists());
        assert!(!wrong.exists());
        assert!(!orphan.exists());
        assert!(chosen.join("account.db").exists());
        assert!(!chosen.join(INSTALL_MARKER).exists());
        assert!(older.join("account.db").exists());
        assert_eq!(std::fs::read(complete)?, b"complete archive");
        drop(index);
        std::fs::remove_dir_all(root)?;
        Ok(())
    }
}

#[cfg(test)]
mod reclamation_tests {
    use super::*;
    #[test]
    fn r2_restart_reclaims_only_a_committed_replacement_after_a_crash()
    -> Result<(), Box<dyn std::error::Error>> {
        for committed in [false, true] {
            let root = crate::bus::runtime_tests::root(if committed {
                "reclaim-committed"
            } else {
                "reclaim-uncommitted"
            });
            let index = AccountIndex::open(&root)?;
            let row = index.create_account("alice", "root")?;
            let old = root.join(&row.db_relative_path);
            std::fs::create_dir_all(old.parent().ok_or("parent")?)?;
            std::fs::write(&old, b"old encrypted database")?;
            let generation = root.join("accounts/alice/generation_new");
            std::fs::create_dir_all(&generation)?;
            std::fs::write(generation.join("account.db"), b"new encrypted database")?;
            mark_install(&generation)?;
            std::fs::write(
                generation.join(".backup-replaced.json"),
                serde_json::to_vec(&row.db_relative_path)?,
            )?;
            let jobs = root.join("backup_jobs");
            std::fs::create_dir(&jobs)?;
            if committed {
                index.install_backup_generation(&ramflux_storage::BackupIndexInstall {
                    account_id: "alice",
                    principal_commitment: "root",
                    db_relative_path: "accounts/alice/generation_new/account.db",
                    object_relative_path: "accounts/alice/generation_new",
                    manifest_json: b"{}",
                    wrapped_key: &ramflux_storage::WrappedAccountDbKey {
                        key_wrapping_provider: "test".into(),
                        key_wrapping_ref: "test".into(),
                        nonce: [1; 12],
                        wrapped_key: vec![2; 48],
                    },
                })?;
            }
            recover(&jobs, &root, &index)?;
            assert_eq!(
                old.exists(),
                !committed,
                "only a durable replacement authorizes old-data deletion"
            );
            assert_eq!(generation.exists(), committed);
            drop(index);
            std::fs::remove_dir_all(root)?;
        }
        Ok(())
    }
}
