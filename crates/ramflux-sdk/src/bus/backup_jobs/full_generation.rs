// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Pairing uses the existing backup generation lease, directory and crash markers.
use super::{
    generation_lock::{GenerationLease, GenerationLocks},
    io::PrivateDirectory,
};
use crate::SdkError;
use ramflux_storage::{AccountIndex, AccountWriterLease, LocalAccountRecord};
use std::path::{Path, PathBuf};

pub(crate) struct FullGenerationDirectory {
    guard: PrivateDirectory,
    index: AccountIndex,
    root: PathBuf,
    account: String,
    _lease: GenerationLease,
    _writer: AccountWriterLease,
}
impl FullGenerationDirectory {
    pub(crate) fn begin(root: &Path, account: &str) -> Result<Self, SdkError> {
        let id = Path::new(account);
        if account.is_empty()
            || account.contains('/')
            || account.as_bytes().contains(&92)
            || account.chars().any(char::is_control)
            || id.components().count() != 1
            || id.components().any(|part| !matches!(part, std::path::Component::Normal(_)))
        {
            return Err(SdkError::PairingCode("WrongContext"));
        }
        let root = std::fs::canonicalize(root)?;
        let index = AccountIndex::open(&root)?;
        let writer = index.acquire_account_writer(account)?;
        let locks = GenerationLocks::for_root(&root)?;
        let lease = locks.try_acquire(account)?.ok_or(SdkError::PairingCode("Busy"))?;
        let parent = root.join("accounts").join(account);
        if std::fs::canonicalize(&parent)? != parent {
            return Err(SdkError::PairingCode("WrongContext"));
        }
        let path = parent.join(format!(
            "generation_{}",
            ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?)
        ));
        crate::platform::fs::create_owner_only_dir(&path)?;
        let guard = PrivateDirectory { path, transferred: false };
        super::recovery::mark_install(&guard.path)?;
        std::fs::File::open(&parent)?.sync_all()?;
        Ok(Self { guard, index, root, account: account.into(), _lease: lease, _writer: writer })
    }
    pub(crate) fn path(&self) -> &Path {
        &self.guard.path
    }
    pub(crate) fn relative(&self, path: &Path) -> Result<String, SdkError> {
        path.strip_prefix(&self.root)
            .ok()
            .and_then(Path::to_str)
            .map(str::to_owned)
            .ok_or(SdkError::PairingCode("WrongContext"))
    }
    pub(crate) fn remember_prior(&self, prior: &LocalAccountRecord) -> Result<(), SdkError> {
        super::reclamation::remember(&self.guard.path, Some(prior))
    }
    pub(crate) fn discard_unselected(
        &self,
        install: &crate::custody::pairing::install_store::Install,
    ) -> Result<(), SdkError> {
        let full =
            install.full_transfer.as_ref().ok_or(SdkError::PairingCode("PublicationPending"))?;
        let selected = self.index.account(&self.account)?;
        if selected.db_relative_path != full.expected_prior_generation.db_relative_path
            || selected.object_dir_relative_path
                != full.expected_prior_generation.object_relative_path
            || self.root.join(&selected.db_relative_path).parent()
                == Some(self.guard.path.as_path())
        {
            return Err(SdkError::PairingCode("PublicationPending"));
        }
        let pending = crate::custody::pairing::install_store::read_pending(
            &self.root,
            &self.account,
            &install.operation_id,
        )?;
        if pending.as_ref() != Some(install) {
            return Err(SdkError::PairingCode("PublicationPending"));
        }
        // Keep the possible-publication fence and original vault owners. Only the
        // positively unselected G1 directory is abandoned, never the pairing intent.
        let mut retained = install.clone();
        retained.schema = "ramflux.pairing.Install.v2".into();
        retained.version = 2;
        retained.full_transfer = None;
        retained.state = "vault_durable".into();
        crate::custody::pairing::install_store::write_pending(&self.root, &retained)
    }
    pub(crate) fn finish_g3(&mut self) -> Result<(), SdkError> {
        self.guard.transferred = true;
        if super::reclamation::complete(&self.guard.path, &self.root, &self.index, &self.account)? {
            match std::fs::remove_file(self.guard.path.join(super::recovery::INSTALL_MARKER)) {
                Ok(()) => std::fs::File::open(&self.guard.path)?.sync_all()?,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
        }
        Ok(())
    }
}
impl Drop for FullGenerationDirectory {
    fn drop(&mut self) {
        // Query possible G2 outcomes; an unreadable owner or retained pending full
        // install is never permission to delete a possibly required generation.
        let selected = self.index.account(&self.account).map_or(true, |row| {
            self.root.join(row.db_relative_path).parent() == Some(self.guard.path.as_path())
        });
        let retained =
            protect_pending_full(&self.root, &self.account, &self.guard.path).unwrap_or(true);
        self.guard.transferred |= selected || retained;
    }
}
pub(super) fn protect_pending_full(
    root: &Path,
    id: &str,
    generation: &Path,
) -> Result<bool, SdkError> {
    Ok(crate::custody::pairing::install_store::list_pending(root, id)?.iter().any(|row| {
        row.full_transfer
            .as_ref()
            .is_some_and(|full| root.join(&full.db_relative_path).parent() == Some(generation))
    }))
}

#[cfg(test)]
mod tests;
