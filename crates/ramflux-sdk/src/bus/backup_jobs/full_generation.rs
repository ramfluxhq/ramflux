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
    pub(crate) fn recover_selected(
        root: &Path,
        install: &crate::custody::pairing::install_store::Install,
    ) -> Result<Self, SdkError> {
        install.validate()?;
        let root = std::fs::canonicalize(root)?;
        let index = AccountIndex::open(&root)?;
        let account = install.account_id.clone();
        let full =
            install.full_transfer.as_ref().ok_or(SdkError::PairingCode("PublicationPending"))?;
        let selected = index.account(&account)?;
        let database = root.join(&full.db_relative_path);
        let path = database.parent().ok_or(SdkError::PairingCode("PublicationPending"))?.to_owned();
        let nonce = path
            .file_name()
            .and_then(|value| value.to_str())
            .and_then(|value| value.strip_prefix("generation_"))
            .ok_or(SdkError::PairingCode("PublicationPending"))?;
        if ramflux_protocol::decode_base64url(nonce)
            .map_err(|_| SdkError::PairingCode("PublicationPending"))?
            .len()
            != 32
            || path.parent() != Some(root.join("accounts").join(&account).as_path())
            || std::fs::canonicalize(&path)? != path
            || std::fs::canonicalize(&database)? != database
            || database.file_name().and_then(|value| value.to_str()) != Some("account.db")
            || selected.db_relative_path != full.db_relative_path
            || selected.object_dir_relative_path != full.object_relative_path
            || root.join(&full.object_relative_path) != path.join("objects")
        {
            return Err(SdkError::PairingCode("PublicationPending"));
        }
        let writer = index.acquire_account_writer(&account)?;
        let locks = GenerationLocks::for_root(&root)?;
        let lease = locks.try_acquire(&account)?.ok_or(SdkError::PairingCode("Busy"))?;
        // A positively selected generation is never removed by an interrupted recovery.
        let guard = PrivateDirectory { path, transferred: true };
        Ok(Self { guard, index, root, account, _lease: lease, _writer: writer })
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
    /// Abandon only an exact positively unselected crash-left G1, preserving publication keys.
    pub(crate) fn discard_crashed_unselected(
        root: &Path,
        install: &crate::custody::pairing::install_store::Install,
    ) -> Result<crate::custody::pairing::install_store::Install, SdkError> {
        install.validate()?;
        let Some(full) = &install.full_transfer else { return Ok(install.clone()) };
        if install.state != "adopt_prepared" {
            return Err(SdkError::PairingCode("PublicationPending"));
        }
        let root = std::fs::canonicalize(root)?;
        let index = AccountIndex::open(&root)?;
        let _writer = index.acquire_account_writer(&install.account_id)?;
        let locks = GenerationLocks::for_root(&root)?;
        let _lease =
            locks.try_acquire(&install.account_id)?.ok_or(SdkError::PairingCode("Busy"))?;
        let selected = index.account(&install.account_id)?;
        let database = root.join(&full.db_relative_path);
        let path = database.parent().ok_or(SdkError::PairingCode("PublicationPending"))?;
        let nonce = path
            .file_name()
            .and_then(|value| value.to_str())
            .and_then(|value| value.strip_prefix("generation_"))
            .ok_or(SdkError::PairingCode("PublicationPending"))?;
        if selected.db_relative_path != full.expected_prior_generation.db_relative_path
            || selected.object_dir_relative_path
                != full.expected_prior_generation.object_relative_path
            || selected.principal_commitment != install.account_anchor
            || path.parent() != Some(root.join("accounts").join(&install.account_id).as_path())
            || database.file_name().and_then(|value| value.to_str()) != Some("account.db")
            || root.join(&full.object_relative_path) != path.join("objects")
            || !ramflux_protocol::decode_base64url(nonce).is_ok_and(|bytes| bytes.len() == 32)
            || crate::custody::pairing::install_store::read_pending(
                &root,
                &install.account_id,
                &install.operation_id,
            )?
            .as_ref()
                != Some(install)
        {
            return Err(SdkError::PairingCode("PublicationPending"));
        }
        // An absent unselected directory is also a valid pre-G1 crash outcome.
        if path.try_exists()? && std::fs::canonicalize(path)? != path {
            return Err(SdkError::PairingCode("PublicationPending"));
        }
        let mut retained = install.clone();
        retained.schema = "ramflux.pairing.Install.v2".into();
        retained.version = 2;
        retained.full_transfer = None;
        retained.state = "vault_durable".into();
        crate::custody::pairing::install_store::write_pending(&root, &retained)?;
        match std::fs::remove_dir_all(path) {
            Ok(()) => std::fs::File::open(
                path.parent().ok_or(SdkError::PairingCode("PublicationPending"))?,
            )?
            .sync_all()?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        Ok(retained)
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
