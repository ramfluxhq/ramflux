// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! One durable commit selects an entire verified account generation and its recovery material.

use super::AccountIndex;
use crate::{LocalAccountRecord, StorageError, WrappedAccountDbKey};
use rusqlite::{OptionalExtension, params};

pub struct BackupIndexInstall<'a> {
    pub account_id: &'a str,
    pub principal_commitment: &'a str,
    pub db_relative_path: &'a str,
    pub object_relative_path: &'a str,
    pub manifest_json: &'a [u8],
    pub wrapped_key: &'a WrappedAccountDbKey,
}

/// One SQLite read snapshot of the selected paths and their G2 recovery manifest.
/// The manifest can contain private legacy recovery metadata; never log this value.
pub struct AccountGenerationSelection {
    pub account: LocalAccountRecord,
    pub manifest_json: Option<Vec<u8>>,
}

impl AccountIndex {
    /// Read the generation pointer and its recovery material in one SQL statement.
    /// Separate `account`/manifest reads could otherwise straddle a concurrent selection.
    /// This observation grants no generation lease or permission to select/install data.
    /// # Errors
    /// Returns missing-account or index read errors.
    pub fn account_generation_selection(
        &self,
        id: &str,
    ) -> Result<AccountGenerationSelection, StorageError> {
        self.connection.query_row(
            "SELECT a.local_account_id,a.principal_commitment,a.db_relative_path,a.object_dir_relative_path,a.account_state,g.manifest_json FROM local_account a LEFT JOIN account_backup_generation g ON g.local_account_id=a.local_account_id WHERE a.local_account_id=?1",
            params![id], |row| Ok(AccountGenerationSelection {
                account: LocalAccountRecord {
                    local_account_id:row.get(0)?, principal_commitment:row.get(1)?,
                    db_relative_path:row.get(2)?,object_dir_relative_path:row.get(3)?,account_state:row.get(4)?,
                }, manifest_json:row.get(5)?,
            }),
        ).optional()?.ok_or_else(||StorageError::AccountNotFound(id.into()))
    }
    pub(super) fn install_backup_schema(&self) -> Result<(), StorageError> {
        self.connection.execute_batch("CREATE TABLE IF NOT EXISTS account_backup_generation(local_account_id TEXT PRIMARY KEY,manifest_json BLOB NOT NULL);")?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            // Existing WAL files may predate the recovery manifest and the stricter DB mode.
            for suffix in ["", "-wal", "-shm"] {
                let path = self.root.join(format!("{}{suffix}", crate::ACCOUNT_INDEX_FILE));
                match std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)) {
                    Ok(()) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error.into()),
                }
            }
        }
        Ok(())
    }
    /// Reads the recovery manifest selected by the account's durable generation pointer.
    /// # Errors
    /// Returns index errors; None denotes the unchanged legacy manifest layout.
    pub fn backup_generation_manifest(&self, id: &str) -> Result<Option<Vec<u8>>, StorageError> {
        Ok(self
            .connection
            .query_row(
                "SELECT manifest_json FROM account_backup_generation WHERE local_account_id=?1",
                params![id],
                |row| row.get(0),
            )
            .optional()?)
    }
    /// Updates an installed generation's manifest atomically, without creating a legacy file.
    /// # Errors
    /// Returns SQL errors; false means the account still uses a legacy manifest file.
    pub fn update_backup_generation_manifest(
        &self,
        id: &str,
        manifest: &[u8],
    ) -> Result<bool, StorageError> {
        Ok(self.connection.execute(
            "UPDATE account_backup_generation SET manifest_json=?2 WHERE local_account_id=?1",
            params![id, manifest],
        )? != 0)
    }
    fn ensure_generation_hint(&self, id: &str) -> Result<(), StorageError> {
        let accounts = self.root.join("accounts");
        let parent = accounts.join(id);
        std::fs::create_dir_all(&parent)?;
        let path = parent.join(crate::BACKUP_GENERATION_MARKER);
        let mut options = std::fs::OpenOptions::new();
        options.create_new(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = match options.open(&path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                std::fs::File::open(&path)?
            }
            Err(error) => return Err(error.into()),
        };
        file.sync_all()?;
        // The hint precedes commit, so false positives only cause an index lookup. Sync newly
        // created account-parent entries as well as files before publishing the generation.
        for directory in [&parent, &accounts, &self.root] {
            crate::sync_path::sync_path(directory)?;
        }
        Ok(())
    }
    /// Atomically installs prepared paths, key wrapping and recovery manifest under FULL/WAL.
    /// Files must already be durable. An error leaves the selected generation unchanged.
    /// # Errors
    /// Rejects a root replacement or unsafe relative path and returns index commit errors.
    pub fn install_backup_generation(
        &self,
        install: &BackupIndexInstall<'_>,
    ) -> Result<(), StorageError> {
        let owner = self.acquire_account_writer(install.account_id)?;
        let _fence =
            owner.owner.generation.read().map_err(|_| StorageError::AuthorizationRejected)?;
        self.install_generation_under_fence(install, None)
    }

    /// Caller holds the shared account's exclusive generation fence on its actual writer.
    pub(crate) fn install_generation_under_fence(
        &self,
        install: &BackupIndexInstall<'_>,
        expected: Option<(&LocalAccountRecord, &WrappedAccountDbKey)>,
    ) -> Result<(), StorageError> {
        for path in [install.db_relative_path, install.object_relative_path] {
            if std::path::Path::new(path)
                .components()
                .any(|part| !matches!(part, std::path::Component::Normal(_)))
            {
                return Err(StorageError::AuthorizationRejected);
            }
        }
        let id = std::path::Path::new(install.account_id);
        if id.components().count() != 1
            || id.components().any(|p| !matches!(p, std::path::Component::Normal(_)))
        {
            return Err(StorageError::AuthorizationRejected);
        }
        let _writer = self.acquire_account_writer(install.account_id)?;
        match self.account(install.account_id) {
            Ok(account) => crate::account_erase::refuse_removed(&account)?,
            Err(StorageError::AccountNotFound(_)) => {}
            Err(error) => return Err(error),
        }
        self.ensure_generation_hint(install.account_id)?;
        let account = install.account_id.to_owned();
        let principal = install.principal_commitment.to_owned();
        let db_path = install.db_relative_path.to_owned();
        let object_path = install.object_relative_path.to_owned();
        let manifest = install.manifest_json.to_vec();
        let wrapped = install.wrapped_key.clone();
        let expected = expected.map(|(account, key)| (account.clone(), key.clone()));
        let committed = self.connection.call(move |raw| {
            let tx = raw.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            if let Some((prior, key)) = expected {
                // One worker job and one SQL transaction: no index call can join the
                // interval between the prior-selection comparison and the pointer switch.
                let same: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM local_account WHERE local_account_id=?1 AND principal_commitment=?2 AND db_relative_path=?3 AND object_dir_relative_path=?4 AND account_state=?5 AND key_wrapping_provider=?6 AND key_wrapping_ref=?7 AND wrapped_key=?8 AND wrapped_key_nonce=?9)", params![prior.local_account_id,prior.principal_commitment,prior.db_relative_path,prior.object_dir_relative_path,prior.account_state,key.key_wrapping_provider,key.key_wrapping_ref,key.wrapped_key,key.nonce.as_slice()], |row| row.get(0))?;
                if !same { return Ok(false); }
            }
            let previous: Option<String> = tx.query_row("SELECT principal_commitment FROM local_account WHERE local_account_id=?1", params![account], |row| row.get(0)).optional()?;
            if previous.as_deref().is_some_and(|root| root != principal) { return Err(rusqlite::Error::InvalidQuery); }
            tx.execute("INSERT INTO local_account(local_account_id,principal_commitment,display_label,db_relative_path,object_dir_relative_path,key_wrapping_provider,key_wrapping_ref,wrapped_key,wrapped_key_nonce,account_state,created_at,last_opened_at) VALUES(?1,?2,NULL,?3,?4,?5,?6,?7,?8,'active',?9,NULL) ON CONFLICT(local_account_id) DO UPDATE SET db_relative_path=excluded.db_relative_path,object_dir_relative_path=excluded.object_dir_relative_path,key_wrapping_provider=excluded.key_wrapping_provider,key_wrapping_ref=excluded.key_wrapping_ref,wrapped_key=excluded.wrapped_key,wrapped_key_nonce=excluded.wrapped_key_nonce",params![account,principal,db_path,object_path,wrapped.key_wrapping_provider,wrapped.key_wrapping_ref,wrapped.wrapped_key,wrapped.nonce.as_slice(),super::unix_now()])?;
            tx.execute("INSERT INTO account_backup_generation VALUES(?1,?2) ON CONFLICT(local_account_id) DO UPDATE SET manifest_json=excluded.manifest_json",params![account,manifest])?;
            tx.commit()?;
            Ok(true)
        })?;
        if !committed {
            return Err(StorageError::PairingField("Busy"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    #[test]
    fn recovery_manifest_index_and_existing_wal_files_are_owner_only()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::PermissionsExt;
        let root = std::env::temp_dir().join(format!(
            "rf-backup-index-permissions-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_nanos()
        ));
        let index = AccountIndex::open(&root)?;
        index.create_account("account", "root")?;
        let paths = ["", "-wal", "-shm"]
            .map(|suffix| root.join(format!("{}{suffix}", crate::ACCOUNT_INDEX_FILE)));
        assert!(paths[1].exists(), "the fixture must exercise an existing WAL");
        for path in &paths {
            if path.exists() {
                std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644))?;
            }
        }
        let reopened = AccountIndex::open(&root)?;
        for path in &paths {
            if path.exists() {
                assert_eq!(std::fs::metadata(path)?.permissions().mode() & 0o777, 0o600);
            }
        }
        drop(reopened);
        drop(index);
        std::fs::remove_dir_all(root)?;
        Ok(())
    }
    #[test]
    fn a_failed_generation_index_commit_keeps_the_entire_previous_selection()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = std::env::temp_dir().join(format!(
            "rf-backup-index-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_nanos()
        ));
        let index = AccountIndex::open(&root)?;
        index.create_account("account", "root")?;
        let before = index.account("account")?;
        let key = crate::WrappedAccountDbKey {
            key_wrapping_provider: "vault".into(),
            key_wrapping_ref: "vault:account".into(),
            nonce: [1; 12],
            wrapped_key: vec![2; 48],
        };
        index.connection.execute_batch("CREATE TRIGGER reject_test_manifest BEFORE INSERT ON account_backup_generation BEGIN SELECT RAISE(ABORT,'injected index commit failure'); END;")?;
        let install = BackupIndexInstall {
            account_id: "account",
            principal_commitment: "root",
            db_relative_path: "accounts/account/new/account.db",
            object_relative_path: "accounts/account/new",
            manifest_json: b"new manifest",
            wrapped_key: &key,
        };
        assert!(index.install_backup_generation(&install).is_err());
        assert_eq!(index.account("account")?.db_relative_path, before.db_relative_path);
        assert!(index.backup_generation_manifest("account")?.is_none());
        let unchanged = index.account_generation_selection("account")?;
        assert_eq!(unchanged.account, before);
        assert!(unchanged.manifest_json.is_none(), "failed commit exposed a new recovery marker");
        index.connection.execute_batch("DROP TRIGGER reject_test_manifest")?;
        index.install_backup_generation(&install)?;
        assert_eq!(index.account("account")?.db_relative_path, install.db_relative_path);
        assert_eq!(index.backup_generation_manifest("account")?, Some(b"new manifest".to_vec()));
        drop(index);
        let reopened = AccountIndex::open(&root)?;
        assert_eq!(reopened.account("account")?.db_relative_path, install.db_relative_path);
        let selected = reopened.account_generation_selection("account")?;
        assert_eq!(selected.account.db_relative_path, install.db_relative_path);
        assert_eq!(selected.account.object_dir_relative_path, install.object_relative_path);
        assert_eq!(selected.manifest_json, Some(b"new manifest".to_vec()));
        drop(reopened);
        std::fs::remove_dir_all(root)?;
        Ok(())
    }
}
