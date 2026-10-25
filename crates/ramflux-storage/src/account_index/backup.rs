// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! One durable commit selects an entire verified account generation and its recovery material.

use super::AccountIndex;
use crate::{StorageError, WrappedAccountDbKey};
use rusqlite::{OptionalExtension, params};

pub struct BackupIndexInstall<'a> {
    pub account_id: &'a str,
    pub principal_commitment: &'a str,
    pub db_relative_path: &'a str,
    pub object_relative_path: &'a str,
    pub manifest_json: &'a [u8],
    pub wrapped_key: &'a WrappedAccountDbKey,
}

impl AccountIndex {
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
    /// Atomically installs prepared paths, key wrapping and recovery manifest under FULL/WAL.
    /// Files must already be durable. An error leaves the selected generation unchanged.
    /// # Errors
    /// Rejects a root replacement or unsafe relative path and returns index commit errors.
    pub fn install_backup_generation(
        &self,
        install: &BackupIndexInstall<'_>,
    ) -> Result<(), StorageError> {
        for path in [install.db_relative_path, install.object_relative_path] {
            if std::path::Path::new(path)
                .components()
                .any(|part| !matches!(part, std::path::Component::Normal(_)))
            {
                return Err(StorageError::AuthorizationRejected);
            }
        }
        let transaction = self.connection.unchecked_transaction()?;
        let previous = self
            .connection
            .query_row(
                "SELECT principal_commitment FROM local_account WHERE local_account_id=?1",
                params![install.account_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        if previous.as_deref().is_some_and(|root| root != install.principal_commitment) {
            return Err(StorageError::AuthorizationRejected);
        }
        self.connection.execute("INSERT INTO local_account(local_account_id,principal_commitment,display_label,db_relative_path,object_dir_relative_path,key_wrapping_provider,key_wrapping_ref,wrapped_key,wrapped_key_nonce,account_state,created_at,last_opened_at) VALUES(?1,?2,NULL,?3,?4,?5,?6,?7,?8,'active',?9,NULL) ON CONFLICT(local_account_id) DO UPDATE SET db_relative_path=excluded.db_relative_path,object_dir_relative_path=excluded.object_dir_relative_path,key_wrapping_provider=excluded.key_wrapping_provider,key_wrapping_ref=excluded.key_wrapping_ref,wrapped_key=excluded.wrapped_key,wrapped_key_nonce=excluded.wrapped_key_nonce",params![install.account_id,install.principal_commitment,install.db_relative_path,install.object_relative_path,install.wrapped_key.key_wrapping_provider,install.wrapped_key.key_wrapping_ref,install.wrapped_key.wrapped_key,install.wrapped_key.nonce.as_slice(),super::unix_now()])?;
        self.connection.execute("INSERT INTO account_backup_generation VALUES(?1,?2) ON CONFLICT(local_account_id) DO UPDATE SET manifest_json=excluded.manifest_json",params![install.account_id,install.manifest_json])?;
        transaction.commit()?;
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
        index.connection.execute_batch("DROP TRIGGER reject_test_manifest")?;
        index.install_backup_generation(&install)?;
        assert_eq!(index.account("account")?.db_relative_path, install.db_relative_path);
        assert_eq!(index.backup_generation_manifest("account")?, Some(b"new manifest".to_vec()));
        drop(index);
        let reopened = AccountIndex::open(&root)?;
        assert_eq!(reopened.account("account")?.db_relative_path, install.db_relative_path);
        drop(reopened);
        std::fs::remove_dir_all(root)?;
        Ok(())
    }
}
