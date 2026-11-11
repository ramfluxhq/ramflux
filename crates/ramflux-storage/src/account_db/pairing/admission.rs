// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! A weak, read-only admission capability. It cannot keep an unlocked account DB alive.
use crate::{AccountDb, AdoptionRow, StorageError, database::WeakConnection};
use std::path::{Path, PathBuf};

#[derive(Clone)]
pub struct PairingAdmissionReader {
    account_id: String,
    path: PathBuf,
    index: std::sync::Arc<crate::AccountIndex>,
    connection: WeakConnection,
}
impl std::fmt::Debug for PairingAdmissionReader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PairingAdmissionReader")
            .field("account_id", &self.account_id)
            .finish_non_exhaustive()
    }
}
impl AccountDb {
    /// Borrow a reader tied to this unlocked DB worker. No key or connection is copied.
    #[must_use]
    pub fn pairing_admission_reader(&self) -> PairingAdmissionReader {
        PairingAdmissionReader {
            account_id: self.local_account_id.clone(),
            path: self.connection.owned_path().to_path_buf(),
            index: self.account_index.clone(),
            connection: self.connection.downgrade(),
        }
    }
}
impl PairingAdmissionReader {
    /// Whether the original unlocked worker still exists; this reader never retains it.
    #[must_use]
    pub fn is_open(&self) -> bool {
        self.connection.upgrade_account_writer().is_some()
    }
    /// Read the actual current adoption row from the still-unlocked account DB.
    /// # Errors
    /// Refuses another account/path, a closed DB or invalid persisted adoption metadata.
    pub fn read_for(
        &self,
        root: &Path,
        account: &str,
    ) -> Result<Option<AdoptionRow>, StorageError> {
        let account_root = std::fs::canonicalize(root.join("accounts").join(account))?;
        let selected = self.index.account(account)?;
        crate::account_erase::refuse_removed(&selected)?;
        if account != self.account_id
            || std::fs::canonicalize(self.index.root())? != std::fs::canonicalize(root)?
            || !std::fs::canonicalize(&self.path)?.starts_with(&account_root)
            || std::fs::canonicalize(self.index.root().join(selected.db_relative_path))?
                != std::fs::canonicalize(&self.path)?
        {
            return Err(StorageError::AuthorizationRejected);
        }
        let connection =
            self.connection.upgrade_account_writer().ok_or(StorageError::AuthorizationRejected)?;
        super::journal::read_adoption(&connection, account)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn pairing_admission_reader_is_live_bound_and_does_not_keep_the_db_unlocked()
    -> Result<(), Box<dyn std::error::Error>> {
        let (root, db) = crate::tests::test_db("pairing-weak-admission")?;
        let reader = db.pairing_admission_reader();
        assert!(reader.is_open());
        assert!(reader.read_for(&root, "acct")?.is_none());
        assert!(reader.read_for(&root, "another").is_err());
        let historical = db.open_reader()?;
        let historical_admission = historical.pairing_admission_reader();
        assert!(
            !historical_admission.is_open(),
            "a query-only snapshot cannot act as an unlocked account writer"
        );
        assert!(historical_admission.read_for(&root, "acct").is_err());
        let before = reader.index.account("acct")?.db_relative_path;
        std::fs::write(root.join("accounts/acct/foreign.db"), b"wrong selected generation")?;
        reader.index.connection.execute(
            "UPDATE local_account SET db_relative_path='accounts/acct/foreign.db' WHERE local_account_id='acct'", [],
        )?;
        assert!(
            reader.read_for(&root, "acct").is_err(),
            "a stale unlocked generation must not admit networking"
        );
        reader.index.connection.execute(
            "UPDATE local_account SET db_relative_path=?1 WHERE local_account_id='acct'",
            rusqlite::params![before],
        )?;
        assert!(reader.read_for(&root, "acct")?.is_none());
        drop(db);
        assert!(!reader.is_open(), "a network config must not retain the unlocked DB worker");
        assert!(reader.read_for(&root, "acct").is_err());
        Ok(())
    }
}
