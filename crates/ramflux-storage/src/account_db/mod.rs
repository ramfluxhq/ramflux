// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::wildcard_imports)]
use crate::encryption::{
    AccountKeyWrappingProvider, WrappedAccountDbKey, apply_key, current_encryption_mode,
    verify_or_install_key_fingerprint, wrap_with_vault_secret,
};
use crate::schema::migrate_account_db;
use crate::*;
use rusqlite::{Connection, params};
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::path::PathBuf;

pub mod bot;
pub mod conversation_list;
pub mod conversation_projection;
pub mod conversation_state;
pub mod friend;
pub mod group_pending;
pub mod groups;
pub mod history;
pub mod identity_verification;
pub mod mcp;
pub mod messages;
pub mod object;

pub struct AccountDb {
    pub local_account_id: String,
    pub path: PathBuf,
    mode: EncryptionMode,
    current_key: AccountDbKey,
    device_signer: Option<ramflux_crypto::DeviceBranch>,
    clock: AccountClock,
    pub(crate) connection: Connection,
    volatile_typing: RefCell<BTreeMap<(String, String), TypingStateRecord>>,
    volatile_presence: RefCell<BTreeMap<String, ContactPresenceRecord>>,
}

impl AccountDb {
    pub fn open(
        index: &AccountIndex,
        local_account_id: &str,
        key: &AccountDbKey,
    ) -> Result<Self, StorageError> {
        let account = index.account(local_account_id)?;
        let path = index.root().join(account.db_relative_path);
        let connection = Connection::open(&path)?;
        apply_key(&connection, key)?;
        let mode = current_encryption_mode(&connection);
        if mode != EncryptionMode::SqlCipher && !insecure_test_sqlite_allowed() {
            return Err(StorageError::EncryptionUnavailable { mode });
        }
        migrate_account_db(&connection)?;
        verify_or_install_key_fingerprint(&connection, key)?;
        Ok(Self {
            local_account_id: local_account_id.to_owned(),
            path,
            mode,
            current_key: key.clone(),
            device_signer: None,
            clock: AccountClock::real(),
            connection,
            volatile_typing: RefCell::new(BTreeMap::new()),
            volatile_presence: RefCell::new(BTreeMap::new()),
        })
    }

    #[must_use]
    pub const fn encryption_mode(&self) -> EncryptionMode {
        self.mode
    }

    #[must_use]
    pub fn with_device_signer(mut self, device_signer: ramflux_crypto::DeviceBranch) -> Self {
        self.device_signer = Some(device_signer);
        self
    }

    pub fn set_device_signer(&mut self, device_signer: ramflux_crypto::DeviceBranch) {
        self.device_signer = Some(device_signer);
    }

    pub(crate) const fn device_signer(&self) -> Option<&ramflux_crypto::DeviceBranch> {
        self.device_signer.as_ref()
    }

    #[must_use]
    pub fn with_clock(mut self, clock: AccountClock) -> Self {
        self.clock = clock;
        self
    }

    pub fn set_clock(&mut self, clock: AccountClock) {
        self.clock = clock;
    }

    #[must_use]
    pub(crate) fn now_unix(&self) -> i64 {
        self.clock.now_unix()
    }

    /// # Errors
    /// Returns an error when fresh nonce generation or AEAD wrapping fails.
    pub fn wrap_current_db_key(
        &self,
        key_encryption_key: &[u8; 32],
    ) -> Result<WrappedAccountDbKey, StorageError> {
        let (nonce, wrapped_key) =
            wrap_with_vault_secret(key_encryption_key, self.current_key.bytes())?;
        Ok(WrappedAccountDbKey {
            key_wrapping_provider: "platform-local-vault".to_owned(),
            key_wrapping_ref: format!("platform-local-vault:{}", self.local_account_id),
            nonce,
            wrapped_key,
        })
    }

    /// # Errors
    /// Returns an error when validation, serialization, storage, or state checks fail.
    pub fn rekey(&mut self, new_key: &AccountDbKey) -> Result<(), StorageError> {
        self.rekey_database(new_key)?;
        self.current_key = new_key.clone();
        Ok(())
    }

    /// # Errors
    /// Returns an error if `SQLCipher` rekeying, fingerprint update, provider wrapping, or rollback
    /// fails. On provider failure, the DB key and key fingerprint are restored to the old key.
    pub fn rekey_with_wrapping(
        &mut self,
        new_key: &AccountDbKey,
        provider: &mut dyn AccountKeyWrappingProvider,
        previous_wrapped_key: &WrappedAccountDbKey,
    ) -> Result<WrappedAccountDbKey, StorageError> {
        let old_key = self.current_key.clone();
        self.rekey_database(new_key)?;
        match provider.wrap_account_db_key(&self.local_account_id, new_key) {
            Ok(wrapped) => {
                self.current_key = new_key.clone();
                Ok(wrapped)
            }
            Err(error) => {
                self.rekey_database(&old_key).map_err(|rollback_error| {
                    StorageError::RekeyRollbackFailed(rollback_error.to_string())
                })?;
                provider
                    .restore_wrapped_account_db_key(&self.local_account_id, previous_wrapped_key)
                    .map_err(|rollback_error| {
                        StorageError::RekeyRollbackFailed(rollback_error.to_string())
                    })?;
                Err(error)
            }
        }
    }

    fn rekey_database(&mut self, new_key: &AccountDbKey) -> Result<(), StorageError> {
        if self.mode == EncryptionMode::SqlCipher {
            self.connection
                .execute_batch(&format!("PRAGMA rekey = \"x'{}'\";", new_key.sqlcipher_hex()))?;
        }
        self.connection.execute(
            "UPDATE account_key_check SET key_fingerprint = ?1 WHERE singleton_id = 1",
            params![new_key.fingerprint()],
        )?;
        Ok(())
    }
}

const fn insecure_test_sqlite_allowed() -> bool {
    cfg!(feature = "insecure-test-sqlite")
}
