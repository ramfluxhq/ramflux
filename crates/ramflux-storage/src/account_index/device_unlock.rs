// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Device-held unlock wrapping of the account DB key and the code attempt counter.
//!
//! The device wrap opens the account without user input; its key needs the platform-held device
//! secret. The attempt counter lives beside it so it survives a process restart while the
//! encrypted account DB is closed.

use super::AccountIndex;
use crate::{StorageError, WrappedAccountDbKey};
use rusqlite::{OptionalExtension, params};

/// Durable code-attempt state of one account.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CodeAttempts {
    /// Consecutive failed (or interrupted) code checks since the last success.
    pub failures: u32,
    /// Unix time of the last code check, if any.
    pub last_attempt_at: Option<i64>,
}

impl AccountIndex {
    pub(super) fn install_device_unlock_schema(&self) -> Result<(), StorageError> {
        self.connection.execute_batch(
            "CREATE TABLE IF NOT EXISTS account_device_unlock (
                local_account_id TEXT PRIMARY KEY,
                wrapped_key BLOB,
                wrapped_key_nonce BLOB,
                code_failures INTEGER NOT NULL DEFAULT 0,
                code_attempt_at INTEGER
            );",
        )?;
        Ok(())
    }

    /// Stores the device wrap of the account DB key, replacing any earlier one.
    ///
    /// # Errors
    /// Returns an error when the account is missing or the row cannot be written.
    pub fn store_device_wrapped_db_key(
        &self,
        local_account_id: &str,
        wrapped: &WrappedAccountDbKey,
    ) -> Result<(), StorageError> {
        self.account(local_account_id)?;
        self.connection.execute(
            "INSERT INTO account_device_unlock (local_account_id, wrapped_key, wrapped_key_nonce)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(local_account_id) DO UPDATE SET
                wrapped_key = excluded.wrapped_key,
                wrapped_key_nonce = excluded.wrapped_key_nonce",
            params![local_account_id, wrapped.wrapped_key, wrapped.nonce.as_slice()],
        )?;
        Ok(())
    }

    /// Loads the device wrap, or `None` when the account has none (never set, or locked).
    ///
    /// # Errors
    /// Returns an error when the stored nonce is malformed or the row cannot be read.
    pub fn load_device_wrapped_db_key(
        &self,
        local_account_id: &str,
    ) -> Result<Option<WrappedAccountDbKey>, StorageError> {
        let row = self
            .connection
            .query_row(
                "SELECT wrapped_key, wrapped_key_nonce FROM account_device_unlock
                  WHERE local_account_id = ?1",
                params![local_account_id],
                |row| Ok((row.get::<_, Option<Vec<u8>>>(0)?, row.get::<_, Option<Vec<u8>>>(1)?)),
            )
            .optional()?;
        let Some((Some(wrapped_key), Some(nonce))) = row else {
            return Ok(None);
        };
        let nonce: [u8; 12] = nonce.try_into().map_err(|_bytes: Vec<u8>| {
            StorageError::KeyWrappingFailed("invalid device wrap nonce length".to_owned())
        })?;
        Ok(Some(WrappedAccountDbKey {
            key_wrapping_provider: "platform-device-unlock".to_owned(),
            key_wrapping_ref: String::new(),
            nonce,
            wrapped_key,
        }))
    }

    /// Removes the device wrap (explicit lock); the attempt counter is kept.
    ///
    /// # Errors
    /// Returns an error when the row cannot be updated.
    pub fn clear_device_wrapped_db_key(&self, local_account_id: &str) -> Result<(), StorageError> {
        self.connection.execute(
            "UPDATE account_device_unlock SET wrapped_key = NULL, wrapped_key_nonce = NULL
              WHERE local_account_id = ?1",
            params![local_account_id],
        )?;
        Ok(())
    }

    /// Reads the code attempt state; an account without a row has no failures.
    ///
    /// # Errors
    /// Returns an error when the row cannot be read.
    pub fn code_attempts(&self, local_account_id: &str) -> Result<CodeAttempts, StorageError> {
        let row = self
            .connection
            .query_row(
                "SELECT code_failures, code_attempt_at FROM account_device_unlock
                  WHERE local_account_id = ?1",
                params![local_account_id],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, Option<i64>>(1)?)),
            )
            .optional()?;
        Ok(row.map_or_else(CodeAttempts::default, |(failures, last_attempt_at)| CodeAttempts {
            failures: u32::try_from(failures.max(0)).unwrap_or(u32::MAX),
            last_attempt_at,
        }))
    }

    /// Durably counts one code check as failed before it runs; a success resets it.
    ///
    /// # Errors
    /// Returns an error when the account is missing or the counter cannot be written.
    pub fn begin_code_attempt(&self, local_account_id: &str, now: i64) -> Result<(), StorageError> {
        self.account(local_account_id)?;
        self.connection.execute(
            "INSERT INTO account_device_unlock (local_account_id, code_failures, code_attempt_at)
             VALUES (?1, 1, ?2)
             ON CONFLICT(local_account_id) DO UPDATE SET
                code_failures = code_failures + 1,
                code_attempt_at = excluded.code_attempt_at",
            params![local_account_id, now],
        )?;
        Ok(())
    }

    /// Resets the counter after a correct code.
    ///
    /// # Errors
    /// Returns an error when the counter cannot be written.
    pub fn reset_code_attempts(&self, local_account_id: &str) -> Result<(), StorageError> {
        self.connection.execute(
            "UPDATE account_device_unlock SET code_failures = 0 WHERE local_account_id = ?1",
            params![local_account_id],
        )?;
        Ok(())
    }

    /// Removes all device-unlock state of an erased account.
    pub(crate) fn erase_device_unlock(&self, local_account_id: &str) -> Result<(), StorageError> {
        self.connection.execute(
            "DELETE FROM account_device_unlock WHERE local_account_id = ?1",
            params![local_account_id],
        )?;
        Ok(())
    }
}
