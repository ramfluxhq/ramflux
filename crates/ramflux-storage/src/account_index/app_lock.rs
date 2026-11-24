// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Per-account app-lock policy. An absent row is off, with timeout 0 and generation 0.

use super::AccountIndex;
use crate::{StorageError, WrappedAccountDbKey};
use rusqlite::{OptionalExtension, params};

/// Inclusive upper bound of `account.app_lock.configure` `timeout_ms`.
pub const APP_LOCK_MAX_TIMEOUT_MS: u64 = 86_400_000;

/// Durable app-lock policy of one account. Absent storage is off, timeout 0, generation 0.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[must_use]
pub struct AppLockPolicy {
    /// Whether a restart must stay locked until the user unlocks.
    pub enabled: bool,
    /// Idle timeout in milliseconds. Unused until the lifecycle card.
    pub timeout_ms: u64,
    /// Increases by one on every committed policy change.
    pub generation: u64,
}

impl AccountIndex {
    pub(super) fn install_app_lock_schema(&self) -> Result<(), StorageError> {
        self.connection.execute_batch(
            "CREATE TABLE IF NOT EXISTS account_app_lock (
                local_account_id TEXT PRIMARY KEY,
                enabled INTEGER NOT NULL,
                timeout_ms INTEGER NOT NULL,
                generation INTEGER NOT NULL
            );",
        )?;
        Ok(())
    }

    /// Reads the policy. A missing row is off.
    ///
    /// # Errors
    /// Returns an error when the row cannot be read or a stored value is not 0/1,
    /// a timeout in range, or a non-negative generation.
    pub fn app_lock_policy(&self, local_account_id: &str) -> Result<AppLockPolicy, StorageError> {
        let row = self
            .connection
            .query_row(
                "SELECT enabled, timeout_ms, generation FROM account_app_lock
                  WHERE local_account_id = ?1",
                params![local_account_id],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?, row.get::<_, i64>(2)?)),
            )
            .optional()?;
        row.map_or(Ok(AppLockPolicy::default()), |(enabled, timeout_ms, generation)| {
            decode_policy(enabled, timeout_ms, generation)
        })
    }

    /// Turns app lock on and clears the silent device wrap in one commit.
    ///
    /// # Errors
    /// Returns an error when the account is missing, the timeout is out of range,
    /// or the index cannot commit.
    pub fn enable_app_lock(
        &self,
        local_account_id: &str,
        timeout_ms: u64,
    ) -> Result<AppLockPolicy, StorageError> {
        self.commit_app_lock(local_account_id, true, timeout_ms, None)
    }

    /// Restores the silent wrap and turns app lock off in one commit.
    ///
    /// # Errors
    /// Returns an error when the account is missing, the timeout is out of range,
    /// or the index cannot commit.
    pub fn disable_app_lock(
        &self,
        local_account_id: &str,
        timeout_ms: u64,
        wrap: &WrappedAccountDbKey,
    ) -> Result<AppLockPolicy, StorageError> {
        self.commit_app_lock(local_account_id, false, timeout_ms, Some(wrap.clone()))
    }

    /// Drops silent wraps for every account whose stored policy is on.
    ///
    /// # Errors
    /// Returns an error when a policy cannot be read or a wrap cannot be cleared.
    /// A read error fails closed: the caller must not open that account silently.
    pub fn strip_enabled_app_lock_wraps(&self) -> Result<(), StorageError> {
        for local_account_id in self.known_account_ids()? {
            if self.app_lock_policy(&local_account_id)?.enabled {
                self.clear_device_wrapped_db_key(&local_account_id)?;
            }
        }
        Ok(())
    }

    /// Removes the policy row of an erased account.
    pub(crate) fn erase_app_lock(&self, local_account_id: &str) -> Result<(), StorageError> {
        self.connection.execute(
            "DELETE FROM account_app_lock WHERE local_account_id = ?1",
            params![local_account_id],
        )?;
        Ok(())
    }

    fn commit_app_lock(
        &self,
        local_account_id: &str,
        enabled: bool,
        timeout_ms: u64,
        wrap: Option<WrappedAccountDbKey>,
    ) -> Result<AppLockPolicy, StorageError> {
        if enabled == wrap.is_some() {
            return Err(StorageError::Integrity("app lock wrap does not match the policy"));
        }
        let timeout_ms = checked_timeout(timeout_ms)?;
        let id = local_account_id.to_owned();
        let enabled_flag = i64::from(enabled);
        self.connection.call_immediate_result(move |tx| {
            write_app_lock(tx, &id, enabled_flag, timeout_ms, wrap.as_ref())
        })?
    }
}

fn checked_timeout(timeout_ms: u64) -> Result<i64, StorageError> {
    if timeout_ms > APP_LOCK_MAX_TIMEOUT_MS {
        return Err(StorageError::Integrity("app lock timeout is out of range"));
    }
    i64::try_from(timeout_ms)
        .map_err(|_| StorageError::Integrity("app lock timeout is out of range"))
}

fn write_app_lock(
    tx: &rusqlite::Transaction<'_>,
    local_account_id: &str,
    enabled: i64,
    timeout_ms: i64,
    wrap: Option<&WrappedAccountDbKey>,
) -> Result<AppLockPolicy, StorageError> {
    require_account(tx, local_account_id)?;
    let generation = next_generation(tx, local_account_id)?;
    tx.execute(
        "INSERT INTO account_app_lock (local_account_id, enabled, timeout_ms, generation)
         VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT(local_account_id) DO UPDATE SET
            enabled = excluded.enabled,
            timeout_ms = excluded.timeout_ms,
            generation = excluded.generation",
        params![local_account_id, enabled, timeout_ms, generation],
    )?;
    if let Some(wrap) = wrap {
        store_wrap(tx, local_account_id, wrap)?;
    } else {
        clear_wrap(tx, local_account_id)?;
    }
    decode_policy(enabled, timeout_ms, generation)
}

fn require_account(
    tx: &rusqlite::Transaction<'_>,
    local_account_id: &str,
) -> Result<(), StorageError> {
    let found = tx
        .query_row(
            "SELECT 1 FROM local_account WHERE local_account_id = ?1",
            params![local_account_id],
            |_| Ok(1_i64),
        )
        .optional()?;
    if found.is_none() {
        return Err(StorageError::AccountNotFound(local_account_id.to_owned()));
    }
    Ok(())
}

fn next_generation(
    tx: &rusqlite::Transaction<'_>,
    local_account_id: &str,
) -> Result<i64, StorageError> {
    let current = tx
        .query_row(
            "SELECT generation FROM account_app_lock WHERE local_account_id = ?1",
            params![local_account_id],
            |row| row.get::<_, i64>(0),
        )
        .optional()?;
    let current = match current {
        Some(value) if value >= 0 => value,
        Some(_) => return Err(StorageError::Integrity("app lock policy is corrupt")),
        None => 0,
    };
    current.checked_add(1).ok_or(StorageError::Integrity("app lock generation overflow"))
}

fn store_wrap(
    tx: &rusqlite::Transaction<'_>,
    local_account_id: &str,
    wrap: &WrappedAccountDbKey,
) -> Result<(), StorageError> {
    tx.execute(
        "INSERT INTO account_device_unlock (local_account_id, wrapped_key, wrapped_key_nonce)
         VALUES (?1, ?2, ?3)
         ON CONFLICT(local_account_id) DO UPDATE SET
            wrapped_key = excluded.wrapped_key,
            wrapped_key_nonce = excluded.wrapped_key_nonce",
        params![local_account_id, wrap.wrapped_key, wrap.nonce.as_slice()],
    )?;
    Ok(())
}

fn clear_wrap(tx: &rusqlite::Transaction<'_>, local_account_id: &str) -> Result<(), StorageError> {
    tx.execute(
        "UPDATE account_device_unlock SET wrapped_key = NULL, wrapped_key_nonce = NULL
          WHERE local_account_id = ?1",
        params![local_account_id],
    )?;
    Ok(())
}

fn decode_policy(
    enabled: i64,
    timeout_ms: i64,
    generation: i64,
) -> Result<AppLockPolicy, StorageError> {
    let enabled = match enabled {
        0 => false,
        1 => true,
        _ => return Err(StorageError::Integrity("app lock policy is corrupt")),
    };
    if generation < 0 {
        return Err(StorageError::Integrity("app lock policy is corrupt"));
    }
    let timeout_ms = u64::try_from(timeout_ms)
        .map_err(|_| StorageError::Integrity("app lock policy is corrupt"))?;
    if timeout_ms > APP_LOCK_MAX_TIMEOUT_MS {
        return Err(StorageError::Integrity("app lock policy is corrupt"));
    }
    Ok(AppLockPolicy {
        enabled,
        timeout_ms,
        generation: u64::try_from(generation)
            .map_err(|_| StorageError::Integrity("app lock policy is corrupt"))?,
    })
}
