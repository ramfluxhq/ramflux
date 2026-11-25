// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Per-account app-lock policy. An absent row is off, with timeout 0 and generation 0.
//!
//! The row also keeps the durable hard-lock override (set by an explicit `account.lock`, cleared
//! only by a correct account code) and the optional platform presence wrap of the account key.
//! Every policy change is checked against the generation the caller read and commits the policy,
//! the silent wrap and the presence wrap in one transaction.

use super::AccountIndex;
use crate::{StorageError, WrappedAccountDbKey};
use rusqlite::{OptionalExtension, params};

/// Inclusive upper bound of `account.app_lock.configure` `timeout_ms`.
pub const APP_LOCK_MAX_TIMEOUT_MS: u64 = 86_400_000;
/// Largest opaque presence wrap the storage accepts from a platform provider.
pub const APP_LOCK_PRESENCE_WRAP_MAX_BYTES: usize = 4_096;

/// Durable app-lock policy of one account. Absent storage is off, timeout 0, generation 0.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[must_use]
pub struct AppLockPolicy {
    /// Whether a restart must stay locked until the user unlocks.
    pub enabled: bool,
    /// Idle timeout in milliseconds.
    pub timeout_ms: u64,
    /// Increases by one on every committed policy change.
    pub generation: u64,
    /// Set by an explicit `account.lock`; presence unlock is refused until a correct code clears it.
    pub hard_locked: bool,
    /// A presence wrap is stored for the account. Only ever true while the policy is on.
    pub presence_wrapped: bool,
}

/// Opaque platform presence wrap of the account key plus the device it was bound to.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AppLockPresenceWrap {
    /// Installed device identity the wrap is bound to.
    pub device_id: String,
    /// Opaque provider bytes, at most [`APP_LOCK_PRESENCE_WRAP_MAX_BYTES`].
    pub wrapped: Vec<u8>,
}

/// One policy change. The generation read by the caller must still be current on commit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AppLockChange {
    /// Turn on. Clears the silent wrap; `presence` (when present) replaces any earlier one.
    Enable { timeout_ms: u64, presence: Option<AppLockPresenceWrap> },
    /// Turn off. Restores the silent wrap and clears the presence wrap.
    Disable { timeout_ms: u64, silent: WrappedAccountDbKey },
}

impl AccountIndex {
    pub(super) fn install_app_lock_schema(&self) -> Result<(), StorageError> {
        self.connection.execute_batch(
            "CREATE TABLE IF NOT EXISTS account_app_lock (
                local_account_id TEXT PRIMARY KEY,
                enabled INTEGER NOT NULL,
                timeout_ms INTEGER NOT NULL,
                generation INTEGER NOT NULL,
                hard_locked INTEGER NOT NULL DEFAULT 0,
                presence_device_id TEXT,
                presence_wrap BLOB
            );",
        )?;
        Ok(())
    }

    /// Reads the policy. A missing row is off.
    ///
    /// # Errors
    /// Returns an error when the row cannot be read or a stored value is out of range.
    pub fn app_lock_policy(&self, local_account_id: &str) -> Result<AppLockPolicy, StorageError> {
        let row = self
            .connection
            .query_row(
                "SELECT enabled, timeout_ms, generation, hard_locked,
                        presence_wrap IS NOT NULL AND presence_device_id IS NOT NULL
                   FROM account_app_lock WHERE local_account_id = ?1",
                params![local_account_id],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, bool>(4)?,
                    ))
                },
            )
            .optional()?;
        let Some((enabled, timeout_ms, generation, hard_locked, presence)) = row else {
            return Ok(AppLockPolicy::default());
        };
        let mut policy = decode_policy(enabled, timeout_ms, generation)?;
        policy.hard_locked = decode_flag(hard_locked)?;
        policy.presence_wrapped = policy.enabled && presence;
        Ok(policy)
    }

    /// Reads the presence wrap of the account, when one is stored.
    ///
    /// # Errors
    /// Returns an error when the row cannot be read or the stored wrap is oversized.
    pub fn app_lock_presence_wrap(
        &self,
        local_account_id: &str,
    ) -> Result<Option<AppLockPresenceWrap>, StorageError> {
        let row = self
            .connection
            .query_row(
                "SELECT presence_device_id, presence_wrap FROM account_app_lock
                  WHERE local_account_id = ?1",
                params![local_account_id],
                |row| Ok((row.get::<_, Option<String>>(0)?, row.get::<_, Option<Vec<u8>>>(1)?)),
            )
            .optional()?;
        let Some((Some(device_id), Some(wrapped))) = row else {
            return Ok(None);
        };
        if wrapped.is_empty() || wrapped.len() > APP_LOCK_PRESENCE_WRAP_MAX_BYTES {
            return Err(StorageError::Integrity("app lock presence wrap is corrupt"));
        }
        Ok(Some(AppLockPresenceWrap { device_id, wrapped }))
    }

    /// Commits one policy change if `expected_generation` is still current.
    ///
    /// # Errors
    /// Returns an error when the account is missing, the timeout or wrap is out of range, the
    /// generation changed since it was read, or the index cannot commit. A failed commit leaves
    /// the previous policy, silent wrap and presence wrap unchanged.
    pub fn commit_app_lock(
        &self,
        local_account_id: &str,
        expected_generation: u64,
        change: AppLockChange,
    ) -> Result<AppLockPolicy, StorageError> {
        let timeout_ms = match &change {
            AppLockChange::Enable { timeout_ms, presence } => {
                if let Some(wrap) = presence {
                    checked_presence(wrap)?;
                }
                *timeout_ms
            }
            AppLockChange::Disable { timeout_ms, .. } => *timeout_ms,
        };
        checked_timeout(timeout_ms)?;
        let id = local_account_id.to_owned();
        let expected = i64::try_from(expected_generation)
            .map_err(|_| StorageError::Integrity("app lock generation overflow"))?;
        self.connection
            .call_immediate_result(move |tx| write_app_lock(tx, &id, expected, change))?
    }

    /// Records the durable hard-lock override. Set before an explicit `account.lock` is
    /// acknowledged; cleared only after a correct account code.
    ///
    /// # Errors
    /// Returns an error when the account is missing or the index cannot commit.
    pub fn set_app_lock_hard_lock(
        &self,
        local_account_id: &str,
        locked: bool,
    ) -> Result<(), StorageError> {
        let id = local_account_id.to_owned();
        self.connection.call_immediate_result(move |tx| {
            require_account(tx, &id)?;
            tx.execute(
                "INSERT INTO account_app_lock (local_account_id, enabled, timeout_ms, generation, hard_locked)
                 VALUES (?1, 0, 0, 0, ?2)
                 ON CONFLICT(local_account_id) DO UPDATE SET hard_locked = excluded.hard_locked",
                params![id, i64::from(locked)],
            )?;
            Ok(())
        })?
    }

    /// Drops the presence wrap after the platform reports its key invalid. The policy stays on,
    /// so the account can only be unlocked with its code.
    ///
    /// # Errors
    /// Returns an error when the index cannot commit.
    pub fn clear_app_lock_presence_wrap(&self, local_account_id: &str) -> Result<(), StorageError> {
        let id = local_account_id.to_owned();
        self.connection.call_immediate_result(move |tx| {
            tx.execute(
                "UPDATE account_app_lock SET presence_device_id = NULL, presence_wrap = NULL
                  WHERE local_account_id = ?1",
                params![id],
            )?;
            Ok::<(), StorageError>(())
        })?
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

    /// Removes the policy row, the hard-lock override and any presence wrap of an erased account.
    pub(crate) fn erase_app_lock(&self, local_account_id: &str) -> Result<(), StorageError> {
        self.connection.execute(
            "DELETE FROM account_app_lock WHERE local_account_id = ?1",
            params![local_account_id],
        )?;
        Ok(())
    }
}

fn checked_timeout(timeout_ms: u64) -> Result<i64, StorageError> {
    if timeout_ms > APP_LOCK_MAX_TIMEOUT_MS {
        return Err(StorageError::Integrity("app lock timeout is out of range"));
    }
    i64::try_from(timeout_ms)
        .map_err(|_| StorageError::Integrity("app lock timeout is out of range"))
}

fn checked_presence(wrap: &AppLockPresenceWrap) -> Result<(), StorageError> {
    if wrap.device_id.is_empty()
        || wrap.wrapped.is_empty()
        || wrap.wrapped.len() > APP_LOCK_PRESENCE_WRAP_MAX_BYTES
    {
        return Err(StorageError::Integrity("app lock presence wrap is out of range"));
    }
    Ok(())
}

fn write_app_lock(
    tx: &rusqlite::Transaction<'_>,
    local_account_id: &str,
    expected: i64,
    change: AppLockChange,
) -> Result<AppLockPolicy, StorageError> {
    let (enabled, timeout_ms, presence, silent) = match change {
        AppLockChange::Enable { timeout_ms, presence } => {
            (true, checked_timeout(timeout_ms)?, presence, None)
        }
        AppLockChange::Disable { timeout_ms, silent } => {
            (false, checked_timeout(timeout_ms)?, None, Some(silent))
        }
    };
    require_account(tx, local_account_id)?;
    let generation = next_generation(tx, local_account_id, expected)?;
    let enabled_flag = i64::from(enabled);
    let (device_id, wrap) = match presence {
        Some(wrap) => (Some(wrap.device_id), Some(wrap.wrapped)),
        None => (None, None),
    };
    tx.execute(
        "INSERT INTO account_app_lock
            (local_account_id, enabled, timeout_ms, generation, presence_device_id, presence_wrap)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)
         ON CONFLICT(local_account_id) DO UPDATE SET
            enabled = excluded.enabled,
            timeout_ms = excluded.timeout_ms,
            generation = excluded.generation,
            presence_device_id = excluded.presence_device_id,
            presence_wrap = excluded.presence_wrap",
        params![local_account_id, enabled_flag, timeout_ms, generation, device_id, wrap],
    )?;
    match silent {
        Some(silent) => store_wrap(tx, local_account_id, &silent)?,
        None => clear_wrap(tx, local_account_id)?,
    }
    let hard_locked = hard_lock_flag(tx, local_account_id)?;
    Ok(AppLockPolicy {
        enabled,
        timeout_ms: u64::try_from(timeout_ms)
            .map_err(|_| StorageError::Integrity("app lock policy is corrupt"))?,
        generation: u64::try_from(generation)
            .map_err(|_| StorageError::Integrity("app lock policy is corrupt"))?,
        hard_locked,
        presence_wrapped: enabled && device_id_present(tx, local_account_id)?,
    })
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

/// Checks the stored generation equals `expected` and returns the next one.
fn next_generation(
    tx: &rusqlite::Transaction<'_>,
    local_account_id: &str,
    expected: i64,
) -> Result<i64, StorageError> {
    let current = tx
        .query_row(
            "SELECT generation FROM account_app_lock WHERE local_account_id = ?1",
            params![local_account_id],
            |row| row.get::<_, i64>(0),
        )
        .optional()?
        .unwrap_or(0);
    if current < 0 {
        return Err(StorageError::Integrity("app lock policy is corrupt"));
    }
    if current != expected {
        return Err(StorageError::Integrity("app lock generation changed"));
    }
    current.checked_add(1).ok_or(StorageError::Integrity("app lock generation overflow"))
}

fn hard_lock_flag(
    tx: &rusqlite::Transaction<'_>,
    local_account_id: &str,
) -> Result<bool, StorageError> {
    let flag = tx
        .query_row(
            "SELECT hard_locked FROM account_app_lock WHERE local_account_id = ?1",
            params![local_account_id],
            |row| row.get::<_, i64>(0),
        )
        .optional()?
        .unwrap_or(0);
    decode_flag(flag)
}

fn device_id_present(
    tx: &rusqlite::Transaction<'_>,
    local_account_id: &str,
) -> Result<bool, StorageError> {
    let present = tx
        .query_row(
            "SELECT presence_wrap IS NOT NULL AND presence_device_id IS NOT NULL
               FROM account_app_lock WHERE local_account_id = ?1",
            params![local_account_id],
            |row| row.get::<_, bool>(0),
        )
        .optional()?;
    Ok(present.unwrap_or(false))
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

fn decode_flag(value: i64) -> Result<bool, StorageError> {
    match value {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(StorageError::Integrity("app lock policy is corrupt")),
    }
}

fn decode_policy(
    enabled: i64,
    timeout_ms: i64,
    generation: i64,
) -> Result<AppLockPolicy, StorageError> {
    let enabled = decode_flag(enabled)?;
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
        hard_locked: false,
        presence_wrapped: false,
    })
}
