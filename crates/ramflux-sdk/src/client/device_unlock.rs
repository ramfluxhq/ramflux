// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Device-held unlock of an account database.
//!
//! A random 32-byte device secret per account lives only in the platform vault. Mixed with the
//! file-held vault secret it forms the device-bound vault secret that both wraps of the database
//! key use: the device wrap (silent unlock at start, switch and after idle) and the code wrap
//! (six-digit account code, Argon2id). Without the device secret neither wrap opens, so the
//! six-digit code is never the only barrier against offline guessing. Code checks are counted
//! durably in the account index and limited here.

use crate::SdkError;
use crate::custody::{DEVICE_UNLOCK_PREFIX, PrimaryVault};
use ramflux_storage::{
    AccountDbKey, AccountIndex, FileVaultSecretSource, StorageError, VaultSecretSource,
    WrappedAccountDbKey, unwrap_with_vault_secret, wrap_with_vault_secret,
};
use std::path::Path;
use zeroize::Zeroizing;

/// Failed code checks that are allowed without a wait.
pub(crate) const FREE_CODE_FAILURES: u32 = 5;
/// Failed code checks after which every code check is refused.
pub(crate) const MAX_CODE_FAILURES: u32 = 10;
/// Wait after the first failure beyond the free ones; it doubles with each further failure.
const FIRST_WAIT_SECS: i64 = 30;

/// Whether a binding creates a new device secret (new account data) or loads the existing one.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeviceSecret {
    /// Create a new device secret (new account data); an earlier item is replaced.
    Create,
    /// Load the existing device secret.
    Load,
}

/// Vault reference of one account's device-unlock secret. The account id never appears in it.
#[must_use]
pub(crate) fn device_unlock_reference(account_id: &str) -> String {
    let id = blake3::derive_key("ramflux.device_unlock.ref.v1", account_id.as_bytes());
    format!("{DEVICE_UNLOCK_PREFIX}{}", ramflux_protocol::encode_base64url(id))
}

/// Vault-secret source whose output needs both the data-root file secret and the device secret.
pub(crate) struct DeviceBoundVaultSecret {
    file: FileVaultSecretSource,
    account_id: String,
    device_secret: Zeroizing<[u8; 32]>,
}

impl DeviceBoundVaultSecret {
    /// Binds `account_id` to its platform-held device secret.
    ///
    /// # Errors
    /// Returns `DeviceUnlockUnavailable` when the vault cannot hold or return the secret.
    pub(crate) fn bind(
        root: &Path,
        vault: &dyn PrimaryVault,
        account_id: &str,
        secret: DeviceSecret,
    ) -> Result<Self, SdkError> {
        let device_secret = match secret {
            DeviceSecret::Create => create_device_secret(vault, account_id)?,
            DeviceSecret::Load => load_or_recall(root, vault, account_id)?,
        };
        #[cfg(test)]
        let device_secret = test_device::reconcile(root, account_id, secret, &device_secret)?;
        Ok(Self {
            file: FileVaultSecretSource::new(root),
            account_id: account_id.to_owned(),
            device_secret,
        })
    }

    /// Read the existing file secret without creating it, for shared read-only access.
    pub(crate) fn existing_secret(&self, root: &Path) -> Result<Zeroizing<[u8; 32]>, SdkError> {
        let file =
            Zeroizing::new(ramflux_storage::read_existing_vault_secret(root, &self.account_id)?);
        let mut hasher = Zeroizing::new(blake3::Hasher::new());
        hasher.update(b"ramflux.account_db_device_bound.v1");
        hasher.update(&*file);
        hasher.update(&*self.device_secret);
        Ok(Zeroizing::new(*hasher.finalize().as_bytes()))
    }
}

impl VaultSecretSource for DeviceBoundVaultSecret {
    fn vault_secret(&self, local_account_id: &str) -> Result<[u8; 32], StorageError> {
        if local_account_id != self.account_id {
            return Err(StorageError::KeyWrappingFailed(
                "device secret is bound to another account".to_owned(),
            ));
        }
        device_bound_secret(&self.file, local_account_id, &self.device_secret)
    }
}

/// `V = BLAKE3("ramflux.account_db_device_bound.v1" || file secret || device secret)`.
fn device_bound_secret(
    file: &FileVaultSecretSource,
    local_account_id: &str,
    device_secret: &[u8; 32],
) -> Result<[u8; 32], StorageError> {
    let file = Zeroizing::new(file.vault_secret(local_account_id)?);
    let mut hasher = Zeroizing::new(blake3::Hasher::new());
    hasher.update(b"ramflux.account_db_device_bound.v1");
    hasher.update(&*file);
    hasher.update(device_secret);
    Ok(*hasher.finalize().as_bytes())
}

fn create_device_secret(
    vault: &dyn PrimaryVault,
    account_id: &str,
) -> Result<Zeroizing<[u8; 32]>, SdkError> {
    let reference = device_unlock_reference(account_id);
    // A leftover item of an earlier account with the same id is replaced; when it cannot be
    // removed, the insert-only store below refuses and creation fails closed.
    if vault.delete(&reference).is_err() {
        tracing::debug!(reason_code = "device_unlock_cleanup", "no earlier device secret removed");
    }
    let mut secret = Zeroizing::new([0_u8; 32]);
    getrandom::fill(&mut *secret).map_err(|_| SdkError::CustodyRandomUnavailable)?;
    vault
        .store_device_unlock_secret(&reference, &secret)
        .map_err(|_| device_unlock_unavailable())?;
    Ok(secret)
}

fn load_device_secret(
    vault: &dyn PrimaryVault,
    account_id: &str,
) -> Result<Zeroizing<[u8; 32]>, SdkError> {
    let bytes = vault
        .load_device_unlock_secret(&device_unlock_reference(account_id))
        .map_err(|_| device_unlock_unavailable())?;
    load_exact(&bytes)
}

fn load_exact(bytes: &[u8]) -> Result<Zeroizing<[u8; 32]>, SdkError> {
    let mut secret = Zeroizing::new([0_u8; 32]);
    if bytes.len() != secret.len() {
        return Err(device_unlock_unavailable());
    }
    secret.copy_from_slice(bytes);
    Ok(secret)
}

#[cfg(not(test))]
fn load_or_recall(
    _root: &Path,
    vault: &dyn PrimaryVault,
    account_id: &str,
) -> Result<Zeroizing<[u8; 32]>, SdkError> {
    load_device_secret(vault, account_id)
}

#[cfg(test)]
fn load_or_recall(
    root: &Path,
    vault: &dyn PrimaryVault,
    account_id: &str,
) -> Result<Zeroizing<[u8; 32]>, SdkError> {
    match load_device_secret(vault, account_id) {
        Ok(secret) => Ok(secret),
        Err(error) => test_device::recall(root, account_id).ok_or(error),
    }
}

/// Fixture builds only: the device-bound vault secret of an account created by an
/// `--itest-memory-vault` daemon, read from that daemon's fixture vault file in `root`.
///
/// # Errors
/// Returns vault, file-secret or binding failures.
#[cfg(feature = "itest-memory-vault")]
pub fn itest_account_vault_secret(root: &Path, account_id: &str) -> Result<[u8; 32], SdkError> {
    let vault =
        crate::custody::MemoryPrimaryVault::persist_at(root.join("itest-memory-vault.json"))?;
    let source = DeviceBoundVaultSecret::bind(root, &vault, account_id, DeviceSecret::Load)?;
    Ok(source.vault_secret(account_id)?)
}

/// Removes an account's device secret (account data discarded). Missing items succeed.
///
/// # Errors
/// Returns provider failures.
pub(crate) fn delete_device_secret(
    vault: &dyn PrimaryVault,
    account_id: &str,
) -> Result<(), SdkError> {
    vault.delete(&device_unlock_reference(account_id))
}

pub(crate) fn device_key_encryption_key(vault_secret: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    Zeroizing::new(blake3::derive_key("ramflux.account_db_device_kek.v1", vault_secret))
}

/// Writes (or replaces) the device wrap of `key` under the device-bound vault secret.
///
/// # Errors
/// Returns wrapping or index errors.
pub(crate) fn store_device_wrap(
    index: &AccountIndex,
    account_id: &str,
    vault_secret: &[u8; 32],
    key: &AccountDbKey,
) -> Result<(), SdkError> {
    index.store_device_wrapped_db_key(
        account_id,
        &wrapped_device_key(account_id, vault_secret, key)?,
    )?;
    Ok(())
}

/// Builds the device wrap without writing it.
///
/// # Errors
/// Returns an error when the key cannot be wrapped.
pub(crate) fn wrapped_device_key(
    account_id: &str,
    vault_secret: &[u8; 32],
    key: &AccountDbKey,
) -> Result<WrappedAccountDbKey, SdkError> {
    let kek = device_key_encryption_key(vault_secret);
    let (nonce, wrapped_key) = wrap_with_vault_secret(&kek, key.bytes())?;
    Ok(WrappedAccountDbKey {
        key_wrapping_provider: "platform-device-unlock".to_owned(),
        key_wrapping_ref: device_unlock_reference(account_id),
        nonce,
        wrapped_key,
    })
}

/// Opens the device wrap. An account without one (explicitly locked) needs its code.
///
/// # Errors
/// `AccountCodeRequired` without a device wrap; integrity errors for a wrong device secret.
pub(crate) fn open_device_wrap(
    index: &AccountIndex,
    account_id: &str,
    vault_secret: &[u8; 32],
) -> Result<AccountDbKey, SdkError> {
    let wrapped =
        index.load_device_wrapped_db_key(account_id)?.ok_or_else(account_code_required)?;
    Ok(unwrap_with_vault_secret(&device_key_encryption_key(vault_secret), &wrapped)?)
}

/// Admits one code check and counts it as failed before it runs.
///
/// # Errors
/// `UnlockAttemptsExhausted` after [`MAX_CODE_FAILURES`]; `UnlockRetryLater` during a wait.
pub(crate) fn guard_code_attempt(index: &AccountIndex, account_id: &str) -> Result<(), SdkError> {
    let now = ramflux_storage::unix_now();
    let attempts = index.code_attempts(account_id)?;
    if attempts.failures >= MAX_CODE_FAILURES {
        return Err(refusal(
            "UnlockAttemptsExhausted",
            "too many wrong account codes; restore the account from its recovery phrase",
            serde_json::json!({"reason_code": "unlock_attempts_exhausted"}),
        ));
    }
    if attempts.failures >= FREE_CODE_FAILURES {
        let doublings = attempts.failures.saturating_sub(FREE_CODE_FAILURES).min(16);
        let wait = FIRST_WAIT_SECS.checked_shl(doublings).unwrap_or(i64::MAX);
        let ready_at = attempts.last_attempt_at.unwrap_or(0).saturating_add(wait);
        if now < ready_at {
            let retry_after_secs = ready_at.saturating_sub(now);
            let retry_after_ms =
                u64::try_from(retry_after_secs).map_or(0, |wait| wait.saturating_mul(1_000));
            return Err(refusal(
                "UnlockRetryLater",
                "too many wrong account codes; wait before the next try",
                serde_json::json!({
                    "reason_code": "unlock_retry_later",
                    "retry_after_secs": retry_after_secs,
                    "retry_after_ms": retry_after_ms,
                }),
            ));
        }
    }
    index.begin_code_attempt(account_id, now)?;
    Ok(())
}

/// Clears the failure count after a correct code.
///
/// # Errors
/// Returns index errors.
pub(crate) fn code_attempt_succeeded(
    index: &AccountIndex,
    account_id: &str,
) -> Result<(), SdkError> {
    index.reset_code_attempts(account_id)?;
    Ok(())
}

/// The platform vault holds no usable device secret for the account.
#[must_use]
pub(crate) fn device_unlock_unavailable() -> SdkError {
    refusal(
        "DeviceUnlockUnavailable",
        "the platform vault holds no device unlock secret for this account",
        serde_json::json!({"reason_code": "device_unlock_unavailable"}),
    )
}

/// The account was explicitly locked; only its code opens it.
#[must_use]
pub(crate) fn account_code_required() -> SdkError {
    refusal(
        "AccountCodeRequired",
        "this account is locked; enter its account code",
        serde_json::json!({"reason_code": "account_code_required"}),
    )
}

fn refusal(code: &str, message: &str, body: serde_json::Value) -> SdkError {
    SdkError::LocalBusRefused { code: code.into(), message: message.into(), body: Box::new(body) }
}

/// Unit-test device model: a client opened without a vault runs on a device whose vault holds
/// one device secret per (data root, native account), shared with any vault-bound client in
/// the same process. Production clients always bind a real vault; this module does not exist there.
#[cfg(test)]
#[path = "device_unlock_test_device.rs"]
pub(crate) mod test_device;
