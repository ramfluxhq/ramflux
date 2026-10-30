// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! One-use participant provisioning into a local credential vault.
use crate::{Error, Result};
use ramflux_sdk::{LocalBusClient, custody::AgentProvisioningBundle};
use std::{
    fs::OpenOptions,
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::Path,
};
use zeroize::Zeroizing;

const MAX_BUNDLE_BYTES: u64 = 8192;
#[cfg(target_os = "macos")]
const KEYCHAIN_SERVICE: &str = "ramflux";

/// Production credentials use the operator Mac keychain. The memory variant is integration-only.
pub enum CredentialVault {
    #[cfg(target_os = "macos")]
    Keychain,
    #[cfg(feature = "itest-memory-vault")]
    Memory(std::sync::Mutex<Option<(String, Zeroizing<String>)>>),
    Unsupported,
}

impl CredentialVault {
    /// Select the production OS provider.
    #[must_use]
    pub const fn production() -> Self {
        #[cfg(target_os = "macos")]
        {
            Self::Keychain
        }
        #[cfg(not(target_os = "macos"))]
        {
            Self::Unsupported
        }
    }

    /// Select the explicitly integration-only volatile provider.
    #[cfg(feature = "itest-memory-vault")]
    #[must_use]
    pub const fn itest_memory() -> Self {
        Self::Memory(std::sync::Mutex::new(None))
    }

    fn store(&self, account: &str, passphrase: &str) -> Result<()> {
        #[cfg(not(any(target_os = "macos", feature = "itest-memory-vault")))]
        let _ = (account, passphrase);
        match self {
            #[cfg(target_os = "macos")]
            Self::Keychain => {
                let entry =
                    keyring::Entry::new(KEYCHAIN_SERVICE, account).map_err(|_| Error::Storage)?;
                match entry.get_password() {
                    Err(keyring::Error::NoEntry) => {}
                    Ok(_) | Err(_) => return Err(Error::Storage),
                }
                entry.set_password(passphrase).map_err(|_| Error::Storage)
            }
            #[cfg(feature = "itest-memory-vault")]
            Self::Memory(value) => {
                let mut value = value.lock().map_err(|_| Error::Storage)?;
                if value.is_some() {
                    return Err(Error::Storage);
                }
                *value = Some((account.to_owned(), Zeroizing::new(passphrase.to_owned())));
                Ok(())
            }
            Self::Unsupported => Err(Error::Storage),
        }
    }

    fn load(&self, account: &str) -> Result<Option<Zeroizing<String>>> {
        #[cfg(not(any(target_os = "macos", feature = "itest-memory-vault")))]
        let _ = account;
        match self {
            #[cfg(target_os = "macos")]
            Self::Keychain => {
                let entry =
                    keyring::Entry::new(KEYCHAIN_SERVICE, account).map_err(|_| Error::Storage)?;
                match entry.get_password() {
                    Ok(secret) => Ok(Some(Zeroizing::new(secret))),
                    Err(keyring::Error::NoEntry) => Ok(None),
                    Err(_) => Err(Error::Storage),
                }
            }
            #[cfg(feature = "itest-memory-vault")]
            Self::Memory(value) => {
                let value = value.lock().map_err(|_| Error::Storage)?;
                Ok(value
                    .as_ref()
                    .filter(|(stored_account, _)| stored_account == account)
                    .map(|(_, secret)| secret.clone()))
            }
            Self::Unsupported => Ok(None),
        }
    }
}

/// Import a private one-use file into the selected vault, then remove the file.
/// # Errors
/// Rejects symlinks, non-private permissions, oversized or malformed content, account mismatch,
/// unavailable vaults, and failed file removal.
pub fn import_provisioning_bundle(
    vault: &CredentialVault,
    path: &Path,
    expected_account: &str,
) -> Result<()> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| Error::Storage)?;
    let metadata = file.metadata().map_err(|_| Error::Storage)?;
    if !metadata.file_type().is_file()
        || metadata.permissions().mode() & 0o077 != 0
        || metadata.uid() != rustix::process::geteuid().as_raw()
    {
        let _ = file.set_permissions(std::fs::Permissions::from_mode(0o0));
        return Err(Error::Config);
    }
    let link = std::fs::symlink_metadata(path).map_err(|_| Error::Storage)?;
    if link.file_type().is_symlink() || link.dev() != metadata.dev() || link.ino() != metadata.ino()
    {
        let _ = file.set_permissions(std::fs::Permissions::from_mode(0o0));
        return Err(Error::Config);
    }
    let mut bytes = Zeroizing::new(Vec::new());
    let read = (&mut file).take(MAX_BUNDLE_BYTES + 1).read_to_end(&mut bytes);
    // Consume the only on-disk copy before parsing or touching the destination vault. This makes
    // malformed, mismatched, unsupported-vault and vault-write failures fail closed as well.
    if std::fs::remove_file(path).is_err() {
        let _ = file.set_permissions(std::fs::Permissions::from_mode(0o0));
        return Err(Error::Storage);
    }
    read.map_err(|_| Error::Storage)?;
    if bytes.len() > usize::try_from(MAX_BUNDLE_BYTES).map_err(|_| Error::Limit)? {
        return Err(Error::Limit);
    }
    let bundle: AgentProvisioningBundle =
        serde_json::from_slice(&bytes).map_err(|_| Error::Config)?;
    if bundle.account_id != expected_account || bundle.data_passphrase.is_empty() {
        return Err(Error::Config);
    }
    vault.store(&bundle.account_id, &bundle.data_passphrase)
}

/// Unlock an imported account before the host starts consuming participant traffic.
/// # Errors
/// Returns vault or local-bus failures without exposing credentials.
pub async fn unlock_provisioned_account(
    vault: &CredentialVault,
    socket: &Path,
    account: &str,
) -> Result<()> {
    let Some(passphrase) = vault.load(account)? else {
        return Ok(());
    };
    let mut bus = LocalBusClient::connect(socket).await.map_err(|_| Error::Bus)?;
    bus.request(
        Some(account.to_owned()),
        "account",
        "account.unlock",
        serde_json::json!({"passphrase":passphrase.as_str()}),
    )
    .await
    .map_err(|_| Error::Bus)?;
    Ok(())
}

#[cfg(all(test, feature = "itest-memory-vault"))]
mod tests {
    use super::*;
    use std::os::unix::fs::OpenOptionsExt;

    #[test]
    fn fifo_bundle_is_refused_without_waiting_for_a_writer() -> Result<()> {
        let root = tempfile::tempdir().map_err(|_| Error::Storage)?;
        let path = root.path().join("fifo.bundle");
        let status =
            std::process::Command::new("mkfifo").arg(&path).status().map_err(|_| Error::Storage)?;
        assert!(status.success());
        let started = std::time::Instant::now();
        assert!(matches!(
            import_provisioning_bundle(&CredentialVault::itest_memory(), &path, "agent"),
            Err(Error::Config)
        ));
        assert!(started.elapsed() < std::time::Duration::from_secs(1));
        Ok(())
    }

    #[test]
    fn private_bundle_imports_once_and_is_removed() -> Result<()> {
        let root = tempfile::tempdir().map_err(|_| Error::Storage)?;
        let path = root.path().join("agent.bundle");
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .map_err(|_| Error::Storage)?;
        std::io::Write::write_all(
            &mut file,
            br#"{"account_id":"agent","data_passphrase":"private"}"#,
        )
        .map_err(|_| Error::Storage)?;
        drop(file);
        let vault = CredentialVault::itest_memory();
        import_provisioning_bundle(&vault, &path, "agent")?;
        assert!(!path.exists());
        assert_eq!(vault.load("agent")?.as_ref().map(|secret| secret.as_str()), Some("private"));
        Ok(())
    }

    #[test]
    fn failed_bundle_import_is_consumed_and_symlinks_are_refused() -> Result<()> {
        let root = tempfile::tempdir().map_err(|_| Error::Storage)?;
        let target = root.path().join("target.bundle");
        std::fs::write(&target, b"not-json").map_err(|_| Error::Storage)?;
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600))
            .map_err(|_| Error::Storage)?;
        let link = root.path().join("link.bundle");
        std::os::unix::fs::symlink(&target, &link).map_err(|_| Error::Storage)?;
        let vault = CredentialVault::itest_memory();
        assert!(matches!(import_provisioning_bundle(&vault, &link, "agent"), Err(Error::Storage)));
        assert!(target.exists());
        assert!(matches!(import_provisioning_bundle(&vault, &target, "agent"), Err(Error::Config)));
        assert!(!target.exists());

        let mismatch = root.path().join("mismatch.bundle");
        std::fs::write(&mismatch, br#"{"account_id":"other","data_passphrase":"private"}"#)
            .map_err(|_| Error::Storage)?;
        std::fs::set_permissions(&mismatch, std::fs::Permissions::from_mode(0o600))
            .map_err(|_| Error::Storage)?;
        assert!(matches!(
            import_provisioning_bundle(&vault, &mismatch, "agent"),
            Err(Error::Config)
        ));
        assert!(!mismatch.exists());
        Ok(())
    }
}
