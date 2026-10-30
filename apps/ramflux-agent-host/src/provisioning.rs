// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! One-use participant provisioning into a local credential vault.
use crate::{Error, Result};
use ramflux_sdk::{LocalBusClient, custody::AgentProvisioningBundle};
use std::{io::Read, os::unix::fs::PermissionsExt, path::Path};
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
    let link = std::fs::symlink_metadata(path).map_err(|_| Error::Storage)?;
    if link.file_type().is_symlink() {
        return Err(Error::Config);
    }
    let file = std::fs::File::open(path).map_err(|_| Error::Storage)?;
    let metadata = file.metadata().map_err(|_| Error::Storage)?;
    if !metadata.file_type().is_file() || metadata.permissions().mode() & 0o077 != 0 {
        return Err(Error::Config);
    }
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(MAX_BUNDLE_BYTES + 1).read_to_end(&mut bytes).map_err(|_| Error::Storage)?;
    if bytes.len() > usize::try_from(MAX_BUNDLE_BYTES).map_err(|_| Error::Limit)? {
        return Err(Error::Limit);
    }
    let bundle: AgentProvisioningBundle =
        serde_json::from_slice(&bytes).map_err(|_| Error::Config)?;
    if bundle.account_id != expected_account || bundle.data_passphrase.is_empty() {
        return Err(Error::Config);
    }
    vault.store(&bundle.account_id, &bundle.data_passphrase)?;
    std::fs::remove_file(path).map_err(|_| Error::Storage)
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
}
