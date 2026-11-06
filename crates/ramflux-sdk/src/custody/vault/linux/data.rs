// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Data-only facade; no primary, branch or pending-provisioning read API.
use super::{LinuxPrimaryVault, LinuxVaultConfig, LinuxVaultRole, primary::Realm};
use crate::SdkError;
use std::path::PathBuf;
use zeroize::Zeroizing;

/// Explicit data-unlock adapter, independent of native authority selection.
pub struct LinuxDataCredentials {
    realm: Realm,
    reference: String,
    class: &'static str,
}
impl LinuxDataCredentials {
    /// Open only a data role. No authority KEKs are read.
    /// # Errors
    /// Refuses any other role and unavailable or uncommitted installations.
    pub async fn open(
        root: PathBuf,
        account: String,
        config: LinuxVaultConfig,
    ) -> Result<Self, SdkError> {
        if config.role() != LinuxVaultRole::DataOnly {
            return Err(SdkError::CustodyVaultUnavailable);
        }
        let class = config.mode().strength_class();
        let reference = format!("unlock:{account}");
        let canonical = ramflux_protocol::encode_base64url([0; 32]);
        let realm = LinuxPrimaryVault::open(root, account, canonical, config).await?.take_data()?;
        Ok(Self { realm, reference, class })
    }
    /// Honest strength class of the selected data realm.
    #[must_use]
    pub fn vault_class(&self) -> &'static str {
        self.class
    }
    /// Insert a new saved passphrase; existing entries are never overwritten.
    /// # Errors
    /// Refuses empty or overlong secrets, existing entries and file failures.
    pub fn store_new(&self, secret: &[u8]) -> Result<(), SdkError> {
        self.realm.insert(&self.reference, 4, secret)
    }
    /// Load only the account's saved data-unlock passphrase.
    /// # Errors
    /// Refuses missing, corrupt or transplanted entries.
    pub fn load(&self) -> Result<Zeroizing<Vec<u8>>, SdkError> {
        Ok(Zeroizing::new(self.realm.read(&self.reference, 4)?.bytes().to_vec()))
    }
    /// Delete a saved passphrase. Missing entries succeed.
    /// # Errors
    /// Refuses unsafe files or provider errors.
    pub fn delete(&self) -> Result<(), SdkError> {
        self.realm.delete(&self.reference, 4)
    }
}
