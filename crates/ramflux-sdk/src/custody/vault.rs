// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Non-synchronizing primary credentials; never falls back to the data vault or a file.
use crate::SdkError;
use ramflux_crypto::custody::SelfSigningKey;
use zeroize::Zeroizing;

/// Implementations must be non-synchronizing, primary-local and independent of data unlock.
/// No bus method exposes these credentials; public authority reads do not load them.
pub trait PrimaryVault {
    /// Check provider availability before asking a user to save recovery material.
    /// # Errors
    /// Fails closed when the provider is unsupported, locked or lacks host entitlements.
    fn preflight(&self) -> Result<(), SdkError>;
    /// # Errors
    /// Fails closed on unsupported/locked/unavailable providers and existing entries.
    fn store_new(&self, reference: &str, key: &SelfSigningKey) -> Result<(), SdkError>;
    /// # Errors
    /// Rejects unavailable or corrupt primary credentials. No portable export API exists.
    fn load_primary(&self, reference: &str) -> Result<SelfSigningKey, SdkError>;
    /// Store branch credentials separately from primary authority.
    /// # Errors
    /// Fails closed on provider failure or an existing entry.
    fn store_branch(&self, reference: &str, seeds: &Zeroizing<[u8; 64]>) -> Result<(), SdkError>;
}
/// Software OS credential vault. This is not a nonexportable hardware Ed25519 key.
/// macOS uses its protected, explicitly non-synchronizing keychain. Other platforms
/// fail closed until their primary provider is implemented and reviewed.
#[derive(Clone, Copy, Debug, Default)]
pub struct NativePrimaryVault;
#[cfg(target_os = "macos")]
mod native {
    use super::{SdkError, Zeroizing};
    use security_framework::passwords::{
        PasswordOptions, generic_password, set_generic_password_options,
    };
    const SERVICE: &str = "org.ramflux.identity.primary.v1";
    fn options(reference: &str) -> PasswordOptions {
        let mut options = PasswordOptions::new_generic_password(SERVICE, reference);
        options.use_protected_keychain();
        options.set_access_synchronized(Some(false));
        options
    }
    pub(super) fn preflight() -> Result<(), SdkError> {
        match generic_password(options("provider-availability-probe")) {
            Ok(bytes) => {
                drop(Zeroizing::new(bytes));
                Ok(())
            }
            Err(error) if error.code() == -25300 => Ok(()),
            Err(_) => Err(SdkError::CustodyVaultUnavailable),
        }
    }
    pub(super) fn put(reference: &str, secret: &[u8]) -> Result<(), SdkError> {
        match generic_password(options(reference)) {
            Ok(bytes) => {
                drop(Zeroizing::new(bytes));
                return Err(SdkError::CustodyVaultUnavailable);
            }
            Err(error) if error.code() == -25300 => {}
            Err(_) => return Err(SdkError::CustodyVaultUnavailable),
        }
        let mut insertion = options(reference);
        let access = security_framework::access_control::SecAccessControl::create_with_protection(
            Some(security_framework::access_control::ProtectionMode::AccessibleWhenUnlockedThisDeviceOnly), 0,
        ).map_err(|_|SdkError::CustodyVaultUnavailable)?;
        insertion.set_access_control(access);
        set_generic_password_options(secret, insertion)
            .map_err(|_| SdkError::CustodyVaultUnavailable)
    }
    pub(super) fn get(reference: &str) -> Result<Zeroizing<Vec<u8>>, SdkError> {
        generic_password(options(reference))
            .map(Zeroizing::new)
            .map_err(|_| SdkError::CustodyVaultUnavailable)
    }
}
impl PrimaryVault for NativePrimaryVault {
    fn preflight(&self) -> Result<(), SdkError> {
        #[cfg(target_os = "macos")]
        {
            native::preflight()
        }
        #[cfg(not(target_os = "macos"))]
        {
            Err(SdkError::CustodyVaultUnavailable)
        }
    }
    fn store_new(&self, reference: &str, key: &SelfSigningKey) -> Result<(), SdkError> {
        #[cfg(target_os = "macos")]
        {
            native::put(reference, &*key.vault_seed())
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (reference, key);
            Err(SdkError::CustodyVaultUnavailable)
        }
    }
    fn load_primary(&self, reference: &str) -> Result<SelfSigningKey, SdkError> {
        #[cfg(target_os = "macos")]
        {
            let bytes = native::get(reference)?;
            let mut seed = Zeroizing::new([0; 32]);
            if bytes.len() != 32 {
                return Err(SdkError::CustodyVaultUnavailable);
            }
            seed.copy_from_slice(&bytes);
            Ok(SelfSigningKey::from_vault_seed(&seed))
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = reference;
            Err(SdkError::CustodyVaultUnavailable)
        }
    }
    fn store_branch(&self, reference: &str, seeds: &Zeroizing<[u8; 64]>) -> Result<(), SdkError> {
        #[cfg(target_os = "macos")]
        {
            native::put(reference, &**seeds)
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (reference, seeds);
            Err(SdkError::CustodyVaultUnavailable)
        }
    }
}
