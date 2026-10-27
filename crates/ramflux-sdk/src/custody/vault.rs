// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Non-synchronizing primary credentials; never falls back to the data vault or a file.
use super::HomeAuthorizationRequest;
use crate::SdkError;
use ramflux_crypto::custody::SelfSigningKey;
use zeroize::Zeroizing;

/// Implementations must be non-synchronizing, primary-local and independent of data unlock.
/// No bus method exposes these credentials; public authority reads do not load them.
pub trait PrimaryVault: Send + Sync {
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
    /// Sign a stored migration proposal after enforcing independent user presence.
    /// # Errors
    /// The default refuses: a data unlock or an existing load_primary implementation is insufficient.
    fn sign_home_authorization(
        &self,
        _request: HomeAuthorizationRequest<'_>,
    ) -> Result<
        ramflux_protocol::home_migration::Signed<ramflux_protocol::home_migration::Authorization>,
        SdkError,
    > {
        Err(super::home_authorization::unavailable())
    }
    /// Load only the branch credential for network possession; never loads master authority.
    /// # Errors
    /// Rejects unsupported providers and missing/corrupt branch entries.
    fn load_branch(
        &self,
        _reference: &str,
        _principal: &str,
        _device: &ramflux_protocol::custody::DeviceRef,
    ) -> Result<BranchCredentials, SdkError> {
        Err(SdkError::CustodyVaultUnavailable)
    }
    /// Remove a credential written by an incomplete creation attempt. Missing entries succeed.
    /// # Errors
    /// Returns provider failures; callers retain the fail-closed account reservation.
    fn delete(&self, reference: &str) -> Result<(), SdkError>;
    /// Store branch credentials separately from primary authority.
    /// # Errors
    /// Fails closed on provider failure or an existing entry.
    fn store_branch(&self, reference: &str, seeds: &Zeroizing<[u8; 64]>) -> Result<(), SdkError>;
    /// Store the one-use local data passphrase for a headless participant until its custodian
    /// exports the provisioning bundle. This secret is independent of primary and branch keys.
    /// # Errors
    /// Fails closed on unsupported providers, an existing entry, or provider failure.
    fn store_provisioning_secret(&self, _reference: &str, _secret: &[u8]) -> Result<(), SdkError> {
        Err(SdkError::CustodyVaultUnavailable)
    }
    /// Load the pending headless-participant data passphrase without exposing authority keys.
    /// # Errors
    /// Rejects unsupported providers and missing or corrupt entries.
    fn load_provisioning_secret(&self, _reference: &str) -> Result<Zeroizing<Vec<u8>>, SdkError> {
        Err(SdkError::CustodyVaultUnavailable)
    }
}
/// Software OS credential vault. This is not a nonexportable hardware Ed25519 key.
/// macOS uses its protected, explicitly non-synchronizing keychain. Other platforms
/// fail closed until their primary provider is implemented and reviewed.
#[derive(Clone, Copy, Debug, Default)]
pub struct NativePrimaryVault;
#[cfg(target_os = "macos")]
mod native;
#[cfg(any(target_os = "macos", test))]
mod presence;
impl PrimaryVault for NativePrimaryVault {
    fn sign_home_authorization(
        &self,
        request: HomeAuthorizationRequest<'_>,
    ) -> Result<
        ramflux_protocol::home_migration::Signed<ramflux_protocol::home_migration::Authorization>,
        SdkError,
    > {
        #[cfg(target_os = "macos")]
        {
            let primary = presence::approved_primary(
                &native::KeychainItems,
                request.primary_reference(),
                request.expected_primary_public_key(),
            )?;
            let now = super::home_authorization::now()?.max(request.requested_at);
            request.sign_once(&primary, now)
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = request;
            Err(super::home_authorization::unavailable())
        }
    }
    fn delete(&self, reference: &str) -> Result<(), SdkError> {
        #[cfg(target_os = "macos")]
        {
            native::delete(reference)
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = reference;
            Err(SdkError::CustodyVaultUnavailable)
        }
    }
    fn load_branch(
        &self,
        reference: &str,
        principal: &str,
        device: &ramflux_protocol::custody::DeviceRef,
    ) -> Result<BranchCredentials, SdkError> {
        #[cfg(target_os = "macos")]
        {
            let bytes = native::get_branch(reference)?;
            let mut seeds = Zeroizing::new([0; 64]);
            if bytes.len() != 64 {
                return Err(SdkError::CustodyVaultUnavailable);
            }
            seeds.copy_from_slice(&bytes);
            BranchCredentials::from_vault_seeds(principal, device, &seeds)
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (reference, principal, device);
            Err(SdkError::CustodyVaultUnavailable)
        }
    }

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
            native::store_primary(reference, &*key.vault_seed())
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
            let bytes = native::get_primary(reference)?;
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
            native::store_branch(reference, &**seeds)
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (reference, seeds);
            Err(SdkError::CustodyVaultUnavailable)
        }
    }
    fn store_provisioning_secret(&self, reference: &str, secret: &[u8]) -> Result<(), SdkError> {
        #[cfg(target_os = "macos")]
        {
            native::put(reference, secret)
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (reference, secret);
            Err(SdkError::CustodyVaultUnavailable)
        }
    }
    fn load_provisioning_secret(&self, reference: &str) -> Result<Zeroizing<Vec<u8>>, SdkError> {
        #[cfg(target_os = "macos")]
        {
            native::get(reference)
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = reference;
            Err(SdkError::CustodyVaultUnavailable)
        }
    }
}

/// Branch credentials do not expose a portable export API.
#[derive(Debug)]
pub struct BranchCredentials {
    pub(crate) signing: ramflux_crypto::DeviceBranch,
    pub(crate) agreement: ramflux_crypto::X25519KeyPair,
}
impl BranchCredentials {
    pub(crate) fn signed_prekey_seed(&self) -> Zeroizing<[u8; 32]> {
        // Stable branch-only bootstrap material. Bootstrap forward secrecy requires
        // rotating random prekeys and erasure; tracked separately from identity custody.
        let secret = Zeroizing::new(self.agreement.secret.to_bytes());
        Zeroizing::new(ramflux_crypto::blake3_keyed_derive(
            &secret,
            b"ramflux.identity.custody_signed_prekey.v1",
        ))
    }

    pub(crate) fn prekey_bundle(&self) -> Result<ramflux_crypto::PrekeyBundle, SdkError> {
        let signed = ramflux_crypto::X25519KeyPair::from_seed(*self.signed_prekey_seed());
        Ok(ramflux_crypto::create_prekey_bundle(
            &self.signing,
            &self.agreement,
            "custody-prekey-v1",
            &signed,
            None,
            None,
        )?)
    }

    /// Provider boundary for a branch-only entry, separate from primary credentials.
    /// # Errors
    /// Rejects invalid device names and zero epochs.
    pub fn from_vault_seeds(
        principal: &str,
        device: &ramflux_protocol::custody::DeviceRef,
        seeds: &Zeroizing<[u8; 64]>,
    ) -> Result<Self, SdkError> {
        ramflux_protocol::validate_device_name(&device.device_id)?;
        if device.device_epoch == 0 {
            return Err(SdkError::CustodySetupInvalid);
        }
        let mut signing = Zeroizing::new([0; 32]);
        let mut agreement = Zeroizing::new([0; 32]);
        signing.copy_from_slice(&seeds[..32]);
        agreement.copy_from_slice(&seeds[32..]);
        Ok(Self {
            signing: ramflux_crypto::create_device_branch(
                principal,
                &device.device_id,
                device.device_epoch,
                *signing,
            ),
            agreement: ramflux_crypto::X25519KeyPair::from_seed(*agreement),
        })
    }
}
