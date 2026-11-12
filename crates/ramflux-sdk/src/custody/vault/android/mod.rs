// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Android primary vault: seeds wrapped by a hardware-backed Android Keystore key.
//!
//! The Keystore never holds a seed. It holds an AES-256-GCM key that cannot leave the TEE or
//! `StrongBox`, and each vault entry is one owner-only file under the application's
//! no-backup directory containing the seed encrypted by that key. A key the platform does
//! not report as hardware-backed is refused and deleted: there is no software fallback, no
//! file fallback and no in-memory fallback in this provider.
//!
//! The module also builds for host tests, where a fake stands in for the Keystore.
#![cfg_attr(not(target_os = "android"), allow(dead_code))]

mod blob_store;
pub(crate) mod envelope;
#[cfg(target_os = "android")]
mod jni_bridge;
pub(crate) mod keystore;

use std::path::PathBuf;
use std::sync::{Arc, OnceLock};

use ramflux_crypto::custody::SelfSigningKey;
use zeroize::Zeroizing;

use self::blob_store::KeystoreItems;
use self::keystore::{BridgeError, KeyKind, KeystoreBridge, SecurityLevel, StrongBoxPreference};
use super::{BranchCredentials, HomeAuthorizationRequest, PrimaryVault, presence, primary_items};
use crate::SdkError;
use crate::custody::CustodyVaultReason;

/// Seeds wrapped by an Android Keystore key held in the Trusted Execution Environment.
pub const VAULT_CLASS_ANDROID_TEE: &str = "hardware_wrapped_android_keystore_tee";
/// Seeds wrapped by an Android Keystore key held in a `StrongBox` secure element.
pub const VAULT_CLASS_ANDROID_STRONGBOX: &str = "hardware_wrapped_android_keystore_strongbox";
/// The wrapping key's level could not be read. No store succeeds in this state; the class
/// exists so that a record never claims hardware it did not observe.
pub const VAULT_CLASS_ANDROID_UNVERIFIED: &str = "android_keystore_unverified";

const PROBE_REFERENCE: &str = "provider-availability-probe";

/// What the host application hands the vault once per process.
pub(crate) struct VaultHost {
    items: KeystoreItems,
}

impl VaultHost {
    pub(crate) fn new(
        vault_dir: PathBuf,
        bridge: Arc<dyn KeystoreBridge>,
        strongbox: StrongBoxPreference,
    ) -> Self {
        Self { items: KeystoreItems::new(vault_dir, bridge, strongbox) }
    }
}

static PROCESS_HOST: OnceLock<Arc<VaultHost>> = OnceLock::new();

/// Install the process-wide vault host. The first installation wins; a second call with any
/// arguments is refused so a later caller cannot redirect the vault directory.
///
/// # Errors
/// `CustodyVaultUnavailable` when a host is already installed.
pub(crate) fn install_process_host(host: VaultHost) -> Result<(), SdkError> {
    PROCESS_HOST.set(Arc::new(host)).map_err(|_| SdkError::CustodyVaultUnavailable)
}

/// Install the Android Keystore vault for this process.
///
/// `vault_dir` must be the directory returned by
/// [`crate::platform::android::AndroidStorage::vault_dir`]. `prefer_strongbox` opts in to a
/// `StrongBox` key with a fallback to the TEE; it never permits a software key.
///
/// # Errors
/// `CustodyVaultUnavailable` when the Kotlin helper has not registered itself, or a vault is
/// already installed.
#[cfg(target_os = "android")]
pub fn install_android_vault(vault_dir: PathBuf, prefer_strongbox: bool) -> Result<(), SdkError> {
    let bridge = jni_bridge::JniKeystore::from_registered().map_err(refuse)?;
    let strongbox = if prefer_strongbox {
        StrongBoxPreference::PreferStrongBox
    } else {
        StrongBoxPreference::TeeOnly
    };
    install_process_host(VaultHost::new(vault_dir, Arc::new(bridge), strongbox))
}

/// Map a Keystore refusal onto the vault's fail-closed errors.
pub(crate) fn refuse(error: BridgeError) -> SdkError {
    match error {
        // A blob whose wrapping key is gone is an orphan (§7): never mint fresh state.
        BridgeError::KeyMissing => SdkError::CustodyVault(CustodyVaultReason::Missing),
        BridgeError::Locked => SdkError::CustodyVault(CustodyVaultReason::Locked),
        BridgeError::Authentication => SdkError::CustodyVault(CustodyVaultReason::Corrupt),
        BridgeError::NotInstalled
        | BridgeError::NotHardwareBacked
        | BridgeError::PresenceRefused
        | BridgeError::Failed => SdkError::CustodyVaultUnavailable,
    }
}

/// Primary vault backed by the Android Keystore. Fails closed until the host installed it.
#[derive(Clone, Default)]
pub struct AndroidKeystoreVault {
    host: Option<Arc<VaultHost>>,
}

impl std::fmt::Debug for AndroidKeystoreVault {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("AndroidKeystoreVault").finish_non_exhaustive()
    }
}

impl AndroidKeystoreVault {
    /// The vault installed for this process by the host application.
    #[must_use]
    pub const fn process() -> Self {
        Self { host: None }
    }

    /// A vault over an explicit host, for tests with a fake Keystore.
    #[cfg(test)]
    pub(crate) fn with_host(host: VaultHost) -> Self {
        Self { host: Some(Arc::new(host)) }
    }

    fn items(&self) -> Result<&KeystoreItems, SdkError> {
        match &self.host {
            Some(host) => Ok(&host.items),
            None => PROCESS_HOST
                .get()
                .map(|host| &host.items)
                .ok_or(SdkError::CustodyVaultUnavailable),
        }
    }

    fn background_level(&self) -> Result<SecurityLevel, SdkError> {
        let level = self.items()?.bridge().key_level(KeyKind::Background).map_err(refuse)?;
        keystore::require_hardware(level).map_err(refuse)
    }

    fn insert_new(&self, reference: &str, secret: &[u8]) -> Result<(), SdkError> {
        use presence::Items as _;
        if !self.items()?.insert(reference, secret, false)? {
            return Err(SdkError::CustodyVaultUnavailable);
        }
        Ok(())
    }

    fn read_existing(&self, reference: &str) -> Result<Zeroizing<Vec<u8>>, SdkError> {
        use presence::Items as _;
        self.items()?.read(reference, false)?.ok_or(SdkError::CustodyVaultUnavailable)
    }
}

impl PrimaryVault for AndroidKeystoreVault {
    fn vault_class(&self) -> &'static str {
        match self.background_level() {
            Ok(SecurityLevel::StrongBox) => VAULT_CLASS_ANDROID_STRONGBOX,
            Ok(SecurityLevel::TrustedEnvironment) => VAULT_CLASS_ANDROID_TEE,
            _ => VAULT_CLASS_ANDROID_UNVERIFIED,
        }
    }

    /// Creates the wrapping key when absent, refuses a key outside secure hardware, and
    /// completes one wrap and unwrap round trip before reporting the provider usable.
    fn preflight(&self) -> Result<(), SdkError> {
        let items = self.items()?;
        items.prepare_directory()?;
        let level = items.ensure_hardware_key(KeyKind::Background)?;
        let aad = envelope::associated_data(KeyKind::Background, level, PROBE_REFERENCE);
        let bridge = items.bridge();
        let wrapped = bridge.wrap(KeyKind::Background, &aad, b"probe").map_err(refuse)?;
        let opened = bridge.unwrap(KeyKind::Background, &aad, &wrapped).map_err(refuse)?;
        if opened.as_slice() == b"probe" { Ok(()) } else { Err(SdkError::CustodyVaultUnavailable) }
    }

    fn store_new(&self, reference: &str, key: &SelfSigningKey) -> Result<(), SdkError> {
        primary_items::store(self.items()?, reference, &*key.vault_seed())
    }

    fn load_primary(&self, reference: &str) -> Result<SelfSigningKey, SdkError> {
        let bytes = primary_items::load(self.items()?, reference)?;
        if bytes.len() != 32 {
            return Err(SdkError::CustodyVaultUnavailable);
        }
        let mut seed = Zeroizing::new([0; 32]);
        seed.copy_from_slice(&bytes);
        Ok(SelfSigningKey::from_vault_seed(&seed))
    }

    fn home_authorization_preflight(&self) -> Result<(), SdkError> {
        let unavailable = crate::custody::home_authorization::unavailable;
        let items = self.items().map_err(|_| unavailable())?;
        self.background_level().map_err(|_| unavailable())?;
        if items.bridge().presence_available() { Ok(()) } else { Err(unavailable()) }
    }

    fn sign_home_authorization(
        &self,
        request: HomeAuthorizationRequest<'_>,
    ) -> Result<
        ramflux_protocol::home_migration::Signed<ramflux_protocol::home_migration::Authorization>,
        SdkError,
    > {
        let items =
            self.items().map_err(|_| crate::custody::home_authorization::unavailable())?;
        // The presence item is wrapped by the authentication-bound key, so this read cannot
        // complete without a fresh user authentication enforced by the Keystore.
        let primary = presence::approved_primary(
            items,
            request.primary_reference(),
            request.expected_primary_public_key(),
        )?;
        let now = crate::custody::home_authorization::now()?.max(request.requested_at);
        request.sign_once(&primary, now)
    }

    fn load_branch(
        &self,
        reference: &str,
        principal: &str,
        device: &ramflux_protocol::custody::DeviceRef,
    ) -> Result<BranchCredentials, SdkError> {
        let bytes = self.read_existing(reference)?;
        if bytes.len() != 64 {
            return Err(SdkError::CustodyVaultUnavailable);
        }
        let mut seeds = Zeroizing::new([0; 64]);
        seeds.copy_from_slice(&bytes);
        BranchCredentials::from_vault_seeds(principal, device, &seeds)
    }

    fn delete(&self, reference: &str) -> Result<(), SdkError> {
        if reference.starts_with(ramflux_storage::FileVaultSecretSource::OWNER_PREFIX) {
            return Ok(());
        }
        primary_items::delete(self.items()?, reference)
    }

    fn store_branch(&self, reference: &str, seeds: &Zeroizing<[u8; 64]>) -> Result<(), SdkError> {
        self.insert_new(reference, &**seeds)
    }

    fn store_provisioning_secret(&self, reference: &str, secret: &[u8]) -> Result<(), SdkError> {
        self.insert_new(reference, secret)
    }

    fn load_provisioning_secret(&self, reference: &str) -> Result<Zeroizing<Vec<u8>>, SdkError> {
        self.read_existing(reference)
    }
}

#[cfg(test)]
mod tests;
