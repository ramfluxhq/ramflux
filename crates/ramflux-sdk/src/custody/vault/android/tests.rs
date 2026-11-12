// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Android vault behaviour against a fake Keystore that performs real AES-256-GCM.

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use zeroize::Zeroizing;

use super::blob_store::KeystoreItems;
use super::envelope::{Envelope, MAX_ENVELOPE_LEN, associated_data};
use super::keystore::{
    BridgeError, GCM_IV_LEN, KeyKind, KeystoreBridge, SecurityLevel, StrongBoxPreference, Wrapped,
};
use super::{
    AndroidKeystoreVault, VAULT_CLASS_ANDROID_STRONGBOX, VAULT_CLASS_ANDROID_TEE,
    VAULT_CLASS_ANDROID_UNVERIFIED, VaultHost,
};
use crate::SdkError;
use crate::custody::vault::presence::Items;
use crate::custody::{CustodyVaultReason, PrimaryVault};
use ramflux_crypto::custody::SelfSigningKey;

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[derive(Default)]
struct FakeState {
    keys: HashMap<u8, ([u8; 32], SecurityLevel)>,
    counter: u64,
    presence_granted: bool,
    locked: bool,
    wraps: usize,
    deleted_after_refusal: usize,
}

/// A Keystore double. `generated` is the level the "device" gives a new key for each
/// preference, which lets a test model a device without secure hardware.
struct FakeKeystore {
    tee_level: SecurityLevel,
    strongbox_level: Option<SecurityLevel>,
    prompter: bool,
    state: Mutex<FakeState>,
}

impl FakeKeystore {
    fn device(tee_level: SecurityLevel, strongbox_level: Option<SecurityLevel>) -> Arc<Self> {
        Arc::new(Self { tee_level, strongbox_level, prompter: true, state: Mutex::default() })
    }

    fn state(&self) -> Result<std::sync::MutexGuard<'_, FakeState>, BridgeError> {
        self.state.lock().map_err(|_| BridgeError::Failed)
    }

    fn cipher(&self, kind: KeyKind) -> Result<Aes256Gcm, BridgeError> {
        let state = self.state()?;
        if state.locked {
            return Err(BridgeError::Locked);
        }
        if kind == KeyKind::Presence && !state.presence_granted {
            return Err(BridgeError::PresenceRefused);
        }
        let (key, _) = state.keys.get(&kind.code()).ok_or(BridgeError::KeyMissing)?;
        Aes256Gcm::new_from_slice(key).map_err(|_| BridgeError::Failed)
    }
}

impl KeystoreBridge for FakeKeystore {
    fn ensure_key(
        &self,
        kind: KeyKind,
        strongbox: StrongBoxPreference,
    ) -> Result<SecurityLevel, BridgeError> {
        let mut state = self.state()?;
        if let Some((_, level)) = state.keys.get(&kind.code()) {
            return Ok(*level);
        }
        let level = match (strongbox, self.strongbox_level) {
            (StrongBoxPreference::PreferStrongBox, Some(level)) => level,
            _ => self.tee_level,
        };
        if !level.is_hardware() {
            // The real helper deletes a key that did not land in secure hardware.
            state.deleted_after_refusal += 1;
            return Err(BridgeError::NotHardwareBacked);
        }
        state.counter += 1;
        let mut key = [0_u8; 32];
        key[..8].copy_from_slice(&state.counter.to_be_bytes());
        key[8] = kind.code();
        state.keys.insert(kind.code(), (key, level));
        Ok(level)
    }

    fn key_level(&self, kind: KeyKind) -> Result<SecurityLevel, BridgeError> {
        self.state()?.keys.get(&kind.code()).map(|(_, level)| *level).ok_or(BridgeError::KeyMissing)
    }

    fn wrap(&self, kind: KeyKind, aad: &[u8], plaintext: &[u8]) -> Result<Wrapped, BridgeError> {
        // On a device a wrap with the presence key prompts as well; the fake models the
        // prompt only on unwrap, which is the read the vault's rules depend on.
        let cipher = {
            let state = self.state()?;
            let (key, _) = state.keys.get(&kind.code()).ok_or(BridgeError::KeyMissing)?;
            Aes256Gcm::new_from_slice(key).map_err(|_| BridgeError::Failed)?
        };
        let mut state = self.state()?;
        state.counter += 1;
        state.wraps += 1;
        let mut iv = [0_u8; GCM_IV_LEN];
        iv[..8].copy_from_slice(&state.counter.to_be_bytes());
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&iv), Payload { msg: plaintext, aad })
            .map_err(|_| BridgeError::Failed)?;
        Ok(Wrapped { iv, ciphertext })
    }

    fn unwrap(
        &self,
        kind: KeyKind,
        aad: &[u8],
        wrapped: &Wrapped,
    ) -> Result<Zeroizing<Vec<u8>>, BridgeError> {
        let cipher = self.cipher(kind)?;
        if kind == KeyKind::Presence {
            // One authentication authorizes one use.
            self.state()?.presence_granted = false;
        }
        cipher
            .decrypt(Nonce::from_slice(&wrapped.iv), Payload { msg: &wrapped.ciphertext, aad })
            .map(Zeroizing::new)
            .map_err(|_| BridgeError::Authentication)
    }

    fn presence_available(&self) -> bool {
        self.prompter
    }

    fn delete_key(&self, kind: KeyKind) -> Result<(), BridgeError> {
        self.state()?.keys.remove(&kind.code());
        Ok(())
    }
}

fn vault(
    dir: &Path,
    keystore: &Arc<FakeKeystore>,
    strongbox: StrongBoxPreference,
) -> AndroidKeystoreVault {
    let bridge: Arc<dyn KeystoreBridge> = keystore.clone();
    AndroidKeystoreVault::with_host(VaultHost::new(dir.join("vault"), bridge, strongbox))
}

fn items(dir: &Path, keystore: &Arc<FakeKeystore>) -> KeystoreItems {
    let bridge: Arc<dyn KeystoreBridge> = keystore.clone();
    KeystoreItems::new(dir.join("vault"), bridge, StrongBoxPreference::TeeOnly)
}

fn tee() -> Arc<FakeKeystore> {
    FakeKeystore::device(SecurityLevel::TrustedEnvironment, None)
}

fn primary_key(fill: u8) -> SelfSigningKey {
    SelfSigningKey::from_vault_seed(&Zeroizing::new([fill; 32]))
}

const REFERENCE: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

#[test]
fn primary_seed_round_trips_through_a_hardware_wrapped_entry() -> TestResult {
    let dir = tempfile::tempdir()?;
    let keystore = tee();
    let vault = vault(dir.path(), &keystore, StrongBoxPreference::TeeOnly);
    vault.preflight()?;
    let key = primary_key(7);
    vault.store_new(REFERENCE, &key)?;
    let loaded = vault.load_primary(REFERENCE)?;
    assert_eq!(loaded.public_key(), key.public_key());
    assert_eq!(vault.vault_class(), VAULT_CLASS_ANDROID_TEE);
    Ok(())
}

#[test]
fn stored_entry_never_contains_the_seed_bytes() -> TestResult {
    let dir = tempfile::tempdir()?;
    let keystore = tee();
    let vault = vault(dir.path(), &keystore, StrongBoxPreference::TeeOnly);
    let seed = [0xA5_u8; 32];
    vault.store_new(REFERENCE, &SelfSigningKey::from_vault_seed(&Zeroizing::new(seed)))?;
    let mut entries = 0;
    for entry in std::fs::read_dir(dir.path().join("vault"))? {
        let path = entry?.path();
        let bytes = std::fs::read(&path)?;
        assert!(bytes.len() <= MAX_ENVELOPE_LEN);
        assert!(!bytes.windows(seed.len()).any(|window| window == seed));
        let name = path.file_name().and_then(|name| name.to_str()).unwrap_or_default().to_owned();
        assert!(!name.contains(REFERENCE), "file name leaks the vault reference");
        entries += 1;
    }
    assert_eq!(entries, 1);
    Ok(())
}

#[test]
fn production_code_has_no_software_keystore_fallback() -> TestResult {
    for level in [SecurityLevel::Software, SecurityLevel::Unknown, SecurityLevel::UnknownSecure] {
        let dir = tempfile::tempdir()?;
        let keystore = FakeKeystore::device(level, None);
        let vault = vault(dir.path(), &keystore, StrongBoxPreference::TeeOnly);
        assert!(matches!(vault.preflight(), Err(SdkError::CustodyVaultUnavailable)));
        assert!(matches!(
            vault.store_new(REFERENCE, &primary_key(1)),
            Err(SdkError::CustodyVaultUnavailable)
        ));
        assert!(matches!(
            vault.store_branch("branch:x", &Zeroizing::new([2; 64])),
            Err(SdkError::CustodyVaultUnavailable)
        ));
        assert_eq!(vault.vault_class(), VAULT_CLASS_ANDROID_UNVERIFIED);
        let state = keystore.state().map_err(|_| "poisoned")?;
        assert_eq!(state.wraps, 0, "a non-hardware key wrapped a secret");
        assert!(state.keys.is_empty(), "a non-hardware key was kept");
        assert!(state.deleted_after_refusal > 0);
        drop(state);
        // Nothing was written: no entry, and no plaintext or software-wrapped file.
        let written = std::fs::read_dir(dir.path().join("vault")).map(Iterator::count).unwrap_or(0);
        assert_eq!(written, 0);
    }
    Ok(())
}

#[test]
fn a_key_that_reports_software_after_creation_is_refused_on_read() -> TestResult {
    let dir = tempfile::tempdir()?;
    let keystore = tee();
    let vault = vault(dir.path(), &keystore, StrongBoxPreference::TeeOnly);
    vault.store_new(REFERENCE, &primary_key(3))?;
    if let Some(entry) = keystore.state().map_err(|_| "poisoned")?.keys.get_mut(&0) {
        entry.1 = SecurityLevel::Software;
    }
    assert!(matches!(vault.load_primary(REFERENCE), Err(SdkError::CustodyVaultUnavailable)));
    Ok(())
}

#[test]
fn strongbox_is_opt_in_and_falls_back_to_the_tee_only() -> TestResult {
    let dir = tempfile::tempdir()?;
    let with_strongbox =
        FakeKeystore::device(SecurityLevel::TrustedEnvironment, Some(SecurityLevel::StrongBox));
    let default = vault(dir.path(), &with_strongbox, StrongBoxPreference::TeeOnly);
    default.preflight()?;
    assert_eq!(default.vault_class(), VAULT_CLASS_ANDROID_TEE);

    let dir = tempfile::tempdir()?;
    let with_strongbox =
        FakeKeystore::device(SecurityLevel::TrustedEnvironment, Some(SecurityLevel::StrongBox));
    let opted = vault(dir.path(), &with_strongbox, StrongBoxPreference::PreferStrongBox);
    opted.preflight()?;
    assert_eq!(opted.vault_class(), VAULT_CLASS_ANDROID_STRONGBOX);

    let dir = tempfile::tempdir()?;
    let without = tee();
    let fallback = vault(dir.path(), &without, StrongBoxPreference::PreferStrongBox);
    fallback.preflight()?;
    assert_eq!(fallback.vault_class(), VAULT_CLASS_ANDROID_TEE);
    Ok(())
}

#[test]
fn store_new_refuses_an_existing_entry() -> TestResult {
    let dir = tempfile::tempdir()?;
    let keystore = tee();
    let vault = vault(dir.path(), &keystore, StrongBoxPreference::TeeOnly);
    vault.store_new(REFERENCE, &primary_key(1))?;
    assert!(matches!(
        vault.store_new(REFERENCE, &primary_key(2)),
        Err(SdkError::CustodyVaultUnavailable)
    ));
    assert_eq!(vault.load_primary(REFERENCE)?.public_key(), primary_key(1).public_key());
    Ok(())
}

#[test]
fn orphaned_entry_without_its_keystore_key_fails_closed() -> TestResult {
    let dir = tempfile::tempdir()?;
    let keystore = tee();
    let vault = vault(dir.path(), &keystore, StrongBoxPreference::TeeOnly);
    vault.store_new(REFERENCE, &primary_key(4))?;
    // A device transfer copied the wrapped blob but the Keystore key stayed behind.
    keystore.delete_key(KeyKind::Background).map_err(|_| "delete")?;
    assert!(matches!(
        vault.load_primary(REFERENCE),
        Err(SdkError::CustodyVault(CustodyVaultReason::Missing))
    ));
    // The old identity is not silently replaced by fresh state under the same reference.
    assert!(matches!(
        vault.store_new(REFERENCE, &primary_key(5)),
        Err(SdkError::CustodyVaultUnavailable)
    ));
    Ok(())
}

#[test]
fn entry_moved_to_another_reference_fails_authentication() -> TestResult {
    let dir = tempfile::tempdir()?;
    let keystore = tee();
    let store = items(dir.path(), &keystore);
    assert!(store.insert("branch:one", &[9; 64], false)?);
    assert!(store.insert("branch:two", &[8; 64], false)?);
    let mut paths = Vec::new();
    for entry in std::fs::read_dir(dir.path().join("vault"))? {
        paths.push(entry?.path());
    }
    assert_eq!(paths.len(), 2);
    let first = std::fs::read(&paths[0])?;
    std::fs::write(&paths[1], &first)?;
    let results = [store.read("branch:one", false), store.read("branch:two", false)];
    let corrupt = results
        .iter()
        .filter(|result| matches!(result, Err(SdkError::CustodyVault(CustodyVaultReason::Corrupt))))
        .count();
    assert_eq!(corrupt, 1, "a swapped blob opened under the wrong reference");
    Ok(())
}

#[test]
fn tampered_and_truncated_entries_are_corrupt() -> TestResult {
    let dir = tempfile::tempdir()?;
    let keystore = tee();
    let store = items(dir.path(), &keystore);
    assert!(store.insert("branch:one", &[9; 64], false)?);
    let path = std::fs::read_dir(dir.path().join("vault"))?.next().ok_or("no entry")??.path();
    let original = std::fs::read(&path)?;
    let mut flipped = original.clone();
    if let Some(last) = flipped.last_mut() {
        *last ^= 1;
    }
    std::fs::write(&path, &flipped)?;
    assert!(matches!(
        store.read("branch:one", false),
        Err(SdkError::CustodyVault(CustodyVaultReason::Corrupt))
    ));
    std::fs::write(&path, &original[..original.len() - 1])?;
    assert!(matches!(
        store.read("branch:one", false),
        Err(SdkError::CustodyVault(CustodyVaultReason::Corrupt))
    ));
    std::fs::write(&path, vec![0_u8; MAX_ENVELOPE_LEN + 1])?;
    assert!(matches!(
        store.read("branch:one", false),
        Err(SdkError::CustodyVault(CustodyVaultReason::Corrupt))
    ));
    Ok(())
}

#[test]
fn envelope_rejects_software_level_and_unknown_fields() {
    let wrapped = Wrapped { iv: [1; GCM_IV_LEN], ciphertext: vec![2; 48] };
    let good = Envelope {
        kind: KeyKind::Background,
        level: SecurityLevel::TrustedEnvironment,
        wrapped: wrapped.clone(),
    };
    let encoded = good.encode().unwrap_or_default();
    assert_eq!(Envelope::decode(&encoded), Ok(good));
    for (index, value) in [(4_usize, 2_u8), (5, 9), (6, 0), (6, 3), (6, 4), (0, b'X')] {
        let mut bad = encoded.clone();
        bad[index] = value;
        assert!(Envelope::decode(&bad).is_err(), "byte {index}={value} was accepted");
    }
    let mut trailing = encoded.clone();
    trailing.push(0);
    assert!(Envelope::decode(&trailing).is_err());
    let software = Envelope { kind: KeyKind::Background, level: SecurityLevel::Software, wrapped };
    assert!(software.encode().is_ok_and(|bytes| Envelope::decode(&bytes).is_err()));
    assert_ne!(
        associated_data(KeyKind::Background, SecurityLevel::TrustedEnvironment, "a"),
        associated_data(KeyKind::Presence, SecurityLevel::TrustedEnvironment, "a")
    );
}

#[test]
fn silent_read_never_opens_a_presence_entry() -> TestResult {
    let dir = tempfile::tempdir()?;
    let keystore = tee();
    let store = items(dir.path(), &keystore);
    assert!(store.insert("presence:v1:x", &[5; 32], true)?);
    assert!(matches!(store.read("presence:v1:x", false), Err(SdkError::CustodyVaultUnavailable)));
    // Without a fresh authentication the presence key refuses.
    assert!(matches!(store.read("presence:v1:x", true), Err(SdkError::CustodyVaultUnavailable)));
    keystore.state().map_err(|_| "poisoned")?.presence_granted = true;
    assert_eq!(store.read("presence:v1:x", true)?.map(|bytes| bytes.len()), Some(32));
    // The grant was consumed by that one use.
    assert!(matches!(store.read("presence:v1:x", true), Err(SdkError::CustodyVaultUnavailable)));
    Ok(())
}

#[test]
fn locked_device_reports_locked_and_keeps_the_entry() -> TestResult {
    let dir = tempfile::tempdir()?;
    let keystore = tee();
    let vault = vault(dir.path(), &keystore, StrongBoxPreference::TeeOnly);
    vault.store_new(REFERENCE, &primary_key(6))?;
    keystore.state().map_err(|_| "poisoned")?.locked = true;
    assert!(matches!(
        vault.load_primary(REFERENCE),
        Err(SdkError::CustodyVault(CustodyVaultReason::Locked))
    ));
    keystore.state().map_err(|_| "poisoned")?.locked = false;
    assert_eq!(vault.load_primary(REFERENCE)?.public_key(), primary_key(6).public_key());
    Ok(())
}

#[test]
fn branch_and_provisioning_entries_are_insert_only_and_deletable() -> TestResult {
    let dir = tempfile::tempdir()?;
    let keystore = tee();
    let vault = vault(dir.path(), &keystore, StrongBoxPreference::TeeOnly);
    let seeds = Zeroizing::new([3_u8; 64]);
    vault.store_branch("branch:one", &seeds)?;
    assert!(vault.store_branch("branch:one", &seeds).is_err());
    vault.store_provisioning_secret("agent-provisioning:one", b"passphrase")?;
    assert_eq!(vault.load_provisioning_secret("agent-provisioning:one")?.as_slice(), b"passphrase");
    vault.delete("branch:one")?;
    vault.delete("branch:one")?;
    assert!(vault.store_branch("branch:one", &seeds).is_ok());
    assert!(vault.store_provisioning_secret("empty", b"").is_err());
    assert!(vault.store_provisioning_secret("large", &[0; 1025]).is_err());
    Ok(())
}

#[test]
fn erasing_an_orphaned_vault_removes_entries_and_keys() -> TestResult {
    let dir = tempfile::tempdir()?;
    let keystore = tee();
    let vault = vault(dir.path(), &keystore, StrongBoxPreference::TeeOnly);
    vault.store_new(REFERENCE, &primary_key(4))?;
    vault.store_branch("branch:one", &Zeroizing::new([3_u8; 64]))?;
    vault.erase_orphaned_entries()?;
    assert_eq!(std::fs::read_dir(dir.path().join("vault"))?.count(), 0);
    assert!(keystore.state().map_err(|_| "poisoned")?.keys.is_empty());
    assert!(vault.load_primary(REFERENCE).is_err());
    // A new device identity can be stored afterwards under a fresh wrapping key.
    vault.store_new(REFERENCE, &primary_key(9))?;
    assert_eq!(vault.load_primary(REFERENCE)?.public_key(), primary_key(9).public_key());
    Ok(())
}

#[test]
fn uninstalled_process_vault_fails_closed() {
    // No test installs the process host, so the production entry point is still unarmed.
    let vault = AndroidKeystoreVault::process();
    assert!(matches!(vault.preflight(), Err(SdkError::CustodyVaultUnavailable)));
    assert!(matches!(vault.load_primary(REFERENCE), Err(SdkError::CustodyVaultUnavailable)));
    assert!(matches!(
        vault.store_new(REFERENCE, &primary_key(1)),
        Err(SdkError::CustodyVaultUnavailable)
    ));
    assert_eq!(vault.vault_class(), VAULT_CLASS_ANDROID_UNVERIFIED);
    assert!(vault.home_authorization_preflight().is_err());
}

#[test]
fn provider_sources_name_no_fallback_vault() -> TestResult {
    // The acceptance asks for proof that production Android code cannot reach a software or
    // fixture vault. The provider's own sources must not mention one.
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/custody/vault/android");
    for name in ["mod.rs", "blob_store.rs", "keystore.rs", "envelope.rs", "jni_bridge.rs"] {
        let source = std::fs::read_to_string(dir.join(name))?;
        for forbidden in
            ["MemoryPrimaryVault", "memory_vault", "FileVault::", "aes_gcm", "Aes256Gcm"]
        {
            assert!(!source.contains(forbidden), "{name} references {forbidden}");
        }
    }
    let selector = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("src/bus/custody_setup.rs"),
    )?;
    assert!(selector.contains("AndroidKeystoreVault::process()"));
    Ok(())
}
