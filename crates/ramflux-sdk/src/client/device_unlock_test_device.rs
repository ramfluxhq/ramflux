// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Unit-test device model: a client opened without a vault runs on a device whose vault holds
//! one device secret per (data root, native account), shared with any vault-bound client in
//! the same process. Production clients always bind a real vault; this module does not exist there.
use super::{DeviceSecret, FileVaultSecretSource, device_bound_secret};
use crate::SdkError;
use ramflux_storage::{StorageError, VaultSecretSource};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{LazyLock, Mutex};
use zeroize::Zeroizing;

type Key = (PathBuf, String);
static SECRETS: LazyLock<Mutex<BTreeMap<Key, [u8; 32]>>> =
    LazyLock::new(|| Mutex::new(BTreeMap::new()));

fn key(root: &Path, id: &str) -> Key {
    (std::fs::canonicalize(root).unwrap_or_else(|_| root.to_path_buf()), id.to_owned())
}

/// Keep the vault-bound secret and the plain-client secret of one account equal.
pub(crate) fn reconcile(
    root: &Path,
    id: &str,
    mode: DeviceSecret,
    loaded: &[u8; 32],
) -> Result<Zeroizing<[u8; 32]>, SdkError> {
    let mut secrets = SECRETS.lock().map_err(|_| SdkError::CustodyVaultUnavailable)?;
    let entry = secrets.entry(key(root, id));
    let value = match (mode, entry) {
        (DeviceSecret::Load, std::collections::btree_map::Entry::Occupied(slot)) => *slot.get(),
        (_, std::collections::btree_map::Entry::Occupied(mut slot)) => {
            slot.insert(*loaded);
            *loaded
        }
        (_, std::collections::btree_map::Entry::Vacant(slot)) => *slot.insert(*loaded),
    };
    Ok(Zeroizing::new(value))
}

/// Fallback when the fixture vault holds no device secret: the plain-client one, if any.
pub(crate) fn recall(root: &Path, id: &str) -> Option<Zeroizing<[u8; 32]>> {
    SECRETS.lock().ok()?.get(&key(root, id)).map(|value| Zeroizing::new(*value))
}

/// The default vault-secret source of a unit-test client opened without a vault.
pub(crate) struct PlainSource {
    file: FileVaultSecretSource,
    root: PathBuf,
}

impl PlainSource {
    pub(crate) fn new(root: &Path) -> Self {
        Self { file: FileVaultSecretSource::new(root), root: root.to_path_buf() }
    }
}

impl VaultSecretSource for PlainSource {
    fn vault_secret(&self, id: &str) -> Result<[u8; 32], StorageError> {
        // As in production, only native account data is device-bound; legacy and plain
        // library accounts keep the file secret alone.
        if !crate::custody::account_exists(&self.root, id).unwrap_or(false) {
            return self.file.vault_secret(id);
        }
        let mut secrets = SECRETS.lock().map_err(|_| {
            StorageError::KeyWrappingFailed("test device secrets poisoned".to_owned())
        })?;
        let secret = *secrets.entry(key(&self.root, id)).or_insert_with(rand_secret);
        drop(secrets);
        device_bound_secret(&self.file, id, &secret)
    }
}

fn rand_secret() -> [u8; 32] {
    let mut secret = [0_u8; 32];
    getrandom::fill(&mut secret).expect("test: random device secret");
    secret
}
