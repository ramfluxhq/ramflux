// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Vault entries as owner-only files of Keystore-wrapped bytes.
//!
//! Insert never replaces an entry, every write is flushed to the file and its directory,
//! and plaintext lives only in zeroizing buffers between the caller and the Keystore.

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use zeroize::Zeroizing;

use super::envelope::{Envelope, MAX_ENVELOPE_LEN, associated_data};
use super::keystore::{
    KeyKind, KeystoreBridge, MAX_SECRET_LEN, SecurityLevel, StrongBoxPreference, require_hardware,
};
use super::refuse;
use crate::SdkError;
use crate::custody::CustodyVaultReason;
use crate::custody::vault::presence::Items;

const FILE_DOMAIN: &[u8] = b"ramflux.android.vault.file.v1";
const ENTRY_SUFFIX: &str = "rfv";

pub(crate) struct KeystoreItems {
    dir: PathBuf,
    bridge: Arc<dyn KeystoreBridge>,
    strongbox: StrongBoxPreference,
}

fn unavailable() -> SdkError {
    SdkError::CustodyVaultUnavailable
}

fn key_kind(presence: bool) -> KeyKind {
    if presence { KeyKind::Presence } else { KeyKind::Background }
}

fn valid_reference(reference: &str) -> bool {
    !reference.is_empty() && reference.len() <= 512 && !reference.chars().any(char::is_control)
}

impl KeystoreItems {
    pub(crate) fn new(
        dir: PathBuf,
        bridge: Arc<dyn KeystoreBridge>,
        strongbox: StrongBoxPreference,
    ) -> Self {
        Self { dir, bridge, strongbox }
    }

    pub(crate) fn bridge(&self) -> &dyn KeystoreBridge {
        self.bridge.as_ref()
    }

    /// Create the vault directory owner-only when it is absent.
    pub(crate) fn prepare_directory(&self) -> Result<(), SdkError> {
        match std::fs::symlink_metadata(&self.dir) {
            Ok(metadata) if metadata.is_dir() => Ok(()),
            Ok(_) => Err(SdkError::CustodyVault(CustodyVaultReason::Permission)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                crate::platform::fs::create_owner_only_dir(&self.dir)
            }
            Err(error) => Err(error.into()),
        }
    }

    /// Create the key when absent and refuse anything that is not secure hardware.
    pub(crate) fn ensure_hardware_key(&self, kind: KeyKind) -> Result<SecurityLevel, SdkError> {
        let level = self.bridge.ensure_key(kind, self.strongbox).map_err(refuse)?;
        require_hardware(level).map_err(refuse)
    }

    /// Remove every entry and both wrapping keys. This is the "delete the orphan and link
    /// as a new device" action; nothing can be recovered from the vault afterwards.
    pub(crate) fn erase_all(&self) -> Result<(), SdkError> {
        match std::fs::read_dir(&self.dir) {
            Ok(entries) => {
                for entry in entries {
                    let path = entry?.path();
                    let owned = path
                        .extension()
                        .is_some_and(|extension| extension == ENTRY_SUFFIX || extension == "tmp");
                    if owned {
                        std::fs::remove_file(&path)?;
                    }
                }
                self.sync_directory()?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        for kind in [KeyKind::Background, KeyKind::Presence] {
            self.bridge.delete_key(kind).map_err(refuse)?;
        }
        Ok(())
    }

    /// File name: a domain-separated hash, so a reference never becomes a path component.
    fn path(&self, reference: &str) -> Result<PathBuf, SdkError> {
        if !valid_reference(reference) {
            return Err(unavailable());
        }
        let mut hasher = blake3::Hasher::new();
        hasher.update(FILE_DOMAIN);
        hasher.update(&[0]);
        hasher.update(reference.as_bytes());
        Ok(self.dir.join(format!("{}.{ENTRY_SUFFIX}", hasher.finalize().to_hex())))
    }

    fn sync_directory(&self) -> Result<(), SdkError> {
        std::fs::File::open(&self.dir)?.sync_all()?;
        Ok(())
    }

    fn seal(&self, reference: &str, bytes: &[u8], kind: KeyKind) -> Result<Vec<u8>, SdkError> {
        if bytes.is_empty() || bytes.len() > MAX_SECRET_LEN {
            return Err(unavailable());
        }
        let level = self.ensure_hardware_key(kind)?;
        let aad = associated_data(kind, level, reference);
        let wrapped = self.bridge.wrap(kind, &aad, bytes).map_err(refuse)?;
        Envelope { kind, level, wrapped }.encode().map_err(|_| unavailable())
    }

    fn write_new(path: &Path, encoded: &[u8]) -> std::io::Result<()> {
        let mut file = crate::platform::fs::create_new_owner_only_io(path)?;
        let written = file.write_all(encoded).and_then(|()| file.sync_all());
        if written.is_err() {
            // Never leave a truncated entry that a later read would report as corrupt.
            let _ = std::fs::remove_file(path);
        }
        written
    }

    fn read_file(path: &Path) -> Result<Option<Vec<u8>>, SdkError> {
        let metadata = match std::fs::symlink_metadata(path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        if !metadata.is_file() {
            return Err(SdkError::CustodyVault(CustodyVaultReason::Permission));
        }
        if metadata.len() > MAX_ENVELOPE_LEN as u64 {
            return Err(SdkError::CustodyVault(CustodyVaultReason::Corrupt));
        }
        Ok(Some(std::fs::read(path)?))
    }
}

impl Items for KeystoreItems {
    fn exists(&self, reference: &str) -> Result<bool, SdkError> {
        Ok(self.path(reference)?.try_exists()?)
    }

    fn read(
        &self,
        reference: &str,
        presence: bool,
    ) -> Result<Option<Zeroizing<Vec<u8>>>, SdkError> {
        let Some(bytes) = Self::read_file(&self.path(reference)?)? else {
            return Ok(None);
        };
        let envelope = Envelope::decode(&bytes)
            .map_err(|_| SdkError::CustodyVault(CustodyVaultReason::Corrupt))?;
        // A silent read must never reach the presence key, and a presence read must never be
        // satisfied by an entry the background key can open.
        if envelope.kind != key_kind(presence) {
            return Err(unavailable());
        }
        // The level is read from the live key, not trusted from the file. A blob whose key
        // is gone (restored or transferred without its Keystore key) is an orphan.
        let live = self.bridge.key_level(envelope.kind).map_err(refuse)?;
        let live = require_hardware(live).map_err(refuse)?;
        if live != envelope.level {
            return Err(SdkError::CustodyVault(CustodyVaultReason::Corrupt));
        }
        let aad = associated_data(envelope.kind, envelope.level, reference);
        let secret = self.bridge.unwrap(envelope.kind, &aad, &envelope.wrapped).map_err(refuse)?;
        if secret.is_empty() || secret.len() > MAX_SECRET_LEN {
            return Err(SdkError::CustodyVault(CustodyVaultReason::Corrupt));
        }
        Ok(Some(secret))
    }

    fn insert(&self, reference: &str, bytes: &[u8], presence: bool) -> Result<bool, SdkError> {
        let path = self.path(reference)?;
        if path.try_exists()? {
            return Ok(false);
        }
        self.prepare_directory()?;
        let encoded = self.seal(reference, bytes, key_kind(presence))?;
        match Self::write_new(&path, &encoded) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => return Ok(false),
            Err(error) => return Err(error.into()),
        }
        self.sync_directory()?;
        Ok(true)
    }

    fn journal(&self, reference: &str, bytes: &[u8]) -> Result<(), SdkError> {
        let path = self.path(reference)?;
        self.prepare_directory()?;
        let encoded = self.seal(reference, bytes, KeyKind::Background)?;
        let staged = path.with_extension("tmp");
        match std::fs::remove_file(&staged) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        Self::write_new(&staged, &encoded)?;
        if let Err(error) = std::fs::rename(&staged, &path) {
            let _ = std::fs::remove_file(&staged);
            return Err(error.into());
        }
        self.sync_directory()
    }

    fn delete(&self, reference: &str) -> Result<(), SdkError> {
        match std::fs::remove_file(self.path(reference)?) {
            Ok(()) => self.sync_directory(),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        }
    }
}
