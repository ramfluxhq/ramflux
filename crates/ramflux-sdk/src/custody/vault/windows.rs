// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Windows primary vault: each credential is a DPAPI blob bound to the current user, kept in
//! an owner-only file next to the database.
//!
//! Limits, to be shown by the user interface:
//! - DPAPI is not a root of trust against malware running in the user's session. Any process
//!   of the same user can ask the system to unprotect the same blob.
//! - On a domain-joined machine, domain administrators can recover DPAPI-protected data, and
//!   DPAPI master keys may roam with the profile.
//! - The machine scope is never used. There is no file, registry or plaintext fallback: when
//!   DPAPI is unavailable every operation returns `CustodyVaultUnavailable`.
//! - User presence (Windows Hello) is not implemented, so home-migration authorization stays
//!   unavailable on Windows.

mod dpapi;

use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use ramflux_crypto::custody::SelfSigningKey;
use zeroize::Zeroizing;

use super::{BranchCredentials, PrimaryVault};
use crate::SdkError;
use crate::platform::fs;

/// DPAPI user-scope blob in an owner-only file. Software only: not hardware bound, and
/// recoverable by a domain administrator on a domain-joined machine.
pub const VAULT_CLASS_WINDOWS_DPAPI: &str = "software_os_credential_windows_dpapi_user";

/// Directory of the vault under the data root.
const VAULT_DIRECTORY: &str = "vault";
const ENTRY_SUFFIX: &str = ".dpapi";
/// Domain separation for the optional entropy. It is not a secret: it binds a blob to this
/// format and to one reference, so a blob copied over another entry does not open.
const ENTROPY_DOMAIN: &[u8] = b"ramflux.windows_vault.entropy.v1\0";
const NAME_DOMAIN: &str = "ramflux.windows_vault.entry_name.v1";
const CHECK_DOMAIN: &str = "ramflux.windows_vault.record_check.v1";
const RECORD_MAGIC: &[u8; 4] = b"RFW1";
const MAX_REFERENCE_BYTES: usize = 256;
const MAX_SECRET_BYTES: usize = 1024;
const CHECK_BYTES: usize = 32;

fn unavailable<E>(_: E) -> SdkError {
    SdkError::CustodyVaultUnavailable
}

/// Windows primary vault rooted at `<data root>\vault`.
#[derive(Clone)]
pub struct WindowsDpapiVault {
    directory: PathBuf,
}

impl std::fmt::Debug for WindowsDpapiVault {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The directory names the user profile; entries and secrets are never formatted.
        formatter.debug_struct("WindowsDpapiVault").finish_non_exhaustive()
    }
}

impl WindowsDpapiVault {
    /// Vault for the database under `data_root`.
    #[must_use]
    pub fn for_data_root(data_root: &Path) -> Self {
        Self { directory: data_root.join(VAULT_DIRECTORY) }
    }

    fn valid_reference(reference: &str) -> Result<(), SdkError> {
        if reference.is_empty()
            || reference.len() > MAX_REFERENCE_BYTES
            || reference.chars().any(char::is_control)
        {
            return Err(SdkError::CustodyVaultUnavailable);
        }
        Ok(())
    }

    /// File names are case-insensitive on Windows and a reference may hold characters a file
    /// name cannot, so the name is the lowercase hex of a hash of the reference.
    fn entry_path(&self, reference: &str) -> Result<PathBuf, SdkError> {
        Self::valid_reference(reference)?;
        let digest = ramflux_crypto::blake3_256(NAME_DOMAIN, reference.as_bytes());
        let mut name = String::with_capacity(digest.len() * 2 + ENTRY_SUFFIX.len());
        for byte in digest {
            name.push_str(&format!("{byte:02x}"));
        }
        name.push_str(ENTRY_SUFFIX);
        Ok(self.directory.join(name))
    }

    fn entropy(reference: &str) -> Vec<u8> {
        [ENTROPY_DOMAIN, reference.as_bytes()].concat()
    }

    /// `magic | reference length | reference | secret length | secret | check`. The check is
    /// an application-level integrity value over everything before it: the system's own check
    /// is documented as not reliable enough to detect every altered blob.
    fn encode(reference: &str, secret: &[u8]) -> Result<Zeroizing<Vec<u8>>, SdkError> {
        if secret.is_empty() || secret.len() > MAX_SECRET_BYTES {
            return Err(SdkError::CustodyVaultUnavailable);
        }
        let reference_len = u16::try_from(reference.len()).map_err(unavailable)?;
        let secret_len = u16::try_from(secret.len()).map_err(unavailable)?;
        let mut record = Zeroizing::new(Vec::with_capacity(
            RECORD_MAGIC.len() + 4 + reference.len() + secret.len() + CHECK_BYTES,
        ));
        record.extend_from_slice(RECORD_MAGIC);
        record.extend_from_slice(&reference_len.to_be_bytes());
        record.extend_from_slice(reference.as_bytes());
        record.extend_from_slice(&secret_len.to_be_bytes());
        record.extend_from_slice(secret);
        let check = ramflux_crypto::blake3_256(CHECK_DOMAIN, &record);
        record.extend_from_slice(&check);
        Ok(record)
    }

    fn decode(reference: &str, record: &[u8]) -> Result<Zeroizing<Vec<u8>>, SdkError> {
        let invalid = || SdkError::CustodyVaultUnavailable;
        let body_len = record.len().checked_sub(CHECK_BYTES).ok_or_else(invalid)?;
        let (body, check) = record.split_at(body_len);
        if ramflux_crypto::blake3_256(CHECK_DOMAIN, body).as_slice() != check {
            return Err(invalid());
        }
        let rest = body.strip_prefix(RECORD_MAGIC.as_slice()).ok_or_else(invalid)?;
        let (length, rest) = rest.split_at_checked(2).ok_or_else(invalid)?;
        let length = usize::from(u16::from_be_bytes([length[0], length[1]]));
        let (stored, rest) = rest.split_at_checked(length).ok_or_else(invalid)?;
        if stored != reference.as_bytes() {
            return Err(invalid());
        }
        let (length, secret) = rest.split_at_checked(2).ok_or_else(invalid)?;
        let length = usize::from(u16::from_be_bytes([length[0], length[1]]));
        if secret.len() != length || length == 0 || length > MAX_SECRET_BYTES {
            return Err(invalid());
        }
        Ok(Zeroizing::new(secret.to_vec()))
    }

    /// The vault directory exists, is owner-only, and belongs to the current user.
    fn ready(&self) -> Result<(), SdkError> {
        match fs::create_owner_only_dir(&self.directory) {
            Ok(()) => {}
            Err(SdkError::Io(error)) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(_) => return Err(SdkError::CustodyVaultUnavailable),
        }
        // Refuses a directory another user owns before any blob is written into it.
        fs::set_owner_only_dir(&self.directory).map_err(unavailable)
    }

    /// Insert only. The blob is written to a private temporary name, flushed, and moved to
    /// its final name with a no-replace move, so an existing entry is never overwritten and a
    /// crash leaves either no entry or a complete one.
    fn insert(&self, reference: &str, secret: &[u8]) -> Result<(), SdkError> {
        let path = self.entry_path(reference)?;
        self.ready()?;
        if path.exists() {
            return Err(SdkError::CustodyVaultUnavailable);
        }
        let record = Self::encode(reference, secret)?;
        let protected =
            dpapi::protect(&record, &Self::entropy(reference)).map_err(unavailable)?;
        let mut nonce = [0_u8; 8];
        getrandom::fill(&mut nonce).map_err(unavailable)?;
        let temporary = path.with_extension(format!("tmp-{:016x}", u64::from_be_bytes(nonce)));
        let written = (|| -> Result<(), SdkError> {
            let mut file = fs::create_new_owner_only(&temporary)?;
            file.write_all(&protected)?;
            file.sync_all()?;
            drop(file);
            fs::rename_no_replace(&temporary, &path)?;
            Ok(())
        })();
        if written.is_err() {
            let _ = std::fs::remove_file(&temporary);
        }
        written.map_err(unavailable)
    }

    fn read(&self, reference: &str) -> Result<Zeroizing<Vec<u8>>, SdkError> {
        let path = self.entry_path(reference)?;
        let mut protected = Vec::new();
        std::fs::File::open(&path)
            .map_err(unavailable)?
            .take(u64::try_from(dpapi::MAX_BLOB_BYTES + 1).map_err(unavailable)?)
            .read_to_end(&mut protected)
            .map_err(unavailable)?;
        if protected.len() > dpapi::MAX_BLOB_BYTES {
            return Err(SdkError::CustodyVaultUnavailable);
        }
        let record =
            dpapi::unprotect(&protected, &Self::entropy(reference)).map_err(unavailable)?;
        Self::decode(reference, &record)
    }

    fn read_exact<const N: usize>(&self, reference: &str) -> Result<Zeroizing<[u8; N]>, SdkError> {
        let bytes = self.read(reference)?;
        let mut fixed = Zeroizing::new([0_u8; N]);
        if bytes.len() != N {
            return Err(SdkError::CustodyVaultUnavailable);
        }
        fixed.copy_from_slice(&bytes);
        Ok(fixed)
    }
}

impl PrimaryVault for WindowsDpapiVault {
    fn vault_class(&self) -> &'static str {
        VAULT_CLASS_WINDOWS_DPAPI
    }

    /// A real protect and unprotect round trip in memory: a profile whose DPAPI keys are not
    /// loaded fails here, before the user is asked to save recovery material.
    fn preflight(&self) -> Result<(), SdkError> {
        self.ready()?;
        let entropy = Self::entropy("provider-availability-probe");
        let protected = dpapi::protect(b"probe", &entropy).map_err(unavailable)?;
        let opened = dpapi::unprotect(&protected, &entropy).map_err(unavailable)?;
        if opened.as_slice() == b"probe" { Ok(()) } else { Err(SdkError::CustodyVaultUnavailable) }
    }

    fn store_new(&self, reference: &str, key: &SelfSigningKey) -> Result<(), SdkError> {
        self.insert(reference, &*key.vault_seed())
    }

    fn load_primary(&self, reference: &str) -> Result<SelfSigningKey, SdkError> {
        Ok(SelfSigningKey::from_vault_seed(&self.read_exact::<32>(reference)?))
    }

    fn load_branch(
        &self,
        reference: &str,
        principal: &str,
        device: &ramflux_protocol::custody::DeviceRef,
    ) -> Result<BranchCredentials, SdkError> {
        BranchCredentials::from_vault_seeds(principal, device, &self.read_exact::<64>(reference)?)
    }

    fn delete(&self, reference: &str) -> Result<(), SdkError> {
        if reference.starts_with(ramflux_storage::FileVaultSecretSource::OWNER_PREFIX) {
            return Ok(());
        }
        match std::fs::remove_file(self.entry_path(reference)?) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(_) => Err(SdkError::CustodyVaultUnavailable),
        }
    }

    fn store_branch(&self, reference: &str, seeds: &Zeroizing<[u8; 64]>) -> Result<(), SdkError> {
        self.insert(reference, &**seeds)
    }

    fn store_provisioning_secret(&self, reference: &str, secret: &[u8]) -> Result<(), SdkError> {
        self.insert(reference, secret)
    }

    fn load_provisioning_secret(&self, reference: &str) -> Result<Zeroizing<Vec<u8>>, SdkError> {
        self.read(reference)
    }
}

#[cfg(test)]
mod tests;
