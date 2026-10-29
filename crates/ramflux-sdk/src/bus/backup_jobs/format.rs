// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Encrypted archive payload framing; recovery secrets never enter a plaintext staging file.
use crate::{SdkError, bus::protocol::LocalBusPersistedAccount};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce, aead::Aead};
use serde::{Deserialize, Serialize};
use std::{
    io::{Read, Write},
    path::Path,
};
use zeroize::{Zeroize, Zeroizing};
const MAX_IDENTITY_BYTES: usize = 16 * 1024 * 1024;

#[derive(Serialize, Deserialize)]
pub(super) struct Metadata {
    #[serde(flatten)]
    pub identity: Identity,
    pub database_key: [u8; 32],
    pub ca_pem: Vec<u8>,
}
impl Drop for Metadata {
    fn drop(&mut self) {
        self.database_key.zeroize();
        if let Identity::Legacy { manifest } = &mut self.identity {
            manifest.root_seed.zeroize();
            manifest.device_seed.zeroize();
            manifest.account_secret.zeroize();
        }
    }
}
impl Metadata {
    pub fn validate(&self, account: &str) -> Result<(), SdkError> {
        self.identity.validate(account)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(untagged, deny_unknown_fields)]
pub(in crate::bus) enum Identity {
    Native { native: Box<super::native::DataIdentity> },
    Legacy { manifest: Box<LocalBusPersistedAccount> },
}
impl Identity {
    pub fn account_id(&self) -> &str {
        match self {
            Self::Legacy { manifest } => &manifest.local_account_id,
            Self::Native { native } => &native.local_account_id,
        }
    }
    pub fn label(&self) -> Option<String> {
        match self {
            Self::Legacy { manifest } => manifest.label.clone(),
            Self::Native { native } => {
                Some(native.authority.publication.record.body.profile.display_name.clone())
            }
        }
    }
    pub fn legacy(&self) -> Result<&LocalBusPersistedAccount, SdkError> {
        match self {
            Self::Legacy { manifest } => Ok(manifest),
            Self::Native { .. } => Err(SdkError::CustodyModeDowngrade),
        }
    }
    pub fn legacy_mut(&mut self) -> Result<&mut LocalBusPersistedAccount, SdkError> {
        match self {
            Self::Legacy { manifest } => Ok(manifest),
            Self::Native { .. } => Err(SdkError::CustodyModeDowngrade),
        }
    }
    fn validate(&self, account: &str) -> Result<(), SdkError> {
        if let Self::Native { native } = self {
            return native.validate(account);
        }
        let manifest = self.legacy()?;
        if manifest.local_account_id != account
            || manifest.local_account_id.is_empty()
            || (Path::new(&manifest.local_account_id).components().count() != 1
                || Path::new(&manifest.local_account_id)
                    .components()
                    .any(|part| !matches!(part, std::path::Component::Normal(_))))
            || manifest.local_account_id == ".."
        {
            return Err(SdkError::LocalBus("invalid archive account".into()));
        }
        let root = ramflux_crypto::public_key_base64url_from_seed(manifest.root_seed);
        if crate::prekey::identity_root_public_key_commitment(&root)?
            != manifest.principal_commitment
        {
            return Err(SdkError::LocalBus("archive root commitment mismatch".into()));
        }
        Ok(())
    }
}

pub(super) fn payload(metadata: &Metadata, database: &Path) -> Result<impl Read, SdkError> {
    let bytes = Zeroizing::new(serde_json::to_vec(metadata)?);
    if bytes.len() > MAX_IDENTITY_BYTES {
        return Err(SdkError::LocalBus("archive identity metadata exceeds format budget".into()));
    }
    let mut prefix = Zeroizing::new(Vec::with_capacity(8 + bytes.len()));
    prefix.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    prefix.extend_from_slice(&bytes);
    Ok(std::io::Cursor::new(prefix).chain(std::fs::File::open(database)?))
}

pub(super) struct Unpack {
    prefix: Vec<u8>,
    metadata: Option<Metadata>,
    pub database: std::fs::File,
    expected: Option<usize>,
}
impl Unpack {
    pub fn new(database: std::fs::File) -> Self {
        Self { prefix: Vec::new(), metadata: None, database, expected: None }
    }
    pub fn finish(mut self) -> Result<Metadata, SdkError> {
        self.database.sync_all()?;
        self.metadata.take().ok_or_else(|| SdkError::LocalBus("truncated archive identity".into()))
    }
}
impl Drop for Unpack {
    fn drop(&mut self) {
        self.prefix.zeroize();
    }
}
impl Write for Unpack {
    fn write(&mut self, mut input: &[u8]) -> std::io::Result<usize> {
        let total = input.len();
        if self.expected.is_none() {
            let n = (8 - self.prefix.len()).min(input.len());
            self.prefix.extend_from_slice(&input[..n]);
            input = &input[n..];
            if self.prefix.len() == 8 {
                let size = u64::from_be_bytes(
                    self.prefix
                        .as_slice()
                        .try_into()
                        .map_err(|_| std::io::ErrorKind::InvalidData)?,
                );
                if size == 0 || size > MAX_IDENTITY_BYTES as u64 {
                    return Err(std::io::ErrorKind::InvalidData.into());
                }
                self.expected =
                    Some(usize::try_from(size).map_err(|_| std::io::ErrorKind::InvalidData)?);
                self.prefix.clear();
            }
        }
        if self.metadata.is_none()
            && let Some(size) = self.expected
        {
            let n = (size - self.prefix.len()).min(input.len());
            self.prefix.extend_from_slice(&input[..n]);
            input = &input[n..];
            if self.prefix.len() == size {
                self.metadata =
                    Some(serde_json::from_slice(&self.prefix).map_err(std::io::Error::other)?);
                self.prefix.zeroize();
                self.prefix.clear();
            }
        }
        if self.metadata.is_some() {
            self.database.write_all(input)?;
        }
        Ok(total)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.database.flush()
    }
}

pub(super) fn save_metadata(
    path: &Path,
    key: &[u8; 32],
    metadata: &Metadata,
) -> Result<(), SdkError> {
    let clear = Zeroizing::new(serde_json::to_vec(metadata)?);
    let nonce = ramflux_crypto::random_32()?;
    let meta_key = Zeroizing::new(ramflux_crypto::blake3_keyed_derive(
        key,
        b"ramflux.backup.staging.metadata.v1",
    ));
    let cipher = Aes256Gcm::new((&*meta_key).into());
    let sealed = cipher
        .encrypt(Nonce::from_slice(&nonce[..12]), clear.as_slice())
        .map_err(|_| SdkError::LocalBus("staging encryption failed".into()))?;
    let mut bytes = nonce[..12].to_vec();
    bytes.extend(sealed);
    std::fs::write(path, &bytes)?;
    std::fs::File::open(path)?.sync_all()?;
    Ok(())
}
pub(super) fn load_metadata(path: &Path, key: &[u8; 32]) -> Result<Metadata, SdkError> {
    let bytes = std::fs::read(path)?;
    if bytes.len() < 28 || bytes.len() > MAX_IDENTITY_BYTES + 28 {
        return Err(SdkError::LocalBus("invalid staging metadata".into()));
    }
    let meta_key = Zeroizing::new(ramflux_crypto::blake3_keyed_derive(
        key,
        b"ramflux.backup.staging.metadata.v1",
    ));
    let clear = Zeroizing::new(
        Aes256Gcm::new((&*meta_key).into())
            .decrypt(Nonce::from_slice(&bytes[..12]), &bytes[12..])
            .map_err(|_| SdkError::LocalBus("staging authentication failed".into()))?,
    );
    Ok(serde_json::from_slice(&clear)?)
}
