// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Authenticated, constant-memory account archives. Decrypt only into private staging;
//! no output may be installed before the final marker and physical EOF both verify.

mod framing;
#[cfg(test)]
mod tests;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use std::io::{Read, Write};
use zeroize::Zeroizing;

/// Plaintext bytes per independently authenticated archive chunk.
pub const CHUNK_SIZE: usize = 64 * 1024;
const MAGIC: &[u8; 8] = b"RFLXBA02";
const MAX_HEADER_SIZE: usize = 4096;
const TAG_SIZE: usize = 16;

/// Stable public metadata authenticated by both key wrapping and every data chunk.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupContext {
    pub account_id: String,
    pub created_at: u64,
}

/// Validated metadata and authenticated byte count, available only after final verification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BackupStreamSummary {
    pub context: BackupContext,
    pub plaintext_bytes: u64,
}

/// Backup errors distinguish I/O failure, malformed framing and authentication failure.
#[derive(Debug, thiserror::Error)]
pub enum BackupStreamError {
    #[error("backup I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("backup key derivation failed: {0}")]
    Derivation(#[from] crate::CryptoError),
    #[error("invalid backup archive: {0}")]
    Invalid(&'static str),
    #[error("backup authentication failed")]
    Authentication,
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Header {
    schema: String,
    version: u32,
    context: BackupContext,
    chunk_size: usize,
    kdf: String,
    memory_kib: u32,
    time_cost: u32,
    parallelism: u32,
    cipher: String,
    salt: [u8; 32],
    wrap_nonce: Vec<u8>,
    stream_prefix: Vec<u8>,
}

impl Header {
    fn fresh(context: BackupContext) -> Result<Self, BackupStreamError> {
        Ok(Self {
            schema: "ramflux.account.backup.stream.v2".into(),
            version: 2,
            context,
            chunk_size: CHUNK_SIZE,
            kdf: "argon2id-v19".into(),
            memory_kib: 262_144,
            time_cost: 3,
            parallelism: 1,
            cipher: "xchacha20poly1305-stream64be".into(),
            salt: crate::random_32()?,
            wrap_nonce: crate::random_32()?[..24].to_vec(),
            stream_prefix: crate::random_32()?[..15].to_vec(),
        })
    }
    fn validate(&self) -> Result<(), BackupStreamError> {
        if self.schema != "ramflux.account.backup.stream.v2"
            || self.version != 2
            || self.chunk_size != CHUNK_SIZE
            || self.kdf != "argon2id-v19"
            || self.memory_kib != 262_144
            || self.time_cost != 3
            || self.parallelism != 1
            || self.cipher != "xchacha20poly1305-stream64be"
            || self.wrap_nonce.len() != 24
            || self.stream_prefix.len() != 15
            || self.context.account_id.is_empty()
            || self.context.account_id.len() > 1024
        {
            return Err(BackupStreamError::Invalid("unsupported header"));
        }
        Ok(())
    }
}

/// Encrypts an unbounded input stream with a random file key and fixed-size chunks.
/// The caller must flush/fsync and atomically publish its output file after success.
///
/// # Errors
/// Returns typed I/O, key derivation, invalid metadata or authentication errors.
pub fn encrypt_backup_stream(
    input: &mut impl Read,
    output: &mut impl Write,
    passphrase: &[u8],
    context: BackupContext,
) -> Result<BackupStreamSummary, BackupStreamError> {
    let header = Header::fresh(context)?;
    header.validate()?;
    let wrapping_key = crate::derive_recovery_secret(passphrase, &header.salt)?;
    encrypt_with_key(input, output, &header, wrapping_key.expose())
}

fn encrypt_with_key(
    input: &mut impl Read,
    output: &mut impl Write,
    header: &Header,
    wrapping_key: &[u8; 32],
) -> Result<BackupStreamSummary, BackupStreamError> {
    let bytes =
        serde_json::to_vec(header).map_err(|_| BackupStreamError::Invalid("header encoding"))?;
    if bytes.len() > MAX_HEADER_SIZE {
        return Err(BackupStreamError::Invalid("header too large"));
    }
    let length = u32::try_from(bytes.len())
        .map_err(|_| BackupStreamError::Invalid("header length overflow"))?;
    let mut authenticated = Vec::from(MAGIC.as_slice());
    authenticated.extend_from_slice(&length.to_be_bytes());
    authenticated.extend_from_slice(&bytes);
    let file_key = Zeroizing::new(crate::random_32()?);
    let cipher = XChaCha20Poly1305::new(wrapping_key.into());
    let wrapped = cipher
        .encrypt(
            XNonce::from_slice(&header.wrap_nonce),
            Payload { msg: file_key.as_slice(), aad: &authenticated },
        )
        .map_err(|_| BackupStreamError::Authentication)?;
    authenticated.extend_from_slice(&wrapped);
    output.write_all(&authenticated)?;
    let plaintext_bytes =
        framing::encrypt_chunks(input, output, &file_key, &header.stream_prefix, &authenticated)?;
    Ok(BackupStreamSummary { context: header.context.clone(), plaintext_bytes })
}

/// Authenticates an archive into caller-owned private staging, using bounded memory.
/// Output already written remains untrusted until this function returns success.
/// Never pass a live database or final destination as `output`.
///
/// # Errors
/// Rejects wrong passphrases, modified headers/chunks, truncation, reordering,
/// appended bytes, unsupported parameters and I/O failures.
pub fn decrypt_backup_stream(
    input: &mut impl Read,
    output: &mut impl Write,
    passphrase: &[u8],
) -> Result<BackupStreamSummary, BackupStreamError> {
    let (header, authenticated, wrapped) = read_header(input)?;
    let wrapping_key = crate::derive_recovery_secret(passphrase, &header.salt)?;
    decrypt_with_key(input, output, header, authenticated, &wrapped, wrapping_key.expose())
}

fn read_header(input: &mut impl Read) -> Result<(Header, Vec<u8>, [u8; 48]), BackupStreamError> {
    let mut prefix = [0; 12];
    input.read_exact(&mut prefix)?;
    if &prefix[..8] != MAGIC {
        return Err(BackupStreamError::Invalid("magic"));
    }
    let size = u32::from_be_bytes([prefix[8], prefix[9], prefix[10], prefix[11]]) as usize;
    if size == 0 || size > MAX_HEADER_SIZE {
        return Err(BackupStreamError::Invalid("header length"));
    }
    let mut bytes = vec![0; size];
    input.read_exact(&mut bytes)?;
    let header: Header = serde_json::from_slice(&bytes)
        .map_err(|_| BackupStreamError::Invalid("header encoding"))?;
    header.validate()?;
    let mut authenticated = prefix.to_vec();
    authenticated.extend_from_slice(&bytes);
    let mut wrapped = [0; 48];
    input.read_exact(&mut wrapped)?;
    Ok((header, authenticated, wrapped))
}

fn decrypt_with_key(
    input: &mut impl Read,
    output: &mut impl Write,
    header: Header,
    mut authenticated: Vec<u8>,
    wrapped: &[u8; 48],
    wrapping_key: &[u8; 32],
) -> Result<BackupStreamSummary, BackupStreamError> {
    let cipher = XChaCha20Poly1305::new(wrapping_key.into());
    let file_key = Zeroizing::new(
        cipher
            .decrypt(
                XNonce::from_slice(&header.wrap_nonce),
                Payload { msg: wrapped, aad: &authenticated },
            )
            .map_err(|_| BackupStreamError::Authentication)?,
    );
    let key: &[u8; 32] = file_key
        .as_slice()
        .try_into()
        .map_err(|_| BackupStreamError::Invalid("wrapped key length"))?;
    authenticated.extend_from_slice(wrapped);
    let plaintext_bytes =
        framing::decrypt_chunks(input, output, key, &header.stream_prefix, &authenticated)?;
    Ok(BackupStreamSummary { context: header.context, plaintext_bytes })
}
