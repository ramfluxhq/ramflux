// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! A5.M4/OVP-19: key operations require the original unlocked account writer, not its file vault.
use super::super::AccountDb;
use crate::{AccountDbKey, StorageError};
use chacha20poly1305::{
    ChaCha20Poly1305, Key, Nonce, Tag,
    aead::{AeadInPlace, KeyInit},
};
use hkdf::Hkdf;
use ramflux_crypto::custody::pairing::PairingRole;
use ramflux_protocol::custody::pairing::full_transfer::CHUNK_BYTES;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::Zeroizing;

const WRAP_DOMAIN: &[u8] = b"ramflux.full_transfer.stage_key.wrap.v1";
const CHUNK_DOMAIN: &[u8] = b"ramflux.full_transfer.stage_chunk.v1";
const KEY_SCHEMA: &str = "ramflux.full_transfer.stage_key.v1";
const SLOT_OVERHEAD: usize = 12 + 16;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum StageDirection {
    Forward,
    Reverse,
}
impl StageDirection {
    const fn byte(self) -> u8 {
        match self {
            Self::Forward => b'f',
            Self::Reverse => b'r',
        }
    }
}
/// Non-exportable independent stage key. Its borrow ends before the corresponding DB can lock.
/// Use short I/O scopes; never retain this owner across network waits.
pub struct FullStageKey<'a> {
    db: &'a AccountDb,
    key: AccountDbKey,
}
impl Drop for FullStageKey<'_> {
    fn drop(&mut self) {
        // Keep the DB borrow alive through explicit key destruction. AccountDbKey's Drop
        // wipes the old value; the replacement contains only public zero bytes.
        self.key = AccountDbKey::from_bytes([0; 32]);
    }
}
/// Exact local `stage.key` ciphertext, never a branch/data/primary vault item. No Debug/serde.
pub struct WrappedFullStageKey {
    nonce: [u8; 12],
    ciphertext: [u8; 48],
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyFile {
    ciphertext: String,
    nonce: String,
    schema: String,
    version: u32,
}
/// Fixed OVP-19 file frame: nonce12 || ciphertext || tag16. No plaintext/Debug/serde owner.
pub struct EncryptedStageChunk {
    bytes: Zeroizing<Vec<u8>>,
}
impl AccountDb {
    pub(super) fn require_full_stage_unlock(&self) -> Result<(), StorageError> {
        self.require_selected_transfer_source()?;
        if self.connection.downgrade().upgrade_account_writer().is_none() {
            return Err(StorageError::AuthorizationRejected);
        }
        Ok(())
    }
    /// Generate a fresh independent stage key through the guarded unlocked DB-key owner.
    /// # Errors
    /// Refuses a closed/read-only/stale generation, unavailable entropy or failed AEAD.
    pub fn create_full_stage_key(
        &self,
        transfer: &[u8; 32],
        role: PairingRole,
    ) -> Result<(FullStageKey<'_>, WrappedFullStageKey), StorageError> {
        self.require_full_stage_unlock()?;
        let owner = FullStageKey { db: self, key: AccountDbKey::generate()? };
        let wrapped = owner.wrap_for(transfer, role)?;
        Ok((owner, wrapped))
    }
    /// Open only with this actual unlocked DB key and its exact local account/transfer/role.
    /// # Errors
    /// Refuses wrong scopes/keys, read-only retained snapshots, stale generations and corruption.
    pub fn open_full_stage_key(
        &self,
        transfer: &[u8; 32],
        role: PairingRole,
        wrapped: &WrappedFullStageKey,
    ) -> Result<FullStageKey<'_>, StorageError> {
        self.require_full_stage_unlock()?;
        let mut bytes = Zeroizing::new(wrapped.ciphertext.to_vec());
        ChaCha20Poly1305::new(Key::from_slice(self.current_key.bytes()))
            .decrypt_in_place(
                Nonce::from_slice(&wrapped.nonce),
                &wrap_aad(&self.local_account_id, transfer, role)?,
                &mut *bytes,
            )
            .map_err(|_| invalid())?;
        let key = Zeroizing::new(<[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| invalid())?);
        Ok(FullStageKey { db: self, key: AccountDbKey::from_bytes(*key) })
    }
}
fn invalid() -> StorageError {
    StorageError::PairingField("WrongContext")
}
fn framed(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), StorageError> {
    out.extend_from_slice(&u32::try_from(bytes.len()).map_err(|_| invalid())?.to_be_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}
fn wrap_aad(local: &str, transfer: &[u8; 32], role: PairingRole) -> Result<Vec<u8>, StorageError> {
    let mut aad = Vec::new();
    framed(&mut aad, WRAP_DOMAIN)?;
    framed(&mut aad, local.as_bytes())?;
    aad.extend_from_slice(transfer);
    aad.push(role.byte());
    Ok(aad)
}
fn fresh_nonce() -> Result<[u8; 12], StorageError> {
    let random = Zeroizing::new(ramflux_crypto::random_32()?);
    random[..12].try_into().map_err(|_| invalid())
}
impl WrappedFullStageKey {
    /// Direct canonical local encoding, <=1KiB. Never contains a plaintext stage/DB key.
    /// # Errors
    /// Refuses local serialization failure.
    pub fn to_file_bytes(&self) -> Result<Zeroizing<Vec<u8>>, StorageError> {
        let wire = KeyFile {
            ciphertext: ramflux_protocol::encode_base64url(self.ciphertext),
            nonce: ramflux_protocol::encode_base64url(self.nonce),
            schema: KEY_SCHEMA.into(),
            version: 1,
        };
        let mut bytes = Zeroizing::new(Vec::with_capacity(256));
        serde_json::to_writer(&mut *bytes, &wire).map_err(|_| invalid())?;
        Ok(bytes)
    }
    /// # Errors
    /// Refuses unknown/duplicate/noncanonical fields, another schema, wrong lengths or >1KiB.
    pub fn from_file_bytes(bytes: &[u8]) -> Result<Self, StorageError> {
        if bytes.len() > 1024 {
            return Err(invalid());
        }
        let wire: KeyFile = ramflux_protocol::parse_i_json_secret(bytes).map_err(|_| invalid())?;
        if wire.schema != KEY_SCHEMA || wire.version != 1 {
            return Err(invalid());
        }
        let nonce =
            Zeroizing::new(ramflux_protocol::decode_base64url(&wire.nonce).map_err(|_| invalid())?);
        let ciphertext = Zeroizing::new(
            ramflux_protocol::decode_base64url(&wire.ciphertext).map_err(|_| invalid())?,
        );
        let value = Self {
            nonce: nonce.as_slice().try_into().map_err(|_| invalid())?,
            ciphertext: ciphertext.as_slice().try_into().map_err(|_| invalid())?,
        };
        if value.to_file_bytes()?.as_slice() != bytes {
            return Err(invalid());
        }
        Ok(value)
    }
}
impl EncryptedStageChunk {
    /// Take the one bounded original disk allocation, preserving its erasing ownership.
    /// # Errors
    /// Refuses short or over-size slot frames before use by an AEAD owner.
    pub fn from_file_bytes(bytes: Zeroizing<Vec<u8>>) -> Result<Self, StorageError> {
        if bytes.len() <= SLOT_OVERHEAD || bytes.len() > CHUNK_BYTES as usize + SLOT_OVERHEAD {
            return Err(StorageError::PairingField("ChunkMismatch"));
        }
        Ok(Self { bytes })
    }
    #[must_use]
    pub fn as_file_bytes(&self) -> &[u8] {
        &self.bytes
    }
}
impl FullStageKey<'_> {
    pub(super) fn require_live(&self) -> Result<(), StorageError> {
        self.db.require_full_stage_unlock()
    }
    pub(super) fn wrap_for(
        &self,
        transfer: &[u8; 32],
        role: PairingRole,
    ) -> Result<WrappedFullStageKey, StorageError> {
        self.require_live()?;
        let nonce = fresh_nonce()?;
        let mut ciphertext = Zeroizing::new(Vec::with_capacity(48));
        ciphertext.extend_from_slice(self.key.bytes());
        ChaCha20Poly1305::new(Key::from_slice(self.db.current_key.bytes()))
            .encrypt_in_place(
                Nonce::from_slice(&nonce),
                &wrap_aad(&self.db.local_account_id, transfer, role)?,
                &mut *ciphertext,
            )
            .map_err(|_| invalid())?;
        let wrapped = WrappedFullStageKey {
            nonce,
            ciphertext: ciphertext.as_slice().try_into().map_err(|_| invalid())?,
        };
        Ok(wrapped)
    }
    pub(super) fn open_metadata(
        &self,
        path: &std::path::Path,
    ) -> Result<crate::database::Connection, StorageError> {
        self.db.require_full_stage_unlock()?;
        let connection = crate::database::Connection::open_with_flags(
            path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE | rusqlite::OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )?;
        crate::encryption::apply_key(&connection, &self.key)?;
        let mode = crate::encryption::current_encryption_mode(&connection);
        if mode != crate::EncryptionMode::SqlCipher && !super::super::insecure_test_sqlite_allowed()
        {
            return Err(StorageError::EncryptionUnavailable { mode });
        }
        connection.execute_batch(
            "PRAGMA synchronous=FULL; PRAGMA journal_mode=DELETE; PRAGMA locking_mode=EXCLUSIVE; PRAGMA temp_store=MEMORY;",
        )?;
        Ok(connection)
    }
    fn cipher(
        &self,
        manifest: &[u8; 32],
        direction: StageDirection,
    ) -> Result<ChaCha20Poly1305, StorageError> {
        self.db.require_full_stage_unlock()?;
        let mut info = Vec::from(CHUNK_DOMAIN);
        info.push(direction.byte());
        let mut key = Zeroizing::new([0; 32]);
        Hkdf::<Sha256>::new(Some(manifest), self.key.bytes())
            .expand(&info, key.as_mut())
            .map_err(|_| invalid())?;
        Ok(ChaCha20Poly1305::new(Key::from_slice(key.as_ref())))
    }
    /// Seal a local immutable chunk using the approved independent stage-key HKDF and fresh nonce.
    /// Ledger/disk quota/fsync/duplicate rules belong to the staged file owner, not this cipher.
    /// # Errors
    /// Refuses a stale unlock, empty/oversize plaintext, entropy/AEAD failure or bad length.
    pub fn seal_chunk(
        &self,
        manifest: &[u8; 32],
        direction: StageDirection,
        index: u64,
        plaintext: &[u8],
    ) -> Result<EncryptedStageChunk, StorageError> {
        if plaintext.is_empty() || plaintext.len() > CHUNK_BYTES as usize {
            return Err(StorageError::PairingField("ChunkMismatch"));
        }
        let nonce = fresh_nonce()?;
        let mut bytes = Zeroizing::new(Vec::with_capacity(plaintext.len() + SLOT_OVERHEAD));
        bytes.extend_from_slice(&nonce);
        bytes.extend_from_slice(plaintext);
        let aad = chunk_aad(manifest, index, plaintext.len())?;
        let tag = self
            .cipher(manifest, direction)?
            .encrypt_in_place_detached(Nonce::from_slice(&nonce), &aad, &mut bytes[12..])
            .map_err(|_| StorageError::PairingField("ChunkMismatch"))?;
        bytes.extend_from_slice(&tag);
        Ok(EncryptedStageChunk { bytes })
    }
    /// Open actual slot bytes; the staged file owner must also compare the retained chunk digest.
    /// # Errors
    /// Refuses a wrong manifest/direction/index/length, corrupt frame or stale unlock.
    pub fn open_chunk(
        &self,
        manifest: &[u8; 32],
        direction: StageDirection,
        index: u64,
        length: u32,
        chunk: &EncryptedStageChunk,
    ) -> Result<Zeroizing<Vec<u8>>, StorageError> {
        let length =
            usize::try_from(length).map_err(|_| StorageError::PairingField("ChunkMismatch"))?;
        if length == 0
            || length > CHUNK_BYTES as usize
            || chunk.bytes.len() != length + SLOT_OVERHEAD
        {
            return Err(StorageError::PairingField("ChunkMismatch"));
        }
        let aad = chunk_aad(manifest, index, length)?;
        let mut plaintext = Zeroizing::new(chunk.bytes[12..12 + length].to_vec());
        self.cipher(manifest, direction)?
            .decrypt_in_place_detached(
                Nonce::from_slice(&chunk.bytes[..12]),
                &aad,
                &mut plaintext,
                Tag::from_slice(&chunk.bytes[12 + length..]),
            )
            .map_err(|_| StorageError::PairingField("ChunkMismatch"))?;
        Ok(plaintext)
    }
}
fn chunk_aad(manifest: &[u8; 32], index: u64, length: usize) -> Result<Vec<u8>, StorageError> {
    let mut aad = Vec::new();
    framed(&mut aad, CHUNK_DOMAIN)?;
    aad.extend_from_slice(manifest);
    aad.extend_from_slice(&index.to_be_bytes());
    aad.extend_from_slice(&u32::try_from(length).map_err(|_| invalid())?.to_be_bytes());
    Ok(aad)
}
#[cfg(test)]
#[path = "keys_tests.rs"]
mod tests;
