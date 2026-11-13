// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Manifest/direction-specific decrypt-only capability for root-drained local work.
use super::{
    CHUNK_BYTES, EncryptedStageChunk, FullStageKey, SLOT_OVERHEAD, StageDirection, chunk_aad,
};
use crate::StorageError;
use crate::account_db::full_transfer::source_scalar::SourceGuard;
use chacha20poly1305::{ChaCha20Poly1305, Nonce, Tag, aead::AeadInPlace as _};
use zeroize::Zeroizing;
fn mismatch() -> StorageError {
    StorageError::PairingField("ChunkMismatch")
}
pub(in crate::account_db::full_transfer) struct FullChunkReadKey {
    cipher: ChaCha20Poly1305,
    manifest: [u8; 32],
    guard: SourceGuard,
}
impl FullStageKey<'_> {
    pub(in crate::account_db::full_transfer) fn chunk_read_key(
        &self,
        manifest: [u8; 32],
        direction: StageDirection,
        guard: SourceGuard,
    ) -> Result<FullChunkReadKey, StorageError> {
        guard.require()?;
        // Reuse the exact existing stage HKDF and fixed manifest/direction domain.
        let cipher = self.cipher(&manifest, direction)?;
        Ok(FullChunkReadKey { cipher, manifest, guard })
    }
}
impl FullChunkReadKey {
    pub(in crate::account_db::full_transfer) fn open(
        &self,
        index: u64,
        length: u32,
        chunk: &EncryptedStageChunk,
    ) -> Result<Zeroizing<Vec<u8>>, StorageError> {
        self.guard.require()?;
        let length = usize::try_from(length).map_err(|_| mismatch())?;
        if length == 0
            || length > CHUNK_BYTES as usize
            || chunk.bytes.len() != length + SLOT_OVERHEAD
        {
            return Err(mismatch());
        }
        let nonce = chunk.bytes.get(..12).ok_or_else(mismatch)?;
        let body = chunk.bytes.get(12..12 + length).ok_or_else(mismatch)?;
        let tag = chunk.bytes.get(12 + length..).ok_or_else(mismatch)?;
        let mut plaintext = Zeroizing::new(body.to_vec());
        self.cipher
            .decrypt_in_place_detached(
                Nonce::from_slice(nonce),
                &chunk_aad(&self.manifest, index, length)?,
                &mut plaintext,
                Tag::from_slice(tag),
            )
            .map_err(|_| mismatch())?;
        self.guard.require()?;
        Ok(plaintext)
    }
}
