// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Bounded-memory verification of existing whole-object RFC 8439 ciphertext and plaintext hashes.

use chacha20::cipher::{KeyIvInit, StreamCipher};
use poly1305::{
    Poly1305,
    universal_hash::{KeyInit, UniversalHash},
};
use std::io::Read;
use zeroize::{Zeroize, Zeroizing};

#[derive(Debug, thiserror::Error)]
pub enum ObjectVerificationError {
    #[error("object input failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("object authentication or hash mismatch")]
    Mismatch,
}

/// Verifies the stored AEAD and both hashes without retaining an entire attachment.
/// No plaintext is released; input length includes the final 16-byte authentication tag.
/// # Errors
/// Rejects truncation, invalid keys/tags, hash mismatch, excessive cipher length or I/O failure.
pub fn verify_object_stream(
    input: &mut impl Read,
    ciphertext_bytes: u64,
    key: &[u8; 32],
    object_id: &str,
    manifest_hash: &str,
    plaintext_hash: &str,
) -> Result<(), ObjectVerificationError> {
    use ObjectVerificationError::Mismatch;
    let length = ciphertext_bytes.checked_sub(16).ok_or(Mismatch)?;
    let nonce_hash = crate::blake3_256(ramflux_protocol::domain::OBJECT, object_id.as_bytes());
    let nonce = chacha20::Nonce::from_slice(&nonce_hash[..12]);
    let mut cipher = chacha20::ChaCha20::new(key.into(), nonce);
    let mut block = Zeroizing::new([0_u8; 64]);
    cipher.apply_keystream(&mut *block);
    let mut mac = Poly1305::new(poly1305::Key::from_slice(&block[..32]));
    block.zeroize();
    mac.update_padded(object_id.as_bytes());
    let mut encrypted_hash =
        crate::Blake3DomainHasher::new(ramflux_protocol::domain::OBJECT_MANIFEST);
    let mut clear_hash = crate::Blake3DomainHasher::new(ramflux_protocol::domain::OBJECT);
    let mut remaining = length;
    let mut buffer = Zeroizing::new(vec![0_u8; 64 * 1024]);
    while remaining > 0 {
        let count = usize::try_from(remaining.min(buffer.len() as u64)).map_err(|_| Mismatch)?;
        let bytes = &mut buffer[..count];
        input.read_exact(bytes)?;
        encrypted_hash.update(bytes);
        mac.update_padded(bytes);
        cipher.try_apply_keystream(bytes).map_err(|_| Mismatch)?;
        clear_hash.update(bytes);
        bytes.zeroize();
        remaining -= count as u64;
    }
    let mut tag = [0_u8; 16];
    input.read_exact(&mut tag)?;
    encrypted_hash.update(&tag);
    let mut lengths = [0_u8; 16];
    lengths[..8].copy_from_slice(&(object_id.len() as u64).to_le_bytes());
    lengths[8..].copy_from_slice(&length.to_le_bytes());
    mac.update_padded(&lengths);
    mac.verify((&tag).into()).map_err(|_| Mismatch)?;
    if encrypted_hash.finalize_base64url() != manifest_hash
        || clear_hash.finalize_base64url() != plaintext_hash
    {
        return Err(Mismatch);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chacha20poly1305::aead::{Aead, Payload};
    #[test]
    fn streamed_attachment_verification_matches_production_aead_at_every_block_boundary()
    -> Result<(), Box<dyn std::error::Error>> {
        let key = [9; 32];
        let id = "attachment";
        let nonce = crate::blake3_256(ramflux_protocol::domain::OBJECT, id.as_bytes());
        for size in [0, 1, 15, 16, 17, 65_535, 65_536, 65_537, 131_073] {
            let plaintext = vec![71; size];
            let cipher = chacha20poly1305::ChaCha20Poly1305::new((&key).into());
            let ciphertext = cipher
                .encrypt(
                    chacha20poly1305::Nonce::from_slice(&nonce[..12]),
                    Payload { msg: &plaintext, aad: id.as_bytes() },
                )
                .map_err(|_| "encrypt")?;
            let hash =
                crate::blake3_256_base64url(ramflux_protocol::domain::OBJECT_MANIFEST, &ciphertext);
            let clear = crate::blake3_256_base64url(ramflux_protocol::domain::OBJECT, &plaintext);
            verify_object_stream(
                &mut ciphertext.as_slice(),
                ciphertext.len() as u64,
                &key,
                id,
                &hash,
                &clear,
            )?;
            assert!(
                verify_object_stream(
                    &mut ciphertext.as_slice(),
                    ciphertext.len() as u64,
                    &[10; 32],
                    id,
                    &hash,
                    &clear
                )
                .is_err()
            );
            let mut altered = ciphertext.clone();
            altered[0] ^= 1;
            assert!(
                verify_object_stream(
                    &mut altered.as_slice(),
                    altered.len() as u64,
                    &key,
                    id,
                    &hash,
                    &clear
                )
                .is_err()
            );
            assert!(
                verify_object_stream(
                    &mut ciphertext.as_slice(),
                    ciphertext.len() as u64,
                    &key,
                    id,
                    &hash,
                    "wrong hash"
                )
                .is_err()
            );
        }
        Ok(())
    }
}
