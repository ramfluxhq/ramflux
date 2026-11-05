// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Dormant independent segment encryption. Persist ciphertext for retries;
//! a new upload generation always requires a fresh sealer and object id.
use chacha20poly1305::{
    ChaCha20Poly1305, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use ramflux_protocol::large_attachment::{FormatError, SegmentLayout, digest};
use zeroize::Zeroizing;

#[derive(Debug, thiserror::Error)]
pub enum SegmentError {
    #[error(transparent)]
    Format(#[from] FormatError),
    #[error("segment authentication failed")]
    Authentication,
    #[error("segment index already sealed or out of order")]
    NonceReuse,
    #[error("random key generation failed")]
    Random,
}

/// Owns one fresh file key. Not cloneable or serializable. Calls consume indices
/// even if sealing fails, so the same key/nonce cannot be retried with new bytes.
pub struct SegmentSealer {
    key: Zeroizing<[u8; 32]>,
    object_id: [u8; 32],
    layout: SegmentLayout,
    next_index: u64,
}

impl SegmentSealer {
    /// Generates independent random key and object identity for this generation.
    /// # Errors
    /// Rejects invalid dimensions or unavailable operating system randomness.
    pub fn new(layout: SegmentLayout) -> Result<Self, SegmentError> {
        layout.dimensions()?;
        let mut key = Zeroizing::new([0; 32]);
        let mut object_id = [0; 32];
        getrandom::fill(key.as_mut()).map_err(|_| SegmentError::Random)?;
        getrandom::fill(&mut object_id).map_err(|_| SegmentError::Random)?;
        Ok(Self { key, object_id, layout, next_index: 0 })
    }

    #[must_use]
    pub fn object_id(&self) -> &[u8; 32] {
        &self.object_id
    }

    /// Borrow the secret only for qualified-recipient wrapping. Never relay it.
    #[must_use]
    pub fn file_key(&self) -> &[u8; 32] {
        &self.key
    }

    /// Encrypts precisely one segment, in order. Retries use stored ciphertext.
    /// # Errors
    /// Rejects reused/skipped indices, wrong lengths and encryption failure.
    pub fn seal(&mut self, index: u64, plaintext: &[u8]) -> Result<Vec<u8>, SegmentError> {
        if index != self.next_index {
            return Err(SegmentError::NonceReuse);
        }
        let ad = self.layout.associated_data(&self.object_id, index)?;
        if plaintext.len() as u64 != self.layout.segment_plaintext_length(index)? {
            return Err(FormatError("segment plaintext length").into());
        }
        self.next_index += 1;
        let cipher = ChaCha20Poly1305::new_from_slice(self.key.as_ref())
            .map_err(|_| SegmentError::Authentication)?;
        cipher
            .encrypt(Nonce::from_slice(&nonce(index)), Payload { msg: plaintext, aad: &ad })
            .map_err(|_| SegmentError::Authentication)
    }
}

/// Authenticates one segment into a zeroizing private staging buffer. The caller
/// must verify the final streaming plaintext digest before publishing a file.
/// # Errors
/// Rejects altered layout/index/length, missing tags or authentication failures.
pub fn open_segment(
    key: &[u8; 32],
    object_id: &[u8; 32],
    layout: SegmentLayout,
    index: u64,
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>, SegmentError> {
    let ad = layout.associated_data(object_id, index)?;
    if ciphertext.len() as u64 != layout.segment_plaintext_length(index)? + 16 {
        return Err(FormatError("segment ciphertext length").into());
    }
    let cipher = ChaCha20Poly1305::new_from_slice(key).map_err(|_| SegmentError::Authentication)?;
    cipher
        .decrypt(Nonce::from_slice(&nonce(index)), Payload { msg: ciphertext, aad: &ad })
        .map(Zeroizing::new)
        .map_err(|_| SegmentError::Authentication)
}

fn nonce(index: u64) -> [u8; 12] {
    let mut nonce = [0; 12];
    nonce[4..].copy_from_slice(&index.to_be_bytes());
    nonce
}

/// # Errors
/// Rejects oversized ciphertext framing.
pub fn segment_digest(ciphertext: &[u8]) -> Result<[u8; 32], FormatError> {
    digest("ramflux.attachment.segment.cipher.v1", ciphertext)
}

/// Incremental DS plaintext verifier. No final export is allowed until finish.
pub struct PlaintextVerifier {
    hasher: blake3::Hasher,
    expected_length: u64,
    seen: u64,
}
impl PlaintextVerifier {
    #[must_use]
    pub fn new(expected_length: u64) -> Self {
        let domain = b"ramflux.attachment.plaintext.v1";
        let mut hasher = blake3::Hasher::new();
        hasher.update(&31_u32.to_be_bytes());
        hasher.update(domain);
        hasher.update(&expected_length.to_be_bytes());
        Self { hasher, expected_length, seen: 0 }
    }
    /// # Errors
    /// Rejects length overflow or bytes beyond the declared file length.
    pub fn update(&mut self, plaintext: &[u8]) -> Result<(), FormatError> {
        let next = self
            .seen
            .checked_add(plaintext.len() as u64)
            .ok_or(FormatError("plaintext overflow"))?;
        if next > self.expected_length {
            return Err(FormatError("plaintext length exceeded"));
        }
        self.hasher.update(plaintext);
        self.seen = next;
        Ok(())
    }
    /// # Errors
    /// Rejects incomplete or substituted plaintext.
    pub fn finish(self, expected: &[u8; 32]) -> Result<(), FormatError> {
        if self.seen != self.expected_length || self.hasher.finalize().as_bytes() != expected {
            return Err(FormatError("final plaintext integrity"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
