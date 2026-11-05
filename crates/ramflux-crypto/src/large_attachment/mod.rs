// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Dormant independent segment encryption. Persist ciphertext for retries;
//! a new upload generation always requires a fresh sealer and object id.
use chacha20poly1305::{
    ChaCha20Poly1305, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use ramflux_protocol::large_attachment::{
    FormatError, MediaRef, SegmentLayout, VerifiedContentManifest, digest,
};
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

/// Owns one fresh file key. Not cloneable or serializable. Validation errors
/// consume no index; once encryption starts, the index is consumed even on failure.
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
) -> Result<UnverifiedStaging, SegmentError> {
    let ad = layout.associated_data(object_id, index)?;
    if ciphertext.len() as u64 != layout.segment_plaintext_length(index)? + 16 {
        return Err(FormatError("segment ciphertext length").into());
    }
    let cipher = ChaCha20Poly1305::new_from_slice(key).map_err(|_| SegmentError::Authentication)?;
    cipher
        .decrypt(Nonce::from_slice(&nonce(index)), Payload { msg: ciphertext, aad: &ad })
        .map(|bytes| UnverifiedStaging {
            bytes: Zeroizing::new(bytes),
            object_id: *object_id,
            layout,
            index,
        })
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

/// AEAD-authenticated plaintext for private staging only. It is not a verified file
/// and must never be accepted by the P16 final export API.
pub struct UnverifiedStaging {
    bytes: Zeroizing<Vec<u8>>,
    object_id: [u8; 32],
    layout: SegmentLayout,
    index: u64,
}
impl UnverifiedStaging {
    /// Borrow only to write private staging, which stays unpublished until finish.
    #[must_use]
    pub fn as_staging_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Proof that all ordered segments matched the authenticated inner plaintext
/// digest. P16 must consume this token and bind its staging file to these exact
/// identities before atomic export. There is no public constructor or clone.
pub struct VerifiedPlaintext {
    object_id: [u8; 32],
    inner_digest: [u8; 32],
    length: u64,
}
impl VerifiedPlaintext {
    #[must_use]
    pub fn object_id(&self) -> &[u8; 32] {
        &self.object_id
    }
    #[must_use]
    pub fn inner_digest(&self) -> &[u8; 32] {
        &self.inner_digest
    }
    #[must_use]
    pub fn length(&self) -> u64 {
        self.length
    }
}

/// Incremental ordered final verification, constructed from an authenticated S0
/// reference bound to the signature-verified native manifest. Message/owner trust
/// admission remains the caller's responsibility; codec validity is not authority.
pub struct PlaintextVerifier {
    hasher: blake3::Hasher,
    layout: SegmentLayout,
    expected_digest: [u8; 32],
    object_id: [u8; 32],
    inner_digest: [u8; 32],
    seen: u64,
    next_index: u64,
}
impl PlaintextVerifier {
    /// # Errors
    /// Refuses reference/native binding mismatch or invalid dimensions.
    pub fn new(
        reference: &MediaRef,
        native: &VerifiedContentManifest,
    ) -> Result<Self, FormatError> {
        reference.validate_binding(native)?;
        let manifest = &reference.large_manifest;
        let domain = b"ramflux.attachment.plaintext.v1";
        let mut hasher = blake3::Hasher::new();
        hasher.update(
            &u32::try_from(domain.len())
                .map_err(|_| FormatError("plaintext domain length"))?
                .to_be_bytes(),
        );
        hasher.update(domain);
        hasher.update(&manifest.plaintext_length.to_be_bytes());
        Ok(Self {
            hasher,
            layout: manifest.layout(),
            expected_digest: manifest.plaintext_digest,
            object_id: native.manifest().object_id,
            inner_digest: reference.manifest_digest,
            seen: 0,
            next_index: 0,
        })
    }

    /// # Errors
    /// Rejects out-of-order, substituted or incorrectly sized staging segments.
    pub fn update_segment(
        &mut self,
        index: u64,
        plaintext: &UnverifiedStaging,
    ) -> Result<(), FormatError> {
        if index != self.next_index
            || plaintext.index != index
            || plaintext.object_id != self.object_id
            || plaintext.layout != self.layout
        {
            return Err(FormatError("plaintext segment identity/order"));
        }
        if plaintext.bytes.len() as u64 != self.layout.segment_plaintext_length(index)? {
            return Err(FormatError("plaintext segment length"));
        }
        let next = self
            .seen
            .checked_add(plaintext.bytes.len() as u64)
            .ok_or(FormatError("plaintext overflow"))?;
        if next > self.layout.plaintext_length {
            return Err(FormatError("plaintext length exceeded"));
        }
        self.hasher.update(&plaintext.bytes);
        self.seen = next;
        self.next_index += 1;
        Ok(())
    }

    /// # Errors
    /// Refuses incomplete length/count or a mismatched final plaintext digest.
    pub fn finish(self) -> Result<VerifiedPlaintext, FormatError> {
        if self.seen != self.layout.plaintext_length {
            return Err(FormatError("incomplete plaintext length"));
        }
        if self.next_index != u64::from(self.layout.dimensions()?.0) {
            return Err(FormatError("incomplete plaintext segment count"));
        }
        if self.hasher.finalize().as_bytes() != &self.expected_digest {
            return Err(FormatError("final plaintext digest"));
        }
        Ok(VerifiedPlaintext {
            object_id: self.object_id,
            inner_digest: self.inner_digest,
            length: self.seen,
        })
    }
}

#[cfg(test)]
mod tests;
