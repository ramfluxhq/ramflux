// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Dormant large-attachment wire formats. These codecs confer no authority.
mod media;
mod native;
pub use media::{MediaKeySlot, MediaManifest, MediaRef, PeerMedia, QualifiedDevice, Thumbnail};
pub use native::{ContentManifest, QualifiedOwner};

pub const SEGMENT_BYTES: u32 = 4 * 1024 * 1024;
pub const PLAINTEXT_SEGMENT_BYTES: u64 = SEGMENT_BYTES as u64 - 16;
pub const MAX_MANIFEST_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("invalid large attachment: {0}")]
pub struct FormatError(pub &'static str);

/// Checked immutable lengths shared by native, inner and AEAD formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SegmentLayout {
    pub plaintext_length: u64,
    pub network_chunk_bytes: u32,
}

impl SegmentLayout {
    /// Returns the segment count and ciphertext length.
    /// # Errors
    /// Rejects unsupported chunks, arithmetic overflow and oversized hash lists.
    pub fn dimensions(self) -> Result<(u32, u64), FormatError> {
        if !matches!(self.network_chunk_bytes, 524_288 | 1_048_576) {
            return Err(FormatError("network chunk size"));
        }
        let n = self.plaintext_length.div_ceil(PLAINTEXT_SEGMENT_BYTES).max(1);
        if n > (MAX_MANIFEST_BYTES / 34) as u64 {
            return Err(FormatError("segment list exceeds inner cap"));
        }
        let cipher = self
            .plaintext_length
            .checked_add(n * 16)
            .ok_or(FormatError("ciphertext length overflow"))?;
        Ok((u32::try_from(n).map_err(|_| FormatError("segment count"))?, cipher))
    }

    /// Exact segment AD from the frozen version-one transcript.
    /// # Errors
    /// Rejects invalid layout or index.
    pub fn associated_data(self, object_id: &[u8; 32], index: u64) -> Result<Vec<u8>, FormatError> {
        let (n, cipher) = self.dimensions()?;
        if index >= u64::from(n) {
            return Err(FormatError("segment index"));
        }
        let len =
            (self.plaintext_length - index * PLAINTEXT_SEGMENT_BYTES).min(PLAINTEXT_SEGMENT_BYTES);
        let mut out = Vec::new();
        lp(&mut out, b"ramflux.attachment.segment.v1")?;
        out.extend_from_slice(&1_u64.to_be_bytes());
        out.extend_from_slice(object_id);
        for value in [
            self.plaintext_length,
            cipher,
            u64::from(SEGMENT_BYTES),
            u64::from(self.network_chunk_bytes),
            u64::from(n),
            index,
            len,
            u64::from(index + 1 == u64::from(n)),
        ] {
            out.extend_from_slice(&value.to_be_bytes());
        }
        Ok(out)
    }

    /// # Errors
    /// Rejects invalid layout or index.
    pub fn segment_plaintext_length(self, index: u64) -> Result<u64, FormatError> {
        let (n, _) = self.dimensions()?;
        if index >= u64::from(n) {
            return Err(FormatError("segment index"));
        }
        Ok((self.plaintext_length - index * PLAINTEXT_SEGMENT_BYTES).min(PLAINTEXT_SEGMENT_BYTES))
    }
}

pub(crate) fn lp(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), FormatError> {
    let len = u32::try_from(bytes.len()).map_err(|_| FormatError("LP length"))?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

/// Domain-separated digest D, with checked u32 length framing.
/// # Errors
/// Rejects inputs exceeding LP framing.
pub fn digest(domain: &str, bytes: &[u8]) -> Result<[u8; 32], FormatError> {
    let mut h = blake3::Hasher::new();
    for b in [domain.as_bytes(), bytes] {
        h.update(
            &u32::try_from(b.len()).map_err(|_| FormatError("digest LP length"))?.to_be_bytes(),
        );
        h.update(b);
    }
    Ok(*h.finalize().as_bytes())
}

#[cfg(test)]
mod tests;
