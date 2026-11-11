// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Constant-memory chunk/root and chain commitments; no hash-list collection.
use super::{CHUNK_BYTES, PairingWire, Result, SourceManifest, WireError, require};

pub(super) fn framed(tag: &str) -> zeroize::Zeroizing<blake3::Hasher> {
    let mut hasher = zeroize::Zeroizing::new(blake3::Hasher::new());
    // All full-profile tags are fixed ASCII strings, well within a u32 frame.
    hasher.update(&u32::try_from(tag.len()).unwrap_or(u32::MAX).to_be_bytes());
    hasher.update(tag.as_bytes());
    hasher
}
/// Return (chunk count, final chunk length), checking platform/SQLite signed offsets.
/// # Errors
/// Rejects lengths outside signed 64-bit platform file limits.
pub fn chunk_layout(total: u64) -> Result<(u64, u32)> {
    require(total <= i64::MAX.cast_unsigned(), "total_bytes")?;
    let chunk = u64::from(CHUNK_BYTES);
    let count = total / chunk + u64::from(!total.is_multiple_of(chunk));
    let last = if total == 0 { 0 } else { ((total - 1) % chunk) + 1 };
    Ok((count, u32::try_from(last).map_err(|_| WireError::Size)?))
}
/// # Errors
/// Rejects empty or oversized chunks before hashing.
pub fn chunk_digest(index: u64, plaintext: &[u8]) -> Result<[u8; 32]> {
    require(!plaintext.is_empty() && plaintext.len() <= CHUNK_BYTES as usize, "chunk_length")?;
    let mut hasher = framed("ramflux.pairing.full.chunk.v1");
    hasher.update(&index.to_be_bytes());
    hasher.update(&u32::try_from(plaintext.len()).map_err(|_| WireError::Size)?.to_be_bytes());
    hasher.update(plaintext);
    Ok(*hasher.finalize().as_bytes())
}
/// Exact ordered root, including the empty stream. Only one chunk is borrowed at a time.
pub struct RootHasher {
    hasher: zeroize::Zeroizing<blake3::Hasher>,
    count: u64,
    final_length: u32,
    next: u64,
}
impl RootHasher {
    /// # Errors
    /// Rejects lengths that cannot be staged on supported platforms.
    pub fn new(total: u64) -> Result<Self> {
        let (count, final_length) = chunk_layout(total)?;
        let mut hasher = framed("ramflux.pairing.full.root.v1");
        hasher.update(&total.to_be_bytes());
        hasher.update(&count.to_be_bytes());
        Ok(Self { hasher, count, final_length, next: 0 })
    }
    /// Add the actual plaintext, checking its exact position and length first.
    /// # Errors
    /// Rejects duplicate/skipped/extra chunks and short nonfinal chunks.
    pub fn push(&mut self, index: u64, plaintext: &[u8]) -> Result<[u8; 32]> {
        require(index == self.next && index < self.count, "chunk_index")?;
        let expected = if index + 1 == self.count { self.final_length } else { CHUNK_BYTES };
        require(plaintext.len() == expected as usize, "chunk_length")?;
        let digest = chunk_digest(index, plaintext)?;
        self.hasher.update(&digest);
        self.next += 1;
        Ok(digest)
    }
    /// # Errors
    /// Refuses an incomplete stream.
    pub fn finish(self) -> Result<[u8; 32]> {
        require(self.next == self.count, "chunk_count")?;
        Ok(*self.hasher.finalize().as_bytes())
    }
}
/// # Errors
/// Refuses invalid signed-object shape; callers independently verify its branch signature.
pub fn manifest_hash(manifest: &SourceManifest) -> Result<[u8; 32]> {
    let mut hasher = framed("ramflux.pairing.full.manifest.v1");
    hasher.update(&manifest.to_wire_bytes()?);
    Ok(*hasher.finalize().as_bytes())
}
/// Replays disk-backed ordered manifest metadata into the length-prefixed chain commitment.
/// A new instance is required for each chain length because the count precedes its members.
pub struct ChainHasher {
    hasher: zeroize::Zeroizing<blake3::Hasher>,
    count: u64,
    next: u64,
}
impl ChainHasher {
    /// # Errors
    /// A chain always includes a base manifest.
    pub fn new(count: u64) -> Result<Self> {
        require(count > 0, "manifest_count")?;
        let mut hasher = framed("ramflux.pairing.full.chain.v1");
        hasher.update(&count.to_be_bytes());
        Ok(Self { hasher, count, next: 0 })
    }
    /// # Errors
    /// Refuses out-of-order or extra metadata. Parent/context checks belong to the manifest owner.
    pub fn push(&mut self, cut: u64, manifest: &[u8; 32], root: &[u8; 32]) -> Result<()> {
        require(cut == self.next && cut < self.count, "snapshot_cut")?;
        self.hasher.update(manifest);
        self.hasher.update(root);
        self.next += 1;
        Ok(())
    }
    /// # Errors
    /// Refuses an incomplete chain.
    pub fn finish(self) -> Result<[u8; 32]> {
        require(self.next == self.count, "manifest_count")?;
        Ok(*self.hasher.finalize().as_bytes())
    }
}
