// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Dormant ciphertext storage; authentication/quota and final message publication
//! remain with their service owners. Operators keep the root private and fixed.
mod local;
pub use local::{LocalAttachmentBackend, PreparedSegment};
#[cfg(test)]
mod tests;
use ramflux_protocol::large_attachment::{SEGMENT_BYTES, VerifiedContentManifest};
use redb::{ReadableDatabase, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};

const SEGMENTS: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("native_attachment_backend_segments_v1");
const OBJECTS: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("native_attachment_backend_objects_v1");
#[derive(Debug, thiserror::Error)]
pub enum BackendError {
    #[error("backend identity conflict")]
    Conflict,
    #[error("backend range or page outside bounds")]
    Bounds,
    #[error("backend bytes are incomplete or corrupt")]
    Integrity,
    #[error("backend identity retired")]
    Retired,
    #[error("backend operation already has an owner")]
    Busy,
    #[error("backend persistence: {0}")]
    Store(String),
    #[error("remote backend: {0}")]
    Remote(&'static str),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackendSegment {
    object: [u8; 32],
    manifest: [u8; 32],
    generation: u64,
    index: u32,
    length: u64,
    chunk: u32,
    digest: [u8; 32],
}
impl BackendSegment {
    /// # Errors
    /// Refuses invalid generation/layout/index in signature-verified native bytes.
    pub fn from_manifest(
        native: &VerifiedContentManifest,
        generation: u64,
        index: u32,
    ) -> Result<Self, BackendError> {
        let m = native.manifest();
        if generation == 0 {
            return Err(BackendError::Bounds);
        }
        Ok(Self {
            object: m.object_id,
            manifest: m.hash().map_err(|_| BackendError::Integrity)?,
            generation,
            index,
            length: m
                .layout
                .segment_plaintext_length(u64::from(index))
                .map_err(|_| BackendError::Bounds)?
                + 16,
            chunk: m.layout.network_chunk_bytes,
            digest: *m.segment_digests.get(index as usize).ok_or(BackendError::Bounds)?,
        })
    }
    #[must_use]
    pub fn length(&self) -> u64 {
        self.length
    }
    #[must_use]
    pub fn chunk_bytes(&self) -> u32 {
        self.chunk
    }
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        self.digest
    }
    fn validate(&self) -> Result<(), BackendError> {
        if self.generation == 0
            || !(16..=u64::from(SEGMENT_BYTES)).contains(&self.length)
            || !matches!(self.chunk, 524_288 | 1_048_576)
        {
            return Err(BackendError::Bounds);
        }
        Ok(())
    }
}
#[derive(Clone, Serialize, Deserialize)]
struct Record {
    spec: BackendSegment,
    bits: u8,
    hashes: Vec<[u8; 32]>,
    committed: bool,
    upload: Option<String>,
}
#[derive(Clone, Serialize, Deserialize)]
struct Object {
    generation: u64,
    retired: bool,
}
#[derive(Debug, Clone)]
pub struct BackendEntry {
    pub spec: BackendSegment,
    pub received: u8,
    pub committed: bool,
    pub upload: Option<String>,
}
/// Receipt constructor is private; only durable backend publication can mint it.
pub struct BackendCommit {
    spec: BackendSegment,
}
impl BackendCommit {
    #[must_use]
    pub fn segment(&self) -> &BackendSegment {
        &self.spec
    }
}
/// All bodies use fixed-size scratch buffers. Call from bounded blocking I/O workers.
pub trait AttachmentBackend {
    /// # Errors
    /// Rejects unaligned/conflicting/short/oversized chunks and failed persistence.
    fn write_chunk(
        &self,
        spec: &BackendSegment,
        offset: u64,
        input: &mut dyn Read,
    ) -> Result<(), BackendError>;
    /// # Errors
    /// Refuses incomplete/corrupt content or any failed durable commit.
    fn commit(&self, spec: &BackendSegment) -> Result<BackendCommit, BackendError>;
    /// # Errors
    /// Refuses unpublished identities, invalid closed ranges and storage failures.
    fn read_range(
        &self,
        spec: &BackendSegment,
        offset: u64,
        length: u64,
        output: &mut dyn Write,
    ) -> Result<(), BackendError>;
    /// Returns bounded private-worker metadata; never grants serving authority.
    /// # Errors
    /// Refuses invalid pages or failed persistence.
    fn enumerate(
        &self,
        after: Option<&[u8]>,
        limit: usize,
    ) -> Result<Vec<BackendEntry>, BackendError>;
    /// Reconciles a single bounded segment after a crash.
    /// # Errors
    /// Refuses concurrent owners, retired identity or corrupt persistence.
    fn reconcile(&self, spec: &BackendSegment) -> Result<(), BackendError>;
    /// Fences the whole object before deleting this segment. The quota owner must
    /// delete every segment/orphan before releasing the whole object's charge.
    /// # Errors
    /// Retains cleanup debt on any deletion/durability failure.
    fn delete(&self, spec: &BackendSegment) -> Result<(), BackendError>;
}
pub(super) fn install(tx: &redb::WriteTransaction) -> Result<(), crate::NodeCoreError> {
    let map = |e: redb::TableError| crate::NodeCoreError::Redb(e.to_string());
    let _ = tx.open_table(SEGMENTS).map_err(map)?;
    let _ = tx.open_table(OBJECTS).map_err(map)?;
    Ok(())
}
fn store(error: impl std::fmt::Display) -> BackendError {
    BackendError::Store(error.to_string())
}
fn encode<T: Serialize>(v: &T) -> Result<Vec<u8>, BackendError> {
    serde_json::to_vec(v).map_err(store)
}
fn decode<T: serde::de::DeserializeOwned>(v: &[u8]) -> Result<T, BackendError> {
    serde_json::from_slice(v).map_err(store)
}
fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(char::from(DIGITS[usize::from(b >> 4)]));
        out.push(char::from(DIGITS[usize::from(b & 15)]));
    }
    out
}
fn segment_hasher(length: u64) -> blake3::Hasher {
    let tag = b"ramflux.attachment.segment.cipher.v1";
    let mut h = blake3::Hasher::new();
    h.update(&36_u32.to_be_bytes());
    h.update(tag);
    h.update(&length.to_be_bytes()[4..]);
    h
}
fn chunk_length(spec: &BackendSegment, offset: u64) -> Result<u64, BackendError> {
    spec.validate()?;
    if offset >= spec.length || !offset.is_multiple_of(u64::from(spec.chunk)) {
        return Err(BackendError::Bounds);
    }
    Ok((spec.length - offset).min(u64::from(spec.chunk)))
}
fn range(spec: &BackendSegment, offset: u64, length: u64) -> Result<(), BackendError> {
    spec.validate()?;
    if length == 0
        || length > u64::from(spec.chunk)
        || offset.checked_add(length).is_none_or(|end| end > spec.length)
    {
        return Err(BackendError::Bounds);
    }
    Ok(())
}

/// Streaming native segment digest verifier, also enforcing exact output length.
pub struct SegmentHashWriter {
    hash: blake3::Hasher,
    remaining: u64,
}
impl SegmentHashWriter {
    #[must_use]
    pub fn new(length: u64) -> Self {
        Self { hash: segment_hasher(length), remaining: length }
    }
    /// # Errors
    /// Refuses truncated or corrupt remote content.
    pub fn finish(self, expected: [u8; 32]) -> Result<(), BackendError> {
        if self.remaining != 0 || self.hash.finalize().as_bytes() != &expected {
            return Err(BackendError::Integrity);
        }
        Ok(())
    }
}
impl Write for SegmentHashWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() as u64 > self.remaining {
            return Err(std::io::Error::other("oversized segment stream"));
        }
        self.hash.update(bytes);
        self.remaining -= bytes.len() as u64;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
