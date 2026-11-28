// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Blobs (MLS-SPEC r1.1 2.7): entries and Welcomes larger than 512 KiB travel as chunks of at most
//! 512 KiB. A blob is named by `blob_ref = BLAKE3(whole payload)`; chunks arrive in order, the
//! first one carries the authority (a commit-bucket token or an admin signature), the last one
//! closes the blob if the hash matches. Pending uploads are capped per group (64 MiB; the 32 MiB
//! per session cap belongs to the session), unreferenced blobs expire after 15 minutes.

use ramflux_crypto::large_group::{LgWriter as Enc, MAX_INLINE_MLS};

use super::host::{Authority, Cx, LargeGroupHost};
use super::refusal::{LgRefusal, LgResult};
use super::rows::{BlobMeta, key};
use crate::RouterRedbStore;
use crate::router_store::lg_store::LgTable;

/// Largest chunk (spec: entries over 512 KiB are blobs).
pub const CHUNK_MAX: usize = MAX_INLINE_MLS;
/// Most chunks of a blob.
pub const CHUNKS_MAX: u32 = 32;
/// Largest blob (Welcome and commit are at most 16 MiB, MLS-0).
pub const BLOB_MAX_BYTES: u64 = 16 * 1024 * 1024;
/// Pending (unreferenced) bytes per group.
pub const PENDING_GROUP_BYTES: u64 = 64 * 1024 * 1024;
/// Pending uploads per group.
const PENDING_UPLOADS_MAX: usize = 256;
/// Metadata of an upload nobody owns yet.
const META_PENDING: u8 = 0;
const CHUNK: u8 = 1;
/// Metadata of a blob an entry or Welcome owns.
const META_OWNED: u8 = 2;
const DELETE_BATCH: usize = 64;

/// One chunk of an upload.
#[derive(Clone, Copy, Debug)]
pub struct BlobPut<'a> {
    /// `BLAKE3` of the whole payload.
    pub blob_ref: [u8; 32],
    /// Chunk position (uploads go in order from 0).
    pub idx: u32,
    /// Chunks in the blob (1 to 32; the same in every call).
    pub total: u32,
    /// The bytes (1 byte to 512 KiB).
    pub chunk: &'a [u8],
}

/// Progress after a chunk.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlobProgress {
    /// Chunks stored.
    pub received: u32,
    /// All chunks are in and the hash matched.
    pub complete: bool,
}

/// The request body a `blob.put` authority covers (token bind or admin-signed body).
#[must_use]
pub fn blob_put_body(blob_ref: &[u8; 32], total: u32) -> Vec<u8> {
    let mut enc = Enc::default();
    enc.fixed(blob_ref).u32(total);
    enc.finish()
}

fn meta_key(gid: &[u8; 32], blob_ref: &[u8; 32]) -> Vec<u8> {
    key(gid, &[&[META_PENDING], blob_ref])
}

fn owned_key(gid: &[u8; 32], blob_ref: &[u8; 32]) -> Vec<u8> {
    key(gid, &[&[META_OWNED], blob_ref])
}

fn chunk_key(gid: &[u8; 32], blob_ref: &[u8; 32], idx: u32) -> Vec<u8> {
    key(gid, &[&[CHUNK], blob_ref, &idx.to_be_bytes()])
}

impl LargeGroupHost {
    /// Store one chunk. The first chunk (`idx` 0) needs `auth` (`op` `blob.put`, body
    /// [`blob_put_body`]); later chunks of a pending upload need none.
    ///
    /// # Errors
    /// `unauthorized`, `blob_bad` (order, size, hash), `limit` (pending caps).
    pub fn blob_put(
        &self,
        store: &RouterRedbStore,
        now: u64,
        gid: &[u8; 32],
        put: &BlobPut<'_>,
        auth: Option<Authority<'_>>,
    ) -> LgResult<BlobProgress> {
        if put.chunk.is_empty()
            || put.chunk.len() > CHUNK_MAX
            || put.total == 0
            || put.total > CHUNKS_MAX
            || put.idx >= put.total
        {
            return Err(LgRefusal::BlobBad);
        }
        self.run(store, now, |cx| {
            let mut head = cx.head(gid)?;
            let existing = cx.find_meta(gid, &put.blob_ref)?;
            let mut meta = if let Some((meta, pending)) = existing {
                if !pending || meta.complete || meta.total != put.total || meta.received != put.idx {
                    return Err(LgRefusal::BlobBad);
                }
                meta
            } else {
                if put.idx != 0 {
                    return Err(LgRefusal::BlobBad);
                }
                let auth = auth.ok_or(LgRefusal::Unauthorized)?;
                let body = blob_put_body(&put.blob_ref, put.total);
                cx.authorize_op(gid, &mut head, "blob.put", &body, auth)?;
                cx.put_head(gid, &head)?;
                cx.check_pending_room(gid, put.chunk.len())?;
                BlobMeta {
                    created_ms: cx.now,
                    total: put.total,
                    received: 0,
                    bytes: 0,
                    complete: false,
                    referenced: false,
                }
            };
            meta.bytes = meta.bytes.saturating_add(u64::try_from(put.chunk.len()).unwrap_or(u64::MAX));
            if meta.bytes > BLOB_MAX_BYTES {
                return Err(LgRefusal::BlobBad);
            }
            cx.tx.put(LgTable::Blob, &chunk_key(gid, &put.blob_ref, put.idx), put.chunk)?;
            meta.received = meta.received.saturating_add(1);
            if meta.received == meta.total {
                if cx.blob_hash(gid, &put.blob_ref, meta.total)? != put.blob_ref {
                    return Err(LgRefusal::BlobBad);
                }
                meta.complete = true;
            }
            cx.tx.put(LgTable::Blob, &meta_key(gid, &put.blob_ref), &meta.encode())?;
            Ok(BlobProgress { received: meta.received, complete: meta.complete })
        })
    }

    /// One chunk of a complete blob (a member session's `blob.get`).
    ///
    /// # Errors
    /// `not_found` when the blob is unknown, incomplete or the chunk does not exist.
    pub fn blob_get(
        &self,
        store: &RouterRedbStore,
        gid: &[u8; 32],
        blob_ref: &[u8; 32],
        idx: u32,
    ) -> LgResult<Vec<u8>> {
        store.lg_read(|view| {
            let mut meta = view.get(LgTable::Blob, &owned_key(gid, blob_ref))?;
            if meta.is_none() {
                meta = view.get(LgTable::Blob, &meta_key(gid, blob_ref))?;
            }
            Ok(match meta.map(|bytes| BlobMeta::decode(&bytes)) {
                Some(Ok(meta)) if meta.complete => view
                    .get(LgTable::Blob, &chunk_key(gid, blob_ref, idx))?
                    .ok_or(LgRefusal::NotFound),
                Some(Err(refusal)) => Err(refusal),
                _ => Err(LgRefusal::NotFound),
            })
        })?
    }
}

impl Cx<'_> {
    /// Metadata of a blob and whether it is still a pending upload.
    fn find_meta(&self, gid: &[u8; 32], blob_ref: &[u8; 32]) -> LgResult<Option<(BlobMeta, bool)>> {
        if let Some(bytes) = self.tx.get(LgTable::Blob, &owned_key(gid, blob_ref))? {
            return Ok(Some((BlobMeta::decode(&bytes)?, false)));
        }
        match self.tx.get(LgTable::Blob, &meta_key(gid, blob_ref))? {
            Some(bytes) => Ok(Some((BlobMeta::decode(&bytes)?, true))),
            None => Ok(None),
        }
    }

    /// Chunk 0 of a complete blob (the entry header checks read the MLS header from it).
    pub(super) fn blob_complete_chunk0(
        &self,
        gid: &[u8; 32],
        blob_ref: &[u8; 32],
    ) -> LgResult<Vec<u8>> {
        match self.find_meta(gid, blob_ref)? {
            Some((meta, _)) if meta.complete && meta.total > 0 => self
                .tx
                .get(LgTable::Blob, &chunk_key(gid, blob_ref, 0))?
                .ok_or(LgRefusal::BlobMissing),
            _ => Err(LgRefusal::BlobMissing),
        }
    }

    /// An entry or Welcome takes ownership of a complete pending blob (a blob has one owner).
    pub(super) fn blob_reference(&self, gid: &[u8; 32], blob_ref: &[u8; 32]) -> LgResult<()> {
        let (mut meta, pending) = self
            .find_meta(gid, blob_ref)?
            .filter(|(meta, pending)| meta.complete && *pending)
            .ok_or(LgRefusal::BlobMissing)?;
        meta.referenced = true;
        self.tx.del(LgTable::Blob, &meta_key(gid, blob_ref))?;
        Ok(self.tx.put(LgTable::Blob, &owned_key(gid, blob_ref), &meta.encode())?)
    }

    /// Delete a blob and its chunks.
    pub(super) fn blob_delete(&self, gid: &[u8; 32], blob_ref: &[u8; 32]) -> LgResult<()> {
        self.tx.del(LgTable::Blob, &meta_key(gid, blob_ref))?;
        self.tx.del(LgTable::Blob, &owned_key(gid, blob_ref))?;
        let prefix = key(gid, &[&[CHUNK], blob_ref]);
        while self.tx.delete_prefix(LgTable::Blob, &prefix, DELETE_BATCH)? == DELETE_BATCH {}
        Ok(())
    }

    fn blob_hash(&self, gid: &[u8; 32], blob_ref: &[u8; 32], total: u32) -> LgResult<[u8; 32]> {
        let mut hasher = blake3::Hasher::new();
        for idx in 0..total {
            let chunk = self
                .tx
                .get(LgTable::Blob, &chunk_key(gid, blob_ref, idx))?
                .ok_or(LgRefusal::BlobBad)?;
            hasher.update(&chunk);
        }
        Ok(*hasher.finalize().as_bytes())
    }

    /// Room for one more pending upload: at most 256 uploads and 64 MiB unreferenced per group.
    fn check_pending_room(&self, gid: &[u8; 32], first_chunk: usize) -> LgResult<()> {
        let prefix = key(gid, &[&[META_PENDING]]);
        let rows = self.tx.scan(LgTable::Blob, &prefix, &prefix, PENDING_UPLOADS_MAX + 1)?;
        if rows.len() >= PENDING_UPLOADS_MAX {
            return Err(LgRefusal::Limit);
        }
        let mut pending = u64::try_from(first_chunk).unwrap_or(u64::MAX);
        for (_, value) in rows {
            pending = pending.saturating_add(BlobMeta::decode(&value)?.bytes);
        }
        if pending > PENDING_GROUP_BYTES { Err(LgRefusal::Limit) } else { Ok(()) }
    }

    /// Delete every unreferenced upload older than 15 minutes (the sweep).
    pub(super) fn sweep_blobs(&self, gid: &[u8; 32]) -> LgResult<()> {
        let prefix = key(gid, &[&[META_PENDING]]);
        let pending = self.tx.scan(LgTable::Blob, &prefix, &prefix, PENDING_UPLOADS_MAX + 1)?;
        for (row_key, value) in pending {
            let meta = BlobMeta::decode(&value)?;
            if super::check::blob_orphaned(meta.created_ms, meta.referenced, self.now) {
                let blob_ref: [u8; 32] = row_key
                    .get(prefix.len()..)
                    .and_then(|tail| tail.try_into().ok())
                    .ok_or(LgRefusal::Internal)?;
                self.blob_delete(gid, &blob_ref)?;
            }
        }
        Ok(())
    }
}
