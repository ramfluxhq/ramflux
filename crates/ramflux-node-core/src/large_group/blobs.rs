// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Blobs (MLS-SPEC r1.1 2.7): entries and Welcomes larger than 512 KiB travel as chunks of at most
//! 512 KiB. A blob is named by `blob_ref = BLAKE3(whole payload)`; chunks arrive in order, the
//! first one carries the authority (a commit-bucket token or an admin signature) and declares the
//! blob's `total_bytes`, the last one closes the blob if the hash matches. Every chunk but the last
//! is exactly 512 KiB, so `total_bytes` fixes the chunk count and the size of each chunk. The
//! declared bytes are reserved against the per-group pending cap (64 MiB; the 32 MiB per session
//! cap belongs to the session) at chunk 0, and released when an entry or Welcome takes the blob or
//! it expires unreferenced after 15 minutes.

use ramflux_crypto::large_group::{MAX_INLINE_MLS, blob_put_body};

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
    /// Bytes in the whole blob (1 byte to 16 MiB; the same in every call, declared by chunk 0).
    pub total_bytes: u64,
    /// The bytes: exactly 512 KiB, except the last chunk which holds the rest of `total_bytes`.
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

/// The size rule of one chunk: `total` is `ceil(total_bytes / 512 KiB)` (at most 32 chunks and
/// 16 MiB), every chunk but the last holds exactly 512 KiB and the last holds the rest.
#[must_use]
pub(crate) fn chunk_layout_ok(total: u32, total_bytes: u64, idx: u32, len: usize) -> bool {
    let chunk_max = u64::try_from(CHUNK_MAX).unwrap_or(u64::MAX);
    if total_bytes == 0
        || total_bytes > BLOB_MAX_BYTES
        || total == 0
        || total > CHUNKS_MAX
        || u64::from(total) != total_bytes.div_ceil(chunk_max)
        || idx >= total
    {
        return false;
    }
    let expected = if idx + 1 < total {
        chunk_max
    } else {
        total_bytes.saturating_sub(u64::from(total - 1).saturating_mul(chunk_max))
    };
    u64::try_from(len).is_ok_and(|len| len == expected)
}

/// Whether `declared` more bytes fit beside the `reserved` ones of the group's other pending
/// uploads.
#[must_use]
pub(crate) const fn reservation_fits(reserved: u64, declared: u64) -> bool {
    reserved.saturating_add(declared) <= PENDING_GROUP_BYTES
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
    /// [`blob_put_body`] (in `ramflux-crypto`)); later chunks of a pending upload need none.
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
        if !chunk_layout_ok(put.total, put.total_bytes, put.idx, put.chunk.len()) {
            return Err(LgRefusal::BlobBad);
        }
        self.run(store, now, |cx| {
            let mut head = cx.head(gid)?;
            let existing = cx.find_meta(gid, &put.blob_ref)?;
            let mut meta = if let Some((meta, pending)) = existing {
                if !pending
                    || meta.complete
                    || meta.total != put.total
                    || meta.declared_bytes != put.total_bytes
                    || meta.received != put.idx
                    || super::check::blob_orphaned(meta.created_ms, false, cx.now)
                {
                    return Err(LgRefusal::BlobBad);
                }
                meta
            } else {
                if put.idx != 0 {
                    return Err(LgRefusal::BlobBad);
                }
                let auth = auth.ok_or(LgRefusal::Unauthorized)?;
                let body = blob_put_body(&put.blob_ref, put.total, put.total_bytes);
                cx.authorize_op(gid, &mut head, "blob.put", &body, auth)?;
                cx.put_head(gid, &head)?;
                cx.check_pending_room(gid, put.total_bytes)?;
                BlobMeta {
                    created_ms: cx.now,
                    total: put.total,
                    received: 0,
                    bytes: 0,
                    declared_bytes: put.total_bytes,
                    complete: false,
                    referenced: false,
                }
            };
            meta.bytes =
                meta.bytes.saturating_add(u64::try_from(put.chunk.len()).unwrap_or(u64::MAX));
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
    #[allow(clippy::unused_self, reason = "uniform host API")]
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
        let (mut meta, _) = self
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

    /// Room for one more pending upload: at most 256 uploads, and the declared bytes of every
    /// pending upload (expired ones are dropped first) plus `declared` within 64 MiB per group.
    fn check_pending_room(&self, gid: &[u8; 32], declared: u64) -> LgResult<()> {
        self.sweep_blobs(gid)?;
        let prefix = key(gid, &[&[META_PENDING]]);
        let rows = self.tx.scan(LgTable::Blob, &prefix, &prefix, PENDING_UPLOADS_MAX + 1)?;
        if rows.len() >= PENDING_UPLOADS_MAX {
            return Err(LgRefusal::Limit);
        }
        let mut reserved = 0_u64;
        for (_, value) in rows {
            reserved = reserved.saturating_add(BlobMeta::decode(&value)?.declared_bytes);
        }
        if reservation_fits(reserved, declared) { Ok(()) } else { Err(LgRefusal::Limit) }
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

#[cfg(test)]
mod tests {
    use super::*;

    const MIB: u64 = 1024 * 1024;

    #[test]
    fn every_chunk_but_the_last_is_exactly_512_kib() {
        let full = CHUNK_MAX;
        let big = 2 * u64::try_from(full).expect("test: fits") + 10;
        assert!(chunk_layout_ok(1, 100, 0, 100), "one short chunk");
        assert!(!chunk_layout_ok(1, 100, 0, 99), "the chunk must hold all declared bytes");
        assert!(chunk_layout_ok(3, big, 0, full), "first of three is full");
        assert!(chunk_layout_ok(3, big, 1, full), "middle is full");
        assert!(chunk_layout_ok(3, big, 2, 10), "last holds the rest");
        assert!(!chunk_layout_ok(3, big, 0, full - 1), "a short middle chunk");
        assert!(!chunk_layout_ok(3, big, 2, 11), "a long last chunk");
        assert!(chunk_layout_ok(2, MIB, 1, full), "an exact multiple ends with a full chunk");
        assert!(!chunk_layout_ok(3, MIB, 0, full), "total must equal ceil(total_bytes / 512 KiB)");
        assert!(!chunk_layout_ok(1, 0, 0, 0), "an empty blob is refused");
        assert!(!chunk_layout_ok(33, 16 * MIB + 1, 0, full), "over 16 MiB is refused");
        assert!(chunk_layout_ok(32, 16 * MIB, 31, full), "16 MiB is 32 full chunks");
        assert!(!chunk_layout_ok(2, MIB, 2, full), "idx past total");
    }

    #[test]
    fn declared_bytes_are_reserved_against_the_group_cap() {
        assert!(reservation_fits(0, PENDING_GROUP_BYTES), "the whole cap fits an empty group");
        assert!(!reservation_fits(1, PENDING_GROUP_BYTES), "one byte more does not");
        let four = 4 * 16 * MIB;
        assert!(reservation_fits(0, four), "four 16 MiB uploads fill the cap");
        assert!(!reservation_fits(four, 1), "a fifth is refused at chunk 0");
        assert!(!reservation_fits(u64::MAX, 1), "no overflow");
    }

    #[test]
    fn the_put_body_binds_total_bytes() {
        let a = blob_put_body(&[1; 32], 2, MIB);
        assert_ne!(a, blob_put_body(&[1; 32], 2, MIB + 1), "total_bytes is authorised");
        assert_eq!(a.len(), 32 + 4 + 8, "blob_ref, total, total_bytes");
    }
}
