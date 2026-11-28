// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Group attachments (MLS-SPEC r1.3 2.2, 2.5, 2.6, 2.7; Fable F2): sealed files of at most 16 MiB
//! in a multiple of 64 KiB, uploaded in 512 KiB chunks before the post that names them. They live
//! in their own table (`lg_attach`), never in `lg_blob`, so no commit or entry can name one and
//! `attach.*` never reads a commit blob. The host ties an attachment to nothing: no post, no
//! pseudonym, no session, no fetch count; a complete row holds the UTC day of completion, never the
//! time of day. Chunk 0 spends one `attach`-bucket token (no admin-signature path); later chunks
//! need nothing (the last chunk's hash check refuses foreign bytes). An attachment lives 30 to 31
//! days from completion, or until the group's store is over `attach_store_bytes` (then oldest
//! first), or until its `del_secret` holder deletes it. Admin delete is a tombstone only: the
//! blob stays until it expires.
//!
//! Keys under `gid`: `[0] ‖ blob_ref` pending upload; `[1] ‖ blob_ref ‖ idx` chunk; `[2] ‖
//! blob_ref` complete; `[3] ‖ completed_day (8 BE) ‖ blob_ref` age index; `[4]` stored bytes.

use ramflux_crypto::large_group::{
    ATTACH_MAX_BYTES, LgReader as Dec, LgWriter as Enc, Token, TokenBucket, attach_put_body,
    attach_size_ok, op_bind,
};
use subtle::ConstantTimeEq;

use super::blobs::{BlobProgress, chunk_layout_ok};
use super::check::{DAY_MS, attach_expired, attach_pool_fits, blob_orphaned, evict_until};
use super::host::{Cx, LargeGroupHost};
use super::refusal::{LgRefusal, LgResult};
use super::rows::{AttachDone, AttachPending, key};
use crate::RouterRedbStore;
use crate::router_store::lg_store::LgTable;

/// Pending uploads per group.
const PENDING_MAX: usize = 256;
/// Rows one pass of eviction or expiry looks at.
const PASS_ROWS: usize = 4_096;
const DELETE_BATCH: usize = 64;
/// The store ceiling never goes below one maximum attachment.
pub const ATTACH_STORE_FLOOR: u64 = ATTACH_MAX_BYTES;
/// Default store ceiling per group: 8 GiB.
pub const ATTACH_STORE_DEFAULT: u64 = 8 * 1024 * 1024 * 1024;

const PENDING: u8 = 0;
const CHUNK: u8 = 1;
const DONE: u8 = 2;
const AGE: u8 = 3;
const STATS: u8 = 4;

/// One chunk of an attachment upload.
#[derive(Clone, Copy, Debug)]
pub struct AttachPut<'a> {
    /// `BLAKE3` of the whole sealed attachment.
    pub blob_ref: [u8; 32],
    /// Chunk position (uploads go in order from 0).
    pub idx: u32,
    /// Chunks in the attachment (the same in every call).
    pub total: u32,
    /// Bytes of the whole attachment (a multiple of 64 KiB up to 16 MiB; declared by chunk 0).
    pub total_bytes: u64,
    /// `BLAKE3(del_secret)`: required on chunk 0, absent on later chunks.
    pub del_hash: Option<[u8; 32]>,
    /// The bytes: exactly 512 KiB, except the last chunk which holds the rest of `total_bytes`.
    pub chunk: &'a [u8],
}

fn pending_key(gid: &[u8; 32], blob_ref: &[u8; 32]) -> Vec<u8> {
    key(gid, &[&[PENDING], blob_ref])
}

fn chunk_key(gid: &[u8; 32], blob_ref: &[u8; 32], idx: u32) -> Vec<u8> {
    key(gid, &[&[CHUNK], blob_ref, &idx.to_be_bytes()])
}

fn done_key(gid: &[u8; 32], blob_ref: &[u8; 32]) -> Vec<u8> {
    key(gid, &[&[DONE], blob_ref])
}

fn age_key(gid: &[u8; 32], day: u64, blob_ref: &[u8; 32]) -> Vec<u8> {
    key(gid, &[&[AGE], &day.to_be_bytes(), blob_ref])
}

fn stats_key(gid: &[u8; 32]) -> Vec<u8> {
    key(gid, &[&[STATS]])
}

fn ct_equal(left: &[u8; 32], right: &[u8; 32]) -> bool {
    bool::from(left.ct_eq(right))
}

impl LargeGroupHost {
    /// The effective per-group store ceiling (the configured value, at least 16 MiB).
    pub(super) fn attach_cap(&self) -> u64 {
        self.config.attach_store_bytes.max(ATTACH_STORE_FLOOR)
    }

    /// Store one chunk of an attachment. Chunk 0 declares `total_bytes` and `del_hash` and spends
    /// one `attach` token bound to `op_bind("attach.put", gid, attach_put_body(..))`; later chunks
    /// of a pending upload need no token and no `del_hash`.
    ///
    /// # Errors
    /// `unauthorized` (token), `token_epoch_stale`, `token_spent`, `blob_bad` (size, order, hash,
    /// a known `blob_ref`), `bad_request` (`del_hash` rule), `limit` (pending pool).
    pub fn attach_put(
        &self,
        store: &RouterRedbStore,
        now: u64,
        gid: &[u8; 32],
        put: &AttachPut<'_>,
        token: Option<&Token>,
    ) -> LgResult<BlobProgress> {
        if !attach_size_ok(put.total_bytes)
            || !chunk_layout_ok(put.total, put.total_bytes, put.idx, put.chunk.len())
        {
            return Err(LgRefusal::BlobBad);
        }
        if put.del_hash.is_some() != (put.idx == 0) {
            return Err(LgRefusal::BadRequest);
        }
        let cap = self.attach_cap();
        self.run(store, now, |cx| {
            let mut head = cx.head(gid)?;
            let row_key = pending_key(gid, &put.blob_ref);
            let mut meta = if put.idx == 0 {
                if cx.tx.get(LgTable::Attach, &row_key)?.is_some()
                    || cx.tx.get(LgTable::Attach, &done_key(gid, &put.blob_ref))?.is_some()
                {
                    return Err(LgRefusal::BlobBad);
                }
                let del_hash = put.del_hash.ok_or(LgRefusal::BadRequest)?;
                let token = token.ok_or(LgRefusal::Unauthorized)?;
                let body = attach_put_body(&put.blob_ref, put.total, put.total_bytes, &del_hash);
                let bind = op_bind("attach.put", gid, &body);
                cx.spend_token(gid, &mut head, TokenBucket::Attach, token, &bind)?;
                cx.put_head(gid, &head)?;
                cx.check_attach_room(gid, put.total_bytes)?;
                AttachPending {
                    created_ms: cx.now,
                    total: put.total,
                    received: 0,
                    bytes: 0,
                    declared_bytes: put.total_bytes,
                    del_hash,
                }
            } else {
                let bytes = cx.tx.get(LgTable::Attach, &row_key)?.ok_or(LgRefusal::BlobBad)?;
                let meta = AttachPending::decode(&bytes)?;
                if meta.total != put.total
                    || meta.declared_bytes != put.total_bytes
                    || meta.received != put.idx
                    || blob_orphaned(meta.created_ms, false, cx.now)
                {
                    return Err(LgRefusal::BlobBad);
                }
                meta
            };
            meta.bytes =
                meta.bytes.saturating_add(u64::try_from(put.chunk.len()).unwrap_or(u64::MAX));
            if meta.bytes > ATTACH_MAX_BYTES {
                return Err(LgRefusal::BlobBad);
            }
            cx.tx.put(LgTable::Attach, &chunk_key(gid, &put.blob_ref, put.idx), put.chunk)?;
            meta.received = meta.received.saturating_add(1);
            if meta.received < meta.total {
                cx.tx.put(LgTable::Attach, &row_key, &meta.encode())?;
                return Ok(BlobProgress { received: meta.received, complete: false });
            }
            if cx.attach_hash(gid, &put.blob_ref, meta.total)? != put.blob_ref {
                return Err(LgRefusal::BlobBad);
            }
            cx.attach_complete(gid, &put.blob_ref, &meta)?;
            cx.attach_evict(gid, cap)?;
            Ok(BlobProgress { received: meta.received, complete: true })
        })
    }

    /// One chunk of a complete attachment. Read-only: a fetch changes nothing and extends nothing.
    ///
    /// # Errors
    /// `not_found` when the attachment is unknown, incomplete, gone or the chunk does not exist
    /// (the client shows `expired`).
    #[allow(clippy::unused_self, reason = "uniform host API")]
    pub fn attach_get(
        &self,
        store: &RouterRedbStore,
        gid: &[u8; 32],
        blob_ref: &[u8; 32],
        idx: u32,
    ) -> LgResult<Vec<u8>> {
        store.lg_read(|view| {
            if view.get(LgTable::Attach, &done_key(gid, blob_ref))?.is_none() {
                return Ok(Err(LgRefusal::NotFound));
            }
            Ok(view
                .get(LgTable::Attach, &chunk_key(gid, blob_ref, idx))?
                .ok_or(LgRefusal::NotFound))
        })?
    }

    /// Delete an attachment, pending or complete, for the holder of its `del_secret`. No token.
    ///
    /// # Errors
    /// `not_found` (unknown), `unauthorized` (`BLAKE3(del_secret)` is not the stored `del_hash`).
    pub fn attach_delete(
        &self,
        store: &RouterRedbStore,
        now: u64,
        gid: &[u8; 32],
        blob_ref: &[u8; 32],
        del_secret: &[u8; 32],
    ) -> LgResult<()> {
        self.run(store, now, |cx| {
            let (del_hash, done) = if let Some(bytes) =
                cx.tx.get(LgTable::Attach, &done_key(gid, blob_ref))?
            {
                let row = AttachDone::decode(&bytes)?;
                (row.del_hash, Some(row))
            } else if let Some(bytes) = cx.tx.get(LgTable::Attach, &pending_key(gid, blob_ref))? {
                (AttachPending::decode(&bytes)?.del_hash, None)
            } else {
                return Err(LgRefusal::NotFound);
            };
            if !ct_equal(blake3::hash(del_secret).as_bytes(), &del_hash) {
                return Err(LgRefusal::Unauthorized);
            }
            cx.attach_remove(gid, blob_ref, done.as_ref())
        })
    }
}

impl Cx<'_> {
    fn stored_bytes(&self, gid: &[u8; 32]) -> LgResult<u64> {
        match self.tx.get(LgTable::Attach, &stats_key(gid))? {
            Some(bytes) => {
                let mut dec = Dec::new(&bytes);
                let value = dec.u64().map_err(|_| LgRefusal::Internal)?;
                dec.finish().map_err(|_| LgRefusal::Internal)?;
                Ok(value)
            }
            None => Ok(0),
        }
    }

    fn put_stored_bytes(&self, gid: &[u8; 32], stored: u64) -> LgResult<()> {
        let mut enc = Enc::default();
        enc.u64(stored);
        Ok(self.tx.put(LgTable::Attach, &stats_key(gid), &enc.finish())?)
    }

    /// Room for one more pending upload: at most 256 uploads and, with `declared`, 128 MiB of
    /// declared bytes (expired uploads are dropped first). Counts come from a scan, never a
    /// stored counter.
    fn check_attach_room(&self, gid: &[u8; 32], declared: u64) -> LgResult<()> {
        self.sweep_attach_pending(gid)?;
        let prefix = key(gid, &[&[PENDING]]);
        let rows = self.tx.scan(LgTable::Attach, &prefix, &prefix, PENDING_MAX + 1)?;
        if rows.len() >= PENDING_MAX {
            return Err(LgRefusal::Limit);
        }
        let mut pending = 0_u64;
        for (_, value) in rows {
            pending = pending.saturating_add(AttachPending::decode(&value)?.declared_bytes);
        }
        if attach_pool_fits(pending, declared) { Ok(()) } else { Err(LgRefusal::Limit) }
    }

    /// Delete every pending upload of the group older than 15 minutes.
    pub(super) fn sweep_attach_pending(&self, gid: &[u8; 32]) -> LgResult<()> {
        let prefix = key(gid, &[&[PENDING]]);
        for (row_key, value) in self.tx.scan(LgTable::Attach, &prefix, &prefix, PENDING_MAX + 1)? {
            if blob_orphaned(AttachPending::decode(&value)?.created_ms, false, self.now) {
                let blob_ref: [u8; 32] = row_key
                    .get(prefix.len()..)
                    .and_then(|tail| tail.try_into().ok())
                    .ok_or(LgRefusal::Internal)?;
                self.attach_remove(gid, &blob_ref, None)?;
            }
        }
        Ok(())
    }

    fn attach_hash(&self, gid: &[u8; 32], blob_ref: &[u8; 32], total: u32) -> LgResult<[u8; 32]> {
        let mut hasher = blake3::Hasher::new();
        for idx in 0..total {
            let chunk = self
                .tx
                .get(LgTable::Attach, &chunk_key(gid, blob_ref, idx))?
                .ok_or(LgRefusal::BlobBad)?;
            hasher.update(&chunk);
        }
        Ok(*hasher.finalize().as_bytes())
    }

    /// Pending becomes complete in one transaction: row, age index (UTC day), stored bytes.
    fn attach_complete(
        &self,
        gid: &[u8; 32],
        blob_ref: &[u8; 32],
        meta: &AttachPending,
    ) -> LgResult<()> {
        let day = self.now / DAY_MS;
        let done = AttachDone {
            completed_day: day,
            total: meta.total,
            bytes: meta.bytes,
            del_hash: meta.del_hash,
        };
        self.tx.del(LgTable::Attach, &pending_key(gid, blob_ref))?;
        self.tx.put(LgTable::Attach, &done_key(gid, blob_ref), &done.encode())?;
        self.tx.put(LgTable::Attach, &age_key(gid, day, blob_ref), &[])?;
        let stored = self.stored_bytes(gid)?.saturating_add(meta.bytes);
        self.put_stored_bytes(gid, stored)
    }

    /// Delete an attachment's rows and chunks; a complete one (`done`) also leaves the age index
    /// and the stored-bytes stat.
    fn attach_remove(
        &self,
        gid: &[u8; 32],
        blob_ref: &[u8; 32],
        done: Option<&AttachDone>,
    ) -> LgResult<()> {
        self.tx.del(LgTable::Attach, &pending_key(gid, blob_ref))?;
        let prefix = key(gid, &[&[CHUNK], blob_ref]);
        while self.tx.delete_prefix(LgTable::Attach, &prefix, DELETE_BATCH)? == DELETE_BATCH {}
        if let Some(done) = done {
            self.tx.del(LgTable::Attach, &done_key(gid, blob_ref))?;
            self.tx.del(LgTable::Attach, &age_key(gid, done.completed_day, blob_ref))?;
            let stored = self.stored_bytes(gid)?.saturating_sub(done.bytes);
            self.put_stored_bytes(gid, stored)?;
        }
        Ok(())
    }

    /// The oldest complete attachments of the group (age index order), at most `limit`.
    fn attach_oldest(&self, gid: &[u8; 32], limit: usize) -> LgResult<Vec<([u8; 32], AttachDone)>> {
        let prefix = key(gid, &[&[AGE]]);
        let mut found = Vec::new();
        for (row_key, _) in self.tx.scan(LgTable::Attach, &prefix, &prefix, limit)? {
            let blob_ref: [u8; 32] = row_key
                .get(prefix.len().saturating_add(8)..)
                .and_then(|tail| tail.try_into().ok())
                .ok_or(LgRefusal::Internal)?;
            let bytes = self
                .tx
                .get(LgTable::Attach, &done_key(gid, &blob_ref))?
                .ok_or(LgRefusal::Internal)?;
            found.push((blob_ref, AttachDone::decode(&bytes)?));
        }
        Ok(found)
    }

    /// Evict oldest first until the group's stored bytes are at most `cap`. A completion never
    /// leaves the store over the ceiling (one attachment is at most 16 MiB, the floor of `cap`).
    pub(super) fn attach_evict(&self, gid: &[u8; 32], cap: u64) -> LgResult<()> {
        loop {
            let stored = self.stored_bytes(gid)?;
            if stored <= cap {
                return Ok(());
            }
            let oldest = self.attach_oldest(gid, PASS_ROWS)?;
            let sizes: Vec<u64> = oldest.iter().map(|(_, done)| done.bytes).collect();
            let count = evict_until(stored, cap, &sizes);
            if count == 0 {
                return Ok(());
            }
            for (blob_ref, done) in oldest.iter().take(count) {
                self.attach_remove(gid, blob_ref, Some(done))?;
            }
        }
    }

    /// The retention pass of one group: pending uploads past 15 minutes, complete attachments past
    /// `completed_day + 31`, then oldest first while the store is over `cap`.
    pub(super) fn sweep_attach(&self, gid: &[u8; 32], cap: u64) -> LgResult<()> {
        self.sweep_attach_pending(gid)?;
        let today = self.now / DAY_MS;
        let mut expired = Vec::new();
        for (blob_ref, done) in self.attach_oldest(gid, PASS_ROWS)? {
            if !attach_expired(done.completed_day, today) {
                break;
            }
            expired.push((blob_ref, done));
        }
        for (blob_ref, done) in &expired {
            self.attach_remove(gid, blob_ref, Some(done))?;
        }
        self.attach_evict(gid, cap)
    }
}
