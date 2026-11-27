// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Log append, token epoch rolls and the checks on posted entries (tokens, CAS, key delivery).

use ramflux_crypto::large_group::{
    EntryHeader, EntryKind, KeyDelivery, LgReader as Dec, LgWriter as Enc, PostEntry,
    RedeliveryDecision, SIZE_BUCKETS, SignedKeyBody, TAG_SLOTS, Token, audit_path, entry_bind_hash,
    entry_chain_hash, header_hash, host_head_sign, kd_meta_encode, leaf_hash, merkle_root,
    next_head, random_array, verify_token_binding,
};

use super::host::{Op, verify_plain};
use super::rows::{LogRow, Meta, ROLE_ADMIN, UNKEYED};
use super::store::{LOG, PSEUDO, Refuse, SLOT, SPENT, STATE, key};

type Paths = Vec<Vec<[u8; 32]>>;

const DAY_MS: u64 = 24 * 60 * 60 * 1_000;
const GRACE_MS: u64 = 10 * 60 * 1_000;
const SPENT_FULL: u64 = 1_000_000;
const TAG_REPLY: u8 = 3;
const ROLL_DAILY: u8 = 2;
const ROLL_SPENT_FULL: u8 = 3;

fn bad<T>(_: T) -> Refuse {
    "bad_request"
}

impl Op<'_> {
    /// Chains, signs and stores one entry; updates the counters in `meta` (the caller stores it).
    pub(super) fn append_row(
        &mut self,
        gid: &[u8; 32],
        meta: &mut Meta,
        header: EntryHeader,
        parts: (Vec<u8>, Vec<u8>, Vec<u8>),
        slots: (&[u8; 32], u32),
    ) -> Result<(u64, LogRow), Refuse> {
        let (ciphertext, token, kd_meta) = parts;
        let seq = meta.last_seq.saturating_add(1);
        let appended_ms = self
            .mem
            .faults
            .forced_appended_ms
            .take()
            .unwrap_or_else(|| self.now.max(meta.last_appended_ms));
        let bind = entry_bind_hash(&header_hash(&header), &ciphertext);
        let chain = entry_chain_hash(&bind, &token, appended_ms, seq);
        let head = next_head(&meta.last_head, seq, &chain);
        let keys = self.keys(gid)?;
        let sig = host_head_sign(&keys.key.head_signing_seed(), gid, seq, &head);
        let row = LogRow {
            header,
            ciphertext,
            token,
            kd_meta,
            appended_ms,
            head,
            sig,
            slot_root: *slots.0,
            slot_count: slots.1,
        };
        self.tx.put(LOG, &key(&[gid, &seq.to_be_bytes()]), &row.encode())?;
        meta.last_seq = seq;
        meta.last_head = head;
        meta.last_appended_ms = appended_ms;
        Ok((seq, row))
    }

    fn plain_header(kind: u8, key_epoch: u64) -> Result<EntryHeader, Refuse> {
        Ok(EntryHeader {
            kind,
            post_id: random_array::<16>().map_err(|_| "internal")?,
            key_epoch,
            bucket: 0,
            del_secret_hash: [0_u8; 32],
            tags: [[0_u8; 16]; TAG_SLOTS],
        })
    }

    /// Appends a host-visible entry whose body is plaintext (admin chain, `slot_bad`).
    pub(super) fn append_plain(
        &mut self,
        gid: &[u8; 32],
        kind: u8,
        body: &[u8],
    ) -> Result<u64, Refuse> {
        let mut meta = self.meta(gid)?;
        let header = Self::plain_header(kind, meta.key_epoch)?;
        let (seq, _) = self.append_row(
            gid,
            &mut meta,
            header,
            (body.to_vec(), Vec::new(), Vec::new()),
            (&[0; 32], 0),
        )?;
        self.put_meta(gid, &meta)?;
        Ok(seq)
    }

    /// Writes a `token_epoch` roll (host-written, host-visible) and ends the previous epoch.
    pub(super) fn write_roll(
        &mut self,
        gid: &[u8; 32],
        reason: u8,
        refs: &[u64],
    ) -> Result<u64, Refuse> {
        let mut meta = self.meta(gid)?;
        meta.te = meta.te.saturating_add(1);
        meta.te_started_ms = self.now;
        meta.last_roll_kind = reason;
        meta.spent_count = 0;
        let mut body = Enc::default();
        body.u32(meta.te).u8(reason).u32(u32::try_from(refs.len()).unwrap_or(0));
        for seq in refs {
            body.u64(*seq);
        }
        body.u64(self.now);
        let header = Self::plain_header(EntryKind::TOKEN_EPOCH, meta.key_epoch)?;
        let (seq, _) = self.append_row(
            gid,
            &mut meta,
            header,
            (body.finish(), Vec::new(), Vec::new()),
            (&[0; 32], 0),
        )?;
        if let Some(old) = meta.te.checked_sub(2) {
            self.tx.delete_prefix(SPENT, &key(&[gid, &old.to_be_bytes()]))?;
        }
        self.tx.delete_prefix(STATE, &key(&[gid, &[TAG_REPLY]]))?;
        self.put_meta(gid, &meta)?;
        Ok(seq)
    }

    pub(super) fn maybe_daily_roll(&mut self, gid: &[u8; 32]) -> Result<(), Refuse> {
        let meta = self.meta(gid)?;
        if meta.spent_count >= SPENT_FULL {
            self.write_roll(gid, ROLL_SPENT_FULL, &[])?;
        } else if self.now.saturating_sub(meta.te_started_ms) >= DAY_MS {
            self.write_roll(gid, ROLL_DAILY, &[])?;
        }
        Ok(())
    }

    fn token_ok(
        &mut self,
        gid: &[u8; 32],
        meta: &mut Meta,
        entry: &PostEntry,
    ) -> Result<(), Refuse> {
        let token = Token::from_bytes(&entry.token).map_err(|_| "bad_token")?;
        let grace = token.te.saturating_add(1) == meta.te
            && matches!(meta.last_roll_kind, ROLL_DAILY | ROLL_SPENT_FULL)
            && self.now.saturating_sub(meta.te_started_ms) < GRACE_MS;
        if token.te != meta.te && !grace {
            return Err("token_epoch_stale");
        }
        let keys = self.keys(gid)?;
        let bind = entry_bind_hash(&header_hash(&entry.header), &entry.ciphertext);
        let spent =
            verify_token_binding(&keys.root, gid, &token, &bind).map_err(|_| "bad_token")?;
        let spent_key = key(&[gid, &token.te.to_be_bytes(), &spent]);
        if self.tx.get(SPENT, &spent_key)?.is_some() {
            return Err("spent");
        }
        self.tx.put(SPENT, &spent_key, &[])?;
        meta.spent_count = meta.spent_count.saturating_add(1);
        Ok(())
    }

    /// Host check of a key-moving entry (design 2.4.1): CAS, slot set, root and signer.
    fn check_key(
        &mut self,
        gid: &[u8; 32],
        meta: &Meta,
        header: &EntryHeader,
        kd: &KeyDelivery,
    ) -> Result<([u8; 32], Paths), Refuse> {
        let body = SignedKeyBody::decode(&kd.body_bytes).map_err(bad)?;
        let redeliver = header.kind == EntryKind::KEY_REDELIVER;
        let (want_epoch, want_prev) = if redeliver {
            (meta.key_epoch, meta.epoch_prev_seq)
        } else {
            (meta.key_epoch.saturating_add(1), meta.epoch_seq)
        };
        if body.group_id != *gid
            || body.kind != header.kind
            || body.key_epoch != header.key_epoch
            || header.key_epoch != want_epoch
            || body.prev_key_seq != want_prev
        {
            return Err("key_epoch_stale");
        }
        let count = kd.joiners.len();
        let sorted = kd.joiners.windows(2).all(|pair| pair[0] < pair[1]);
        if count == 0 || count > 100 || !sorted || kd.slots.len() != count {
            return Err("slot_set_mismatch");
        }
        let mut leaves = Vec::with_capacity(count);
        for (p, ct) in kd.joiners.iter().zip(&kd.slots) {
            leaves.push(leaf_hash(p, ct));
        }
        let root = merkle_root(&leaves).map_err(|_| "slot_set_mismatch")?;
        if body.slot_root != root || usize::try_from(body.slot_count).ok() != Some(count) {
            return Err("slot_set_mismatch");
        }
        self.check_joiners(gid, meta, header.kind, kd)?;
        let mut paths = Vec::with_capacity(count);
        for index in 0..count {
            paths.push(audit_path(&leaves, index).map_err(|_| "internal")?);
        }
        Ok((root, paths))
    }

    fn check_joiners(
        &mut self,
        gid: &[u8; 32],
        meta: &Meta,
        kind: u8,
        kd: &KeyDelivery,
    ) -> Result<(), Refuse> {
        if kind == EntryKind::KEY_W {
            let (Some(signer), Some(sig)) = (kd.signer_p, kd.body_sig) else {
                return Err("bad_signature");
            };
            verify_plain(&signer, &kd.body_bytes, &sig)?;
            if !meta.approval_on
                || self.pseudo(gid, &signer)?.is_none_or(|row| !row.active || row.role < ROLE_ADMIN)
            {
                return Err("forbidden");
            }
        }
        for joiner in &kd.joiners {
            let row = self.pseudo(gid, joiner)?.ok_or("not_found")?;
            let ok = match kind {
                EntryKind::KEY_W => !row.active && self.now.saturating_sub(row.joined_ms) < DAY_MS,
                EntryKind::KEY_W_PRIME => {
                    !meta.approval_on && row.active && row.keyed_epoch == UNKEYED
                }
                _ => kd.joiners.len() == 1 && row.keyed_epoch == meta.key_epoch,
            };
            if !ok {
                return Err("joiner_state");
            }
        }
        if kind == EntryKind::KEY_REDELIVER {
            let now = self.now;
            let seq = meta.last_seq.saturating_add(1);
            let joiner = kd.joiners.first().copied().ok_or("bad_request")?;
            let ledger = self.mem.ledgers.entry((*gid, joiner)).or_default();
            match ledger.decide_redelivery(now, seq) {
                RedeliveryDecision::Accept => {}
                RedeliveryDecision::RefuseCounted => return Err("redelivery_refused"),
                RedeliveryDecision::RefuseCeilingOfferRejoin => return Err("redelivery_ceiling"),
            }
        }
        Ok(())
    }

    pub(super) fn post(&mut self, body: &[u8]) -> Result<Vec<u8>, Refuse> {
        let mut dec = Dec::new(body);
        let gid: [u8; 32] = dec.fixed().map_err(bad)?;
        let entry = PostEntry::decode(dec.var(32 * 1024).map_err(bad)?).map_err(bad)?;
        dec.finish().map_err(bad)?;
        self.maybe_daily_roll(&gid)?;
        let mut meta = self.meta(&gid)?;
        let kind = entry.header.kind;
        if !matches!(
            kind,
            EntryKind::POST
                | EntryKind::REACTION
                | EntryKind::EDIT
                | EntryKind::KEY_W
                | EntryKind::KEY_W_PRIME
                | EntryKind::KEY_REDELIVER
        ) {
            return Err("unsupported_kind");
        }
        let bucket = usize::try_from(entry.header.bucket).map_err(bad)?;
        if !SIZE_BUCKETS.contains(&bucket) || entry.ciphertext.len() != bucket {
            return Err("bad_bucket");
        }
        let is_key =
            matches!(kind, EntryKind::KEY_W | EntryKind::KEY_W_PRIME | EntryKind::KEY_REDELIVER);
        if is_key != entry.key.is_some() {
            return Err("bad_request");
        }
        if !is_key && entry.header.key_epoch != meta.key_epoch {
            return Err("key_epoch_stale");
        }
        let checked = match &entry.key {
            Some(kd) => Some(self.check_key(&gid, &meta, &entry.header, kd)?),
            None => None,
        };
        if kind != EntryKind::KEY_W {
            self.token_ok(&gid, &mut meta, &entry)?;
        } else if !entry.token.is_empty() {
            return Err("bad_request");
        }
        let kd_meta = entry.key.as_ref().map(kd_meta_encode).unwrap_or_default();
        let (root, count) = match (&checked, &entry.key) {
            (Some((root, _)), Some(kd)) => (*root, u32::try_from(kd.joiners.len()).map_err(bad)?),
            _ => ([0_u8; 32], 0),
        };
        let header = entry.header;
        let (seq, row) = self.append_row(
            &gid,
            &mut meta,
            header,
            (entry.ciphertext, entry.token, kd_meta),
            (&root, count),
        )?;
        if let (Some((_, paths)), Some(kd)) = (checked, entry.key) {
            self.store_key_effects(&gid, &mut meta, (seq, kind), &kd, &paths)?;
        }
        self.put_meta(&gid, &meta)?;
        let mut reply = Enc::default();
        reply.u64(seq).u64(row.appended_ms).fixed(&row.head).fixed(&row.sig);
        Ok(reply.finish())
    }

    fn store_key_effects(
        &mut self,
        gid: &[u8; 32],
        meta: &mut Meta,
        (seq, kind): (u64, u8),
        kd: &KeyDelivery,
        paths: &[Vec<[u8; 32]>],
    ) -> Result<(), Refuse> {
        let wrong = self.mem.faults.wrong_slot.take();
        if kind != EntryKind::KEY_REDELIVER {
            meta.epoch_prev_seq = meta.epoch_seq;
            meta.epoch_seq = seq;
            meta.key_epoch = meta.key_epoch.saturating_add(1);
        }
        for (index, ((p, ct), path)) in kd.joiners.iter().zip(&kd.slots).zip(paths).enumerate() {
            let stored = if wrong == Some(*p) {
                random_array::<32>()
                    .map_err(|_| "internal")?
                    .repeat(ct.len() / 32 + 1)
                    .get(..ct.len())
                    .map(<[u8]>::to_vec)
                    .unwrap_or_default()
            } else {
                ct.clone()
            };
            let mut slot = Enc::default();
            slot.u32(u32::try_from(index).map_err(bad)?).var(&stored);
            slot.u32(u32::try_from(path.len()).map_err(bad)?);
            for node in path {
                slot.fixed(node);
            }
            self.tx.put(SLOT, &key(&[gid, &seq.to_be_bytes(), p]), &slot.finish())?;
            let mut row = self.pseudo(gid, p)?.ok_or("not_found")?;
            row.active = true;
            row.keyed_epoch = meta.key_epoch;
            self.tx.put(PSEUDO, &key(&[gid, p]), &row.encode())?;
        }
        Ok(())
    }
}
