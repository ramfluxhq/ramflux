// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Request dispatch and the group-level operations: create, invite, join, pending list, admin
//! chain, `slot_bad` and read. Requests are authenticated by pseudonym signatures only.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use ramflux_crypto::large_group::{
    EntryKind, Genesis, JoinPolicy, LgGroupKey, LgReader as Dec, LgTokenRootKey, LgWriter as Enc,
    LogView, MEMBER_CAP, ReadReply, ReadRequest, RedeliveryLedger, SignedReq, SlotView,
    admin_chain_head, random_array,
};

use super::key_file;
use super::rows::{Invite, LogRow, Meta, Pseudo, ROLE_ADMIN, ROLE_MEMBER, ROLE_OWNER, UNKEYED};
use super::store::{self, INVITE, LOG, PSEUDO, Refuse, SLOT, STATE, Tx, key};

const TAG_META: u8 = 0;
const TAG_ADMIN: u8 = 1;
const MAX_PENDING: usize = 1_000;
const PENDING_TTL_MS: u64 = 24 * 60 * 60 * 1_000;
const JOIN_BURST_MILLI: u64 = 10_000;
const JOIN_COST_MILLI: u64 = 1_000;
const READ_PAGE: usize = 64;
const MAX_BLOB: usize = 2048;
const GENESIS_SIG_DOMAIN: &[u8] = b"rf-lg-genesis-sig-v1";
const JOIN_DOMAIN: &[u8] = b"rf-lg-join-v1";

/// Answer to one request: a status token (`ok` or a refusal) and an opaque body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LgReply {
    pub status: &'static str,
    pub body: Vec<u8>,
}

pub(super) struct GroupKeys {
    pub(super) key: LgGroupKey,
    pub(super) root: LgTokenRootKey,
}

#[derive(Default)]
pub(super) struct Hold {
    pub(super) except: [u8; 32],
    pub(super) from_seq: u64,
    pub(super) until_ms: u64,
}

#[derive(Default)]
pub(super) struct Faults {
    pub(super) hold: Option<Hold>,
    pub(super) forced_appended_ms: Option<u64>,
    pub(super) wrong_slot: Option<[u8; 32]>,
}

#[derive(Default)]
pub(super) struct Mem {
    pub(super) clock_offset_ms: i64,
    join_buckets: HashMap<[u8; 32], (u64, u64)>,
    pub(super) ledgers: HashMap<([u8; 32], [u8; 32]), RedeliveryLedger>,
    keys: HashMap<[u8; 32], Arc<GroupKeys>>,
    pub(super) faults: Faults,
}

/// The large-group host of one node.
pub struct LargeGroupHost {
    db: redb::Database,
    key_dir: PathBuf,
    debug: bool,
    mem: Mutex<Mem>,
}

/// One request in flight: a write transaction plus the in-memory state.
pub(super) struct Op<'a> {
    pub(super) tx: Tx,
    pub(super) mem: &'a mut Mem,
    pub(super) key_dir: &'a PathBuf,
    pub(super) now: u64,
    pub(super) debug: bool,
}

impl LargeGroupHost {
    /// Opens (creating) the host store at `db_path` and the key directory at `key_dir`.
    ///
    /// `debug` enables the hidden fault-injection requests.
    ///
    /// # Errors
    /// Returns a refusal token when the store or the key directory cannot be prepared.
    pub fn open(
        db_path: &std::path::Path,
        key_dir: &std::path::Path,
        debug: bool,
    ) -> Result<Self, &'static str> {
        let key_dir = key_file::open_dir(key_dir)?;
        let db = store::open_db(db_path)?;
        Ok(Self { db, key_dir, debug, mem: Mutex::new(Mem::default()) })
    }

    /// Handles one request. The host never sees which session or account carried it.
    #[must_use]
    pub fn handle(&self, op: &str, body: &[u8]) -> LgReply {
        let mut mem = self.mem.lock().unwrap_or_else(PoisonError::into_inner);
        let now = wall_ms().saturating_add_signed(mem.clock_offset_ms);
        let outcome = Tx::begin(&self.db).and_then(|tx| {
            let mut run = Op { tx, mem: &mut mem, key_dir: &self.key_dir, now, debug: self.debug };
            let reply = run.dispatch(op, body)?;
            run.tx.commit()?;
            Ok(reply)
        });
        match outcome {
            Ok(body) => LgReply { status: "ok", body },
            Err(status) => LgReply { status, body: Vec::new() },
        }
    }
}

fn wall_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|elapsed| u64::try_from(elapsed.as_millis()).ok())
        .unwrap_or(0)
}

fn bad<T>(_: T) -> Refuse {
    "bad_request"
}

pub(super) fn verify_plain(pk: &[u8; 32], message: &[u8], sig: &[u8; 64]) -> Result<(), Refuse> {
    let key = VerifyingKey::from_bytes(pk).map_err(|_| "bad_signature")?;
    key.verify(message, &Signature::from_bytes(sig)).map_err(|_| "bad_signature")
}

impl Op<'_> {
    fn dispatch(&mut self, op: &str, body: &[u8]) -> Result<Vec<u8>, Refuse> {
        match op {
            "create_prepare" => self.create_prepare(),
            "create" => self.create(body),
            "invite" => self.invite(body),
            "join" => self.join(body),
            "pending" => self.pending(body),
            "issue" => self.issue(body),
            "post" => self.post(body),
            "slot_bad" => self.slot_bad(body),
            "admin" => self.admin(body),
            "read" => self.read(body),
            debug if debug.starts_with("debug_") => self.debug_op(debug, body),
            _ => Err("unknown_op"),
        }
    }

    pub(super) fn meta(&self, gid: &[u8; 32]) -> Result<Meta, Refuse> {
        let bytes = self.tx.get(STATE, &key(&[gid, &[TAG_META]]))?.ok_or("not_found")?;
        Meta::decode(&bytes)
    }

    pub(super) fn put_meta(&self, gid: &[u8; 32], meta: &Meta) -> Result<(), Refuse> {
        self.tx.put(STATE, &key(&[gid, &[TAG_META]]), &meta.encode())
    }

    pub(super) fn pseudo(&self, gid: &[u8; 32], p: &[u8; 32]) -> Result<Option<Pseudo>, Refuse> {
        self.tx.get(PSEUDO, &key(&[gid, p]))?.map(|bytes| Pseudo::decode(&bytes)).transpose()
    }

    pub(super) fn put_pseudo(
        &self,
        gid: &[u8; 32],
        p: &[u8; 32],
        row: &Pseudo,
    ) -> Result<(), Refuse> {
        self.tx.put(PSEUDO, &key(&[gid, p]), &row.encode())
    }

    pub(super) fn keys(&mut self, gid: &[u8; 32]) -> Result<Arc<GroupKeys>, Refuse> {
        if let Some(found) = self.mem.keys.get(gid) {
            return Ok(Arc::clone(found));
        }
        let loaded = key_file::load(self.key_dir, &key_file::group_name(gid))?;
        let root = LgTokenRootKey::from_seed(&loaded.token_root_seed()).map_err(|_| "key_file")?;
        let keys = Arc::new(GroupKeys { key: loaded, root });
        self.mem.keys.insert(*gid, Arc::clone(&keys));
        Ok(keys)
    }

    pub(super) fn admin_chain(&self, gid: &[u8; 32]) -> Result<Vec<Vec<u8>>, Refuse> {
        let rows = self.tx.scan(STATE, &key(&[gid, &[TAG_ADMIN]]), 64)?;
        Ok(rows.into_iter().map(|(_, value)| value).collect())
    }

    pub(super) fn admin_head(&self, gid: &[u8; 32]) -> Result<[u8; 32], Refuse> {
        Ok(admin_chain_head(gid, &self.admin_chain(gid)?))
    }

    fn active_signer(&self, req: &SignedReq, op: &str) -> Result<Pseudo, Refuse> {
        req.verify(op).map_err(|_| "bad_signature")?;
        self.meta(&req.gid)?;
        let row = self.pseudo(&req.gid, &req.p)?.ok_or("not_found")?;
        if row.active { Ok(row) } else { Err("pending") }
    }

    fn create_prepare(&mut self) -> Result<Vec<u8>, Refuse> {
        let key_bytes = LgGroupKey::generate().map_err(|_| "internal")?;
        let prep_id = random_array::<16>().map_err(|_| "internal")?;
        key_file::publish(self.key_dir, &key_file::prep_name(&prep_id), &key_bytes)?;
        let root =
            LgTokenRootKey::from_seed(&key_bytes.token_root_seed()).map_err(|_| "internal")?;
        let head_pk = ed25519_dalek::SigningKey::from_bytes(&key_bytes.head_signing_seed())
            .verifying_key()
            .to_bytes();
        let mut enc = Enc::default();
        enc.fixed(&prep_id).fixed(&head_pk).fixed(&root.public_key());
        Ok(enc.finish())
    }

    fn create(&mut self, body: &[u8]) -> Result<Vec<u8>, Refuse> {
        let mut dec = Dec::new(body);
        let prep_id: [u8; 16] = dec.fixed().map_err(bad)?;
        let genesis_bytes = dec.var(4096).map_err(bad)?.to_vec();
        let owner_sig: [u8; 64] = dec.fixed().map_err(bad)?;
        dec.finish().map_err(bad)?;
        let genesis = Genesis::decode(&genesis_bytes).map_err(bad)?;
        let mut message = Enc::new(GENESIS_SIG_DOMAIN);
        message.var(&genesis_bytes);
        verify_plain(&genesis.owner_p_pub, &message.finish(), &owner_sig)?;
        if genesis.member_cap != MEMBER_CAP {
            return Err("bad_request");
        }
        let prep = key_file::prep_name(&prep_id);
        let prepared = key_file::load(self.key_dir, &prep)?;
        let root =
            LgTokenRootKey::from_seed(&prepared.token_root_seed()).map_err(|_| "internal")?;
        let head_pk = ed25519_dalek::SigningKey::from_bytes(&prepared.head_signing_seed())
            .verifying_key()
            .to_bytes();
        if genesis.token_root_pk != root.public_key() || genesis.host_head_pk != head_pk {
            return Err("genesis_key_mismatch");
        }
        let gid = genesis.group_id();
        if self.tx.get(STATE, &key(&[&gid, &[TAG_META]]))?.is_some() {
            return Err("group_exists");
        }
        key_file::promote(self.key_dir, &prep, &key_file::group_name(&gid))?;
        let meta = Meta {
            genesis: genesis_bytes,
            te: 0,
            te_started_ms: self.now,
            last_roll_kind: 2,
            key_epoch: 0,
            epoch_seq: 0,
            epoch_prev_seq: 0,
            last_seq: 0,
            last_head: [0_u8; 32],
            last_appended_ms: 0,
            join_pk: genesis.join_pk_0,
            approval_on: genesis.join_policy == JoinPolicy::ApprovalOn,
            spent_count: 0,
        };
        self.put_meta(&gid, &meta)?;
        let owner = Pseudo {
            role: ROLE_OWNER,
            active: true,
            joined_ms: self.now,
            keyed_epoch: 0,
            blob: Vec::new(),
            batches: Vec::new(),
            free: Vec::new(),
            last_free_te: 0,
        };
        self.put_pseudo(&gid, &genesis.owner_p_pub, &owner)?;
        Ok(gid.to_vec())
    }

    fn invite(&mut self, body: &[u8]) -> Result<Vec<u8>, Refuse> {
        let req = SignedReq::decode(body).map_err(bad)?;
        let signer = self.active_signer(&req, "invite")?;
        if signer.role < ROLE_ADMIN {
            return Err("forbidden");
        }
        let mut dec = Dec::new(&req.body);
        let invite_id: [u8; 16] = dec.fixed().map_err(bad)?;
        let invite = Invite {
            pk: dec.fixed().map_err(bad)?,
            role: dec.u8().map_err(bad)?,
            max_uses: dec.u32().map_err(bad)?,
            uses: 0,
            expires_ms: dec.u64().map_err(bad)?,
        };
        dec.finish().map_err(bad)?;
        if invite.role > ROLE_MEMBER || invite.max_uses == 0 {
            return Err("bad_request");
        }
        let row_key = key(&[&req.gid, &invite_id]);
        if self.tx.get(INVITE, &row_key)?.is_some() {
            return Err("invite_exists");
        }
        self.tx.put(INVITE, &row_key, &invite.encode())?;
        Ok(Vec::new())
    }

    /// Per-group join bucket: 1 per second, burst 10 (milli-tokens; one token per 1000 ms).
    fn join_bucket_ok(&mut self, gid: &[u8; 32]) -> bool {
        let now = self.now;
        let (tokens, last) =
            self.mem.join_buckets.get(gid).copied().unwrap_or((JOIN_BURST_MILLI, now));
        let refilled = tokens.saturating_add(now.saturating_sub(last)).min(JOIN_BURST_MILLI);
        if refilled < JOIN_COST_MILLI {
            self.mem.join_buckets.insert(*gid, (refilled, now));
            return false;
        }
        self.mem.join_buckets.insert(*gid, (refilled - JOIN_COST_MILLI, now));
        true
    }

    fn join(&mut self, body: &[u8]) -> Result<Vec<u8>, Refuse> {
        let mut dec = Dec::new(body);
        let gid: [u8; 32] = dec.fixed().map_err(bad)?;
        let p: [u8; 32] = dec.fixed().map_err(bad)?;
        let invite_id: [u8; 16] = dec.fixed().map_err(bad)?;
        let invite_sig: [u8; 64] = dec.fixed().map_err(bad)?;
        let join_pk_id: [u8; 16] = dec.fixed().map_err(bad)?;
        let blob = dec.var(MAX_BLOB).map_err(bad)?.to_vec();
        dec.finish().map_err(bad)?;
        let meta = self.meta(&gid)?;
        if !self.join_bucket_ok(&gid) {
            return Err("join_rate_limited");
        }
        let invite_key = key(&[&gid, &invite_id]);
        let mut invite =
            Invite::decode(&self.tx.get(INVITE, &invite_key)?.ok_or("invite_invalid")?)?;
        if invite.uses >= invite.max_uses || invite.expires_ms <= self.now {
            return Err("invite_invalid");
        }
        let mut proof = Enc::new(JOIN_DOMAIN);
        proof.fixed(&gid).fixed(&p).fixed(&join_pk_id);
        verify_plain(&invite.pk, &proof.finish(), &invite_sig).map_err(|_| "invite_invalid")?;
        if join_pk_id[..] != blake3::hash(&meta.join_pk).as_bytes()[..16] {
            return Err("join_key_stale");
        }
        if self.pseudo(&gid, &p)?.is_some() {
            return Err("already_joined");
        }
        let rows = self.tx.scan(PSEUDO, &gid, usize::MAX)?;
        let mut pending = 0_usize;
        for (_, value) in &rows {
            if !Pseudo::decode(value)?.active {
                pending += 1;
            }
        }
        if meta.approval_on && pending >= MAX_PENDING {
            return Err("pending_full");
        }
        if rows.len() >= usize::try_from(MEMBER_CAP).unwrap_or(usize::MAX) {
            return Err("member_cap");
        }
        invite.uses = invite.uses.saturating_add(1);
        self.tx.put(INVITE, &invite_key, &invite.encode())?;
        let active = !meta.approval_on;
        let row = Pseudo {
            role: ROLE_MEMBER,
            active,
            joined_ms: self.now,
            keyed_epoch: UNKEYED,
            blob,
            batches: Vec::new(),
            free: Vec::new(),
            last_free_te: meta.te,
        };
        self.put_pseudo(&gid, &p, &row)?;
        Ok(vec![u8::from(active)])
    }

    fn pending(&mut self, body: &[u8]) -> Result<Vec<u8>, Refuse> {
        let req = SignedReq::decode(body).map_err(bad)?;
        let signer = self.active_signer(&req, "pending")?;
        let meta = self.meta(&req.gid)?;
        if meta.approval_on && signer.role < ROLE_ADMIN {
            return Err("forbidden");
        }
        if !meta.approval_on && signer.keyed_epoch == UNKEYED {
            return Err("forbidden");
        }
        let mut found = Vec::new();
        for (row_key, value) in self.tx.scan(PSEUDO, &req.gid, usize::MAX)? {
            let row = Pseudo::decode(&value)?;
            let waiting = if meta.approval_on {
                !row.active && self.now.saturating_sub(row.joined_ms) < PENDING_TTL_MS
            } else {
                row.active && row.keyed_epoch == UNKEYED
            };
            let p = row_key.get(32..).ok_or("corrupt_row")?;
            if waiting && found.len() < 100 {
                found.push((p.to_vec(), row.blob));
            }
        }
        let mut enc = Enc::default();
        enc.u32(u32::try_from(found.len()).unwrap_or(0));
        for (p, blob) in &found {
            enc.fixed(p).var(blob);
        }
        Ok(enc.finish())
    }

    /// Admin promote / demote. Demoting the owner is refused; the owner is unremovable.
    fn admin(&mut self, body: &[u8]) -> Result<Vec<u8>, Refuse> {
        let req = SignedReq::decode(body).map_err(bad)?;
        let signer = self.active_signer(&req, "admin")?;
        let mut dec = Dec::new(&req.body);
        let action = dec.u8().map_err(bad)?;
        let target: [u8; 32] = dec.fixed().map_err(bad)?;
        dec.finish().map_err(bad)?;
        let mut row = self.pseudo(&req.gid, &target)?.ok_or("not_found")?;
        if action == 1 {
            if signer.role != ROLE_OWNER || row.role != ROLE_MEMBER {
                return Err("forbidden");
            }
            row.role = ROLE_ADMIN;
        } else if action == 2 {
            if row.role == ROLE_OWNER {
                return Err("owner_unremovable");
            }
            if signer.role < ROLE_ADMIN || row.role != ROLE_ADMIN {
                return Err("forbidden");
            }
            row.role = ROLE_MEMBER;
        } else {
            return Err("bad_request");
        }
        self.put_pseudo(&req.gid, &target, &row)?;
        let prev = self.admin_head(&req.gid)?;
        let mut entry = Enc::default();
        entry.fixed(&prev).var(&req.encode());
        let chain = self.admin_chain(&req.gid)?;
        let index = u32::try_from(chain.len()).map_err(bad)?;
        let entry = entry.finish();
        self.tx.put(STATE, &key(&[&req.gid, &[TAG_ADMIN], &index.to_be_bytes()]), &entry)?;
        self.append_plain(&req.gid, EntryKind::ADMIN, &entry)?;
        Ok(Vec::new())
    }

    fn slot_bad(&mut self, body: &[u8]) -> Result<Vec<u8>, Refuse> {
        let req = SignedReq::decode(body).map_err(bad)?;
        let signer = self.active_signer(&req, "slot_bad")?;
        let meta = self.meta(&req.gid)?;
        let mut dec = Dec::new(&req.body);
        let key_epoch = dec.u64().map_err(bad)?;
        let bad_seq = dec.u64().map_err(bad)?;
        dec.finish().map_err(bad)?;
        if signer.keyed_epoch != key_epoch || key_epoch > meta.key_epoch {
            return Err("bad_request");
        }
        let now = self.now;
        let ledger = self.mem.ledgers.entry((req.gid, req.p)).or_default();
        ledger.accept_slot_bad(now, bad_seq).map_err(|_| "slot_bad_rate_limited")?;
        let mut note = Enc::default();
        note.fixed(&req.p).u64(key_epoch).u64(bad_seq);
        self.append_plain(&req.gid, EntryKind::SLOT_BAD, &note.finish())?;
        Ok(Vec::new())
    }

    fn read(&mut self, body: &[u8]) -> Result<Vec<u8>, Refuse> {
        let req = SignedReq::decode(body).map_err(bad)?;
        self.active_signer(&req, "read")?;
        let asked = ReadRequest::decode(&req.body).map_err(bad)?;
        self.maybe_daily_roll(&req.gid)?;
        let meta = self.meta(&req.gid)?;
        let limit = usize::try_from(asked.limit).unwrap_or(READ_PAGE).clamp(1, READ_PAGE);
        let mut upto = meta.last_seq;
        if let Some(hold) = &self.mem.faults.hold
            && req.p != hold.except
            && self.now < hold.until_ms
        {
            upto = upto.min(hold.from_seq.saturating_sub(1));
        }
        let start = key(&[&req.gid, &asked.from_seq.max(1).to_be_bytes()]);
        let mut entries = Vec::new();
        for (row_key, value) in self.tx.scan_from(LOG, &req.gid, &start, limit)? {
            let seq_bytes: [u8; 8] =
                row_key.get(32..40).and_then(|b| b.try_into().ok()).ok_or("corrupt_row")?;
            let seq = u64::from_be_bytes(seq_bytes);
            if seq > upto {
                break;
            }
            let row = LogRow::decode(&value)?;
            let slot = self.slot_view(&req.gid, seq, &req.p, &row)?;
            entries.push(LogView {
                seq,
                appended_at_ms: row.appended_ms,
                head: row.head,
                host_sig: row.sig,
                header: row.header,
                ciphertext: row.ciphertext,
                token: row.token,
                kd_meta: row.kd_meta,
                slot,
            });
        }
        let reply = ReadReply {
            genesis: meta.genesis.clone(),
            te: meta.te,
            key_epoch: meta.key_epoch,
            epoch_seq: meta.epoch_seq,
            last_seq: upto,
            now_ms: self.now,
            admin_chain: self.admin_chain(&req.gid)?,
            entries,
        };
        Ok(reply.encode())
    }

    fn slot_view(
        &self,
        gid: &[u8; 32],
        seq: u64,
        p: &[u8; 32],
        row: &LogRow,
    ) -> Result<Option<SlotView>, Refuse> {
        let Some(bytes) = self.tx.get(SLOT, &key(&[gid, &seq.to_be_bytes(), p]))? else {
            return Ok(None);
        };
        let mut dec = Dec::new(&bytes);
        let index = dec.u32().map_err(bad)?;
        let ct = dec.var(32 * 1024).map_err(bad)?.to_vec();
        let nodes = usize::try_from(dec.u32().map_err(bad)?).map_err(bad)?;
        let mut path = Vec::new();
        for _ in 0..nodes.min(16) {
            path.push(dec.fixed().map_err(bad)?);
        }
        Ok(Some(SlotView { index, slot_count: row.slot_count, slot_root: row.slot_root, ct, path }))
    }
}
