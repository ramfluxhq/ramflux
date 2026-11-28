// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Join requests, the two queues and stored Welcomes (MLS-SPEC r1.1 2.4, 2.5; from 6ed `host.rs`).
//!
//! `invite` requests (ident session, invite proof) go to the outsider queue; `own_device` and
//! `rejoin` requests (member session, one commit token) go to the member queue. Each queue holds
//! at most 1 000 pending requests, the group takes 1 per second with a burst of 10, and a request
//! expires after 24 h. A commit may add only pseudonyms that have a pending entry (the join tie,
//! checked in `entries`). The host reads the pseudonym `P` from the KeyPackage's leaf signature key;
//! everything else of the request stays sealed to the join key.

use ramflux_crypto::large_group::{
    JoinKind, JoinRequest, JoinSession, LgReader as Dec, LgWriter as Enc, SignedReq, Token,
    TokenBucket,
};
use ramflux_protocol::domain::LG_JOIN_V1;

use super::check::{JOIN_QUEUE_MAX, key_package_signature_key};
use super::host::{Authority, Cx, LargeGroupHost, verify_plain};
use super::refusal::{LgRefusal, LgResult};
use super::rows::{
    BlobMeta, InviteRow, JoinRow, QUEUE_MEMBER, QUEUE_OUTSIDER, WelcomeRow, key,
};
use crate::RouterRedbStore;
use crate::router_store::lg_store::LgTable;

/// Most pending requests one `join.pending` answer lists per queue.
const PENDING_PAGE: usize = 100;
/// A Welcome is stored for the joiners of commits no older than this (7 d).
const WELCOME_ENTRY_MAX_AGE_MS: u64 = super::check::WELCOME_TTL_MS;

/// A pending join request as `join.pending` lists it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingJoin {
    /// The joiner's pseudonym (the KeyPackage's leaf signature key).
    pub p: [u8; 32],
    /// The queue it waits in.
    pub queue: u8,
    /// `JoinKind::code()`.
    pub kind: u8,
    /// Join key it is sealed to.
    pub join_pk_id: [u8; 32],
    /// The KeyPackage.
    pub key_package: Vec<u8>,
    /// The sealed roster entry.
    pub sealed: Vec<u8>,
}

/// What `welcome.get` returns: where to pull the Welcome from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WelcomeInfo {
    /// Blob holding the Welcome (`blob.get`).
    pub blob_ref: [u8; 32],
    /// Chunks of the blob.
    pub total: u32,
    /// Bytes of the blob.
    pub bytes: u64,
}

/// The hash a member-session join token binds to: `BLAKE3(rf-lg-join-v1 ‖ kind ‖ H(KeyPackage) ‖
/// join_pk_id ‖ H(sealed))`.
#[must_use]
pub fn join_bind(req: &JoinRequest) -> [u8; 32] {
    let mut enc = Enc::new(LG_JOIN_V1.as_bytes());
    enc.u8(req.kind.code())
        .fixed(blake3::hash(&req.key_package).as_bytes())
        .fixed(&req.join_pk_id)
        .fixed(blake3::hash(&req.sealed).as_bytes());
    *blake3::hash(&enc.finish()).as_bytes()
}

/// The message an invite's key signs: `rf-lg-join-v1 ‖ group_id ‖ P ‖ join_pk_id`; the proof in
/// `JoinRequest::auth` is `invite_id (16) ‖ signature (64)`.
#[must_use]
pub fn invite_proof_message(gid: &[u8; 32], p: &[u8; 32], join_pk_id: &[u8; 32]) -> Vec<u8> {
    let mut enc = Enc::new(LG_JOIN_V1.as_bytes());
    enc.fixed(gid).fixed(p).fixed(join_pk_id);
    enc.finish()
}

fn queue_of(kind: JoinKind) -> u8 {
    if kind.member_queue() { QUEUE_MEMBER } else { QUEUE_OUTSIDER }
}

impl LargeGroupHost {
    /// Queue one join request. `session` is the kind of session it arrived on (the host refuses a
    /// kind on the wrong session); `gid` is the session's group.
    ///
    /// # Errors
    /// `session_scope`, `join_rate_limited`, `join_key_stale`, `invite_invalid`, `unauthorized`
    /// (token), `already_joined`, `pending_full`, `leaf_cap`, `bad_request`.
    pub fn join(
        &self,
        store: &RouterRedbStore,
        now: u64,
        session: JoinSession,
        req: &JoinRequest,
        gid: &[u8; 32],
    ) -> LgResult<u8> {
        if req.kind.session() != session {
            return Err(LgRefusal::SessionScope);
        }
        let p = key_package_signature_key(&req.key_package)?;
        if !self.join_bucket_take(gid, now) {
            return Err(LgRefusal::JoinRateLimited);
        }
        self.settle(store, now, gid)?;
        self.run(store, now, |cx| {
            let mut head = cx.head(gid)?;
            if *blake3::hash(&head.join_pk).as_bytes() != req.join_pk_id {
                return Err(LgRefusal::JoinKeyStale);
            }
            if cx.pset(gid, &p)?.is_some() || cx.pending_queue(gid, &p)?.is_some() {
                return Err(LgRefusal::AlreadyJoined);
            }
            if head.pset_count >= ramflux_crypto::large_group::LEAF_CAP {
                return Err(LgRefusal::LeafCap);
            }
            let invite = match req.kind {
                JoinKind::Invite => Some(cx.check_invite(gid, req, &p)?),
                JoinKind::OwnDevice | JoinKind::Rejoin => {
                    let token = Token::from_bytes(&req.auth).map_err(|_| LgRefusal::BadRequest)?;
                    cx.spend_token(gid, &mut head, TokenBucket::Commit, &token, &join_bind(req))?;
                    None
                }
            };
            let queue = queue_of(req.kind);
            let pending =
                if queue == QUEUE_MEMBER { head.pending_member } else { head.pending_outsider };
            if pending >= JOIN_QUEUE_MAX {
                cx.expire_joins(gid, &mut head, queue)?;
            }
            let pending =
                if queue == QUEUE_MEMBER { head.pending_member } else { head.pending_outsider };
            if pending >= JOIN_QUEUE_MAX {
                return Err(LgRefusal::PendingFull);
            }
            if let Some((invite_key, invite)) = invite {
                cx.tx.put(LgTable::Invite, &invite_key, &invite.encode())?;
            }
            let row = JoinRow {
                created_ms: cx.now,
                kind: req.kind.code(),
                join_pk_id: req.join_pk_id,
                key_package: req.key_package.clone(),
                sealed: req.sealed.clone(),
            };
            cx.tx.put(LgTable::Join, &key(gid, &[&[queue], &p]), &row.encode())?;
            if queue == QUEUE_MEMBER {
                head.pending_member = head.pending_member.saturating_add(1);
            } else {
                head.pending_outsider = head.pending_outsider.saturating_add(1);
            }
            cx.put_head(gid, &head)?;
            Ok(queue)
        })
    }

    /// The pending requests (member queue first, at most 100 per queue). With approval ON only an
    /// admin may ask, otherwise any leaf. `req` is P-signed (op `join.pending`, empty body).
    ///
    /// # Errors
    /// `unauthorized`, `forbidden`.
    pub fn join_pending(
        &self,
        store: &RouterRedbStore,
        now: u64,
        req: &SignedReq,
    ) -> LgResult<Vec<PendingJoin>> {
        req.verify("join.pending").map_err(|_| LgRefusal::Unauthorized)?;
        let gid = req.gid;
        self.run(store, now, |cx| {
            let head = cx.head(&gid)?;
            let leaf = cx.pset(&gid, &req.p)?.filter(|row| !row.leaving);
            leaf.ok_or(LgRefusal::Unauthorized)?;
            let genesis = ramflux_crypto::large_group::Genesis::decode(&head.genesis)?;
            if genesis.approval && cx.admin_role(&gid, &req.p)?.is_none() {
                return Err(LgRefusal::Forbidden);
            }
            let mut found = Vec::new();
            for queue in [QUEUE_MEMBER, QUEUE_OUTSIDER] {
                let prefix = key(&gid, &[&[queue]]);
                for (row_key, value) in cx.tx.scan(LgTable::Join, &prefix, &prefix, PENDING_PAGE)? {
                    let row = JoinRow::decode(&value)?;
                    if super::check::join_expired(row.created_ms, cx.now) {
                        continue;
                    }
                    let p: [u8; 32] = row_key
                        .get(prefix.len()..)
                        .and_then(|tail| tail.try_into().ok())
                        .ok_or(LgRefusal::Internal)?;
                    found.push(PendingJoin {
                        p,
                        queue,
                        kind: row.kind,
                        join_pk_id: row.join_pk_id,
                        key_package: row.key_package,
                        sealed: row.sealed,
                    });
                }
            }
            Ok(found)
        })
    }

    /// Store the Welcome of the commit at `commit_seq` (a blob of at most 16 MiB already uploaded
    /// and complete). Authority: an admin's signature or one commit token over
    /// `welcome_put_body(commit_seq, blob_ref)`; the commit must be a retained commit that added
    /// pseudonyms, at most 7 days old.
    ///
    /// # Errors
    /// `unauthorized`, `not_found`, `blob_missing`, `bad_request`.
    pub fn welcome_put(
        &self,
        store: &RouterRedbStore,
        now: u64,
        gid: &[u8; 32],
        commit_seq: u64,
        blob_ref: &[u8; 32],
        auth: Authority<'_>,
    ) -> LgResult<()> {
        self.run(store, now, |cx| {
            let mut head = cx.head(gid)?;
            cx.authorize_op(gid, &mut head, "welcome.put", &welcome_put_body(commit_seq, blob_ref), auth)?;
            let bytes = cx
                .tx
                .get(LgTable::Log, &key(gid, &[&commit_seq.to_be_bytes()]))?
                .ok_or(LgRefusal::NotFound)?;
            let entry = super::rows::LogRow::decode(&bytes)?;
            let envelope = ramflux_crypto::large_group::Envelope::decode(&entry.envelope)?;
            let added = envelope.header.added_p;
            if envelope.header.kind != ramflux_crypto::large_group::EnvKind::Commit
                || added.is_empty()
                || entry.appended_ms.saturating_add(WELCOME_ENTRY_MAX_AGE_MS) < cx.now
            {
                return Err(LgRefusal::BadRequest);
            }
            let welcome_key = key(gid, &[&commit_seq.to_be_bytes()]);
            if cx.tx.get(LgTable::Welcome, &welcome_key)?.is_some() {
                return Err(LgRefusal::BadRequest);
            }
            cx.blob_reference(gid, blob_ref)?;
            let row = WelcomeRow {
                created_ms: cx.now,
                drained_ms: 0,
                blob_ref: *blob_ref,
                joiners: added.clone(),
                remaining: added,
            };
            cx.tx.put(LgTable::Welcome, &welcome_key, &row.encode())?;
            cx.put_head(gid, &head)
        })
    }

    /// `welcome.get`: a joiner (P-signed, op `welcome.get`, body = the commit's `log_seq`, 8
    /// bytes) learns where its Welcome is. The host counts the joiner as served; the row and blob
    /// go once every joiner was served (after a short grace) or after 7 days.
    ///
    /// # Errors
    /// `unauthorized`, `not_found`.
    pub fn welcome_get(
        &self,
        store: &RouterRedbStore,
        now: u64,
        req: &SignedReq,
    ) -> LgResult<WelcomeInfo> {
        req.verify("welcome.get").map_err(|_| LgRefusal::Unauthorized)?;
        let seq_bytes: [u8; 8] =
            req.body.as_slice().try_into().map_err(|_| LgRefusal::BadRequest)?;
        let gid = req.gid;
        self.run(store, now, |cx| {
            let welcome_key = key(&gid, &[&seq_bytes]);
            let bytes = cx.tx.get(LgTable::Welcome, &welcome_key)?.ok_or(LgRefusal::NotFound)?;
            let mut row = WelcomeRow::decode(&bytes)?;
            if !row.joiners.contains(&req.p) {
                return Err(LgRefusal::Unauthorized);
            }
            if let Some(index) = row.remaining.iter().position(|p| *p == req.p) {
                row.remaining.swap_remove(index);
                if row.remaining.is_empty() {
                    row.drained_ms = cx.now;
                }
                cx.tx.put(LgTable::Welcome, &welcome_key, &row.encode())?;
            }
            let meta = cx
                .tx
                .get(LgTable::Blob, &key(&gid, &[&[2], &row.blob_ref]))?
                .map(|bytes| BlobMeta::decode(&bytes))
                .transpose()?
                .ok_or(LgRefusal::NotFound)?;
            Ok(WelcomeInfo { blob_ref: row.blob_ref, total: meta.total, bytes: meta.bytes })
        })
    }
}

/// The request body a `welcome.put` authority covers.
#[must_use]
pub fn welcome_put_body(commit_seq: u64, blob_ref: &[u8; 32]) -> Vec<u8> {
    let mut enc = Enc::default();
    enc.u64(commit_seq).fixed(blob_ref);
    enc.finish()
}

impl Cx<'_> {
    /// Verify the invite proof of a join request; returns the updated invite row (uses + 1) to
    /// store once every other check has passed.
    fn check_invite(
        &self,
        gid: &[u8; 32],
        req: &JoinRequest,
        p: &[u8; 32],
    ) -> LgResult<(Vec<u8>, InviteRow)> {
        let bad = |_| LgRefusal::InviteInvalid;
        let mut dec = Dec::new(&req.auth);
        let invite_id: [u8; 16] = dec.fixed().map_err(bad)?;
        let sig: [u8; 64] = dec.fixed().map_err(bad)?;
        dec.finish().map_err(bad)?;
        let invite_key = key(gid, &[&invite_id]);
        let bytes = self.tx.get(LgTable::Invite, &invite_key)?.ok_or(LgRefusal::InviteInvalid)?;
        let mut invite = InviteRow::decode(&bytes)?;
        if invite.revoked || invite.uses >= invite.max_uses || invite.expires_ms <= self.now {
            return Err(LgRefusal::InviteInvalid);
        }
        let message = invite_proof_message(gid, p, &req.join_pk_id);
        verify_plain(&invite.pk, &message, &sig).map_err(|_| LgRefusal::InviteInvalid)?;
        invite.uses = invite.uses.saturating_add(1);
        Ok((invite_key, invite))
    }

    /// Drop the Welcome stored for a voided commit.
    pub(super) fn welcome_discard(&self, gid: &[u8; 32], commit_seq: u64) -> LgResult<()> {
        let welcome_key = key(gid, &[&commit_seq.to_be_bytes()]);
        if let Some(bytes) = self.tx.get(LgTable::Welcome, &welcome_key)? {
            let row = WelcomeRow::decode(&bytes)?;
            self.blob_delete(gid, &row.blob_ref)?;
            self.tx.del(LgTable::Welcome, &welcome_key)?;
        }
        Ok(())
    }
}
