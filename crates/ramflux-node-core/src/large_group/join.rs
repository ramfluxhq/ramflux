// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Join requests, the two queues and stored Welcomes (MLS-SPEC r1.1 2.4, 2.5; from 6ed `host.rs`).
//!
//! `invite` requests (ident session, invite proof) go to the outsider queue; `own_device` and
//! `rejoin` requests (member session, one commit token) go to the member queue. Each queue holds
//! at most 1 000 pending requests, the group takes 1 per second with a burst of 10, and a request
//! expires after 24 h. A commit may add only pseudonyms that have a pending entry (the join tie,
//! checked in `entries`; a pending row older than 24 h does not count). The host reads the
//! pseudonym `P` from the `KeyPackage`'s leaf signature key; everything else of the request stays
//! sealed to the join key. A Welcome is stored by the commit that adds the joiner (`entries`) and
//! found by `P`.

use ramflux_crypto::large_group::{
    JoinKind, JoinRequest, JoinSession, LgReader as Dec, SignedReq, Token, TokenBucket,
    invite_proof_message, join_bind,
};

use super::check::{JOIN_QUEUE_MAX, key_package_signature_key};
use super::host::{Cx, LargeGroupHost, verify_plain};
use super::refusal::{LgRefusal, LgResult};
use super::rows::{BlobMeta, InviteRow, JoinRow, QUEUE_MEMBER, QUEUE_OUTSIDER, WelcomeRow, key};
use crate::RouterRedbStore;
use crate::router_store::lg_store::LgTable;

/// Most pending requests one `join.pending` answer lists per queue.
const PENDING_PAGE: usize = 100;

/// A pending join request as `join.pending` lists it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingJoin {
    /// The joiner's pseudonym (the `KeyPackage`'s leaf signature key).
    pub p: [u8; 32],
    /// The queue it waits in.
    pub queue: u8,
    /// `JoinKind::code()`.
    pub kind: u8,
    /// Join key it is sealed to.
    pub join_pk_id: [u8; 32],
    /// The `KeyPackage`.
    pub key_package: Vec<u8>,
    /// The sealed roster entry.
    pub sealed: Vec<u8>,
}

/// What `welcome.get` returns: where to pull the Welcome from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WelcomeInfo {
    /// `log_seq` of the commit that added the joiner.
    pub commit_seq: u64,
    /// Blob holding the Welcome (`blob.get`).
    pub blob_ref: [u8; 32],
    /// Chunks of the blob.
    pub total: u32,
    /// Bytes of the blob.
    pub bytes: u64,
}

/// The request names the group's current join key, else `join_key_stale` carrying the current key.
/// Callers run it only after the invite row and proof were verified (an `invite` request), so a
/// link holder learns the key only with a live link; `own_device` and `rejoin` get it at once.
pub(super) fn join_key_check(head_join_pk: &[u8; 32], join_pk_id: &[u8; 32]) -> LgResult<()> {
    if blake3::hash(head_join_pk).as_bytes() == join_pk_id {
        Ok(())
    } else {
        Err(LgRefusal::JoinKeyStale { join_pk: *head_join_pk })
    }
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
            // An invite's row and proof come first (nothing is stored here, no use is counted
            // until the request is queued); only then may a stale key be answered with the
            // current one. A group id alone, a revoked, expired or used-up link learns no key.
            let invite = match req.kind {
                JoinKind::Invite => Some(cx.check_invite(gid, req, &p)?),
                JoinKind::OwnDevice | JoinKind::Rejoin => None,
            };
            join_key_check(&head.join_pk, &req.join_pk_id)?;
            cx.drop_stale_join(gid, &mut head, &p)?;
            if cx.pset(gid, &p)?.is_some() || cx.pending_queue(gid, &p)?.is_some() {
                return Err(LgRefusal::AlreadyJoined);
            }
            if head.pset_count >= ramflux_crypto::large_group::LEAF_CAP {
                return Err(LgRefusal::LeafCap);
            }
            if !matches!(req.kind, JoinKind::Invite) {
                let token = Token::from_bytes(&req.auth).map_err(|_| LgRefusal::BadRequest)?;
                cx.spend_token(gid, &mut head, TokenBucket::Commit, &token, &join_bind(req))?;
            }
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

    /// `welcome.get`: a joiner (P-signed, op `welcome.get`, empty body) learns where its Welcome
    /// is; the host finds it by `P` and nothing else is asked. The host counts the joiner as
    /// served; the row and blob go once every joiner was served (after a short grace) or after 7
    /// days.
    ///
    /// # Errors
    /// `unauthorized`, `not_found`, `bad_request` (a body).
    pub fn welcome_get(
        &self,
        store: &RouterRedbStore,
        now: u64,
        req: &SignedReq,
    ) -> LgResult<WelcomeInfo> {
        req.verify("welcome.get").map_err(|_| LgRefusal::Unauthorized)?;
        if !req.body.is_empty() {
            return Err(LgRefusal::BadRequest);
        }
        let gid = req.gid;
        self.run(store, now, |cx| {
            let index = cx.tx.get(LgTable::Welcome, &welcome_index_key(&gid, &req.p))?;
            let seq_bytes: [u8; 8] = index
                .ok_or(LgRefusal::NotFound)?
                .as_slice()
                .try_into()
                .map_err(|_| LgRefusal::Internal)?;
            let welcome_key = welcome_row_key(&gid, u64::from_be_bytes(seq_bytes));
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
            Ok(WelcomeInfo {
                commit_seq: u64::from_be_bytes(seq_bytes),
                blob_ref: row.blob_ref,
                total: meta.total,
                bytes: meta.bytes,
            })
        })
    }
}

const WELCOME_ROW: u8 = 0;
const WELCOME_INDEX: u8 = 1;

/// Key of the Welcome row of the commit at `commit_seq`.
pub(super) fn welcome_row_key(gid: &[u8; 32], commit_seq: u64) -> Vec<u8> {
    key(gid, &[&[WELCOME_ROW], &commit_seq.to_be_bytes()])
}

/// Prefix of every Welcome row of a group (the index rows are not under it).
pub(super) fn welcome_row_prefix(gid: &[u8; 32]) -> Vec<u8> {
    key(gid, &[&[WELCOME_ROW]])
}

/// Key of the `(group, P) -> commit_seq` index row.
fn welcome_index_key(gid: &[u8; 32], p: &[u8; 32]) -> Vec<u8> {
    key(gid, &[&[WELCOME_INDEX], p])
}

impl Cx<'_> {
    /// Verify the invite row (live: not revoked, not used up, not expired) and the proof of a join
    /// request; returns the updated invite row (uses + 1) to store once every other check has
    /// passed. Nothing is stored here.
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

    /// Store the Welcome of the commit at `commit_seq` (the blob is already owned by the commit):
    /// the row, and one index row per joiner so that `welcome.get` finds it by `P`.
    pub(super) fn welcome_store(
        &self,
        gid: &[u8; 32],
        commit_seq: u64,
        blob_ref: &[u8; 32],
        joiners: &[[u8; 32]],
    ) -> LgResult<()> {
        let row = WelcomeRow {
            created_ms: self.now,
            drained_ms: 0,
            blob_ref: *blob_ref,
            joiners: joiners.to_vec(),
            remaining: joiners.to_vec(),
        };
        self.tx.put(LgTable::Welcome, &welcome_row_key(gid, commit_seq), &row.encode())?;
        for p in joiners {
            self.tx.put(LgTable::Welcome, &welcome_index_key(gid, p), &commit_seq.to_be_bytes())?;
        }
        Ok(())
    }

    /// Delete the Welcome row of `commit_seq`, its blob and the index rows that still point at it.
    pub(super) fn welcome_discard(&self, gid: &[u8; 32], commit_seq: u64) -> LgResult<()> {
        let welcome_key = welcome_row_key(gid, commit_seq);
        if let Some(bytes) = self.tx.get(LgTable::Welcome, &welcome_key)? {
            let row = WelcomeRow::decode(&bytes)?;
            self.blob_delete(gid, &row.blob_ref)?;
            for p in &row.joiners {
                let index = welcome_index_key(gid, p);
                if self.tx.get(LgTable::Welcome, &index)?.as_deref()
                    == Some(commit_seq.to_be_bytes().as_slice())
                {
                    self.tx.del(LgTable::Welcome, &index)?;
                }
            }
            self.tx.del(LgTable::Welcome, &welcome_key)?;
        }
        Ok(())
    }

    /// Delete the pending join rows of `p` that are 24 h old or older (a stale row must neither
    /// block a new request nor satisfy a commit's join tie) and keep the queue counters.
    fn drop_stale_join(
        &self,
        gid: &[u8; 32],
        head: &mut super::rows::HeadRow,
        p: &[u8; 32],
    ) -> LgResult<()> {
        for queue in [QUEUE_MEMBER, QUEUE_OUTSIDER] {
            let row_key = key(gid, &[&[queue], p]);
            let Some(bytes) = self.tx.get(LgTable::Join, &row_key)? else {
                continue;
            };
            if super::check::join_expired(JoinRow::decode(&bytes)?.created_ms, self.now) {
                self.tx.del(LgTable::Join, &row_key)?;
                if queue == QUEUE_MEMBER {
                    head.pending_member = head.pending_member.saturating_sub(1);
                } else {
                    head.pending_outsider = head.pending_outsider.saturating_sub(1);
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_stale_join_key_answers_with_the_current_key() {
        let current = [7_u8; 32];
        let current_id = *blake3::hash(&current).as_bytes();
        assert_eq!(join_key_check(&current, &current_id), Ok(()), "the current key passes");
        let old_id = *blake3::hash(&[6_u8; 32]).as_bytes();
        assert_eq!(
            join_key_check(&current, &old_id),
            Err(LgRefusal::JoinKeyStale { join_pk: current }),
            "a retired key id gets the current join key"
        );
        assert_eq!(
            join_key_check(&current, &current).map_err(|refusal| refusal.code()),
            Err("join_key_stale"),
            "the id is the hash of the key, never the key"
        );
    }
}
