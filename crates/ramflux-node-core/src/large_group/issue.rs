// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Posting tokens (MLS-SPEC r1.1 2.6; from 6ed `issue.rs`): batched issuance of 20 under
//! per-pseudonym quotas in three buckets (`post`, `commit`, `open`), redemption and the one-time
//! spend, and the `open` session token.

use ramflux_crypto::large_group::{
    BATCH_SIZE, LgReader as Dec, LgWriter as Enc, RollKind, SignedReq, Token, TokenBucket,
    token_info, verify_token_binding,
};
use ramflux_protocol::domain::LG_OPEN_V1;

use super::check::DAY_MS;
use super::host::{Cx, LargeGroupHost};
use super::refusal::{LgRefusal, LgResult};
use super::rows::{HeadRow, IssueRow, key};
use crate::RouterRedbStore;
use crate::router_store::lg_store::LgTable;

const OP_DOMAIN: &[u8] = b"rf-lg-op-v1";
/// After a `daily` or `spent_full` roll the host still takes the previous epoch's tokens (10 min);
/// after a `revoke` roll it does not.
const GRACE_MS: u64 = 10 * 60 * 1_000;
/// Free refill batches per bucket per 24 h (after rolls).
const FREE_BATCHES_PER_DAY: usize = 10;
const ISSUE_ROW: u8 = 1;
const REPLY_CACHE: u8 = 2;
const BATCH: u32 = 20;

/// What an operation's token is bound to: `BLAKE3(rf-lg-op-v1 ‖ op ‖ group_id ‖ body)`. Used by
/// `invite.put/revoke`, `blob.put`, `welcome.put` (the entry kinds bind to the envelope instead,
/// the `open` token to [`open_bind`]).
#[must_use]
pub fn op_bind(op: &str, gid: &[u8; 32], body: &[u8]) -> [u8; 32] {
    let mut enc = Enc::new(OP_DOMAIN);
    enc.var(op.as_bytes()).fixed(gid).var(body);
    *blake3::hash(&enc.finish()).as_bytes()
}

/// What an `open` token is bound to: `BLAKE3(rf-lg-open-v1 ‖ group_id ‖ session nonce)`.
#[must_use]
pub fn open_bind(gid: &[u8; 32], nonce: &[u8; 32]) -> [u8; 32] {
    let mut enc = Enc::new(LG_OPEN_V1.as_bytes());
    enc.fixed(gid).fixed(nonce);
    *blake3::hash(&enc.finish()).as_bytes()
}

/// The host's answer to one issuance: 20 evaluated elements and the batch proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TokenReply {
    /// Evaluated elements, in request order.
    pub evaluated: Vec<[u8; 32]>,
    /// DLEQ batch proof.
    pub proof: [u8; 64],
}

impl TokenReply {
    /// Wire form: the elements back to back, then the proof.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut enc = Enc::default();
        for element in &self.evaluated {
            enc.fixed(element);
        }
        enc.fixed(&self.proof);
        enc.finish()
    }

    /// # Errors
    /// `bad_request` for any other length than 20 elements and a proof.
    pub fn decode(bytes: &[u8]) -> LgResult<Self> {
        let bad = |_| LgRefusal::BadRequest;
        let mut dec = Dec::new(bytes);
        let mut evaluated = Vec::with_capacity(BATCH_SIZE);
        for _ in 0..BATCH_SIZE {
            evaluated.push(dec.fixed::<32>().map_err(bad)?);
        }
        let proof = dec.fixed::<64>().map_err(bad)?;
        dec.finish().map_err(bad)?;
        Ok(Self { evaluated, proof })
    }
}

impl Cx<'_> {
    /// Redeem `token` for `bucket` against the entry hash `bind`, once: wrong epoch, wrong bucket
    /// or wrong binding is `unauthorized` or `token_epoch_stale`, a second spend `token_spent`.
    /// Counts the spend in `head` (the caller stores it).
    pub(super) fn spend_token(
        &self,
        gid: &[u8; 32],
        head: &mut HeadRow,
        bucket: TokenBucket,
        token: &Token,
        bind: &[u8; 32],
    ) -> LgResult<()> {
        let rolled_softly = head.last_roll_kind == RollKind::Daily.code()
            || head.last_roll_kind == RollKind::SpentFull.code();
        let grace = token.te.saturating_add(1) == head.te
            && rolled_softly
            && self.now.saturating_sub(head.te_started_ms) < GRACE_MS;
        if token.te != head.te && !grace {
            return Err(LgRefusal::TokenEpochStale);
        }
        let keys = self.host.group_keys(gid)?;
        let spent = verify_token_binding(&keys.root, gid, bucket, token, bind)
            .map_err(|_| LgRefusal::Unauthorized)?;
        let row_key = key(gid, &[&token.te.to_be_bytes(), &spent]);
        if self.tx.get(LgTable::Spent, &row_key)?.is_some() {
            return Err(LgRefusal::TokenSpent);
        }
        self.tx.put(LgTable::Spent, &row_key, &[])?;
        head.spent_count = head.spent_count.saturating_add(1);
        Ok(())
    }
}

impl LargeGroupHost {
    /// Spend one `open` token to start a member session (spec 2.1, 2.6): the token must be bound
    /// to `open_bind(group_id, nonce)`. Nothing about the session is stored.
    ///
    /// # Errors
    /// `not_found`, `unauthorized`, `token_epoch_stale`, `token_spent`.
    pub fn open_session(
        &self,
        store: &RouterRedbStore,
        now: u64,
        gid: &[u8; 32],
        token: &Token,
        nonce: &[u8; 32],
    ) -> LgResult<()> {
        self.settle(store, now, gid)?;
        self.run(store, now, |cx| {
            let mut head = cx.head(gid)?;
            cx.spend_token(gid, &mut head, TokenBucket::Open, token, &open_bind(gid, nonce))?;
            cx.put_head(gid, &head)
        })
    }

    /// Issue one batch of 20 tokens (`req` is P-signed, op `tokens`; body: `te`, bucket code,
    /// request id, count 20, 20 blinded elements). A leaf gets `ceil(quota / 20)` paid batches per
    /// 24 h (first day: `ceil(first_day / 20)`) and one free refill batch per token epoch (at most
    /// 10 a day). A retry of the same request returns the cached reply at no cost.
    ///
    /// # Errors
    /// `unauthorized` (not a leaf, or leaving), `token_epoch_stale`, `quota`, `bad_request`.
    pub fn tokens(
        &self,
        store: &RouterRedbStore,
        now: u64,
        req: &SignedReq,
    ) -> LgResult<TokenReply> {
        req.verify("tokens").map_err(|_| LgRefusal::Unauthorized)?;
        let bad = |_| LgRefusal::BadRequest;
        let mut dec = Dec::new(&req.body);
        let te = dec.u32().map_err(bad)?;
        let bucket = TokenBucket::from_code(dec.u8().map_err(bad)?)?;
        let _request_id: [u8; 16] = dec.fixed().map_err(bad)?;
        if dec.u32().map_err(bad)? != BATCH {
            return Err(LgRefusal::BadRequest);
        }
        let mut blinded = Vec::with_capacity(BATCH_SIZE);
        for _ in 0..BATCH_SIZE {
            blinded.push(dec.fixed::<32>().map_err(bad)?);
        }
        dec.finish().map_err(bad)?;
        let gid = req.gid;
        self.settle(store, now, &gid)?;
        self.run(store, now, |cx| {
            let head = cx.head(&gid)?;
            let leaf = cx.pset(&gid, &req.p)?.filter(|row| !row.leaving);
            let leaf = leaf.ok_or(LgRefusal::Unauthorized)?;
            let cache_key = key(&gid, &[&[REPLY_CACHE], blake3::hash(&req.body).as_bytes()]);
            if let Some(cached) = cx.tx.get(LgTable::Tokens, &cache_key)? {
                return TokenReply::decode(&cached);
            }
            if te != head.te {
                return Err(LgRefusal::TokenEpochStale);
            }
            let issue_key = key(&gid, &[&[ISSUE_ROW], &req.p, &[bucket.code()]]);
            let mut row = cx
                .tx
                .get(LgTable::Tokens, &issue_key)?
                .map(|bytes| IssueRow::decode(&bytes))
                .transpose()?
                .unwrap_or_default();
            row.batches.retain(|at| cx.now.saturating_sub(*at) < DAY_MS);
            row.free.retain(|at| cx.now.saturating_sub(*at) < DAY_MS);
            let quota = bucket.quota(cx.host.config.open_per_day);
            let first_day = cx.now.saturating_sub(leaf.joined_ms) < DAY_MS;
            let day = if first_day { quota.first_day } else { quota.per_day };
            let paid_max = usize::try_from(day.div_ceil(BATCH)).unwrap_or(usize::MAX);
            if row.last_free_te < head.te && row.free.len() < FREE_BATCHES_PER_DAY {
                row.last_free_te = head.te;
                row.free.push(cx.now);
            } else if row.batches.len() >= paid_max {
                return Err(LgRefusal::Quota);
            } else {
                row.batches.push(cx.now);
            }
            let keys = cx.host.group_keys(&gid)?;
            let issued = keys
                .root
                .issue_batch(&blinded, &token_info(&gid, te, bucket))
                .map_err(|_| LgRefusal::Internal)?;
            let reply = TokenReply { evaluated: issued.evaluated, proof: issued.proof };
            cx.tx.put(LgTable::Tokens, &cache_key, &reply.encode())?;
            cx.tx.put(LgTable::Tokens, &issue_key, &row.encode())?;
            Ok(reply)
        })
    }
}
