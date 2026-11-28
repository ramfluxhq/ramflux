// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! `submit`: the check order of MLS-SPEC r1.1 2.3 and the append (from 6ed `entries.rs`).
//!
//! 1 session scope, 2 authorisation, 3 outer MLS header and kind, 4 epoch rule, 5 commit checks
//! (authenticated data, pacing and cap, join tie, removals, blobs, the Welcome), 6 append. One
//! write transaction; every refusal aborts it, so a refused entry spends no token (a commit spends
//! four) and writes no row; the Welcome row is written in the commit's own transaction.

use ramflux_crypto::large_group::{
    ADMIN_COMMIT_GAP_MS, EnvAuth, EnvKind, Envelope, Genesis, LEAF_CAP, MEMBER_COMMIT_GAP_MS,
    RemoveGround, TokenBucket, parse_void_payload, verify_envelope_sig,
};

use super::check::{
    check_commit_aad, check_outer_header, check_pacing, epoch_rule, join_row_live, join_tie,
    prune_ring,
};
use super::host::{Cx, LargeGroupHost};
use super::refusal::{LgRefusal, LgResult};
use super::rows::{
    HeadRow, JoinRow, LogRow, PsetRow, QUEUE_MEMBER, QUEUE_OUTSIDER, RING_MAX, ROLE_MEMBER,
    ROLE_OWNER, key,
};
use crate::RouterRedbStore;
use crate::router_store::lg_store::LgTable;

/// What `submit` answers: the entry's place in the head chain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppendReceipt {
    /// Position of the entry.
    pub log_seq: u64,
    /// Host time of the append.
    pub appended_at_ms: u64,
    /// Head chain value `head_n`.
    pub head: [u8; 32],
    /// Host signature over `head_n`.
    pub host_sig: [u8; 64],
}

/// Who authorised an entry.
enum Signer {
    /// A redeemed token (the host cannot tell who).
    Token,
    /// An admin pseudonym.
    Admin,
    /// A leaving pseudonym (`leave` only).
    Leaver([u8; 32]),
}

/// What a commit check needs besides the group and its head.
struct CommitIn<'a> {
    env: &'a Envelope,
    mls: &'a [u8],
    signer: Signer,
}

/// The MLS bytes of an entry: inline, or the first chunk of its blob.
enum Mls<'a> {
    Inline(&'a [u8]),
    Chunk(Vec<u8>),
    None,
}

impl Mls<'_> {
    fn bytes(&self) -> &[u8] {
        match self {
            Self::Inline(bytes) => bytes,
            Self::Chunk(bytes) => bytes,
            Self::None => &[],
        }
    }
}

impl LargeGroupHost {
    /// Handle one `submit{envelope}` of a session on `session_gid` (member session for posts,
    /// proposals, state, commits, tombstones, leave; ident session for admin entries and void).
    ///
    /// # Errors
    /// The refusals of spec 2.3: `session_scope`, `unauthorized`, `token_spent`,
    /// `token_epoch_stale`, `header_mismatch`, `stale`, `paced`, `commit_bad_adds`,
    /// `blob_missing`, plus `commit_bad_removes`, `leaf_cap`, `owner_unremovable`, `bad_request`.
    pub fn submit(
        &self,
        store: &RouterRedbStore,
        now: u64,
        session_gid: &[u8; 32],
        bytes: &[u8],
    ) -> LgResult<AppendReceipt> {
        let envelope = Envelope::decode(bytes).map_err(|_| LgRefusal::BadRequest)?;
        // 1: session scope (before anything else is read).
        if envelope.header.group_id != *session_gid {
            return Err(LgRefusal::SessionScope);
        }
        self.settle(store, now, session_gid)?;
        let receipt = self.run(store, now, |cx| cx.submit(&envelope))?;
        // `run` returns only after commit and writer release. Refused entries never reach
        // matching, and a dropped wake cannot change the successful append receipt.
        if envelope.header.kind == EnvKind::Post {
            self.enqueue_post_wakes(store, now, &envelope);
        }
        Ok(receipt)
    }
}

impl Cx<'_> {
    fn submit(&self, env: &Envelope) -> LgResult<AppendReceipt> {
        let gid = env.header.group_id;
        let mut head = self.head(&gid)?;
        // 2: authorisation.
        let signer = self.authorize_entry(&gid, &mut head, env)?;
        // 3: outer header and kind; 4: epoch rule.
        let mls = self.mls_bytes(&gid, env)?;
        let outer = check_outer_header(&env.header, mls.bytes())?;
        epoch_rule(env.header.kind, env.header.epoch, head.epoch)?;
        // 5 and 6.
        let row = match env.header.kind {
            EnvKind::Commit => {
                outer.ok_or(LgRefusal::Internal)?;
                let input = CommitIn { env, mls: mls.bytes(), signer };
                self.append_commit(&gid, &mut head, &input)?
            }
            EnvKind::Post | EnvKind::Tombstone | EnvKind::Proposal | EnvKind::State => {
                self.reference_blob(&gid, env)?;
                let row =
                    self.append_entry(&gid, &mut head, env.header.clone(), env.payload.clone())?;
                if env.header.kind == EnvKind::Post {
                    head.post_count = head.post_count.saturating_add(1);
                }
                row
            }
            EnvKind::Leave => self.append_leave(&gid, &mut head, env, &signer)?,
            EnvKind::Void => self.append_void(&gid, &mut head, env)?,
            EnvKind::Roll => return Err(LgRefusal::Unauthorized),
        };
        self.put_head(&gid, &head)?;
        Ok(AppendReceipt {
            log_seq: head.log_seq,
            appended_at_ms: row.appended_ms,
            head: row.head,
            host_sig: row.sig,
        })
    }

    /// Spec 2.3 check 2.
    fn authorize_entry(
        &self,
        gid: &[u8; 32],
        head: &mut HeadRow,
        env: &Envelope,
    ) -> LgResult<Signer> {
        match &env.header.auth {
            EnvAuth::Token(token) => {
                let bucket: TokenBucket = env.header.bucket.ok_or(LgRefusal::BadRequest)?;
                self.spend_token(gid, head, bucket, token, &env.bind_hash())?;
                Ok(Signer::Token)
            }
            // A commit pays four tokens, all verified and spent here or none (the caller's
            // transaction aborts on the first refusal).
            EnvAuth::CommitTokens(tokens) => {
                let bucket: TokenBucket = env.header.bucket.ok_or(LgRefusal::BadRequest)?;
                let bind = env.bind_hash();
                for token in tokens {
                    self.spend_token(gid, head, bucket, token, &bind)?;
                }
                Ok(Signer::Token)
            }
            EnvAuth::AdminSig(sig) => {
                for p in self.admin_set(gid)? {
                    if verify_envelope_sig(&p, &env.header, &env.payload, sig).is_ok() {
                        return Ok(Signer::Admin);
                    }
                }
                Err(LgRefusal::Unauthorized)
            }
            // A P-signature names no signer, so only `leave` (payload = P) can use it.
            EnvAuth::PSig(sig) if env.header.kind == EnvKind::Leave => {
                let p: [u8; 32] =
                    env.payload.as_slice().try_into().map_err(|_| LgRefusal::BadRequest)?;
                verify_envelope_sig(&p, &env.header, &env.payload, sig)
                    .map_err(|_| LgRefusal::Unauthorized)?;
                Ok(Signer::Leaver(p))
            }
            EnvAuth::PSig(_) | EnvAuth::Host => Err(LgRefusal::Unauthorized),
        }
    }

    /// The MLS bytes the header checks read: inline, or chunk 0 of the complete blob.
    fn mls_bytes<'e>(&self, gid: &[u8; 32], env: &'e Envelope) -> LgResult<Mls<'e>> {
        if env.header.kind.mls_content().is_none() {
            return if env.header.blob_ref.is_some() {
                Err(LgRefusal::HeaderMismatch)
            } else {
                Ok(Mls::None)
            };
        }
        match env.header.blob_ref {
            None => Ok(Mls::Inline(&env.payload)),
            Some(blob_ref) => {
                if !env.payload.is_empty() {
                    return Err(LgRefusal::HeaderMismatch);
                }
                self.blob_complete_chunk0(gid, &blob_ref).map(Mls::Chunk)
            }
        }
    }

    /// Spec 2.3 check 5e for entries that are not commits.
    fn reference_blob(&self, gid: &[u8; 32], env: &Envelope) -> LgResult<()> {
        match env.header.blob_ref {
            Some(blob_ref) => self.blob_reference(gid, &blob_ref),
            None => Ok(()),
        }
    }

    /// The queue where `p` has a live pending join (younger than 24 h; a stale row that nobody
    /// has swept yet does not count).
    pub(super) fn pending_queue(&self, gid: &[u8; 32], p: &[u8; 32]) -> LgResult<Option<u8>> {
        for queue in [QUEUE_MEMBER, QUEUE_OUTSIDER] {
            if let Some(bytes) = self.tx.get(LgTable::Join, &key(gid, &[&[queue], p]))?
                && join_row_live(JoinRow::decode(&bytes)?.created_ms, self.now)
            {
                return Ok(Some(queue));
            }
        }
        Ok(None)
    }

    fn append_commit(
        &self,
        gid: &[u8; 32],
        head: &mut HeadRow,
        input: &CommitIn<'_>,
    ) -> LgResult<LogRow> {
        let CommitIn { env, mls, signer } = input;
        let header = &env.header;
        let by_admin = matches!(signer, Signer::Admin);
        // 5a: authenticated data equals the envelope header.
        check_commit_aad(header, mls)?;
        // 5b: pacing and the commit cap C (admin included).
        let gap = if by_admin { ADMIN_COMMIT_GAP_MS } else { MEMBER_COMMIT_GAP_MS };
        let cap = self.host.config.commit_cap_24h.min(u32::try_from(RING_MAX).unwrap_or(u32::MAX));
        check_pacing(self.now, head.last_commit_at_ms, gap, &head.commits_24h, cap)?;
        // 5c: the join tie.
        let genesis = Genesis::decode(&head.genesis)?;
        let mut found = Vec::with_capacity(header.added_p.len());
        for (index, p) in header.added_p.iter().enumerate() {
            let duplicate = header.added_p.get(..index).is_some_and(|before| before.contains(p));
            if duplicate || self.pset(gid, p)?.is_some() {
                return Err(LgRefusal::CommitBadAdds);
            }
            found.push(self.pending_queue(gid, p)?);
        }
        let (from_member, from_outsider) = join_tie(&found, genesis.approval, by_admin)?;
        // Removals: leaves of the set only, never the owner; the admin ground needs an admin
        // commit, the leave ground a stored `leave`.
        let mut undo = Vec::with_capacity(header.removed.len());
        for (index, removal) in header.removed.iter().enumerate() {
            let duplicate =
                header.removed.get(..index).is_some_and(|b| b.iter().any(|r| r.p == removal.p));
            let row = self.pset(gid, &removal.p)?;
            let Some(row) = row.filter(|_| !duplicate) else {
                return Err(LgRefusal::CommitBadRemoves);
            };
            if row.role == ROLE_OWNER {
                return Err(LgRefusal::OwnerUnremovable);
            }
            let ground_ok = match removal.ground {
                RemoveGround::Admin => by_admin,
                RemoveGround::Leave => row.leaving,
                RemoveGround::OwnSibling | RemoveGround::Rejoin => true,
            };
            if !ground_ok {
                return Err(LgRefusal::CommitBadRemoves);
            }
            undo.push((removal.p, row));
        }
        let adds = u32::try_from(header.added_p.len()).map_err(|_| LgRefusal::BadRequest)?;
        let removes = u32::try_from(undo.len()).map_err(|_| LgRefusal::BadRequest)?;
        if head.pset_count.saturating_add(adds).saturating_sub(removes) > LEAF_CAP {
            return Err(LgRefusal::LeafCap);
        }
        // 5e: the commit's own blob, and the Welcome of its adds (a complete pending blob).
        self.reference_blob(gid, env)?;
        match (header.added_p.is_empty(), header.welcome_ref) {
            (false, Some(welcome_ref)) => self.blob_reference(gid, &welcome_ref)?,
            (false, None) => return Err(LgRefusal::BlobMissing),
            (true, _) => {}
        }
        // 6: append; epoch + 1; leaf set and queues follow the cleartext header.
        let seq_before = head.log_seq;
        let row = self.append_entry(gid, head, header.clone(), env.payload.clone())?;
        let seq = seq_before.saturating_add(1);
        if let Some(welcome_ref) = header.welcome_ref {
            self.welcome_store(gid, seq, &welcome_ref, &header.added_p)?;
        }
        for (p, queue) in header.added_p.iter().zip(&found) {
            if let Some(queue) = queue {
                self.tx.del(LgTable::Join, &key(gid, &[&[*queue], p]))?;
            }
            let member = PsetRow { role: ROLE_MEMBER, joined_ms: row.appended_ms, leaving: false };
            self.pset_insert(gid, head, p, &member)?;
        }
        head.pending_member = head.pending_member.saturating_sub(from_member);
        head.pending_outsider = head.pending_outsider.saturating_sub(from_outsider);
        let mut admin_removal = false;
        for removal in &header.removed {
            self.pset_remove(gid, head, &removal.p)?;
            admin_removal |= removal.ground == RemoveGround::Admin;
        }
        if let Some(join_pk) = header.join_pk_new {
            head.join_pk = join_pk;
        }
        head.voidable_seq = seq;
        head.voidable_epoch = head.epoch;
        head.undo_removed = undo;
        head.epoch = head.epoch.saturating_add(1);
        head.last_commit_at_ms = row.appended_ms;
        let mut ring = prune_ring(&head.commits_24h, row.appended_ms);
        ring.push(row.appended_ms);
        let excess = ring.len().saturating_sub(RING_MAX);
        head.commits_24h = ring.split_off(excess);
        if admin_removal {
            Self::hold_admin_removal(head, seq);
            self.maybe_roll(gid, head)?;
        }
        Ok(row)
    }

    /// `leave{P}`: the leaver gets no more tokens at once; its leaf goes with the next commit that
    /// removes it (ground `leave`). A leaver older than 24 h is listed for the coalesced roll.
    fn append_leave(
        &self,
        gid: &[u8; 32],
        head: &mut HeadRow,
        env: &Envelope,
        signer: &Signer,
    ) -> LgResult<LogRow> {
        let Signer::Leaver(p) = signer else {
            return Err(LgRefusal::Unauthorized);
        };
        let mut row = self.pset(gid, p)?.ok_or(LgRefusal::Unauthorized)?;
        if row.role == ROLE_OWNER {
            return Err(LgRefusal::OwnerUnremovable);
        }
        if row.leaving {
            return Err(LgRefusal::BadRequest);
        }
        let entry = self.append_entry(gid, head, env.header.clone(), env.payload.clone())?;
        row.leaving = true;
        self.tx.put(LgTable::Pset, &key(gid, &[p]), &row.encode())?;
        if self.now.saturating_sub(row.joined_ms) >= super::check::DAY_MS {
            Self::hold_leave(head, head.log_seq, self.now);
        }
        Ok(entry)
    }

    /// `void{seq}` by an admin: only the head commit; the epoch returns to the voided commit's
    /// epoch and the leaf set to what it was before it. No row is rewritten; the joins the commit
    /// consumed are not restored (those joiners ask again).
    fn append_void(&self, gid: &[u8; 32], head: &mut HeadRow, env: &Envelope) -> LgResult<LogRow> {
        let target = parse_void_payload(&env.payload).map_err(|_| LgRefusal::BadRequest)?;
        if target == 0 || target != head.voidable_seq || env.header.epoch != head.epoch {
            return Err(LgRefusal::Stale { epoch: head.epoch });
        }
        let bytes = self
            .tx
            .get(LgTable::Log, &key(gid, &[&target.to_be_bytes()]))?
            .ok_or(LgRefusal::NotFound)?;
        let voided = Envelope::decode(&LogRow::decode(&bytes)?.envelope)?;
        let entry = self.append_entry(gid, head, env.header.clone(), env.payload.clone())?;
        for p in &voided.header.added_p {
            self.pset_remove(gid, head, p)?;
        }
        for (p, row) in std::mem::take(&mut head.undo_removed) {
            self.pset_insert(gid, head, &p, &row)?;
        }
        self.welcome_discard(gid, target)?;
        head.epoch = head.voidable_epoch;
        head.voidable_seq = 0;
        Ok(entry)
    }

    /// Delete pending join rows of `queue` older than 24 h and recount the queue.
    pub(super) fn expire_joins(
        &self,
        gid: &[u8; 32],
        head: &mut HeadRow,
        queue: u8,
    ) -> LgResult<()> {
        let prefix = key(gid, &[&[queue]]);
        let rows = self.tx.scan(
            LgTable::Join,
            &prefix,
            &prefix,
            usize::try_from(super::check::JOIN_QUEUE_MAX).unwrap_or(1_000).saturating_add(1),
        )?;
        let mut left = 0_u32;
        for (row_key, value) in rows {
            if super::check::join_expired(JoinRow::decode(&value)?.created_ms, self.now) {
                self.tx.del(LgTable::Join, &row_key)?;
            } else {
                left = left.saturating_add(1);
            }
        }
        if queue == QUEUE_MEMBER {
            head.pending_member = left;
        } else {
            head.pending_outsider = left;
        }
        Ok(())
    }
}
