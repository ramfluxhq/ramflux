// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! The group host of one node (MLS-SPEC r1.1 2): group create, reads, the admin chain and invites,
//! and the shared helpers of every operation. All state sits in the `lg_*` tables of the router
//! database (`router_store::lg_store`); every operation is one write transaction that a refusal
//! aborts. The host takes the host time `now_ms` as an argument and never sees a session id, a
//! source address or an arrival time: the caller (the gateway) holds those in memory only and
//! passes the session's `group_id` for the scope check.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use ramflux_crypto::large_group::{
    EnvHeader, Genesis, LgReader as Dec, LgTokenRootKey, LgWriter as Enc, LogView, ReadReply,
    SignedReq, Token, TokenBucket, admin_chain_head, host_head_sign, next_head, random_array,
};

use super::check::{COMMIT_CAP_24H_DEFAULT, JoinBucket};
use super::key_file::{self, HostKeys};
use super::refusal::{LgRefusal, LgResult};
use super::rows::{HeadRow, InviteRow, LogRow, PsetRow, ROLE_ADMIN, ROLE_MEMBER, ROLE_OWNER, key};
use crate::RouterRedbStore;
use crate::router_store::lg_store::{LgTable, LgTx, LgWrite};

const GENESIS_SIG_DOMAIN: &[u8] = b"rf-lg-genesis-sig-v1";
const ADMIN_SET: u8 = 1;
const ADMIN_CHAIN: u8 = 2;
/// Most admin-chain entries (the read reply carries at most 64).
const ADMIN_CHAIN_MAX: usize = 64;
const READ_PAGE_MAX: usize = 64;
/// Soft byte budget of one read page (the frame limit is 768 KiB; at least one entry is sent).
const READ_PAGE_BYTES: usize = 512 * 1024;
/// Invites: most uses and longest life (spec 2.4: 100 per 7 d).
const INVITE_MAX_USES: u32 = 100;
const INVITE_MAX_TTL_MS: u64 = 7 * super::check::DAY_MS;
const MAX_GENESIS_BYTES: usize = 4096;

/// Settings of one host.
#[derive(Clone, Debug)]
pub struct HostConfig {
    /// This node's id; a genesis naming another host is refused.
    pub host_node_id: String,
    /// `open` bucket quota per pseudonym per 24 h. Placeholder until MEAS-8 (`2 × p95` phone
    /// reconnects); no real-run row asserts it before then.
    pub open_per_day: u32,
    /// Commit cap `C` per rolling 24 h (admin included); `min(1 440, ...)` once MEAS-1 exists.
    pub commit_cap_24h: u32,
}

impl HostConfig {
    /// Placeholder `open` quota until MEAS-8 (spec 2.6).
    pub const OPEN_PER_DAY_PLACEHOLDER: u32 = 24;

    /// Defaults for `host_node_id`: the `open` placeholder and the 1 440 commit cap bound.
    #[must_use]
    pub fn new(host_node_id: impl Into<String>) -> Self {
        Self {
            host_node_id: host_node_id.into(),
            open_per_day: Self::OPEN_PER_DAY_PLACEHOLDER,
            commit_cap_24h: COMMIT_CAP_24H_DEFAULT,
        }
    }
}

/// Keys prepared for a group that is not created yet (the genesis must name the public keys).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedGroup {
    /// Handle to pass to [`LargeGroupHost::create`].
    pub prep_id: [u8; 16],
    /// Public key of the group's head-signing key.
    pub host_head_pk: [u8; 32],
    /// Public key of the group's POPRF token root.
    pub token_root_pk: [u8; 32],
}

/// Answer of `status`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupStatus {
    /// Head epoch.
    pub epoch: u64,
    /// Head `log_seq`.
    pub log_seq: u64,
    /// Current token epoch.
    pub te: u32,
    /// First retained `log_seq`.
    pub floor_seq: u64,
    /// Head chain value at `log_seq`.
    pub head: [u8; 32],
}

/// Loaded keys of one group.
pub(super) struct HostKeySet {
    pub(super) keys: HostKeys,
    pub(super) root: LgTokenRootKey,
}

/// How a member-session or ident op proves the right to act.
#[derive(Clone, Copy, Debug)]
pub enum Authority<'a> {
    /// A P-signed request (ident session); the signer must be an admin.
    Signed(&'a SignedReq),
    /// A commit-bucket token (member session) bound to the operation by
    /// [`super::issue::op_bind`].
    Token(&'a Token),
}

/// The group host.
pub struct LargeGroupHost {
    pub(super) key_dir: PathBuf,
    pub(super) config: HostConfig,
    keys: Mutex<HashMap<[u8; 32], Arc<HostKeySet>>>,
    buckets: Mutex<HashMap<[u8; 32], JoinBucket>>,
}

/// One operation in flight: the open write transaction and the host time.
pub(super) struct Cx<'a> {
    pub(super) tx: &'a LgTx<'a>,
    pub(super) host: &'a LargeGroupHost,
    pub(super) now: u64,
}

impl LargeGroupHost {
    /// Opens the host with its key directory (mode 0700, created if missing).
    ///
    /// # Errors
    /// [`LgRefusal::KeyFile`] when the directory cannot be prepared.
    pub fn open(key_dir: &Path, config: HostConfig) -> LgResult<Self> {
        Ok(Self {
            key_dir: key_file::open_dir(key_dir)?,
            config,
            keys: Mutex::new(HashMap::new()),
            buckets: Mutex::new(HashMap::new()),
        })
    }

    /// Run `op` in one write transaction on the router database; a refusal aborts it.
    pub(super) fn run<R>(
        &self,
        store: &RouterRedbStore,
        now: u64,
        op: impl FnOnce(&Cx<'_>) -> LgResult<R>,
    ) -> LgResult<R> {
        store.lg_write(|tx| {
            let cx = Cx { tx, host: self, now };
            Ok(match op(&cx) {
                Ok(value) => LgWrite::Commit(Ok(value)),
                Err(refusal) => LgWrite::Abort(Err(refusal)),
            })
        })?
    }

    /// Take one request from the group's join bucket (1 per second, burst 10; in memory only).
    pub(super) fn join_bucket_take(&self, gid: &[u8; 32], now: u64) -> bool {
        let mut buckets = self.buckets.lock().unwrap_or_else(PoisonError::into_inner);
        buckets.entry(*gid).or_insert_with(|| JoinBucket::new(now)).take(now)
    }

    pub(super) fn group_keys(&self, gid: &[u8; 32]) -> LgResult<Arc<HostKeySet>> {
        let mut cache = self.keys.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(found) = cache.get(gid) {
            return Ok(Arc::clone(found));
        }
        let keys = key_file::load(&self.key_dir, &key_file::group_name(gid))?;
        let root = keys.token_root()?;
        let loaded = Arc::new(HostKeySet { keys, root });
        cache.insert(*gid, Arc::clone(&loaded));
        Ok(loaded)
    }

    /// Generate the keys of a group to be created: the owner's client puts the two public keys
    /// into the genesis (and so into `group_id`) and calls [`Self::create`].
    ///
    /// # Errors
    /// Key file or randomness failures.
    pub fn create_prepare(&self) -> LgResult<PreparedGroup> {
        let keys = HostKeys::generate()?;
        let prep_id = random_array::<16>()?;
        key_file::publish(&self.key_dir, &key_file::prep_name(&prep_id), &keys)?;
        Ok(PreparedGroup {
            prep_id,
            host_head_pk: keys.head_public()?,
            token_root_pk: keys.token_root()?.public_key(),
        })
    }

    /// Create a group from the owner-signed genesis (spec 2.2, 2.7). Tier 5000 and every tier
    /// other than 1000 is refused `tier_unavailable`.
    ///
    /// # Errors
    /// Refusals: `tier_unavailable`, `bad_request`, `unauthorized`, `group_exists`, key file.
    pub fn create(
        &self,
        store: &RouterRedbStore,
        now: u64,
        prep_id: &[u8; 16],
        genesis_bytes: &[u8],
        owner_sig: &[u8; 64],
    ) -> LgResult<[u8; 32]> {
        if genesis_bytes.len() > MAX_GENESIS_BYTES {
            return Err(LgRefusal::BadRequest);
        }
        let genesis = Genesis::decode(genesis_bytes)?;
        if genesis.host_node_id != self.config.host_node_id {
            return Err(LgRefusal::BadRequest);
        }
        let mut message = Enc::new(GENESIS_SIG_DOMAIN);
        message.var(genesis_bytes);
        verify_plain(&genesis.owner_p_pub, &message.finish(), owner_sig)?;
        let prep = key_file::prep_name(prep_id);
        let prepared = key_file::load(&self.key_dir, &prep)?;
        if genesis.token_root_pk != prepared.token_root()?.public_key()
            || genesis.host_head_pk != prepared.head_public()?
        {
            return Err(LgRefusal::BadRequest);
        }
        let gid = genesis.group_id();
        self.run(store, now, |cx| {
            if cx.tx.get(LgTable::Head, &gid)?.is_some() {
                return Err(LgRefusal::GroupExists);
            }
            key_file::promote(&self.key_dir, &prep, &key_file::group_name(&gid))?;
            let mut head = HeadRow {
                genesis: genesis_bytes.to_vec(),
                epoch: 0,
                log_seq: 0,
                last_head: [0; 32],
                last_appended_ms: now,
                last_commit_at_ms: 0,
                commits_24h: Vec::new(),
                p_set_hash: [0; 32],
                pset_count: 0,
                floor_seq: 0,
                post_count: 0,
                te: 0,
                te_started_ms: now,
                last_roll_kind: 0,
                spent_count: 0,
                rolls: Vec::new(),
                held_admin: Vec::new(),
                held_leave: Vec::new(),
                held_leave_since_ms: 0,
                join_pk: genesis.join_pk_0,
                pending_member: 0,
                pending_outsider: 0,
                voidable_seq: 0,
                voidable_epoch: 0,
                undo_removed: Vec::new(),
                route_count: 0,
                evals: 0,
            };
            let owner = PsetRow { role: ROLE_OWNER, joined_ms: now, leaving: false };
            cx.pset_insert(&gid, &mut head, &genesis.owner_p_pub, &owner)?;
            cx.tx.put(
                LgTable::Admin,
                &key(&gid, &[&[ADMIN_SET], &genesis.owner_p_pub]),
                &[ROLE_OWNER],
            )?;
            cx.put_head(&gid, &head)?;
            Ok(gid)
        })
    }

    /// Current head counters of a group.
    ///
    /// # Errors
    /// `not_found` for an unknown group.
    #[allow(clippy::unused_self, reason = "uniform host API")]
    pub fn status(&self, store: &RouterRedbStore, gid: &[u8; 32]) -> LgResult<GroupStatus> {
        store.lg_read(|view| view.get(LgTable::Head, gid))?.map_or(
            Err(LgRefusal::NotFound),
            |bytes| {
                let head = HeadRow::decode(&bytes)?;
                Ok(GroupStatus {
                    epoch: head.epoch,
                    log_seq: head.log_seq,
                    te: head.te,
                    floor_seq: head.floor_seq,
                    head: head.last_head,
                })
            },
        )
    }

    /// A page of the log from `from_seq` (at most 64 entries and about 512 KiB) with the genesis,
    /// the admin chain and the head counters. Needs a member session; the host checks nothing
    /// about the reader.
    ///
    /// # Errors
    /// `not_found`; `pruned` when `from_seq` is below the first retained entry.
    #[allow(clippy::unused_self, reason = "uniform host API")]
    pub fn read(
        &self,
        store: &RouterRedbStore,
        now: u64,
        gid: &[u8; 32],
        from_seq: u64,
        limit: u32,
    ) -> LgResult<ReadReply> {
        let limit = usize::try_from(limit).unwrap_or(READ_PAGE_MAX).clamp(1, READ_PAGE_MAX);
        store.lg_read(|view| {
            let Some(head_bytes) = view.get(LgTable::Head, gid)? else {
                return Ok(Err(LgRefusal::NotFound));
            };
            let head = match HeadRow::decode(&head_bytes) {
                Ok(head) => head,
                Err(refusal) => return Ok(Err(refusal)),
            };
            if head.floor_seq > 0 && from_seq < head.floor_seq {
                return Ok(Err(LgRefusal::Pruned { floor_seq: head.floor_seq }));
            }
            let start = key(gid, &[&from_seq.max(1).to_be_bytes()]);
            let mut entries = Vec::new();
            let mut bytes = 0_usize;
            for (row_key, value) in view.scan(LgTable::Log, gid, &start, limit)? {
                if !entries.is_empty() && bytes >= READ_PAGE_BYTES {
                    break;
                }
                bytes = bytes.saturating_add(value.len());
                match log_view(&row_key, &value) {
                    Ok(entry) => entries.push(entry),
                    Err(refusal) => return Ok(Err(refusal)),
                }
            }
            let chain_prefix = key(gid, &[&[ADMIN_CHAIN]]);
            let admin_chain = view
                .scan(LgTable::Admin, &chain_prefix, &chain_prefix, ADMIN_CHAIN_MAX)?
                .into_iter()
                .map(|(_, value)| value)
                .collect();
            Ok(Ok(ReadReply {
                genesis: head.genesis,
                te: head.te,
                epoch: head.epoch,
                last_seq: head.log_seq,
                now_ms: now,
                admin_chain,
                entries,
            }))
        })?
    }

    /// Promote (`action` 1, owner only) or demote (`action` 2, an admin) `target`. Writes one
    /// admin-chain entry `prev_head ‖ request`; the owner is never demoted.
    ///
    /// # Errors
    /// `unauthorized`, `forbidden`, `owner_unremovable`, `not_found`, `limit` (chain full).
    pub fn admin(&self, store: &RouterRedbStore, now: u64, req: &SignedReq) -> LgResult<()> {
        req.verify("admin").map_err(|_| LgRefusal::Unauthorized)?;
        let mut dec = Dec::new(&req.body);
        let action = dec.u8().map_err(|_| LgRefusal::BadRequest)?;
        let target: [u8; 32] = dec.fixed().map_err(|_| LgRefusal::BadRequest)?;
        dec.finish().map_err(|_| LgRefusal::BadRequest)?;
        let gid = req.gid;
        self.run(store, now, |cx| {
            cx.head(&gid)?;
            let signer = cx.admin_role(&gid, &req.p)?.ok_or(LgRefusal::Unauthorized)?;
            let target_role = cx.admin_role(&gid, &target)?;
            let in_group = cx.pset(&gid, &target)?;
            match action {
                1 => {
                    if signer != ROLE_OWNER || in_group.is_none() || target_role.is_some() {
                        return Err(LgRefusal::Forbidden);
                    }
                    cx.tx.put(
                        LgTable::Admin,
                        &key(&gid, &[&[ADMIN_SET], &target]),
                        &[ROLE_ADMIN],
                    )?;
                }
                2 => {
                    if target_role == Some(ROLE_OWNER) {
                        return Err(LgRefusal::OwnerUnremovable);
                    }
                    if target_role != Some(ROLE_ADMIN) {
                        return Err(LgRefusal::Forbidden);
                    }
                    cx.tx.del(LgTable::Admin, &key(&gid, &[&[ADMIN_SET], &target]))?;
                }
                _ => return Err(LgRefusal::BadRequest),
            }
            let chain = cx.admin_chain(&gid)?;
            if chain.len() >= ADMIN_CHAIN_MAX {
                return Err(LgRefusal::Limit);
            }
            let mut entry = Enc::default();
            entry.fixed(&admin_chain_head(&gid, &chain)).var(&req.encode());
            let index = u32::try_from(chain.len()).map_err(|_| LgRefusal::Internal)?;
            cx.tx.put(
                LgTable::Admin,
                &key(&gid, &[&[ADMIN_CHAIN], &index.to_be_bytes()]),
                &entry.finish(),
            )?;
            if let Some(mut row) = in_group {
                row.role = if action == 1 { ROLE_ADMIN } else { ROLE_MEMBER };
                cx.tx.put(LgTable::Pset, &key(&gid, &[&target]), &row.encode())?;
            }
            Ok(())
        })
    }

    /// Store an invite (spec 2.4: at most 100 uses, at most 7 days). An admin signs on an ident
    /// session, or a member spends one commit-bucket token.
    ///
    /// # Errors
    /// `unauthorized`, `bad_request`, `invite_invalid` (id taken).
    pub fn invite_put(
        &self,
        store: &RouterRedbStore,
        now: u64,
        gid: &[u8; 32],
        spec: &InviteSpec,
        auth: Authority<'_>,
    ) -> LgResult<()> {
        if spec.max_uses == 0
            || spec.max_uses > INVITE_MAX_USES
            || spec.expires_ms <= now
            || spec.expires_ms > now.saturating_add(INVITE_MAX_TTL_MS)
        {
            return Err(LgRefusal::BadRequest);
        }
        let body = spec.encode();
        self.run(store, now, |cx| {
            let mut head = cx.head(gid)?;
            cx.authorize_op(gid, &mut head, "invite.put", &body, auth)?;
            let row_key = key(gid, &[&spec.invite_id]);
            if cx.tx.get(LgTable::Invite, &row_key)?.is_some() {
                return Err(LgRefusal::InviteInvalid);
            }
            let row = InviteRow {
                pk: spec.pk,
                max_uses: spec.max_uses,
                uses: 0,
                expires_ms: spec.expires_ms,
                revoked: false,
            };
            cx.tx.put(LgTable::Invite, &row_key, &row.encode())?;
            cx.put_head(gid, &head)
        })
    }

    /// Revoke an invite; same authority rules as [`Self::invite_put`].
    ///
    /// # Errors
    /// `unauthorized`, `not_found`.
    pub fn invite_revoke(
        &self,
        store: &RouterRedbStore,
        now: u64,
        gid: &[u8; 32],
        invite_id: &[u8; 16],
        auth: Authority<'_>,
    ) -> LgResult<()> {
        self.run(store, now, |cx| {
            let mut head = cx.head(gid)?;
            cx.authorize_op(gid, &mut head, "invite.revoke", invite_id, auth)?;
            let row_key = key(gid, &[invite_id]);
            let bytes = cx.tx.get(LgTable::Invite, &row_key)?.ok_or(LgRefusal::NotFound)?;
            let mut row = InviteRow::decode(&bytes)?;
            row.revoked = true;
            cx.tx.put(LgTable::Invite, &row_key, &row.encode())?;
            cx.put_head(gid, &head)
        })
    }
}

/// Fields of an invite.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InviteSpec {
    /// Invite id (in the link).
    pub invite_id: [u8; 16],
    /// Key the joiner's proof is verified with.
    pub pk: [u8; 32],
    /// Most uses (1 to 100).
    pub max_uses: u32,
    /// Host time it expires (at most 7 days ahead).
    pub expires_ms: u64,
}

impl InviteSpec {
    /// The request body an admin signs, and the bytes a member's token binds to.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut enc = Enc::default();
        enc.fixed(&self.invite_id).fixed(&self.pk).u32(self.max_uses).u64(self.expires_ms);
        enc.finish()
    }
}

fn log_view(row_key: &[u8], value: &[u8]) -> LgResult<LogView> {
    let seq_bytes: [u8; 8] =
        row_key.get(32..40).and_then(|bytes| bytes.try_into().ok()).ok_or(LgRefusal::Internal)?;
    let row = LogRow::decode(value)?;
    Ok(LogView {
        seq: u64::from_be_bytes(seq_bytes),
        appended_at_ms: row.appended_ms,
        head: row.head,
        host_sig: row.sig,
        envelope: ramflux_crypto::large_group::Envelope::decode(&row.envelope)?,
    })
}

/// Verify a plain Ed25519 signature.
pub(super) fn verify_plain(pk: &[u8; 32], message: &[u8], sig: &[u8; 64]) -> LgResult<()> {
    let key = VerifyingKey::from_bytes(pk).map_err(|_| LgRefusal::Unauthorized)?;
    key.verify(message, &Signature::from_bytes(sig)).map_err(|_| LgRefusal::Unauthorized)
}

impl Cx<'_> {
    pub(super) fn head(&self, gid: &[u8; 32]) -> LgResult<HeadRow> {
        let bytes = self.tx.get(LgTable::Head, gid)?.ok_or(LgRefusal::NotFound)?;
        HeadRow::decode(&bytes)
    }

    pub(super) fn put_head(&self, gid: &[u8; 32], head: &HeadRow) -> LgResult<()> {
        Ok(self.tx.put(LgTable::Head, gid, &head.encode())?)
    }

    pub(super) fn pset(&self, gid: &[u8; 32], p: &[u8; 32]) -> LgResult<Option<PsetRow>> {
        self.tx
            .get(LgTable::Pset, &key(gid, &[p]))?
            .map(|bytes| PsetRow::decode(&bytes))
            .transpose()
    }

    /// Add a leaf pseudonym; keeps the count and the set hash in `head` (the caller stores it).
    pub(super) fn pset_insert(
        &self,
        gid: &[u8; 32],
        head: &mut HeadRow,
        p: &[u8; 32],
        row: &PsetRow,
    ) -> LgResult<()> {
        if self.tx.get(LgTable::Pset, &key(gid, &[p]))?.is_none() {
            head.pset_count = head.pset_count.saturating_add(1);
            xor_into(&mut head.p_set_hash, p);
        }
        Ok(self.tx.put(LgTable::Pset, &key(gid, &[p]), &row.encode())?)
    }

    /// Remove a leaf pseudonym; returns its row when it was there.
    pub(super) fn pset_remove(
        &self,
        gid: &[u8; 32],
        head: &mut HeadRow,
        p: &[u8; 32],
    ) -> LgResult<Option<PsetRow>> {
        let old = self.pset(gid, p)?;
        if old.is_some() {
            head.pset_count = head.pset_count.saturating_sub(1);
            xor_into(&mut head.p_set_hash, p);
            self.tx.del(LgTable::Pset, &key(gid, &[p]))?;
        }
        Ok(old)
    }

    /// Role of `p` in the admin set (`None`: not an admin).
    pub(super) fn admin_role(&self, gid: &[u8; 32], p: &[u8; 32]) -> LgResult<Option<u8>> {
        Ok(self
            .tx
            .get(LgTable::Admin, &key(gid, &[&[ADMIN_SET], p]))?
            .and_then(|bytes| bytes.first().copied()))
    }

    /// Every admin pseudonym (the owner included); at most 65.
    pub(super) fn admin_set(&self, gid: &[u8; 32]) -> LgResult<Vec<[u8; 32]>> {
        let prefix = key(gid, &[&[ADMIN_SET]]);
        let rows = self.tx.scan(LgTable::Admin, &prefix, &prefix, ADMIN_CHAIN_MAX + 1)?;
        Ok(rows
            .into_iter()
            .filter_map(|(row_key, _)| row_key.get(prefix.len()..)?.try_into().ok())
            .collect())
    }

    pub(super) fn admin_chain(&self, gid: &[u8; 32]) -> LgResult<Vec<Vec<u8>>> {
        let prefix = key(gid, &[&[ADMIN_CHAIN]]);
        Ok(self
            .tx
            .scan(LgTable::Admin, &prefix, &prefix, ADMIN_CHAIN_MAX)?
            .into_iter()
            .map(|(_, value)| value)
            .collect())
    }

    /// Chain, sign and store one entry; updates the position fields of `head` (the caller stores
    /// it). The head chain entry hash is `Envelope::chain_hash(appended_at, log_seq)`.
    pub(super) fn append_entry(
        &self,
        gid: &[u8; 32],
        head: &mut HeadRow,
        header: EnvHeader,
        payload: Vec<u8>,
    ) -> LgResult<LogRow> {
        let seq = head.log_seq.checked_add(1).ok_or(LgRefusal::Internal)?;
        let appended = self.now.max(head.last_appended_ms);
        let envelope = ramflux_crypto::large_group::Envelope { header, payload };
        let chain = envelope.chain_hash(appended, seq);
        let new_head = next_head(&head.last_head, seq, &chain);
        let sig = host_head_sign(
            &self.host.group_keys(gid)?.keys.head_signing_seed()?,
            gid,
            seq,
            &new_head,
        );
        let row = LogRow {
            kind: envelope.header.kind.code(),
            epoch: envelope.header.epoch,
            appended_ms: appended,
            head: new_head,
            sig,
            envelope: envelope.encode(),
        };
        self.tx.put(LgTable::Log, &key(gid, &[&seq.to_be_bytes()]), &row.encode())?;
        head.log_seq = seq;
        head.last_head = new_head;
        head.last_appended_ms = appended;
        Ok(row)
    }

    /// Authorise a non-entry operation on `body`: an admin's signature on an ident session, or one
    /// commit-bucket token bound to `(op, group_id, body)`.
    pub(super) fn authorize_op(
        &self,
        gid: &[u8; 32],
        head: &mut HeadRow,
        op: &str,
        body: &[u8],
        auth: Authority<'_>,
    ) -> LgResult<()> {
        match auth {
            Authority::Signed(req) => {
                req.verify(op).map_err(|_| LgRefusal::Unauthorized)?;
                if req.gid != *gid || req.body != body {
                    return Err(LgRefusal::Unauthorized);
                }
                self.admin_role(gid, &req.p)?.map(|_| ()).ok_or(LgRefusal::Unauthorized)
            }
            Authority::Token(token) => {
                let bind = super::issue::op_bind(op, gid, body);
                self.spend_token(gid, head, TokenBucket::Commit, token, &bind)
            }
        }
    }
}

fn xor_into(acc: &mut [u8; 32], p: &[u8; 32]) {
    let hashed = blake3::hash(p);
    for (dst, src) in acc.iter_mut().zip(hashed.as_bytes()) {
        *dst ^= *src;
    }
}
