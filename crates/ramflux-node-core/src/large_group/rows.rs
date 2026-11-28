// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Row layouts of the `lg_*` tables and their keys (MLS-SPEC r1.1 2.2): deterministic binary rows
//! through the large-group codec, every variable field bounded. No row holds an account, a device
//! id, a session id, a source address or an arrival time; `appended_at` is the head chain's own
//! time.

use ramflux_crypto::large_group::{LgError, LgReader as Dec, LgWriter as Enc};

use super::refusal::{LgRefusal, LgResult};

/// Role of a leaf pseudonym.
pub const ROLE_MEMBER: u8 = 0;
/// Admin.
pub const ROLE_ADMIN: u8 = 1;
/// Owner (never removable).
pub const ROLE_OWNER: u8 = 2;

/// Join queue of `own_device` and `rejoin` requests.
pub const QUEUE_MEMBER: u8 = 0;
/// Join queue of `invite` requests.
pub const QUEUE_OUTSIDER: u8 = 1;

const MAX_GENESIS: usize = 4096;
const MAX_ENVELOPE: usize = 600 * 1024;
const MAX_JOIN_FIELD: usize = 32 * 1024;
const MAX_ROUTE_TOKEN: usize = 1024;
/// Most entries of the timestamp rings kept in a row.
pub const RING_MAX: usize = 2_048;
/// Most roll records kept in the head row.
const ROLL_RECORDS_MAX: usize = 64;
/// Most log sequences held for a coming revoke roll.
pub const HELD_REFS_MAX: usize = 64;
/// Most removed leaves an undo record keeps (one commit removes at most 100).
const UNDO_MAX: usize = 100;

fn bad(_: LgError) -> LgRefusal {
    LgRefusal::Internal
}

fn count(len: usize) -> u32 {
    u32::try_from(len).unwrap_or(u32::MAX)
}

fn read_count(dec: &mut Dec<'_>, max: usize) -> LgResult<usize> {
    let n = usize::try_from(dec.u32().map_err(bad)?).map_err(|_| LgRefusal::Internal)?;
    if n > max { Err(LgRefusal::Internal) } else { Ok(n) }
}

fn put_u64_list(enc: &mut Enc, list: &[u64]) {
    enc.u32(count(list.len()));
    for item in list {
        enc.u64(*item);
    }
}

fn get_u64_list(dec: &mut Dec<'_>, max: usize) -> LgResult<Vec<u64>> {
    let n = read_count(dec, max)?;
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        out.push(dec.u64().map_err(bad)?);
    }
    Ok(out)
}

/// Key of a group-scoped row: `gid ‖ parts…`.
#[must_use]
pub fn key(gid: &[u8; 32], parts: &[&[u8]]) -> Vec<u8> {
    let mut out = gid.to_vec();
    for part in parts {
        out.extend_from_slice(part);
    }
    out
}

/// A leaf pseudonym row (`lg_pset`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PsetRow {
    /// [`ROLE_MEMBER`], [`ROLE_ADMIN`] or [`ROLE_OWNER`].
    pub role: u8,
    /// Host time the leaf was added.
    pub joined_ms: u64,
    /// A `leave` entry is stored for it; it gets no more tokens.
    pub leaving: bool,
}

impl PsetRow {
    pub(super) fn encode(&self) -> Vec<u8> {
        let mut enc = Enc::default();
        enc.u8(self.role).u64(self.joined_ms).u8(u8::from(self.leaving));
        enc.finish()
    }

    pub(super) fn decode(bytes: &[u8]) -> LgResult<Self> {
        let mut dec = Dec::new(bytes);
        let row = Self {
            role: dec.u8().map_err(bad)?,
            joined_ms: dec.u64().map_err(bad)?,
            leaving: dec.u8().map_err(bad)? == 1,
        };
        dec.finish().map_err(bad)?;
        Ok(row)
    }
}

/// Per-group counters (`lg_head`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeadRow {
    /// Canonical genesis bytes.
    pub genesis: Vec<u8>,
    /// Current MLS epoch (a commit adds one, a void returns to the voided epoch).
    pub epoch: u64,
    /// Last appended `log_seq` (the head chain position `n`).
    pub log_seq: u64,
    /// Head chain value at `log_seq`.
    pub last_head: [u8; 32],
    /// `appended_at` of the last entry (host time, never decreasing).
    pub last_appended_ms: u64,
    /// `appended_at` of the last commit (pacing).
    pub last_commit_at_ms: u64,
    /// `appended_at` of every commit in the rolling 24 h (the cap `C`).
    pub commits_24h: Vec<u64>,
    /// XOR of `BLAKE3(P)` over the current leaf pseudonyms.
    pub p_set_hash: [u8; 32],
    /// Number of leaf pseudonyms.
    pub pset_count: u32,
    /// First retained `log_seq` (`0` until something is pruned).
    pub floor_seq: u64,
    /// Posts in the log (retention cap).
    pub post_count: u64,
    /// Current token epoch.
    pub te: u32,
    /// Host time the current token epoch began.
    pub te_started_ms: u64,
    /// Code of the roll that began it (`0` at create).
    pub last_roll_kind: u8,
    /// Tokens spent in the current epoch.
    pub spent_count: u64,
    /// Recent rolls `(kind code, started_at)` for the roll caps.
    pub rolls: Vec<(u8, u64)>,
    /// Admin-removal commits waiting for their revoke roll.
    pub held_admin: Vec<u64>,
    /// Leaves waiting for the coalesced revoke roll.
    pub held_leave: Vec<u64>,
    /// Host time the oldest held leave arrived.
    pub held_leave_since_ms: u64,
    /// Current join key.
    pub join_pk: [u8; 32],
    /// Pending requests in the member queue.
    pub pending_member: u32,
    /// Pending requests in the outsider queue.
    pub pending_outsider: u32,
    /// `log_seq` of the last commit, while it can still be voided (`0` otherwise).
    pub voidable_seq: u64,
    /// Epoch the voidable commit was made at.
    pub voidable_epoch: u64,
    /// Rows the voidable commit removed from `lg_pset`, to put back on a void.
    pub undo_removed: Vec<([u8; 32], PsetRow)>,
    /// Registered push routes.
    pub route_count: u32,
}

impl HeadRow {
    pub(super) fn encode(&self) -> Vec<u8> {
        let mut enc = Enc::default();
        enc.var(&self.genesis)
            .u64(self.epoch)
            .u64(self.log_seq)
            .fixed(&self.last_head)
            .u64(self.last_appended_ms)
            .u64(self.last_commit_at_ms);
        put_u64_list(&mut enc, &self.commits_24h);
        enc.fixed(&self.p_set_hash)
            .u32(self.pset_count)
            .u64(self.floor_seq)
            .u64(self.post_count)
            .u32(self.te)
            .u64(self.te_started_ms)
            .u8(self.last_roll_kind)
            .u64(self.spent_count);
        enc.u32(count(self.rolls.len()));
        for (kind, at) in &self.rolls {
            enc.u8(*kind).u64(*at);
        }
        put_u64_list(&mut enc, &self.held_admin);
        put_u64_list(&mut enc, &self.held_leave);
        enc.u64(self.held_leave_since_ms)
            .fixed(&self.join_pk)
            .u32(self.pending_member)
            .u32(self.pending_outsider)
            .u64(self.voidable_seq)
            .u64(self.voidable_epoch);
        enc.u32(count(self.undo_removed.len()));
        for (p, row) in &self.undo_removed {
            enc.fixed(p).var(&row.encode());
        }
        enc.u32(self.route_count);
        enc.finish()
    }

    pub(super) fn decode(bytes: &[u8]) -> LgResult<Self> {
        let mut dec = Dec::new(bytes);
        let genesis = dec.var(MAX_GENESIS).map_err(bad)?.to_vec();
        let epoch = dec.u64().map_err(bad)?;
        let log_seq = dec.u64().map_err(bad)?;
        let last_head = dec.fixed().map_err(bad)?;
        let last_appended_ms = dec.u64().map_err(bad)?;
        let last_commit_at_ms = dec.u64().map_err(bad)?;
        let commits_24h = get_u64_list(&mut dec, RING_MAX)?;
        let p_set_hash = dec.fixed().map_err(bad)?;
        let pset_count = dec.u32().map_err(bad)?;
        let floor_seq = dec.u64().map_err(bad)?;
        let post_count = dec.u64().map_err(bad)?;
        let te = dec.u32().map_err(bad)?;
        let te_started_ms = dec.u64().map_err(bad)?;
        let last_roll_kind = dec.u8().map_err(bad)?;
        let spent_count = dec.u64().map_err(bad)?;
        let roll_n = read_count(&mut dec, ROLL_RECORDS_MAX)?;
        let mut rolls = Vec::with_capacity(roll_n);
        for _ in 0..roll_n {
            rolls.push((dec.u8().map_err(bad)?, dec.u64().map_err(bad)?));
        }
        let held_admin = get_u64_list(&mut dec, HELD_REFS_MAX)?;
        let held_leave = get_u64_list(&mut dec, HELD_REFS_MAX)?;
        let held_leave_since_ms = dec.u64().map_err(bad)?;
        let join_pk = dec.fixed().map_err(bad)?;
        let pending_member = dec.u32().map_err(bad)?;
        let pending_outsider = dec.u32().map_err(bad)?;
        let voidable_seq = dec.u64().map_err(bad)?;
        let voidable_epoch = dec.u64().map_err(bad)?;
        let undo_n = read_count(&mut dec, UNDO_MAX)?;
        let mut undo_removed = Vec::with_capacity(undo_n);
        for _ in 0..undo_n {
            let p = dec.fixed().map_err(bad)?;
            undo_removed.push((p, PsetRow::decode(dec.var(64).map_err(bad)?)?));
        }
        let route_count = dec.u32().map_err(bad)?;
        dec.finish().map_err(bad)?;
        Ok(Self {
            genesis,
            epoch,
            log_seq,
            last_head,
            last_appended_ms,
            last_commit_at_ms,
            commits_24h,
            p_set_hash,
            pset_count,
            floor_seq,
            post_count,
            te,
            te_started_ms,
            last_roll_kind,
            spent_count,
            rolls,
            held_admin,
            held_leave,
            held_leave_since_ms,
            join_pk,
            pending_member,
            pending_outsider,
            voidable_seq,
            voidable_epoch,
            undo_removed,
            route_count,
        })
    }
}

/// One log row (`lg_log`): the encoded `rf-lg-env-v1` envelope (header and inline payload) and the
/// head chain position. There is no author field.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LogRow {
    /// `EnvKind::code()`.
    pub kind: u8,
    /// Entry epoch (the envelope header's).
    pub epoch: u64,
    /// Host time of the append.
    pub appended_ms: u64,
    /// Head chain value `head_n`.
    pub head: [u8; 32],
    /// Host signature over `head_n`.
    pub sig: [u8; 64],
    /// Encoded envelope.
    pub envelope: Vec<u8>,
}

impl LogRow {
    pub(super) fn encode(&self) -> Vec<u8> {
        let mut enc = Enc::default();
        enc.u8(self.kind)
            .u64(self.epoch)
            .u64(self.appended_ms)
            .fixed(&self.head)
            .fixed(&self.sig)
            .var(&self.envelope);
        enc.finish()
    }

    pub(super) fn decode(bytes: &[u8]) -> LgResult<Self> {
        let mut dec = Dec::new(bytes);
        let row = Self {
            kind: dec.u8().map_err(bad)?,
            epoch: dec.u64().map_err(bad)?,
            appended_ms: dec.u64().map_err(bad)?,
            head: dec.fixed().map_err(bad)?,
            sig: dec.fixed().map_err(bad)?,
            envelope: dec.var(MAX_ENVELOPE).map_err(bad)?.to_vec(),
        };
        dec.finish().map_err(bad)?;
        Ok(row)
    }
}

/// A pending join request (`lg_join`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JoinRow {
    /// Host time the request was queued (expiry after 24 h).
    pub created_ms: u64,
    /// `JoinKind::code()`.
    pub kind: u8,
    /// `BLAKE3(join_pk)` the request was sealed to.
    pub join_pk_id: [u8; 32],
    /// The `KeyPackage` bytes.
    pub key_package: Vec<u8>,
    /// The HPKE blob (opaque to the host).
    pub sealed: Vec<u8>,
}

impl JoinRow {
    pub(super) fn encode(&self) -> Vec<u8> {
        let mut enc = Enc::default();
        enc.u64(self.created_ms)
            .u8(self.kind)
            .fixed(&self.join_pk_id)
            .var(&self.key_package)
            .var(&self.sealed);
        enc.finish()
    }

    pub(super) fn decode(bytes: &[u8]) -> LgResult<Self> {
        let mut dec = Dec::new(bytes);
        let row = Self {
            created_ms: dec.u64().map_err(bad)?,
            kind: dec.u8().map_err(bad)?,
            join_pk_id: dec.fixed().map_err(bad)?,
            key_package: dec.var(MAX_JOIN_FIELD).map_err(bad)?.to_vec(),
            sealed: dec.var(MAX_JOIN_FIELD).map_err(bad)?.to_vec(),
        };
        dec.finish().map_err(bad)?;
        Ok(row)
    }
}

/// An invite (`lg_invite`); the row never names its creator.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InviteRow {
    /// Public key the invite proof is verified with.
    pub pk: [u8; 32],
    /// Most uses.
    pub max_uses: u32,
    /// Uses so far.
    pub uses: u32,
    /// Host time the invite expires.
    pub expires_ms: u64,
    /// Revoked.
    pub revoked: bool,
}

impl InviteRow {
    pub(super) fn encode(&self) -> Vec<u8> {
        let mut enc = Enc::default();
        enc.fixed(&self.pk)
            .u32(self.max_uses)
            .u32(self.uses)
            .u64(self.expires_ms)
            .u8(u8::from(self.revoked));
        enc.finish()
    }

    pub(super) fn decode(bytes: &[u8]) -> LgResult<Self> {
        let mut dec = Dec::new(bytes);
        let row = Self {
            pk: dec.fixed().map_err(bad)?,
            max_uses: dec.u32().map_err(bad)?,
            uses: dec.u32().map_err(bad)?,
            expires_ms: dec.u64().map_err(bad)?,
            revoked: dec.u8().map_err(bad)? == 1,
        };
        dec.finish().map_err(bad)?;
        Ok(row)
    }
}

/// Issuance counters of one pseudonym in one bucket (`lg_tokens`): batch times inside the last
/// 24 h and the refill batches after rolls.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct IssueRow {
    /// Times of paid batches in the last 24 h.
    pub batches: Vec<u64>,
    /// Times of free refill batches in the last 24 h.
    pub free: Vec<u64>,
    /// Token epoch of the last free refill.
    pub last_free_te: u32,
}

impl IssueRow {
    pub(super) fn encode(&self) -> Vec<u8> {
        let mut enc = Enc::default();
        enc.u32(self.last_free_te);
        put_u64_list(&mut enc, &self.batches);
        put_u64_list(&mut enc, &self.free);
        enc.finish()
    }

    pub(super) fn decode(bytes: &[u8]) -> LgResult<Self> {
        let mut dec = Dec::new(bytes);
        let last_free_te = dec.u32().map_err(bad)?;
        let batches = get_u64_list(&mut dec, 256)?;
        let free = get_u64_list(&mut dec, 256)?;
        dec.finish().map_err(bad)?;
        Ok(Self { batches, free, last_free_te })
    }
}

/// Blob upload state (`lg_blob`, metadata key).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlobMeta {
    /// Host time the first chunk arrived (orphan expiry 15 min).
    pub created_ms: u64,
    /// Chunks the blob has.
    pub total: u32,
    /// Chunks stored.
    pub received: u32,
    /// Bytes stored.
    pub bytes: u64,
    /// All chunks stored and the hash matches `blob_ref`.
    pub complete: bool,
    /// An entry or a Welcome names it; it lives and dies with that row.
    pub referenced: bool,
}

impl BlobMeta {
    pub(super) fn encode(&self) -> Vec<u8> {
        let mut enc = Enc::default();
        enc.u64(self.created_ms)
            .u32(self.total)
            .u32(self.received)
            .u64(self.bytes)
            .u8(u8::from(self.complete))
            .u8(u8::from(self.referenced));
        enc.finish()
    }

    pub(super) fn decode(bytes: &[u8]) -> LgResult<Self> {
        let mut dec = Dec::new(bytes);
        let row = Self {
            created_ms: dec.u64().map_err(bad)?,
            total: dec.u32().map_err(bad)?,
            received: dec.u32().map_err(bad)?,
            bytes: dec.u64().map_err(bad)?,
            complete: dec.u8().map_err(bad)? == 1,
            referenced: dec.u8().map_err(bad)? == 1,
        };
        dec.finish().map_err(bad)?;
        Ok(row)
    }
}

/// A push route (`lg_route`): no account, device or pseudonym.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RouteRow {
    /// Push token sealed to this node for the centre.
    pub sealed_token: Vec<u8>,
    /// Key of the mention tags.
    pub mention_key: [u8; 32],
    /// `RouteMode::code()`.
    pub mode: u8,
    /// `BLAKE3(del_secret)`.
    pub del_hash: [u8; 32],
    /// UTC day number of the registration (never the time of day).
    pub registered_day: u64,
}

impl RouteRow {
    pub(super) fn encode(&self) -> Vec<u8> {
        let mut enc = Enc::default();
        enc.var(&self.sealed_token)
            .fixed(&self.mention_key)
            .u8(self.mode)
            .fixed(&self.del_hash)
            .u64(self.registered_day);
        enc.finish()
    }

    pub(super) fn decode(bytes: &[u8]) -> LgResult<Self> {
        let mut dec = Dec::new(bytes);
        let row = Self {
            sealed_token: dec.var(MAX_ROUTE_TOKEN).map_err(bad)?.to_vec(),
            mention_key: dec.fixed().map_err(bad)?,
            mode: dec.u8().map_err(bad)?,
            del_hash: dec.fixed().map_err(bad)?,
            registered_day: dec.u64().map_err(bad)?,
        };
        dec.finish().map_err(bad)?;
        Ok(row)
    }
}

/// A stored Welcome (`lg_welcome`): the blob and the joiners that have not fetched it yet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WelcomeRow {
    /// Host time it was stored.
    pub created_ms: u64,
    /// Host time the last joiner fetched it (`0` while some joiner has not).
    pub drained_ms: u64,
    /// Blob holding the Welcome.
    pub blob_ref: [u8; 32],
    /// Every joiner of the commit (they may fetch again until the row goes).
    pub joiners: Vec<[u8; 32]>,
    /// Joiners that have not fetched it yet.
    pub remaining: Vec<[u8; 32]>,
}

impl WelcomeRow {
    pub(super) fn encode(&self) -> Vec<u8> {
        let mut enc = Enc::default();
        enc.u64(self.created_ms).u64(self.drained_ms).fixed(&self.blob_ref);
        for list in [&self.joiners, &self.remaining] {
            enc.u32(count(list.len()));
            for p in list {
                enc.fixed(p);
            }
        }
        enc.finish()
    }

    pub(super) fn decode(bytes: &[u8]) -> LgResult<Self> {
        let mut dec = Dec::new(bytes);
        let created_ms = dec.u64().map_err(bad)?;
        let drained_ms = dec.u64().map_err(bad)?;
        let blob_ref = dec.fixed().map_err(bad)?;
        let mut lists = [Vec::new(), Vec::new()];
        for list in &mut lists {
            let n = read_count(&mut dec, 128)?;
            for _ in 0..n {
                list.push(dec.fixed().map_err(bad)?);
            }
        }
        dec.finish().map_err(bad)?;
        let [joiners, remaining] = lists;
        Ok(Self { created_ms, drained_ms, blob_ref, joiners, remaining })
    }
}
