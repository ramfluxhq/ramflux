// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! The pure rules of the group host (MLS-SPEC r1.1 2.3 to 2.6): outer MLS header checks, the epoch
//! rule, commit authenticated data, pacing and the commit cap `C`, the join tie and the join
//! bucket, `KeyPackage` pseudonym extraction and the retention cut-offs. Nothing here touches a
//! table or a clock: `now` is always an argument, and no rule decides validity of MLS content by
//! time (rule V); time feeds only pacing, quotas and retention.

use ramflux_crypto::large_group::{EnvHeader, EnvKind, MlsContent};

use super::refusal::{LgRefusal, LgResult};
use crate::mls_header::{
    MlsContentType, MlsOuterHeader, parse_outer_header, parse_private_message,
};

/// One day in milliseconds.
pub const DAY_MS: u64 = 86_400_000;
/// Application messages are accepted this many epochs behind the head (spec 2.3 check 4).
pub const APP_EPOCH_WINDOW: u64 = 3;
/// Upper bound of the commit cap `C` until MEAS-1 sets it (`min(1 440, ...)`, spec 1.3): a config
/// value of the host, never asserted by a real-run row before MEAS-1.
pub const COMMIT_CAP_24H_DEFAULT: u32 = 1_440;
/// Most pending requests per join queue.
pub const JOIN_QUEUE_MAX: u32 = 1_000;
/// Pending join requests expire after this (24 h).
pub const JOIN_TTL_MS: u64 = DAY_MS;
/// Log entries (posts and everything else) are kept this long (30 d).
pub const RETAIN_MS: u64 = 30 * DAY_MS;
/// Most posts kept in a group's log (1 M, owner 4).
pub const POSTS_MAX: u64 = 1_000_000;
/// A stored Welcome is deleted after this (7 d) if some joiner has not fetched it.
pub const WELCOME_TTL_MS: u64 = 7 * DAY_MS;
/// A fully fetched Welcome stays this long so the joiner can still pull its chunks (10 min).
pub const WELCOME_DRAINED_GRACE_MS: u64 = 600_000;
/// An upload nobody references is dropped after this (15 min).
pub const BLOB_ORPHAN_MS: u64 = 900_000;
/// A route is dropped when `registered_day + ROUTE_DAYS <= today` (spec 2.2: 7 to 8 days).
pub const ROUTE_DAYS: u64 = 8;
const JOIN_BURST_MILLI: u64 = 10_000;
const JOIN_COST_MILLI: u64 = 1_000;

fn content_of(kind: EnvKind) -> Option<MlsContentType> {
    kind.mls_content().map(|content| match content {
        MlsContent::Commit => MlsContentType::Commit,
        MlsContent::Proposal => MlsContentType::Proposal,
        MlsContent::Application => MlsContentType::Application,
    })
}

/// Spec 2.3 check 3: the outer `PrivateMessage` header of an entry that carries MLS content must
/// name this group and the envelope's epoch, and its content type must be the one the envelope
/// kind needs (commit to commit, proposal to proposal, post/state/tombstone to application).
/// Kinds without MLS content (`leave`, `void`, `roll`) return `None`.
///
/// # Errors
/// [`LgRefusal::HeaderMismatch`] for any disagreement or a header that does not parse.
pub fn check_outer_header(header: &EnvHeader, mls: &[u8]) -> LgResult<Option<MlsOuterHeader>> {
    let Some(want) = content_of(header.kind) else {
        return Ok(None);
    };
    let outer = parse_outer_header(mls).map_err(|_| LgRefusal::HeaderMismatch)?;
    if outer.content_type != want
        || outer.group_id.as_slice() != header.group_id.as_slice()
        || outer.epoch != header.epoch
    {
        return Err(LgRefusal::HeaderMismatch);
    }
    Ok(Some(outer))
}

/// Spec 2.3 check 4: commits and proposals need `epoch == head`; application content needs
/// `head - 3 <= epoch <= head`. Entries without MLS content only need to be no newer than the
/// head.
///
/// # Errors
/// [`LgRefusal::Stale`] carrying the head epoch.
pub fn epoch_rule(kind: EnvKind, epoch: u64, head_epoch: u64) -> LgResult<()> {
    let ok = match content_of(kind) {
        Some(MlsContentType::Commit | MlsContentType::Proposal) => epoch == head_epoch,
        Some(MlsContentType::Application) => {
            epoch <= head_epoch && epoch >= head_epoch.saturating_sub(APP_EPOCH_WINDOW)
        }
        None => epoch <= head_epoch,
    };
    if ok { Ok(()) } else { Err(LgRefusal::Stale { epoch: head_epoch }) }
}

/// Spec 2.3 check 5a: the commit's `authenticated_data` is `rf-lg-aad-v1` followed by the
/// canonical header without the authorisation, `blob_ref` and `welcome_ref`; it must equal the
/// envelope header's own AAD bytes. The field comes from the one shared MLS header parser.
///
/// # Errors
/// [`LgRefusal::HeaderMismatch`].
pub fn check_commit_aad(header: &EnvHeader, mls: &[u8]) -> LgResult<()> {
    let (_, aad) = parse_private_message(mls).map_err(|_| LgRefusal::HeaderMismatch)?;
    if aad == header.aad_bytes().as_slice() { Ok(()) } else { Err(LgRefusal::HeaderMismatch) }
}

/// Drop commit times older than 24 h.
#[must_use]
pub fn prune_ring(ring: &[u64], now: u64) -> Vec<u64> {
    ring.iter().copied().filter(|at| at.saturating_add(DAY_MS) > now).collect()
}

/// Spec 2.3 check 5b: at least `gap_ms` after the previous commit and fewer than `cap` commits in
/// the rolling 24 h (admin commits included).
///
/// # Errors
/// [`LgRefusal::Paced`] with the earliest accepted time.
pub fn check_pacing(
    now: u64,
    last_commit_at: u64,
    gap_ms: u64,
    ring: &[u64],
    cap: u32,
) -> LgResult<()> {
    if last_commit_at != 0 {
        let next = last_commit_at.saturating_add(gap_ms);
        if now < next {
            return Err(LgRefusal::Paced { retry_at_ms: next });
        }
    }
    let recent = prune_ring(ring, now);
    let cap = usize::try_from(cap).unwrap_or(usize::MAX);
    if recent.len() >= cap {
        let oldest = recent.iter().copied().min().unwrap_or(now);
        return Err(LgRefusal::Paced { retry_at_ms: oldest.saturating_add(DAY_MS) });
    }
    Ok(())
}

/// Per-group join bucket: 1 request per second, burst 10 (milli-tokens).
#[derive(Clone, Copy, Debug)]
pub struct JoinBucket {
    milli: u64,
    last_ms: u64,
}

impl JoinBucket {
    /// A full bucket at `now`.
    #[must_use]
    pub const fn new(now: u64) -> Self {
        Self { milli: JOIN_BURST_MILLI, last_ms: now }
    }

    /// Take one request's worth; `false` when the bucket is empty.
    pub fn take(&mut self, now: u64) -> bool {
        let refilled =
            self.milli.saturating_add(now.saturating_sub(self.last_ms)).min(JOIN_BURST_MILLI);
        self.last_ms = now;
        if refilled < JOIN_COST_MILLI {
            self.milli = refilled;
            false
        } else {
            self.milli = refilled - JOIN_COST_MILLI;
            true
        }
    }
}

/// Spec 2.3 check 5c, the join tie: every added pseudonym must have a pending join entry
/// (`found[i]` is the queue of `added[i]`, or `None`). With approval ON an `invite` join (outsider
/// queue) is valid only in an admin-committed commit. Returns how many joins come from each queue.
///
/// # Errors
/// [`LgRefusal::CommitBadAdds`].
pub fn join_tie(found: &[Option<u8>], approval_on: bool, by_admin: bool) -> LgResult<(u32, u32)> {
    let (mut member, mut outsider) = (0_u32, 0_u32);
    for queue in found {
        match queue {
            Some(super::rows::QUEUE_MEMBER) => member = member.saturating_add(1),
            Some(super::rows::QUEUE_OUTSIDER) => outsider = outsider.saturating_add(1),
            _ => return Err(LgRefusal::CommitBadAdds),
        }
    }
    if approval_on && outsider > 0 && !by_admin {
        return Err(LgRefusal::CommitBadAdds);
    }
    Ok((member, outsider))
}

/// The leaf signature key of the `MLSMessage`-wrapped `KeyPackage` that `ramflux-mls` emits: the
/// pseudonym `P` (by definition the leaf signature key, so reading it adds no field and no link).
/// The host needs it to tie a join request to an `added_P` without reading the roster. The bytes
/// are parsed with the openmls types in `ramflux-mls`; only the structure is checked here.
///
/// # Errors
/// [`LgRefusal::BadRequest`] when the bytes are not an MLS 1.0 `KeyPackage` message of the ramflux
/// suite.
pub fn key_package_signature_key(key_package: &[u8]) -> LgResult<[u8; 32]> {
    ramflux_mls::key_package_signature_key(key_package).map_err(|_| LgRefusal::BadRequest)
}

/// A log entry is past retention.
#[must_use]
pub const fn entry_expired(appended_ms: u64, now: u64) -> bool {
    appended_ms.saturating_add(RETAIN_MS) < now
}

/// A join request is past its 24 h.
#[must_use]
pub const fn join_expired(created_ms: u64, now: u64) -> bool {
    created_ms.saturating_add(JOIN_TTL_MS) <= now
}

/// A pending join row satisfies the join tie only while it is younger than 24 h (expiry otherwise
/// runs only when a queue is full, so a stale row must not count).
#[must_use]
pub const fn join_row_live(created_ms: u64, now: u64) -> bool {
    !join_expired(created_ms, now)
}

/// An unreferenced upload is an orphan.
#[must_use]
pub const fn blob_orphaned(created_ms: u64, referenced: bool, now: u64) -> bool {
    !referenced && created_ms.saturating_add(BLOB_ORPHAN_MS) <= now
}

/// A stored Welcome is deleted: 7 d old, or every joiner fetched it and the grace has passed
/// (`drained_ms == 0` while some joiner has not).
#[must_use]
pub const fn welcome_expired(created_ms: u64, drained_ms: u64, now: u64) -> bool {
    created_ms.saturating_add(WELCOME_TTL_MS) <= now
        || (drained_ms != 0 && drained_ms.saturating_add(WELCOME_DRAINED_GRACE_MS) <= now)
}

/// Attachment pending bytes per group (declared bytes of all unfinished uploads).
pub const ATTACH_PENDING_GROUP_BYTES: u64 = 128 * 1024 * 1024;
/// A complete attachment lives until UTC day `completed_day + 31` (30 to 31 days).
pub const ATTACH_RETAIN_DAYS: u64 = 31;

/// A complete attachment completed on UTC day `completed_day` is dropped on `today`.
#[must_use]
pub const fn attach_expired(completed_day: u64, today: u64) -> bool {
    completed_day.saturating_add(ATTACH_RETAIN_DAYS) <= today
}

/// Whether `declared` more bytes fit beside the `pending` ones of the group's other unfinished
/// attachment uploads.
#[must_use]
pub const fn attach_pool_fits(pending: u64, declared: u64) -> bool {
    pending.saturating_add(declared) <= ATTACH_PENDING_GROUP_BYTES
}

/// How many of the oldest complete attachments (`sizes`, oldest first) go so that the store
/// (`stored` bytes) is at most `cap`.
#[must_use]
pub fn evict_until(stored: u64, cap: u64, sizes: &[u64]) -> usize {
    let mut left = stored;
    let mut count = 0;
    for size in sizes {
        if left <= cap {
            break;
        }
        left = left.saturating_sub(*size);
        count += 1;
    }
    count
}

/// A route registered on UTC day `registered_day` is dropped on `today`.
#[must_use]
pub const fn route_expired(registered_day: u64, today: u64) -> bool {
    registered_day.saturating_add(ROUTE_DAYS) <= today
}

#[cfg(test)]
mod tests {
    use ramflux_crypto::large_group::{EnvAuth, TAG_SLOTS};

    use super::super::rows::{QUEUE_MEMBER, QUEUE_OUTSIDER};
    use super::*;

    const GID: [u8; 32] = [7; 32];

    fn header(kind: EnvKind, epoch: u64) -> EnvHeader {
        EnvHeader {
            group_id: GID,
            kind,
            epoch,
            post_id: [1; 16],
            bucket: None,
            tags: [[0; 16]; TAG_SLOTS],
            del_hash: None,
            blob_ref: None,
            welcome_ref: None,
            added_p: Vec::new(),
            removed: Vec::new(),
            join_pk_new: None,
            auth: EnvAuth::AdminSig([0; 64]),
        }
    }

    fn mls_message(group: &[u8; 32], epoch: u64, content: u8, aad: &[u8]) -> Vec<u8> {
        let mut out = vec![0, 1, 0, 2, 32];
        out.extend_from_slice(group);
        out.extend_from_slice(&epoch.to_be_bytes());
        out.push(content);
        let len = u16::try_from(aad.len()).expect("test: short aad");
        if len < 64 {
            out.push(u8::try_from(len).expect("test: one byte length"));
        } else {
            out.extend_from_slice(&(0x4000 | len).to_be_bytes());
        }
        out.extend_from_slice(aad);
        out.extend_from_slice(&[0, 0]);
        out
    }

    #[test]
    fn outer_header_checks_group_epoch_and_content_type() {
        let commit = header(EnvKind::Commit, 3);
        let good = mls_message(&GID, 3, 3, b"");
        assert!(check_outer_header(&commit, &good).is_ok(), "a matching commit must pass");
        for (name, bytes) in [
            ("other group", mls_message(&[8; 32], 3, 3, b"")),
            ("other epoch", mls_message(&GID, 4, 3, b"")),
            ("application content in a commit entry", mls_message(&GID, 3, 1, b"")),
            ("proposal content in a commit entry", mls_message(&GID, 3, 2, b"")),
        ] {
            assert_eq!(
                check_outer_header(&commit, &bytes),
                Err(LgRefusal::HeaderMismatch),
                "{name} must be a header mismatch"
            );
        }
        let post = header(EnvKind::Post, 3);
        assert!(
            check_outer_header(&post, &mls_message(&GID, 3, 1, b"")).is_ok(),
            "a post carries application content"
        );
        assert_eq!(
            check_outer_header(&header(EnvKind::Void, 3), &[]),
            Ok(None),
            "a void carries no MLS content"
        );
        assert_eq!(
            check_outer_header(&commit, &good[..10]),
            Err(LgRefusal::HeaderMismatch),
            "a truncated header must be refused"
        );
    }

    #[test]
    fn epoch_rule_is_exact_for_commits_and_windowed_for_application() {
        assert_eq!(epoch_rule(EnvKind::Commit, 5, 5), Ok(()), "commit at head");
        assert_eq!(
            epoch_rule(EnvKind::Commit, 4, 5),
            Err(LgRefusal::Stale { epoch: 5 }),
            "commit behind head"
        );
        assert_eq!(
            epoch_rule(EnvKind::Proposal, 6, 5),
            Err(LgRefusal::Stale { epoch: 5 }),
            "proposal ahead of head"
        );
        assert_eq!(epoch_rule(EnvKind::Post, 2, 5), Ok(()), "head - 3 is inside the window");
        assert_eq!(
            epoch_rule(EnvKind::Post, 1, 5),
            Err(LgRefusal::Stale { epoch: 5 }),
            "head - 4 is outside the window"
        );
        assert_eq!(epoch_rule(EnvKind::Tombstone, 6, 5), Err(LgRefusal::Stale { epoch: 5 }));
        assert_eq!(epoch_rule(EnvKind::Post, 0, 1), Ok(()), "the window floors at zero");
    }

    #[test]
    fn commit_aad_must_equal_the_header_aad() {
        let commit = header(EnvKind::Commit, 3);
        let aad = commit.aad_bytes();
        let message = mls_message(&GID, 3, 3, &aad);
        assert!(check_outer_header(&commit, &message).is_ok(), "test: header parses");
        assert_eq!(check_commit_aad(&commit, &message), Ok(()), "equal AAD passes");
        let mut other = commit.clone();
        other.epoch = 9;
        assert_eq!(
            check_commit_aad(&other, &message),
            Err(LgRefusal::HeaderMismatch),
            "an AAD of another header must be refused"
        );
        let mut with_refs = commit.clone();
        with_refs.blob_ref = Some([1; 32]);
        with_refs.welcome_ref = Some([2; 32]);
        assert_eq!(
            check_commit_aad(&with_refs, &message),
            Ok(()),
            "blob_ref and welcome_ref are outside the AAD"
        );
    }

    #[test]
    fn pacing_and_the_daily_cap() {
        assert_eq!(check_pacing(1_000, 0, 60_000, &[], 10), Ok(()), "first commit is free");
        assert_eq!(
            check_pacing(40_000, 10_000, 60_000, &[10_000], 10),
            Err(LgRefusal::Paced { retry_at_ms: 70_000 }),
            "a member commit within 60 s is paced"
        );
        assert_eq!(check_pacing(16_000, 10_000, 5_000, &[10_000], 10), Ok(()), "admin gap 5 s");
        let ring = [100_u64, 200_000, 300_000];
        assert_eq!(
            check_pacing(400_000, 300_000, 5_000, &ring, 3),
            Err(LgRefusal::Paced { retry_at_ms: 100 + DAY_MS }),
            "the cap holds until the oldest commit is 24 h old"
        );
        assert_eq!(
            check_pacing(DAY_MS + 1_000, 300_000, 5_000, &ring, 3),
            Ok(()),
            "a commit older than 24 h leaves the window"
        );
        assert!(check_pacing(1_000, 0, 5_000, &[], 0).is_err(), "cap 0 refuses every commit");
    }

    #[test]
    fn join_tie_and_bucket() {
        assert_eq!(join_tie(&[Some(QUEUE_MEMBER), Some(QUEUE_OUTSIDER)], false, false), Ok((1, 1)));
        assert_eq!(
            join_tie(&[Some(QUEUE_MEMBER), None], false, false),
            Err(LgRefusal::CommitBadAdds),
            "an add without a pending join is refused"
        );
        assert_eq!(
            join_tie(&[Some(QUEUE_OUTSIDER)], true, false),
            Err(LgRefusal::CommitBadAdds),
            "approval ON: an invite join needs an admin commit"
        );
        assert_eq!(join_tie(&[Some(QUEUE_OUTSIDER)], true, true), Ok((0, 1)), "admin commit");
        assert_eq!(join_tie(&[Some(QUEUE_MEMBER)], true, false), Ok((1, 0)), "own_device is free");
        let mut bucket = JoinBucket::new(0);
        assert!((0..10).all(|_| bucket.take(0)), "burst of 10");
        assert!(!bucket.take(0), "the eleventh at once is refused");
        assert!(!bucket.take(999), "not yet refilled");
        assert!(bucket.take(1_999), "one second refills one request");
    }

    /// A key-value backend that keeps nothing: enough to mint a `KeyPackage`.
    struct NullKv;

    impl ramflux_mls::MlsKv for NullKv {
        type Tx<'a> = ();

        fn get(
            &self,
            _label: &str,
            _key: &[u8],
        ) -> Result<Option<zeroize::Zeroizing<Vec<u8>>>, ramflux_mls::MlsKvError> {
            Ok(None)
        }

        fn row_stats(&self) -> Result<ramflux_mls::RowStats, ramflux_mls::MlsKvError> {
            Ok(ramflux_mls::RowStats::default())
        }

        fn commit_batch<F>(
            &self,
            _batch: ramflux_mls::WriteBatch,
            _caller: F,
        ) -> Result<(), ramflux_mls::MlsKvError>
        where
            F: for<'a> FnOnce(&mut Self::Tx<'a>) -> Result<(), ramflux_mls::MlsKvError>
                + Send
                + 'static,
        {
            Ok(())
        }
    }

    #[test]
    fn key_package_pseudonym_is_read_from_the_wrapped_leaf() {
        let crypto = ramflux_mls::CryptoHandle::init().expect("test: crypto probe");
        let mls = ramflux_mls::Mls::new(NullKv, crypto);
        let minted = mls
            .key_package(ramflux_mls::GroupKind::Group)
            .expect("test: key package")
            .commit_plain()
            .expect("test: staged key package");
        assert_eq!(
            minted.bytes.get(..4),
            Some(&[0_u8, 1, 0, 5][..]),
            "ramflux-mls emits the MLSMessage form (version, wire format 5)"
        );
        assert_eq!(
            key_package_signature_key(&minted.bytes),
            Ok(minted.leaf_sig_pk),
            "P is the leaf signature key of the wrapped KeyPackage"
        );
        assert_eq!(
            key_package_signature_key(&minted.bytes[4..]),
            Err(LgRefusal::BadRequest),
            "the unwrapped form is not accepted"
        );
        assert_eq!(
            key_package_signature_key(&minted.bytes[..minted.bytes.len() - 1]),
            Err(LgRefusal::BadRequest),
            "a truncated message is refused"
        );
        let mut other_suite = minted.bytes.clone();
        other_suite[7] = 2;
        assert_eq!(
            key_package_signature_key(&other_suite),
            Err(LgRefusal::BadRequest),
            "another suite is refused"
        );
    }

    #[test]
    fn retention_cut_offs() {
        assert!(!entry_expired(0, RETAIN_MS), "exactly 30 d is kept");
        assert!(entry_expired(0, RETAIN_MS + 1), "past 30 d goes");
        assert!(!join_expired(0, JOIN_TTL_MS - 1) && join_expired(0, JOIN_TTL_MS), "24 h joins");
        assert!(join_row_live(0, JOIN_TTL_MS - 1), "a row younger than 24 h satisfies the tie");
        assert!(!join_row_live(0, JOIN_TTL_MS), "a row 24 h old does not");
        assert!(!blob_orphaned(0, true, BLOB_ORPHAN_MS) && blob_orphaned(0, false, BLOB_ORPHAN_MS));
        assert!(!welcome_expired(0, 0, WELCOME_TTL_MS - 1), "an unfetched Welcome lives 7 d");
        assert!(welcome_expired(0, 0, WELCOME_TTL_MS), "and goes after 7 d");
        assert!(welcome_expired(0, 1_000, 1_000 + WELCOME_DRAINED_GRACE_MS), "fetched: grace");
        assert!(!route_expired(10, 17) && route_expired(10, 18), "registered_day + 8 <= today");
    }

    #[test]
    fn attachment_pool_and_retention_edges() {
        let mib = 1024 * 1024;
        assert!(
            attach_pool_fits(0, ATTACH_PENDING_GROUP_BYTES),
            "the whole pool fits an empty group"
        );
        assert!(attach_pool_fits(112 * mib, 16 * mib), "112 + 16 MiB is the edge");
        assert!(!attach_pool_fits(112 * mib + 1, 16 * mib), "one byte over the pool");
        assert!(!attach_pool_fits(u64::MAX, 1), "no overflow");
        assert!(!attach_expired(10, 40), "30 days after completion it is still kept");
        assert!(attach_expired(10, 41), "completed_day + 31 is gone");
        assert!(!attach_expired(u64::MAX, 0), "no overflow");
    }

    #[test]
    fn eviction_goes_oldest_first_until_the_store_fits() {
        assert_eq!(evict_until(10, 10, &[5, 5]), 0, "at the cap nothing goes");
        assert_eq!(evict_until(11, 10, &[5, 5]), 1, "one eviction is enough");
        assert_eq!(evict_until(20, 10, &[5, 4, 3]), 3, "evicts while still over");
        assert_eq!(evict_until(20, 10, &[5, 5, 5]), 2, "stops once it fits");
        assert_eq!(evict_until(20, 0, &[]), 0, "nothing to evict");
    }
}
