// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! The pure rules of the group host (MLS-SPEC r1.1 2.3 to 2.6): outer MLS header checks, the epoch
//! rule, commit authenticated data, pacing and the commit cap `C`, the join tie and the join
//! bucket, KeyPackage pseudonym extraction and the retention cut-offs. Nothing here touches a
//! table or a clock: `now` is always an argument, and no rule decides validity of MLS content by
//! time (rule V); time feeds only pacing, quotas and retention.

use ramflux_crypto::large_group::{EnvHeader, EnvKind, MlsContent};

use super::refusal::{LgRefusal, LgResult};
use crate::mls_header::{MlsContentType, MlsOuterHeader, parse_outer_header};

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

/// Reads one RFC 9420 variable-length integer at `*pos`; the 1, 2 and 4 byte forms.
fn read_varint(data: &[u8], pos: &mut usize) -> Option<usize> {
    let first = *data.get(*pos)?;
    let width = match first >> 6 {
        0 => 1,
        1 => 2,
        2 => 4,
        _ => return None,
    };
    let bytes = data.get(*pos..pos.checked_add(width)?)?;
    let mut value = usize::from(first & 0x3f);
    for byte in bytes.iter().skip(1) {
        value = (value << 8) | usize::from(*byte);
    }
    *pos += width;
    Some(value)
}

/// The cleartext `authenticated_data` of a `PrivateMessage` that [`check_outer_header`] parsed
/// (it follows the content type).
///
/// # Errors
/// [`LgRefusal::HeaderMismatch`] when the field is missing or runs past the message.
pub fn authenticated_data<'a>(mls: &'a [u8], outer: &MlsOuterHeader) -> LgResult<&'a [u8]> {
    let mismatch = || LgRefusal::HeaderMismatch;
    // version (2) + wire format (2), then the group id length prefix as the parser read it.
    let mut pos = 4_usize;
    let prefix = read_varint(mls, &mut pos).ok_or_else(mismatch)?;
    if prefix != outer.group_id.len() {
        return Err(mismatch());
    }
    // group id bytes, epoch (8), content type (1)
    pos = pos
        .checked_add(prefix)
        .and_then(|at| at.checked_add(9))
        .ok_or_else(mismatch)?;
    let len = read_varint(mls, &mut pos).ok_or_else(mismatch)?;
    let end = pos.checked_add(len).ok_or_else(mismatch)?;
    mls.get(pos..end).ok_or_else(mismatch)
}

/// Spec 2.3 check 5a: the commit's `authenticated_data` is `rf-lg-aad-v1 ‖ canonical header
/// without token and blob_ref`, which must equal the envelope header's own AAD bytes.
///
/// # Errors
/// [`LgRefusal::HeaderMismatch`].
pub fn check_commit_aad(header: &EnvHeader, mls: &[u8], outer: &MlsOuterHeader) -> LgResult<()> {
    if authenticated_data(mls, outer)? == header.aad_bytes().as_slice() {
        Ok(())
    } else {
        Err(LgRefusal::HeaderMismatch)
    }
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
        let refilled = self
            .milli
            .saturating_add(now.saturating_sub(self.last_ms))
            .min(JOIN_BURST_MILLI);
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

/// The leaf signature key of a serialized KeyPackage: `protocol_version (2) ‖ cipher_suite (2) ‖
/// init_key<V> ‖ LeafNode{encryption_key<V> ‖ signature_key<V> …}`. The host needs the pseudonym
/// `P` to tie a join request to an `added_P` without reading the roster.
///
/// # Errors
/// [`LgRefusal::BadRequest`] when the bytes are not an Ed25519 KeyPackage prefix.
pub fn key_package_signature_key(key_package: &[u8]) -> LgResult<[u8; 32]> {
    let bad = || LgRefusal::BadRequest;
    let mut pos = 4_usize;
    for _ in 0..2 {
        let len = read_varint(key_package, &mut pos).ok_or_else(bad)?;
        pos = pos.checked_add(len).ok_or_else(bad)?;
    }
    let len = read_varint(key_package, &mut pos).ok_or_else(bad)?;
    if len != 32 {
        return Err(bad());
    }
    let end = pos.checked_add(32).ok_or_else(bad)?;
    key_package.get(pos..end).and_then(|bytes| bytes.try_into().ok()).ok_or_else(bad)
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
        let outer = check_outer_header(&commit, &message)
            .expect("test: header parses")
            .expect("test: commit has MLS content");
        assert_eq!(check_commit_aad(&commit, &message, &outer), Ok(()), "equal AAD passes");
        let mut other = commit.clone();
        other.epoch = 9;
        assert_eq!(
            check_commit_aad(&other, &message, &outer),
            Err(LgRefusal::HeaderMismatch),
            "an AAD of another header must be refused"
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

    #[test]
    fn key_package_pseudonym_is_read_from_the_leaf() {
        let mut kp = vec![0, 1, 0, 1, 3, 9, 9, 9, 2, 5, 5, 32];
        kp.extend_from_slice(&[0xAB; 32]);
        kp.extend_from_slice(&[1, 2, 3]);
        assert_eq!(key_package_signature_key(&kp), Ok([0xAB; 32]), "signature key at the leaf");
        assert_eq!(
            key_package_signature_key(&kp[..20]),
            Err(LgRefusal::BadRequest),
            "a truncated KeyPackage is refused"
        );
        kp[11] = 31;
        assert_eq!(key_package_signature_key(&kp), Err(LgRefusal::BadRequest), "not 32 bytes");
    }

    #[test]
    fn retention_cut_offs() {
        assert!(!entry_expired(0, RETAIN_MS), "exactly 30 d is kept");
        assert!(entry_expired(0, RETAIN_MS + 1), "past 30 d goes");
        assert!(!join_expired(0, JOIN_TTL_MS - 1) && join_expired(0, JOIN_TTL_MS), "24 h joins");
        assert!(!blob_orphaned(0, true, BLOB_ORPHAN_MS) && blob_orphaned(0, false, BLOB_ORPHAN_MS));
        assert!(!welcome_expired(0, 0, WELCOME_TTL_MS - 1), "an unfetched Welcome lives 7 d");
        assert!(welcome_expired(0, 0, WELCOME_TTL_MS), "and goes after 7 d");
        assert!(welcome_expired(0, 1_000, 1_000 + WELCOME_DRAINED_GRACE_MS), "fetched: grace");
        assert!(!route_expired(10, 17) && route_expired(10, 18), "registered_day + 8 <= today");
    }
}
