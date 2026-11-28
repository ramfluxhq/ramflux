// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Pure rules of MLS-SPEC r1.1 section 2 that the host and the clients apply: settling delay and
//! late warnings (R3-H1, O7), token-epoch roll acceptance (H1), `appended_at` checks (R3-L1), commit
//! pacing limits and the commit election order (`rf-lg-elect-v1`, windows of 3 every 60 s).
//! Times are milliseconds on the caller's clock (the debug clock in real runs).

use ramflux_protocol::domain::LG_ELECT_V1;

use super::LgError;
use super::codec::Enc;
use super::ids::LEAF_CAP;

/// `A + 180 s`: the common opening of an epoch.
pub const SETTLE_ROLL_DELAY_MS: u64 = 180_000;
/// `r + 30 s`: a batch's own settling after its reply.
pub const SETTLE_REPLY_DELAY_MS: u64 = 30_000;
/// Clock-skew allowance [assumption; P3 records skew].
pub const SKEW_MS: u64 = 30_000;
/// Upper bound of the per-client per-epoch uniform draw `U(0, 60 s)`.
pub const ROLL_U_MAX_MS: u64 = 60_000;
/// Revoke rolls (admin removals and leaves) are at least this far apart: at most 48 a day.
pub const REVOKE_ROLL_GAP_MS: u64 = 30 * 60_000;
const HOUR_MS: u64 = 60 * 60_000;
const DAY_MS: u64 = 24 * HOUR_MS;
const DAILY_MIN_GAP_MS: u64 = 23 * HOUR_MS;
const MAX_SPENT_FULL_PER_DAY: usize = 2;
const MAX_LEDGER_RECORDS: usize = 64;

/// A token of epoch `te` is spent at `max(r + 30 s, A + 180 s + U(0, 60 s))`.
#[must_use]
pub fn settle_at_ms(reply_received_ms: u64, roll_appended_at_ms: u64, u_ms: u64) -> u64 {
    let own = reply_received_ms.saturating_add(SETTLE_REPLY_DELAY_MS);
    let common = roll_appended_at_ms
        .saturating_add(SETTLE_ROLL_DELAY_MS)
        .saturating_add(u_ms.min(ROLL_U_MAX_MS));
    own.max(common)
}

/// The roll entry arrived later than `A + 30 s`: "group host is behaving unusually".
#[must_use]
pub const fn late_roll(roll_appended_at_ms: u64, received_ms: u64) -> bool {
    received_ms > roll_appended_at_ms.saturating_add(SKEW_MS)
}

/// A batch reply arrived later than `A + 180 s`: same warning.
#[must_use]
pub const fn late_reply(roll_appended_at_ms: u64, received_ms: u64) -> bool {
    received_ms > roll_appended_at_ms.saturating_add(SETTLE_ROLL_DELAY_MS)
}

/// `appended_at` must be non-decreasing in `log_seq` and at most local receipt + 30 s.
#[must_use]
pub fn appended_at_ok(previous_ms: Option<u64>, this_ms: u64, receipt_ms: u64) -> bool {
    previous_ms.is_none_or(|prev| this_ms >= prev) && this_ms <= receipt_ms.saturating_add(SKEW_MS)
}

/// Reason of a `token_epoch` entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RollKind {
    RevokeAdmin,
    RevokeLeave,
    Daily,
    SpentFull,
}

impl RollKind {
    const fn is_revoke(self) -> bool {
        matches!(self, Self::RevokeAdmin | Self::RevokeLeave)
    }

    /// Wire code.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::RevokeAdmin => 1,
            Self::RevokeLeave => 2,
            Self::Daily => 3,
            Self::SpentFull => 4,
        }
    }

    /// # Errors
    /// Refuses an unknown code.
    pub fn from_code(code: u8) -> Result<Self, LgError> {
        match code {
            1 => Ok(Self::RevokeAdmin),
            2 => Ok(Self::RevokeLeave),
            3 => Ok(Self::Daily),
            4 => Ok(Self::SpentFull),
            _ => Err(LgError::Format("roll kind")),
        }
    }
}

/// One accepted or candidate roll.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RollRecord {
    pub kind: RollKind,
    pub started_at_ms: u64,
    /// Every `ref_seqs` entry is a valid removal/ban/leave (leavers >= 24 h old), checked by the
    /// caller against the log.
    pub refs_valid: bool,
}

/// Why a roll fails its rule ("the group host is behaving unusually"; no refill).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RollRefusal {
    BadReferences,
    /// A revoke roll less than 30 minutes after the previous one.
    RevokeTooSoon,
    DailyTooSoon,
    SpentFullCapPerDay,
}

/// Client-side history of accepted rolls for the roll table.
#[derive(Debug, Default)]
pub struct RollWindow {
    accepted: Vec<RollRecord>,
}

impl RollWindow {
    #[must_use]
    pub const fn new() -> Self {
        Self { accepted: Vec::new() }
    }

    /// Accepted rolls (client-state export).
    #[must_use]
    pub fn records(&self) -> &[RollRecord] {
        &self.accepted
    }

    /// Restores a window from [`Self::records`].
    #[must_use]
    pub const fn from_records(accepted: Vec<RollRecord>) -> Self {
        Self { accepted }
    }

    /// Checks `candidate` against the roll table and records it when it passes.
    ///
    /// # Errors
    /// Returns the refusal; the caller shows the host warning and does not refill for that epoch.
    pub fn accept(&mut self, candidate: RollRecord) -> Result<(), RollRefusal> {
        let now = candidate.started_at_ms;
        if candidate.kind.is_revoke() && !candidate.refs_valid {
            return Err(RollRefusal::BadReferences);
        }
        match candidate.kind {
            RollKind::RevokeAdmin | RollKind::RevokeLeave => {
                let last_revoke = self
                    .accepted
                    .iter()
                    .filter(|r| r.kind.is_revoke())
                    .map(|r| r.started_at_ms)
                    .max();
                if last_revoke.is_some_and(|t| now.saturating_sub(t) < REVOKE_ROLL_GAP_MS) {
                    return Err(RollRefusal::RevokeTooSoon);
                }
            }
            RollKind::Daily => {
                let last = self
                    .accepted
                    .iter()
                    .filter(|r| matches!(r.kind, RollKind::Daily | RollKind::SpentFull))
                    .map(|r| r.started_at_ms)
                    .max();
                if last.is_some_and(|t| now.saturating_sub(t) < DAILY_MIN_GAP_MS) {
                    return Err(RollRefusal::DailyTooSoon);
                }
            }
            RollKind::SpentFull => {
                let in_day = self
                    .accepted
                    .iter()
                    .filter(|r| {
                        r.kind == RollKind::SpentFull
                            && now.saturating_sub(r.started_at_ms) < DAY_MS
                    })
                    .count();
                if in_day >= MAX_SPENT_FULL_PER_DAY {
                    return Err(RollRefusal::SpentFullCapPerDay);
                }
            }
        }
        self.accepted.push(candidate);
        if self.accepted.len() > 4 * MAX_LEDGER_RECORDS {
            let drop = self.accepted.len() - 2 * MAX_LEDGER_RECORDS;
            self.accepted.drain(..drop);
        }
        Ok(())
    }
}

/// Groups with fewer leaves than this skip the token privacy delay (O7).
pub const PRIVACY_DELAY_MIN_LEAVES: u32 = 50;
/// Member commits are at least this far apart (spec 2.3 check 5).
pub const MEMBER_COMMIT_GAP_MS: u64 = 60_000;
/// Admin commits are at least this far apart.
pub const ADMIN_COMMIT_GAP_MS: u64 = 5_000;
/// Adds in one commit (spec 2.7).
pub const MAX_ADDS_PER_COMMIT: usize = 100;
/// Election candidates tried per window (spec 2.4).
pub const ELECT_WINDOW_SIZE: usize = 3;
/// Election window length; not shorter than the member pacing (L5).
pub const ELECT_WINDOW_MS: u64 = 60_000;

/// Whether the token privacy delay applies to a group whose tree has `leaf_count` leaves.
#[must_use]
pub const fn privacy_delay_applies(leaf_count: u32) -> bool {
    leaf_count >= PRIVACY_DELAY_MIN_LEAVES
}

/// A member device that may commit pending joins.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ElectCandidate {
    pub leaf: u32,
    pub admin: bool,
}

/// `rank = BLAKE3("rf-lg-elect-v1" ‖ group_id ‖ I2OSP(epoch, 8) ‖ I2OSP(leaf, 4))`.
#[must_use]
pub fn election_rank(group_id: &[u8; 32], epoch: u64, leaf: u32) -> [u8; 32] {
    let mut enc = Enc::new(LG_ELECT_V1.as_bytes());
    enc.fixed(group_id).u64(epoch).u32(leaf);
    *blake3::hash(&enc.finish()).as_bytes()
}

/// Election order: admins first, then ascending [`election_rank`]; ties break by leaf index.
///
/// # Errors
/// Refuses more candidates than the leaf cap.
pub fn election_order(
    group_id: &[u8; 32],
    epoch: u64,
    candidates: &[ElectCandidate],
) -> Result<Vec<ElectCandidate>, LgError> {
    if candidates.len() > usize::try_from(LEAF_CAP).unwrap_or(usize::MAX) {
        return Err(LgError::Format("election candidates"));
    }
    let mut ranked: Vec<(bool, [u8; 32], ElectCandidate)> =
        candidates.iter().map(|c| (!c.admin, election_rank(group_id, epoch, c.leaf), *c)).collect();
    ranked.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)).then(a.2.leaf.cmp(&b.2.leaf)));
    Ok(ranked.into_iter().map(|(_, _, c)| c).collect())
}

/// Milliseconds after the commit became possible at which the candidate at `position` in
/// [`election_order`] may commit (windows of [`ELECT_WINDOW_SIZE`] every [`ELECT_WINDOW_MS`]).
#[must_use]
pub fn election_delay_ms(position: usize) -> u64 {
    let window = u64::try_from(position / ELECT_WINDOW_SIZE).unwrap_or(u64::MAX);
    window.saturating_mul(ELECT_WINDOW_MS)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn revoke(kind: RollKind, at: u64) -> RollRecord {
        RollRecord { kind, started_at_ms: at, refs_valid: true }
    }

    #[test]
    fn revoke_rolls_are_thirty_minutes_apart() {
        let mut window = RollWindow::new();
        assert_eq!(window.accept(revoke(RollKind::RevokeAdmin, 1_000)), Ok(()), "the first");
        assert_eq!(
            window.accept(revoke(RollKind::RevokeLeave, 1_000 + REVOKE_ROLL_GAP_MS - 1)),
            Err(RollRefusal::RevokeTooSoon),
            "a leave roll 30 min minus 1 ms later is refused"
        );
        assert_eq!(
            window.accept(revoke(RollKind::RevokeAdmin, 1_000 + REVOKE_ROLL_GAP_MS)),
            Ok(()),
            "exactly 30 min later passes"
        );
        let mut now = 1_000 + REVOKE_ROLL_GAP_MS;
        let mut accepted = 2_u32;
        for _ in 0..100 {
            now += REVOKE_ROLL_GAP_MS;
            if now >= 1_000 + DAY_MS {
                break;
            }
            window.accept(revoke(RollKind::RevokeAdmin, now)).expect("test: spaced roll passes");
            accepted += 1;
        }
        assert!(accepted <= 48, "at most 48 revoke rolls in a day, got {accepted}");
    }

    #[test]
    fn revoke_gap_does_not_touch_daily_and_spent_full() {
        let mut window = RollWindow::new();
        window.accept(revoke(RollKind::RevokeAdmin, 0)).expect("test: revoke");
        assert_eq!(window.accept(revoke(RollKind::Daily, 1)), Ok(()), "daily ignores revokes");
        assert_eq!(
            window.accept(revoke(RollKind::Daily, 2)),
            Err(RollRefusal::DailyTooSoon),
            "daily still needs 23 h"
        );
        assert_eq!(window.accept(revoke(RollKind::SpentFull, 3)), Ok(()), "spent_full one");
        assert_eq!(window.accept(revoke(RollKind::SpentFull, 4)), Ok(()), "spent_full two");
        assert_eq!(
            window.accept(revoke(RollKind::SpentFull, 5)),
            Err(RollRefusal::SpentFullCapPerDay),
            "spent_full is capped at 2 a day"
        );
        let mut bad = revoke(RollKind::RevokeLeave, 10 * DAY_MS);
        bad.refs_valid = false;
        assert_eq!(window.accept(bad), Err(RollRefusal::BadReferences), "bad references");
    }
}
