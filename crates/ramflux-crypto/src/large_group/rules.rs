// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Pure rules of design v7 sections 2.3 and 2.4 that clients (and, for the ledger, the host)
//! apply: settling delay and late warnings (R3-H1), epoch-roll acceptance (H1), `appended_at`
//! checks (R3-L1), the provisional joiner key (R3-M1) and the redelivery limits (R3-L2).
//! Times are milliseconds on the caller's clock (the debug clock in real runs).

use super::{EpochKey, LgError};

/// `A + 180 s`: the common opening of an epoch.
pub const SETTLE_ROLL_DELAY_MS: u64 = 180_000;
/// `r + 30 s`: a batch's own settling after its reply.
pub const SETTLE_REPLY_DELAY_MS: u64 = 30_000;
/// Clock-skew allowance [assumption; P3 records skew].
pub const SKEW_MS: u64 = 30_000;
/// Upper bound of the per-client per-epoch uniform draw `U(0, 60 s)`.
pub const ROLL_U_MAX_MS: u64 = 60_000;
const MIN_LEAVE_ROLL_GAP_MS: u64 = 10 * 60_000;
const HOUR_MS: u64 = 60 * 60_000;
const DAY_MS: u64 = 24 * HOUR_MS;
const DAILY_MIN_GAP_MS: u64 = 23 * HOUR_MS;
const MAX_REVOKE_PER_HOUR: usize = 6;
const MAX_SPENT_FULL_PER_DAY: usize = 2;
const PROVISIONAL_TIMEOUT_MS: u64 = 120_000;
const MAX_CANDIDATES: usize = 8;
const COUNTED_REDELIVERIES: usize = 3;
const REDELIVERIES_PER_DAY: usize = 10;
const SLOT_BAD_GAP_MS: u64 = 60_000;
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
    LeaveRollTooSoon,
    RevokeCapPerHour,
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
                if candidate.kind == RollKind::RevokeLeave
                    && last_revoke.is_some_and(|t| now.saturating_sub(t) < MIN_LEAVE_ROLL_GAP_MS)
                {
                    return Err(RollRefusal::LeaveRollTooSoon);
                }
                let in_hour = self
                    .accepted
                    .iter()
                    .filter(|r| r.kind.is_revoke() && now.saturating_sub(r.started_at_ms) < HOUR_MS)
                    .count();
                if in_hour >= MAX_REVOKE_PER_HOUR {
                    return Err(RollRefusal::RevokeCapPerHour);
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

/// State of an OFF joiner's key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProvisionalState {
    /// Welcomer key held, no posting ("Verifying group key").
    Provisional,
    /// Two slots from distinct writers agree, or an admin entry decrypted: may post.
    Confirmed,
    /// Failed AEAD or timed out: key dropped, `slot_bad` to send.
    Dropped,
}

/// R3-M1: the OFF joiner's provisional `K_{e+1}`.
pub struct ProvisionalKey {
    since_ms: u64,
    state: ProvisionalState,
    candidates: Vec<([u8; 32], EpochKey)>,
    confirmed: Option<usize>,
}

impl ProvisionalKey {
    /// Starts provisional with the welcomer's slot key.
    #[must_use]
    pub fn new(welcomer: [u8; 32], key: EpochKey, now_ms: u64) -> Self {
        Self {
            since_ms: now_ms,
            state: ProvisionalState::Provisional,
            candidates: vec![(welcomer, key)],
            confirmed: None,
        }
    }

    #[must_use]
    pub const fn state(&self) -> ProvisionalState {
        self.state
    }

    /// Posting is allowed only under a confirmed key; a dropped value is never used.
    #[must_use]
    pub fn confirmed_key(&self) -> Option<&EpochKey> {
        self.confirmed.and_then(|index| self.candidates.get(index)).map(|(_, key)| key)
    }

    /// An `e+1` entry other than the welcomer's `W'` failed AEAD under the held key, so drop it
    /// and send `slot_bad`. Returns whether a `slot_bad` is due.
    pub fn entry_failed_aead(&mut self) -> bool {
        if self.state == ProvisionalState::Provisional {
            self.state = ProvisionalState::Dropped;
            return true;
        }
        false
    }

    /// 2 min without confirmation drops the key; returns whether a `slot_bad` is due.
    pub fn tick(&mut self, now_ms: u64) -> bool {
        if self.state == ProvisionalState::Provisional
            && now_ms.saturating_sub(self.since_ms) >= PROVISIONAL_TIMEOUT_MS
        {
            self.state = ProvisionalState::Dropped;
            return true;
        }
        false
    }

    /// Another writer's slot (typically the `W'_redeliver` a `slot_bad` triggered). The key is
    /// confirmed when two slots from distinct writers agree.
    pub fn offer_slot(&mut self, writer: [u8; 32], key: EpochKey) -> ProvisionalState {
        if self.confirmed.is_none() && self.candidates.len() < MAX_CANDIDATES {
            let agreeing = self
                .candidates
                .iter()
                .position(|(other, existing)| *other != writer && existing.same_as(&key));
            self.candidates.push((writer, key));
            if let Some(index) = agreeing {
                self.confirmed = Some(index);
                self.state = ProvisionalState::Confirmed;
            }
        }
        self.state
    }

    /// An admin-`P`-signed entry (admin chaining to the genesis owner) decrypted under candidate
    /// `index` confirms that candidate.
    pub fn admin_entry_decrypted(&mut self, candidate_index: usize) -> ProvisionalState {
        if self.confirmed.is_none() && candidate_index < self.candidates.len() {
            self.confirmed = Some(candidate_index);
            self.state = ProvisionalState::Confirmed;
        }
        self.state
    }

    /// Candidate keys by index (to test an admin entry against each).
    #[must_use]
    pub fn candidate(&self, index: usize) -> Option<&EpochKey> {
        self.candidates.get(index).map(|(_, key)| key)
    }
}

/// Host decision on a `W'_redeliver`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedeliveryDecision {
    Accept,
    /// 3 counted redeliveries reached.
    RefuseCounted,
    /// 10 per joiner per 24 h reached: the UI offers rejoin with a fresh `P`.
    RefuseCeilingOfferRejoin,
}

#[derive(Debug, Clone, Copy)]
struct Redelivery {
    at_ms: u64,
    seq: u64,
    referenced: bool,
}

/// Host-side per-joiner ledger (R2-L6, R3-L2).
#[derive(Debug, Default)]
pub struct RedeliveryLedger {
    records: Vec<Redelivery>,
    last_slot_bad_ms: Option<u64>,
}

impl RedeliveryLedger {
    #[must_use]
    pub const fn new() -> Self {
        Self { records: Vec::new(), last_slot_bad_ms: None }
    }

    /// Decides a redelivery and records it (as log entry `seq`) when accepted.
    pub fn decide_redelivery(&mut self, now_ms: u64, seq: u64) -> RedeliveryDecision {
        let in_day =
            self.records.iter().filter(|r| now_ms.saturating_sub(r.at_ms) < DAY_MS).count();
        if in_day >= REDELIVERIES_PER_DAY {
            return RedeliveryDecision::RefuseCeilingOfferRejoin;
        }
        let counted = self.records.iter().filter(|r| !r.referenced).count();
        if counted >= COUNTED_REDELIVERIES {
            return RedeliveryDecision::RefuseCounted;
        }
        self.records.push(Redelivery { at_ms: now_ms, seq, referenced: false });
        if self.records.len() > MAX_LEDGER_RECORDS {
            self.records.remove(0);
        }
        RedeliveryDecision::Accept
    }

    /// `slot_bad {bad_seq}` from the joiner: at most one per minute; marks the referenced
    /// redelivery as not counted. Returns whether the host accepts the message.
    ///
    /// # Errors
    /// Returns [`LgError::Verify`] when more than one `slot_bad` per minute arrives.
    pub fn accept_slot_bad(&mut self, now_ms: u64, bad_seq: u64) -> Result<(), LgError> {
        if self.last_slot_bad_ms.is_some_and(|t| now_ms.saturating_sub(t) < SLOT_BAD_GAP_MS) {
            return Err(LgError::Verify("slot_bad rate limited"));
        }
        self.last_slot_bad_ms = Some(now_ms);
        for record in &mut self.records {
            if record.seq == bad_seq {
                record.referenced = true;
            }
        }
        Ok(())
    }
}
