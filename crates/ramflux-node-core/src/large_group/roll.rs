// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Token epoch rolls written by the host (LARGE-GROUP-01 2.3, MLS-SPEC r1.2 2.6; from 6ed
//! `entries.rs`): `daily` after 24 h, `spent_full` at 1 M spent tokens, and `revoke` after admin
//! removals and leaves, all under the roll caps of `ramflux_crypto::large_group` (`RollWindow`):
//! revoke rolls are at least 30 minutes apart, and one revoke roll lists every removal and leave
//! held at that time. A leave alone still waits its 10 minute window. A roll is a host-signed
//! `roll` entry; the old epoch's spent set is dropped two epochs later.

use ramflux_crypto::large_group::{
    EnvAuth, EnvHeader, EnvKind, REVOKE_ROLL_GAP_MS, RollKind, RollPayload, RollRecord, RollWindow,
    TAG_SLOTS, random_array,
};

use super::check::DAY_MS;
use super::host::{Cx, LargeGroupHost};
use super::refusal::{LgRefusal, LgResult};
use super::rows::{HELD_REFS_MAX, HeadRow, key};
use crate::RouterRedbStore;
use crate::router_store::lg_store::LgTable;

const SPENT_FULL: u64 = 1_000_000;
/// A leave opens a 10 minute window; one roll lists every leave of the window.
const LEAVE_COALESCE_MS: u64 = 10 * 60 * 1_000;
/// Rolls kept in the head row for the roll caps.
const ROLL_RECORDS_KEPT: usize = 64;
const SPENT_DELETE_BATCH: usize = 4_096;

/// A host-written entry header (`roll`).
pub(super) fn host_header(
    gid: &[u8; 32],
    kind: EnvKind,
    epoch: u64,
) -> Result<EnvHeader, ramflux_crypto::large_group::LgError> {
    Ok(EnvHeader {
        group_id: *gid,
        kind,
        epoch,
        post_id: random_array::<16>()?,
        bucket: None,
        tags: [[0; 16]; TAG_SLOTS],
        del_hash: None,
        blob_ref: None,
        welcome_ref: None,
        added_p: Vec::new(),
        removed: Vec::new(),
        join_pk_new: None,
        auth: EnvAuth::Host,
    })
}

/// Whether the held removals and leaves call for a revoke roll at `now`: an admin removal at
/// once, a leave after its 10 minute window, and either only 30 minutes after the last revoke
/// roll.
fn revoke_due(head: &HeadRow, now: u64) -> bool {
    let wanted = !head.held_admin.is_empty()
        || (!head.held_leave.is_empty()
            && now.saturating_sub(head.held_leave_since_ms) >= LEAVE_COALESCE_MS);
    let last_revoke = head
        .rolls
        .iter()
        .filter(|(code, _)| {
            *code == RollKind::RevokeAdmin.code() || *code == RollKind::RevokeLeave.code()
        })
        .map(|(_, at)| *at)
        .max();
    wanted && last_revoke.is_none_or(|at| now.saturating_sub(at) >= REVOKE_ROLL_GAP_MS)
}

/// Whether some roll is due for `head` at `now` (the cheap read-side test; the roll caps decide
/// whether it is then written).
#[must_use]
pub(super) fn roll_due(head: &HeadRow, now: u64) -> bool {
    head.spent_count >= SPENT_FULL
        || now.saturating_sub(head.te_started_ms) >= DAY_MS
        || revoke_due(head, now)
}

impl LargeGroupHost {
    /// Write any due roll in a transaction of its own, so a later refusal of the caller's request
    /// cannot undo it.
    pub(super) fn settle(&self, store: &RouterRedbStore, now: u64, gid: &[u8; 32]) -> LgResult<()> {
        let due = store
            .lg_read(|view| view.get(LgTable::Head, gid))?
            .map(|bytes| HeadRow::decode(&bytes))
            .transpose()?
            .is_some_and(|head| roll_due(&head, now));
        if !due {
            return Ok(());
        }
        self.run(store, now, |cx| {
            let mut head = cx.head(gid)?;
            cx.maybe_roll(gid, &mut head)?;
            cx.put_head(gid, &head)
        })
    }
}

impl Cx<'_> {
    /// Write the rolls that are due and allowed by the caps; refused rolls stay held.
    pub(super) fn maybe_roll(&self, gid: &[u8; 32], head: &mut HeadRow) -> LgResult<()> {
        let mut window = RollWindow::from_records(
            head.rolls
                .iter()
                .filter_map(|(code, at)| {
                    RollKind::from_code(*code).ok().map(|kind| RollRecord {
                        kind,
                        started_at_ms: *at,
                        refs_valid: true,
                    })
                })
                .collect(),
        );
        if revoke_due(head, self.now) {
            let kind = if head.held_admin.is_empty() {
                RollKind::RevokeLeave
            } else {
                RollKind::RevokeAdmin
            };
            let mut refs = head.held_admin.clone();
            refs.extend_from_slice(&head.held_leave);
            if self.try_roll(gid, head, &mut window, kind, &refs)? {
                head.held_admin.clear();
                head.held_leave.clear();
            }
        }
        if head.spent_count >= SPENT_FULL {
            self.try_roll(gid, head, &mut window, RollKind::SpentFull, &[])?;
        } else if self.now.saturating_sub(head.te_started_ms) >= DAY_MS {
            self.try_roll(gid, head, &mut window, RollKind::Daily, &[])?;
        }
        Ok(())
    }

    fn try_roll(
        &self,
        gid: &[u8; 32],
        head: &mut HeadRow,
        window: &mut RollWindow,
        kind: RollKind,
        refs: &[u64],
    ) -> LgResult<bool> {
        let record = RollRecord { kind, started_at_ms: self.now, refs_valid: true };
        if window.accept(record).is_err() {
            return Ok(false);
        }
        head.te = head.te.checked_add(1).ok_or(LgRefusal::Internal)?;
        head.te_started_ms = self.now;
        head.last_roll_kind = kind.code();
        head.spent_count = 0;
        let payload = RollPayload { kind, te: head.te, ref_seqs: refs.to_vec() }.encode();
        let header = host_header(gid, EnvKind::Roll, head.epoch)?;
        self.append_entry(gid, head, header, payload)?;
        let kept = window.records().len().saturating_sub(ROLL_RECORDS_KEPT);
        head.rolls = window
            .records()
            .iter()
            .skip(kept)
            .map(|record| (record.kind.code(), record.started_at_ms))
            .collect();
        if let Some(old) = head.te.checked_sub(2) {
            self.tx.delete_prefix(
                LgTable::Spent,
                &key(gid, &[&old.to_be_bytes()]),
                SPENT_DELETE_BATCH,
            )?;
        }
        self.tx.delete_prefix(LgTable::Tokens, &key(gid, &[&[2]]), SPENT_DELETE_BATCH)?;
        Ok(true)
    }

    /// Remember an admin-removal commit for the revoke roll.
    pub(super) fn hold_admin_removal(head: &mut HeadRow, seq: u64) {
        if head.held_admin.len() < HELD_REFS_MAX {
            head.held_admin.push(seq);
        }
    }

    /// Remember a leave (by a pseudonym older than 24 h) for the coalesced revoke roll.
    pub(super) fn hold_leave(head: &mut HeadRow, seq: u64, now: u64) {
        if head.held_leave.is_empty() {
            head.held_leave_since_ms = now;
        }
        if head.held_leave.len() < HELD_REFS_MAX {
            head.held_leave.push(seq);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn head() -> HeadRow {
        HeadRow {
            genesis: Vec::new(),
            epoch: 0,
            log_seq: 0,
            last_head: [0; 32],
            last_appended_ms: 0,
            last_commit_at_ms: 0,
            commits_24h: Vec::new(),
            p_set_hash: [0; 32],
            pset_count: 0,
            floor_seq: 0,
            post_count: 0,
            te: 0,
            te_started_ms: 0,
            last_roll_kind: 0,
            spent_count: 0,
            rolls: Vec::new(),
            held_admin: Vec::new(),
            held_leave: Vec::new(),
            held_leave_since_ms: 0,
            join_pk: [0; 32],
            pending_member: 0,
            pending_outsider: 0,
            voidable_seq: 0,
            voidable_epoch: 0,
            undo_removed: Vec::new(),
            route_count: 0,
            evals: 0,
        }
    }

    #[test]
    fn one_revoke_roll_waits_thirty_minutes_after_the_last() {
        let mut head = head();
        head.held_admin.push(5);
        assert!(revoke_due(&head, 1_000), "an admin removal rolls at once on a fresh group");
        head.rolls.push((RollKind::RevokeAdmin.code(), 1_000));
        assert!(!revoke_due(&head, 1_000 + REVOKE_ROLL_GAP_MS - 1), "held within 30 min");
        assert!(revoke_due(&head, 1_000 + REVOKE_ROLL_GAP_MS), "due 30 min after the last");
        head.rolls.push((RollKind::Daily.code(), 1_000 + 10));
        assert!(!revoke_due(&head, 1_000 + REVOKE_ROLL_GAP_MS - 1), "a daily roll does not reset");
    }

    #[test]
    fn a_leave_alone_waits_its_ten_minutes() {
        let mut head = head();
        head.held_leave.push(7);
        head.held_leave_since_ms = 1_000;
        assert!(!revoke_due(&head, 1_000 + LEAVE_COALESCE_MS - 1), "inside the leave window");
        assert!(revoke_due(&head, 1_000 + LEAVE_COALESCE_MS), "after the leave window");
        head.held_admin.push(8);
        assert!(revoke_due(&head, 1_001), "an admin removal does not wait for the leave window");
    }
}
