// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Token epoch rolls written by the host (LARGE-GROUP-01 2.3, MLS-SPEC r1.1 2.6; from 6ed
//! `entries.rs`): `daily` after 24 h, `spent_full` at 1 M spent tokens, and `revoke` after admin
//! removals and coalesced leaves, all under the roll caps of `ramflux_crypto::large_group`
//! (`RollWindow`). A roll is a host-signed `roll` entry; the old epoch's spent set is dropped two
//! epochs later.

use ramflux_crypto::large_group::{
    EnvAuth, EnvHeader, EnvKind, RollKind, RollPayload, RollRecord, RollWindow, TAG_SLOTS,
    random_array,
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
        added_p: Vec::new(),
        removed: Vec::new(),
        join_pk_new: None,
        auth: EnvAuth::Host,
    })
}

/// Whether some roll is due for `head` at `now` (the cheap read-side test; the roll caps decide
/// whether it is then written).
#[must_use]
pub(super) fn roll_due(head: &HeadRow, now: u64) -> bool {
    head.spent_count >= SPENT_FULL
        || now.saturating_sub(head.te_started_ms) >= DAY_MS
        || !head.held_admin.is_empty()
        || (!head.held_leave.is_empty()
            && now.saturating_sub(head.held_leave_since_ms) >= LEAVE_COALESCE_MS)
}

impl LargeGroupHost {
    /// Write any due roll in a transaction of its own, so a later refusal of the caller's request
    /// cannot undo it.
    pub(super) fn settle(
        &self,
        store: &RouterRedbStore,
        now: u64,
        gid: &[u8; 32],
    ) -> LgResult<()> {
        let due = store
            .lg_read(|view| Ok(view.get(LgTable::Head, gid)?))?
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
        if !head.held_admin.is_empty() {
            let refs = head.held_admin.clone();
            if self.try_roll(gid, head, &mut window, RollKind::RevokeAdmin, &refs)? {
                head.held_admin.clear();
            }
        }
        if !head.held_leave.is_empty()
            && self.now.saturating_sub(head.held_leave_since_ms) >= LEAVE_COALESCE_MS
        {
            let refs = head.held_leave.clone();
            if self.try_roll(gid, head, &mut window, RollKind::RevokeLeave, &refs)? {
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
