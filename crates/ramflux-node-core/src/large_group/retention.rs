// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Retention (MLS-SPEC r1.1 2.5): entries 30 days (posts also at most 1 M), pending joins 24 h,
//! Welcomes 7 days or shortly after the last joiner fetched, unreferenced uploads 15 minutes,
//! routes 7 to 8 days, spent sets two epochs after their epoch ends. Genesis, the admin chain, the
//! token root and invites are kept. One sweep call works on a bounded number of groups and each
//! group's pass is bounded, so a backlog is worked off over several calls.

use std::time::Duration;

use ramflux_crypto::large_group::{EnvKind, Envelope};

use super::check::{DAY_MS, POSTS_MAX, entry_expired, route_expired, welcome_expired};
use super::host::{Cx, LargeGroupHost};
use super::join::welcome_row_prefix;
use super::key_file;
use super::refusal::{LgRefusal, LgResult};
use super::rows::{HeadRow, LogRow, QUEUE_MEMBER, QUEUE_OUTSIDER, RouteRow, WelcomeRow, key};
use crate::RouterRedbStore;
use crate::router_store::lg_store::LgTable;

/// Log entries one group pass looks at.
const LOG_BATCH: usize = 512;
/// Rows of the small per-group tables one pass looks at.
const ROW_BATCH: usize = 4_096;
/// Prepared keys of a create that never came are removed after this.
const PREPARED_KEY_MAX_AGE: Duration = Duration::from_secs(3_600);

impl LargeGroupHost {
    /// Sweep up to `max_groups` groups after `cursor` (`None`: from the first); returns the cursor
    /// to continue from, or `None` when the last group was done. Also removes stale prepared key
    /// files.
    ///
    /// # Errors
    /// Store failures.
    pub fn sweep(
        &self,
        store: &RouterRedbStore,
        now: u64,
        cursor: Option<[u8; 32]>,
        max_groups: usize,
    ) -> LgResult<Option<[u8; 32]>> {
        let start = cursor.map_or_else(Vec::new, |last| {
            let mut next = last.to_vec();
            next.push(0);
            next
        });
        let groups = store
            .lg_read(|view| view.scan(LgTable::Head, &[], &start, max_groups.saturating_add(1)))?;
        let mut last = None;
        for (gid_bytes, _) in groups.iter().take(max_groups) {
            let gid: [u8; 32] = gid_bytes.as_slice().try_into().map_err(|_| LgRefusal::Internal)?;
            self.settle(store, now, &gid)?;
            self.run(store, now, |cx| cx.sweep_group(&gid))?;
            last = Some(gid);
        }
        if cursor.is_none() {
            key_file::remove_stale_prepared(&self.key_dir, PREPARED_KEY_MAX_AGE)?;
        }
        Ok(if groups.len() > max_groups { last } else { None })
    }
}

impl Cx<'_> {
    fn sweep_group(&self, gid: &[u8; 32]) -> LgResult<()> {
        let mut head = self.head(gid)?;
        self.sweep_log(gid, &mut head)?;
        self.expire_joins(gid, &mut head, QUEUE_MEMBER)?;
        self.expire_joins(gid, &mut head, QUEUE_OUTSIDER)?;
        self.sweep_welcomes(gid)?;
        self.sweep_blobs(gid)?;
        self.sweep_routes(gid, &mut head)?;
        self.sweep_spent(gid, &head)?;
        self.put_head(gid, &head)
    }

    /// Entries older than 30 d go from the front of the log; beyond 1 M posts the oldest posts go.
    fn sweep_log(&self, gid: &[u8; 32], head: &mut HeadRow) -> LgResult<()> {
        let prefix = key(gid, &[]);
        let start = key(gid, &[&head.floor_seq.max(1).to_be_bytes()]);
        let mut first_kept = None;
        for (row_key, value) in self.tx.scan(LgTable::Log, &prefix, &start, LOG_BATCH)? {
            let row = LogRow::decode(&value)?;
            if !entry_expired(row.appended_ms, self.now) {
                first_kept = seq_of(&row_key);
                break;
            }
            self.delete_entry(gid, head, &row_key, &row)?;
        }
        head.floor_seq = match first_kept {
            Some(seq) => seq,
            None => head.log_seq.saturating_add(1),
        };
        if head.post_count > POSTS_MAX {
            let mut over = head.post_count - POSTS_MAX;
            for (row_key, value) in self.tx.scan(LgTable::Log, &prefix, &start, LOG_BATCH)? {
                if over == 0 {
                    break;
                }
                let row = LogRow::decode(&value)?;
                if row.kind == EnvKind::Post.code() {
                    self.delete_entry(gid, head, &row_key, &row)?;
                    over -= 1;
                }
            }
        }
        Ok(())
    }

    fn delete_entry(
        &self,
        gid: &[u8; 32],
        head: &mut HeadRow,
        row_key: &[u8],
        row: &LogRow,
    ) -> LgResult<()> {
        if let Some(blob_ref) = Envelope::decode(&row.envelope)?.header.blob_ref {
            self.blob_delete(gid, &blob_ref)?;
        }
        if row.kind == EnvKind::Post.code() {
            head.post_count = head.post_count.saturating_sub(1);
        }
        Ok(self.tx.del(LgTable::Log, row_key)?)
    }

    fn sweep_welcomes(&self, gid: &[u8; 32]) -> LgResult<()> {
        let prefix = welcome_row_prefix(gid);
        for (row_key, value) in self.tx.scan(LgTable::Welcome, &prefix, &prefix, ROW_BATCH)? {
            let row = WelcomeRow::decode(&value)?;
            if welcome_expired(row.created_ms, row.drained_ms, self.now) {
                let seq_bytes: [u8; 8] = row_key
                    .get(prefix.len()..)
                    .and_then(|tail| tail.try_into().ok())
                    .ok_or(LgRefusal::Internal)?;
                self.welcome_discard(gid, u64::from_be_bytes(seq_bytes))?;
            }
        }
        Ok(())
    }

    fn sweep_routes(&self, gid: &[u8; 32], head: &mut HeadRow) -> LgResult<()> {
        let prefix = key(gid, &[]);
        let today = self.now / DAY_MS;
        for (row_key, value) in self.tx.scan(LgTable::Route, &prefix, &prefix, ROW_BATCH)? {
            if route_expired(RouteRow::decode(&value)?.registered_day, today) {
                self.tx.del(LgTable::Route, &row_key)?;
                head.route_count = head.route_count.saturating_sub(1);
            }
        }
        Ok(())
    }

    /// Spent sets of epochs more than one behind the current one (the grace covers `te - 1`).
    fn sweep_spent(&self, gid: &[u8; 32], head: &HeadRow) -> LgResult<()> {
        let prefix = key(gid, &[]);
        for (row_key, _) in self.tx.scan(LgTable::Spent, &prefix, &prefix, ROW_BATCH)? {
            let Some(te_bytes) =
                row_key.get(32..36).and_then(|bytes| <[u8; 4]>::try_from(bytes).ok())
            else {
                continue;
            };
            if u32::from_be_bytes(te_bytes).saturating_add(1) >= head.te {
                break;
            }
            self.tx.del(LgTable::Spent, &row_key)?;
        }
        Ok(())
    }
}

fn seq_of(row_key: &[u8]) -> Option<u64> {
    let bytes: [u8; 8] = row_key.get(32..40)?.try_into().ok()?;
    Some(u64::from_be_bytes(bytes))
}
