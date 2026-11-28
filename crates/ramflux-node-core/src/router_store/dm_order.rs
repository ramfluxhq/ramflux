// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! The `dm_order` tables on the router database: the small ordering state of DM and self groups
//! (`dm_head`, `dm_log`, `dm_scope`, `dm_ids`), their row codecs and the log retention.
//!
//! The rules (exact-epoch CAS, scope binding, limits) live in `crate::dm_order`; this module only
//! stores and prunes. Rows are binary and length-bounded; nothing here reads a clock.
use super::direct_write::DirectWrite;
use super::{NodeCoreError, ReadableDatabase, ReadableTable, RouterRedbStore, TableDefinition};

const HEAD: TableDefinition<&[u8], &[u8]> = TableDefinition::new("dm_head_v1");
const LOG: TableDefinition<&[u8], &[u8]> = TableDefinition::new("dm_log_v1");
const SCOPE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("dm_scope_v1");
const IDS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("dm_ids_v1");

/// Log entries younger than this are never pruned by age (30 days).
pub(crate) const LOG_MIN_AGE_SECS: u64 = 30 * 86_400;
/// The newest entries of a group that are always kept.
pub(crate) const LOG_KEEP_NEWEST: u64 = 256;
/// Hard cap of log entries per group; the oldest go first.
pub(crate) const LOG_HARD_CAP: u64 = 4_096;
/// Longest scope id the tables accept.
pub(crate) const SCOPE_ID_MAX_BYTES: usize = 64;
/// Most anchors of one group (a DM has two, a self group one).
pub(crate) const ANCHORS_MAX: usize = 2;
/// Most re-establish timestamps kept per scope (the self limit is the larger one).
pub(crate) const RE_ESTABLISH_KEEP: usize = 8;
/// Longest anchor or node id string stored.
const ID_STRING_MAX: usize = 128;
/// Longest commit blob stored (the request bound, 1 MiB).
pub(crate) const COMMIT_MAX_BYTES: usize = 1 << 20;

/// A group id: `BLAKE3` output.
pub(crate) type GroupId = [u8; 32];

fn error(source: impl std::fmt::Display) -> NodeCoreError {
    NodeCoreError::Redb(source.to_string())
}

fn corrupt() -> NodeCoreError {
    NodeCoreError::UnsupportedPersistedFormat("dm_order row")
}

/// The head of one group.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DmHead {
    pub(crate) kind: u8,
    pub(crate) scope_id: Vec<u8>,
    pub(crate) anchors: Vec<String>,
    pub(crate) epoch: u64,
    pub(crate) log_seq: u64,
    pub(crate) replaced_by: Option<GroupId>,
}

/// One accepted commit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DmLogEntry {
    pub(crate) log_seq: u64,
    pub(crate) epoch: u64,
    pub(crate) accepted_at: u64,
    pub(crate) origin_node: String,
    pub(crate) commit: Vec<u8>,
}

/// The current group of a scope and the recent re-establish times (for the per-scope limit).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DmScopeRow {
    pub(crate) group_id: GroupId,
    pub(crate) re_established: Vec<u64>,
}

struct Reader<'a> {
    rest: &'a [u8],
}

impl<'a> Reader<'a> {
    fn take(&mut self, count: usize) -> Result<&'a [u8], NodeCoreError> {
        let (head, rest) = self.rest.split_at_checked(count).ok_or_else(corrupt)?;
        self.rest = rest;
        Ok(head)
    }

    fn u8(&mut self) -> Result<u8, NodeCoreError> {
        self.take(1)?.first().copied().ok_or_else(corrupt)
    }

    fn u16(&mut self) -> Result<u16, NodeCoreError> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().map_err(|_| corrupt())?))
    }

    fn u64(&mut self) -> Result<u64, NodeCoreError> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().map_err(|_| corrupt())?))
    }

    fn group_id(&mut self) -> Result<GroupId, NodeCoreError> {
        self.take(32)?.try_into().map_err(|_| corrupt())
    }

    fn string(&mut self) -> Result<String, NodeCoreError> {
        let len = usize::from(self.u16()?);
        if len > ID_STRING_MAX {
            return Err(corrupt());
        }
        String::from_utf8(self.take(len)?.to_vec()).map_err(|_| corrupt())
    }

    fn finish(&self) -> Result<(), NodeCoreError> {
        if self.rest.is_empty() { Ok(()) } else { Err(corrupt()) }
    }
}

fn put_string(out: &mut Vec<u8>, value: &str) -> Result<(), NodeCoreError> {
    let len = u16::try_from(value.len()).map_err(|_| corrupt())?;
    if value.len() > ID_STRING_MAX {
        return Err(corrupt());
    }
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(value.as_bytes());
    Ok(())
}

impl DmHead {
    fn encode(&self) -> Result<Vec<u8>, NodeCoreError> {
        let mut out = vec![self.kind];
        let scope_len = u16::try_from(self.scope_id.len()).map_err(|_| corrupt())?;
        if self.scope_id.len() > SCOPE_ID_MAX_BYTES || self.anchors.len() > ANCHORS_MAX {
            return Err(corrupt());
        }
        out.extend_from_slice(&scope_len.to_be_bytes());
        out.extend_from_slice(&self.scope_id);
        out.push(u8::try_from(self.anchors.len()).map_err(|_| corrupt())?);
        for anchor in &self.anchors {
            put_string(&mut out, anchor)?;
        }
        out.extend_from_slice(&self.epoch.to_be_bytes());
        out.extend_from_slice(&self.log_seq.to_be_bytes());
        match &self.replaced_by {
            Some(id) => {
                out.push(1);
                out.extend_from_slice(id);
            }
            None => out.push(0),
        }
        Ok(out)
    }

    fn decode(bytes: &[u8]) -> Result<Self, NodeCoreError> {
        let mut reader = Reader { rest: bytes };
        let kind = reader.u8()?;
        let scope_len = usize::from(reader.u16()?);
        if scope_len > SCOPE_ID_MAX_BYTES {
            return Err(corrupt());
        }
        let scope_id = reader.take(scope_len)?.to_vec();
        let count = usize::from(reader.u8()?);
        if count > ANCHORS_MAX {
            return Err(corrupt());
        }
        let mut anchors = Vec::with_capacity(count);
        for _ in 0..count {
            anchors.push(reader.string()?);
        }
        let epoch = reader.u64()?;
        let log_seq = reader.u64()?;
        let replaced_by = match reader.u8()? {
            0 => None,
            1 => Some(reader.group_id()?),
            _ => return Err(corrupt()),
        };
        reader.finish()?;
        Ok(Self { kind, scope_id, anchors, epoch, log_seq, replaced_by })
    }
}

impl DmLogEntry {
    fn encode(&self) -> Result<Vec<u8>, NodeCoreError> {
        if self.commit.len() > COMMIT_MAX_BYTES {
            return Err(corrupt());
        }
        let mut out = Vec::with_capacity(self.commit.len().saturating_add(160));
        out.extend_from_slice(&self.epoch.to_be_bytes());
        out.extend_from_slice(&self.accepted_at.to_be_bytes());
        put_string(&mut out, &self.origin_node)?;
        out.extend_from_slice(&self.commit);
        Ok(out)
    }

    fn decode(log_seq: u64, bytes: &[u8]) -> Result<Self, NodeCoreError> {
        let mut reader = Reader { rest: bytes };
        let epoch = reader.u64()?;
        let accepted_at = reader.u64()?;
        let origin_node = reader.string()?;
        let commit = reader.rest.to_vec();
        if commit.len() > COMMIT_MAX_BYTES {
            return Err(corrupt());
        }
        Ok(Self { log_seq, epoch, accepted_at, origin_node, commit })
    }
}

impl DmScopeRow {
    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(33 + self.re_established.len() * 8);
        out.extend_from_slice(&self.group_id);
        let keep = self.re_established.len().min(RE_ESTABLISH_KEEP);
        out.push(u8::try_from(keep).unwrap_or(0));
        for at in self.re_established.iter().rev().take(keep).rev() {
            out.extend_from_slice(&at.to_be_bytes());
        }
        out
    }

    fn decode(bytes: &[u8]) -> Result<Self, NodeCoreError> {
        let mut reader = Reader { rest: bytes };
        let group_id = reader.group_id()?;
        let count = usize::from(reader.u8()?);
        if count > RE_ESTABLISH_KEEP {
            return Err(corrupt());
        }
        let mut re_established = Vec::with_capacity(count);
        for _ in 0..count {
            re_established.push(reader.u64()?);
        }
        reader.finish()?;
        Ok(Self { group_id, re_established })
    }
}

fn log_key(group: &[u8], log_seq: u64) -> Vec<u8> {
    let mut key = Vec::with_capacity(group.len().saturating_add(8));
    key.extend_from_slice(group);
    key.extend_from_slice(&log_seq.to_be_bytes());
    key
}

/// The key of a scope row: kind byte then the scope id.
fn scope_key(kind: u8, scope_id: &[u8]) -> Vec<u8> {
    let mut key = Vec::with_capacity(scope_id.len().saturating_add(1));
    key.push(kind);
    key.extend_from_slice(scope_id);
    key
}

fn read_head<T: ReadableTable<&'static [u8], &'static [u8]>>(
    table: &T,
    group: &[u8],
) -> Result<Option<DmHead>, NodeCoreError> {
    table.get(group).map_err(error)?.map(|row| DmHead::decode(row.value())).transpose()
}

fn read_scope<T: ReadableTable<&'static [u8], &'static [u8]>>(
    table: &T,
    kind: u8,
    scope_id: &[u8],
) -> Result<Option<DmScopeRow>, NodeCoreError> {
    table
        .get(scope_key(kind, scope_id).as_slice())
        .map_err(error)?
        .map(|row| DmScopeRow::decode(row.value()))
        .transpose()
}

/// Lowest retained `log_seq` of a group, if any entry is retained.
fn read_oldest<T: ReadableTable<&'static [u8], &'static [u8]>>(
    table: &T,
    group: &[u8],
) -> Result<Option<u64>, NodeCoreError> {
    let start = log_key(group, 0);
    let end = log_key(group, u64::MAX);
    let mut rows = table.range(start.as_slice()..=end.as_slice()).map_err(error)?;
    let Some(row) = rows.next() else { return Ok(None) };
    let (key, _) = row.map_err(error)?;
    seq_of(key.value(), group.len()).map(Some)
}

fn seq_of(key: &[u8], group_len: usize) -> Result<u64, NodeCoreError> {
    let tail = key.get(group_len..).ok_or_else(corrupt)?;
    Ok(u64::from_be_bytes(tail.try_into().map_err(|_| corrupt())?))
}

/// Entries after `after`, at most `max_entries` and about `max_bytes` (at least one entry), and
/// whether more follow.
fn read_after<T: ReadableTable<&'static [u8], &'static [u8]>>(
    table: &T,
    group: &[u8],
    after: u64,
    max_entries: usize,
    max_bytes: usize,
) -> Result<(Vec<DmLogEntry>, bool), NodeCoreError> {
    let Some(first) = after.checked_add(1) else { return Ok((Vec::new(), false)) };
    let start = log_key(group, first);
    let end = log_key(group, u64::MAX);
    let mut out = Vec::new();
    let mut bytes = 0_usize;
    for row in table.range(start.as_slice()..=end.as_slice()).map_err(error)? {
        let (key, value) = row.map_err(error)?;
        if out.len() >= max_entries || (!out.is_empty() && bytes >= max_bytes) {
            return Ok((out, true));
        }
        let entry = DmLogEntry::decode(seq_of(key.value(), group.len())?, value.value())?;
        bytes = bytes.saturating_add(entry.commit.len());
        out.push(entry);
    }
    Ok((out, false))
}

/// The read side of the tables (one snapshot).
pub(crate) struct DmView {
    head: redb::ReadOnlyTable<&'static [u8], &'static [u8]>,
    log: redb::ReadOnlyTable<&'static [u8], &'static [u8]>,
    scope: redb::ReadOnlyTable<&'static [u8], &'static [u8]>,
}

impl DmView {
    pub(crate) fn head(&self, group: &[u8]) -> Result<Option<DmHead>, NodeCoreError> {
        read_head(&self.head, group)
    }

    pub(crate) fn scope(
        &self,
        kind: u8,
        scope_id: &[u8],
    ) -> Result<Option<DmScopeRow>, NodeCoreError> {
        read_scope(&self.scope, kind, scope_id)
    }

    pub(crate) fn oldest(&self, group: &[u8]) -> Result<Option<u64>, NodeCoreError> {
        read_oldest(&self.log, group)
    }

    pub(crate) fn after(
        &self,
        group: &[u8],
        after: u64,
        max_entries: usize,
        max_bytes: usize,
    ) -> Result<(Vec<DmLogEntry>, bool), NodeCoreError> {
        read_after(&self.log, group, after, max_entries, max_bytes)
    }
}

/// The write side: every table open in one write transaction.
pub(crate) struct DmTx<'t> {
    head: redb::Table<'t, &'static [u8], &'static [u8]>,
    log: redb::Table<'t, &'static [u8], &'static [u8]>,
    scope: redb::Table<'t, &'static [u8], &'static [u8]>,
    ids: redb::Table<'t, &'static [u8], &'static [u8]>,
}

impl DmTx<'_> {
    pub(crate) fn head(&self, group: &[u8]) -> Result<Option<DmHead>, NodeCoreError> {
        read_head(&self.head, group)
    }

    pub(crate) fn put_head(&mut self, group: &[u8], head: &DmHead) -> Result<(), NodeCoreError> {
        let bytes = head.encode()?;
        self.head.insert(group, bytes.as_slice()).map_err(error)?;
        Ok(())
    }

    pub(crate) fn scope(
        &self,
        kind: u8,
        scope_id: &[u8],
    ) -> Result<Option<DmScopeRow>, NodeCoreError> {
        read_scope(&self.scope, kind, scope_id)
    }

    pub(crate) fn put_scope(
        &mut self,
        kind: u8,
        scope_id: &[u8],
        row: &DmScopeRow,
    ) -> Result<(), NodeCoreError> {
        let bytes = row.encode();
        self.scope.insert(scope_key(kind, scope_id).as_slice(), bytes.as_slice()).map_err(error)?;
        Ok(())
    }

    /// Whether `group` was ever used on this node.
    pub(crate) fn id_used(&self, group: &[u8]) -> Result<bool, NodeCoreError> {
        Ok(self.ids.get(group).map_err(error)?.is_some())
    }

    /// Record `group` as used; rows are never pruned.
    pub(crate) fn mark_id(&mut self, group: &[u8], kind: u8) -> Result<(), NodeCoreError> {
        self.ids.insert(group, [kind].as_slice()).map_err(error)?;
        Ok(())
    }

    /// Append `entry` and prune the group's log: entries older than 30 days that are not among the
    /// newest 256, and anything beyond the hard cap, oldest first.
    pub(crate) fn append(
        &mut self,
        group: &[u8],
        entry: &DmLogEntry,
        now: u64,
    ) -> Result<(), NodeCoreError> {
        let bytes = entry.encode()?;
        self.log
            .insert(log_key(group, entry.log_seq).as_slice(), bytes.as_slice())
            .map_err(error)?;
        let newest = entry.log_seq;
        let mut doomed = Vec::new();
        {
            let start = log_key(group, 0);
            let end = log_key(group, u64::MAX);
            for row in self.log.range(start.as_slice()..=end.as_slice()).map_err(error)? {
                let (key, value) = row.map_err(error)?;
                let seq = seq_of(key.value(), group.len())?;
                let retained = newest.saturating_sub(seq).saturating_add(1);
                let over_cap = retained > LOG_HARD_CAP;
                let aged = retained > LOG_KEEP_NEWEST
                    && accepted_at_of(value.value())?.saturating_add(LOG_MIN_AGE_SECS) < now;
                if over_cap || aged {
                    doomed.push(key.value().to_vec());
                } else {
                    // Entries are ordered by age: every later one is newer and shorter-lived.
                    break;
                }
            }
        }
        for key in doomed {
            self.log.remove(key.as_slice()).map_err(error)?;
        }
        Ok(())
    }
}

fn accepted_at_of(value: &[u8]) -> Result<u64, NodeCoreError> {
    let at = value.get(8..16).ok_or_else(corrupt)?;
    Ok(u64::from_be_bytes(at.try_into().map_err(|_| corrupt())?))
}

/// How a write closure ends: its change is committed or dropped.
pub(crate) enum DmWrite<R> {
    /// Commit the transaction and return `R`.
    Commit(R),
    /// Drop the transaction (a refusal) and return `R`.
    Abort(R),
}

/// Create the tables so reads on a fresh database find them.
pub(super) fn initialize(txn: &redb::WriteTransaction) -> Result<(), NodeCoreError> {
    for table in [HEAD, LOG, SCOPE, IDS] {
        txn.open_table(table).map_err(error)?;
    }
    Ok(())
}

impl RouterRedbStore {
    /// Run `change` in one write transaction on the `dm_order` tables.
    ///
    /// # Errors
    /// Database failures and malformed rows; refusals are values of `R`.
    pub(crate) fn dm_order_write<R>(
        &self,
        change: impl FnOnce(&mut DmTx<'_>) -> Result<DmWrite<R>, NodeCoreError>,
    ) -> Result<R, NodeCoreError> {
        let txn: DirectWrite<'_> = self.begin_write()?;
        let outcome = {
            let mut tx = DmTx {
                head: txn.open_table(HEAD).map_err(error)?,
                log: txn.open_table(LOG).map_err(error)?,
                scope: txn.open_table(SCOPE).map_err(error)?,
                ids: txn.open_table(IDS).map_err(error)?,
            };
            change(&mut tx)?
        };
        match outcome {
            DmWrite::Commit(value) => {
                txn.commit()?;
                Ok(value)
            }
            DmWrite::Abort(value) => {
                txn.abort()?;
                Ok(value)
            }
        }
    }

    /// Run `read` on one snapshot of the `dm_order` tables.
    ///
    /// # Errors
    /// Database failures and malformed rows.
    pub(crate) fn dm_order_read<R>(
        &self,
        read: impl FnOnce(&DmView) -> Result<R, NodeCoreError>,
    ) -> Result<R, NodeCoreError> {
        let txn = self.db.begin_read().map_err(error)?;
        let view = DmView {
            head: txn.open_table(HEAD).map_err(error)?,
            log: txn.open_table(LOG).map_err(error)?,
            scope: txn.open_table(SCOPE).map_err(error)?,
        };
        read(&view)
    }
}
