// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! The `lg_*` tables of the group host on the router database (MLS-SPEC r1.1 2.2): one write
//! transaction per append. This module only opens tables and moves bytes; the row layouts and the
//! rules live in `crate::large_group`. Nothing here reads a clock or stores a session id, source
//! address or arrival time.
use super::direct_write::DirectWrite;
use super::{NodeCoreError, ReadableDatabase, ReadableTable, RouterRedbStore, TableDefinition};

type Tbl = TableDefinition<'static, &'static [u8], &'static [u8]>;

const HEAD: Tbl = TableDefinition::new("lg_head_v1");
const LOG: Tbl = TableDefinition::new("lg_log_v1");
const PSET: Tbl = TableDefinition::new("lg_pset_v1");
const JOIN: Tbl = TableDefinition::new("lg_join_v1");
const SPENT: Tbl = TableDefinition::new("lg_spent_v1");
const TOKENS: Tbl = TableDefinition::new("lg_tokens_v1");
const INVITE: Tbl = TableDefinition::new("lg_invite_v1");
const BLOB: Tbl = TableDefinition::new("lg_blob_v1");
const ROUTE: Tbl = TableDefinition::new("lg_route_v1");
const ADMIN: Tbl = TableDefinition::new("lg_admin_v1");
const WELCOME: Tbl = TableDefinition::new("lg_welcome_v1");

/// The tables of the group host.
#[derive(Clone, Copy, Debug)]
pub(crate) enum LgTable {
    /// Per-group counters and the head chain position.
    Head,
    /// The entry log.
    Log,
    /// Current leaf pseudonyms.
    Pset,
    /// Pending join requests (two queues).
    Join,
    /// Spent token tags.
    Spent,
    /// Issuance counters and cached issuance replies.
    Tokens,
    /// Invites.
    Invite,
    /// Blob metadata and chunks.
    Blob,
    /// Push routes.
    Route,
    /// Admin set and admin chain.
    Admin,
    /// Stored Welcomes.
    Welcome,
}

impl LgTable {
    const ALL: [Self; 11] = [
        Self::Head,
        Self::Log,
        Self::Pset,
        Self::Join,
        Self::Spent,
        Self::Tokens,
        Self::Invite,
        Self::Blob,
        Self::Route,
        Self::Admin,
        Self::Welcome,
    ];

    const fn def(self) -> Tbl {
        match self {
            Self::Head => HEAD,
            Self::Log => LOG,
            Self::Pset => PSET,
            Self::Join => JOIN,
            Self::Spent => SPENT,
            Self::Tokens => TOKENS,
            Self::Invite => INVITE,
            Self::Blob => BLOB,
            Self::Route => ROUTE,
            Self::Admin => ADMIN,
            Self::Welcome => WELCOME,
        }
    }
}

/// Rows of one scan: key and value.
pub(crate) type LgRows = Vec<(Vec<u8>, Vec<u8>)>;

fn error(source: impl std::fmt::Display) -> NodeCoreError {
    NodeCoreError::Redb(source.to_string())
}

/// How a write closure ends: its change is committed or dropped.
pub(crate) enum LgWrite<R> {
    /// Commit the transaction and return `R`.
    Commit(R),
    /// Drop the transaction (a refusal) and return `R`.
    Abort(R),
}

/// The write side: tables are opened per call, so no handle outlives a call.
pub(crate) struct LgTx<'t> {
    txn: &'t redb::WriteTransaction,
}

impl LgTx<'_> {
    pub(crate) fn get(&self, table: LgTable, key: &[u8]) -> Result<Option<Vec<u8>>, NodeCoreError> {
        let table = self.txn.open_table(table.def()).map_err(error)?;
        let found = table.get(key).map_err(error)?;
        Ok(found.map(|guard| guard.value().to_vec()))
    }

    pub(crate) fn put(
        &self,
        table: LgTable,
        key: &[u8],
        value: &[u8],
    ) -> Result<(), NodeCoreError> {
        let mut table = self.txn.open_table(table.def()).map_err(error)?;
        table.insert(key, value).map_err(error)?;
        Ok(())
    }

    pub(crate) fn del(&self, table: LgTable, key: &[u8]) -> Result<(), NodeCoreError> {
        let mut table = self.txn.open_table(table.def()).map_err(error)?;
        table.remove(key).map_err(error)?;
        Ok(())
    }

    /// Rows whose key starts with `prefix`, from `start` (which must start with `prefix`), in key
    /// order, at most `limit`.
    pub(crate) fn scan(
        &self,
        table: LgTable,
        prefix: &[u8],
        start: &[u8],
        limit: usize,
    ) -> Result<LgRows, NodeCoreError> {
        let table = self.txn.open_table(table.def()).map_err(error)?;
        collect(&table, prefix, start, limit)
    }

    /// Delete up to `limit` rows under `prefix`; returns how many went.
    pub(crate) fn delete_prefix(
        &self,
        table: LgTable,
        prefix: &[u8],
        limit: usize,
    ) -> Result<usize, NodeCoreError> {
        let mut table = self.txn.open_table(table.def()).map_err(error)?;
        let keys: Vec<Vec<u8>> =
            collect(&table, prefix, prefix, limit)?.into_iter().map(|(key, _)| key).collect();
        for key in &keys {
            table.remove(key.as_slice()).map_err(error)?;
        }
        Ok(keys.len())
    }
}

fn collect<T: ReadableTable<&'static [u8], &'static [u8]>>(
    table: &T,
    prefix: &[u8],
    start: &[u8],
    limit: usize,
) -> Result<LgRows, NodeCoreError> {
    let mut out = Vec::new();
    for row in table.range::<&[u8]>(start..).map_err(error)? {
        let (key, value) = row.map_err(error)?;
        if !key.value().starts_with(prefix) || out.len() >= limit {
            break;
        }
        out.push((key.value().to_vec(), value.value().to_vec()));
    }
    Ok(out)
}

/// The read side: one snapshot.
pub(crate) struct LgView {
    txn: redb::ReadTransaction,
}

impl LgView {
    pub(crate) fn get(&self, table: LgTable, key: &[u8]) -> Result<Option<Vec<u8>>, NodeCoreError> {
        let table = self.txn.open_table(table.def()).map_err(error)?;
        let found = table.get(key).map_err(error)?;
        Ok(found.map(|guard| guard.value().to_vec()))
    }

    pub(crate) fn scan(
        &self,
        table: LgTable,
        prefix: &[u8],
        start: &[u8],
        limit: usize,
    ) -> Result<LgRows, NodeCoreError> {
        let table = self.txn.open_table(table.def()).map_err(error)?;
        collect(&table, prefix, start, limit)
    }
}

/// Create the tables so reads on a fresh database find them.
pub(super) fn initialize(txn: &redb::WriteTransaction) -> Result<(), NodeCoreError> {
    for table in LgTable::ALL {
        txn.open_table(table.def()).map_err(error)?;
    }
    Ok(())
}

impl RouterRedbStore {
    /// Run `change` in one write transaction on the `lg_*` tables.
    ///
    /// # Errors
    /// Database failures; refusals are values of `R`.
    pub(crate) fn lg_write<R>(
        &self,
        change: impl FnOnce(&LgTx<'_>) -> Result<LgWrite<R>, NodeCoreError>,
    ) -> Result<R, NodeCoreError> {
        let txn: DirectWrite<'_> = self.begin_write()?;
        let outcome = change(&LgTx { txn: &txn })?;
        match outcome {
            LgWrite::Commit(value) => {
                txn.commit()?;
                Ok(value)
            }
            LgWrite::Abort(value) => {
                txn.abort()?;
                Ok(value)
            }
        }
    }

    /// Run `read` on one snapshot of the `lg_*` tables.
    ///
    /// # Errors
    /// Database failures.
    pub(crate) fn lg_read<R>(
        &self,
        read: impl FnOnce(&LgView) -> Result<R, NodeCoreError>,
    ) -> Result<R, NodeCoreError> {
        let view = LgView { txn: self.db.begin_read().map_err(error)? };
        read(&view)
    }
}
