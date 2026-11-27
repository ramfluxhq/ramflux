// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! The six `lg_*` redb tables and one write transaction wrapper.

use redb::{ReadableTable, TableDefinition};

pub(super) type Refuse = &'static str;
pub(super) type Rows = Vec<(Vec<u8>, Vec<u8>)>;
type Tbl = TableDefinition<'static, &'static [u8], &'static [u8]>;

pub(super) const PSEUDO: Tbl = TableDefinition::new("lg_pseudo");
pub(super) const INVITE: Tbl = TableDefinition::new("lg_invite");
pub(super) const LOG: Tbl = TableDefinition::new("lg_log");
pub(super) const SLOT: Tbl = TableDefinition::new("lg_slot");
pub(super) const SPENT: Tbl = TableDefinition::new("lg_spent");
pub(super) const STATE: Tbl = TableDefinition::new("lg_state");

pub(super) fn internal(error: impl std::fmt::Display) -> Refuse {
    tracing::warn!(%error, "large-group store error");
    "internal"
}

/// One write transaction; dropping it without [`Tx::commit`] aborts every change.
pub(super) struct Tx {
    txn: redb::WriteTransaction,
}

pub(super) fn open_db(path: &std::path::Path) -> Result<redb::Database, Refuse> {
    let db = redb::Database::create(path).map_err(internal)?;
    let txn = db.begin_write().map_err(internal)?;
    for table in [PSEUDO, INVITE, LOG, SLOT, SPENT, STATE] {
        txn.open_table(table).map_err(internal)?;
    }
    txn.commit().map_err(internal)?;
    Ok(db)
}

impl Tx {
    pub(super) fn begin(db: &redb::Database) -> Result<Self, Refuse> {
        Ok(Self { txn: db.begin_write().map_err(internal)? })
    }

    pub(super) fn commit(self) -> Result<(), Refuse> {
        self.txn.commit().map_err(internal)
    }

    pub(super) fn get(&self, table: Tbl, key: &[u8]) -> Result<Option<Vec<u8>>, Refuse> {
        let table = self.txn.open_table(table).map_err(internal)?;
        let found = table.get(key).map_err(internal)?;
        Ok(found.map(|guard| guard.value().to_vec()))
    }

    pub(super) fn put(&self, table: Tbl, key: &[u8], value: &[u8]) -> Result<(), Refuse> {
        let mut table = self.txn.open_table(table).map_err(internal)?;
        table.insert(key, value).map_err(internal)?;
        Ok(())
    }

    pub(super) fn del(&self, table: Tbl, key: &[u8]) -> Result<(), Refuse> {
        let mut table = self.txn.open_table(table).map_err(internal)?;
        table.remove(key).map_err(internal)?;
        Ok(())
    }

    /// Rows whose key starts with `prefix`, in key order, at most `limit`.
    pub(super) fn scan(&self, table: Tbl, prefix: &[u8], limit: usize) -> Result<Rows, Refuse> {
        let table = self.txn.open_table(table).map_err(internal)?;
        let mut out = Vec::new();
        for row in table.range::<&[u8]>(prefix..).map_err(internal)? {
            let (key, value) = row.map_err(internal)?;
            if !key.value().starts_with(prefix) || out.len() >= limit {
                break;
            }
            out.push((key.value().to_vec(), value.value().to_vec()));
        }
        Ok(out)
    }

    /// Like [`Self::scan`] but starting at `start` (which must begin with `prefix`).
    pub(super) fn scan_from(
        &self,
        table: Tbl,
        prefix: &[u8],
        start: &[u8],
        limit: usize,
    ) -> Result<Rows, Refuse> {
        let table = self.txn.open_table(table).map_err(internal)?;
        let mut out = Vec::new();
        for row in table.range::<&[u8]>(start..).map_err(internal)? {
            let (key, value) = row.map_err(internal)?;
            if !key.value().starts_with(prefix) || out.len() >= limit {
                break;
            }
            out.push((key.value().to_vec(), value.value().to_vec()));
        }
        Ok(out)
    }

    pub(super) fn delete_prefix(&self, table: Tbl, prefix: &[u8]) -> Result<(), Refuse> {
        let keys = self.scan(table, prefix, usize::MAX)?;
        for (key, _) in keys {
            self.del(table, &key)?;
        }
        Ok(())
    }
}

/// `gid || tag` and similar composite keys.
pub(super) fn key(parts: &[&[u8]]) -> Vec<u8> {
    parts.concat()
}
