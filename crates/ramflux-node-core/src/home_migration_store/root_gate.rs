// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Durable root admission floors cover devices added after a sealed delivery map.
use super::{
    NodeCoreError, ReadableDatabase, ReadableTable, Refusal, RouterRedbStore, TableDefinition,
    decode, storage, write,
};
const ROOT_GATES: TableDefinition<&str, &[u8]> = TableDefinition::new("home_root_gates_v1");
pub(super) fn persist(
    tx: &redb::WriteTransaction,
    anchor: &str,
    reason: Option<Refusal>,
) -> Result<(), NodeCoreError> {
    if let Some(reason) = reason {
        write(tx, ROOT_GATES, anchor, &reason)
    } else {
        tx.open_table(ROOT_GATES).map_err(storage)?.remove(anchor).map_err(storage)?;
        Ok(())
    }
}
impl RouterRedbStore {
    pub(crate) fn load_inactive_migration_roots(
        db: &redb::Database,
    ) -> Result<std::collections::BTreeMap<String, Refusal>, NodeCoreError> {
        let tx = db.begin_read().map_err(storage)?;
        let table = match tx.open_table(ROOT_GATES) {
            Ok(table) => table,
            Err(redb::TableError::TableDoesNotExist(_)) => {
                return Ok(std::collections::BTreeMap::default());
            }
            Err(error) => return Err(storage(error)),
        };
        table
            .iter()
            .map_err(storage)?
            .map(|row| {
                let (key, value) = row.map_err(storage)?;
                Ok((key.value().to_owned(), decode(value.value())?))
            })
            .collect()
    }
    pub(crate) fn refresh_migration_root(&self, anchor: &str) -> Result<(), NodeCoreError> {
        let tx = self.migration_db().begin_read().map_err(storage)?;
        let table = tx.open_table(ROOT_GATES).map_err(storage)?;
        let reason =
            table.get(anchor).map_err(storage)?.map(|value| decode(value.value())).transpose()?;
        self.cache_migration_root(anchor, reason)
    }
    pub(crate) fn cache_migration_root(
        &self,
        anchor: &str,
        reason: Option<Refusal>,
    ) -> Result<(), NodeCoreError> {
        let mut roots = self.inactive_migration_roots.write().map_err(storage)?;
        if let Some(reason) = reason {
            roots.insert(anchor.into(), reason);
        } else {
            roots.remove(anchor);
        }
        Ok(())
    }
}
