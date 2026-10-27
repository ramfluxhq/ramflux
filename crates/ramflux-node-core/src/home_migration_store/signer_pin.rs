// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Migration records retain one local signing identity; rotation is a later protocol.
use super::{
    MigrationNode, NodeCoreError, ReadableDatabase, RouterRedbStore, TableDefinition, read,
    storage, write,
};
const LOCAL_NODE: TableDefinition<&str, &[u8]> = TableDefinition::new("migration_local_signer_v1");
pub(super) fn retain(
    tx: &redb::WriteTransaction,
    node: &MigrationNode,
) -> Result<(), NodeCoreError> {
    let expected = (node.node_id().to_owned(), node.public_key().to_owned());
    if let Some(existing) = read::<(String, String)>(tx, LOCAL_NODE, "identity")? {
        if existing != expected {
            return Err(storage("migration records require the retained node signer"));
        }
    } else {
        write(tx, LOCAL_NODE, "identity", &expected)?;
    }
    Ok(())
}
impl RouterRedbStore {
    /// Check before serving: migration records cannot survive signer removal or rotation.
    /// This is read-only and does not pin an unused node merely because it starts.
    /// # Errors
    /// Rejects unavailable migration runtime, changed node identity, and storage failures.
    pub fn validate_home_migration_runtime(
        &self,
        identity: Option<(&str, &str)>,
    ) -> Result<(), NodeCoreError> {
        let tx = self.migration_db().begin_read().map_err(storage)?;
        let table = match tx.open_table(LOCAL_NODE) {
            Ok(table) => table,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(()),
            Err(error) => return Err(storage(error)),
        };
        let Some(row) = table.get("identity").map_err(storage)? else {
            return Ok(());
        };
        let expected: (String, String) = super::decode(row.value())?;
        if identity != Some((&expected.0, &expected.1)) {
            return Err(storage(
                "migration records require the retained node signer and enabled runtime",
            ));
        }
        Ok(())
    }
}
