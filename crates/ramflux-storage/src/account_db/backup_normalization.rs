// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Normalize a single private input using an empty peer, without importing archive copies.
use crate::account_db::backup_database::BackupDatabase;
use crate::{AccountDbKey, StorageError};

impl BackupDatabase {
    /// Normalizes this private generation before archive activation or index selection.
    /// The empty peer carries schema and account identity only; all authority is local.
    /// # Errors
    /// Refuses malformed graphs and storage failures, rolling back all row changes.
    #[doc(hidden)]
    pub fn normalize_backup_candidate(&mut self) -> Result<(), StorageError> {
        let key = AccountDbKey::generate()?;
        self.db.execute_batch(&format!(
            "ATTACH DATABASE ':memory:' AS incoming KEY \"x'{}'\"",
            key.sqlcipher_hex()
        ))?;
        let result = (|| {
            let tables = self.db.prepare("SELECT name FROM main.sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")?
                .query_map([], |r| r.get::<_, String>(0))?.collect::<rusqlite::Result<Vec<_>>>()?;
            for table in tables {
                let name = table.replace('"', "\"\"");
                self.db.execute_batch(&format!(
                    "CREATE TABLE incoming.\"{name}\" AS SELECT * FROM main.\"{name}\" WHERE 0"
                ))?;
            }
            // No message, binding, deletion, reference, or payload rows enter the peer.
            self.db.execute_batch("INSERT INTO incoming.runtime_account_identity SELECT * FROM main.runtime_account_identity; INSERT INTO incoming.schema_migration SELECT * FROM main.schema_migration; INSERT INTO incoming.account_mac_bundle SELECT * FROM main.account_mac_bundle;")?;
            self.begin_merge_inputs(true, |_| Ok(()))?;
            self.merge_object_erasure(&mut || Ok(()))?;
            self.merge_contact_fences()?;
            self.prepare_conversation_counts()?;
            self.finish_merge()
        })();
        if result.is_err() {
            let _ = self.db.execute_batch("ROLLBACK");
        }
        self.db.execute_batch("DETACH DATABASE incoming")?;
        result
    }
}
