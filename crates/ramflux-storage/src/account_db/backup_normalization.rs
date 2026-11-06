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
            capture_input_deletions(&self.db)?;
            crate::account_db::large_segments::retirement::merge_floors(&self.db)?;
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

fn capture_input_deletions(db: &rusqlite::Connection) -> Result<(), StorageError> {
    let mut query = db.prepare("SELECT r.reference_hash,m.message_id,r.selector,r.commitment FROM main.object_retention_reference r JOIN main.object_message_reference m USING(reference_hash)")?;
    let mut rows = query.query([])?;
    while let Some(row) = rows.next()? {
        let message: String = row.get(1)?;
        if crate::account_db::backup_selector_admission::graph::target_deleted(db, &message)? {
            db.execute(
                "INSERT OR IGNORE INTO main.backup_target_delete VALUES(?1,?2,?3,?4)",
                rusqlite::params![
                    row.get::<_, String>(0)?,
                    message,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?
                ],
            )?;
        }
    }
    Ok(())
}
