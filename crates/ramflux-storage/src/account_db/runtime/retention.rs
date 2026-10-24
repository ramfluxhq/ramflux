// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Expiry and fixed row budgets for disposable actor receipts, statuses and reply intents.
use super::super::AccountDb;
use crate::StorageError;
use rusqlite::params;
impl AccountDb {
    /// Delete expired (or legacy undated) records and retain at most `limit` live rows.
    /// The caller supplies a private namespace whose JSON records have `expires_at` seconds.
    /// # Errors
    /// Rejects empty/non-ASCII prefixes and returns SQL errors. Runs atomically with caller writes.
    pub fn retain_expiring_actor_states(
        &self,
        prefix: &str,
        now: i64,
        limit: u32,
    ) -> Result<(), StorageError> {
        let mut bytes = prefix.as_bytes().to_vec();
        if !prefix.is_ascii() {
            return Err(StorageError::AuthorizationRejected);
        }
        let last = bytes.pop().filter(|b| *b < 127).ok_or(StorageError::AuthorizationRejected)?;
        bytes.push(last + 1);
        let end = String::from_utf8(bytes).map_err(|_| StorageError::AuthorizationRejected)?;
        self.write_transaction(|| {
            self.connection.execute(
                "DELETE FROM runtime_actor_state WHERE state_kind>=?1 AND state_kind<?2 AND CASE WHEN json_valid(CAST(state_json AS TEXT)) THEN COALESCE(CAST(json_extract(CAST(state_json AS TEXT),'$.expires_at') AS INTEGER),0) ELSE 0 END<=?3",
                params![prefix,end,now],
            )?;
            self.connection.execute(
                "DELETE FROM runtime_actor_state WHERE state_kind IN (SELECT state_kind FROM runtime_actor_state WHERE state_kind>=?1 AND state_kind<?2 ORDER BY CAST(json_extract(CAST(state_json AS TEXT),'$.expires_at') AS INTEGER) DESC,state_kind DESC LIMIT -1 OFFSET ?3)",
                params![prefix,end,limit.min(4096)],
            )?;
            Ok(())
        })
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn expiry_and_row_cap_prune_only_the_selected_namespace()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = std::env::temp_dir().join(format!(
            "rf-retain-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_nanos()
        ));
        let index = crate::AccountIndex::open(&root)?;
        index.create_account("a", "root")?;
        let db = AccountDb::open(&index, "a", &crate::AccountDbKey::derive("a", b"secret"))?;
        for (id, expiry) in [("expired", 9), ("old", 20), ("new", 30), ("newer", 40)] {
            db.persist_actor_state(
                &format!("receipt/{id}"),
                &serde_json::json!({"expires_at":expiry}),
            )?;
        }
        db.persist_actor_state("receipt/legacy", &"undated")?;
        db.persist_actor_state("receipt0/neighbor", &"keep")?;
        db.retain_expiring_actor_states("receipt/", 10, 2)?;
        assert_eq!(db.actor_state_key_page("receipt/", 10)?, vec!["receipt/new", "receipt/newer"]);
        assert!(db.actor_state_exists("receipt0/neighbor")?);
        db.retain_expiring_actor_states("receipt/", 40, 2)?;
        assert_eq!(db.actor_state_usage("receipt/")?.0, 0);
        assert!(db.retain_expiring_actor_states("", 0, 1).is_err());
        drop(db);
        drop(index);
        std::fs::remove_dir_all(root)?;
        Ok(())
    }
}
