// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Expiry and fixed row budgets for disposable actor receipts, statuses and reply intents.
use super::super::AccountDb;
use crate::StorageError;
use rusqlite::params;
impl AccountDb {
    /// Retains pending rows before acknowledged/completed rows, oldest confirmed rows first.
    ///
    /// The private namespace has the same expiry contract as `retain_expiring_actor_states`.
    /// Supports bounded delivery windows up to 32,768 rows without changing other callers' caps.
    /// # Errors
    /// Rejects invalid prefixes or budgets and returns storage errors atomically.
    pub fn retain_delivery_actor_states(
        &self,
        prefix: &str,
        now: i64,
        limit: u32,
    ) -> Result<(), StorageError> {
        if limit > 32_768 {
            return Err(StorageError::AuthorizationRejected);
        }
        if self.retain_indexed_own_copy_states(prefix, now, limit)? {
            return Ok(());
        }
        self.retain_actor_states(prefix, now, Some(limit), true)
    }

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
        self.retain_actor_states(prefix, now, Some(limit.min(4096)), false)
    }

    /// Delete expired or legacy undated rows without evicting any live receipt.
    /// # Errors
    /// Rejects empty/non-ASCII prefixes and returns SQL errors atomically.
    pub fn expire_actor_states(&self, prefix: &str, now: i64) -> Result<(), StorageError> {
        self.retain_actor_states(prefix, now, None, false)
    }

    fn retain_actor_states(
        &self,
        prefix: &str,
        now: i64,
        limit: Option<u32>,
        pending_first: bool,
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
            if let Some(limit) = limit {
                self.connection.execute(
                "DELETE FROM runtime_actor_state WHERE state_kind IN (SELECT state_kind FROM runtime_actor_state WHERE state_kind>=?1 AND state_kind<?2 ORDER BY CASE WHEN ?4 THEN COALESCE(json_extract(CAST(state_json AS TEXT),'$.completed'),json_extract(CAST(state_json AS TEXT),'$.acknowledged'),0) ELSE 0 END ASC,CAST(json_extract(CAST(state_json AS TEXT),'$.expires_at') AS INTEGER) DESC,state_kind DESC LIMIT -1 OFFSET ?3)",
                    params![prefix,end,limit,pending_first],
                )?;
            }
            Ok(())
        })
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn expiry_only_retains_every_live_pending_row() -> Result<(), Box<dyn std::error::Error>> {
        let (_root, db) = crate::tests::test_db("expiry-only")?;
        for (key, expiry) in [("receipt/expired", 9), ("receipt/live", 11), ("receipt/other", 12)] {
            db.persist_actor_state(
                key,
                &serde_json::json!({"expires_at":expiry,"completed":false}),
            )?;
        }
        db.persist_actor_state("receipt0/neighbor", &"keep")?;
        db.expire_actor_states("receipt/", 10)?;
        assert_eq!(
            db.actor_state_key_page("receipt/", 10)?,
            vec!["receipt/live", "receipt/other"],
            "expiry-only must preserve every live pending row"
        );
        assert!(
            db.actor_state_exists("receipt0/neighbor")?,
            "neighbor namespace remains untouched"
        );
        assert!(
            db.expire_actor_states("", 10).is_err(),
            "empty prefix cannot delete all namespaces"
        );
        Ok(())
    }

    #[test]
    fn delivery_retention_keeps_pending_rows_and_supports_the_larger_stream_budget()
    -> Result<(), Box<dyn std::error::Error>> {
        let (_root, db) = crate::tests::test_db("delivery-retention")?;
        db.write_transaction(|| {
            for i in 0..5000 {
                db.persist_actor_state(
                    &format!("receipt/{i:05}"),
                    &serde_json::json!({"expires_at":100 + i,"acknowledged":true}),
                )?;
            }
            Ok::<_, StorageError>(())
        })?;
        db.retain_delivery_actor_states("receipt/", 0, 5000)?;
        assert_eq!(db.actor_state_usage("receipt/")?.0, 5000);
        db.persist_actor_state(
            "receipt/pending",
            &serde_json::json!({"expires_at":20,"acknowledged":false}),
        )?;
        db.persist_actor_state(
            "receipt/unconfirmed",
            &serde_json::json!({"expires_at":30,"acknowledged":false}),
        )?;
        db.persist_actor_state("receipt0/neighbor", &"keep")?;
        db.retain_delivery_actor_states("receipt/", 0, 3)?;
        assert_eq!(
            db.actor_state_key_page("receipt/", 10)?,
            vec!["receipt/04999", "receipt/pending", "receipt/unconfirmed"]
        );
        db.retain_delivery_actor_states("receipt/", 0, 2)?;
        assert_eq!(
            db.actor_state_key_page("receipt/", 10)?,
            vec!["receipt/pending", "receipt/unconfirmed"]
        );
        db.retain_delivery_actor_states("receipt/", 20, 2)?;
        assert_eq!(db.actor_state_key_page("receipt/", 10)?, vec!["receipt/unconfirmed"]);
        assert!(db.actor_state_exists("receipt0/neighbor")?);
        assert!(db.retain_delivery_actor_states("receipt/", 0, 32_769).is_err());
        drop(db);
        Ok(())
    }

    #[test]
    fn expiry_and_row_cap_prune_only_the_selected_namespace()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = ramflux_test_support::TestPath::new()
            .expect("test: allocate fixture directory")
            .child(format!(
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
        Ok(())
    }
}
