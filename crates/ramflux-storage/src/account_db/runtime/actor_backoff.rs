// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Indexed eligibility and bounded cleanup for private actor-row retry fences.
use super::super::AccountDb;
use crate::StorageError;
use rusqlite::params;

impl AccountDb {
    /// Read eligible keys without letting backed-off rows occupy a page slot.
    ///
    /// Retry metadata lives at `backoff_prefix + item_key` and contains `next_at`.
    /// Missing or malformed metadata is eligible; the original item is never hidden forever.
    /// # Errors
    /// Rejects unsupported prefixes and returns SQLite failures.
    pub fn actor_state_ready_key_page(
        &self,
        prefix: &str,
        backoff_prefix: &str,
        now: i64,
        limit: u32,
    ) -> Result<Vec<String>, StorageError> {
        let end = super::control::namespace_end(prefix)?;
        let _backoff_end = super::control::namespace_end(backoff_prefix)?;
        let mut query = self.connection.prepare(
            "SELECT item.state_kind FROM runtime_actor_state item
             LEFT JOIN runtime_actor_state retry ON retry.state_kind=?3||item.state_kind
             WHERE item.state_kind>=?1 AND item.state_kind<?2
             AND CASE WHEN json_valid(CAST(retry.state_json AS TEXT))
                 THEN min(COALESCE(CAST(json_extract(CAST(retry.state_json AS TEXT),'$.next_at') AS INTEGER),0),
                     COALESCE(CAST(json_extract(CAST(retry.state_json AS TEXT),'$.expires_at') AS INTEGER),0))
                 ELSE 0 END<=?4
             ORDER BY item.state_kind LIMIT ?5",
        )?;
        Ok(query
            .query_map(params![prefix, end, backoff_prefix, now, limit.min(4096)], |row| {
                row.get(0)
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// Remove a bounded page of expired/orphan retry metadata, preserving original rows.
    ///
    /// Participates in the caller's writer transaction when present.
    /// # Errors
    /// Rejects unsupported prefixes and returns SQLite failures.
    pub fn prune_actor_state_backoff(
        &self,
        backoff_prefix: &str,
        now: i64,
        limit: u32,
    ) -> Result<(), StorageError> {
        let end = super::control::namespace_end(backoff_prefix)?;
        self.connection.execute(
            "DELETE FROM runtime_actor_state WHERE state_kind IN (
                SELECT retry.state_kind FROM runtime_actor_state retry
                WHERE retry.state_kind>=?1 AND retry.state_kind<?2 AND (
                    NOT EXISTS(SELECT 1 FROM runtime_actor_state item
                        WHERE item.state_kind=substr(retry.state_kind,length(?1)+1))
                    OR CASE WHEN json_valid(CAST(retry.state_json AS TEXT))
                        THEN COALESCE(CAST(json_extract(CAST(retry.state_json AS TEXT),'$.expires_at') AS INTEGER),0)
                        ELSE 0 END<=?3)
                ORDER BY retry.state_kind LIMIT ?4)",
            params![backoff_prefix, end, now, limit.min(4096)],
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ready_pages_skip_backoff_before_limit_and_cleanup_never_deletes_originals()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = std::env::temp_dir().join(format!(
            "rf-actor-backoff-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_nanos()
        ));
        let index = crate::AccountIndex::open(&root)?;
        index.create_account("a", "root")?;
        let db = AccountDb::open(&index, "a", &crate::AccountDbKey::derive("a", b"secret"))?;
        let value = serde_json::json!({"keep":"original lease"});
        for id in ["lease/a", "lease/b", "neighbor/a"] {
            db.persist_actor_state(id, &value)?;
        }
        db.persist_actor_state(
            "retry/lease/a",
            &serde_json::json!({"next_at":300,"expires_at":600}),
        )?;
        assert_eq!(db.actor_state_ready_key_page("lease/", "retry/", 0, 1)?, vec!["lease/b"]);
        assert_eq!(db.load_actor_state::<serde_json::Value>("lease/a")?, Some(value.clone()));
        assert_eq!(db.actor_state_ready_key_page("lease/", "retry/", 300, 1)?, vec!["lease/a"]);
        // Even damaged retry metadata cannot hide an item indefinitely.
        db.persist_actor_state(
            "retry/lease/a",
            &serde_json::json!({"next_at":900,"expires_at":10}),
        )?;
        assert_eq!(db.actor_state_ready_key_page("lease/", "retry/", 11, 1)?, vec!["lease/a"]);
        db.connection.execute(
            "UPDATE runtime_actor_state SET state_json=?1 WHERE state_kind='retry/lease/a'",
            params![b"{".as_slice()],
        )?;
        assert_eq!(db.actor_state_ready_key_page("lease/", "retry/", 0, 1)?, vec!["lease/a"]);
        db.prune_actor_state_backoff("retry/", 0, 128)?;
        assert!(!db.actor_state_exists("retry/lease/a")?);
        db.persist_actor_state(
            "retry/lease/missing",
            &serde_json::json!({"next_at":900,"expires_at":1000}),
        )?;
        db.prune_actor_state_backoff("retry/", 0, 128)?;
        assert!(!db.actor_state_exists("retry/lease/missing")?);
        assert_eq!(db.load_actor_state::<serde_json::Value>("lease/a")?, Some(value));
        drop((db, index));
        std::fs::remove_dir_all(root)?;
        Ok(())
    }
}
