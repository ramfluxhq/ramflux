// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Encrypted control records and atomic multi-record state updates.

use super::super::AccountDb;
use crate::StorageError;
use rusqlite::{OptionalExtension, params};
use zeroize::Zeroizing;

impl AccountDb {
    /// Tests actor-state presence without decoding a private snapshot.
    /// # Errors
    /// Returns SQLite errors.
    pub fn actor_state_exists(&self, kind: &str) -> Result<bool, StorageError> {
        Ok(self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM runtime_actor_state WHERE state_kind=?1)",
            params![kind],
            |row| row.get(0),
        )?)
    }

    /// # Errors
    /// Returns an error when the account-owned control state cannot be committed.
    pub fn persist_actor_state<T: serde::Serialize>(
        &self,
        kind: &str,
        state: &T,
    ) -> Result<(), StorageError> {
        let encoded = Zeroizing::new(serde_json::to_vec(state)?);
        self.connection.execute("INSERT INTO runtime_actor_state(state_kind,state_json) VALUES(?1,?2) ON CONFLICT(state_kind) DO UPDATE SET state_json=excluded.state_json WHERE state_json<>excluded.state_json", params![kind,encoded.as_slice()])?;
        Ok(())
    }

    /// # Errors
    /// Returns an error when a control-state batch or its outbox rows cannot commit together.
    pub fn persist_actor_state_batch<T: serde::Serialize>(
        &self,
        states: &[(String, T)],
    ) -> Result<(), StorageError> {
        if states.is_empty() {
            return Ok(());
        }
        let transaction = self.connection.immediate_transaction()?;
        for (kind, state) in states {
            self.persist_actor_state(kind, state)?;
        }
        transaction.commit()?;
        Ok(())
    }

    /// # Errors
    /// Returns an error when the requested persisted control-state list cannot be decoded.
    pub fn list_actor_states<T: serde::de::DeserializeOwned>(
        &self,
        prefix: &str,
    ) -> Result<Vec<T>, StorageError> {
        let mut statement = self.connection.prepare("SELECT state_json FROM runtime_actor_state WHERE substr(state_kind,1,length(?1))=?1 ORDER BY state_kind")?;
        statement
            .query_map(params![prefix], |row| row.get::<_, Vec<u8>>(0))?
            .map(|row| {
                let body = Zeroizing::new(row?);
                Ok(serde_json::from_slice(&body)?)
            })
            .collect()
    }

    /// # Errors
    /// Returns an error when the account-owned control state cannot be reconstructed.
    pub fn load_actor_state<T: serde::de::DeserializeOwned>(
        &self,
        kind: &str,
    ) -> Result<Option<T>, StorageError> {
        let body: Option<Vec<u8>> = self
            .connection
            .query_row(
                "SELECT state_json FROM runtime_actor_state WHERE state_kind=?1",
                params![kind],
                |row| row.get(0),
            )
            .optional()?;
        body.map(|body| {
            let body = Zeroizing::new(body);
            serde_json::from_slice(&body).map_err(StorageError::from)
        })
        .transpose()
    }
}

impl AccountDb {
    /// Removes private actor state in the caller's transaction.
    /// # Errors
    /// Returns SQLite errors.
    pub fn remove_actor_state(&self, key: &str) -> Result<(), StorageError> {
        self.connection.execute(
            "DELETE FROM runtime_actor_state WHERE state_kind=?1",
            rusqlite::params![key],
        )?;
        Ok(())
    }
}

fn namespace_end(prefix: &str) -> Result<String, StorageError> {
    let mut bytes = prefix.as_bytes().to_vec();
    let last = bytes.pop().filter(|byte| *byte < 127).ok_or(StorageError::AuthorizationRejected)?;
    bytes.push(last + 1);
    String::from_utf8(bytes).map_err(|_| StorageError::AuthorizationRejected)
}
impl AccountDb {
    /// Count records and encoded bytes with an indexed namespace range, without decoding values.
    /// # Errors
    /// Rejects an empty prefix or a non-ASCII final character; returns SQL errors.
    pub fn actor_state_usage(&self, prefix: &str) -> Result<(u64, u64), StorageError> {
        let end = namespace_end(prefix)?;
        Ok(self.connection.query_row("SELECT count(*),coalesce(sum(length(state_json)),0) FROM runtime_actor_state WHERE state_kind>=?1 AND state_kind<?2",params![prefix,end],|row|Ok((row.get(0)?,row.get(1)?)))?)
    }
    /// Reads an indexed namespace page strictly after a durable queue cursor.
    ///
    /// # Errors
    /// Rejects an out-of-namespace cursor, unsupported prefix or SQL failures.
    pub fn actor_state_key_page_after(
        &self,
        prefix: &str,
        after: &str,
        limit: u32,
    ) -> Result<Vec<String>, StorageError> {
        if !after.is_empty() && !after.starts_with(prefix) {
            return Err(StorageError::AuthorizationRejected);
        }
        let end = namespace_end(prefix)?;
        let mut query=self.connection.prepare("SELECT state_kind FROM runtime_actor_state WHERE state_kind>=?1 AND state_kind<?2 AND state_kind>?3 ORDER BY state_kind LIMIT ?4")?;
        Ok(query
            .query_map(params![prefix, end, after, limit.min(4096)], |row| row.get(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// Read a bounded page of namespace keys without decoding private state values.
    /// # Errors
    /// Rejects unsupported prefixes and returns SQL errors.
    pub fn actor_state_key_page(
        &self,
        prefix: &str,
        limit: u32,
    ) -> Result<Vec<String>, StorageError> {
        let end = namespace_end(prefix)?;
        let mut query=self.connection.prepare("SELECT state_kind FROM runtime_actor_state WHERE state_kind>=?1 AND state_kind<?2 ORDER BY state_kind LIMIT ?3")?;
        Ok(query
            .query_map(params![prefix, end, limit.min(4096)], |row| row.get(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn actor_queue_usage_and_pages_exclude_neighbor_namespaces()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = std::env::temp_dir().join(format!(
            "rf-queue-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_nanos()
        ));
        let index = crate::AccountIndex::open(&root)?;
        index.create_account("a", "root")?;
        let db = AccountDb::open(&index, "a", &crate::AccountDbKey::derive("a", b"secret"))?;
        let body = serde_json::json!({"payload":"中文 🦀"});
        for key in ["queue/a", "queue/b", "queue0/a", "queud/a", "unrelated/a"] {
            db.persist_actor_state(key, &body)?;
        }
        assert_eq!(db.actor_state_key_page("queue/", 1)?, vec!["queue/a"]);
        assert_eq!(db.actor_state_key_page("queue/", 0)?, Vec::<String>::new());
        assert_eq!(
            db.actor_state_usage("queue/")?,
            (2, 2 * u64::try_from(serde_json::to_vec(&body)?.len())?)
        );
        db.remove_actor_state("queue/a")?;
        assert_eq!(db.actor_state_key_page("queue/", 10)?, vec!["queue/b"]);
        assert_eq!(db.actor_state_usage("empty/")?, (0, 0));
        assert!(db.actor_state_usage("").is_err());
        drop(db);
        drop(index);
        std::fs::remove_dir_all(root)?;
        Ok(())
    }
}
