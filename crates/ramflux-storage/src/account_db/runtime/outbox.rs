// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Bounded unpublished pages and durable router acceptance markers.

use super::super::AccountDb;
use super::AccountOutboxEntry;
use crate::StorageError;
use rusqlite::params;

impl AccountDb {
    /// # Errors
    /// Returns an error if the bounded unpublished outbox page cannot be read.
    pub fn pending_outbox(&self, limit: u32) -> Result<Vec<AccountOutboxEntry>, StorageError> {
        let mut statement = self.connection.prepare(
            "SELECT sequence,table_name,change_kind,row_id,keys_json FROM runtime_outbox WHERE published=0 ORDER BY sequence LIMIT ?1"
        )?;
        Ok(statement
            .query_map(params![limit.min(256)], |row| {
                Ok(AccountOutboxEntry {
                    sequence: row.get(0)?,
                    table_name: row.get(1)?,
                    change_kind: row.get(2)?,
                    row_id: row.get(3)?,
                    keys: row
                        .get::<_, Option<String>>(4)?
                        .map(|value| serde_json::from_str(&value))
                        .transpose()
                        .map_err(|error| {
                            rusqlite::Error::FromSqlConversionFailure(
                                4,
                                rusqlite::types::Type::Text,
                                Box::new(error),
                            )
                        })?
                        .unwrap_or(serde_json::Value::Null),
                })
            })?
            .collect::<rusqlite::Result<_>>()?)
    }

    /// Finds the newest unpublished change for one actor-state key.
    /// # Errors
    /// Returns an error when the outbox cannot be read.
    pub fn pending_actor_state_sequence(&self, kind: &str) -> Result<Option<i64>, StorageError> {
        Ok(self.connection.query_row(
            "SELECT max(sequence) FROM runtime_outbox WHERE published=0 AND table_name='runtime_actor_state' AND actor_state_kind=?1",
            params![kind],
            |row| row.get(0),
        )?)
    }

    /// # Errors
    /// Returns an error when an acknowledged outbox page cannot be marked published.
    pub fn mark_outbox_published(&self, sequence: i64) -> Result<(), StorageError> {
        self.connection.execute(
            "UPDATE runtime_outbox SET published=1 WHERE published=0 AND sequence<=?1",
            params![sequence],
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pending_actor_sequence_selects_latest_matching_unpublished_entry()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = ramflux_test_support::TestPath::new()
            .expect("test: allocate fixture directory")
            .child(format!(
                "rf-outbox-{}-{}",
                std::process::id(),
                std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_nanos()
            ));
        let index = crate::AccountIndex::open(&root)?;
        index.create_account("a", "root")?;
        let db = AccountDb::open(&index, "a", &crate::AccountDbKey::derive("a", b"secret"))?;
        let mut plan = db.connection.prepare(
            "EXPLAIN QUERY PLAN SELECT max(sequence) FROM runtime_outbox WHERE published=0 AND table_name='runtime_actor_state' AND actor_state_kind=?1",
        )?;
        let details = plan
            .query_map(params!["account/networking"], |row| row.get::<_, String>(3))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        assert!(
            details.iter().any(|line| line.contains("runtime_outbox_actor_kind")),
            "{details:?}"
        );
        drop(plan);
        assert_eq!(db.pending_actor_state_sequence("account/networking")?, None);
        db.persist_actor_state("account/networking", &1)?;
        let first = db.pending_actor_state_sequence("account/networking")?.ok_or("first")?;
        db.persist_actor_state("account/networking", &2)?;
        let second = db.pending_actor_state_sequence("account/networking")?.ok_or("second")?;
        assert!(second > first);
        db.persist_actor_state("account/other", &3)?;
        assert_eq!(db.pending_actor_state_sequence("account/networking")?, Some(second));
        db.mark_outbox_published(first)?;
        assert_eq!(db.pending_actor_state_sequence("account/networking")?, Some(second));
        db.mark_outbox_published(second)?;
        assert_eq!(db.pending_actor_state_sequence("account/networking")?, None);
        drop(db);
        drop(index);
        std::fs::remove_dir_all(root)?;
        Ok(())
    }
}
