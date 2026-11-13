// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Opt-in test instrumentation for all statements on the account writer connection.
use crate::{AccountDb, StorageError};
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

struct ProgressReset<'a>(&'a AccountDb);
impl Drop for ProgressReset<'_> {
    fn drop(&mut self) {
        let _ = self.0.connection.call(|connection| {
            connection.progress_handler(0, None::<fn() -> bool>)?;
            Ok(())
        });
    }
}

impl AccountDb {
    /// Counts SQLite VM instructions, including triggers, executed by a synchronous test operation.
    /// Enabled only by `test-instrumentation`; use a dedicated account with no concurrent writers.
    /// The handler is removed even if the operation returns an error or unwinds.
    /// # Errors
    /// Returns an error if installing instrumentation on the writer fails.
    pub fn measure_sqlite_vm_steps<T>(
        &self,
        operation: impl FnOnce() -> T,
    ) -> Result<(T, u64), StorageError> {
        let steps = Arc::new(AtomicU64::new(0));
        let counter = steps.clone();
        self.connection.call(move |connection| {
            connection.progress_handler(
                1,
                Some(move || {
                    counter.fetch_add(1, Ordering::Relaxed);
                    false
                }),
            )?;
            Ok(())
        })?;
        let reset = ProgressReset(self);
        let result = operation();
        drop(reset);
        Ok((result, steps.load(Ordering::Relaxed)))
    }
}

struct CommitReset<'a>(&'a AccountDb);
impl Drop for CommitReset<'_> {
    fn drop(&mut self) {
        let _ = self.0.connection.call(|connection| {
            connection.commit_hook(None::<fn() -> bool>)?;
            Ok(())
        });
    }
}
impl AccountDb {
    /// Reject the first real SQLite commit in a synchronous test operation.
    /// Available only with test instrumentation; use a dedicated account writer.
    /// The commit hook is removed on success, failure and unwind.
    /// # Errors
    /// Returns hook installation errors. The callback's result is returned unchanged.
    pub fn reject_next_sqlite_commit<T>(
        &self,
        operation: impl FnOnce() -> T,
    ) -> Result<(T, u64), StorageError> {
        let commits = Arc::new(AtomicU64::new(0));
        let counter = commits.clone();
        self.connection.call(move |connection| {
            connection.commit_hook(Some(move || counter.fetch_add(1, Ordering::Relaxed) == 0))?;
            Ok(())
        })?;
        let reset = CommitReset(self);
        let result = operation();
        drop(reset);
        Ok((result, commits.load(Ordering::Relaxed)))
    }
}

impl AccountDb {
    /// Hash every logical table row, excluding only explicitly named actor-state keys.
    /// Test instrumentation only; compare a dedicated account with no concurrent writer.
    /// Returned values contain hashes rather than private row payloads.
    /// # Errors
    /// Returns SQLite errors enumerating the pinned account snapshot.
    pub fn test_table_fingerprints(
        &self,
        allowed_actor_keys: &[String],
    ) -> Result<std::collections::BTreeMap<String, Vec<[u8; 32]>>, StorageError> {
        let allowed = allowed_actor_keys.to_vec();
        self.connection
            .call(move |db| {
                let tables = db
                    .prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")?
                    .query_map([], |row| row.get::<_, String>(0))?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                let mut snapshot = std::collections::BTreeMap::new();
                for table in tables {
                    let sql = format!("SELECT * FROM \"{}\"", table.replace('"', "\"\""));
                    let mut query = db.prepare(&sql)?;
                    let columns = query.column_count();
                    let mut rows = query.query([])?;
                    let mut fingerprints = Vec::new();
                    while let Some(row) = rows.next()? {
                        if table == "runtime_actor_state"
                            && allowed.contains(&row.get::<_, String>("state_kind")?)
                        {
                            continue;
                        }
                        let mut hasher = blake3::Hasher::new();
                        for index in 0..columns {
                            let value = row.get::<_, rusqlite::types::Value>(index)?;
                            let encoded = format!("{value:?}");
                            hasher.update(&(encoded.len() as u64).to_be_bytes());
                            hasher.update(encoded.as_bytes());
                        }
                        fingerprints.push(*hasher.finalize().as_bytes());
                    }
                    fingerprints.sort_unstable();
                    snapshot.insert(table, fingerprints);
                }
                Ok(snapshot)
            })
            .map_err(StorageError::from)
    }
}
