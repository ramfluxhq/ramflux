// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Account-database backend of the MLS key-value storage (`ramflux-mls`, table `mls_kv`).
//!
//! The table is local to the device: backups, transfers and merges never carry it. Reads return
//! `Zeroizing` buffers. A flush is ONE immediate transaction that applies the MLS rows in order and
//! then runs the caller's closure, so the caller's rows commit or roll back together with them.
//! After a flush that changed epoch secrets the WAL is truncated so deleted secrets do not linger.
use super::{AccountDb, StorageError};
use zeroize::Zeroizing;

const WRITE_SQL: &str = "INSERT INTO mls_kv(label,key,value) VALUES(?1,?2,?3) \
    ON CONFLICT(label,key) DO UPDATE SET value=excluded.value";
const DELETE_SQL: &str = "DELETE FROM mls_kv WHERE label=?1 AND key=?2";

/// One buffered MLS row write.
#[derive(Debug)]
pub enum MlsKvWrite {
    /// Insert or replace a row.
    Put {
        /// Row label.
        label: String,
        /// Row key.
        key: Vec<u8>,
        /// Row value (zeroized after the write).
        value: Zeroizing<Vec<u8>>,
    },
    /// Remove a row (no error when absent).
    Delete {
        /// Row label.
        label: String,
        /// Row key.
        key: Vec<u8>,
    },
}

/// A SQL parameter a caller row may bind.
#[derive(Debug)]
pub enum MlsKvParam {
    /// SQL NULL.
    Null,
    /// Integer.
    Integer(i64),
    /// Text.
    Text(String),
    /// Blob.
    Blob(Vec<u8>),
}

/// Statistics of the `mls_kv` table.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MlsKvStats {
    /// Number of rows.
    pub rows: u64,
    /// Size in bytes of the largest value.
    pub largest_value_bytes: u64,
}

/// The transaction a flush hands to the caller's closure; it lives only inside the flush.
pub struct MlsKvTx<'a> {
    tx: &'a rusqlite::Transaction<'a>,
}

impl MlsKvTx<'_> {
    /// Execute one statement of the caller's rows inside the flush transaction.
    ///
    /// # Errors
    /// SQLite errors; the whole flush then rolls back.
    pub fn execute(&mut self, sql: &str, params: &[MlsKvParam]) -> Result<usize, StorageError> {
        let values = params.iter().map(|param| match param {
            MlsKvParam::Null => rusqlite::types::Value::Null,
            MlsKvParam::Integer(value) => rusqlite::types::Value::Integer(*value),
            MlsKvParam::Text(value) => rusqlite::types::Value::Text(value.clone()),
            MlsKvParam::Blob(value) => rusqlite::types::Value::Blob(value.clone()),
        });
        Ok(self.tx.execute(sql, rusqlite::params_from_iter(values))?)
    }
}

/// Why a flush failed.
#[derive(Debug)]
pub enum MlsKvCommitError<E> {
    /// The database failed (the transaction rolled back).
    Storage(StorageError),
    /// The caller's closure failed (the transaction rolled back).
    Caller(E),
}

/// Cheap handle on the account database for the MLS runtime. It shares the database worker, so it
/// must be dropped together with the account runtime.
#[derive(Clone)]
pub struct MlsKvStore {
    connection: crate::database::Connection,
}

impl AccountDb {
    /// A handle for the MLS key-value storage on this account database.
    #[must_use]
    pub fn mls_kv(&self) -> MlsKvStore {
        MlsKvStore { connection: self.connection.clone() }
    }
}

impl MlsKvStore {
    /// Whether `other` talks to the same database worker.
    #[must_use]
    pub fn same_database(&self, other: &Self) -> bool {
        self.connection.same_worker(&other.connection)
    }

    /// Read one row; the value is zeroized when dropped.
    ///
    /// # Errors
    /// SQLite errors.
    pub fn get(&self, label: &str, key: &[u8]) -> Result<Option<Zeroizing<Vec<u8>>>, StorageError> {
        let (label, key) = (label.to_owned(), key.to_vec());
        Ok(self.connection.call(move |db| {
            let mut statement =
                db.prepare_cached("SELECT value FROM mls_kv WHERE label=?1 AND key=?2")?;
            let mut rows = statement.query(rusqlite::params![label, key])?;
            match rows.next()? {
                Some(row) => Ok(Some(Zeroizing::new(row.get_ref(0)?.as_blob()?.to_vec()))),
                None => Ok(None),
            }
        })?)
    }

    /// Row count and largest value size of the whole table.
    ///
    /// # Errors
    /// SQLite errors.
    pub fn stats(&self) -> Result<MlsKvStats, StorageError> {
        let (rows, largest): (i64, i64) = self.connection.call(|db| {
            db.query_row("SELECT COUNT(*), COALESCE(MAX(length(value)),0) FROM mls_kv", [], |row| {
                Ok((row.get(0)?, row.get(1)?))
            })
        })?;
        Ok(MlsKvStats {
            rows: u64::try_from(rows).unwrap_or(0),
            largest_value_bytes: u64::try_from(largest).unwrap_or(0),
        })
    }

    /// Apply `writes` in order and then `caller` inside ONE immediate transaction. Any error rolls
    /// everything back. After a commit with `epoch_changed` the WAL is truncated (a busy or failed
    /// checkpoint falls back to the background checkpoint schedule).
    ///
    /// # Errors
    /// [`MlsKvCommitError::Storage`] for database failures (also when an outer transaction is
    /// open), [`MlsKvCommitError::Caller`] for an error of `caller`.
    pub fn commit_batch<E, F>(
        &self,
        writes: Vec<MlsKvWrite>,
        epoch_changed: bool,
        caller: F,
    ) -> Result<(), MlsKvCommitError<E>>
    where
        E: Send + 'static,
        F: for<'a> FnOnce(&mut MlsKvTx<'a>) -> Result<(), E> + Send + 'static,
    {
        let outcome = self
            .connection
            .call_immediate_result(move |tx| {
                for write in &writes {
                    match write {
                        MlsKvWrite::Put { label, key, value } => {
                            tx.prepare_cached(WRITE_SQL)?.execute(rusqlite::params![
                                label,
                                key,
                                value.as_slice()
                            ])?;
                        }
                        MlsKvWrite::Delete { label, key } => {
                            tx.prepare_cached(DELETE_SQL)?
                                .execute(rusqlite::params![label, key])?;
                        }
                    }
                }
                let mut handle = MlsKvTx { tx };
                caller(&mut handle).map_err(FlushError::Caller)
            })
            .map_err(|error| MlsKvCommitError::Storage(error.into()))?;
        // A rusqlite error inside the writes arrives through `FlushError::Sqlite`.
        outcome.map_err(|error| match error {
            FlushError::Sqlite(error) => MlsKvCommitError::Storage(error.into()),
            FlushError::Caller(error) => MlsKvCommitError::Caller(error),
        })?;
        if epoch_changed {
            self.truncate_wal_or_schedule();
        }
        Ok(())
    }

    /// Mirror of `checkpoint_retired_secrets_if_committed`: truncate the WAL now; when SQLite
    /// reports busy or the checkpoint fails, request the background checkpoint.
    fn truncate_wal_or_schedule(&self) {
        let truncated = self.connection.call(|db| {
            db.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| row.get::<_, i64>(0))
        });
        if !matches!(truncated, Ok(0)) {
            self.connection.request_background_checkpoint();
        }
    }
}

enum FlushError<E> {
    Sqlite(rusqlite::Error),
    Caller(E),
}

impl<E> From<rusqlite::Error> for FlushError<E> {
    fn from(error: rusqlite::Error) -> Self {
        Self::Sqlite(error)
    }
}
