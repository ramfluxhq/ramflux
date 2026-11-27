// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! `ramflux_mls::MlsKv` on the `SQLCipher` account database (table `mls_kv`).
use ramflux_mls::{MlsKv, MlsKvError, RowStats, WriteBatch, WriteOp};
use ramflux_storage::{MlsKvCommitError, MlsKvStore, MlsKvTx, MlsKvWrite};
use zeroize::Zeroizing;

/// The account database as the MLS key-value backend. Cheap to clone; shares the database worker.
#[derive(Clone)]
pub struct SqlMlsKv {
    store: MlsKvStore,
}

impl SqlMlsKv {
    /// Wrap the account database handle.
    #[must_use]
    pub fn new(store: MlsKvStore) -> Self {
        Self { store }
    }

    /// Whether this adapter talks to the same database as `store`.
    #[must_use]
    pub fn is_on(&self, store: &MlsKvStore) -> bool {
        self.store.same_database(store)
    }
}

fn backend(error: &ramflux_storage::StorageError) -> MlsKvError {
    MlsKvError::Backend(error.to_string())
}

impl MlsKv for SqlMlsKv {
    type Tx<'a> = MlsKvTx<'a>;

    fn get(&self, label: &str, key: &[u8]) -> Result<Option<Zeroizing<Vec<u8>>>, MlsKvError> {
        self.store.get(label, key).map_err(|error| backend(&error))
    }

    fn row_stats(&self) -> Result<RowStats, MlsKvError> {
        let stats = self.store.stats().map_err(|error| backend(&error))?;
        Ok(RowStats { rows: stats.rows, largest_value_bytes: stats.largest_value_bytes })
    }

    fn commit_batch<F>(&self, batch: WriteBatch, caller: F) -> Result<(), MlsKvError>
    where
        F: for<'a> FnOnce(&mut Self::Tx<'a>) -> Result<(), MlsKvError> + Send + 'static,
    {
        let WriteBatch { ops, epoch_changed } = batch;
        let writes = ops
            .into_iter()
            .map(|op| match op {
                WriteOp::Put { label, key, value } => MlsKvWrite::Put { label, key, value },
                WriteOp::Delete { label, key } => MlsKvWrite::Delete { label, key },
            })
            .collect();
        self.store.commit_batch(writes, epoch_changed, caller).map_err(|error| match error {
            MlsKvCommitError::Storage(error) => backend(&error),
            MlsKvCommitError::Caller(error) => error,
        })
    }
}
