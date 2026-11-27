// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Key-value surface the MLS storage runs on, the write overlay and the flush API.
//!
//! The account database implements [`MlsKv`] (part 0b). Reads see the overlay first, writes and
//! deletes stay in memory until [`Staged::commit`] hands them to the backend in one transaction.

use std::collections::BTreeMap;
use std::sync::{Mutex, MutexGuard};

use serde::Serialize;
use serde::de::DeserializeOwned;
use zeroize::Zeroizing;

use crate::MAX_STORED_VALUE_BYTES;

/// Storage failure.
#[derive(Debug, thiserror::Error)]
pub enum MlsKvError {
    /// The backend (database) failed.
    #[error("backend: {0}")]
    Backend(String),
    /// A value could not be encoded or decoded.
    #[error("codec: {0}")]
    Codec(String),
    /// A stored value exceeds the decode bound.
    #[error("stored value of {0} bytes exceeds the decode bound")]
    TooLarge(usize),
    /// The overlay lock was poisoned by a panic in another thread.
    #[error("overlay lock poisoned")]
    Poisoned,
}

impl From<serde_json::Error> for MlsKvError {
    fn from(error: serde_json::Error) -> Self {
        Self::Codec(error.to_string())
    }
}

/// One buffered write.
#[derive(Debug)]
pub enum WriteOp {
    /// Insert or replace a row.
    Put {
        /// Row label.
        label: String,
        /// Row key.
        key: Vec<u8>,
        /// Row value.
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

/// The buffered writes of one operation, in deterministic key order.
#[derive(Debug, Default)]
pub struct WriteBatch {
    /// Ordered writes.
    pub ops: Vec<WriteOp>,
    /// True when the batch changed epoch secrets; the backend then checkpoints the WAL.
    pub epoch_changed: bool,
}

/// Row statistics reported by the debug status.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RowStats {
    /// Number of rows.
    pub rows: u64,
    /// Size in bytes of the largest value.
    pub largest_value_bytes: u64,
}

/// Transactional key-value backend of the MLS storage.
pub trait MlsKv {
    /// Transaction handle handed to the caller closure of [`Staged::commit`].
    type Tx<'a>;

    /// Read one row.
    ///
    /// # Errors
    /// Backend failure.
    fn get(&self, label: &str, key: &[u8]) -> Result<Option<Zeroizing<Vec<u8>>>, MlsKvError>;

    /// Row statistics of `mls_kv` (the whole account, all labels).
    ///
    /// # Errors
    /// Backend failure.
    fn row_stats(&self) -> Result<RowStats, MlsKvError>;

    /// Apply `batch` and then run `caller` inside ONE immediate transaction. Any error rolls
    /// everything back. After a batch with `epoch_changed` the backend checkpoints the WAL.
    ///
    /// # Errors
    /// Backend failure or an error returned by `caller`.
    fn commit_batch<F>(&self, batch: WriteBatch, caller: F) -> Result<(), MlsKvError>
    where
        F: for<'a> FnOnce(&mut Self::Tx<'a>) -> Result<(), MlsKvError> + Send + 'static;
}

/// An operation output that is released only after its state reached the database. It holds the
/// account's operation lock, so no other operation can start between staging and commit.
pub struct Staged<'k, K: MlsKv, T> {
    kv: &'k K,
    batch: WriteBatch,
    output: T,
    _operation: MutexGuard<'k, ()>,
}

impl<'k, K: MlsKv, T> Staged<'k, K, T> {
    pub(crate) fn new(
        kv: &'k K,
        batch: WriteBatch,
        output: T,
        operation: MutexGuard<'k, ()>,
    ) -> Self {
        Self { kv, batch, output, _operation: operation }
    }

    /// Number of buffered writes (diagnostics).
    #[must_use]
    pub fn pending_writes(&self) -> usize {
        self.batch.ops.len()
    }

    /// Persist the buffered MLS rows and the caller's rows in one transaction, then release the
    /// output. On error nothing is persisted and the output is dropped.
    ///
    /// # Errors
    /// Backend failure or an error returned by `caller`.
    pub fn commit<F>(self, caller: F) -> Result<T, MlsKvError>
    where
        F: for<'a> FnOnce(&mut K::Tx<'a>) -> Result<(), MlsKvError> + Send + 'static,
    {
        self.kv.commit_batch(self.batch, caller)?;
        Ok(self.output)
    }

    /// [`Staged::commit`] with no caller rows (MLS-0 and the debug surface).
    ///
    /// # Errors
    /// Backend failure.
    pub fn commit_plain(self) -> Result<T, MlsKvError> {
        self.commit(|_tx| Ok(()))
    }
}

type RowKey = (String, Vec<u8>);

/// What the overlay knows about one row.
pub(crate) enum RowState {
    /// The overlay has no entry; ask the backend.
    Untouched,
    /// A buffered delete.
    Deleted,
    /// A buffered write.
    Value(Zeroizing<Vec<u8>>),
}

/// In-memory write overlay in front of the backend.
#[derive(Debug, Default)]
pub struct Overlay {
    rows: BTreeMap<RowKey, Option<Zeroizing<Vec<u8>>>>,
    epoch_changed: bool,
}

impl Overlay {
    pub(crate) fn put(&mut self, label: &str, key: Vec<u8>, value: Zeroizing<Vec<u8>>) {
        if label == crate::storage::LABEL_EPOCH_SECRETS {
            self.epoch_changed = true;
        }
        self.rows.insert((label.to_owned(), key), Some(value));
    }

    pub(crate) fn delete(&mut self, label: &str, key: Vec<u8>) {
        self.rows.insert((label.to_owned(), key), None);
    }

    pub(crate) fn lookup(&self, label: &str, key: &[u8]) -> RowState {
        match self.rows.get(&(label.to_owned(), key.to_vec())) {
            None => RowState::Untouched,
            Some(None) => RowState::Deleted,
            Some(Some(value)) => RowState::Value(Zeroizing::new(value.to_vec())),
        }
    }

    pub(crate) fn into_batch(self) -> WriteBatch {
        let ops = self
            .rows
            .into_iter()
            .map(|((label, key), value)| match value {
                Some(value) => WriteOp::Put { label, key, value },
                None => WriteOp::Delete { label, key },
            })
            .collect();
        WriteBatch { ops, epoch_changed: self.epoch_changed }
    }
}

/// Overlay plus backend reference: the raw row layer the typed storage methods use.
pub struct RowStore<'k, K: MlsKv> {
    kv: &'k K,
    overlay: Mutex<Overlay>,
}

impl<'k, K: MlsKv> RowStore<'k, K> {
    pub(crate) fn new(kv: &'k K) -> Self {
        Self { kv, overlay: Mutex::new(Overlay::default()) }
    }

    fn overlay(&self) -> Result<std::sync::MutexGuard<'_, Overlay>, MlsKvError> {
        self.overlay.lock().map_err(|_| MlsKvError::Poisoned)
    }

    /// Read a row (overlay first).
    ///
    /// # Errors
    /// Backend failure.
    pub fn get(&self, label: &str, key: &[u8]) -> Result<Option<Zeroizing<Vec<u8>>>, MlsKvError> {
        match self.overlay()?.lookup(label, key) {
            RowState::Value(value) => Ok(Some(value)),
            RowState::Deleted => Ok(None),
            RowState::Untouched => self.kv.get(label, key),
        }
    }

    /// Buffer a write.
    ///
    /// # Errors
    /// Poisoned overlay.
    pub fn put(
        &self,
        label: &str,
        key: Vec<u8>,
        value: Zeroizing<Vec<u8>>,
    ) -> Result<(), MlsKvError> {
        self.overlay()?.put(label, key, value);
        Ok(())
    }

    /// Buffer a delete.
    ///
    /// # Errors
    /// Poisoned overlay.
    pub fn delete(&self, label: &str, key: Vec<u8>) -> Result<(), MlsKvError> {
        self.overlay()?.delete(label, key);
        Ok(())
    }

    /// Take the buffered writes; the overlay is empty afterwards.
    ///
    /// # Errors
    /// Poisoned overlay.
    pub fn take_batch(&self) -> Result<WriteBatch, MlsKvError> {
        Ok(std::mem::take(&mut *self.overlay()?).into_batch())
    }

    /// Typed read of a JSON row.
    ///
    /// # Errors
    /// Backend failure, size bound or codec failure.
    pub fn read<V: DeserializeOwned>(
        &self,
        label: &str,
        key: &[u8],
    ) -> Result<Option<V>, MlsKvError> {
        match self.get(label, key)? {
            Some(raw) => Ok(Some(decode(&raw)?)),
            None => Ok(None),
        }
    }

    /// Typed read of a list row (a JSON array of JSON-encoded elements).
    ///
    /// # Errors
    /// Backend failure, size bound or codec failure.
    pub fn read_list<V: DeserializeOwned>(
        &self,
        label: &str,
        key: &[u8],
    ) -> Result<Vec<V>, MlsKvError> {
        let Some(raw) = self.get(label, key)? else { return Ok(Vec::new()) };
        let elements: Vec<Vec<u8>> = decode(&raw)?;
        elements.iter().map(|element| decode(element)).collect()
    }

    /// Encode and buffer a JSON row.
    ///
    /// # Errors
    /// Codec failure.
    pub fn write<V: Serialize + ?Sized>(
        &self,
        label: &str,
        key: Vec<u8>,
        value: &V,
    ) -> Result<(), MlsKvError> {
        self.put(label, key, encode(value)?)
    }

    /// Append one element to a list row.
    ///
    /// # Errors
    /// Backend failure, size bound or codec failure.
    pub fn append<V: Serialize + ?Sized>(
        &self,
        label: &str,
        key: &[u8],
        value: &V,
    ) -> Result<(), MlsKvError> {
        let mut elements: Vec<Vec<u8>> = match self.get(label, key)? {
            Some(raw) => decode(&raw)?,
            None => Vec::new(),
        };
        elements.push(encode(value)?.to_vec());
        self.put(label, key.to_vec(), encode(&elements)?)
    }

    /// Remove the first element equal to `value` from a list row.
    ///
    /// # Errors
    /// Backend failure, size bound or codec failure.
    pub fn remove_item<V: Serialize + ?Sized>(
        &self,
        label: &str,
        key: &[u8],
        value: &V,
    ) -> Result<(), MlsKvError> {
        let Some(raw) = self.get(label, key)? else { return Ok(()) };
        let mut elements: Vec<Vec<u8>> = decode(&raw)?;
        let needle = encode(value)?;
        if let Some(position) =
            elements.iter().position(|element| element.as_slice() == needle.as_slice())
        {
            elements.remove(position);
        }
        self.put(label, key.to_vec(), encode(&elements)?)
    }
}

/// Encode a value as JSON into a zeroizing buffer.
///
/// # Errors
/// Codec failure.
pub fn encode<V: Serialize + ?Sized>(value: &V) -> Result<Zeroizing<Vec<u8>>, MlsKvError> {
    let mut buffer = Zeroizing::new(Vec::new());
    serde_json::to_writer(&mut *buffer, value)?;
    Ok(buffer)
}

/// Decode a JSON value after the size bound check. This is the only JSON decode site of the
/// storage layer.
///
/// # Errors
/// [`MlsKvError::TooLarge`] above [`MAX_STORED_VALUE_BYTES`], or a codec failure.
pub fn decode<V: DeserializeOwned>(bytes: &[u8]) -> Result<V, MlsKvError> {
    if bytes.len() > MAX_STORED_VALUE_BYTES {
        return Err(MlsKvError::TooLarge(bytes.len()));
    }
    Ok(serde_json::from_slice(bytes)?)
}
