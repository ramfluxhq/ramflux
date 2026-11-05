// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Storage-only incarnation metadata, kept out of the legacy public cursor shape.

use super::{CursorAckState, InboxEntry, NodeCoreError, ROUTER_CURSOR_STATE_TABLE};
use redb::ReadableTable;
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize)]
pub(crate) struct StoredCursor {
    #[serde(flatten)]
    pub(crate) cursor: CursorAckState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) inbox_incarnation_id: Option<String>,
}

pub(crate) fn error(value: impl std::fmt::Display) -> NodeCoreError {
    NodeCoreError::Redb(value.to_string())
}

pub(crate) fn validate(id: &str) -> Result<(), NodeCoreError> {
    if id.len() != 32
        || !id.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(error("invalid inbox incarnation in stored cursor"));
    }
    Ok(())
}

pub(crate) fn new_id() -> Result<String, NodeCoreError> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let bytes = ramflux_crypto::random_32().map_err(error)?;
    let mut result = String::with_capacity(32);
    for byte in &bytes[..16] {
        result.push(char::from(HEX[usize::from(byte >> 4)]));
        result.push(char::from(HEX[usize::from(byte & 15)]));
    }
    Ok(result)
}

pub(super) fn read_id(
    table: &redb::Table<'_, &str, &[u8]>,
    target: &str,
) -> Result<Option<String>, NodeCoreError> {
    let stored = table.get(target).map_err(error)?;
    let Some(stored) = stored else { return Ok(None) };
    let cursor: StoredCursor = serde_json::from_slice(stored.value()).map_err(error)?;
    if let Some(id) = &cursor.inbox_incarnation_id {
        validate(id)?;
    }
    Ok(cursor.inbox_incarnation_id)
}

pub(crate) fn encode_cursor(
    cursor: &CursorAckState,
    id: Option<&str>,
) -> Result<Vec<u8>, NodeCoreError> {
    if let Some(id) = id {
        validate(id)?;
    }
    serde_json::to_vec(&StoredCursor {
        cursor: cursor.clone(),
        inbox_incarnation_id: id.map(str::to_owned),
    })
    .map_err(error)
}

/// Assign E and advance the issued counter inside the entry's existing transaction.
pub(super) fn observe_entry(
    txn: &redb::WriteTransaction,
    entry: &InboxEntry,
) -> Result<(), NodeCoreError> {
    ensure_cursor(txn, &entry.target_delivery_id, entry.inbox_seq)?;
    Ok(())
}

pub(super) fn ensure_cursor(
    txn: &redb::WriteTransaction,
    target: &str,
    issued: u64,
) -> Result<String, NodeCoreError> {
    let mut table = txn.open_table(ROUTER_CURSOR_STATE_TABLE).map_err(error)?;
    let previous = table
        .get(target)
        .map_err(error)?
        .map(|bytes| serde_json::from_slice::<StoredCursor>(bytes.value()))
        .transpose()
        .map_err(error)?;
    let mut stored = previous.unwrap_or_else(|| StoredCursor {
        cursor: CursorAckState {
            target_delivery_id: target.to_owned(),
            ..CursorAckState::default()
        },
        inbox_incarnation_id: None,
    });
    let id = match stored.inbox_incarnation_id {
        Some(id) => {
            validate(&id)?;
            id
        }
        None => new_id()?,
    };
    stored.cursor.issued_inbox_seq = stored.cursor.issued_inbox_seq.max(issued);
    let bytes = encode_cursor(&stored.cursor, Some(&id))?;
    table.insert(target, bytes.as_slice()).map_err(error)?;
    Ok(id)
}

#[cfg(test)]
mod tests;

/// The redb-only half of the pre-S6 upgrade; all recovered counters share one commit.
pub(super) fn upgrade_redb(
    db: &redb::Database,
    path: &std::path::Path,
    inbox: &crate::OpaqueDeviceInbox,
) -> Result<(), NodeCoreError> {
    crate::durability_io::boundary(path, "incarnation_upgrade", || {
        let mut txn = db.begin_write().map_err(std::io::Error::other)?;
        txn.set_durability(redb::Durability::Immediate).map_err(std::io::Error::other)?;
        for cursor in inbox.cursor_states() {
            ensure_cursor(
                &txn,
                &cursor.target_delivery_id,
                inbox.issued_sequence(&cursor.target_delivery_id),
            )
            .map_err(std::io::Error::other)?;
        }
        txn.commit().map_err(std::io::Error::other)
    })
    .map_err(error)
}

/// Write a canonical E and its counter together, refusing an incompatible durable cursor.
pub(crate) fn set_cursor(
    txn: &redb::WriteTransaction,
    target: &str,
    issued: u64,
    id: &str,
    rotate: bool,
) -> Result<(), NodeCoreError> {
    validate(id)?;
    let mut table = txn.open_table(ROUTER_CURSOR_STATE_TABLE).map_err(error)?;
    let previous = table
        .get(target)
        .map_err(error)?
        .map(|row| serde_json::from_slice::<StoredCursor>(row.value()))
        .transpose()
        .map_err(error)?;
    let mut cursor = previous.as_ref().map_or_else(
        || CursorAckState { target_delivery_id: target.into(), ..CursorAckState::default() },
        |stored| stored.cursor.clone(),
    );
    if !rotate
        && previous
            .as_ref()
            .and_then(|stored| stored.inbox_incarnation_id.as_deref())
            .is_some_and(|old| old != id)
    {
        return Err(error("inbox incarnation mismatch during persistence"));
    }
    cursor.issued_inbox_seq = cursor.issued_inbox_seq.max(issued);
    table.insert(target, encode_cursor(&cursor, Some(id))?.as_slice()).map_err(error)?;
    Ok(())
}

impl super::RouterRedbStore {
    /// Read the durable incarnation and issued high-water without creating a mailbox.
    /// # Errors
    /// Returns an error for invalid stored metadata or conflicting redb/WAL incarnations.
    pub fn inbox_status(&self, target: &str) -> Result<(Option<String>, u64), NodeCoreError> {
        use redb::ReadableDatabase;
        let txn = self.db.begin_read().map_err(error)?;
        let table = txn.open_table(ROUTER_CURSOR_STATE_TABLE).map_err(error)?;
        let stored = table
            .get(target)
            .map_err(error)?
            .map(|row| serde_json::from_slice::<StoredCursor>(row.value()))
            .transpose()
            .map_err(error)?;
        let (mut id, mut issued) = stored.map_or((None, 0), |stored| {
            (
                stored.inbox_incarnation_id,
                stored
                    .cursor
                    .issued_inbox_seq
                    .max(stored.cursor.inbox_seq)
                    .max(stored.cursor.settled_inbox_seq),
            )
        });
        if let Some(current) = &id {
            validate(current)?;
        }
        if let Some(wal) = &self.submission_wal
            && let Some((wal_id, wal_issued)) = wal.committed_inbox(target)?
        {
            if id.as_ref().is_some_and(|id| id != &wal_id) {
                return Err(error("redb/WAL inbox incarnation mismatch"));
            }
            id = Some(wal_id);
            issued = issued.max(wal_issued);
        }
        Ok((id, issued))
    }
    /// Durably initialize the authenticated capable session's own empty inbox.
    /// Callers run storage operations on the store/blocking thread before replying.
    /// # Errors
    /// Returns admission, entropy or storage errors without acknowledging initialization.
    pub fn initialize_inbox(&self, target: &str) -> Result<String, NodeCoreError> {
        let _lease = self.acquire_acknowledgement(target)?;
        let mut txn = self.db.begin_write().map_err(error)?;
        txn.set_durability(redb::Durability::Immediate).map_err(error)?;
        let id = if let Some(wal) = &self.submission_wal {
            let id = wal.reserve_incarnation(target)?;
            set_cursor(&txn, target, 0, &id, false)?;
            id
        } else {
            ensure_cursor(&txn, target, 0)?
        };
        txn.commit().map_err(error)?;
        Ok(id)
    }
    pub(super) fn checkpoint_incarnation(
        &self,
        txn: &redb::WriteTransaction,
        cursor: &CursorAckState,
    ) -> Result<(), NodeCoreError> {
        if let Some(wal) = &self.submission_wal
            && let Some((id, issued)) = wal.committed_inbox(&cursor.target_delivery_id)?
        {
            set_cursor(txn, &cursor.target_delivery_id, issued, &id, false)?;
        }
        Ok(())
    }
}

#[cfg(test)]
pub(crate) fn test_store(
    root: &std::path::Path,
    mode: u8,
    segment_bytes: u64,
) -> Result<super::RouterRedbStore, NodeCoreError> {
    let mut store = super::RouterRedbStore::open_without_wal(root.join("db"))?;
    if mode != 0 {
        store.submission_wal = Some(crate::RouterWalStore::open_associated_config(
            &root.join("wal"),
            std::sync::Arc::clone(&store.db),
            &store.path,
            mode == 2,
            1,
            segment_bytes,
        )?);
    }
    Ok(store)
}
