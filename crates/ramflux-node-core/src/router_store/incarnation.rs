// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Storage-only incarnation metadata, kept out of the legacy public cursor shape.

use super::{CursorAckState, InboxEntry, NodeCoreError, ROUTER_CURSOR_STATE_TABLE};
use redb::ReadableTable;
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize)]
struct StoredCursor {
    #[serde(flatten)]
    cursor: CursorAckState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    inbox_incarnation_id: Option<String>,
}

fn error(value: impl std::fmt::Display) -> NodeCoreError {
    NodeCoreError::Redb(value.to_string())
}

fn validate(id: &str) -> Result<(), NodeCoreError> {
    if id.len() != 32
        || !id.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(error("invalid inbox incarnation in stored cursor"));
    }
    Ok(())
}

fn new_id() -> Result<String, NodeCoreError> {
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

pub(super) fn encode_cursor(
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
