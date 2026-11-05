// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Storage-only incarnation metadata, kept out of the legacy public cursor shape.

use super::incarnation_state as state;
use super::{CursorAckState, InboxEntry, NodeCoreError, ROUTER_CURSOR_STATE_TABLE};
use redb::{ReadableDatabase, ReadableTable};
#[cfg(test)]
pub(super) mod work;
use serde::{Deserialize, Serialize};

#[derive(Serialize)]
pub(crate) struct StoredCursor {
    #[serde(flatten)]
    pub(crate) cursor: CursorAckState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) inbox_incarnation_id: Option<String>,
}

impl<'de> Deserialize<'de> for StoredCursor {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        // serde's flatten buffer does not decode numeric JSON object keys. Preserve
        // ordinary CursorAckState decoding for nack_attempts and other sequence maps.
        let value = serde_json::Value::deserialize(deserializer)?;
        let inbox_incarnation_id = value
            .get("inbox_incarnation_id")
            .map(|id| Option::<String>::deserialize(id.clone()))
            .transpose()
            .map_err(serde::de::Error::custom)?
            .flatten();
        let cursor = CursorAckState::deserialize(value).map_err(serde::de::Error::custom)?;
        Ok(Self { cursor, inbox_incarnation_id })
    }
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

pub(crate) fn read_id(
    txn: &redb::WriteTransaction,
    target: &str,
) -> Result<Option<String>, NodeCoreError> {
    Ok(state::read(txn, target)?.map(|(id, _)| id))
}
pub(crate) fn decode_cursor(bytes: &[u8]) -> Result<CursorAckState, NodeCoreError> {
    #[cfg(test)]
    work::read(bytes.len());
    serde_json::from_slice(bytes).map_err(error)
}

pub(crate) fn encode_cursor(
    cursor: &CursorAckState,
    id: Option<&str>,
) -> Result<Vec<u8>, NodeCoreError> {
    if let Some(id) = id {
        validate(id)?;
    }
    let bytes = serde_json::to_vec(&StoredCursor {
        cursor: cursor.clone(),
        inbox_incarnation_id: id.map(str::to_owned),
    })
    .map_err(error)?;
    #[cfg(test)]
    work::write(bytes.len());
    Ok(bytes)
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
    state::set(txn, target, issued, None, false)
}

#[cfg(test)]
mod tests;

/// The redb-only half of the pre-S6 upgrade; all recovered counters share one commit.
pub(super) fn upgrade_redb(
    db: &redb::Database,
    path: &std::path::Path,
    inbox: &crate::OpaqueDeviceInbox,
) -> Result<(), NodeCoreError> {
    crate::fatal_durability::run(|| {
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
    })
}

/// Write a canonical E and its counter together, refusing an incompatible durable cursor.
pub(crate) fn set_cursor(
    txn: &redb::WriteTransaction,
    target: &str,
    issued: u64,
    id: &str,
    rotate: bool,
) -> Result<(), NodeCoreError> {
    state::set(txn, target, issued, Some(id), rotate)?;
    if rotate {
        // Rotation is offline; update the compatibility field once, never per append.
        let mut table = txn.open_table(ROUTER_CURSOR_STATE_TABLE).map_err(error)?;
        let previous =
            table.get(target).map_err(error)?.map(|row| decode_cursor(row.value())).transpose()?;
        if let Some(mut cursor) = previous {
            cursor.issued_inbox_seq = cursor.issued_inbox_seq.max(issued);
            table.insert(target, encode_cursor(&cursor, Some(id))?.as_slice()).map_err(error)?;
        }
    }
    Ok(())
}

impl super::RouterRedbStore {
    /// Read the durable incarnation and issued high-water without creating a mailbox.
    /// # Errors
    /// Returns an error for invalid stored metadata or conflicting redb/WAL incarnations.
    pub fn inbox_status(&self, target: &str) -> Result<(Option<String>, u64), NodeCoreError> {
        let txn = self.db.begin_read().map_err(error)?;
        if txn
            .open_table(crate::ROUTER_DELETED_TARGET_TABLE)
            .map_err(error)?
            .get(target)
            .map_err(error)?
            .is_some()
        {
            return Ok((None, 0));
        }
        let table = txn.open_table(state::TABLE).map_err(error)?;
        let (mut id, mut issued) = table
            .get(target)
            .map_err(error)?
            .map(|row| state::decode(row.value()))
            .transpose()?
            .map_or((None, 0), |(id, issued)| (Some(id), issued));
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
    /// Reserve E without a write. The first acceptance or aborted checkpoint owns its persistence.
    pub(crate) fn provisional_inbox_incarnation(
        &self,
        target: &str,
    ) -> Result<String, NodeCoreError> {
        let core = self.publication_core()?;
        if let (Some(id), issued) = self.inbox_status(target)? {
            core.provisional_incarnation(target, id.clone())?;
            core.register(target, &id, issued);
            return Ok(id);
        }
        if let Some(id) = core.current_incarnation(target) {
            return core.provisional_incarnation(target, id);
        }
        let candidate = match &self.submission_wal {
            Some(wal) => wal.reserve_incarnation(target)?,
            None => new_id()?,
        };
        core.provisional_incarnation(target, candidate)
    }

    /// Durably initialize the authenticated capable session's own empty inbox.
    /// Callers run storage operations on the store/blocking thread before replying.
    /// # Errors
    /// Returns admission, entropy or storage errors without acknowledging initialization.
    pub fn initialize_inbox(&self, target: &str) -> Result<String, NodeCoreError> {
        let _lease = self.acquire_acknowledgement(target)?;

        let read = self.db.begin_read().map_err(error)?;
        if read
            .open_table(crate::ROUTER_DELETED_TARGET_TABLE)
            .map_err(error)?
            .get(target)
            .map_err(error)?
            .is_some()
        {
            return Err(error("deleted inbox"));
        }
        drop(read);
        let installed = self.publication.lock().map_err(error)?;
        let core = installed.as_ref().cloned();
        let candidate = match self.inbox_status(target)?.0 {
            Some(id) => id,
            None => match &self.submission_wal {
                Some(wal) => wal.reserve_incarnation(target)?,
                None => new_id()?,
            },
        };
        let provisional = match &core {
            Some(core) => core.provisional_incarnation(target, candidate)?,
            None => candidate,
        };
        // Without a core, keep its installation serialized with this first commit.
        let installation = if core.is_none() {
            Some(installed)
        } else {
            drop(installed);
            None
        };
        #[cfg(any(test, feature = "durability-test-hooks"))]
        crate::durability_test_hooks::notify(&self.path, "inbox_identity_reserved", true)
            .map_err(error)?;
        let id = crate::fatal_durability::run(|| {
            let mut txn = self.begin_write().map_err(error)?;
            txn.set_durability(redb::Durability::Immediate).map_err(error)?;
            let id = if let Some(wal) = &self.submission_wal {
                let id = wal.reserve_incarnation(target)?;
                set_cursor(&txn, target, 0, &id, false)?;
                id
            } else {
                set_cursor(&txn, target, 0, &provisional, false)?;
                provisional.clone()
            };
            txn.commit().map_err(error)?;
            Ok(id)
        })?;
        if let Some(core) = core {
            core.register(target, &id, self.inbox_status(target)?.1);
        }
        drop(installation);
        Ok(id)
    }
    pub(crate) fn checkpoint_incarnation(
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

#[cfg(any(test, feature = "durability-test-hooks"))]
pub(crate) fn test_store(
    root: &std::path::Path,
    mode: u8,
    segment_bytes: u64,
) -> Result<super::RouterRedbStore, NodeCoreError> {
    let mut store =
        super::RouterRedbStore::open_with_wal_root(root.join("db").as_path(), None, true)?;
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

impl super::RouterRedbStore {
    /// Persist a capable ACK only if its captured incarnation is still current.
    /// # Errors
    /// Returns `incarnation_mismatch` before any mutation for stale or unknown inboxes.
    pub fn record_ack_for_incarnation(
        &self,
        cursor: &CursorAckState,
        envelope_id: &str,
        incarnation: &str,
    ) -> Result<(), NodeCoreError> {
        let lease = self.acquire_acknowledgement(&cursor.target_delivery_id)?;
        if self.inbox_status(&cursor.target_delivery_id)?.0.as_deref() != Some(incarnation) {
            return Err(error("incarnation_mismatch"));
        }
        self.record_leased_ack(cursor, envelope_id, lease)
    }
}
