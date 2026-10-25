// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Atomic terminal spool outcomes: bounded audit metadata plus a durable cumulative counter.
use super::{
    FEDERATION_OUTBOUND_SPOOL_TABLE, FederationRedbStore, NodeCoreError, deserialize_spool_entry,
    outbound_spool_key,
};
use redb::ReadableTableMetadata;
use redb::{ReadableDatabase, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};
const LETTERS: TableDefinition<&str, &[u8]> =
    TableDefinition::new("federation_outbound_dead_letters_v1");
const COUNTS: TableDefinition<&str, u64> =
    TableDefinition::new("federation_outbound_dead_letter_counts_v1");
const LIMIT: usize = 4096;
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FederationOutboundDeadLetter {
    pub peer_node_id: String,
    pub seq: u64,
    pub envelope_id: String,
    pub source_device_id: String,
    pub reason_code: crate::EnvelopeAuthorityReason,
    pub dead_lettered_at: u64,
}
impl FederationRedbStore {
    pub(super) fn initialize_dead_letters(&self) -> Result<(), NodeCoreError> {
        let tx = self.db.begin_write().map_err(redb_error)?;
        tx.open_table(LETTERS).map_err(redb_error)?;
        tx.open_table(COUNTS).map_err(redb_error)?;
        tx.commit().map_err(redb_error)
    }
    /// Commits a terminal refusal and removes only its spool entry in the same transaction.
    /// Audit metadata retains at most 4096 outcomes; the cumulative count is never reset by pruning.
    /// # Errors
    /// Returns storage or serialization errors; a failed commit leaves the original entry pending.
    pub fn dead_letter_outbound(
        &self,
        peer: &str,
        seq: u64,
        reason: crate::EnvelopeAuthorityReason,
        now: u64,
    ) -> Result<(), NodeCoreError> {
        let tx = self.db.begin_write().map_err(redb_error)?;
        let mut pending = tx.open_table(FEDERATION_OUTBOUND_SPOOL_TABLE).map_err(redb_error)?;
        let key = outbound_spool_key(peer, seq);
        let Some(raw) = pending.remove(key.as_str()).map_err(redb_error)? else {
            return Ok(());
        };
        let entry = deserialize_spool_entry(raw.value())?;
        let letter = FederationOutboundDeadLetter {
            peer_node_id: peer.into(),
            seq,
            envelope_id: entry.forward.envelope.envelope_id,
            source_device_id: entry.forward.envelope.source_device_id,
            reason_code: reason,
            dead_lettered_at: now,
        };
        let bytes = serde_json::to_vec(&letter)
            .map_err(|e| NodeCoreError::SnapshotSerialization(e.to_string()))?;
        let mut counts = tx.open_table(COUNTS).map_err(redb_error)?;
        let total = counts
            .get("total")
            .map_err(redb_error)?
            .map_or(0, |v| v.value())
            .checked_add(1)
            .ok_or(NodeCoreError::Capacity { resource: "federation_dead_letter_counter" })?;
        let id = format!("{now:020}:{total:020}:{key}");
        let mut letters = tx.open_table(LETTERS).map_err(redb_error)?;
        letters.insert(id.as_str(), bytes.as_slice()).map_err(redb_error)?;
        while letters.len().map_err(redb_error)? > LIMIT as u64 {
            let oldest =
                letters.first().map_err(redb_error)?.map(|(key, _)| key.value().to_owned());
            if let Some(oldest) = oldest {
                letters.remove(oldest.as_str()).map_err(redb_error)?;
            }
        }
        counts.insert("total", total).map_err(redb_error)?;
        drop(raw);
        drop(pending);
        drop(letters);
        drop(counts);
        tx.commit().map_err(redb_error)
    }
    /// # Errors
    /// Returns storage or serialization errors while reading bounded audit metadata.
    pub fn outbound_dead_letters(
        &self,
        limit: usize,
    ) -> Result<Vec<FederationOutboundDeadLetter>, NodeCoreError> {
        let tx = self.db.begin_read().map_err(redb_error)?;
        let table = tx.open_table(LETTERS).map_err(redb_error)?;
        table
            .iter()
            .map_err(redb_error)?
            .take(limit.min(LIMIT))
            .map(|row| {
                let (_, value) = row.map_err(redb_error)?;
                serde_json::from_slice(value.value())
                    .map_err(|e| NodeCoreError::SnapshotSerialization(e.to_string()))
            })
            .collect()
    }
    /// # Errors
    /// Returns storage errors while reading the persistent cumulative counter.
    pub fn outbound_dead_letter_count(&self) -> Result<u64, NodeCoreError> {
        let tx = self.db.begin_read().map_err(redb_error)?;
        let table = tx.open_table(COUNTS).map_err(redb_error)?;
        Ok(table.get("total").map_err(redb_error)?.map_or(0, |v| v.value()))
    }
}
fn redb_error(error: impl std::fmt::Display) -> NodeCoreError {
    NodeCoreError::Redb(error.to_string())
}
