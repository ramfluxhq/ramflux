// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! W0 admission. A durable receipt reserves one terminal slot until settlement.
use super::ReceiveTransaction;
use crate::{ProjectionStore, StorageError};
use rusqlite::{OptionalExtension, params};

const WORK_LIMIT: i64 = 1024;
const BYTE_LIMIT: i64 = 64 * 1024 * 1024;
const ENTRY_LIMIT: usize = 1_048_576;

/// Authenticated, normalized delivery bytes. The caller authenticates before W0.
#[derive(Clone, Copy, Debug)]
pub struct ReceiveStage<'a> {
    pub target: &'a str,
    pub incarnation: &'a str,
    pub sequence: u64,
    pub entry_json: &'a [u8],
    pub admission_key: &'a str,
    pub retain_until: i64,
    pub first_seen: i64,
}

/// Admission never grants processing authority for a conflicting network copy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReceiveStageResult {
    Staged,
    Existing,
    Conflict { diagnostic_created: bool },
    Erased,
    PausedWork,
    PausedBytes,
    PausedIntents,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    inbox_seq: u64,
    target_delivery_id: String,
    envelope: ramflux_protocol::Envelope,
}

impl ReceiveTransaction<'_> {
    /// Reserves work and potential terminal intent before any processing can start.
    /// Duplicate bytes preserve the first work, including its original deadline/key.
    /// # Errors
    /// Rejects invalid normalized input, stale transaction authority and storage failures.
    pub fn stage(&self, input: ReceiveStage<'_>) -> Result<ReceiveStageResult, StorageError> {
        self.require_writer()?;
        self.db.write_transaction(|| self.stage_inner(input))
    }

    fn stage_inner(&self, input: ReceiveStage<'_>) -> Result<ReceiveStageResult, StorageError> {
        if input.target != self.target || input.incarnation != self.incarnation {
            return Err(StorageError::Integrity("receive stage authority mismatch"));
        }
        if input.sequence == 0 {
            return Err(StorageError::Integrity("receive sequence must be positive"));
        }
        if input.entry_json.is_empty() || input.entry_json.len() > ENTRY_LIMIT {
            return Err(StorageError::Integrity("receive entry byte bound"));
        }
        if input.admission_key.is_empty() {
            return Err(StorageError::Integrity("receive admission key missing"));
        }
        let entry: Entry = serde_json::from_slice(input.entry_json)
            .map_err(|_| StorageError::Integrity("receive entry encoding"))?;
        if entry.inbox_seq != input.sequence
            || entry.target_delivery_id != input.target
            || entry.envelope.target_delivery_id != input.target
        {
            return Err(StorageError::Integrity("receive entry binding"));
        }
        let seq = input.sequence.to_be_bytes();
        let key = params![input.target, input.incarnation, seq.as_slice()];
        let disposition: Option<String> = self.db.connection.query_row(
            "SELECT disposition FROM gateway_receive_receipt WHERE target_delivery_id=?1 AND incarnation_id=?2 AND inbox_seq=?3",
            key, |r| r.get(0),
        ).optional()?;
        if disposition.as_deref() == Some("erased") {
            return Ok(ReceiveStageResult::Erased);
        }
        let previous: Option<Vec<u8>> = self.db.connection.query_row(
            "SELECT entry_json FROM gateway_receive_work WHERE target_delivery_id=?1 AND incarnation_id=?2 AND inbox_seq=?3",
            params![input.target,input.incarnation,seq.as_slice()], |r| r.get(0),
        ).optional()?;
        if let Some(bytes) = previous {
            return if bytes == input.entry_json {
                Ok(ReceiveStageResult::Existing)
            } else {
                Ok(ReceiveStageResult::Conflict {
                    diagnostic_created: self.record_conflict(input)?,
                })
            };
        }
        if disposition.is_some() {
            return Err(StorageError::Integrity("receive receipt missing work"));
        }
        // All incarnations count. A receipt and intent for the same key reserve one slot.
        let (count, bytes): (i64, i64) = self.db.connection.query_row(
            "SELECT count(*),coalesce(sum(byte_len),0) FROM gateway_receive_work WHERE target_delivery_id=?1",
            params![input.target], |r| Ok((r.get(0)?,r.get(1)?)),
        )?;
        if count >= WORK_LIMIT {
            return Ok(ReceiveStageResult::PausedWork);
        }
        let length = i64::try_from(input.entry_json.len())
            .map_err(|_| StorageError::Integrity("receive entry byte bound"))?;
        if bytes > BYTE_LIMIT - length {
            return Ok(ReceiveStageResult::PausedBytes);
        }
        let slots: i64 = self.db.connection.query_row(
            "SELECT count(*) FROM (SELECT incarnation_id,inbox_seq FROM gateway_ack_intent WHERE target_delivery_id=?1 UNION SELECT incarnation_id,inbox_seq FROM gateway_receive_receipt WHERE target_delivery_id=?1)",
            params![input.target], |r| r.get(0),
        )?;
        if slots >= WORK_LIMIT {
            return Ok(ReceiveStageResult::PausedIntents);
        }
        self.db.connection.execute(
            "INSERT INTO gateway_receive_receipt VALUES(?1,?2,?3,'staged',?4,?5)",
            params![
                input.target,
                input.incarnation,
                seq.as_slice(),
                input.retain_until,
                input.first_seen
            ],
        )?;
        self.db.connection.execute(
            "INSERT INTO gateway_receive_work VALUES(?1,?2,?3,?4,?5,?6)",
            params![
                input.target,
                input.incarnation,
                seq.as_slice(),
                input.entry_json,
                input.admission_key,
                length
            ],
        )?;
        Ok(ReceiveStageResult::Staged)
    }

    fn record_conflict(&self, input: ReceiveStage<'_>) -> Result<bool, StorageError> {
        // Metadata only, using the existing checkpoint table rather than a sixth ledger table.
        let prefix = format!("gateway_receive_conflict:{:?}:", input.target);
        let key = format!("{prefix}{:?}:{}", input.incarnation, input.sequence);
        if self.db.projection_checkpoint(&key)?.is_some() {
            return Ok(false);
        }
        let previous: i64 = self.db.connection.query_row(
            "SELECT coalesce(max(projection_version),0) FROM projection_checkpoint WHERE substr(projection_name,1,length(?1))=?1",
            params![prefix], |r| r.get(0),
        )?;
        let ordinal = previous
            .checked_add(1)
            .ok_or(StorageError::Integrity("receive diagnostic counter exhausted"))?;
        self.db.connection.execute(
            "INSERT INTO projection_checkpoint(projection_name,projection_version,last_event_id,checkpoint_hash,updated_at) VALUES(?1,?2,'conflict',NULL,?3)",
            params![key, ordinal, input.first_seen],
        )?;
        self.db.connection.execute(
            "DELETE FROM projection_checkpoint WHERE projection_name IN (SELECT projection_name FROM projection_checkpoint WHERE substr(projection_name,1,length(?1))=?1 ORDER BY projection_version DESC,projection_name DESC LIMIT -1 OFFSET 64)",
            params![prefix],
        )?;
        Ok(true)
    }
}
