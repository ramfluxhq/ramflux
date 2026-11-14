// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Enrollment-only automatic history attempts, stored in its excluded local ledger.
use crate::{AccountDb, AdoptionRow, StorageError, TerminalRow};
use ramflux_protocol::custody::{DeviceRef, Publication};
use rusqlite::{OptionalExtension as _, params};
use serde::{Deserialize, Serialize};
pub(super) const SCHEMA: &str = "CREATE TABLE IF NOT EXISTS pairing_own_sync(
 operation_id TEXT NOT NULL PRIMARY KEY CHECK(length(operation_id) BETWEEN 1 AND 96),
 fingerprint TEXT NOT NULL CHECK(length(fingerprint)=43),
 response_json TEXT NOT NULL CHECK(length(CAST(response_json AS BLOB)) BETWEEN 1 AND 2048),
 operation_kind TEXT NOT NULL CHECK(operation_kind='pairing_own_sync_v1')
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS pairing_own_sync_kind ON pairing_own_sync(operation_kind,operation_id);";
const KIND: &str = "pairing_own_sync_v1";
const LIMIT: usize = 2048;
const CAPACITY: u64 = 128;
/// Public device references only. The ordinary SDK must obtain fresh native sync authority.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PairingOwnSyncJob {
    pub operation_id: String,
    pub record_hash: String,
    pub source_ref: DeviceRef,
    pub target_ref: DeviceRef,
}
#[derive(Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum Phase {
    Queued,
    Attempted,
    Done,
    Failed,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Stored {
    version: u8,
    job: PairingOwnSyncJob,
    phase: Phase,
    queued_at: u64,
    result: Option<String>,
}
fn wrong() -> StorageError {
    StorageError::PairingField("WrongContext")
}
fn key(operation: &str) -> String {
    format!("pairing-own-sync:{operation}")
}
fn hash(value: &str) -> Result<(), StorageError> {
    if value.len() != 43 {
        return Err(wrong());
    }
    let bytes = ramflux_protocol::decode_base64url(value).map_err(|_| wrong())?;
    if bytes.len() != 32 || ramflux_protocol::encode_base64url(bytes) != value {
        return Err(wrong());
    }
    Ok(())
}
impl Stored {
    fn validate(&self, db: &AccountDb) -> Result<(), StorageError> {
        hash(&self.job.operation_id)?;
        hash(&self.job.record_hash)?;
        if self.version != 1
            || self.queued_at > ramflux_protocol::MAX_SAFE_JSON_INTEGER
            || self.job.source_ref == self.job.target_ref
            || self.result.as_ref().is_some_and(|value| value.len() > 64)
            || (self.phase == Phase::Failed) != self.result.is_some()
        {
            return Err(wrong());
        }
        for reference in [&self.job.source_ref, &self.job.target_ref] {
            hash(&reference.account_anchor)?;
            if reference.account_anchor != db.principal_commitment
                || reference.device_id.is_empty()
                || reference.device_id.len() > 128
                || reference.device_epoch == 0
                || reference.device_epoch > ramflux_protocol::MAX_SAFE_JSON_INTEGER
            {
                return Err(wrong());
            }
        }
        Ok(())
    }
    fn encode(&self, db: &AccountDb) -> Result<Vec<u8>, StorageError> {
        self.validate(db)?;
        let bytes = ramflux_protocol::canonical_json_bytes(self)?;
        if bytes.len() > LIMIT {
            return Err(wrong());
        }
        Ok(bytes)
    }
}
impl AccountDb {
    pub(super) fn queue_enrollment_own_sync(
        &self,
        adoption: &AdoptionRow,
        terminal: &TerminalRow,
    ) -> Result<(), StorageError> {
        let transaction = self.connection.immediate_transaction()?;
        if let Ok(()) = self.queue_enrollment_own_sync_inner(adoption, terminal) {
            transaction.commit()?;
        } else {
            drop(transaction);
            tracing::warn!(
                "pairing history synchronization could not be scheduled; retry with device sync export"
            );
        }
        Ok(())
    }
    fn queue_enrollment_own_sync_inner(
        &self,
        adoption: &AdoptionRow,
        terminal: &TerminalRow,
    ) -> Result<(), StorageError> {
        let Some(head) = self.pairing_head()? else { return Ok(()) };
        if head.kind != "enroll" || adoption.local_role != "primary" {
            return Ok(());
        }
        let live = self
            .pairing_live_rows()?
            .into_iter()
            .find(|row| row.operation_id == terminal.operation_id)
            .ok_or_else(wrong)?;
        if live.role != "initiator" || live.context.is_none() || live.transcript_hash.is_none() {
            return Ok(());
        }
        if head.state != "acknowledged"
            || head.operation_id != terminal.operation_id
            || head.generation != terminal.generation
            || head.candidate_hash != adoption.record_hash
            || head.publisher_ref != adoption.local_ref
            || terminal.outcome != "completed"
        {
            return Err(wrong());
        }
        let target = head.recipient_ref.as_ref().ok_or_else(wrong)?;
        let publication: Publication = ramflux_protocol::parse_i_json(&head.candidate)?;
        let job = PairingOwnSyncJob {
            operation_id: terminal.operation_id.clone(),
            record_hash: adoption.record_hash.clone(),
            source_ref: ramflux_protocol::parse_i_json(&adoption.local_ref)?,
            target_ref: ramflux_protocol::parse_i_json(target)?,
        };
        if publication.record.body.account_anchor != self.principal_commitment
            || !publication.record.body.devices.iter().any(|device| {
                device.device_id == job.target_ref.device_id
                    && device.device_epoch == job.target_ref.device_epoch
            })
        {
            return Err(wrong());
        }
        let operation = key(&job.operation_id);
        if self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM pairing_own_sync WHERE operation_id=?1)",
            params![operation],
            |row| row.get::<_, bool>(0),
        )? {
            return Ok(());
        }
        self.connection.execute("DELETE FROM pairing_own_sync WHERE operation_kind=?1 AND operation_id IN(SELECT operation_id FROM pairing_own_sync WHERE operation_kind=?1 AND CASE WHEN length(response_json)<=2048 AND json_valid(response_json) THEN json_extract(response_json,'$.phase') END IN ('done','failed') ORDER BY operation_id LIMIT max(0,(SELECT count(*) FROM pairing_own_sync WHERE operation_kind=?1)-127))",params![KIND])?;
        let count: u64 = self.connection.query_row(
            "SELECT count(*) FROM pairing_own_sync WHERE operation_kind=?1",
            params![KIND],
            |row| row.get(0),
        )?;
        if count >= CAPACITY {
            tracing::warn!(
                "pairing history synchronization queue full; retry with device sync export"
            );
            return Ok(());
        }
        let queued: u64 = self.connection.query_row("SELECT count(*) FROM pairing_own_sync WHERE operation_kind=?1 AND CASE WHEN length(response_json)<=2048 AND json_valid(response_json) THEN json_extract(response_json,'$.phase') END='queued'",params![KIND],|row|row.get(0))?;
        let stored = Stored {
            version: 1,
            job,
            phase: if queued < 3 { Phase::Queued } else { Phase::Failed },
            queued_at: terminal.finished_at,
            result: (queued >= 3).then(|| "Busy".into()),
        };
        let bytes = String::from_utf8(stored.encode(self)?).map_err(|_| wrong())?;
        let fingerprint = ramflux_crypto::blake3_256_base64url(
            "ramflux.pairing.own_sync.v1",
            &ramflux_protocol::canonical_json_bytes(&stored.job)?,
        );
        self.connection.execute("INSERT INTO pairing_own_sync(operation_id,fingerprint,response_json,operation_kind) VALUES(?1,?2,?3,?4)",params![operation,fingerprint,bytes,KIND])?;
        Ok(())
    }
    fn own_sync_stored(&self, operation: &str) -> Result<Option<Stored>, StorageError> {
        hash(operation)?;
        let row: Option<(Option<String>,Option<String>)> = self.connection.query_row(
            "SELECT CASE WHEN length(fingerprint)=43 THEN fingerprint END,CASE WHEN length(response_json)<=2048 THEN response_json END FROM pairing_own_sync WHERE operation_id=?1 AND operation_kind=?2",
            params![key(operation),KIND],|row|Ok((row.get(0)?,row.get(1)?)),
        ).optional()?;
        let Some((fingerprint, bytes)) = row else { return Ok(None) };
        let fingerprint = fingerprint.ok_or_else(wrong)?;
        let bytes = bytes.ok_or_else(wrong)?;
        let value: Stored = ramflux_protocol::parse_i_json(bytes.as_bytes())?;
        value.validate(self)?;
        if value.job.operation_id != operation
            || value.encode(self)? != bytes.as_bytes()
            || fingerprint
                != ramflux_crypto::blake3_256_base64url(
                    "ramflux.pairing.own_sync.v1",
                    &ramflux_protocol::canonical_json_bytes(&value.job)?,
                )
        {
            return Err(wrong());
        }
        Ok(Some(value))
    }
    /// Read one bounded enrollment history request. Full transfers never enqueue this work.
    /// # Errors
    /// Refuses malformed local receipts or a retired account generation.
    pub fn next_pairing_own_sync(&self) -> Result<Option<PairingOwnSyncJob>, StorageError> {
        let operation: Option<Option<String>> = self.connection.query_row(
            "SELECT CASE WHEN length(operation_id)<=96 THEN operation_id END FROM pairing_own_sync WHERE operation_kind=?1 AND CASE WHEN length(response_json)<=2048 AND json_valid(response_json) THEN json_extract(response_json,'$.phase') END='queued' ORDER BY operation_id LIMIT 1",
            params![KIND],|row|row.get(0),
        ).optional()?;
        let Some(operation) = operation else { return Ok(None) };
        let operation = operation.ok_or_else(wrong)?;
        let operation = operation.strip_prefix("pairing-own-sync:").ok_or_else(wrong)?;
        let value = self.own_sync_stored(operation)?.ok_or_else(wrong)?;
        Ok(Some(value.job))
    }
    /// Durably consume the one automatic attempt before ordinary network effects.
    /// A crash or failure leaves manual retry available through the existing export API.
    /// # Errors
    /// Refuses foreign/replaced requests, corrupt receipts or transaction failure.
    pub fn claim_pairing_own_sync(&self, job: &PairingOwnSyncJob) -> Result<bool, StorageError> {
        self.write_transaction(|| {
            let mut value = self.own_sync_stored(&job.operation_id)?.ok_or_else(wrong)?;
            if value.job != *job { return Err(wrong()); }
            if value.phase != Phase::Queued { return Ok(false); }
            value.phase = Phase::Attempted;
            self.connection.execute("UPDATE pairing_own_sync SET response_json=?1 WHERE operation_id=?2 AND operation_kind=?3",params![String::from_utf8(value.encode(self)?).map_err(|_| wrong())?,key(&job.operation_id),KIND])?;
            Ok(true)
        })
    }
    /// Store the outcome without changing pairing, native authority or any device's admission.
    /// # Errors
    /// Refuses another request, a non-attempted receipt or an oversized local error code.
    pub fn finish_pairing_own_sync(
        &self,
        job: &PairingOwnSyncJob,
        error: Option<&str>,
    ) -> Result<(), StorageError> {
        if error.is_some_and(|value| value.len() > 64) {
            return Err(wrong());
        }
        self.write_transaction(|| {
            let mut value = self.own_sync_stored(&job.operation_id)?.ok_or_else(wrong)?;
            if value.job != *job || value.phase != Phase::Attempted { return Err(wrong()); }
            value.phase = if error.is_some() {Phase::Failed}else{Phase::Done};
            value.result = error.map(str::to_owned);
            self.connection.execute("UPDATE pairing_own_sync SET response_json=?1 WHERE operation_id=?2 AND operation_kind=?3",params![String::from_utf8(value.encode(self)?).map_err(|_| wrong())?,key(&job.operation_id),KIND])?;
            Ok(())
        })
    }
}
