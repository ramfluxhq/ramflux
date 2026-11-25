// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Durable record of one attachment download (import).
//!
//! The record lives in actor state under `attachment-import/<hash of import id>`, encoded as the
//! same bounded byte record the SEND journal uses (`AckRecord`). The download worker writes it
//! through the account actor's journal channel, so a bitmap bit is set only after the ciphertext
//! segment it names is durable. `begin` writes the record and an operation binding before any
//! worker is scheduled; a restarted account resumes the same import (same `import_id`, same
//! generation). The binding carries a fingerprint of the message and entry: an operation id
//! reused for a different body is refused.

use serde::{Deserialize, Serialize};

use serde_json::{Value, json};

use super::codes::{
    CODE_CANCELLED, CODE_DISK_FULL, CODE_DUPLICATE, CODE_EXPIRED, CODE_LAYOUT_INVALID,
    CODE_NOT_GRANTEE, CODE_SEAL_FAILED, Refusal,
};
use super::upload::AckRecord;
use crate::SdkError;

/// Client-record directory for operation bindings, keyed by operation id (begin path only).
pub(crate) const BINDING: &str = "attachment-import";

/// Where the import stands. `Pending` streams; `Ready` is the whole verified plaintext and may be
/// read or exported (a restart replays it from the cache). `Failed` and `Cancelled` are terminal
/// for the record, and `Finished` means the caller released it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ImportPhase {
    Pending,
    Ready,
    Failed,
    Cancelled,
    Finished,
}

impl ImportPhase {
    /// The wire name of the phase, as the transfer snapshot and the status reply carry it.
    pub(crate) fn wire(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Ready => "ready",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
            Self::Finished => "finished",
        }
    }
}

/// The durable record. It never holds a file key, a grant or a path.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ImportRecord {
    pub(crate) import_id: String,
    pub(crate) generation: u64,
    pub(crate) message_id: String,
    pub(crate) index: u64,
    pub(crate) plaintext_length: u64,
    pub(crate) expires_at: u64,
    pub(crate) phase: ImportPhase,
    pub(crate) revision: u64,
    /// One bit per encrypted segment: set only after that ciphertext is durable on disk.
    #[serde(default)]
    pub(crate) verified: Vec<bool>,
    /// The stable refusal code of a `Failed` record. Empty otherwise.
    #[serde(default)]
    pub(crate) failure: Option<String>,
}

/// The operation-to-import binding.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Binding {
    pub(crate) import_id: String,
    pub(crate) fingerprint: String,
}

/// Fingerprint of the body an operation id was admitted with.
pub(crate) fn fingerprint(message_id: &str, index: u64) -> String {
    ramflux_crypto::blake3_256_base64url(
        "ramflux.attachment.import.fingerprint.v1",
        format!("{message_id}\0{index}").as_bytes(),
    )
}

/// Namespace of the import records in actor state (one key per import).
pub(crate) const RECORD_PREFIX: &str = "attachment-import/";

/// Actor-state key of the record for one import.
pub(crate) fn record_key(import_id: &str) -> String {
    format!(
        "{RECORD_PREFIX}{}",
        ramflux_crypto::blake3_256_base64url(
            "ramflux.attachment.import.record.v1",
            import_id.as_bytes()
        )
    )
}

/// Encodes a record as the journal's byte payload.
/// # Errors
/// Returns a serialization error only if the record cannot be encoded.
pub(crate) fn encode(record: &ImportRecord) -> Result<Vec<u8>, SdkError> {
    Ok(serde_json::to_vec(record)?)
}

/// # Errors
/// Returns a decode error when the stored bytes are not a record.
pub(crate) fn decode(bytes: &[u8]) -> Result<ImportRecord, SdkError> {
    Ok(serde_json::from_slice(bytes)?)
}

/// # Errors
/// Returns a storage error when the record cannot be written.
pub(crate) fn save_record(
    db: &ramflux_storage::AccountDb,
    record: &ImportRecord,
) -> Result<(), SdkError> {
    let acks = encode(record)?;
    db.persist_actor_state(&record_key(&record.import_id), &AckRecord { acks })?;
    Ok(())
}

/// # Errors
/// Returns a storage or decode error when the record cannot be read.
pub(crate) fn load_record(
    db: &ramflux_storage::AccountDb,
    import_id: &str,
) -> Result<Option<ImportRecord>, SdkError> {
    db.load_actor_state::<AckRecord>(&record_key(import_id))?
        .map(|stored| decode(&stored.acks))
        .transpose()
}

/// # Errors
/// Returns a storage error when the binding cannot be written.
pub(crate) fn save_binding(
    db: &ramflux_storage::AccountDb,
    operation_id: &str,
    binding: &Binding,
) -> Result<(), SdkError> {
    db.persist_client_record(BINDING, operation_id, &serde_json::to_value(binding)?)?;
    Ok(())
}

/// # Errors
/// Returns a storage or decode error when the binding cannot be read.
pub(crate) fn load_binding(
    db: &ramflux_storage::AccountDb,
    operation_id: &str,
) -> Result<Option<Binding>, SdkError> {
    db.client_record(BINDING, operation_id)?
        .map(serde_json::from_value)
        .transpose()
        .map_err(Into::into)
}

/// Moves the record to a terminal phase. Returns `Ok(false)` when no record exists.
/// # Errors
/// Returns a storage error when the update cannot be written.
pub(crate) fn set_phase(
    db: &ramflux_storage::AccountDb,
    import_id: &str,
    phase: ImportPhase,
) -> Result<bool, SdkError> {
    let Some(mut record) = load_record(db, import_id)? else {
        return Ok(false);
    };
    if record.phase == phase {
        return Ok(true);
    }
    record.phase = phase;
    record.revision = record.revision.saturating_add(1);
    save_record(db, &record)?;
    Ok(true)
}

/// Refuses a record that cannot admit work. A ready record replays from its cache; a failed or
/// cancelled record never restarts.
/// # Errors
/// Returns `cancelled` or `duplicate` for a terminal phase, the stored failure code for a failed
/// one, and `expired` past the lease.
pub(crate) fn admissible(record: &ImportRecord, now: u64) -> Result<(), Refusal> {
    match record.phase {
        ImportPhase::Pending | ImportPhase::Ready if now >= record.expires_at => {
            Err(Refusal::new(CODE_EXPIRED))
        }
        ImportPhase::Pending | ImportPhase::Ready => Ok(()),
        ImportPhase::Failed => Err(Refusal::new(failure_code(record.failure.as_deref()))),
        ImportPhase::Cancelled => Err(Refusal::new(CODE_CANCELLED)),
        ImportPhase::Finished => Err(Refusal::new(CODE_DUPLICATE)),
    }
}

/// Maps a stored failure back to its stable code; an unknown or absent one is `seal_failed`.
pub(crate) fn failure_code(stored: Option<&str>) -> &'static str {
    [CODE_SEAL_FAILED, CODE_LAYOUT_INVALID, CODE_NOT_GRANTEE, CODE_DISK_FULL]
        .into_iter()
        .find(|code| Some(*code) == stored)
        .unwrap_or(CODE_SEAL_FAILED)
}

/// Journal dedup key of one transfer snapshot. The revision is the record's persisted revision,
/// so the key is unique per durable change and a replayed write dedups.
pub(crate) fn event_source(record: &ImportRecord) -> String {
    format!("attachment-transfer/{}/{}/{}", record.import_id, record.generation, record.revision)
}

/// The `attachment.transfer.changed` body of a download. Counts are ciphertext bytes derived
/// from the bitmap; the plaintext length is reported separately. No path, key or raw error.
pub(crate) fn event_body(
    record: &ImportRecord,
    phase: ImportPhase,
    reason: Option<&str>,
    retryable: bool,
) -> Value {
    let total = ciphertext_total(record);
    let verified = verified_bytes(record);
    json!({
        "transfer_id": record.import_id,
        "prepare_id": Value::Null,
        "operation_id": Value::Null,
        "client_message_id": Value::Null,
        "message_id": record.message_id,
        "import_id": record.import_id,
        "direction": "download",
        "phase": phase.wire(),
        "generation": record.generation,
        "total_bytes": total,
        "accepted_bytes": Value::Null,
        "uploaded_bytes": Value::Null,
        "unique_bytes": verified,
        "verified_bytes": verified,
        "plaintext_length": record.plaintext_length,
        "expires_at": record.expires_at,
        "reason_code": reason,
        "retryable": retryable,
    })
}

/// Ciphertext bytes the bitmap confirms (the verified count of a download).
pub(crate) fn verified_bytes(record: &ImportRecord) -> u64 {
    ciphertext_bytes(
        record,
        record.verified.iter().enumerate().filter(|(_, set)| **set).map(|(index, _)| index),
    )
}

/// Ciphertext bytes of the whole download: every segment's plaintext plus its 16-byte tag.
pub(crate) fn ciphertext_total(record: &ImportRecord) -> u64 {
    ciphertext_bytes(record, 0..record.verified.len())
}

/// Ciphertext bytes of the named segments. Segment sizes come from the layout, so the last one
/// is shorter; an index outside the layout contributes nothing.
fn ciphertext_bytes(record: &ImportRecord, indices: impl Iterator<Item = usize>) -> u64 {
    let layout = ramflux_protocol::large_attachment::SegmentLayout {
        plaintext_length: record.plaintext_length,
        network_chunk_bytes: super::import_job::NETWORK_CHUNK,
    };
    indices
        .filter_map(|index| layout.segment_plaintext_length(index as u64).ok())
        .map(|plain| plain.saturating_add(16))
        .sum()
}

/// Writes a download record for the actor, only while the stored record is still `Pending`,
/// then appends its snapshot. A cancel that landed first makes this refuse, so a worker can
/// never move a cancelled import back to pending or ready.
/// # Errors
/// Returns `cancelled` when the stored record is not pending or is missing, and `seal_failed`
/// when the write is not durable.
pub(crate) fn settle_guarded(
    db: &ramflux_storage::AccountDb,
    key: &str,
    bytes: &[u8],
    event: Option<(String, Value)>,
) -> Result<(), Refusal> {
    let stored = db
        .load_actor_state::<AckRecord>(key)
        .map_err(|_| Refusal::new(CODE_SEAL_FAILED))?
        .ok_or(Refusal::new(CODE_CANCELLED))?;
    let current = decode(&stored.acks).map_err(|_| Refusal::new(CODE_SEAL_FAILED))?;
    if current.phase != ImportPhase::Pending {
        return Err(Refusal::new(CODE_CANCELLED));
    }
    // The record and its snapshot commit in one transaction: a bit is durable exactly when its
    // event is, and a crash never leaves a bit without the snapshot that announces it.
    db.write_transaction(|| -> Result<(), ramflux_storage::StorageError> {
        db.persist_actor_state(key, &AckRecord { acks: bytes.to_vec() })?;
        if let Some((source, body)) = &event {
            db.append_journal(
                source,
                super::transfer::TRANSFER_TOPIC,
                body,
                crate::time::now_unix_timestamp(),
                None,
            )?;
        }
        Ok(())
    })
    .map_err(|_| Refusal::new(CODE_SEAL_FAILED))
}
