// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Durable admission record of one attachment download (import).
//!
//! `begin` writes the record and the operation binding before any worker is scheduled, so a
//! restarted account resumes the same import (same `import_id`, same generation) instead of
//! allocating a new one. The binding carries a fingerprint of the message and entry: an
//! operation id reused for a different body is refused.

use serde::{Deserialize, Serialize};

use super::codes::{CODE_CANCELLED, CODE_DUPLICATE, CODE_EXPIRED, Refusal};
use crate::SdkError;

/// Client-record directory for the import journal, keyed by import id.
pub(crate) const JOURNAL: &str = "attachment-import-journal";
/// Client-record directory for operation bindings, keyed by operation id.
pub(crate) const BINDING: &str = "attachment-import";

/// Where the import stands. Only `Pending` admits work; the rest are terminal for the record.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ImportPhase {
    Pending,
    Cancelled,
    Finished,
}

/// The durable record. Counts and bitmaps are added by the cache step; the record never holds
/// a file key, a grant or a path.
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

/// # Errors
/// Returns a storage error when the record cannot be written.
pub(crate) fn save_record(
    db: &ramflux_storage::AccountDb,
    record: &ImportRecord,
) -> Result<(), SdkError> {
    db.persist_client_record(JOURNAL, &record.import_id, &serde_json::to_value(record)?)?;
    Ok(())
}

/// # Errors
/// Returns a storage or decode error when the record cannot be read.
pub(crate) fn load_record(
    db: &ramflux_storage::AccountDb,
    import_id: &str,
) -> Result<Option<ImportRecord>, SdkError> {
    db.client_record(JOURNAL, import_id)?.map(serde_json::from_value).transpose().map_err(Into::into)
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
    db.client_record(BINDING, operation_id)?.map(serde_json::from_value).transpose().map_err(Into::into)
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

/// Refuses a record that cannot admit work. A terminal record never restarts.
/// # Errors
/// Returns `cancelled` or `duplicate` for a terminal phase, and `expired` past the lease.
pub(crate) fn admissible(record: &ImportRecord, now: u64) -> Result<(), Refusal> {
    match record.phase {
        ImportPhase::Pending if now >= record.expires_at => Err(Refusal::new(CODE_EXPIRED)),
        ImportPhase::Pending => Ok(()),
        ImportPhase::Cancelled => Err(Refusal::new(CODE_CANCELLED)),
        ImportPhase::Finished => Err(Refusal::new(CODE_DUPLICATE)),
    }
}
