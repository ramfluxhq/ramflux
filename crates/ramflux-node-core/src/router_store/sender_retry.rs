// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Source-qualified durable sender assignments. Index expiry is independent of
//! settlement and of the recipient's ciphertext retention deadline.
use super::{
    LocalDeliveryEnvelopeRecord, RouterRedbStore, incarnation, local_delivery_storage_key,
};
use crate::{InboxEntry, NodeCoreError, ROUTER_LOCAL_DELIVERY_ENVELOPE_TABLE};
use redb::{ReadableDatabase, ReadableTable};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Stable sender refusal codes, independent of storage failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum SenderRetryRefusal {
    #[error("aborted_retry_safe")]
    AbortedRetrySafe,
    #[error("idempotency_conflict")]
    IdempotencyConflict,
}

/// Original durable acceptance, retained until the original replay deadline.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SenderAssignment {
    pub target_delivery_id: String,
    pub inbox_incarnation_id: String,
    pub inbox_seq: u64,
    pub retain_until: i64,
    pub digest: String,
}
impl SenderAssignment {
    pub(crate) fn new(
        entry: &InboxEntry,
        id: String,
        retain_until: i64,
    ) -> Result<Self, NodeCoreError> {
        Ok(Self {
            target_delivery_id: entry.target_delivery_id.clone(),
            inbox_incarnation_id: id,
            inbox_seq: entry.inbox_seq,
            retain_until,
            digest: content_digest(&entry.envelope)?,
        })
    }
}

/// Digest immutable sender bytes. Mutable authority and routing extensions are
/// intentionally excluded using the protocol's canonical sender-signature schema.
/// # Errors
/// Returns an error if canonical serialization fails.
pub fn content_digest(envelope: &ramflux_protocol::Envelope) -> Result<String, NodeCoreError> {
    let bytes =
        ramflux_protocol::envelope_sender_signed_bytes(envelope).map_err(incarnation::error)?;
    Ok(ramflux_protocol::encode_base64url(Sha256::digest(bytes)))
}

impl RouterRedbStore {
    /// Look up a complete assignment before generic replay rejection. Legacy
    /// receipts return None and retain their historical replay behavior.
    /// # Errors
    /// Returns storage errors or `idempotency_conflict` for changed sender content.
    pub fn sender_assignment(
        &self,
        root: &str,
        envelope: &ramflux_protocol::Envelope,
        now: i64,
    ) -> Result<Option<SenderAssignment>, NodeCoreError> {
        let key =
            local_delivery_storage_key(root, &envelope.envelope_id, &envelope.target_delivery_id);
        let tx = self.db.begin_read().map_err(incarnation::error)?;
        let table =
            tx.open_table(ROUTER_LOCAL_DELIVERY_ENVELOPE_TABLE).map_err(incarnation::error)?;
        let mut assignment = None;
        if let Some(row) = table.get(key.as_str()).map_err(incarnation::error)? {
            let record: LocalDeliveryEnvelopeRecord =
                serde_json::from_slice(row.value()).map_err(incarnation::error)?;
            if record.expires_at > now {
                assignment = record.assignment;
            }
        }
        if assignment.is_none()
            && let Some(wal) = &self.submission_wal
        {
            assignment = wal.sender_assignment(root, envelope, now)?;
        }
        if let Some(assignment) = &assignment {
            if assignment.digest != content_digest(envelope)? {
                return Err(SenderRetryRefusal::IdempotencyConflict.into());
            }
            if self.inbox_status(&assignment.target_delivery_id)?.0.as_deref()
                != Some(assignment.inbox_incarnation_id.as_str())
            {
                return Err(incarnation::error("incarnation_mismatch"));
            }
        }
        Ok(assignment)
    }
}

pub(super) fn constrain_assignment(
    tx: &redb::WriteTransaction,
    root: &str,
    entry: &InboxEntry,
    deadline: i64,
) -> Result<(), NodeCoreError> {
    let key =
        local_delivery_storage_key(root, &entry.envelope.envelope_id, &entry.target_delivery_id);
    let mut table =
        tx.open_table(ROUTER_LOCAL_DELIVERY_ENVELOPE_TABLE).map_err(incarnation::error)?;
    let mut record: LocalDeliveryEnvelopeRecord = {
        let row = table
            .get(key.as_str())
            .map_err(incarnation::error)?
            .ok_or_else(|| incarnation::error("missing accepted sender index"))?;
        serde_json::from_slice(row.value()).map_err(incarnation::error)?
    };
    if let Some(assignment) = &mut record.assignment {
        assignment.retain_until = deadline;
    }
    let bytes = serde_json::to_vec(&record).map_err(incarnation::error)?;
    table.insert(key.as_str(), bytes.as_slice()).map_err(incarnation::error)?;
    Ok(())
}

#[cfg(test)]
mod tests;

mod registry;
pub(super) use registry::Registry;
pub use registry::{RetryAdmission, RetryOwner, RetryWaiter};

pub(crate) use registry::RetryAbort;
