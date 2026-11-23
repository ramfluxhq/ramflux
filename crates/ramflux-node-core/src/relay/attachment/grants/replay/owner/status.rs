// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Session-scoped resume inspection and bounded durable cleanup recovery.
use super::{
    AttachmentBackend, AttachmentLedgerError, AttachmentOwner, AttachmentReservation,
    AttachmentReservationState, BackendSegment, ContentManifest, OwnerAdmissionError,
    QualifiedOwner, publication, segment_spec,
};
use crate::relay::attachment::backend::LocalAttachmentBackend;
use ramflux_protocol::attachment_wire::{AttachmentAccountStatus, AttachmentUploadStatus};

/// Exact immutable upload identity expected by the resuming sender.
pub struct AttachmentCheckpoint {
    pub upload_id: [u8; 32],
    pub object_id: [u8; 32],
    pub manifest_hash: [u8; 32],
    pub payload_generation: u64,
    pub index: u32,
}

impl super::super::super::ScopedGrantRegistry {
    /// # Errors
    /// Refuses unreadable accounting or an invalid authenticated account anchor.
    pub fn account_status_after_authentication(
        &self,
        requester: &QualifiedOwner,
    ) -> Result<AttachmentAccountStatus, AttachmentLedgerError> {
        let owner = AttachmentOwner::from_authenticated_session(&requester.account_anchor)?;
        self.ledger.account_status(&owner)
    }

    /// Rechecks the upload fence and reconciles bytes before returning durable slice bits.
    /// # Errors
    /// Refuses foreign uploads, substituted identities, stale generations, expiry and busy I/O.
    pub fn checkpoint_after_authentication(
        &self,
        requester: &QualifiedOwner,
        query: &AttachmentCheckpoint,
        backend: &LocalAttachmentBackend,
        now: u64,
    ) -> Result<AttachmentUploadStatus, OwnerAdmissionError> {
        let owner = AttachmentOwner::from_authenticated_session(&requester.account_anchor)?;
        let _lease = self.acquire_upload(query.upload_id, true)?;
        let record = self.ledger.reservation(&owner, &query.upload_id)?;
        check_record(&record, query, now)?;
        let spec = segment_spec(&record, u64::from(query.index))?;
        let status = backend.checkpoint(&spec).map_err(publication)?;
        // Cleanup/expiry may fence the ledger while physical reconciliation runs.
        check_record(&self.ledger.reservation(&owner, &query.upload_id)?, query, now)?;
        let mut received_bytes = 0_u64;
        for bit in 0..spec.length().div_ceil(u64::from(spec.chunk_bytes())) {
            if status.received & (1 << bit) != 0 {
                received_bytes += (spec.length() - bit * u64::from(spec.chunk_bytes()))
                    .min(u64::from(spec.chunk_bytes()));
            }
        }
        Ok(AttachmentUploadStatus {
            state: if record.state == AttachmentReservationState::Committed {
                "committed"
            } else {
                "pending"
            }
            .into(),
            payload_generation: record.pending_generation,
            index: query.index,
            received_bitmap: status.received,
            received_bytes,
            segment_length: spec.length(),
            network_chunk_bytes: spec.chunk_bytes(),
            lease_until: record.lease_until,
            lease_hard_until: record.lease_hard_until,
            expires_at: record.expires_at,
        })
    }

    /// One bounded expiry/debt turn. Failed backend cleanup stays charged and is retried.
    /// # Errors
    /// Refuses unreadable ledger state. Individual busy/failed erasures retain their debt.
    pub fn cleanup_turn(
        &self,
        backend: &dyn AttachmentBackend,
        now: u64,
        after: Option<&[u8]>,
    ) -> Result<Option<Vec<u8>>, AttachmentLedgerError> {
        self.ledger.gc_due(now, 64)?;
        let page = self.ledger.debt_page(after, 8)?;
        for record in page.jobs {
            let owner = AttachmentOwner::from_authenticated_session(&record.owner)?;
            let result = self.reclaim_upload(&owner, &record.upload_id, backend);
            if let Err(error) = result {
                tracing::debug!(%error, "attachment cleanup debt retained");
            }
        }
        Ok(page.next)
    }

    fn reclaim_upload(
        &self,
        owner: &AttachmentOwner,
        upload: &[u8; 32],
        backend: &dyn AttachmentBackend,
    ) -> Result<(), OwnerAdmissionError> {
        let _lease = self.acquire_upload(*upload, true)?;
        self.ledger.reclaim(owner, upload, |record| {
            if record.manifest_hash.is_none() {
                return Ok(());
            }
            let manifest = ContentManifest::decode_signed(&record.manifest_bytes)
                .map_err(|_| AttachmentLedgerError::State)?;
            let count = manifest
                .manifest()
                .layout
                .dimensions()
                .map_err(|_| AttachmentLedgerError::State)?
                .0;
            for index in 0..count {
                let spec =
                    BackendSegment::from_manifest(&manifest, record.pending_generation, index)
                        .map_err(|_| AttachmentLedgerError::State)?;
                backend.delete(&spec).map_err(|_| AttachmentLedgerError::State)?;
            }
            Ok(())
        })?;
        Ok(())
    }
}

fn check_record(
    record: &AttachmentReservation,
    query: &AttachmentCheckpoint,
    now: u64,
) -> Result<(), OwnerAdmissionError> {
    if record.object_id != query.object_id
        || record.manifest_hash != Some(query.manifest_hash)
        || record.pending_generation != query.payload_generation
    {
        return Err(AttachmentLedgerError::Conflict.into());
    }
    match record.state {
        AttachmentReservationState::Pending => {
            crate::relay::attachment::quota::pending(record, now)?;
        }
        AttachmentReservationState::Committed
            if record.expires_at.is_some_and(|expiry| now < expiry) =>
        {
            record.require_bound_generation()?;
        }
        _ => return Err(AttachmentLedgerError::Expired.into()),
    }
    Ok(())
}
