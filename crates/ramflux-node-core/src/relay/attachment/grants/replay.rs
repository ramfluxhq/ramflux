// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
//! Source-authoritative replay restrictions. SDK backups never import this server state.
#[cfg(test)]
mod capacity_tests;
#[cfg(test)]
mod rebuild_tests;
mod storage;
#[cfg(test)]
mod tests;
use super::{AttachmentLedgerError, ScopedGrantRegistry, VerifiedScopedGrant, store};
pub(super) use storage::install;
use storage::{consume, gc};
/// Metadata of a `PoP` already verified against the exact native operation by P9.
/// This type does not authenticate a signature, token, range, or requester.
#[derive(Debug, Clone, Copy)]
pub struct AttachmentReplayProof {
    pub nonce: [u8; 32],
    pub issued_at: u64,
    pub expires_at: u64,
}
#[derive(Debug, thiserror::Error)]
pub enum AttachmentReplayError {
    #[error("invalid proof lifetime or time representation")]
    Invalid,
    #[error("proof expired")]
    Expired,
    #[error("proof nonce already consumed")]
    Replay,
    #[error("replay protection capacity exceeded")]
    ReplayProtectionCapacity,
    #[error("replay clock rollback")]
    ClockUncertain,
    #[error(transparent)]
    Ledger(#[from] AttachmentLedgerError),
}
impl ScopedGrantRegistry {
    /// Atomically admits a current grant and consumes its authenticated requester's
    /// nonce before returning publication ownership. P9 MUST first verify trust,
    /// token/PoP, canonical operation and exact method/range/body binding. All future
    /// native verifiers use this shared owner; this does not activate any endpoint.
    /// # Errors
    /// Refuses invalid/expired/replayed proofs, clock rollback, capacity and stale grants.
    pub fn admit_operation_after_authentication(
        &self,
        grant: &VerifiedScopedGrant,
        right: u32,
        proof: &AttachmentReplayProof,
        now: u64,
    ) -> Result<super::GrantPublicationLease, AttachmentReplayError> {
        self.lease_with_admission(grant, right, now, Into::into, |tx| {
            self.admit_in(tx, grant, proof, now)
        })
    }
    /// Re-reads authority and consumes the nonce in the caller's write transaction.
    pub(super) fn admit_in(
        &self,
        tx: &redb::WriteTransaction,
        grant: &VerifiedScopedGrant,
        proof: &AttachmentReplayProof,
        now: u64,
    ) -> Result<u64, AttachmentReplayError> {
        let effective = storage::clock(tx, now)?;
        // Re-read authority in the SAME write transaction as nonce consumption.
        let row = super::ReadableTable::get(
            &tx.open_table(super::GRANTS).map_err(store)?,
            grant.grant().grant_id.as_slice(),
        )
        .map_err(store)?
        .map(|v| super::decode::<super::RegisteredAttachmentGrant>(v.value()))
        .transpose()?
        .ok_or(AttachmentLedgerError::State)?;
        if row.state != super::ScopedGrantState::Active
            || self.stored_grant(&row)?.grant() != grant.grant()
        {
            return Err(AttachmentLedgerError::State.into());
        }
        let owner = super::AttachmentOwner::from_authenticated_session(
            &grant.grant().owner.account_anchor,
        )?;
        let table = tx.open_table(super::RECORDS).map_err(store)?;
        let value =
            super::ReadableTable::get(&table, super::key(&owner, &row.upload_id).as_slice())
                .map_err(store)?
                .ok_or(AttachmentLedgerError::State)?;
        let payload: super::AttachmentReservation = super::decode(value.value())?;
        if payload.state != super::AttachmentReservationState::Committed
            || payload.object_id != grant.grant().object_id
            || payload.manifest_hash != Some(grant.grant().manifest_hash)
            || payload.expires_at.is_none_or(|t| effective >= t)
            || effective >= row.expires_at
        {
            return Err(AttachmentLedgerError::Expired.into());
        }
        payload.require_bound_generation()?;
        consume(
            tx,
            &self.authority.source,
            &grant.grant().grantee,
            proof,
            effective,
            storage::Limits::default(),
        )?;
        Ok(effective)
    }
    /// Reclaims at most64 expired consumption rows. Never evicts live evidence.
    /// # Errors
    /// Refuses invalid page limits, clock rollback or unavailable/corrupt storage.
    pub fn gc_consumed_proofs(
        &self,
        now: u64,
        limit: usize,
    ) -> Result<usize, AttachmentReplayError> {
        if limit == 0 || limit > 64 {
            return Err(AttachmentReplayError::Invalid);
        }
        let tx = self.ledger.db.begin_write().map_err(store)?;
        let now = storage::clock(&tx, now)?;
        let count = gc(&tx, now, limit)?;
        tx.commit().map_err(store)?;
        Ok(count)
    }
}

impl ScopedGrantRegistry {
    /// Read-only replay pre-check for the authenticated requester's nonce.
    pub(super) fn nonce_consumed_read(
        &self,
        requester: &ramflux_protocol::large_attachment::QualifiedOwner,
        nonce: &[u8; 32],
    ) -> Result<bool, AttachmentReplayError> {
        use redb::ReadableTable;
        let mut key = storage::principal(&self.authority.source, requester).to_vec();
        key.extend(nonce);
        let tx = super::ReadableDatabase::begin_read(&*self.ledger.db).map_err(store)?;
        let rows = tx.open_table(storage::NONCES).map_err(store)?;
        Ok(rows.get(key.as_slice()).map_err(store)?.is_some())
    }
}
/// Shared with the renewal admission transaction: the same nonce ledger, fence and charge.
pub(super) fn nonce_consumed(
    tx: &redb::WriteTransaction,
    source: &str,
    requester: &ramflux_protocol::large_attachment::QualifiedOwner,
    nonce: &[u8; 32],
) -> Result<bool, AttachmentReplayError> {
    use redb::ReadableTable;
    let mut key = storage::principal(source, requester).to_vec();
    key.extend(nonce);
    let rows = tx.open_table(storage::NONCES).map_err(store)?;
    Ok(rows.get(key.as_slice()).map_err(store)?.is_some())
}
pub(super) fn fence_clock(
    tx: &redb::WriteTransaction,
    now: u64,
) -> Result<u64, AttachmentReplayError> {
    storage::clock(tx, now)
}
pub(super) fn consume_nonce(
    tx: &redb::WriteTransaction,
    source: &str,
    requester: &ramflux_protocol::large_attachment::QualifiedOwner,
    proof: &AttachmentReplayProof,
    now: u64,
) -> Result<(), AttachmentReplayError> {
    consume(tx, source, requester, proof, now, storage::Limits::default())
}
