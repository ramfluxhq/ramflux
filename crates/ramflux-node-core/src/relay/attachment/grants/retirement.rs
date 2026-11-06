// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
//! One publication owner per open database. Cancellation never substitutes for a join.
use super::{
    AttachmentLedgerError, AttachmentOwner, AttachmentRegistrationReceipt, AttachmentReservation,
    AttachmentReservationState, GRANTS, ObjectRelayCapability, RECORDS, ReadableDatabase,
    ReadableTable, RegisteredAttachmentGrant, ScopedGrantRegistry, ScopedGrantState,
    ScopedRegistrationAuth, TableDefinition, VerifiedScopedGrant, clock, decode, encode, hex,
    invalid, key, store,
};
use ramflux_protocol::large_attachment::{ScopedAttachmentGrant, VerifiedAttachmentRetirement};
use std::{
    collections::BTreeMap,
    sync::{
        Arc, Mutex, MutexGuard, OnceLock, Weak,
        atomic::{AtomicBool, Ordering},
    },
};
const OPERATIONS: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("native_attachment_retirement_operations_v1");
const REQUESTS: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("native_attachment_retirement_requests_v1");
type Leases = BTreeMap<[u8; 32], Vec<Weak<AtomicBool>>>;
#[derive(Default)]
pub(super) struct LeaseOwner(Mutex<Leases>);
impl LeaseOwner {
    pub(super) fn lock(&self) -> Result<MutexGuard<'_, Leases>, AttachmentLedgerError> {
        self.0.lock().map_err(|_| AttachmentLedgerError::State)
    }
}
pub(super) fn owner(db: &Arc<redb::Database>) -> Result<Arc<LeaseOwner>, AttachmentLedgerError> {
    static OWNERS: OnceLock<Mutex<BTreeMap<usize, Weak<LeaseOwner>>>> = OnceLock::new();
    let mut owners =
        OWNERS.get_or_init(Mutex::default).lock().map_err(|_| AttachmentLedgerError::State)?;
    owners.retain(|_, v| v.strong_count() > 0);
    let id = Arc::as_ptr(db) as usize;
    if let Some(old) = owners.get(&id).and_then(Weak::upgrade) {
        return Ok(old);
    }
    let owner = Arc::new(LeaseOwner::default());
    owners.insert(id, Arc::downgrade(&owner));
    Ok(owner)
}
pub(super) fn install(tx: &redb::WriteTransaction) -> Result<(), AttachmentLedgerError> {
    let _ = tx.open_table(OPERATIONS).map_err(store)?;
    let _ = tx.open_table(REQUESTS).map_err(store)?;
    Ok(())
}
pub(super) fn busy(leases: &Leases, id: &[u8; 32]) -> bool {
    leases.get(id).is_some_and(|v| v.iter().any(|w| w.strong_count() > 0))
}
pub(super) fn forget(
    tx: &redb::WriteTransaction,
    id: &[u8; 32],
) -> Result<(), AttachmentLedgerError> {
    let mut requests = tx.open_table(REQUESTS).map_err(store)?;
    let op = requests.remove(id.as_slice()).map_err(store)?.map(|v| v.value().to_vec());
    if let Some(op) = op {
        tx.open_table(OPERATIONS)
            .map_err(store)?
            .remove(operation_key(id, &op).as_slice())
            .map_err(store)?;
    }
    Ok(())
}
/// Post-authenticated transport result. Only Retired permits a successful ACK.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetirementOutcome {
    RevocationPending,
    Retired,
}
/// Holds actual backend/publication ownership until dropped, even after cancellation.
/// Future QUIC/HTTPS admission must acquire this after authenticating the operation,
/// and retain it across backend work, bounded output and final flush.
pub struct GrantPublicationLease {
    registry: ScopedGrantRegistry,
    grant: VerifiedScopedGrant,
    cancelled: Arc<AtomicBool>,
    now: u64,
}
impl GrantPublicationLease {
    #[must_use]
    pub fn cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }
    /// Executes a bounded publication while retaining actual ownership. Retirement
    /// can fence concurrently, but cannot ACK until this lease has been dropped.
    /// # Errors
    /// Refuses cancellation, expiry, or noncurrent grant state before publication.
    pub fn publish<T>(
        &self,
        now: u64,
        write: impl FnOnce() -> Result<T, AttachmentLedgerError>,
    ) -> Result<T, AttachmentLedgerError> {
        self.check_current(now)?;
        write()
    }
    /// # Errors
    /// Refuses stale, cancelled or expired work. Recheck before each output chunk.
    pub fn check_current(&self, now: u64) -> Result<(), AttachmentLedgerError> {
        if self.cancelled() || now < self.now {
            return Err(AttachmentLedgerError::State);
        }
        self.registry.current(&self.grant, now).map(|_| ())
    }
}
impl ScopedGrantRegistry {
    pub(super) fn stored_grant(
        &self,
        row: &RegisteredAttachmentGrant,
    ) -> Result<VerifiedScopedGrant, AttachmentLedgerError> {
        let bytes = ramflux_protocol::decode_base64url(&row.capability).map_err(invalid)?;
        AttachmentRegistrationReceipt::decode_capability(
            &bytes,
            &self.authority.source,
            self.authority.generation,
            &self.authority.signing_public_key,
            row.expires_at.saturating_sub(1),
        )
        .map(|v| v.0)
        .map_err(invalid)
    }
    pub(super) fn current(
        &self,
        grant: &VerifiedScopedGrant,
        now: u64,
    ) -> Result<RegisteredAttachmentGrant, AttachmentLedgerError> {
        let row = self.lookup(&grant.grant().grant_id)?.ok_or(AttachmentLedgerError::State)?;
        if row.state != ScopedGrantState::Active
            || self.stored_grant(&row)?.grant() != grant.grant()
        {
            return Err(AttachmentLedgerError::State);
        }
        if now >= row.expires_at || now.saturating_add(5) < grant.grant().issued_at {
            return Err(AttachmentLedgerError::Expired);
        }
        let owner =
            AttachmentOwner::from_authenticated_session(&grant.grant().owner.account_anchor)?;
        let tx = self.ledger.db.begin_read().map_err(store)?;
        let records = tx.open_table(RECORDS).map_err(store)?;
        let value = records
            .get(key(&owner, &row.upload_id).as_slice())
            .map_err(store)?
            .ok_or(AttachmentLedgerError::State)?;
        let payload: AttachmentReservation = decode(value.value())?;
        if payload.state != AttachmentReservationState::Committed
            || payload.object_id != grant.grant().object_id
            || payload.manifest_hash != Some(grant.grant().manifest_hash)
            || payload.expires_at.is_none_or(|expiry| now >= expiry)
        {
            return Err(AttachmentLedgerError::Expired);
        }
        Ok(row)
    }
    /// Adds the live-state gate to an ALREADY authenticated operation. This does
    /// not verify a native token/PoP or consume a nonce; those are separate owners.
    /// Rights are one of GET1, HEAD2, Missing4, Renew8, Ack16.
    /// # Errors
    /// Refuses noncurrent state, expiry, missing rights and more than32 live leases.
    #[cfg(test)]
    pub(crate) fn lease_after_operation_admission(
        &self,
        grant: &VerifiedScopedGrant,
        right: u32,
        now: u64,
    ) -> Result<GrantPublicationLease, AttachmentLedgerError> {
        self.lease_with_admission(grant, right, now, |_| Ok(now))
    }
    pub(super) fn lease_with_admission<E: From<AttachmentLedgerError>>(
        &self,
        grant: &VerifiedScopedGrant,
        right: u32,
        now: u64,
        admit: impl FnOnce(&redb::WriteTransaction) -> Result<u64, E>,
    ) -> Result<GrantPublicationLease, E> {
        if !matches!(right, 1 | 2 | 4 | 8 | 16) || grant.grant().rights & right == 0 {
            return Err(AttachmentLedgerError::Conflict.into());
        }
        let mut leases = self.leases.lock()?;
        leases.retain(|_, v| {
            v.retain(|w| w.strong_count() > 0);
            !v.is_empty()
        });
        if leases.values().map(Vec::len).sum::<usize>() >= 32 {
            return Err(AttachmentLedgerError::Capacity.into());
        }
        self.current(grant, now)?;
        // Fence clock rollback durably, sharing the registration clock owner.
        let tx = self.ledger.db.begin_write().map_err(store)?;
        let admitted_now = admit(&tx)?;
        clock(&tx, admitted_now)?;
        tx.commit().map_err(store)?;
        let cancelled = Arc::new(AtomicBool::new(false));
        leases.entry(grant.grant().grant_id).or_default().push(Arc::downgrade(&cancelled));
        Ok(GrantPublicationLease {
            registry: self.clone(),
            grant: grant.clone(),
            cancelled,
            now: admitted_now,
        })
    }
    /// Authenticates the original current owner and durably fences one grant.
    /// The caller's native operation admission must also consume the operation `PoP`
    /// before invoking this dormant component. Retry Pending with the same request.
    /// # Errors
    /// Refuses substitutions, stale owner trust, operation-id reuse or storage failure.
    pub fn retire(
        &self,
        signed: &VerifiedAttachmentRetirement,
        auth: &ScopedRegistrationAuth<'_>,
    ) -> Result<RetirementOutcome, AttachmentLedgerError> {
        let r = signed.request();
        let now = auth.invocation.now;
        let row = self.lookup(&r.grant_id)?.ok_or(AttachmentLedgerError::State)?;
        let grant = self.stored_grant(&row)?;
        let g: &ScopedAttachmentGrant = grant.grant();
        if r.reference_id != g.reference_id
            || r.grant_hash != g.hash().map_err(invalid)?
            || r.grant_epoch != g.epoch
            || r.source_authority != self.authority.source
            || r.authority_generation != self.authority.generation
            || ramflux_protocol::encode_base64url(signed.signer())
                != auth.invocation.token.owner_public_key
            || now.saturating_add(5) < r.issued_at
        {
            return Err(AttachmentLedgerError::Conflict);
        }
        let body = hex(blake3::hash(&r.signing_bytes().map_err(invalid)?).as_bytes());
        self.authenticate_owner(g, ObjectRelayCapability::Tombstone, &body, auth)?;
        let leases = self.leases.lock()?;
        let tx = self.ledger.db.begin_write().map_err(store)?;
        clock(&tx, now)?;
        let mut rows = tx.open_table(GRANTS).map_err(store)?;
        let mut current: RegisteredAttachmentGrant = {
            let value = rows
                .get(r.grant_id.as_slice())
                .map_err(store)?
                .ok_or(AttachmentLedgerError::State)?;
            decode(value.value())?
        };
        let canonical = r.canonical_bytes().map_err(invalid)?;
        let mut ops = tx.open_table(OPERATIONS).map_err(store)?;
        let mut requests = tx.open_table(REQUESTS).map_err(store)?;
        if let Some(old) =
            ops.get(operation_key(&r.grant_id, &r.operation_id).as_slice()).map_err(store)?
            && old.value() != canonical
        {
            return Err(AttachmentLedgerError::Conflict);
        }
        if let Some(old) = requests.get(r.grant_id.as_slice()).map_err(store)?
            && old.value() != r.operation_id
        {
            return Err(AttachmentLedgerError::Conflict);
        }
        ops.insert(operation_key(&r.grant_id, &r.operation_id).as_slice(), canonical.as_slice())
            .map_err(store)?;
        requests.insert(r.grant_id.as_slice(), r.operation_id.as_slice()).map_err(store)?;
        let pending = busy(&leases, &r.grant_id);
        let already_retired = current.state == ScopedGrantState::Retired;
        if !already_retired {
            current.state = ScopedGrantState::Retiring;
        }
        rows.insert(r.grant_id.as_slice(), encode(&current)?.as_slice()).map_err(store)?;
        drop(requests);
        drop(ops);
        drop(rows);
        tx.commit().map_err(store)?;
        if let Some(active) = leases.get(&r.grant_id) {
            for flag in active.iter().filter_map(Weak::upgrade) {
                flag.store(true, Ordering::Release);
            }
        }
        if pending {
            return Ok(RetirementOutcome::RevocationPending);
        }
        if !already_retired {
            // Separate durable transitions: a crash here preserves the denial fence.
            let tx = self.ledger.db.begin_write().map_err(store)?;
            let mut rows = tx.open_table(GRANTS).map_err(store)?;
            current.state = ScopedGrantState::Retired;
            rows.insert(r.grant_id.as_slice(), encode(&current)?.as_slice()).map_err(store)?;
            drop(rows);
            tx.commit().map_err(store)?;
        }
        Ok(RetirementOutcome::Retired)
    }
}

fn operation_key(grant: &[u8], operation: &[u8]) -> Vec<u8> {
    let mut key = grant.to_vec();
    key.extend(operation);
    key
}
