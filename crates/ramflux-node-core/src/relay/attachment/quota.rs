// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
use super::{
    AttachmentLedger, AttachmentLedgerError, AttachmentOwner, AttachmentQuota,
    AttachmentReservation, AttachmentReservationRequest, AttachmentReservationState, DEADLINES,
    DEBTS, OBJECTS, RECORDS, ReadableTable, TOTALS, deadline, decode, encode, key, store,
};
use ramflux_protocol::large_attachment::VerifiedContentManifest;
impl AttachmentLedger {
    /// Reserves exact ciphertext bytes (tags included) before encryption/upload.
    /// Replays are immutable and do not renew leases or charge twice.
    /// # Errors
    /// Refuses quota/metadata exhaustion, conflicting identity, overflow or storage failure.
    pub fn reserve(
        &self,
        owner: &AttachmentOwner,
        request: AttachmentReservationRequest,
        now: u64,
    ) -> Result<AttachmentReservation, AttachmentLedgerError> {
        self.reserve_with(owner, request, now, None)
    }

    /// Reserves with the client's hard deadline. The stored cap is the earlier of that
    /// deadline and the policy cap. A replay returns the stored record and ignores the new deadline.
    /// # Errors
    /// Refuses an already-elapsed deadline, quota exhaustion, conflicting identity, or storage failure.
    pub fn reserve_with_client_deadline(
        &self,
        owner: &AttachmentOwner,
        request: AttachmentReservationRequest,
        now: u64,
        client_hard_until: u64,
    ) -> Result<AttachmentReservation, AttachmentLedgerError> {
        self.reserve_with(owner, request, now, Some(client_hard_until))
    }

    fn reserve_with(
        &self,
        owner: &AttachmentOwner,
        request: AttachmentReservationRequest,
        now: u64,
        client_hard_until: Option<u64>,
    ) -> Result<AttachmentReservation, AttachmentLedgerError> {
        let tx = self.db.begin_write().map_err(store)?;
        let record = self.reserve_on(&tx, owner, &request, now, client_hard_until)?;
        tx.commit().map_err(store)?;
        Ok(record)
    }

    /// Inserts or replays one reservation inside the caller's write. The caller commits.
    /// # Errors
    /// Refuses quota exhaustion, conflicting identity, an elapsed deadline, or storage failure.
    pub(super) fn reserve_on(
        &self,
        tx: &redb::WriteTransaction,
        owner: &AttachmentOwner,
        request: &AttachmentReservationRequest,
        now: u64,
        client_hard_until: Option<u64>,
    ) -> Result<AttachmentReservation, AttachmentLedgerError> {
        let size = request.layout.dimensions().map_err(|_| AttachmentLedgerError::Invalid)?.1;
        if request.layout.plaintext_length > self.policy.max_plaintext_bytes {
            return Err(AttachmentLedgerError::Invalid);
        }
        let record_key = key(owner, &request.upload_id);
        if super::identity::fenced(tx, &record_key)? {
            return Err(AttachmentLedgerError::State);
        }
        let existing = {
            let records = tx.open_table(RECORDS).map_err(store)?;
            match records.get(record_key.as_slice()).map_err(store)? {
                Some(found) => Some(decode::<AttachmentReservation>(found.value())?),
                None => None,
            }
        };
        if let Some(record) = existing {
            return replayed(record, request, now);
        }
        place_pending(self, tx, owner, request, &PendingTerms { now, client_hard_until, size })
    }

    /// Binds a provisional reservation once to the signature-verified ciphertext MC.
    /// The caller must also authenticate current owner authority before this call.
    /// # Errors
    /// Refuses owner/object/layout substitution, expired pending work or rebinding.
    pub fn bind(
        &self,
        owner: &AttachmentOwner,
        id: &[u8; 32],
        manifest: &VerifiedContentManifest,
        now: u64,
    ) -> Result<AttachmentReservation, AttachmentLedgerError> {
        let signed = manifest
            .manifest()
            .signed_bytes(manifest.signature())
            .map_err(|_| AttachmentLedgerError::Invalid)?;
        let tx = self.db.begin_write().map_err(store)?;
        let record = Self::bind_on(&tx, owner, id, &BindOn { manifest, signed: &signed, now })?;
        tx.commit().map_err(store)?;
        Ok(record)
    }

    /// Binds inside the caller's write. `signed` is the exact MC container.
    /// # Errors
    /// Refuses substitution, an oversized container, expiry, or a different hash.
    pub(super) fn bind_on(
        tx: &redb::WriteTransaction,
        owner: &AttachmentOwner,
        id: &[u8; 32],
        input: &BindOn<'_>,
    ) -> Result<AttachmentReservation, AttachmentLedgerError> {
        let native = input.manifest.manifest();
        let hash = native.hash().map_err(|_| AttachmentLedgerError::Invalid)?;
        let signed = input.signed.to_vec();
        let now = input.now;
        Self::change_on(tx, owner, id, |record, _| apply_bind(record, native, hash, &signed, now))
    }
    /// Atomic reserved-to-used settlement after the trusted backend has durably
    /// verified/committed the bound payload. The generation the backend reports must
    /// equal the ledger's `pending_generation`; it is bound once and never taken from a request.
    /// This method does not validate backend data.
    /// # Errors
    /// Refuses expired, unbound or terminal work and storage/length overflow.
    pub fn commit(
        &self,
        owner: &AttachmentOwner,
        id: &[u8; 32],
        backend_generation: u64,
        now: u64,
    ) -> Result<AttachmentReservation, AttachmentLedgerError> {
        let tx = self.db.begin_write().map_err(store)?;
        let record = Self::commit_on(&tx, owner, id, backend_generation, now)?;
        tx.commit().map_err(store)?;
        Ok(record)
    }

    /// Settles reserved bytes inside the caller's write.
    /// # Errors
    /// Refuses expired, unbound, or terminal work and a generation that is not the ledger's.
    pub(super) fn commit_on(
        tx: &redb::WriteTransaction,
        owner: &AttachmentOwner,
        id: &[u8; 32],
        backend_generation: u64,
        now: u64,
    ) -> Result<AttachmentReservation, AttachmentLedgerError> {
        Self::change_on(tx, owner, id, |record, total| {
            apply_commit(record, total, backend_generation, now)
        })
    }

    /// Cancels pending upload debt inside the caller's write.
    /// # Errors
    /// Refuses committed or terminal work.
    pub(super) fn abandon_on(
        tx: &redb::WriteTransaction,
        owner: &AttachmentOwner,
        id: &[u8; 32],
    ) -> Result<AttachmentReservation, AttachmentLedgerError> {
        Self::change_on(tx, owner, id, |record, _| apply_abandon(record))
    }

    /// Fences a committed upload for cleanup once no grant can read it. Idempotent for
    /// work already in cleanup.
    /// # Errors
    /// Refuses pending or unknown work.
    pub(super) fn fence_committed(
        &self,
        owner: &AttachmentOwner,
        id: &[u8; 32],
    ) -> Result<AttachmentReservation, AttachmentLedgerError> {
        self.change(owner, id, |record, _| match record.state {
            AttachmentReservationState::Committed => {
                record.state = AttachmentReservationState::DebtCommitted;
                Ok(())
            }
            AttachmentReservationState::DebtCommitted | AttachmentReservationState::Released => {
                Ok(())
            }
            _ => Err(AttachmentLedgerError::State),
        })
    }

    pub(super) fn change(
        &self,
        owner: &AttachmentOwner,
        id: &[u8; 32],
        update: impl FnOnce(
            &mut AttachmentReservation,
            &mut AttachmentQuota,
        ) -> Result<(), AttachmentLedgerError>,
    ) -> Result<AttachmentReservation, AttachmentLedgerError> {
        let tx = self.db.begin_write().map_err(store)?;
        let record = Self::change_on(&tx, owner, id, update)?;
        tx.commit().map_err(store)?;
        Ok(record)
    }

    pub(super) fn change_on(
        tx: &redb::WriteTransaction,
        owner: &AttachmentOwner,
        id: &[u8; 32],
        update: impl FnOnce(
            &mut AttachmentReservation,
            &mut AttachmentQuota,
        ) -> Result<(), AttachmentLedgerError>,
    ) -> Result<AttachmentReservation, AttachmentLedgerError> {
        let record_key = key(owner, id);
        let mut records = tx.open_table(RECORDS).map_err(store)?;
        let mut record: AttachmentReservation = {
            let v = records
                .get(record_key.as_slice())
                .map_err(store)?
                .ok_or(AttachmentLedgerError::Conflict)?;
            decode(v.value())?
        };
        let before = record.clone();
        let mut totals = tx.open_table(TOTALS).map_err(store)?;
        let mut total: AttachmentQuota = {
            let v =
                totals.get(owner.0.as_str()).map_err(store)?.ok_or(AttachmentLedgerError::State)?;
            decode(v.value())?
        };
        update(&mut record, &mut total)?;
        let mut index = tx.open_table(DEADLINES).map_err(store)?;
        if let Some(time) = live_deadline(&before) {
            index.remove(deadline(time, &record_key).as_slice()).map_err(store)?;
        }
        if let Some(time) = live_deadline(&record) {
            index.insert(deadline(time, &record_key).as_slice(), ()).map_err(store)?;
        }
        let mut debt = tx.open_table(DEBTS).map_err(store)?;
        if matches!(
            record.state,
            AttachmentReservationState::DebtPending | AttachmentReservationState::DebtCommitted
        ) {
            debt.insert(record_key.as_slice(), ()).map_err(store)?;
        } else {
            debt.remove(record_key.as_slice()).map_err(store)?;
        }
        drop(debt);
        super::format::bind(tx, &record)?;
        records.insert(record_key.as_slice(), encode(&record)?.as_slice()).map_err(store)?;
        totals.insert(owner.0.as_str(), encode(&total)?.as_slice()).map_err(store)?;
        drop(index);
        drop(records);
        drop(totals);
        Ok(record)
    }
}

struct PendingTerms {
    now: u64,
    client_hard_until: Option<u64>,
    size: u64,
}

/// Bind inputs kept together so the ledger method stays within the argument limit.
pub(super) struct BindOn<'a> {
    pub manifest: &'a VerifiedContentManifest,
    pub signed: &'a [u8],
    pub now: u64,
}

fn place_pending(
    ledger: &AttachmentLedger,
    tx: &redb::WriteTransaction,
    owner: &AttachmentOwner,
    request: &AttachmentReservationRequest,
    terms: &PendingTerms,
) -> Result<AttachmentReservation, AttachmentLedgerError> {
    if super::terminal::is_terminal(tx, &request.object_id)? {
        return Err(AttachmentLedgerError::State);
    }
    let mut objects = tx.open_table(OBJECTS).map_err(store)?;
    let object_key = key(owner, &request.object_id);
    let fenced = tx
        .open_table(super::identity::FENCE_OBJECTS)
        .map_err(store)?
        .get(object_key.as_slice())
        .map_err(store)?
        .is_some();
    if fenced || objects.get(object_key.as_slice()).map_err(store)?.is_some() {
        return Err(AttachmentLedgerError::Conflict);
    }
    let (hard, lease_until) = pending_window(&ledger.policy, terms.now, terms.client_hard_until)?;
    let mut totals = tx.open_table(TOTALS).map_err(store)?;
    let existing = totals.get(owner.0.as_str()).map_err(store)?;
    let new_owner = existing.is_none();
    let mut total: AttachmentQuota =
        existing.map_or(Ok(AttachmentQuota::default()), |v| decode(v.value()))?;
    charge_quota(&ledger.policy, &mut total, terms.size)?;
    let record = pending_record(owner, request, terms.size, &ledger.policy, hard, lease_until);
    super::terminal::admit(tx, &ledger.policy, new_owner, &mut total)?;
    total.reserved += terms.size;
    total.records += 1;
    let record_key = key(owner, &request.upload_id);
    totals.insert(owner.0.as_str(), encode(&total)?.as_slice()).map_err(store)?;
    tx.open_table(RECORDS)
        .map_err(store)?
        .insert(record_key.as_slice(), encode(&record)?.as_slice())
        .map_err(store)?;
    objects.insert(object_key.as_slice(), record_key.as_slice()).map_err(store)?;
    tx.open_table(DEADLINES)
        .map_err(store)?
        .insert(deadline(record.lease_until, &record_key).as_slice(), ())
        .map_err(store)?;
    drop(objects);
    drop(totals);
    Ok(record)
}

fn pending_window(
    policy: &super::AttachmentPolicy,
    now: u64,
    client_hard_until: Option<u64>,
) -> Result<(u64, u64), AttachmentLedgerError> {
    let policy_cap =
        now.checked_add(policy.pending_max_seconds).ok_or(AttachmentLedgerError::Invalid)?;
    let hard = client_hard_until.map_or(policy_cap, |deadline| policy_cap.min(deadline));
    let lease_until = now
        .checked_add(policy.pending_lease_seconds)
        .ok_or(AttachmentLedgerError::Invalid)?
        .min(hard);
    if hard <= now || lease_until <= now {
        return Err(AttachmentLedgerError::Expired);
    }
    Ok((hard, lease_until))
}

fn charge_quota(
    policy: &super::AttachmentPolicy,
    total: &mut AttachmentQuota,
    size: u64,
) -> Result<(), AttachmentLedgerError> {
    if total.records >= policy.max_records_per_owner
        || total
            .fences
            .checked_add(total.records)
            .is_none_or(|n| n >= policy.max_identity_fences_per_owner)
    {
        return Err(AttachmentLedgerError::Capacity);
    }
    let occupied = total
        .used
        .checked_add(total.reserved)
        .and_then(|n| n.checked_add(size))
        .ok_or(AttachmentLedgerError::Invalid)?;
    if occupied > policy.quota_bytes {
        return Err(AttachmentLedgerError::AccountQuotaExceeded {
            used: total.used,
            reserved: total.reserved,
            limit: policy.quota_bytes,
        });
    }
    Ok(())
}

fn pending_record(
    owner: &AttachmentOwner,
    request: &AttachmentReservationRequest,
    size: u64,
    policy: &super::AttachmentPolicy,
    hard: u64,
    lease_until: u64,
) -> AttachmentReservation {
    AttachmentReservation {
        owner: owner.0.clone(),
        upload_id: request.upload_id,
        object_id: request.object_id,
        plaintext_length: request.layout.plaintext_length,
        network_chunk_bytes: request.layout.network_chunk_bytes,
        size,
        manifest_hash: None,
        manifest_bytes: Vec::new(),
        state: AttachmentReservationState::Pending,
        lease_until,
        lease_hard_until: hard,
        lease_step: policy.pending_lease_seconds,
        retention_seconds: policy.retention_seconds,
        expires_at: None,
        pending_generation: 1,
        committed_generation: None,
    }
}

fn apply_bind(
    record: &mut AttachmentReservation,
    native: &ramflux_protocol::large_attachment::ContentManifest,
    hash: [u8; 32],
    signed: &[u8],
    now: u64,
) -> Result<(), AttachmentLedgerError> {
    if signed.len() > ramflux_protocol::large_attachment::MAX_MANIFEST_BYTES + 72 {
        return Err(AttachmentLedgerError::Invalid);
    }
    if native.owner.account_anchor != record.owner
        || native.object_id != record.object_id
        || native.layout.plaintext_length != record.plaintext_length
        || native.layout.network_chunk_bytes != record.network_chunk_bytes
    {
        return Err(AttachmentLedgerError::Conflict);
    }
    if record.manifest_hash.is_some_and(|old| old != hash) {
        return Err(AttachmentLedgerError::Conflict);
    }
    if record.manifest_bytes.is_empty() {
        record.manifest_bytes = signed.to_vec();
    } else if record.manifest_bytes.as_slice() != signed {
        return Err(AttachmentLedgerError::Conflict);
    }
    if record.state == AttachmentReservationState::Committed {
        if record.expires_at.is_none_or(|expiry| now >= expiry) {
            return Err(AttachmentLedgerError::Expired);
        }
        record.manifest_hash = Some(hash);
        return Ok(());
    }
    pending(record, now)?;
    record.manifest_hash = Some(hash);
    Ok(())
}

fn apply_commit(
    record: &mut AttachmentReservation,
    total: &mut AttachmentQuota,
    backend_generation: u64,
    now: u64,
) -> Result<(), AttachmentLedgerError> {
    if record.pending_generation == 0 {
        return Err(AttachmentLedgerError::State);
    }
    if backend_generation != record.pending_generation {
        return Err(AttachmentLedgerError::Conflict);
    }
    if record.state == AttachmentReservationState::Committed {
        if record.expires_at.is_none_or(|expiry| now >= expiry) {
            return Err(AttachmentLedgerError::Expired);
        }
        return Ok(());
    }
    pending(record, now)?;
    if record.manifest_hash.is_none() {
        return Err(AttachmentLedgerError::State);
    }
    record.expires_at = Some(super::retention::object_expiry(now, record.retention_seconds)?);
    total.reserved = total.reserved.checked_sub(record.size).ok_or(AttachmentLedgerError::State)?;
    total.used = total.used.checked_add(record.size).ok_or(AttachmentLedgerError::Invalid)?;
    record.committed_generation = Some(record.pending_generation);
    record.state = AttachmentReservationState::Committed;
    Ok(())
}

fn apply_abandon(record: &mut AttachmentReservation) -> Result<(), AttachmentLedgerError> {
    match record.state {
        AttachmentReservationState::Pending => {
            record.state = AttachmentReservationState::DebtPending;
        }
        AttachmentReservationState::DebtPending | AttachmentReservationState::Released => {}
        _ => return Err(AttachmentLedgerError::State),
    }
    Ok(())
}
fn replayed(
    record: AttachmentReservation,
    request: &AttachmentReservationRequest,
    now: u64,
) -> Result<AttachmentReservation, AttachmentLedgerError> {
    if record.object_id != request.object_id
        || record.plaintext_length != request.layout.plaintext_length
        || record.network_chunk_bytes != request.layout.network_chunk_bytes
    {
        return Err(AttachmentLedgerError::Conflict);
    }
    match record.state {
        AttachmentReservationState::Pending => pending(&record, now)?,
        AttachmentReservationState::Committed
            if record.expires_at.is_some_and(|time| time > now) => {}
        AttachmentReservationState::Committed => return Err(AttachmentLedgerError::Expired),
        _ => return Err(AttachmentLedgerError::State),
    }
    Ok(record)
}
pub(super) fn pending(
    record: &AttachmentReservation,
    now: u64,
) -> Result<(), AttachmentLedgerError> {
    if record.state != AttachmentReservationState::Pending {
        return Err(AttachmentLedgerError::State);
    }
    if now >= record.lease_until {
        return Err(AttachmentLedgerError::Expired);
    }
    Ok(())
}
pub(super) fn live_deadline(record: &AttachmentReservation) -> Option<u64> {
    match record.state {
        AttachmentReservationState::Pending => Some(record.lease_until),
        AttachmentReservationState::Committed => record.expires_at,
        _ => None,
    }
}
