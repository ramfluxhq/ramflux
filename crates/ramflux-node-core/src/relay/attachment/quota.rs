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
        let size = request.layout.dimensions().map_err(|_| AttachmentLedgerError::Invalid)?.1;
        if request.layout.plaintext_length > self.policy.max_plaintext_bytes {
            return Err(AttachmentLedgerError::Invalid);
        }
        let record_key = key(owner, &request.upload_id);
        let tx = self.db.begin_write().map_err(store)?;
        if super::identity::fenced(&tx, &record_key)? {
            return Err(AttachmentLedgerError::State);
        }
        let mut records = tx.open_table(RECORDS).map_err(store)?;
        if let Some(found) = records.get(record_key.as_slice()).map_err(store)? {
            let record: AttachmentReservation = decode(found.value())?;
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
                AttachmentReservationState::Committed => {
                    return Err(AttachmentLedgerError::Expired);
                }
                _ => return Err(AttachmentLedgerError::State),
            }
            return Ok(record);
        }
        let mut objects = tx.open_table(OBJECTS).map_err(store)?;
        let object_key = key(owner, &request.object_id);
        if tx
            .open_table(super::identity::FENCE_OBJECTS)
            .map_err(store)?
            .get(object_key.as_slice())
            .map_err(store)?
            .is_some()
            || objects.get(object_key.as_slice()).map_err(store)?.is_some()
        {
            return Err(AttachmentLedgerError::Conflict);
        }
        let mut totals = tx.open_table(TOTALS).map_err(store)?;
        let mut total: AttachmentQuota = totals
            .get(owner.0.as_str())
            .map_err(store)?
            .map_or(Ok(AttachmentQuota::default()), |v| decode(v.value()))?;
        if total.records >= self.policy.max_records_per_owner
            || total
                .fences
                .checked_add(total.records)
                .is_none_or(|n| n >= self.policy.max_identity_fences_per_owner)
        {
            return Err(AttachmentLedgerError::Capacity);
        }
        let occupied = total
            .used
            .checked_add(total.reserved)
            .and_then(|n| n.checked_add(size))
            .ok_or(AttachmentLedgerError::Invalid)?;
        if occupied > self.policy.quota_bytes {
            return Err(AttachmentLedgerError::AccountQuotaExceeded {
                used: total.used,
                reserved: total.reserved,
                limit: self.policy.quota_bytes,
            });
        }
        let record = AttachmentReservation {
            owner: owner.0.clone(),
            upload_id: request.upload_id,
            object_id: request.object_id,
            plaintext_length: request.layout.plaintext_length,
            network_chunk_bytes: request.layout.network_chunk_bytes,
            size,
            manifest_hash: None,
            state: AttachmentReservationState::Pending,
            lease_until: now
                .checked_add(self.policy.pending_lease_seconds)
                .ok_or(AttachmentLedgerError::Invalid)?,
            lease_hard_until: now
                .checked_add(self.policy.pending_max_seconds)
                .ok_or(AttachmentLedgerError::Invalid)?,
            lease_step: self.policy.pending_lease_seconds,
            retention_seconds: self.policy.retention_seconds,
            expires_at: None,
        };
        total.reserved += size;
        total.records += 1;
        totals.insert(owner.0.as_str(), encode(&total)?.as_slice()).map_err(store)?;
        records.insert(record_key.as_slice(), encode(&record)?.as_slice()).map_err(store)?;
        objects.insert(object_key.as_slice(), record_key.as_slice()).map_err(store)?;
        tx.open_table(DEADLINES)
            .map_err(store)?
            .insert(deadline(record.lease_until, &record_key).as_slice(), ())
            .map_err(store)?;
        drop(objects);
        drop(totals);
        drop(records);
        tx.commit().map_err(store)?;
        Ok(record)
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
        let native = manifest.manifest();
        let hash = native.hash().map_err(|_| AttachmentLedgerError::Invalid)?;
        self.change(owner, id, |record, _| {
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
            if record.state == AttachmentReservationState::Committed {
                if record.expires_at.is_none_or(|expiry| now >= expiry) {
                    return Err(AttachmentLedgerError::Expired);
                }
                return Ok(());
            }
            pending(record, now)?;
            record.manifest_hash = Some(hash);
            Ok(())
        })
    }
    /// Atomic reserved-to-used settlement after the trusted backend has durably
    /// verified/committed the bound payload. This method does not validate backend data.
    /// # Errors
    /// Refuses expired, unbound or terminal work and storage/length overflow.
    pub fn commit(
        &self,
        owner: &AttachmentOwner,
        id: &[u8; 32],
        now: u64,
    ) -> Result<AttachmentReservation, AttachmentLedgerError> {
        self.change(owner, id, |record, total| {
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
            record.expires_at =
                Some(super::retention::object_expiry(now, record.retention_seconds)?);
            total.reserved =
                total.reserved.checked_sub(record.size).ok_or(AttachmentLedgerError::State)?;
            total.used =
                total.used.checked_add(record.size).ok_or(AttachmentLedgerError::Invalid)?;
            record.state = AttachmentReservationState::Committed;
            Ok(())
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
        let record_key = key(owner, id);
        let tx = self.db.begin_write().map_err(store)?;
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
        records.insert(record_key.as_slice(), encode(&record)?.as_slice()).map_err(store)?;
        totals.insert(owner.0.as_str(), encode(&total)?.as_slice()).map_err(store)?;
        drop(index);
        drop(records);
        drop(totals);
        tx.commit().map_err(store)?;
        Ok(record)
    }
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
