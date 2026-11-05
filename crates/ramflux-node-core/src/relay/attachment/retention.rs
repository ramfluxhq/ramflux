// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
use super::{
    AttachmentLedger, AttachmentLedgerError, AttachmentOwner, AttachmentReservation,
    AttachmentReservationState, DEADLINES, DEBTS, RECORDS, ReadableDatabase, ReadableTable,
    SegmentLayout, decode, encode, key, store,
};
#[derive(Debug, Clone, Copy)]
pub struct AttachmentPolicy {
    pub quota_bytes: u64,
    pub max_plaintext_bytes: u64,
    pub retention_seconds: u64,
    pub pending_lease_seconds: u64,
    pub pending_max_seconds: u64,
    pub max_records_per_owner: u64,
}
impl Default for AttachmentPolicy {
    fn default() -> Self {
        Self {
            quota_bytes: 20 * 1024 * 1024 * 1024,
            max_plaintext_bytes: 4 * 1024 * 1024 * 1024,
            retention_seconds: 7 * 24 * 60 * 60,
            pending_lease_seconds: 3600,
            pending_max_seconds: 86_400,
            max_records_per_owner: 16384,
        }
    }
}
impl AttachmentPolicy {
    pub(super) fn validate(self) -> Result<(), AttachmentLedgerError> {
        if self.retention_seconds == 0
            || self.pending_lease_seconds == 0
            || self.pending_max_seconds < self.pending_lease_seconds
            || self.max_records_per_owner == 0
        {
            return Err(AttachmentLedgerError::Invalid);
        }
        SegmentLayout { plaintext_length: self.max_plaintext_bytes, network_chunk_bytes: 524_288 }
            .dimensions()
            .map_err(|_| AttachmentLedgerError::Invalid)?;
        Ok(())
    }
}
pub(super) fn object_expiry(now: u64, retention: u64) -> Result<u64, AttachmentLedgerError> {
    now.checked_add(retention).ok_or(AttachmentLedgerError::Invalid)
}
impl AttachmentLedger {
    /// # Errors
    /// Refuses expired/nonpending leases, overflow or storage errors. Renewal never
    /// changes the admitted hard deadline or committed object retention.
    pub fn renew_lease(
        &self,
        owner: &AttachmentOwner,
        id: &[u8; 32],
        now: u64,
    ) -> Result<AttachmentReservation, AttachmentLedgerError> {
        self.change(owner, id, |record, _| {
            super::quota::pending(record, now)?;
            let next = now
                .checked_add(record.lease_step)
                .ok_or(AttachmentLedgerError::Invalid)?
                .min(record.lease_hard_until);
            if next <= now {
                return Err(AttachmentLedgerError::Expired);
            }
            record.lease_until = next;
            Ok(())
        })
    }
    /// Cancels only an incomplete owner upload. Committed grant/reference erasure
    /// requires a separate grant-retirement and reference-lifecycle authority.
    /// # Errors
    /// Refuses committed/terminal work or storage failure. Debt stays charged.
    pub fn abandon_pending(
        &self,
        owner: &AttachmentOwner,
        id: &[u8; 32],
    ) -> Result<AttachmentReservation, AttachmentLedgerError> {
        self.change(owner, id, |record, _| {
            match record.state {
                AttachmentReservationState::Pending => {
                    record.state = AttachmentReservationState::DebtPending;
                }
                AttachmentReservationState::DebtPending | AttachmentReservationState::Released => {}
                _ => return Err(AttachmentLedgerError::State),
            }
            Ok(())
        })
    }
    /// Returns at most 128 indexed expiry jobs; no backend I/O or charge release.
    /// Expiry fences serving before cleanup. Unfinished cleanup remains durable debt.
    /// # Errors
    /// Refuses invalid work bounds, corrupt state or storage failure.
    pub fn gc_due(
        &self,
        now: u64,
        limit: usize,
    ) -> Result<Vec<AttachmentReservation>, AttachmentLedgerError> {
        if limit == 0 || limit > 128 {
            return Err(AttachmentLedgerError::Invalid);
        }
        let tx = self.db.begin_write().map_err(store)?;
        let mut index = tx.open_table(DEADLINES).map_err(store)?;
        let mut upper = now.to_be_bytes().to_vec();
        upper.extend_from_slice(&[255; 512]);
        let keys = index
            .range(..=upper.as_slice())
            .map_err(store)?
            .take(limit)
            .map(|item| item.map(|(key, _)| key.value().to_vec()).map_err(store))
            .collect::<Result<Vec<_>, _>>()?;
        let mut records = tx.open_table(RECORDS).map_err(store)?;
        let mut jobs = Vec::new();
        let mut debt = tx.open_table(DEBTS).map_err(store)?;
        for index_key in keys {
            let record_key = index_key.get(8..).ok_or(AttachmentLedgerError::State)?;
            let mut record: AttachmentReservation = {
                let v =
                    records.get(record_key).map_err(store)?.ok_or(AttachmentLedgerError::State)?;
                decode(v.value())?
            };
            match record.state {
                AttachmentReservationState::Pending if record.lease_until <= now => {
                    record.state = AttachmentReservationState::DebtPending;
                }
                AttachmentReservationState::Committed
                    if record.expires_at.is_some_and(|expiry| expiry <= now) =>
                {
                    record.state = AttachmentReservationState::DebtCommitted;
                }
                _ => return Err(AttachmentLedgerError::State),
            }
            records.insert(record_key, encode(&record)?.as_slice()).map_err(store)?;
            debt.insert(record_key, ()).map_err(store)?;
            index.remove(index_key.as_slice()).map_err(store)?;
            jobs.push(record);
        }
        drop(debt);
        drop(index);
        drop(records);
        tx.commit().map_err(store)?;
        Ok(jobs)
    }
    /// Lists bounded durable cleanup debt so a crash after expiry cannot lose work.
    /// # Errors
    /// Refuses invalid limits or unreadable storage. Cursor is the last returned upload id.
    pub fn cleanup_page(
        &self,
        owner: &AttachmentOwner,
        after: Option<[u8; 32]>,
        limit: usize,
    ) -> Result<Vec<AttachmentReservation>, AttachmentLedgerError> {
        if limit == 0 || limit > 128 {
            return Err(AttachmentLedgerError::Invalid);
        }
        let tx = self.db.begin_read().map_err(store)?;
        let table = tx.open_table(DEBTS).map_err(store)?;
        let records = tx.open_table(RECORDS).map_err(store)?;
        let mut jobs = Vec::new();
        let start = key(owner, &after.unwrap_or([0; 32]));
        for item in table.range(start.as_slice()..).map_err(store)?.take(limit + 1) {
            let (debt_key, _) = item.map_err(store)?;
            let value = records
                .get(debt_key.value())
                .map_err(store)?
                .ok_or(AttachmentLedgerError::State)?;
            let record: AttachmentReservation = decode(value.value())?;
            if record.owner != owner.0 {
                break;
            }
            if after.is_some_and(|id| record.upload_id <= id) {
                continue;
            }
            jobs.push(record);
            if jobs.len() == limit {
                break;
            }
        }
        Ok(jobs)
    }
    /// Trusted streaming backend deletion + directory/multipart durability must
    /// finish successfully before accounting releases charge. Never hold a DB
    /// transaction across backend I/O. Cleanup must quiesce all backend writers
    /// before deletion/durability; delete must be idempotent.
    /// # Errors
    /// Retains debt on deletion error; refuses an invalid state or storage failure.
    pub fn reclaim(
        &self,
        owner: &AttachmentOwner,
        id: &[u8; 32],
        cleanup: impl FnOnce(&AttachmentReservation) -> Result<(), AttachmentLedgerError>,
    ) -> Result<AttachmentReservation, AttachmentLedgerError> {
        let record = self.reservation(owner, id)?;
        if record.state == AttachmentReservationState::Released {
            return Ok(record);
        }
        if !matches!(
            record.state,
            AttachmentReservationState::DebtPending | AttachmentReservationState::DebtCommitted
        ) {
            return Err(AttachmentLedgerError::State);
        }
        cleanup(&record)?;
        self.change(owner, id, |current, total| {
            match current.state {
                AttachmentReservationState::DebtPending => {
                    total.reserved = total
                        .reserved
                        .checked_sub(current.size)
                        .ok_or(AttachmentLedgerError::State)?;
                }
                AttachmentReservationState::DebtCommitted => {
                    total.used =
                        total.used.checked_sub(current.size).ok_or(AttachmentLedgerError::State)?;
                }
                AttachmentReservationState::Released => return Ok(()),
                _ => return Err(AttachmentLedgerError::State),
            }
            current.state = AttachmentReservationState::Released;
            Ok(())
        })
    }
    /// Checks retention without sliding expiry or minting native grants/tokens.
    /// # Errors
    /// Refuses noncommitted/expired objects and unreadable storage.
    pub fn committed(
        &self,
        owner: &AttachmentOwner,
        id: &[u8; 32],
        now: u64,
    ) -> Result<AttachmentReservation, AttachmentLedgerError> {
        let record = self.reservation(owner, id)?;
        if record.expires_at.is_some_and(|expiry| now >= expiry)
            || matches!(
                record.state,
                AttachmentReservationState::DebtCommitted | AttachmentReservationState::Released
            )
        {
            return Err(AttachmentLedgerError::Expired);
        }
        if record.state != AttachmentReservationState::Committed {
            return Err(AttachmentLedgerError::State);
        }
        Ok(record)
    }
}
