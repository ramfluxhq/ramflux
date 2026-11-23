// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Account-scoped accounting snapshots, without changing durable quota ownership.
use super::{
    AttachmentLedger, AttachmentLedgerError, AttachmentOwner, AttachmentQuota,
    AttachmentReservation, AttachmentReservationState, DEBTS, RECORDS, ReadableDatabase,
    ReadableTable, TOTALS, decode, key, store,
};
use ramflux_protocol::attachment_wire::{
    AttachmentAccountStatus, AttachmentLimits, AttachmentUsage,
};

impl AttachmentLedger {
    /// Returns disjoint charges from one database snapshot. Debt remains in the quota total.
    /// # Errors
    /// Refuses corrupt or overflowing accounting; never reports uncharged cleanup debt.
    pub fn account_status(
        &self,
        owner: &AttachmentOwner,
    ) -> Result<AttachmentAccountStatus, AttachmentLedgerError> {
        let tx = self.db.begin_read().map_err(store)?;
        let totals = tx.open_table(TOTALS).map_err(store)?;
        let total: AttachmentQuota = totals
            .get(owner.0.as_str())
            .map_err(store)?
            .map_or(Ok(AttachmentQuota::default()), |v| decode(v.value()))?;
        let records = tx.open_table(RECORDS).map_err(store)?;
        let debts = tx.open_table(DEBTS).map_err(store)?;
        let (mut pending, mut committed) = (0_u64, 0_u64);
        let lower = key(owner, &[0; 32]);
        let upper = key(owner, &[255; 32]);
        for (count, entry) in
            debts.range(lower.as_slice()..=upper.as_slice()).map_err(store)?.enumerate()
        {
            let (id, _) = entry.map_err(store)?;
            // The original admission bound may have been lowered since these records were admitted.
            if u64::try_from(count).map_err(store)? >= total.records {
                return Err(AttachmentLedgerError::State);
            }
            let value =
                records.get(id.value()).map_err(store)?.ok_or(AttachmentLedgerError::State)?;
            let row: AttachmentReservation = decode(value.value())?;
            let charge = match row.state {
                AttachmentReservationState::DebtPending => &mut pending,
                AttachmentReservationState::DebtCommitted => &mut committed,
                _ => return Err(AttachmentLedgerError::State),
            };
            *charge = charge.checked_add(row.size).ok_or(AttachmentLedgerError::State)?;
        }
        let charged = total.used.checked_add(total.reserved).ok_or(AttachmentLedgerError::State)?;
        let debt = pending.checked_add(committed).ok_or(AttachmentLedgerError::State)?;
        let policy = self.policy;
        Ok(AttachmentAccountStatus {
            limits: AttachmentLimits {
                max_plaintext_bytes: policy.max_plaintext_bytes,
                quota_bytes: policy.quota_bytes,
                network_chunk_bytes: 524_288,
                segment_bytes: ramflux_protocol::large_attachment::SEGMENT_BYTES,
                retention_seconds: policy.retention_seconds,
                pending_lease_seconds: policy.pending_lease_seconds,
                pending_max_seconds: policy.pending_max_seconds,
            },
            usage: AttachmentUsage {
                used_bytes: total
                    .used
                    .checked_sub(committed)
                    .ok_or(AttachmentLedgerError::State)?,
                reserved_bytes: total
                    .reserved
                    .checked_sub(pending)
                    .ok_or(AttachmentLedgerError::State)?,
                cleanup_debt_bytes: debt,
                charged_bytes: charged,
                available_bytes: policy.quota_bytes.saturating_sub(charged),
            },
        })
    }
}
