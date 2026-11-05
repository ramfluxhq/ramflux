// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Compact time-bounded identity evidence is independent of live quota records.
use super::{
    AttachmentLedger, AttachmentLedgerError, AttachmentOwner, AttachmentQuota,
    AttachmentReservation, AttachmentReservationState, DEADLINES, DEBTS, OBJECTS, RECORDS,
    ReadableDatabase, ReadableTable, TOTALS, TableDefinition, deadline, decode, encode, key, store,
};
pub(super) const FENCES: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("native_attachment_identity_fences_v1");
pub(super) const FENCE_OBJECTS: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("native_attachment_retired_objects_v1");
const EXPIRY: TableDefinition<&[u8], ()> =
    TableDefinition::new("native_attachment_identity_expiry_v1");
const SCHEMA: TableDefinition<&str, u64> = TableDefinition::new("native_attachment_ledger_schema");
fn until(record: &AttachmentReservation) -> Result<u64, AttachmentLedgerError> {
    // Native grants cannot outlive object retention; short tokens max300s +5s skew.
    record
        .expires_at
        .unwrap_or(0)
        .max(record.lease_hard_until)
        .checked_add(305)
        .ok_or(AttachmentLedgerError::Invalid)
}
fn compact(
    tx: &redb::WriteTransaction,
    key_bytes: &[u8],
    record: &AttachmentReservation,
) -> Result<(), AttachmentLedgerError> {
    let owner = AttachmentOwner(record.owner.clone());
    let object_key = key(&owner, &record.object_id);
    let expiry = until(record)?;
    let mut value = record.object_id.to_vec();
    value.extend_from_slice(&expiry.to_be_bytes());
    tx.open_table(FENCES).map_err(store)?.insert(key_bytes, value.as_slice()).map_err(store)?;
    tx.open_table(FENCE_OBJECTS)
        .map_err(store)?
        .insert(object_key.as_slice(), key_bytes)
        .map_err(store)?;
    tx.open_table(EXPIRY)
        .map_err(store)?
        .insert(deadline(expiry, key_bytes).as_slice(), ())
        .map_err(store)?;
    tx.open_table(RECORDS).map_err(store)?.remove(key_bytes).map_err(store)?;
    tx.open_table(OBJECTS).map_err(store)?.remove(object_key.as_slice()).map_err(store)?;
    tx.open_table(DEBTS).map_err(store)?.remove(key_bytes).map_err(store)?;
    {
        let mut timers = tx.open_table(DEADLINES).map_err(store)?;
        timers.remove(deadline(record.lease_until, key_bytes).as_slice()).map_err(store)?;
        if let Some(expiry) = record.expires_at {
            timers.remove(deadline(expiry, key_bytes).as_slice()).map_err(store)?;
        }
    }
    let mut totals = tx.open_table(TOTALS).map_err(store)?;
    let mut total: AttachmentQuota = {
        let v = totals.get(owner.0.as_str()).map_err(store)?.ok_or(AttachmentLedgerError::State)?;
        decode(v.value())?
    };
    total.records = total.records.checked_sub(1).ok_or(AttachmentLedgerError::State)?;
    total.fences = total.fences.checked_add(1).ok_or(AttachmentLedgerError::Invalid)?;
    totals.insert(owner.0.as_str(), encode(&total)?.as_slice()).map_err(store)?;
    Ok(())
}
pub(super) fn install(tx: &redb::WriteTransaction) -> Result<(), AttachmentLedgerError> {
    let mut schema = tx.open_table(SCHEMA).map_err(store)?;
    let _ = tx.open_table(FENCES).map_err(store)?;
    let _ = tx.open_table(FENCE_OBJECTS).map_err(store)?;
    let _ = tx.open_table(EXPIRY).map_err(store)?;
    if schema.get("compact_releases_v1").map_err(store)?.is_some() {
        return Ok(());
    }
    let mut cursor = None;
    loop {
        let rows = tx.open_table(RECORDS).map_err(store)?;
        let start = cursor.as_ref().map_or(std::ops::Bound::Unbounded, |v: &Vec<u8>| {
            std::ops::Bound::Excluded(v.as_slice())
        });
        let page = rows
            .range::<&[u8]>((start, std::ops::Bound::Unbounded))
            .map_err(store)?
            .take(64)
            .map(|entry| {
                let (k, v) = entry.map_err(store)?;
                Ok((k.value().to_vec(), decode::<AttachmentReservation>(v.value())?))
            })
            .collect::<Result<Vec<_>, AttachmentLedgerError>>()?;
        drop(rows);
        if page.is_empty() {
            break;
        }
        for (key, record) in page {
            cursor = Some(key.clone());
            if record.state == AttachmentReservationState::Released {
                compact(tx, &key, &record)?;
            }
        }
    }
    schema.insert("compact_releases_v1", 1).map_err(store)?;
    Ok(())
}
impl AttachmentLedger {
    pub(super) fn has_identity_fence(
        &self,
        owner: &AttachmentOwner,
        id: &[u8; 32],
    ) -> Result<bool, AttachmentLedgerError> {
        let tx = self.db.begin_read().map_err(store)?;
        Ok(tx
            .open_table(FENCES)
            .map_err(store)?
            .get(key(owner, id).as_slice())
            .map_err(store)?
            .is_some())
    }
    pub(super) fn compact_release(
        &self,
        owner: &AttachmentOwner,
        id: &[u8; 32],
    ) -> Result<(), AttachmentLedgerError> {
        let tx = self.db.begin_write().map_err(store)?;
        let key = key(owner, id);
        let record = {
            let rows = tx.open_table(RECORDS).map_err(store)?;
            rows.get(key.as_slice())
                .map_err(store)?
                .map(|v| decode::<AttachmentReservation>(v.value()))
                .transpose()?
        };
        let Some(record) = record else {
            if tx.open_table(FENCES).map_err(store)?.get(key.as_slice()).map_err(store)?.is_some() {
                return Ok(());
            }
            return Err(AttachmentLedgerError::Conflict);
        };
        if !matches!(
            record.state,
            AttachmentReservationState::DebtPending | AttachmentReservationState::DebtCommitted
        ) {
            return Err(AttachmentLedgerError::State);
        }
        {
            let mut totals = tx.open_table(TOTALS).map_err(store)?;
            let mut total: AttachmentQuota = {
                let v = totals
                    .get(owner.0.as_str())
                    .map_err(store)?
                    .ok_or(AttachmentLedgerError::State)?;
                decode(v.value())?
            };
            if total.fences >= self.policy.max_identity_fences_per_owner {
                return Err(AttachmentLedgerError::Capacity);
            }
            match record.state {
                AttachmentReservationState::DebtPending => {
                    total.reserved = total
                        .reserved
                        .checked_sub(record.size)
                        .ok_or(AttachmentLedgerError::State)?;
                }
                AttachmentReservationState::DebtCommitted => {
                    total.used =
                        total.used.checked_sub(record.size).ok_or(AttachmentLedgerError::State)?;
                }
                _ => return Err(AttachmentLedgerError::State),
            }
            totals.insert(owner.0.as_str(), encode(&total)?.as_slice()).map_err(store)?;
        }
        compact(&tx, &key, &record)?;
        tx.commit().map_err(store)
    }
}
pub(super) fn prune(
    tx: &redb::WriteTransaction,
    now: u64,
    limit: usize,
) -> Result<usize, AttachmentLedgerError> {
    let mut expiry = tx.open_table(EXPIRY).map_err(store)?;
    let mut upper = now.to_be_bytes().to_vec();
    upper.extend_from_slice(&[255; 512]);
    let keys = expiry
        .range(..=upper.as_slice())
        .map_err(store)?
        .take(limit)
        .map(|entry| entry.map(|(k, _)| k.value().to_vec()).map_err(store))
        .collect::<Result<Vec<_>, _>>()?;
    let mut fences = tx.open_table(FENCES).map_err(store)?;
    let mut objects = tx.open_table(FENCE_OBJECTS).map_err(store)?;
    let mut totals = tx.open_table(TOTALS).map_err(store)?;
    for entry in &keys {
        let record_key = &entry[8..];
        let value = {
            let value =
                fences.get(record_key).map_err(store)?.ok_or(AttachmentLedgerError::State)?;
            value.value().to_vec()
        };
        if value.len() != 40 {
            return Err(AttachmentLedgerError::State);
        }
        let owner_len = u64::from_be_bytes(
            record_key.get(..8).ok_or(AttachmentLedgerError::State)?.try_into().map_err(store)?,
        );
        if !(1..=256).contains(&owner_len) {
            return Err(AttachmentLedgerError::State);
        }
        let owner_len = usize::try_from(owner_len).map_err(store)?;
        if record_key.len() != owner_len + 40 {
            return Err(AttachmentLedgerError::State);
        }
        let owner = AttachmentOwner(
            String::from_utf8(
                record_key.get(8..8 + owner_len).ok_or(AttachmentLedgerError::State)?.to_vec(),
            )
            .map_err(store)?,
        );
        let id: [u8; 32] = value[..32].try_into().map_err(store)?;
        objects.remove(key(&owner, &id).as_slice()).map_err(store)?;
        fences.remove(record_key).map_err(store)?;
        expiry.remove(entry.as_slice()).map_err(store)?;
        let mut total: AttachmentQuota = {
            let v =
                totals.get(owner.0.as_str()).map_err(store)?.ok_or(AttachmentLedgerError::State)?;
            decode(v.value())?
        };
        total.fences = total.fences.checked_sub(1).ok_or(AttachmentLedgerError::State)?;
        totals.insert(owner.0.as_str(), encode(&total)?.as_slice()).map_err(store)?;
    }
    Ok(keys.len())
}

pub(super) fn fenced(
    tx: &redb::WriteTransaction,
    key: &[u8],
) -> Result<bool, AttachmentLedgerError> {
    Ok(tx.open_table(FENCES).map_err(store)?.get(key).map_err(store)?.is_some())
}
