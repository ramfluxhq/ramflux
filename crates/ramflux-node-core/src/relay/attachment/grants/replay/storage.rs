// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
//! Server backup classification: NONCES and META.clock are authority restrictions.
//! EXPIRY, PRINCIPALS and META.rows/bytes/blocked are derived and rebuilt on normal open.
//! SDK backups import none of these tables; server rollback needs a fresh,
//! externally fenced authority generation, as required by grant registration.
use super::{AttachmentReplayError as Error, AttachmentReplayProof};
use crate::relay::attachment::{AttachmentLedgerError, store};
use ramflux_protocol::large_attachment::QualifiedOwner;
use redb::{ReadableTable, ReadableTableMetadata, TableDefinition, WriteTransaction};
pub(super) const NONCES: TableDefinition<&[u8], u64> =
    TableDefinition::new("native_attachment_consumed_proofs_v1");
pub(super) const EXPIRY: TableDefinition<&[u8], ()> =
    TableDefinition::new("native_attachment_proof_expiry_v1");
pub(super) const PRINCIPALS: TableDefinition<&[u8], u64> =
    TableDefinition::new("native_attachment_proof_principals_v1");
pub(super) const META: TableDefinition<&str, u64> =
    TableDefinition::new("native_attachment_proof_meta_v1");
// Fixed encoded rows: nonce96+expiry8, expiry104, principal64+counter8. Every
// admitted nonce may also create its own principal counter, so each row carries
// one full principal row plus B-tree page slack. Measured on file-backed redb with
// one commit per admission and distinct principals: about 605 B/row on disk
// (7909376 B at 13081 rows) and 617 B/row in the storage probe. ROW_CHARGE adds
// about 11% margin over the worst measured row.
pub(super) const ROW_CHARGE: u64 = 672;
pub(super) const ROOT_CHARGE: u64 = 16 * 1024;
pub(super) const CAP_BYTES: u64 = 8 * 1024 * 1024;
// Largest entry count whose worst-case charge still fits CAP_BYTES. At this count
// the byte cap and the entry cap refuse together; 16384 rows cannot fit at the
// measured worst case within 8 MiB.
pub(super) const DEFAULT_ENTRIES: u64 = (CAP_BYTES - ROOT_CHARGE) / ROW_CHARGE;
#[derive(Clone, Copy)]
pub(super) struct Limits {
    pub entries: u64,
    pub bytes: u64,
    pub principal: u64,
    pub charge: u64,
}
impl Default for Limits {
    fn default() -> Self {
        Self { entries: DEFAULT_ENTRIES, bytes: CAP_BYTES, principal: 1024, charge: ROW_CHARGE }
    }
}
/// Normal server open rebuilds derived indexes and budgets from authoritative nonce
/// rows. The clock fence is preserved. Disaster rollback requires externally fenced
/// authority generation rotation; a copied server DB is not rollback detection.
pub(crate) fn install(tx: &WriteTransaction, now: u64) -> Result<(), AttachmentLedgerError> {
    rebuild(tx, now, Limits::default())
}
// Startup can revisit a previous version's larger limits/charge without losing
// serving availability. Live/malformed primary evidence is never discarded.
pub(super) fn rebuild(
    tx: &WriteTransaction,
    now: u64,
    limits: Limits,
) -> Result<(), AttachmentLedgerError> {
    let saved =
        tx.open_table(META).map_err(store)?.get("clock").map_err(store)?.map_or(0, |v| v.value());
    let now = now.max(saved);
    let had_evidence = expire_before_rebuild(tx, now)?;
    let rows = tx.open_table(NONCES).map_err(store)?;
    let _ = tx.delete_table(EXPIRY).map_err(store)?;
    let _ = tx.delete_table(PRINCIPALS).map_err(store)?;
    let mut expiry = tx.open_table(EXPIRY).map_err(store)?;
    let mut counts = tx.open_table(PRINCIPALS).map_err(store)?;
    let mut blocked = false;
    for entry in rows.iter().map_err(store)? {
        let (key, end) = entry.map_err(store)?;
        let key = key.value();
        let end = end.value();
        if key.len() != 96 || end.checked_add(5).is_none() {
            blocked = true;
            continue;
        }
        expiry.insert(expiry_key(end, key).as_slice(), ()).map_err(store)?;
        let count = counts.get(&key[..64]).map_err(store)?.map_or(0, |v| v.value());
        counts.insert(&key[..64], count.saturating_add(1)).map_err(store)?;
    }
    let total = rows.len().map_err(store)?;
    let mut meta = tx.open_table(META).map_err(store)?;
    meta.insert("rows", total).map_err(store)?;
    meta.insert("bytes", charge(total, limits.charge)).map_err(store)?;
    meta.insert("blocked", u64::from(blocked)).map_err(store)?;
    // GC and its time fence commit together: a clock correction after startup
    // cannot revive a proof whose durable nonce was just expired.
    if had_evidence {
        meta.insert("clock", now).map_err(store)?;
    }
    Ok(())
}
// Dropping each read iterator before removals lets redb mutate uncommitted
// pages in place. retain() keeps the old tree alive and copies a path per delete.
fn expire_before_rebuild(tx: &WriteTransaction, now: u64) -> Result<bool, AttachmentLedgerError> {
    use std::ops::Bound::{Excluded, Unbounded};
    let mut rows = tx.open_table(NONCES).map_err(store)?;
    let had_evidence = rows.len().map_err(store)? != 0;
    let mut cursor: Option<Vec<u8>> = None;
    loop {
        let start = cursor.as_ref().map_or(Unbounded, |key| Excluded(key.as_slice()));
        let page: Vec<(Vec<u8>, u64)> = rows
            .range::<&[u8]>((start, Unbounded))
            .map_err(store)?
            .filter_map(|entry| match entry {
                Ok((key, value)) if key.value().len() == 96 => {
                    Some(Ok((key.value().to_vec(), value.value())))
                }
                Ok(_) => None,
                Err(error) => Some(Err(store(error))),
            })
            .take(64)
            .collect::<Result<_, AttachmentLedgerError>>()?;
        if page.is_empty() {
            break;
        }
        cursor = page.last().map(|(key, _)| key.clone());
        for (key, end) in page {
            if end.checked_add(5).is_some_and(|end| end <= now)
                && rows.remove(key.as_slice()).map_err(store)?.is_none()
            {
                return Err(AttachmentLedgerError::State);
            }
        }
    }
    Ok(had_evidence)
}
fn charge(rows: u64, row_charge: u64) -> u64 {
    ROOT_CHARGE.saturating_add(rows.saturating_mul(row_charge))
}
fn expiry_key(expires: u64, key: &[u8]) -> Vec<u8> {
    let mut out = (expires + 5).to_be_bytes().to_vec();
    out.extend(key);
    out
}
pub(super) fn principal(source: &str, requester: &QualifiedOwner) -> [u8; 64] {
    let mut out = [0; 64];
    let mut source_hash = blake3::Hasher::new();
    source_hash.update(b"ramflux.attachment.replay.source.v1");
    source_hash.update(source.as_bytes());
    out[..32].copy_from_slice(source_hash.finalize().as_bytes());
    let mut h = blake3::Hasher::new();
    h.update(b"ramflux.attachment.replay.requester.v1");
    for s in [&requester.account_anchor, &requester.device_id] {
        h.update(&(s.len() as u64).to_be_bytes());
        h.update(s.as_bytes());
    }
    h.update(&requester.device_epoch.to_be_bytes());
    h.update(&requester.signing_public_key);
    out[32..].copy_from_slice(h.finalize().as_bytes());
    out
}
pub(super) fn clock(tx: &WriteTransaction, now: u64) -> Result<u64, Error> {
    let mut meta = tx.open_table(META).map_err(store)?;
    let saved = meta.get("clock").map_err(store)?.map_or(0, |v| v.value());
    let config = tx.open_table(super::super::CONFIG).map_err(store)?;
    let authority_clock = config
        .get("clock_fence")
        .map_err(store)?
        .map(|v| {
            v.value().try_into().map(u64::from_be_bytes).map_err(|_| AttachmentLedgerError::State)
        })
        .transpose()?
        .unwrap_or(0);
    let before = saved.max(authority_clock);
    if now.saturating_add(5) < before {
        return Err(Error::ClockUncertain);
    }
    let effective = now.max(before);
    meta.insert("clock", effective).map_err(store)?;
    Ok(effective)
}
pub(super) fn consume(
    tx: &WriteTransaction,
    source: &str,
    requester: &QualifiedOwner,
    proof: &AttachmentReplayProof,
    now: u64,
    limits: Limits,
) -> Result<(), Error> {
    if proof.expires_at <= proof.issued_at
        || proof.expires_at - proof.issued_at > 30
        || proof.expires_at.checked_add(5).is_none()
    {
        return Err(Error::Invalid);
    }
    let now = clock(tx, now)?;
    if proof.issued_at > now.saturating_add(5) {
        return Err(Error::Invalid);
    }
    if now >= proof.expires_at + 5 {
        return Err(Error::Expired);
    }
    gc(tx, now, 64)?;
    let owner = principal(source, requester);
    let mut key = owner.to_vec();
    key.extend(proof.nonce);
    let mut rows = tx.open_table(NONCES).map_err(store)?;
    if rows.get(key.as_slice()).map_err(store)?.is_some() {
        return Err(Error::Replay);
    }
    let mut meta = tx.open_table(META).map_err(store)?;
    let blocked = meta.get("blocked").map_err(store)?.map_or(0, |v| v.value()) != 0;
    let bytes = charge(rows.len().map_err(store)?, limits.charge);
    let mut counts = tx.open_table(PRINCIPALS).map_err(store)?;
    let count = counts.get(owner.as_slice()).map_err(store)?.map_or(0, |v| v.value());
    if blocked
        || rows.len().map_err(store)? >= limits.entries
        || bytes.checked_add(limits.charge).is_none_or(|next| next > limits.bytes)
        || count >= limits.principal
    {
        return Err(Error::ReplayProtectionCapacity);
    }
    rows.insert(key.as_slice(), proof.expires_at).map_err(store)?;
    tx.open_table(EXPIRY)
        .map_err(store)?
        .insert(expiry_key(proof.expires_at, &key).as_slice(), ())
        .map_err(store)?;
    counts.insert(owner.as_slice(), count + 1).map_err(store)?;
    meta.insert("rows", rows.len().map_err(store)?).map_err(store)?;
    meta.insert("bytes", bytes + limits.charge).map_err(store)?;
    Ok(())
}
pub(super) fn gc(tx: &WriteTransaction, now: u64, limit: usize) -> Result<usize, Error> {
    let mut index = tx.open_table(EXPIRY).map_err(store)?;
    let mut end = now.to_be_bytes().to_vec();
    end.extend([255; 96]);
    let keys = index
        .range(..=end.as_slice())
        .map_err(store)?
        .take(limit)
        .map(|r| r.map(|(k, _)| k.value().to_vec()).map_err(store))
        .collect::<Result<Vec<_>, _>>()?;
    let mut rows = tx.open_table(NONCES).map_err(store)?;
    let mut counts = tx.open_table(PRINCIPALS).map_err(store)?;
    for key in &keys {
        if key.len() != 104 {
            return Err(AttachmentLedgerError::State.into());
        }
        let row = rows.remove(&key[8..]).map_err(store)?.ok_or(AttachmentLedgerError::State)?;
        if row.value().checked_add(5).is_none() {
            return Err(AttachmentLedgerError::State.into());
        }
        if expiry_key(row.value(), &key[8..]) != *key {
            return Err(AttachmentLedgerError::State.into());
        }
        let count =
            counts.get(&key[8..72]).map_err(store)?.ok_or(AttachmentLedgerError::State)?.value();
        if count == 0 {
            return Err(AttachmentLedgerError::State.into());
        }
        if count == 1 {
            counts.remove(&key[8..72]).map_err(store)?;
        } else {
            counts.insert(&key[8..72], count - 1).map_err(store)?;
        }
        index.remove(key.as_slice()).map_err(store)?;
    }
    let mut meta = tx.open_table(META).map_err(store)?;
    let total = rows.len().map_err(store)?;
    meta.insert("rows", total).map_err(store)?;
    meta.insert("bytes", charge(total, ROW_CHARGE)).map_err(store)?;
    Ok(keys.len())
}
