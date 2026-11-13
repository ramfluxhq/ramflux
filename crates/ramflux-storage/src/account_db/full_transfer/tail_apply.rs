// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Bounded selected-B tail transactions preserve independent local contributions and cursors.
use super::{
    FullTailEndpoint, fixed_union::apply_fixed_base_in_transaction, source_scalar::compiled,
};
use crate::StorageError;
use ramflux_crypto::custody::pairing::PairingRole;
use ramflux_protocol::custody::{
    DeviceRef,
    pairing::full_transfer::{RecordHeader, RecordOp, read_record_header},
};
use rusqlite::{Connection, params};
use std::io::{Read, Seek, SeekFrom};
use zeroize::{Zeroize as _, Zeroizing};
fn wrong() -> StorageError {
    StorageError::PairingField("WrongContext")
}
struct Record {
    header: RecordHeader,
    bytes: Zeroizing<Vec<u8>>,
}
impl Drop for Record {
    fn drop(&mut self) {
        self.header.key.zeroize();
    }
}
#[derive(Clone, Copy)]
struct Progress {
    phase: u8,
    offset: u64,
}
struct Scope {
    operation: String,
    nonce: String,
    digest: [u8; 32],
    owner: String,
    hash: String,
    source: DeviceRef,
}
impl FullTailEndpoint<'_> {
    /// Apply at most 32 validated records through this actual selected B writer.
    /// Restrictions run first. Source absences remove only A's tracked contribution;
    /// independent B assertions, keys, native state and other local rows remain local.
    /// Data writes and their progress cursor commit in the same actual B transaction.
    /// True means both application passes committed, not a signed semantic receipt.
    /// # Errors
    /// Refuses unvalidated/foreign input, lost G3/native scope, wrong local ownership or SQL failure.
    pub fn apply_recipient_batch(
        &self,
        hash: &str,
        limit: u8,
        now: u64,
    ) -> Result<bool, StorageError> {
        self.require_tail(hash, now)?;
        self.stage.require_validated_tail_input(hash)?;
        let record = self.stage.resume_record()?;
        if limit == 0 || limit > 32 || record.role != PairingRole::Responder {
            return Err(wrong());
        }
        self.stage.db.require_selected_transfer_source()?;
        let adoption = self.stage.db.pairing_adoption()?.ok_or_else(wrong)?;
        let scope = Scope {
            operation: self.operation.clone(),
            nonce: adoption.full_generation_nonce.ok_or_else(wrong)?,
            digest: record.stage_digest()?,
            owner: super::super::mac_subkeys::full::source_key(&record.grant.source_ref)?,
            hash: hash.into(),
            source: record.grant.source_ref,
        };
        let progress = self.stage.db.connection.call({
            let operation = scope.operation.clone();
            let nonce = scope.nonce.clone();
            let digest = scope.digest;
            let hash = scope.hash.clone();
            let owner = scope.owner.clone();
            move |raw| read_progress(raw, &operation, &nonce, &digest, &owner, &hash)
        })?;
        if progress.phase == 2 {
            return Ok(true);
        }
        let total = self.stage.forward_manifest(hash)?.manifest.total_bytes.0;
        if progress.offset > total {
            return Err(wrong());
        }
        let mut reader = self.stage.validated_tail_reader(hash)?;
        reader.seek(SeekFrom::Start(progress.offset))?;
        let mut records = Vec::with_capacity(usize::from(limit));
        for _ in 0..limit {
            if reader.stream_position()? == total {
                break;
            }
            self.require_live(now)?;
            records.push(read_record(&mut reader)?);
        }
        let end = reader.stream_position()?;
        if end > total {
            return Err(wrong());
        }
        let next = if end == total {
            if progress.phase == 0 {
                Progress { phase: 1, offset: 0 }
            } else {
                Progress { phase: 2, offset: end }
            }
        } else {
            Progress { phase: progress.phase, offset: end }
        };
        self.require_live(now)?;
        self.stage
            .db
            .connection
            .call(move |raw| Ok(commit_batch(raw, &scope, progress, next, &records)))??;
        self.stage.db.require_selected_transfer_source()?;
        self.require_live(now)?;
        Ok(next.phase == 2)
    }
}
fn read_progress(
    raw: &Connection,
    operation: &str,
    nonce: &str,
    digest: &[u8; 32],
    owner: &str,
    hash: &str,
) -> rusqlite::Result<Progress> {
    raw.query_row("SELECT phase,next_record FROM pairing_full_tail_apply WHERE operation_id=?1 AND generation_nonce=?2 AND stage_digest=?3 AND source_owner=?4 AND tail_hash=?5 AND tail_status IN('pending','merged')",
        params![operation,nonce,digest.as_slice(),owner,hash], |row| Ok(Progress { phase: row.get(0)?, offset: row.get(1)? }))
}
fn read_record(reader: &mut (impl Read + Seek)) -> Result<Record, StorageError> {
    let header = read_record_header(reader).map_err(|_| wrong())?.ok_or_else(wrong)?;
    let mut record = Record { header, bytes: Zeroizing::new(Vec::new()) };
    let rule = compiled(&record.header.family)?;
    let size = record
        .header
        .cell_lengths
        .iter()
        .try_fold(0_u64, |sum, value| sum.checked_add(value.0).ok_or_else(wrong))?;
    if size > 1024 {
        return Err(StorageError::PairingField("UnsupportedRecord"));
    }
    record.bytes = Zeroizing::new(vec![0; usize::try_from(size).map_err(|_| wrong())?]);
    reader.read_exact(&mut record.bytes)?;
    super::copy_full_scalar_record(
        rule,
        &record.header,
        &mut record.bytes.as_slice(),
        &mut std::io::sink(),
    )?;
    Ok(record)
}
fn commit_batch(
    raw: &mut Connection,
    scope: &Scope,
    old: Progress,
    next: Progress,
    records: &[Record],
) -> Result<(), StorageError> {
    let tx = raw.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    let current = read_progress(
        &tx,
        &scope.operation,
        &scope.nonce,
        &scope.digest,
        &scope.owner,
        &scope.hash,
    )?;
    if current.phase != old.phase || current.offset != old.offset {
        return Err(StorageError::PairingField("Busy"));
    }
    for record in records {
        let rule = compiled(&record.header.family)?;
        if rule.restrictive != (old.phase == 0) {
            continue;
        }
        if record.header.op == RecordOp::Absent {
            if !rule.restrictive {
                absent_dependency(&tx, &scope.operation, &record.header)?;
            }
            continue;
        }
        apply_fixed_base_in_transaction(
            &tx,
            &scope.source,
            &record.header,
            &mut record.bytes.as_slice(),
        )?;
        if rule.id == "sql/object_payload_dependency" {
            let cells = super::fixed_union::Cells::read(
                rule,
                &record.header,
                &mut record.bytes.as_slice(),
            )?;
            tx.execute("INSERT INTO pairing_full_tail_dependency VALUES(?1,0,?2,?3) ON CONFLICT DO NOTHING",
                params![scope.operation,cells.text(0)?,cells.text(1)?])?;
        }
    }
    if tx.execute("UPDATE pairing_full_tail_apply SET phase=?1,next_record=?2 WHERE operation_id=?3 AND generation_nonce=?4 AND tail_hash=?5 AND phase=?6 AND next_record=?7 AND tail_status='pending'",
        params![next.phase,next.offset,scope.operation,scope.nonce,scope.hash,old.phase,old.offset])? != 1 { return Err(wrong()); }
    tx.commit()?;
    Ok(())
}
fn absent_dependency(
    raw: &Connection,
    operation: &str,
    header: &RecordHeader,
) -> Result<(), StorageError> {
    if header.family != "sql/object_payload_dependency" || header.key.len() != 128 {
        return Err(wrong());
    }
    let key = Zeroizing::new(ramflux_protocol::decode_base64url(&header.key).map_err(|_| wrong())?);
    if key.len() != 96
        || key.get(..5) != Some([3, 0, 0, 0, 43].as_slice())
        || key.get(48..53) != Some([3, 0, 0, 0, 43].as_slice())
    {
        return Err(wrong());
    }
    let parent = std::str::from_utf8(key.get(5..48).ok_or_else(wrong)?).map_err(|_| wrong())?;
    let child = std::str::from_utf8(key.get(53..96).ok_or_else(wrong)?).map_err(|_| wrong())?;
    super::stage::raw32(parent)?;
    super::stage::raw32(child)?;
    let removed = raw.execute("DELETE FROM pairing_full_tail_dependency WHERE operation_id=?1 AND owner=0 AND parent_commitment=?2 AND child_commitment=?3", params![operation,parent,child])?;
    if removed == 1 {
        raw.execute("DELETE FROM object_payload_dependency WHERE parent_commitment=?1 AND child_commitment=?2 AND NOT EXISTS(SELECT 1 FROM pairing_full_tail_dependency WHERE operation_id=?3 AND parent_commitment=?1 AND child_commitment=?2)", params![parent,child,operation])?;
    }
    Ok(())
}
