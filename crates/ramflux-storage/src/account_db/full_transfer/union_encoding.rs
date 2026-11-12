// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! A5.M5 qualified fixed-row root construction; data encoding is not application/authority.
use super::{
    FullTransferStage,
    source_base::Rooted,
    source_scalar::{SourceGuard, compiled},
    write_full_scalar_sql_row,
};
use crate::StorageError;
use ramflux_crypto::custody::pairing::PairingRole;
use ramflux_protocol::custody::{DeviceRef, pairing::full_transfer::read_record_header};
use rusqlite::params;
use std::io::Write;
use zeroize::{Zeroize as _, Zeroizing};

pub(super) const SCHEMA:&str="
CREATE TABLE IF NOT EXISTS full_union_record(generation_nonce BLOB NOT NULL CHECK(length(generation_nonce)=32),owner TEXT NOT NULL COLLATE BINARY,family TEXT NOT NULL COLLATE BINARY,key TEXT NOT NULL COLLATE BINARY,record BLOB NOT NULL CHECK(length(record) BETWEEN 1 AND 16384),PRIMARY KEY(generation_nonce,owner,family,key)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS full_union_encoding(generation_nonce BLOB PRIMARY KEY CHECK(length(generation_nonce)=32),records INTEGER NOT NULL CHECK(records>=0),total_bytes INTEGER NOT NULL CHECK(total_bytes>=0),chunks_root BLOB NOT NULL CHECK(length(chunks_root)=32));";
fn invalid() -> StorageError {
    StorageError::PairingField("UnsupportedRecord")
}
struct PrivateHeader(ramflux_protocol::custody::pairing::full_transfer::RecordHeader);
impl Drop for PrivateHeader {
    fn drop(&mut self) {
        self.0.key.zeroize();
    }
}

/// Exact data operands for one committed qualified stream. No semantic receipt or approval.
pub struct FullUnionEncoding {
    pub generation_nonce: [u8; 32],
    pub records: u64,
    pub total_bytes: u64,
    pub chunks_root: [u8; 32],
}

/// One short private I/O transaction; drop before network/phrase/native work.
/// Rows MUST be normalized, actual prepared-generation values from typed merge owners.
/// Caller still proves complete input, co-ownership, merge semantics and prepared bytes.
pub struct FullUnionEncodingBuilder<'stage, 'db> {
    stage: &'stage mut FullTransferStage<'db>,
    nonce: [u8; 32],
    owners: [String; 2],
    committed: bool,
    failed: bool,
}
impl Drop for FullUnionEncodingBuilder<'_, '_> {
    fn drop(&mut self) {
        if !self.committed {
            let _ = self.stage.connection.execute_batch("ROLLBACK");
        }
    }
}
impl<'db> FullTransferStage<'db> {
    /// Begin a fresh, independently named local union encoding. Does not restore approval.
    /// # Errors
    /// Refuses source role, foreign account scope, lost unlock, entropy or SQL failure.
    pub fn begin_fixed_union_encoding(
        &mut self,
    ) -> Result<FullUnionEncodingBuilder<'_, 'db>, StorageError> {
        self.require_io()?;
        let record = self.resume_record()?;
        if record.role != PairingRole::Responder
            || record.grant.source_ref.account_anchor != self.db.principal_commitment
            || record.grant.destination_ref.account_anchor != self.db.principal_commitment
        {
            return Err(StorageError::PairingField("WrongContext"));
        }
        let owners = [
            super::super::mac_subkeys::full::source_key(&record.grant.source_ref)?,
            super::super::mac_subkeys::full::source_key(&record.grant.destination_ref)?,
        ];
        let nonce = ramflux_crypto::random_32()?;
        self.connection.execute_batch("BEGIN IMMEDIATE")?;
        Ok(FullUnionEncodingBuilder { stage: self, nonce, owners, committed: false, failed: false })
    }
}
impl FullUnionEncodingBuilder<'_, '_> {
    /// Retain one actual normalized SQL row under its exact contribution Ref.
    /// Identical repeated rows dedupe. A changed same-key row refuses the preparation;
    /// rebuild it rather than silently changing its initial root. No generic SQL/JSON row.
    /// # Errors
    /// Refuses another owner, unsupported codec, malformed row, conflicting duplicate,
    /// lost ordinary unlock, oversized fixed helper row or any failed private write.
    pub fn put_sql_row(
        &mut self,
        owner: &DeviceRef,
        family: &str,
        row: &rusqlite::Row<'_>,
    ) -> Result<(), StorageError> {
        if self.failed {
            return Err(invalid());
        }
        let result = self.put_inner(owner, family, row);
        if result.is_err() {
            self.failed = true;
        }
        result
    }
    fn put_inner(
        &mut self,
        owner: &DeviceRef,
        family: &str,
        row: &rusqlite::Row<'_>,
    ) -> Result<(), StorageError> {
        self.stage.require_io()?;
        let owner = super::super::mac_subkeys::full::source_key(owner)?;
        if !self.owners.contains(&owner) {
            return Err(StorageError::PairingField("WrongContext"));
        }
        let rule = compiled(family)?;
        let mut record = Zeroizing::new(Vec::new());
        write_full_scalar_sql_row(rule, row, &mut *record)?;
        if record.len() > 16384 {
            return Err(invalid());
        }
        let header = read_record_header(&mut record.as_slice())
            .map_err(|_| invalid())?
            .ok_or_else(invalid)?;
        let key = Zeroizing::new(header.key);
        let nonce = self.nonce;
        let changed=self.stage.connection.call(move|db|db.execute(
            "INSERT INTO full_union_record(generation_nonce,owner,family,key,record) VALUES(?1,?2,?3,?4,?5) ON CONFLICT(generation_nonce,owner,family,key) DO UPDATE SET record=excluded.record WHERE full_union_record.record=excluded.record",
            params![nonce.as_slice(),owner,rule.id,key.as_str(),record.as_slice()],
        ))?;
        if changed != 1 {
            return Err(StorageError::PairingField("TransferConflict"));
        }
        Ok(())
    }

    /// Commit count/root over LP(JCS(contribution Ref)) followed by each exact record,
    /// sorted by canonical Ref bytes, family and encoded key. This sets no `verified` bit.
    /// # Errors
    /// Refuses invalid stored rows, arithmetic overflow, unlock loss or durable I/O failure.
    pub fn finish(mut self) -> Result<FullUnionEncoding, StorageError> {
        if self.failed {
            return Err(invalid());
        }
        self.stage.require_io()?;
        let guard = SourceGuard::new(self.stage.db, Some(self.stage.source_cancelled.clone()));
        let first_guard = guard.clone();
        let nonce = self.nonce;
        let owners = self.owners.clone();
        let (records, total) = self
            .stage
            .connection
            .call(move |db| Ok(visit(db, &nonce, &owners, &mut std::io::sink(), &first_guard)))??;
        let nonce = self.nonce;
        let owners = self.owners.clone();
        let root = self.stage.connection.call(move |db| {
            let encode = || -> Result<[u8; 32], StorageError> {
                let mut rooted = Rooted::new(std::io::sink(), total)?;
                if visit(db, &nonce, &owners, &mut rooted, &guard)? != (records, total) {
                    return Err(invalid());
                }
                Ok(rooted.finish(total)?.1)
            };
            Ok(encode())
        })??;
        self.stage.connection.execute("INSERT INTO full_union_encoding(generation_nonce,records,total_bytes,chunks_root) VALUES(?1,?2,?3,?4)",params![self.nonce.as_slice(),records,total,root.as_slice()])?;
        self.stage.require_io()?;
        self.stage.connection.execute_batch("COMMIT")?;
        self.committed = true;
        super::stage::sync_stage(&self.stage.directory)?;
        self.stage.require_io()?;
        Ok(FullUnionEncoding {
            generation_nonce: self.nonce,
            records,
            total_bytes: total,
            chunks_root: root,
        })
    }
}

fn visit(
    db: &rusqlite::Connection,
    nonce: &[u8; 32],
    owners: &[String; 2],
    writer: &mut impl Write,
    guard: &SourceGuard,
) -> Result<(u64, u64), StorageError> {
    let mut statement=db.prepare("SELECT owner,family,key,record FROM full_union_record WHERE generation_nonce=?1 ORDER BY owner COLLATE BINARY,family COLLATE BINARY,key COLLATE BINARY")?;
    let mut rows = statement.query(params![nonce.as_slice()])?;
    let mut records = 0_u64;
    let mut total = 0_u64;
    while let Some(row) = rows.next()? {
        guard.require()?;
        let owner = row.get_ref(0)?.as_str().map_err(|_| invalid())?;
        let family = row.get_ref(1)?.as_str().map_err(|_| invalid())?;
        let key = row.get_ref(2)?.as_str().map_err(|_| invalid())?;
        let bytes = row.get_ref(3)?.as_blob().map_err(|_| invalid())?;
        if bytes.len() > 16384 || !owners.iter().any(|allowed| allowed == owner) {
            return Err(invalid());
        }
        let rule = compiled(family)?;
        let mut input = bytes;
        let header = PrivateHeader(
            read_record_header(&mut input).map_err(|_| invalid())?.ok_or_else(invalid)?,
        );
        if header.0.key != key {
            return Err(invalid());
        }
        super::copy_full_scalar_record(rule, &header.0, &mut input, &mut std::io::sink())?;
        if !input.is_empty() {
            return Err(invalid());
        }
        records = records.checked_add(1).ok_or_else(invalid)?;
        let size = 4_u64
            .checked_add(owner.len() as u64)
            .and_then(|n| n.checked_add(bytes.len() as u64))
            .ok_or_else(invalid)?;
        total =
            total.checked_add(size).filter(|n| i64::try_from(*n).is_ok()).ok_or_else(invalid)?;
        writer.write_all(&u32::try_from(owner.len()).map_err(|_| invalid())?.to_be_bytes())?;
        writer.write_all(owner.as_bytes())?;
        writer.write_all(bytes)?;
    }
    guard.require()?;
    Ok((records, total))
}

#[cfg(test)]
mod tests;
