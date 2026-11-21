// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Bounded source framing probe and direct encrypted SQLite BLOB construction.
use super::source_scalar::SourceGuard;
fn invalid() -> StorageError {
    StorageError::PairingField("UnsupportedRecord")
}
pub(super) struct PrivateHeader(pub(super) RecordHeader);
impl Drop for PrivateHeader {
    fn drop(&mut self) {
        self.0.key.zeroize();
    }
}
use crate::{StorageError, database::Connection};
use ramflux_protocol::custody::pairing::{
    PairingWire as _,
    full_transfer::{RecordHeader, read_record_header},
};
use rusqlite::params;
use std::io::{Seek as _, SeekFrom, Write};
use zeroize::{Zeroize as _, Zeroizing};

pub(super) const RECORD_LIMIT: usize = 262_144;
const FRAGMENT_BYTES: usize = 16_384;
/// A protocol-bounded prefix suffices to parse framing; payload size never sizes this buffer.
pub(super) struct Probe {
    prefix: Zeroizing<Vec<u8>>,
    bytes: u64,
}
impl Probe {
    pub(super) fn new() -> Self {
        Self {
            prefix: Zeroizing::new(Vec::with_capacity(RecordHeader::LIMIT.saturating_add(4))),
            bytes: 0,
        }
    }
    pub(super) fn header(&self, encoded: u64) -> Result<PrivateHeader, StorageError> {
        if encoded != self.bytes || encoded > RECORD_LIMIT as u64 {
            return Err(invalid());
        }
        Ok(PrivateHeader(
            read_record_header(&mut self.prefix.as_slice())
                .map_err(|_| invalid())?
                .ok_or_else(invalid)?,
        ))
    }
}
impl Write for Probe {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let limit = RecordHeader::LIMIT
            .checked_add(4)
            .ok_or_else(|| std::io::Error::other("source header bound overflow"))?;
        let amount = limit.saturating_sub(self.prefix.len()).min(bytes.len());
        self.prefix.extend_from_slice(
            bytes.get(..amount).ok_or_else(|| std::io::Error::other("source header prefix"))?,
        );
        self.bytes = self
            .bytes
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| std::io::Error::other("source record length overflow"))?;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
pub(super) struct Sink {
    db: Connection,
    rowid: i64,
    expected: usize,
    written: usize,
    guard: SourceGuard,
}
impl Sink {
    pub(super) fn create(
        db: &Connection,
        snapshot: &str,
        family: &'static str,
        key: &str,
        length: u64,
        guard: &SourceGuard,
    ) -> Result<Self, StorageError> {
        guard.require()?;
        let expected = usize::try_from(length).map_err(|_| invalid())?;
        if expected == 0 || expected > RECORD_LIMIT {
            return Err(invalid());
        }
        let snapshot = snapshot.to_owned();
        let key = Zeroizing::new(key.to_owned());
        let rowid=db.call(move|db| {
            db.execute("INSERT INTO source_scalar_row(snapshot_id,family,key,record) VALUES(?1,?2,?3,zeroblob(?4))",params![snapshot,family,key.as_str(),expected])?;
            Ok(db.last_insert_rowid())
        })?;
        Ok(Self { db: db.clone(), rowid, expected, written: 0, guard: guard.clone() })
    }
    pub(super) fn finish(self) -> Result<(), StorageError> {
        self.guard.require()?;
        if self.written != self.expected {
            return Err(invalid());
        }
        Ok(())
    }
}
impl Write for Sink {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        self.guard.require().map_err(std::io::Error::other)?;
        let amount = bytes.len().min(FRAGMENT_BYTES);
        let next = self
            .written
            .checked_add(amount)
            .filter(|next| *next <= self.expected)
            .ok_or_else(|| std::io::Error::other("source record exceeds measured length"))?;
        let fragment = Zeroizing::new(
            bytes
                .get(..amount)
                .ok_or_else(|| std::io::Error::other("source record fragment"))?
                .to_vec(),
        );
        let (rowid, offset, expected) = (self.rowid, self.written, self.expected);
        self.db
            .call(move |db| {
                let mut blob = db.blob_open("main", "source_scalar_row", "record", rowid, false)?;
                if blob.len() != expected {
                    return Err(rusqlite::Error::InvalidQuery);
                }
                blob.write_at(&fragment, offset)
            })
            .map_err(std::io::Error::other)?;
        self.written = next;
        Ok(amount)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// A single uncommitted, encrypted candidate. It never grants an application proof.
/// Construction validates exact field grammar before retaining a qualified contribution.
pub(super) struct Candidate<'db> {
    db: &'db rusqlite::Connection,
    pub(super) header: PrivateHeader,
}
struct LocalSink<'db> {
    db: &'db rusqlite::Connection,
    expected: usize,
    written: usize,
}
impl Write for LocalSink<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        let amount = bytes.len().min(FRAGMENT_BYTES);
        let next = self
            .written
            .checked_add(amount)
            .filter(|next| *next <= self.expected)
            .ok_or_else(|| std::io::Error::other("candidate exceeds measured record"))?;
        let mut blob = self
            .db
            .blob_open("main", "full_stream_pending", "record", 1, false)
            .map_err(std::io::Error::other)?;
        if blob.len() != self.expected {
            return Err(std::io::Error::other("candidate size changed"));
        }
        blob.write_at(
            bytes.get(..amount).ok_or_else(|| std::io::Error::other("candidate fragment"))?,
            self.written,
        )
        .map_err(std::io::Error::other)?;
        self.written = next;
        Ok(amount)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
impl<'db> LocalSink<'db> {
    fn create(db: &'db rusqlite::Connection, length: u64) -> Result<Self, StorageError> {
        if db.is_autocommit() || length == 0 || length > RECORD_LIMIT as u64 {
            return Err(invalid());
        }
        db.execute_batch("CREATE TABLE IF NOT EXISTS full_stream_pending(slot INTEGER PRIMARY KEY CHECK(slot=1),record BLOB NOT NULL CHECK(length(record) BETWEEN 1 AND 262144));")?;
        db.execute("INSERT INTO full_stream_pending VALUES(1,zeroblob(?1)) ON CONFLICT(slot) DO UPDATE SET record=excluded.record",[length])?;
        Ok(Self { db, expected: usize::try_from(length).map_err(|_| invalid())?, written: 0 })
    }
    fn finish(self) -> Result<(), StorageError> {
        if self.written != self.expected {
            return Err(invalid());
        }
        Ok(())
    }
}
impl<'db> Candidate<'db> {
    pub(super) fn sql(
        db: &'db rusqlite::Connection,
        rule: &super::FamilyRule,
        row: &rusqlite::Row<'_>,
    ) -> Result<Self, StorageError> {
        let mut probe = Probe::new();
        let length = super::write_full_scalar_sql_row(rule, row, &mut probe)?;
        let header = probe.header(length)?;
        let mut output = LocalSink::create(db, length)?;
        if super::write_full_scalar_sql_row(rule, row, &mut output)? != length {
            return Err(invalid());
        }
        output.finish()?;
        Ok(Self { db, header })
    }
    pub(super) fn input(
        db: &'db rusqlite::Connection,
        rule: &super::FamilyRule,
        header: RecordHeader,
        input: &mut impl std::io::Read,
    ) -> Result<Self, StorageError> {
        let header = PrivateHeader(header);
        let mut prefix = Zeroizing::new(Vec::new());
        ramflux_protocol::custody::pairing::full_transfer::write_record_header(
            &mut *prefix,
            &header.0,
        )
        .map_err(|_| invalid())?;
        let length =
            header.0.cell_lengths.iter().try_fold(prefix.len() as u64, |sum, length| {
                sum.checked_add(length.0).ok_or_else(invalid)
            })?;
        let mut output = LocalSink::create(db, length)?;
        output.write_all(&prefix)?;
        super::copy_full_scalar_record(rule, &header.0, input, &mut output)?;
        output.finish()?;
        Ok(Self { db, header })
    }
    pub(super) fn apply(
        &self,
        private: &mut crate::BackupDatabase,
        source: &ramflux_protocol::custody::DeviceRef,
    ) -> Result<(), StorageError> {
        let mut input = self.db.blob_open("main", "full_stream_pending", "record", 1, true)?;
        let header = PrivateHeader(
            read_record_header(&mut input).map_err(|_| invalid())?.ok_or_else(invalid)?,
        );
        private.apply_full_fixed_base_record(source, &header.0, &mut input)?;
        if input.stream_position()? != input.len() as u64 {
            return Err(invalid());
        }
        Ok(())
    }
    pub(super) fn target(self) -> Result<(), StorageError> {
        if self.db.execute("INSERT INTO current_target(family,key,record) SELECT ?1,?2,record FROM full_stream_pending WHERE slot=1",params![self.header.0.family,self.header.0.key])? != 1 {return Err(invalid());}
        self.db.execute("DELETE FROM full_stream_pending WHERE slot=1", [])?;
        Ok(())
    }
    pub(super) fn retain_original(
        &self,
        nonce: &[u8; 32],
        owner: &str,
    ) -> Result<(), StorageError> {
        if self.db.execute("INSERT INTO full_union_input(generation_nonce,owner,family,key,record) SELECT ?1,?2,?3,?4,record FROM full_stream_pending WHERE slot=1 ON CONFLICT(generation_nonce,owner,family,key) DO UPDATE SET record=excluded.record",params![nonce.as_slice(),owner,self.header.0.family,self.header.0.key])? != 1 {return Err(invalid());}
        Ok(())
    }
    pub(super) fn retain_union(
        self,
        nonce: &[u8; 32],
        owner: &str,
        replace: bool,
    ) -> Result<(), StorageError> {
        use rusqlite::OptionalExtension as _;
        let equal=self.db.query_row("SELECT record=(SELECT record FROM full_stream_pending WHERE slot=1) FROM full_union_record WHERE generation_nonce=?1 AND owner=?2 AND family=?3 AND key=?4",params![nonce.as_slice(),owner,self.header.0.family,self.header.0.key],|row|row.get::<_,bool>(0)).optional()?;
        if equal == Some(false) && !replace {
            return Err(StorageError::PairingField("TransferConflict"));
        }
        if self.db.execute("INSERT INTO full_union_record(generation_nonce,owner,family,key,record) SELECT ?1,?2,?3,?4,record FROM full_stream_pending WHERE slot=1 ON CONFLICT(generation_nonce,owner,family,key) DO UPDATE SET record=excluded.record",params![nonce.as_slice(),owner,self.header.0.family,self.header.0.key])? != 1 {return Err(invalid());}
        self.db.execute("DELETE FROM full_stream_pending WHERE slot=1", [])?;
        Ok(())
    }
}

/// Validate the entire canonical record before any normalized output, then rewind the
/// same owned BLOB handle. Table names are local compiled spool names, never input SQL.
pub(super) fn checked_blob<'db>(
    db: &'db rusqlite::Connection,
    table: &'static str,
    rowid: i64,
    length: u64,
    rule: &super::FamilyRule,
    key: &str,
) -> Result<rusqlite::blob::Blob<'db>, StorageError> {
    if length == 0 || length > RECORD_LIMIT as u64 {
        return Err(invalid());
    }
    let mut input = db.blob_open("main", table, "record", rowid, true)?;
    if input.len() as u64 != length {
        return Err(invalid());
    }
    let header =
        PrivateHeader(read_record_header(&mut input).map_err(|_| invalid())?.ok_or_else(invalid)?);
    if header.0.key != key {
        return Err(invalid());
    }
    super::copy_full_scalar_record(rule, &header.0, &mut input, &mut std::io::sink())?;
    if input.stream_position()? != length {
        return Err(invalid());
    }
    input.seek(SeekFrom::Start(0))?;
    Ok(input)
}
pub(super) fn copy_blob(
    input: &mut impl std::io::Read,
    length: u64,
    output: &mut impl Write,
    guard: &SourceGuard,
) -> Result<(), StorageError> {
    let mut buffer = Zeroizing::new([0_u8; FRAGMENT_BYTES]);
    let mut copied = 0_u64;
    loop {
        guard.require()?;
        let amount = input.read(buffer.as_mut_slice())?;
        if amount == 0 {
            break;
        }
        copied = copied
            .checked_add(amount as u64)
            .filter(|copied| *copied <= length)
            .ok_or_else(invalid)?;
        let bytes = buffer.get_mut(..amount).ok_or_else(invalid)?;
        output.write_all(bytes)?;
        bytes.zeroize();
    }
    if copied != length {
        return Err(invalid());
    }
    Ok(())
}
