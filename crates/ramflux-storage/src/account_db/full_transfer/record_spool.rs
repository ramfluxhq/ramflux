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

const FRAGMENT_BYTES: usize = 16_384;
/// A protocol-bounded prefix suffices to parse framing; payload size never sizes this buffer.
pub(super) struct Probe {
    prefix: Zeroizing<Vec<u8>>,
    bytes: u64,
}
impl Probe {
    pub(super) fn new() -> Self {
        Self { prefix: Zeroizing::new(Vec::new()), bytes: 0 }
    }
    /// Reuse the exact validated encoding when it fits the bounded prefix.
    /// An overflow retains no claim that the prefix is a complete record.
    pub(super) fn into_complete(self) -> Option<Zeroizing<Vec<u8>>> {
        (self.bytes == self.prefix.len() as u64).then_some(self.prefix)
    }
    pub(super) fn header(
        &self,
        encoded: u64,
        rule: &super::FamilyRule,
    ) -> Result<PrivateHeader, StorageError> {
        if encoded != self.bytes {
            return Err(invalid());
        }
        super::record_profile::require_length(rule, encoded)?;
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
        // Allocate only retained bytes, still capped by the protocol header bound.
        // Replace through Zeroizing so growing never frees an unwiped prefix.
        let length = self
            .prefix
            .len()
            .checked_add(amount)
            .ok_or_else(|| std::io::Error::other("source header prefix overflow"))?;
        if length > self.prefix.capacity() {
            let mut prefix = Zeroizing::new(Vec::with_capacity(length));
            prefix.extend_from_slice(&self.prefix);
            self.prefix = prefix;
        }
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
        super::record_profile::require_length(super::source_scalar::compiled(family)?, length)?;
        let expected = usize::try_from(length).map_err(|_| invalid())?;
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
#[derive(Clone, Copy)]
enum Scope {
    Main,
    Verifier,
}
impl Scope {
    fn schema(self) -> &'static str {
        match self {
            Self::Main => "main",
            Self::Verifier => "verifier",
        }
    }
}
struct LocalSink<'db> {
    db: &'db rusqlite::Connection,
    scope: Scope,
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
            .blob_open(self.scope.schema(), "full_stream_pending", "record", 1, false)
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
    fn create(
        db: &'db rusqlite::Connection,
        length: u64,
        scope: Scope,
        rule: &super::FamilyRule,
    ) -> Result<Self, StorageError> {
        if db.is_autocommit() {
            return Err(invalid());
        }
        super::record_profile::require_length(rule, length)?;
        let schema = scope.schema();
        db.execute_batch(&format!("CREATE TABLE IF NOT EXISTS {schema}.full_stream_pending(slot INTEGER PRIMARY KEY CHECK(slot=1),family TEXT NOT NULL,record BLOB NOT NULL {});",super::record_profile::sql_constraint()))?;
        super::record_profile::require_storage_format(db, schema, "full_stream_pending")?;
        db.execute(&format!("INSERT INTO {schema}.full_stream_pending(slot,family,record) VALUES(1,?1,zeroblob(?2)) ON CONFLICT(slot) DO UPDATE SET family=excluded.family,record=excluded.record"),params![rule.id,length])?;
        Ok(Self {
            db,
            scope,
            expected: usize::try_from(length).map_err(|_| invalid())?,
            written: 0,
        })
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
        source: &rusqlite::Connection,
        db: &'db rusqlite::Connection,
        rule: &super::FamilyRule,
        row: &rusqlite::Row<'_>,
        account: &str,
    ) -> Result<Self, StorageError> {
        let header = encode_sql(source, db, rule, row, Scope::Main, Some(account))?;
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
        let mut output = LocalSink::create(db, length, Scope::Main, rule)?;
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
    super::record_profile::require_length(rule, length)?;
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

fn encode_sql(
    source: &rusqlite::Connection,
    db: &rusqlite::Connection,
    rule: &super::FamilyRule,
    row: &rusqlite::Row<'_>,
    scope: Scope,
    account: Option<&str>,
) -> Result<PrivateHeader, StorageError> {
    let mut probe = Probe::new();
    let length = super::owner_sql::write(source, rule, row, &mut probe, account)?;
    let header = probe.header(length, rule)?;
    let mut output = LocalSink::create(db, length, scope, rule)?;
    if super::owner_sql::write(source, rule, row, &mut output, account)? != length {
        return Err(invalid());
    }
    output.finish()?;
    Ok(header)
}
/// Actual private values can only mark a pre-existing expected row, never construct
/// one or become a qualified contribution. Scratch lives outside both sealed files.
pub(super) struct Comparison<'db> {
    db: &'db rusqlite::Connection,
    header: PrivateHeader,
}
impl<'db> Comparison<'db> {
    pub(super) fn sql(
        source: &rusqlite::Connection,
        db: &'db rusqlite::Connection,
        rule: &super::FamilyRule,
        row: &rusqlite::Row<'_>,
        account: &str,
    ) -> Result<Self, StorageError> {
        Ok(Self { db, header: encode_sql(source, db, rule, row, Scope::Verifier, Some(account))? })
    }
    pub(super) fn mark(self) -> Result<(), StorageError> {
        if self.db.execute("UPDATE verifier.materialized_record SET seen=1 WHERE family=?1 AND key=?2 AND record=(SELECT record FROM verifier.full_stream_pending WHERE slot=1)",params![self.header.0.family,self.header.0.key])? != 1 {return Err(StorageError::PairingField("ManifestMismatch"));}
        self.db.execute("DELETE FROM verifier.full_stream_pending WHERE slot=1", [])?;
        Ok(())
    }
}
/// The only derived expected encoding here is the established source-qualified MAC
/// mapping. Its operands come from the independently verified original ledger row.
pub(super) fn expected_imported_mac(
    db: &rusqlite::Connection,
    owner: &str,
    cells: &super::fixed_union::Cells,
) -> Result<(), StorageError> {
    let rule = super::source_scalar::compiled("sql/full_imported_mac_bundle")?;
    let header = db.query_row(
        "SELECT ?1 AS source_ref,?2 AS bundle_id,?3 AS subkeys",
        params![owner, cells.text(0)?, cells.bytes(1)?],
        |row| Ok(encode_sql(db, db, rule, row, Scope::Verifier, None)),
    )??;
    if db.execute("INSERT INTO verifier.materialized_record(family,key,record) SELECT ?1,?2,record FROM verifier.full_stream_pending WHERE slot=1 ON CONFLICT(family,key) DO UPDATE SET record=excluded.record WHERE verifier.materialized_record.record=excluded.record",params![header.0.family,header.0.key])? != 1 {return Err(StorageError::PairingField("ManifestMismatch"));}
    db.execute("DELETE FROM verifier.full_stream_pending WHERE slot=1", [])?;
    Ok(())
}
