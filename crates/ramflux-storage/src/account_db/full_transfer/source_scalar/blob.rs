// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Bounded source framing probe and direct encrypted SQLite BLOB construction.
use super::{PrivateHeader, SourceGuard, invalid};
use crate::{StorageError, database::Connection};
use ramflux_protocol::custody::pairing::{
    PairingWire as _,
    full_transfer::{RecordHeader, read_record_header},
};
use rusqlite::params;
use std::io::Write;
use zeroize::Zeroizing;

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
