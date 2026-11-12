// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Encrypted, fixed-owner base-row spool. SQLite key order is the protocol's encoded order.
use super::source_owner::SourceContext;
use super::{
    CodecRule, FamilyRule, FamilySelector, FullTransferStage, full_transfer_catalog,
    write_full_scalar_sql_row,
};
use crate::{StorageError, database::Connection};
use ramflux_protocol::custody::pairing::full_transfer::{Disposition, read_record_header};
use rusqlite::{OptionalExtension as _, params};
use std::io::Write;
use zeroize::{Zeroize as _, Zeroizing};
struct PrivateHeader(ramflux_protocol::custody::pairing::full_transfer::RecordHeader);
impl Drop for PrivateHeader {
    fn drop(&mut self) {
        self.0.key.zeroize();
    }
}

pub(super) const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS source_scalar_family(snapshot_id TEXT NOT NULL,family TEXT NOT NULL,rule_hash BLOB NOT NULL CHECK(length(rule_hash)=32),records INTEGER NOT NULL,encoded_bytes INTEGER NOT NULL,PRIMARY KEY(snapshot_id,family));
CREATE TABLE IF NOT EXISTS source_scalar_row(snapshot_id TEXT NOT NULL,family TEXT NOT NULL,key TEXT NOT NULL COLLATE BINARY,record BLOB NOT NULL CHECK(length(record) BETWEEN 1 AND 16384),PRIMARY KEY(snapshot_id,family,key));";
fn invalid() -> StorageError {
    StorageError::PairingField("UnsupportedRecord")
}
pub(super) fn compiled(family: &str) -> Result<&'static FamilyRule, StorageError> {
    let rule = full_transfer_catalog().iter().find(|rule| rule.id == family).ok_or_else(invalid)?;
    rule.require_typed_codec()?;
    if rule.disposition != Disposition::Transfer
        || rule.codec.iter().any(|field| {
            field.disposition == Disposition::Transfer
                && !matches!(
                    field.codec,
                    CodecRule::SqlMacSubkeys
                        | CodecRule::SqlBytes { .. }
                        | CodecRule::SqlBase64 { .. }
                        | CodecRule::SqlI64 { .. }
                )
        })
    {
        return Err(invalid());
    }
    Ok(rule)
}
// A copy of the existing selected-generation operands, with only a weak unlock owner.
// Worker callbacks recheck these per row without retaining the authoritative writer.
#[derive(Clone)]
pub(super) struct SourceGuard {
    unlocked: crate::database::WeakConnection,
    index: std::sync::Arc<crate::AccountIndex>,
    local: String,
    path: std::path::PathBuf,
    principal: String,
    cancelled: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
}
impl SourceGuard {
    pub(super) fn new(
        db: &crate::AccountDb,
        cancelled: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
    ) -> Self {
        Self {
            unlocked: db.connection.downgrade(),
            index: db.account_index.clone(),
            local: db.local_account_id.clone(),
            path: db.path.clone(),
            principal: db.principal_commitment.clone(),
            cancelled,
        }
    }
    pub(super) fn require(&self) -> Result<(), StorageError> {
        if self
            .cancelled
            .as_ref()
            .is_some_and(|flag| flag.load(std::sync::atomic::Ordering::Acquire))
        {
            return Err(StorageError::PairingField("Cancelled"));
        }
        if self.unlocked.upgrade_account_writer().is_none() {
            return Err(StorageError::AuthorizationRejected);
        }
        let selected = self.index.account(&self.local)?;
        if selected.account_state == "removed"
            || self.index.root().join(selected.db_relative_path) != self.path
            || selected.principal_commitment != self.principal
        {
            return Err(StorageError::PairingField("SnapshotInvalidated"));
        }
        Ok(())
    }
}
/// Exact counts for this encoded family only, not a complete manifest or semantic receipt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FullScalarSourceCounts {
    pub records: u64,
    pub encoded_bytes: u64,
}
impl SourceContext<'_> {
    /// Encode one fixed-width family from the OWN immutable base cut into encrypted SQL.
    /// Each bounded row is validated before insertion. A transaction publishes all rows and
    /// counts together; failed/repeated encodes cannot expose a partial family. No plaintext
    /// sorter file or unbounded row/key collection is used. Other owners remain unsupported.
    /// # Errors
    /// Refuses wrong source role/cut, unknown schema/codec, duplicate keys or lost unlock.
    pub fn stage_source_fixed_base_family(
        &mut self,
        snapshot_id: &str,
        family: &str,
    ) -> Result<FullScalarSourceCounts, StorageError> {
        self.stage_source_fixed_family(0, snapshot_id, family)
    }
    pub(super) fn stage_source_fixed_family(
        &mut self,
        cut: u64,
        snapshot_id: &str,
        family: &str,
    ) -> Result<FullScalarSourceCounts, StorageError> {
        let rule = compiled(family)?;
        rule.require_typed_codec()?;
        let FamilySelector::Table(table) = rule.selector else {
            return Err(invalid());
        };
        let spool = self.connection.clone();
        let guard = SourceGuard::new(self.db, self.cancelled.clone());
        let snapshot = snapshot_id.to_owned();
        self.with_source_cut(cut, snapshot_id, |input| {
            super::inventory::validate_columns(input, table, rule)?;
            input.call(move |source| Ok(build(source, &spool, &snapshot, table, rule, &guard)))?
        })
    }
    /// Write a committed fixed-owner family in exact bytewise encoded-key order to a
    /// PRIVATE encrypted stream sink. The writer stays with this short local I/O scope;
    /// it must not publish application/network data before whole-stream admission.
    /// # Errors
    /// Refuses absent/changed spool metadata, malformed rows, I/O failure or lost unlock.
    pub fn write_source_fixed_base_family<W: Write + Send + 'static>(
        &self,
        snapshot_id: &str,
        family: &str,
        writer: W,
    ) -> Result<(W, FullScalarSourceCounts), StorageError> {
        self.write_source_fixed_family(0, snapshot_id, family, writer)
    }
    pub(super) fn write_source_fixed_family<W: Write + Send + 'static>(
        &self,
        cut: u64,
        snapshot_id: &str,
        family: &str,
        writer: W,
    ) -> Result<(W, FullScalarSourceCounts), StorageError> {
        self.require_source_live()?;
        // Recheck the exact saved source view, including its private key/generations.
        self.with_source_cut(cut, snapshot_id, |_| Ok(()))?;
        let rule = compiled(family)?;
        let snapshot = snapshot_id.to_owned();
        let guard = SourceGuard::new(self.db, self.cancelled.clone());
        let result = self
            .connection
            .call(move |db| Ok(write_sorted(db, &snapshot, rule, writer, &guard)))??;
        self.require_source_live()?;
        Ok(result)
    }
}
fn counts(
    db: &Connection,
    snapshot: &str,
    rule: &FamilyRule,
) -> Result<Option<FullScalarSourceCounts>, StorageError> {
    let row: Option<(Vec<u8>,u64,u64)> = db.query_row(
        "SELECT rule_hash,records,encoded_bytes FROM source_scalar_family WHERE snapshot_id=?1 AND family=?2",
        params![snapshot,rule.id], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?)),
    ).optional()?;
    row.map(|(hash, records, encoded_bytes)| {
        if hash.as_slice() != rule.rule_hash()? {
            return Err(invalid());
        }
        Ok(FullScalarSourceCounts { records, encoded_bytes })
    })
    .transpose()
}
struct Build {
    db: Connection,
    committed: bool,
}
impl Drop for Build {
    fn drop(&mut self) {
        if !self.committed {
            let _ = self.db.execute_batch("ROLLBACK");
        }
    }
}
fn build(
    source: &mut rusqlite::Connection,
    spool: &Connection,
    snapshot: &str,
    table: &str,
    rule: &'static FamilyRule,
    source_guard: &SourceGuard,
) -> Result<FullScalarSourceCounts, StorageError> {
    source_guard.require()?;
    if let Some(counts) = counts(spool, snapshot, rule)? {
        return Ok(counts);
    }
    spool.execute_batch("BEGIN IMMEDIATE")?;
    let mut guard = Build { db: spool.clone(), committed: false };
    spool.execute(
        "DELETE FROM source_scalar_row WHERE snapshot_id=?1 AND family=?2",
        params![snapshot, rule.id],
    )?;
    let columns =
        rule.cells.iter().map(|cell| format!("\"{}\"", cell.name)).collect::<Vec<_>>().join(",");
    // All identifiers were validated from the local compiled catalog, never peer SQL.
    let mut query = source.prepare(&format!("SELECT {columns} FROM \"{table}\""))?;
    let mut rows = query.query([])?;
    let mut total = FullScalarSourceCounts { records: 0, encoded_bytes: 0 };
    while let Some(row) = rows.next()? {
        source_guard.require()?;
        let mut record = Zeroizing::new(Vec::new());
        let bytes = write_full_scalar_sql_row(rule, row, &mut *record)?;
        if record.len() > 16384 {
            return Err(invalid());
        }
        let header = read_record_header(&mut record.as_slice())
            .map_err(|_| invalid())?
            .ok_or_else(invalid)?;
        let key = Zeroizing::new(header.key);
        let snapshot = snapshot.to_owned();
        // Bypass generic Parameters/Row copies for private encoded rows and keys.
        spool.call(move |db| {
            db.execute(
                "INSERT INTO source_scalar_row(snapshot_id,family,key,record) VALUES(?1,?2,?3,?4)",
                params![snapshot, rule.id, key.as_str(), record.as_slice()],
            )
        })?;
        total.records = total.records.checked_add(1).ok_or_else(invalid)?;
        total.encoded_bytes = total.encoded_bytes.checked_add(bytes).ok_or_else(invalid)?;
    }
    spool.execute("INSERT INTO source_scalar_family(snapshot_id,family,rule_hash,records,encoded_bytes) VALUES(?1,?2,?3,?4,?5)",params![snapshot,rule.id,rule.rule_hash()?.as_slice(),total.records,total.encoded_bytes])?;
    source_guard.require()?;
    spool.execute_batch("COMMIT")?;
    guard.committed = true;
    Ok(total)
}
fn write_sorted<W: Write>(
    db: &mut rusqlite::Connection,
    snapshot: &str,
    rule: &FamilyRule,
    mut writer: W,
    source_guard: &SourceGuard,
) -> Result<(W, FullScalarSourceCounts), StorageError> {
    let (hash,expected_records,expected_bytes):(Vec<u8>,u64,u64)=db.query_row("SELECT rule_hash,records,encoded_bytes FROM source_scalar_family WHERE snapshot_id=?1 AND family=?2",params![snapshot,rule.id],|row|Ok((row.get(0)?,row.get(1)?,row.get(2)?)))?;
    if hash.as_slice() != rule.rule_hash()? {
        return Err(invalid());
    }
    let mut query=db.prepare("SELECT key,record FROM source_scalar_row WHERE snapshot_id=?1 AND family=?2 ORDER BY key COLLATE BINARY")?;
    let mut rows = query.query(params![snapshot, rule.id])?;
    let mut total = FullScalarSourceCounts { records: 0, encoded_bytes: 0 };
    while let Some(row) = rows.next()? {
        source_guard.require()?;
        let key = row.get_ref(0)?.as_str().map_err(|_| invalid())?;
        let record = row.get_ref(1)?.as_blob().map_err(|_| invalid())?;
        if record.len() > 16384 {
            return Err(invalid());
        }
        let mut input = record;
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
        writer.write_all(record)?;
        total.records = total.records.checked_add(1).ok_or_else(invalid)?;
        total.encoded_bytes =
            total.encoded_bytes.checked_add(record.len() as u64).ok_or_else(invalid)?;
    }
    if total.records != expected_records || total.encoded_bytes != expected_bytes {
        return Err(invalid());
    }
    source_guard.require()?;
    Ok((writer, total))
}

impl FullTransferStage<'_> {
    /// Encode one actual immutable base family through its compiled fixed-width owner.
    /// # Errors
    /// Refuses wrong role, unsupported codecs, stale cut/generation, duplicates or I/O failure.
    pub fn stage_source_fixed_base_family(
        &mut self,
        snapshot_id: &str,
        family: &str,
    ) -> Result<FullScalarSourceCounts, StorageError> {
        self.source_context()?.stage_source_fixed_base_family(snapshot_id, family)
    }
    /// Write the exact committed family, in encoded-key order, to a private encrypted sink.
    /// # Errors
    /// Refuses wrong role, missing/stale cuts/spools, malformed rows or output failures.
    pub fn write_source_fixed_base_family<W: Write + Send + 'static>(
        &self,
        snapshot_id: &str,
        family: &str,
        writer: W,
    ) -> Result<(W, FullScalarSourceCounts), StorageError> {
        self.source_context()?.write_source_fixed_base_family(snapshot_id, family, writer)
    }
}
