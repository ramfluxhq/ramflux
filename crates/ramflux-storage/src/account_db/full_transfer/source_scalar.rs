// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Encrypted, fixed-owner base-row spool. SQLite key order is the protocol's encoded order.
use super::record_spool as blob;
use super::source_owner::SourceContext;
use super::{FamilyRule, FamilySelector, FullTransferStage, full_transfer_catalog};
use crate::{StorageError, database::Connection};
use ramflux_protocol::custody::pairing::full_transfer::Disposition;
use rusqlite::{OptionalExtension as _, params};
use std::io::Write;

pub(super) fn schema() -> String {
    let check = super::record_profile::sql_constraint();
    format!("CREATE TABLE IF NOT EXISTS source_scalar_family(snapshot_id TEXT NOT NULL,family TEXT NOT NULL,rule_hash BLOB NOT NULL CHECK(length(rule_hash)=32),records INTEGER NOT NULL,encoded_bytes INTEGER NOT NULL,PRIMARY KEY(snapshot_id,family));
CREATE TABLE IF NOT EXISTS source_scalar_row(snapshot_id TEXT NOT NULL,family TEXT NOT NULL,key TEXT NOT NULL COLLATE BINARY,record BLOB NOT NULL {check},PRIMARY KEY(snapshot_id,family,key));")
}

fn invalid() -> StorageError {
    StorageError::PairingField("UnsupportedRecord")
}
pub(super) fn compiled(family: &str) -> Result<&'static FamilyRule, StorageError> {
    let rule = full_transfer_catalog().iter().find(|rule| rule.id == family).ok_or_else(invalid)?;
    rule.require_typed_codec()?;
    if rule.id == super::message_denial::FAMILY {
        super::message_denial::require_rule(rule)?;
        return Ok(rule);
    }
    if rule.disposition != Disposition::Transfer
        || rule.codec.iter().any(|field| {
            field.disposition == Disposition::Transfer
                && !super::catalog::scalar_sql_codec(&field.codec)
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
    pub(super) fn require_remote_attachments(
        &self,
        snapshot: &Connection,
    ) -> Result<(), StorageError> {
        self.require()?;
        let worker =
            self.unlocked.upgrade_account_writer().ok_or(StorageError::AuthorizationRejected)?;
        super::attachment_availability::require(snapshot, &worker)?;
        self.require()
    }
    pub(super) fn schema_generation(&self) -> Result<u64, StorageError> {
        self.require()?;
        let worker =
            self.unlocked.upgrade_account_writer().ok_or(StorageError::AuthorizationRejected)?;
        let schema =
            worker
                .query_row("SELECT max(schema_version) FROM schema_migration", [], |r| r.get(0))?;
        self.require()?;
        Ok(schema)
    }
    pub(super) fn require(&self) -> Result<(), StorageError> {
        crate::database::require_generation_rebase_deadline()?;
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
        let guard = self.guard.clone();
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
        let guard = self.guard.clone();
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
    let transaction = spool.immediate_transaction()?;
    spool.execute(
        "DELETE FROM source_scalar_row WHERE snapshot_id=?1 AND family=?2",
        params![snapshot, rule.id],
    )?;
    let columns =
        rule.cells.iter().map(|cell| format!("\"{}\"", cell.name)).collect::<Vec<_>>().join(",");
    // All identifiers were validated from the local compiled catalog, never peer SQL.
    let mut query = source.prepare(&format!(
        "SELECT {columns} FROM \"{table}\" WHERE {}",
        super::owner_sql::row_filter(rule)
    ))?;
    let mut rows = query.query([])?;
    let mut total = FullScalarSourceCounts { records: 0, encoded_bytes: 0 };
    while let Some(row) = rows.next()? {
        source_guard.require()?;
        if rule.id == super::input_denial::FAMILY {
            super::input_denial::require_bundle(
                source,
                row.get_ref(1)?.as_str().map_err(|_| invalid())?,
            )?;
        }
        if rule.id == "sql/full_imported_mac_bundle" {
            let source = super::super::mac_subkeys::full::decode_source_ref(
                row.get_ref(0)?.as_str().map_err(|_| invalid())?.as_bytes(),
            )?;
            if source.account_anchor != source_guard.principal {
                return Err(invalid());
            }
        }
        let mut probe = blob::Probe::new();
        let bytes =
            super::owner_sql::write(source, rule, row, &mut probe, Some(&source_guard.principal))?;
        let header = probe.header(bytes, rule)?;
        let mut sink =
            blob::Sink::create(spool, snapshot, rule.id, &header.0.key, bytes, source_guard)?;
        if let Some(encoded) = probe.into_complete() {
            // The first pass already validated every exact byte. Keep the same
            // guarded encrypted sink without encoding a small row a second time.
            sink.write_all(&encoded)?;
        } else if super::owner_sql::write(
            source,
            rule,
            row,
            &mut sink,
            Some(&source_guard.principal),
        )? != bytes
        {
            return Err(invalid());
        }
        sink.finish()?;
        total.records = total.records.checked_add(1).ok_or_else(invalid)?;
        total.encoded_bytes = total.encoded_bytes.checked_add(bytes).ok_or_else(invalid)?;
    }
    spool.execute("INSERT INTO source_scalar_family(snapshot_id,family,rule_hash,records,encoded_bytes) VALUES(?1,?2,?3,?4,?5)",params![snapshot,rule.id,rule.rule_hash()?.as_slice(),total.records,total.encoded_bytes])?;
    source_guard.require()?;
    transaction.commit()?;
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
    let mut query=db.prepare("SELECT key,rowid,length(record) FROM source_scalar_row WHERE snapshot_id=?1 AND family=?2 ORDER BY key COLLATE BINARY")?;
    let mut rows = query.query(params![snapshot, rule.id])?;
    let mut total = FullScalarSourceCounts { records: 0, encoded_bytes: 0 };
    while let Some(row) = rows.next()? {
        source_guard.require()?;
        let key = row.get_ref(0)?.as_str().map_err(|_| invalid())?;
        let length = row.get::<_, u64>(2)?;
        let mut input = super::record_spool::checked_blob(
            db,
            "source_scalar_row",
            row.get(1)?,
            length,
            rule,
            key,
        )?;
        super::record_spool::copy_blob(&mut input, length, &mut writer, source_guard)?;
        total.records = total.records.checked_add(1).ok_or_else(invalid)?;
        total.encoded_bytes = total.encoded_bytes.checked_add(length).ok_or_else(invalid)?;
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
