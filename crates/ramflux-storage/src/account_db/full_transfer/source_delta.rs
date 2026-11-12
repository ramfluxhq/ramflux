// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Fixed-owner cut diff: indexed encoded-key merge join, no row-sized trees or live reads.
use super::{
    FamilyRule, FullBaseSourceEncoding, FullScalarSourceCounts, FullTransferStage,
    full_transfer_catalog, source_base::Rooted, source_scalar::SourceGuard,
};
use crate::{StorageError, database::Connection};
use ramflux_protocol::custody::pairing::full_transfer::{
    Disposition, RecordHeader, RecordOp, U64, chunk_layout, read_record_header, write_record_header,
};
use rusqlite::params;
use std::io::Write;
use zeroize::{Zeroize as _, Zeroizing};

fn invalid() -> StorageError {
    StorageError::PairingField("UnsupportedRecord")
}
struct PrivateHeader(RecordHeader);
impl Drop for PrivateHeader {
    fn drop(&mut self) {
        self.0.key.zeroize();
    }
}

impl FullTransferStage<'_> {
    /// Encode one delta from two retained, consecutive OWN immutable cuts (1 through8).
    /// Complete local schema/typed-owner preflight precedes output. Counts describe only
    /// this diff, including absences; identical rows emit nothing. This operation deletes
    /// no snapshot or prior stream and grants no receipt, J3 or tail admission.
    /// The writer must be private/encrypted until the manifest/signature gates complete.
    /// # Errors
    /// Refuses wrong role, nonconsecutive cuts, unknown owners, decreased privacy generation,
    /// changed schema, corrupt encrypted spools, cancellation, lost unlock or output errors.
    pub fn encode_fixed_delta_source<W: Write + Send + 'static>(
        &mut self,
        cut: u64,
        previous_snapshot: &str,
        current_snapshot: &str,
        writer: W,
    ) -> Result<(W, FullBaseSourceEncoding), StorageError> {
        if !(1..=8).contains(&cut) || previous_snapshot == current_snapshot {
            return Err(StorageError::PairingField("WrongContext"));
        }
        let mut source = self.source_context()?;
        // The compiled preflight walks BOTH actual cuts, not peer-provided family counts.
        // Existing source-family rows are immutable and idempotent for an exact cut/rule.
        let (_, previous) =
            source.encode_fixed_cut_source(cut - 1, previous_snapshot, std::io::sink())?;
        let (_, mut current) =
            source.encode_fixed_cut_source(cut, current_snapshot, std::io::sink())?;
        if previous.storage_generation != current.storage_generation {
            return Err(StorageError::PairingField("SnapshotInvalidated"));
        }
        if previous.source_erasure_generation > current.source_erasure_generation {
            return Err(StorageError::PairingField("ManifestMismatch"));
        }
        let guard = SourceGuard::new(source.db, source.cancelled.clone());
        let mut total = 0_u64;
        for (family, rule) in current.schema.families.iter_mut().zip(full_transfer_catalog()) {
            family.source_rows = U64(0);
            family.portable_records = U64(0);
            family.encoded_bytes = U64(0);
            if family.disposition == Disposition::Transfer {
                let (_, counts) = diff_family(
                    source.connection,
                    previous_snapshot,
                    current_snapshot,
                    rule,
                    std::io::sink(),
                    &guard,
                )?;
                family.source_rows = U64(counts.records);
                family.portable_records = U64(counts.records);
                family.encoded_bytes = U64(counts.encoded_bytes);
                total = total.checked_add(counts.encoded_bytes).ok_or_else(invalid)?;
            }
        }
        let mut output =
            Rooted::new(writer, total)?.with_wire(source.wire_spool(cut, current_snapshot)?);
        for (family, rule) in current.schema.families.iter().zip(full_transfer_catalog()) {
            if family.portable_records.0 == 0 {
                continue;
            }
            let (next, counts) = diff_family(
                source.connection,
                previous_snapshot,
                current_snapshot,
                rule,
                output,
                &guard,
            )?;
            if counts.records != family.portable_records.0
                || counts.encoded_bytes != family.encoded_bytes.0
            {
                return Err(invalid());
            }
            output = next;
        }
        let (writer, root) = output.finish(total)?;
        current.total_bytes = total;
        current.chunk_count = chunk_layout(total).map_err(|_| invalid())?.0;
        current.chunks_root = root;
        source.require_source_live()?;
        Ok((writer, current))
    }
}

fn diff_family<W: Write + Send + 'static>(
    connection: &Connection,
    previous: &str,
    current: &str,
    rule: &'static FamilyRule,
    mut output: W,
    guard: &SourceGuard,
) -> Result<(W, FullScalarSourceCounts), StorageError> {
    guard.require()?;
    let worker_guard = guard.clone();
    let old = previous.to_owned();
    let new = current.to_owned();
    // Two index cursors use at most two bounded SQLite row views; no UNION/temp sorter.
    let result = connection.call(move |db| {
        let run = || -> Result<_, StorageError> {
            let sql = "SELECT key,record FROM source_scalar_row WHERE snapshot_id=?1 AND family=?2 ORDER BY key COLLATE BINARY";
            let mut before = db.prepare(sql)?;
            let mut after = db.prepare(sql)?;
            let mut left = before.query(params![old,rule.id])?;
            let mut right = after.query(params![new,rule.id])?;
            let mut a = left.next()?;
            let mut b = right.next()?;
            let mut counts = FullScalarSourceCounts { records: 0, encoded_bytes: 0 };
            while a.is_some() || b.is_some() {
                worker_guard.require()?;
                let ordering = match (a, b) {
                    (Some(a), Some(b)) => key(a)?.cmp(key(b)?),
                    (Some(_), None) => std::cmp::Ordering::Less,
                    _ => std::cmp::Ordering::Greater,
                };
                match ordering {
                    std::cmp::Ordering::Less => {
                        let row = a.ok_or_else(invalid)?;
                        let mut header = checked(rule, row)?;
                        header.0.op = RecordOp::Absent;
                        header.0.cell_types.clear();
                        header.0.cell_lengths.clear();
                        // Revalidate the absent stable-key grammar through the same owner.
                        super::copy_full_scalar_record(rule,&header.0,&mut std::io::empty(),&mut std::io::sink())?;
                        let mut encoded = Zeroizing::new(Vec::new());
                        write_record_header(&mut *encoded, &header.0).map_err(|_| invalid())?;
                        output.write_all(&encoded)?;
                        add(&mut counts,encoded.len() as u64)?;
                        a = left.next()?;
                    }
                    std::cmp::Ordering::Greater => {
                        let row = b.ok_or_else(invalid)?;
                        let _header = checked(rule,row)?;
                        let bytes = record(row)?;
                        output.write_all(bytes)?;
                        add(&mut counts,bytes.len() as u64)?;
                        b = right.next()?;
                    }
                    std::cmp::Ordering::Equal => {
                        let before = a.ok_or_else(invalid)?;
                        let after = b.ok_or_else(invalid)?;
                        let _before_header = checked(rule,before)?;
                        let _after_header = checked(rule,after)?;
                        if record(before)? != record(after)? {
                            let bytes = record(after)?;
                            output.write_all(bytes)?;
                            add(&mut counts,bytes.len() as u64)?;
                        }
                        a = left.next()?;
                        b = right.next()?;
                    }
                }
            }
            Ok((output,counts))
        };
        Ok(run())
    })??;
    guard.require()?;
    Ok(result)
}
fn key<'a>(row: &'a rusqlite::Row<'_>) -> Result<&'a str, StorageError> {
    row.get_ref(0)?.as_str().map_err(|_| invalid())
}
fn record<'a>(row: &'a rusqlite::Row<'_>) -> Result<&'a [u8], StorageError> {
    let bytes = row.get_ref(1)?.as_blob().map_err(|_| invalid())?;
    if bytes.len() > 16384 {
        return Err(invalid());
    }
    Ok(bytes)
}
fn checked(rule: &FamilyRule, row: &rusqlite::Row<'_>) -> Result<PrivateHeader, StorageError> {
    let mut bytes = record(row)?;
    let header =
        PrivateHeader(read_record_header(&mut bytes).map_err(|_| invalid())?.ok_or_else(invalid)?);
    if header.0.key != key(row)? || header.0.op != RecordOp::Put {
        return Err(invalid());
    }
    super::copy_full_scalar_record(rule, &header.0, &mut bytes, &mut std::io::sink())?;
    if !bytes.is_empty() {
        return Err(invalid());
    }
    Ok(header)
}
fn add(counts: &mut FullScalarSourceCounts, bytes: u64) -> Result<(), StorageError> {
    counts.records = counts.records.checked_add(1).ok_or_else(invalid)?;
    counts.encoded_bytes = counts.encoded_bytes.checked_add(bytes).ok_or_else(invalid)?;
    Ok(())
}
