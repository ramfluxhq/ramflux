// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Complete base stream only when every actual nonempty family has a compiled owner.
use super::source_owner::SourceContext;
use super::{FullTransferSchema, FullTransferStage, full_transfer_catalog};
use crate::StorageError;
use ramflux_protocol::custody::pairing::full_transfer::{
    CHUNK_BYTES, Disposition, RootHasher, U64, chunk_layout,
};
use std::io::Write;
use zeroize::{Zeroize as _, Zeroizing};

/// Actual immutable-cut encoding operands, before the source signature/native/SAS gates.
/// No receiver application or `DataVerified` acceptance is implied by these counts/root.
#[derive(Clone)]
pub struct FullBaseSourceEncoding {
    pub schema: FullTransferSchema,
    pub storage_generation: u64,
    pub source_erasure_generation: u64,
    pub total_bytes: u64,
    pub chunk_count: u64,
    pub chunks_root: [u8; 32],
}
fn invalid() -> StorageError {
    StorageError::PairingField("UnsupportedRecord")
}
impl SourceContext<'_> {
    /// Encode the OWN exact base cut through the implemented fixed-width SQL owners.
    /// The full schema/nonempty-owner preflight precedes every row/output. Unknown actor
    /// or table codecs refuse the complete attempt, never omit records. E/R values
    /// never enter output. Records use compiled family then encoded stable-key order, and the root
    /// covers every exact output byte with ordinary full-profile chunk boundaries.
    /// The sink MUST remain private and encrypted until the manifest/signature owners finish.
    /// # Errors
    /// Refuses unsupported nonempty families, schema changes, encoding/output failure or lock.
    pub fn encode_fixed_base_source<W: Write + Send + 'static>(
        &mut self,
        snapshot_id: &str,
        writer: W,
    ) -> Result<(W, FullBaseSourceEncoding), StorageError> {
        self.encode_fixed_cut_source(0, snapshot_id, writer)
    }
    pub(super) fn encode_fixed_cut_source<W: Write + Send + 'static>(
        &mut self,
        cut: u64,
        snapshot_id: &str,
        writer: W,
    ) -> Result<(W, FullBaseSourceEncoding), StorageError> {
        let rules = full_transfer_catalog();
        let mut schema = self.source_cut_schema(cut, snapshot_id, rules)?;
        schema.require_typed_owners(rules)?;
        let (storage_generation, source_erasure_generation) =
            self.with_source_cut(cut, snapshot_id, |input| {
                Ok((
                    input.query_row(
                        "SELECT max(schema_version) FROM schema_migration",
                        [],
                        |row| row.get::<_, u64>(0),
                    )?,
                    input.query_row(
                        "SELECT generation FROM account_erasure_generation WHERE singleton=1",
                        [],
                        |row| row.get::<_, u64>(0),
                    )?,
                ))
            })?;
        for family in &schema.families {
            if family.disposition == Disposition::Transfer && family.source_rows.0 > 0 {
                super::source_scalar::compiled(&family.id)?;
            }
        }
        let mut total = 0_u64;
        for family in &mut schema.families {
            if family.disposition == Disposition::Transfer && family.source_rows.0 > 0 {
                let counts = self.stage_source_fixed_family(cut, snapshot_id, &family.id)?;
                if counts.records != family.source_rows.0 {
                    return Err(invalid());
                }
                family.portable_records = U64(counts.records);
                family.encoded_bytes = U64(counts.encoded_bytes);
                total = total.checked_add(counts.encoded_bytes).ok_or_else(invalid)?;
            }
        }
        let mut output = Rooted::new(writer, total)?;
        if cut == 0 {
            output = output.with_wire(self.wire_spool(cut, snapshot_id)?);
        }
        for family in &schema.families {
            if family.portable_records.0 > 0 {
                let (next, counts) =
                    self.write_source_fixed_family(cut, snapshot_id, &family.id, output)?;
                if counts.records != family.portable_records.0
                    || counts.encoded_bytes != family.encoded_bytes.0
                {
                    return Err(invalid());
                }
                output = next;
            }
        }
        let (writer, root) = output.finish(total)?;
        self.require_source_live()?;
        Ok((
            writer,
            FullBaseSourceEncoding {
                schema,
                storage_generation,
                source_erasure_generation,
                total_bytes: total,
                chunk_count: chunk_layout(total).map_err(|_| invalid())?.0,
                chunks_root: root,
            },
        ))
    }
}
pub(super) struct Rooted<W> {
    writer: W,
    root: RootHasher,
    cache: Zeroizing<Vec<u8>>,
    index: u64,
    written: u64,
    wire: Option<super::source_wire::SourceWireSpool>,
}
impl<W> Rooted<W> {
    pub(super) fn new(writer: W, total: u64) -> Result<Self, StorageError> {
        Ok(Self {
            writer,
            root: RootHasher::new(total).map_err(|_| invalid())?,
            cache: Zeroizing::new(Vec::with_capacity(CHUNK_BYTES as usize)),
            index: 0,
            written: 0,
            wire: None,
        })
    }
    pub(super) fn with_wire(mut self, wire: super::source_wire::SourceWireSpool) -> Self {
        self.wire = Some(wire);
        self
    }
    pub(super) fn finish(mut self, total: u64) -> Result<(W, [u8; 32]), StorageError> {
        if self.written != total {
            return Err(invalid());
        }
        if !self.cache.is_empty() {
            self.root.push(self.index, &self.cache).map_err(|_| invalid())?;
            if let Some(wire) = &mut self.wire {
                wire.push(self.index, &self.cache)?;
            }
            self.cache.zeroize();
        }
        let root = self.root.finish().map_err(|_| invalid())?;
        if let Some(wire) = self.wire {
            wire.finish(total, root)?;
        }
        Ok((self.writer, root))
    }
}
impl<W: Write> Write for Rooted<W> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let accepted = self.writer.write(bytes)?;
        if accepted > bytes.len() {
            return Err(std::io::Error::other("invalid source sink length"));
        }
        let mut remaining = &bytes[..accepted];
        while !remaining.is_empty() {
            let amount = remaining.len().min(CHUNK_BYTES as usize - self.cache.len());
            self.cache.extend_from_slice(&remaining[..amount]);
            remaining = &remaining[amount..];
            if self.cache.len() == CHUNK_BYTES as usize {
                self.root
                    .push(self.index, &self.cache)
                    .map_err(|_| std::io::Error::other("full source root refused"))?;
                if let Some(wire) = &mut self.wire {
                    wire.push(self.index, &self.cache)
                        .map_err(|_| std::io::Error::other("full source spool refused"))?;
                }
                self.cache.zeroize();
                self.cache.clear();
                self.index = self
                    .index
                    .checked_add(1)
                    .ok_or_else(|| std::io::Error::other("full source index overflow"))?;
            }
        }
        self.written = self
            .written
            .checked_add(accepted as u64)
            .ok_or_else(|| std::io::Error::other("full source byte overflow"))?;
        Ok(accepted)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.writer.flush()
    }
}

impl FullTransferStage<'_> {
    /// Encode all supported nonempty source families after complete cut/schema preflight.
    /// The output remains private; this grants no signature, receipt or native authority.
    /// # Errors
    /// Refuses wrong role, unsupported owners, stale cuts/generations or output failures.
    pub fn encode_fixed_base_source<W: Write + Send + 'static>(
        &mut self,
        snapshot_id: &str,
        writer: W,
    ) -> Result<(W, FullBaseSourceEncoding), StorageError> {
        self.source_context()?.encode_fixed_base_source(snapshot_id, writer)
    }
}
