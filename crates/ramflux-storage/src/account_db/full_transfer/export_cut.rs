// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Pinned-cut canonical export: A publishes one framed file; B installs only a clean copy.
use super::source_base::{FullBaseSourceEncoding, Rooted};
use super::source_owner::SourceContext;
use super::{full_transfer_catalog, inventory};
use crate::account_db::transfer_export::builder::{self, Side};
use crate::account_db::transfer_export::open_verified::VerifiedExport;
use crate::account_db::transfer_export::{self, export_contract_digest};
use crate::{AccountDbKey, StorageError};
use ramflux_protocol::custody::pairing::full_transfer::{Disposition, U64, chunk_layout};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use zeroize::Zeroize as _;

/// `ramflux.transfer.snapshot.v1` — 28 bytes, the existing stream domain. No new wire type.
pub(super) const FRAME_DOMAIN: &[u8; 28] = b"ramflux.transfer.snapshot.v1";

struct RemoveFile(PathBuf);
impl Drop for RemoveFile {
    fn drop(&mut self) {
        discard(&self.0);
    }
}

struct ZeroHeader(Vec<u8>);
impl Drop for ZeroHeader {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

struct CutExport {
    key: AccountDbKey,
    file_len: u64,
    framed: u64,
    storage_generation: u64,
    source_erasure_generation: u64,
}

fn mismatch() -> StorageError {
    StorageError::PairingField("ManifestMismatch")
}

fn framed_len(file_len: u64) -> Result<u64, StorageError> {
    transfer_export::FRAME_HEADER_BYTES
        .checked_add(file_len)
        .ok_or(StorageError::PairingField("NoSpace"))
}

impl SourceContext<'_> {
    /// Build the canonical export of this pinned cut, refuse an unknown namespace or a
    /// framed file over the pre-invitation limit, and stream that frame. The manifest's
    /// `census_hash` is the export contract digest. Family rows are not the byte stream.
    /// # Errors
    /// `UnsupportedRecord` for an unclassified namespace, `NoSpace` over the limit,
    /// plus SQL and I/O.
    pub(super) fn publish_account_export<W: Write + Send + 'static>(
        &mut self,
        snapshot_id: &str,
        writer: W,
    ) -> Result<(W, FullBaseSourceEncoding), StorageError> {
        let rules = full_transfer_catalog();
        let mut schema = self.source_cut_schema(0, snapshot_id, rules)?;
        schema.require_typed_owners(rules)?;
        let target = self.directory.join(format!("account-export-{snapshot_id}.db"));
        let _remove = RemoveFile(target.clone());
        let built = self.build_cut(snapshot_id, &target)?;
        let framed = built.framed;
        assign_frame_length(&mut schema, framed)?;
        schema.census_hash = export_contract_digest()?;
        let mut output = Rooted::new(writer, framed)?.with_wire(self.wire_spool(0, snapshot_id)?);
        write_frame(&mut output, &built.key, &target, built.file_len)?;
        let (writer, root) = output.finish(framed)?;
        self.require_source_live()?;
        Ok((
            writer,
            FullBaseSourceEncoding {
                schema,
                storage_generation: built.storage_generation,
                source_erasure_generation: built.source_erasure_generation,
                total_bytes: framed,
                chunk_count: chunk_layout(framed).map_err(|_| mismatch())?.0,
                chunks_root: root,
            },
        ))
    }

    /// Rebuild the current cut's export and refuse before a delta is written when it
    /// would not have passed the pre-invitation size or namespace gate.
    /// # Errors
    /// The same refusals as [`Self::publish_account_export`], without writing a stream.
    pub(super) fn gate_account_export(
        &mut self,
        cut: u64,
        snapshot_id: &str,
    ) -> Result<(), StorageError> {
        let target = self.directory.join(format!("account-export-gate-{cut}.db"));
        let _remove = RemoveFile(target.clone());
        self.with_source_cut(cut, snapshot_id, |input| {
            let key = AccountDbKey::generate()?;
            let (file_len, _, _) = export_snapshot(input, &target, &key)?;
            inventory::require_export_before_invitation(framed_len(file_len)?)?;
            Ok(())
        })
    }

    fn build_cut(&mut self, snapshot_id: &str, target: &Path) -> Result<CutExport, StorageError> {
        let key = AccountDbKey::generate()?;
        let (file_len, storage_generation, source_erasure_generation) =
            self.with_source_cut(0, snapshot_id, |input| export_snapshot(input, target, &key))?;
        let framed = inventory::require_export_before_invitation(framed_len(file_len)?)?;
        Ok(CutExport { key, file_len, framed, storage_generation, source_erasure_generation })
    }
}

pub(super) fn export_snapshot(
    input: &crate::database::Connection,
    target: &Path,
    key: &AccountDbKey,
) -> Result<(u64, u64, u64), StorageError> {
    let path = target.to_owned();
    let key = key.clone();
    input.call(move |db| {
        let run = || -> Result<(u64, u64, u64), StorageError> {
            let built = builder::build(db, Side::Account, &path, &key)?;
            let storage_generation =
                db.query_row("SELECT max(schema_version) FROM schema_migration", [], |row| {
                    row.get::<_, u64>(0)
                })?;
            let source_erasure_generation = db.query_row(
                "SELECT generation FROM account_erasure_generation WHERE singleton=1",
                [],
                |row| row.get::<_, u64>(0),
            )?;
            Ok((built.bytes, storage_generation, source_erasure_generation))
        };
        Ok(run())
    })?
}

/// The signed `total_bytes` must equal the sum of family `encoded_bytes` (existing
/// manifest rule, no new field). The frame is one blob, so the first transfer family
/// carries that length and every other family contributes none of the byte stream.
pub(super) fn assign_frame_length(
    schema: &mut super::inventory::FullTransferSchema,
    framed: u64,
) -> Result<(), StorageError> {
    let mut found = false;
    for family in &mut schema.families {
        family.portable_records = U64(0);
        family.encoded_bytes = U64(0);
        if !found && family.disposition == Disposition::Transfer {
            family.encoded_bytes = U64(framed);
            found = true;
        }
    }
    if found { Ok(()) } else { Err(StorageError::PairingField("UnsupportedRecord")) }
}

pub(super) fn write_frame<W: Write>(
    output: &mut W,
    key: &AccountDbKey,
    path: &Path,
    file_len: u64,
) -> Result<(), StorageError> {
    output.write_all(FRAME_DOMAIN)?;
    output.write_all(key.bytes())?;
    output.write_all(&file_len.to_be_bytes())?;
    let mut file = std::fs::File::open(path)?;
    let mut buffer = [0_u8; 8192];
    let mut remaining = file_len;
    while remaining > 0 {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            return Err(StorageError::TransferExportRefused("size"));
        }
        let take = u64::try_from(read).map_err(|_| mismatch())?.min(remaining);
        let take = usize::try_from(take).map_err(|_| mismatch())?;
        output.write_all(&buffer[..take])?;
        remaining -= u64::try_from(take).map_err(|_| mismatch())?;
    }
    Ok(())
}

/// Read a framed export from `reader`, check the contract, and write B's clean copy at
/// `target` under `copy_key`. `expected_root` is the manifest account anchor.
/// # Errors
/// `TransferExportRefused` at `size`, `open`, or the step `open_verified` names;
/// `NoSpace` when the frame exceeds the same pre-invitation cap; SQL and I/O.
pub(super) fn install_framed_export<R: Read>(
    reader: &mut R,
    target: &Path,
    copy_key: &AccountDbKey,
    expected_root: &str,
) -> Result<builder::Built, StorageError> {
    let header = ZeroHeader(read_exact(reader, 28 + 32 + 8)?);
    if header.0.get(..28) != Some(FRAME_DOMAIN.as_slice()) {
        return Err(StorageError::TransferExportRefused("open"));
    }
    let key_bytes = header_key(&header.0)?;
    let len_bytes: [u8; 8] =
        header.0.get(60..68).ok_or_else(mismatch)?.try_into().map_err(|_| mismatch())?;
    let file_len = u64::from_be_bytes(len_bytes);
    drop(header);
    inventory::require_export_before_invitation(framed_len(file_len)?)?;
    let received = target.with_extension("received");
    let _remove_received = RemoveFile(received.clone());
    write_received(&received, reader, file_len)?;
    let file_key = AccountDbKey::from_bytes(key_bytes);
    let verified = VerifiedExport::open(&received, &file_key, expected_root)?;
    let built = verified.clean_copy(target, copy_key);
    drop(verified);
    match built {
        Ok(built) => Ok(built),
        Err(error) => {
            discard(target);
            Err(error)
        }
    }
}

fn header_key(header: &[u8]) -> Result<[u8; 32], StorageError> {
    header.get(28..60).ok_or_else(mismatch)?.try_into().map_err(|_| mismatch())
}

fn write_received(path: &Path, reader: &mut impl Read, file_len: u64) -> Result<(), StorageError> {
    let mut file = std::fs::OpenOptions::new();
    file.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut file, 0o600);
    let mut file = file.open(path)?;
    copy_exact(&mut file, reader, file_len)?;
    file.sync_all()?;
    Ok(())
}

fn copy_exact(
    file: &mut impl Write,
    reader: &mut impl Read,
    file_len: u64,
) -> Result<(), StorageError> {
    let mut buffer = [0_u8; 8192];
    let mut remaining = file_len;
    while remaining > 0 {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            return Err(StorageError::TransferExportRefused("size"));
        }
        let take = u64::try_from(read).map_err(|_| mismatch())?.min(remaining);
        let take = usize::try_from(take).map_err(|_| mismatch())?;
        file.write_all(&buffer[..take])?;
        remaining -= u64::try_from(take).map_err(|_| mismatch())?;
    }
    Ok(())
}

fn read_exact(reader: &mut impl Read, len: usize) -> Result<Vec<u8>, StorageError> {
    let mut buffer = vec![0_u8; len];
    let mut filled = 0;
    while filled < len {
        let read = reader.read(&mut buffer[filled..])?;
        if read == 0 {
            return Err(StorageError::TransferExportRefused("size"));
        }
        filled = filled.saturating_add(read);
    }
    Ok(buffer)
}

fn discard(path: &Path) {
    let _ = std::fs::remove_file(path);
    let _ = std::fs::remove_file(format!("{}-journal", path.display()));
    let _ = std::fs::remove_file(format!("{}-wal", path.display()));
    let _ = std::fs::remove_file(format!("{}-shm", path.display()));
}
