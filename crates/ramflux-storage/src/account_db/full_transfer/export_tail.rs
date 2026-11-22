// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Pre-J3 cuts whose parent census is the export digest stay framed exports.
//! A tail appends the open deletion section. Family-census parents stay on the typed diff.
use super::export_cut::{assign_frame_length, export_snapshot, write_frame};
use super::source_base::{FullBaseSourceEncoding, Rooted};
use super::source_owner::SourceContext;
use super::{export_deletion, full_transfer_catalog};
use crate::account_db::transfer_export::open_verified::VerifiedExport;
use crate::account_db::transfer_export::{self, export_contract_digest};
use crate::{AccountDbKey, StorageError};
use ramflux_protocol::custody::pairing::full_transfer::{SourceManifest, chunk_layout};
use std::collections::BTreeSet;
use std::io::Write;
use std::path::{Path, PathBuf};

struct RemoveFile(PathBuf);
impl Drop for RemoveFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
        let _ = std::fs::remove_file(format!("{}-journal", self.0.display()));
        let _ = std::fs::remove_file(format!("{}-wal", self.0.display()));
        let _ = std::fs::remove_file(format!("{}-shm", self.0.display()));
    }
}

struct BuiltCut {
    key: AccountDbKey,
    path: PathBuf,
    _remove: RemoveFile,
    file_len: u64,
    storage_generation: u64,
    source_erasure_generation: u64,
}

/// One successor cut. `deletions` is true only for the tail.
pub(super) struct ExportRequest<'a> {
    pub(super) parent: &'a SourceManifest,
    pub(super) cut: u64,
    pub(super) snapshot_id: &'a str,
    pub(super) deletions: bool,
}

fn mismatch() -> StorageError {
    StorageError::PairingField("ManifestMismatch")
}

/// True when this manifest census is the export contract digest.
/// # Errors
/// Contract-digest failures.
pub(super) fn is_export_census(census_hash: &str) -> Result<bool, StorageError> {
    Ok(census_hash == ramflux_protocol::encode_base64url(export_contract_digest()?))
}

impl SourceContext<'_> {
    /// Frame this cut as a canonical export. The tail also appends its deletion section.
    /// The census stays the export digest so the predecessor check still holds.
    /// # Errors
    /// `NoSpace` when header, file and deletion section exceed 64 MiB; `SnapshotInvalidated`
    /// when the storage generation moved; `ManifestMismatch` when erasure went backwards.
    pub(super) fn encode_export_cut<W: Write + Send + 'static>(
        &mut self,
        request: &ExportRequest<'_>,
        writer: W,
    ) -> Result<(W, FullBaseSourceEncoding), StorageError> {
        if request.cut == 0 || request.cut > 9 {
            return Err(StorageError::PairingField("WrongContext"));
        }
        let rules = full_transfer_catalog();
        let mut schema = self.source_cut_schema(request.cut, request.snapshot_id, rules)?;
        // Same gate as the base frame: an unclassified table already failed inspection.
        // A nonempty family without a typed codec is not a refusal on this path.
        let current = self.materialize_export(request.cut, request.snapshot_id)?;
        require_current(&current, request.parent)?;
        let trailing =
            if request.deletions { self.deletion_bytes(request, &current)? } else { Vec::new() };
        let trailing_len = u64::try_from(trailing.len()).unwrap_or(u64::MAX);
        let framed = transfer_export::require_cut_size(current.file_len, trailing_len)?;
        assign_frame_length(&mut schema, framed)?;
        schema.census_hash = export_contract_digest()?;
        self.spool_export(
            writer,
            Spool {
                cut: request.cut,
                snapshot_id: request.snapshot_id,
                built: &current,
                trailing: &trailing,
                framed,
                schema,
            },
        )
    }

    fn materialize_export(
        &mut self,
        cut: u64,
        snapshot_id: &str,
    ) -> Result<BuiltCut, StorageError> {
        let path = self.directory.join(format!("account-export-{cut}-{snapshot_id}.db"));
        let remove = RemoveFile(path.clone());
        let key = AccountDbKey::generate()?;
        let (file_len, storage_generation, source_erasure_generation) =
            self.with_source_cut(cut, snapshot_id, |input| export_snapshot(input, &path, &key))?;
        Ok(BuiltCut {
            key,
            path,
            _remove: remove,
            file_len,
            storage_generation,
            source_erasure_generation,
        })
    }

    fn deletion_bytes(
        &mut self,
        request: &ExportRequest<'_>,
        current: &BuiltCut,
    ) -> Result<Vec<u8>, StorageError> {
        let parent_cut = request.parent.manifest.snapshot_cut.0;
        let parent = self.materialize_export(parent_cut, &request.parent.manifest.snapshot_id)?;
        require_parent(&parent, request.parent)?;
        let anchor = request.parent.manifest.account_anchor.as_str();
        let parent_keys = export_keys(&parent, anchor)?;
        let current_keys = export_keys(current, anchor)?;
        let missing: Vec<(String, Vec<u8>)> = parent_keys
            .difference(&current_keys)
            .map(|item| (item.0.clone(), item.1.clone()))
            .collect();
        export_deletion::encode(&missing)
    }

    fn spool_export<W: Write + Send + 'static>(
        &mut self,
        writer: W,
        spool: Spool<'_>,
    ) -> Result<(W, FullBaseSourceEncoding), StorageError> {
        let mut output = Rooted::new(writer, spool.framed)?
            .with_wire(self.wire_spool(spool.cut, spool.snapshot_id)?);
        write_frame(&mut output, &spool.built.key, &spool.built.path, spool.built.file_len)?;
        if !spool.trailing.is_empty() {
            output.write_all(spool.trailing)?;
        }
        let (writer, root) = output.finish(spool.framed)?;
        self.require_source_live()?;
        Ok((
            writer,
            FullBaseSourceEncoding {
                schema: spool.schema,
                storage_generation: spool.built.storage_generation,
                source_erasure_generation: spool.built.source_erasure_generation,
                total_bytes: spool.framed,
                chunk_count: chunk_layout(spool.framed).map_err(|_| mismatch())?.0,
                chunks_root: root,
            },
        ))
    }
}

struct Spool<'a> {
    cut: u64,
    snapshot_id: &'a str,
    built: &'a BuiltCut,
    trailing: &'a [u8],
    framed: u64,
    schema: super::inventory::FullTransferSchema,
}

fn require_current(built: &BuiltCut, parent: &SourceManifest) -> Result<(), StorageError> {
    if built.storage_generation != parent.manifest.storage_generation.0 {
        return Err(StorageError::PairingField("SnapshotInvalidated"));
    }
    if built.source_erasure_generation < parent.manifest.source_erasure_generation.0 {
        Err(StorageError::PairingField("ManifestMismatch"))
    } else {
        Ok(())
    }
}

fn require_parent(built: &BuiltCut, parent: &SourceManifest) -> Result<(), StorageError> {
    if built.storage_generation == parent.manifest.storage_generation.0
        && built.source_erasure_generation == parent.manifest.source_erasure_generation.0
    {
        Ok(())
    } else {
        Err(StorageError::PairingField("SnapshotInvalidated"))
    }
}

fn export_keys(
    built: &BuiltCut,
    anchor: &str,
) -> Result<BTreeSet<(String, Vec<u8>)>, StorageError> {
    let verified = VerifiedExport::open(&built.path, &built.key, anchor)?;
    verified.allow_row_read();
    let mut keys = BTreeSet::new();
    for row in crate::account_db::transfer_export::digest::primary_keys(verified.connection())? {
        if !keys.insert((row.table.to_owned(), row.key)) {
            return Err(mismatch());
        }
    }
    Ok(keys)
}

/// File body, file key, and trailing deletion section of one signed export stream.
pub(super) struct SplitFrame {
    pub(super) file: Vec<u8>,
    pub(super) key: [u8; 32],
    pub(super) deletion: Vec<u8>,
}

/// Split a signed export stream into the file body and the trailing deletion section.
/// # Errors
/// `ManifestMismatch` when the frame, the length, or the section shape disagrees;
/// `NoSpace` when the framed total exceeds the pre-publication stop.
pub(super) fn split_stream(
    bytes: &[u8],
    expect_deletion: bool,
) -> Result<SplitFrame, StorageError> {
    if bytes.len() < usize::try_from(transfer_export::FRAME_HEADER_BYTES).map_err(|_| mismatch())? {
        return Err(mismatch());
    }
    if bytes.get(..28) != Some(super::export_cut::FRAME_DOMAIN.as_slice()) {
        return Err(StorageError::TransferExportRefused("open"));
    }
    let key = header_key(bytes)?;
    let file_len = file_len(bytes)?;
    let file_end = usize::try_from(transfer_export::FRAME_HEADER_BYTES)
        .map_err(|_| mismatch())?
        .checked_add(usize::try_from(file_len).map_err(|_| mismatch())?)
        .ok_or_else(mismatch)?;
    if file_end > bytes.len() {
        return Err(mismatch());
    }
    let deletion = bytes.get(file_end..).ok_or_else(mismatch)?.to_vec();
    if (expect_deletion && deletion.len() < 36) || (!expect_deletion && !deletion.is_empty()) {
        return Err(mismatch());
    }
    let trailing = u64::try_from(deletion.len()).unwrap_or(u64::MAX);
    let framed = transfer_export::require_cut_size(file_len, trailing)?;
    if framed != u64::try_from(bytes.len()).unwrap_or(u64::MAX) {
        return Err(mismatch());
    }
    let file = bytes
        .get(
            usize::try_from(transfer_export::FRAME_HEADER_BYTES).map_err(|_| mismatch())?..file_end,
        )
        .ok_or_else(mismatch)?
        .to_vec();
    Ok(SplitFrame { file, key, deletion })
}

fn header_key(bytes: &[u8]) -> Result<[u8; 32], StorageError> {
    bytes.get(28..60).ok_or_else(mismatch)?.try_into().map_err(|_| mismatch())
}

fn file_len(bytes: &[u8]) -> Result<u64, StorageError> {
    let raw: [u8; 8] =
        bytes.get(60..68).ok_or_else(mismatch)?.try_into().map_err(|_| mismatch())?;
    Ok(u64::from_be_bytes(raw))
}

/// Write the file body under the stage directory and open it through `open_verified`.
/// # Errors
/// The named `TransferExportRefused` steps, plus I/O.
pub(super) struct SpilledExport {
    pub(super) verified: VerifiedExport,
    _remove: RemoveFile,
}

pub(super) fn open_spilled(
    directory: &Path,
    name: &str,
    file: &[u8],
    key: &[u8; 32],
    anchor: &str,
) -> Result<SpilledExport, StorageError> {
    let path = directory.join(name);
    let _ = std::fs::remove_file(&path);
    let remove = RemoveFile(path.clone());
    let mut output = super::stage::create_file(&path)?;
    output.write_all(file)?;
    output.sync_all()?;
    drop(output);
    let verified = VerifiedExport::open(&path, &AccountDbKey::from_bytes(*key), anchor)?;
    verified.allow_row_read();
    Ok(SpilledExport { verified, _remove: remove })
}
