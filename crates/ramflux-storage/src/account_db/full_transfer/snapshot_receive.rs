// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! B-side install of the snapshot family: reassemble, verify independently, merge into B's
//! private copy of its own generation, and commit a content root over the merged result.
use super::{
    FullScalarInputCounts, FullUnionEncoding, full_transfer_catalog,
    receiver_contributions::Contributions, receiver_read::ReceiverInput, snapshot,
};
use crate::{AccountDbKey, BackupDatabase, StorageError};
use ramflux_protocol::custody::DeviceRef;
use std::path::Path;

fn mismatch() -> StorageError {
    StorageError::PairingField("ManifestMismatch")
}
/// Name the failed step and error class only; underlying messages are never formatted.
fn step<T>(name: &'static str, result: Result<T, StorageError>) -> Result<T, StorageError> {
    result.inspect_err(|error| {
        let (class, code) = match error {
            StorageError::Sqlite(error) => {
                ("sqlite", error.sqlite_error().map_or(0, |code| code.extended_code))
            }
            StorageError::PairingField(field) => (*field, 0),
            StorageError::Io(_) => ("io", 0),
            StorageError::AuthorizationRejected => ("authorization", 0),
            StorageError::AccountKeyMismatch => ("key", 0),
            _ => ("storage", 0),
        };
        tracing::warn!(step = name, class, code, "transfer snapshot install step failed");
    })
}

/// True when the compiled catalog is the snapshot family.
pub(super) fn active() -> bool {
    matches!(full_transfer_catalog(), [rule] if rule.id == super::catalog::SNAPSHOT_FAMILY)
}

impl Contributions {
    /// Snapshot transfers keep no per-record ledger: the merged file is the evidence.
    /// The file still exists so the existing durable-application owner can sync it.
    pub(super) fn snapshot(
        path: &Path,
        key: &AccountDbKey,
        owners: [&DeviceRef; 2],
    ) -> Result<Self, StorageError> {
        let value = Self {
            nonce: ramflux_crypto::random_32()?,
            owners: [
                super::super::mac_subkeys::full::source_key(owners[0])?,
                super::super::mac_subkeys::full::source_key(owners[1])?,
            ],
        };
        super::stage::create_file(path)?.sync_all()?;
        let db = super::receiver_contributions::open(path, key)?;
        db.execute_batch(super::union_encoding::SCHEMA)?;
        Ok(value)
    }
}

/// Reassemble one authenticated forward cut and merge it into B's private copy.
/// # Errors
/// Refuses a malformed frame, a failed integrity/canary check, pin conflicts or merge errors.
pub(super) fn merge_cut(
    stage: &impl ReceiverInput,
    hash: &str,
    scratch: &Path,
    private_key: &AccountDbKey,
) -> Result<FullScalarInputCounts, StorageError> {
    stage.require_io()?;
    let total = stage.forward_manifest(hash)?.manifest.total_bytes.0;
    let incoming = scratch.join("incoming.db");
    for stale in [incoming.clone(), incoming.with_extension("db-journal")] {
        if std::fs::symlink_metadata(&stale).is_ok() {
            std::fs::remove_file(&stale)?;
        }
    }
    let result = (|| {
        let key = {
            let mut reader = stage.forward_reader(hash)?;
            step("reassemble", snapshot::reassemble(&mut reader, total, &incoming))?
        };
        step("verify", snapshot::verify_incoming(&incoming, &key))?;
        let mut private = step(
            "open private",
            BackupDatabase::open_full_receiver_copy(&scratch.join("private.db"), private_key),
        )?;
        let report = step("merge", private.merge_transfer_snapshot(&incoming, &key))?;
        tracing::info!(
            restored_messages = report.restored.messages,
            restored_contacts = report.restored.contacts,
            restored_groups = report.restored.groups,
            kept_newer_messages = report.kept_newer.messages,
            refused = report.refused_items.len(),
            "transfer snapshot merged into private generation"
        );
        Ok(FullScalarInputCounts { records: 1, encoded_bytes: total })
    })();
    for stale in [incoming.clone(), incoming.with_extension("db-journal")] {
        let _ = std::fs::remove_file(&stale);
    }
    stage.require_io()?;
    result
}

/// Commit the content root of the merged private copy as this generation's local root.
/// # Errors
/// Returns SQL errors.
pub(super) fn union(
    contributions: &Path,
    key: &AccountDbKey,
    nonce: [u8; 32],
    private: &BackupDatabase,
) -> Result<FullUnionEncoding, StorageError> {
    let root = snapshot::content_root(&private.db)?;
    let db = super::receiver_contributions::open(contributions, key)?;
    db.execute(
        "INSERT INTO full_union_encoding(generation_nonce,records,total_bytes,chunks_root) VALUES(?1,1,0,?2) ON CONFLICT(generation_nonce) DO UPDATE SET records=excluded.records,total_bytes=excluded.total_bytes,chunks_root=excluded.chunks_root",
        rusqlite::params![nonce.as_slice(), root.as_slice()],
    )?;
    Ok(FullUnionEncoding { generation_nonce: nonce, records: 1, total_bytes: 0, chunks_root: root })
}

/// Recompute the content root of a private or prepared generation and compare it.
/// # Errors
/// Refuses any content difference from the committed root.
pub(super) fn verify(private: &BackupDatabase, encoding: &FullUnionEncoding) -> Result<(), StorageError> {
    if encoding.records != 1 || snapshot::content_root(&private.db)? != encoding.chunks_root {
        return Err(mismatch());
    }
    Ok(())
}
