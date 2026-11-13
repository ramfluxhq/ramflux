// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Encode only the immutable view pinned by J6; missing bytes never trigger a later cut.
use super::{
    FullSourceDeltaDraft, FullTransferStage, keys::FullSourceMetadataKey,
    source_owner::SourceContext, source_scalar::SourceGuard,
};
use crate::{StorageError, database::Connection};
use ramflux_crypto::custody::{VerifiedRecord, pairing::verify_full_tail_authority};
use ramflux_protocol::custody::pairing::full_transfer::{DataPacket, ManifestKind, SourceManifest};
use std::{fs::File, path::PathBuf, sync::Arc};

/// Bounded local encoding with encrypted metadata and a weak original unlock guard.
/// This grants no signature, relay admission or right to apply a tail to another device.
pub struct FullSourceTailEncodingWork {
    connection: Connection,
    _lock: Arc<File>,
    key: FullSourceMetadataKey,
    guard: SourceGuard,
    directory: PathBuf,
    parent: SourceManifest,
    snapshot: String,
    digest: [u8; 32],
    branch_key: String,
    expires: u64,
}
fn wrong() -> StorageError {
    StorageError::PairingField("WrongContext")
}
impl FullTransferStage<'_> {
    /// Freeze the keyed J6 tail for encoding after releasing A's ordinary writer loan.
    /// `current` must come from this endpoint's own independently verified native query.
    /// # Errors
    /// Refuses missing/invalidated J6, wrong native roles/keys, expiry or incomplete final DV.
    pub fn into_source_tail_encoding_work(
        mut self,
        current: &VerifiedRecord,
        now: u64,
    ) -> Result<FullSourceTailEncodingWork, StorageError> {
        self.require_io()?;
        let identity = self.tail_capture_identity()?;
        let record = self.resume_record()?;
        self.observe_full_native_head(current)?;
        verify_full_tail_authority(&record.grant, current, now).map_err(|error| match error {
            ramflux_crypto::CryptoError::Pairing("LeaseExpired") => {
                StorageError::PairingField("LeaseExpired")
            }
            _ => StorageError::PairingField("HeadChanged"),
        })?;
        if now >= self.reference().lease_expires_at.0 {
            return Err(StorageError::PairingField("LeaseExpired"));
        }
        let durable: bool = self.db.connection.query_row(
            "SELECT cut_state='durable' FROM pairing_full_tail WHERE account_id=?1 AND operation_id=?2 AND stage_id=?3 AND snapshot_id=?4 AND tail_status='pending'",
            rusqlite::params![self.db.local_account_id,identity.operation,self.reference().stage_id,identity.snapshot],
            |row| row.get(0),
        )?;
        if !durable {
            return Err(StorageError::PairingField("SnapshotInvalidated"));
        }
        let Some(DataPacket::DataVerified { manifest_hash, .. }) =
            self.source_last_data_verified()?
        else {
            return Err(wrong());
        };
        let parent = self.forward_manifest(&manifest_hash)?;
        if !parent.manifest.is_last_prepublication_delta()
            || parent.manifest.snapshot_cut.0 + 1 != identity.ordinal
        {
            return Err(wrong());
        }
        self.source_cut_schema(
            identity.ordinal,
            &identity.snapshot,
            super::full_transfer_catalog(),
        )?;
        let guard = SourceGuard::new(self.db, Some(self.source_cancelled.clone()));
        let key = self.key.source_job_key(guard.clone())?;
        Ok(FullSourceTailEncodingWork {
            digest: record.stage_digest()?,
            branch_key: record.grant.branch_keys.source,
            expires: record.grant.expires_at.min(self.reference().lease_expires_at.0),
            connection: self.connection,
            _lock: self.lock,
            key,
            guard,
            directory: self.directory,
            parent,
            snapshot: identity.snapshot,
        })
    }
}
impl FullSourceTailEncodingWork {
    /// Encode the one saved J6 cut against the last prepublication source cut.
    /// No live source recut or network/signing work occurs here; disk spools are encrypted.
    /// # Errors
    /// Refuses missing/corrupt immutable data, unknown owners, schema changes, quota or lock.
    pub fn encode(self) -> Result<FullSourceDeltaDraft, StorageError> {
        self.guard.require()?;
        let mut source = SourceContext {
            key: &self.key,
            connection: &self.connection,
            guard: self.guard.clone(),
            directory: &self.directory,
        };
        let (_, encoded) = source.encode_fixed_tail_source(
            self.parent.manifest.snapshot_cut.0 + 1,
            &self.parent.manifest.snapshot_id,
            &self.snapshot,
            std::io::sink(),
        )?;
        if encoded.total_bytes > ramflux_protocol::custody::pairing::full_transfer::MAX_TAIL_BYTES {
            return Err(StorageError::PairingField("NoSpace"));
        }
        let manifest = super::source_successor::successor_manifest(
            &self.parent,
            self.snapshot,
            encoded,
            ManifestKind::Tail,
        )?;
        self.guard.require()?;
        Ok(FullSourceDeltaDraft {
            manifest,
            digest: self.digest,
            branch_key: self.branch_key,
            expires_at: self.expires,
        })
    }
}
