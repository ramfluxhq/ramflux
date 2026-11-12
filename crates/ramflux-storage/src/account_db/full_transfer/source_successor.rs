// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Root-drained source successor work releases the ordinary writer loan before bulk I/O.
use super::{FullTransferStage, source_owner::SourceContext, source_scalar::SourceGuard};
use crate::{StorageError, database::Connection};
use ramflux_crypto::custody::pairing::PairingRole;
use ramflux_protocol::{
    custody::pairing::{
        PairingWire,
        full_transfer::{DataPacket, Manifest, ManifestKind, SourceManifest, U64, manifest_hash},
    },
    encode_base64url,
};
use rusqlite::OptionalExtension as _;
use std::{
    fs::File,
    path::PathBuf,
    sync::{Arc, atomic::AtomicBool},
};
fn wrong() -> StorageError {
    StorageError::PairingField("WrongContext")
}

mod pending;
use pending::PendingSnapshot;
/// One source-only local job. No authoritative DB connection, raw-key API, serde or Debug.
/// SDK must count/drain this owner on account lock and never carry it over network waits.
pub struct FullSourceSuccessorWork {
    connection: Connection,
    _lock: File,
    key: super::keys::FullSourceMetadataKey,
    guard: SourceGuard,
    directory: PathBuf,
    cut: Option<crate::account_db::backup::FullTransferCut>,
    pending: PendingSnapshot,
    cancelled: Arc<AtomicBool>,
    parent: SourceManifest,
    snapshot_id: String,
    digest: [u8; 32],
    branch_key: String,
    expires_at: u64,
}
/// Exact locally encoded delta signing request. It contains no secret or signing authority.
/// Restart must repeat the original-peer/native/unlock gates before any new signing request.
pub struct FullSourceDeltaDraft {
    manifest: Manifest,
    digest: [u8; 32],
    branch_key: String,
    expires_at: u64,
}
impl FullSourceDeltaDraft {
    #[must_use]
    pub const fn stage_digest(&self) -> [u8; 32] {
        self.digest
    }

    #[must_use]
    pub const fn manifest(&self) -> &Manifest {
        &self.manifest
    }
    #[must_use]
    pub fn expected_branch_key(&self) -> &str {
        &self.branch_key
    }
    #[must_use]
    pub const fn expires_at(&self) -> u64 {
        self.expires_at
    }
    /// Attach only the original A branch signature over the exact privately encoded cut.
    /// # Errors
    /// Refuses malformed/foreign signatures. A separate current local owner retains it.
    pub fn signed_manifest(&self, signature: String) -> Result<SourceManifest, StorageError> {
        let signed =
            SourceManifest { manifest: self.manifest.clone(), source_signature: signature };
        signed.validate().map_err(|_| wrong())?;
        ramflux_crypto::verify_canonical_signature(
            &signed.manifest.signing_bytes().map_err(|_| wrong())?,
            &signed.source_signature,
            &self.branch_key,
        )
        .map_err(|_| wrong())?;
        Ok(signed)
    }
}
impl FullTransferStage<'_> {
    /// Pin the next actual A cut and transfer ONLY local stage ownership to a bounded job.
    /// This consumes the short DB loan; the returned job uses a weak original unlock guard.
    /// # Errors
    /// Refuses missing forward DV, wrong role, expired lease, final delta or changed source.
    pub fn into_source_successor_work(
        self,
        now: u64,
    ) -> Result<FullSourceSuccessorWork, StorageError> {
        self.require_io()?;
        let record = self.resume_record()?;
        pending::reclaim(&self.directory, &self.connection)?;
        let expires_at = record.grant.expires_at.min(self.reference().lease_expires_at.0);
        if record.role != PairingRole::Initiator {
            return Err(wrong());
        }
        if now >= expires_at {
            return Err(StorageError::PairingField("LeaseExpired"));
        }
        let Some(DataPacket::DataVerified { manifest_hash: hash, .. }) =
            self.source_last_data_verified()?
        else {
            return Err(wrong());
        };
        let parent = self.forward_manifest(&hash)?;
        if parent.manifest.kind == ManifestKind::Tail
            || parent.manifest.is_last_prepublication_delta()
            || parent.manifest.snapshot_cut.0 >= 8
        {
            return Err(wrong());
        }
        let next_cut = parent.manifest.snapshot_cut.0 + 1;
        let saved: Option<String> = self
            .connection
            .query_row(
                "SELECT snapshot_id FROM source_cut WHERE cut=?1",
                rusqlite::params![next_cut],
                |r| r.get(0),
            )
            .optional()?;
        let existing = saved.is_some();
        let snapshot_id = if let Some(saved) = saved {
            super::stage::raw32(&saved)?;
            saved
        } else {
            encode_base64url(ramflux_crypto::random_32()?)
        };
        let guard = SourceGuard::new(self.db, Some(self.source_cancelled.clone()));
        let key = self.key.source_job_key(guard.clone())?;
        let cut = if existing { None } else { Some(self.db.pin_full_transfer_cut()?) };
        guard.require()?;
        Ok(FullSourceSuccessorWork {
            connection: self.connection,
            _lock: self.lock,
            key,
            guard,
            pending: PendingSnapshot(
                self.directory.join(format!("pending-source-{snapshot_id}.db")),
            ),
            directory: self.directory,
            cut,
            cancelled: self.source_cancelled,
            parent,
            snapshot_id,
            digest: record.stage_digest()?,
            branch_key: record.grant.branch_keys.source,
            expires_at,
        })
    }
    /// Retain an original-A signed successor only after its exact off-loan encoding.
    /// # Errors
    /// Refuses wrong local scope/body/key, expiry or a changed immutable cut/spool.
    pub fn retain_source_delta(
        &mut self,
        draft: &FullSourceDeltaDraft,
        manifest: &SourceManifest,
        now: u64,
    ) -> Result<(), StorageError> {
        if now >= draft.expires_at {
            return Err(StorageError::PairingField("LeaseExpired"));
        }
        if draft.digest != self.resume_record()?.stage_digest()?
            || draft.manifest != manifest.manifest
            || draft.branch_key != self.resume_record()?.grant.branch_keys.source
        {
            return Err(wrong());
        }
        draft.signed_manifest(manifest.source_signature.clone())?;
        self.retain_source_manifest(manifest, super::full_transfer_catalog())
    }
}
impl FullSourceSuccessorWork {
    /// Copy and encode the pinned source view without retaining its ordinary writer.
    /// All chunks/keys remain in encrypted local spools. No network or signature runs here.
    /// # Errors
    /// Refuses cancellation/lost unlock/selection, changed schema, unsupported rows or I/O.
    pub fn encode(self) -> Result<FullSourceDeltaDraft, StorageError> {
        self.guard.require()?;
        let cut = self.parent.manifest.snapshot_cut.0 + 1;

        let mut source = SourceContext {
            key: &self.key,
            connection: &self.connection,
            guard: self.guard.clone(),
            directory: &self.directory,
        };
        if let Some(pinned) = self.cut {
            let snapshot = pinned.write_private_snapshot(&self.pending.0, self.cancelled)?;
            source.adopt_source_cut(cut, &self.snapshot_id, &self.pending.0, snapshot)?;
        } else {
            // An interrupted local signature/retention step reuses the exact saved cut;
            // later ordinary writes must never substitute for that immutable view.
            source.source_cut_schema(cut, &self.snapshot_id, super::full_transfer_catalog())?;
        }
        let (_, encoded) = source.encode_fixed_delta_source(
            cut,
            &self.parent.manifest.snapshot_id,
            &self.snapshot_id,
            std::io::sink(),
        )?;
        let mut manifest = self.parent.manifest.clone();
        manifest.kind = ManifestKind::Delta;
        manifest.snapshot_id = self.snapshot_id;
        manifest.snapshot_cut = U64(cut);
        manifest.previous_cut = Some(self.parent.manifest.snapshot_cut);
        manifest.parent_manifest_hash =
            Some(encode_base64url(manifest_hash(&self.parent).map_err(|_| wrong())?));
        manifest.families = encoded.schema.families;
        manifest.census_hash = encode_base64url(encoded.schema.census_hash);
        manifest.storage_generation = U64(encoded.storage_generation);
        manifest.source_erasure_generation = U64(encoded.source_erasure_generation);
        manifest.total_bytes = U64(encoded.total_bytes);
        manifest.chunk_count = U64(encoded.chunk_count);
        manifest.chunks_root = encode_base64url(encoded.chunks_root);
        manifest.validate().map_err(|_| wrong())?;
        self.guard.require()?;
        Ok(FullSourceDeltaDraft {
            manifest,
            digest: self.digest,
            branch_key: self.branch_key,
            expires_at: self.expires_at,
        })
    }
}

#[cfg(test)]
mod tests;
